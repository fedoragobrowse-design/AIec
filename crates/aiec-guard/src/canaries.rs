//! Synthetic tripwires: a canary file, a canary hostname and a canary
//! credential, and what happens when a guest touches one.
//!
//! ## What a canary is for
//!
//! The other enforcement surfaces answer "is this destination permitted?". A
//! canary answers a different question: *did the guest go looking for something
//! it was never told about?* An agent that enumerates `~/.ssh`, resolves a
//! hostname nobody configured, or reaches for a credential it has no binding for
//! is behaving in a way no allowlist describes, and the only way to notice is to
//! leave something for it to find.
//!
//! ## Everything here is synthetic
//!
//! A canary value is not a real credential that was copied somewhere, and this
//! module will not let one be configured. Every canary value must carry the
//! reserved marker [`CANARY_VALUE_PREFIX`], and every canary hostname must sit
//! under a reserved top-level domain from [`CANARY_HOST_SUFFIXES`]. A real
//! secret does not begin with `aiec-canary:`, and a real host does not live under
//! `.invalid`; so a policy that tries to plant a live secret as a tripwire is
//! refused at load instead of shipping it. [`CanarySet::synthetic_value`] mints a
//! conforming value for an operator who does not want to invent one.
//!
//! ## Canary values never enter the journal
//!
//! Every record this module produces carries an opaque reference such as
//! `file#0` and a static reason, and nothing else. The operator correlates the
//! reference with their own policy to learn which tripwire fired; a reader of
//! the journal learns that a canary fired and nothing about what it said. The
//! remote sink and operator tooling sit outside the guest, and a canary value
//! that reached them would be a synthetic credential in a wider blast radius
//! than the sandbox it was planted in.
//!
//! [`CanarySet::redact`] exists for the same reason on the other side: a caller
//! that wants to put free text - a reason, an error, a debug line - through
//! anything that was derived from guest input can scrub every canary value out
//! of it first.
//!
//! ## What firing does
//!
//! Reading a canary file or resolving a canary hostname is high severity: the
//! event is recorded at [`Decision::Cut`] and the attachment's network is cut.
//! Presenting a canary credential cuts the network, appends the critical event,
//! and requests durable quarantine. A failed callback is not completion; the
//! already-cut attachment remains contained and the event remains journaled.
//!
//! The monitor never restores, never releases a quarantine and never widens a
//! policy. It cuts and it quarantines, which are the two directions the
//! out-of-guest side is allowed to move on its own.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    Result,
    control::{GuardFence, GuardIdentity, QuarantineRequest, RuleTrigger},
    events::{Category, Decision, EventInput, EventSink, GuardEvent},
    policy::CanaryConfig,
};

/// Marker every canary value must begin with.
///
/// This is the mechanical form of "never use real secrets": a live credential
/// does not start with this, so a policy that plants one is refused at load
/// rather than shipped to a worker.
pub const CANARY_VALUE_PREFIX: &str = "aiec-canary:";

/// Top-level domains a canary hostname may live under.
///
/// Reserved by RFC 2606 and RFC 6761, so a canary hostname can never be a real
/// destination no matter what is deployed around it.
pub const CANARY_HOST_SUFFIXES: &[&str] = &["invalid", "test", "example", "localhost"];

/// Largest number of canary file tripwires in one policy.
pub const MAX_CANARY_FILES: usize = 32;
/// Largest number of canary hostname tripwires in one policy.
pub const MAX_CANARY_HOSTNAMES: usize = 64;
/// Largest number of canary credentials in one policy.
pub const MAX_CANARY_CREDENTIALS: usize = 32;
/// Largest canary value accepted, in bytes.
pub const MAX_CANARY_VALUE_BYTES: usize = 256;
/// Largest canary path accepted, in bytes.
pub const MAX_CANARY_PATH_BYTES: usize = 512;

/// Rule name recorded for a canary file read.
pub const RULE_CANARY_FILE: &str = "canary.file-read";
/// Rule name recorded for a canary hostname resolution.
pub const RULE_CANARY_HOSTNAME: &str = "canary.hostname-resolved";
/// Rule name recorded for a canary credential presentation.
pub const RULE_CANARY_CREDENTIAL: &str = "canary.credential-presented";

/// Which kind of tripwire fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CanaryKind {
    /// A file planted in the guest whose contents are a synthetic secret.
    File,
    /// A hostname planted in policy that resolves nowhere.
    Hostname,
    /// A credential name the guest must never present to the gateway.
    Credential,
}

impl CanaryKind {
    /// Stable lowercase wire name, used in the opaque reference.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Hostname => "hostname",
            Self::Credential => "credential",
        }
    }
}

impl std::fmt::Display for CanaryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How serious a firing is, and therefore what it is allowed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CanarySeverity {
    /// Recorded and cut. The sandbox keeps running with no egress.
    High,
    /// Quarantined immediately.
    Critical,
}

impl CanarySeverity {
    /// Stable lowercase wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for CanarySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The out-of-guest response a firing demands.
///
/// There is deliberately no "allow" and no "warn" here. A canary that fires and
/// changes nothing is a canary nobody reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanaryResponse {
    /// Cut the attachment's network and record at [`Decision::Cut`].
    Cut,
    /// Quarantine the sandbox and record at [`Decision::Quarantine`].
    Quarantine,
}

/// One canary firing, carrying nothing about the canary itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryTrip {
    /// Which tripwire fired.
    pub kind: CanaryKind,
    /// Opaque reference such as `file#0`: which configured canary, and no more.
    pub reference: String,
    /// How serious this is.
    pub severity: CanarySeverity,
    /// The response the monitor carries out.
    pub response: CanaryResponse,
    /// The rule name recorded in the journal.
    pub rule: &'static str,
    /// The static reason recorded in the journal.
    pub reason: &'static str,
}

impl CanaryTrip {
    /// The journal category this firing is recorded under.
    pub fn category(&self) -> Category {
        match self.kind {
            CanaryKind::Hostname => Category::Dns,
            CanaryKind::File | CanaryKind::Credential => Category::Credential,
        }
    }

    /// The journal decision this firing is recorded at.
    pub fn decision(&self) -> Decision {
        match self.response {
            CanaryResponse::Cut => Decision::Cut,
            CanaryResponse::Quarantine => Decision::Quarantine,
        }
    }
}

#[derive(Clone, Debug)]
struct FileCanary {
    path: String,
    value: String,
}

#[derive(Clone, Debug)]
struct HostCanary {
    name: String,
}

#[derive(Clone, Debug)]
struct CredentialCanary {
    name: String,
}

/// The validated set of tripwires a policy configures.
#[derive(Clone, Debug, Default)]
pub struct CanarySet {
    files: Vec<FileCanary>,
    hostnames: Vec<HostCanary>,
    credentials: Vec<CredentialCanary>,
}

fn canary_error(message: impl Into<String>) -> crate::GuardError {
    crate::GuardError::Policy(message.into())
}

impl CanarySet {
    /// Mints a conforming synthetic value for `label`.
    ///
    /// The random suffix means two canaries planted from the same label are
    /// distinguishable to whoever holds the policy, while remaining obviously
    /// synthetic to anything that reads the value.
    pub fn synthetic_value(label: &str) -> String {
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        format!(
            "{CANARY_VALUE_PREFIX}{label}-{}-{}",
            hex::encode(a.as_bytes()),
            hex::encode(b.as_bytes())
        )
    }

    /// An empty set, which matches nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Validates a configured canary set, refusing anything that could be a real
    /// secret and anything unbounded.
    ///
    /// A policy that names a canary value without the reserved marker, a canary
    /// hostname outside a reserved TLD, a relative path, a traversal, a duplicate
    /// entry or more entries than the bounds allow is refused here rather than
    /// half-installed.
    pub fn from_config(config: &CanaryConfig) -> Result<Self> {
        if config.files.len() > MAX_CANARY_FILES {
            return Err(canary_error(format!(
                "canaries.files has {} entries, maximum is {MAX_CANARY_FILES}",
                config.files.len()
            )));
        }
        if config.hostnames.len() > MAX_CANARY_HOSTNAMES {
            return Err(canary_error(format!(
                "canaries.hostnames has {} entries, maximum is {MAX_CANARY_HOSTNAMES}",
                config.hostnames.len()
            )));
        }
        if config.credentials.len() > MAX_CANARY_CREDENTIALS {
            return Err(canary_error(format!(
                "canaries.credentials has {} entries, maximum is {MAX_CANARY_CREDENTIALS}",
                config.credentials.len()
            )));
        }
        let mut files: Vec<FileCanary> = Vec::with_capacity(config.files.len());
        for (index, spec) in config.files.iter().enumerate() {
            validate_canary_path(&spec.path, index)?;
            validate_canary_value(&spec.value, "canaries.files", index)?;
            if files.iter().any(|canary| canary.path == spec.path) {
                return Err(canary_error(format!(
                    "canaries.files[{index}] repeats path {}",
                    bounded(&spec.path)
                )));
            }
            files.push(FileCanary {
                path: spec.path.clone(),
                value: spec.value.clone(),
            });
        }
        let mut hostnames: Vec<HostCanary> = Vec::with_capacity(config.hostnames.len());
        for (index, name) in config.hostnames.iter().enumerate() {
            validate_canary_hostname(name, index)?;
            if hostnames
                .iter()
                .any(|canary| canary.name.eq_ignore_ascii_case(name))
            {
                return Err(canary_error(format!(
                    "canaries.hostnames[{index}] repeats {}",
                    bounded(name)
                )));
            }
            hostnames.push(HostCanary {
                name: name.to_ascii_lowercase(),
            });
        }
        let mut credentials: Vec<CredentialCanary> = Vec::with_capacity(config.credentials.len());
        for (index, name) in config.credentials.iter().enumerate() {
            validate_canary_credential(name, index)?;
            if credentials.iter().any(|canary| canary.name == *name) {
                return Err(canary_error(format!(
                    "canaries.credentials[{index}] repeats {}",
                    bounded(name)
                )));
            }
            credentials.push(CredentialCanary { name: name.clone() });
        }
        Ok(Self {
            files,
            hostnames,
            credentials,
        })
    }

    /// Whether this policy configures any tripwire at all.
    ///
    /// A monitor built from an empty set refuses to be built, so a deployment
    /// that did not opt in pays nothing.
    pub fn is_enabled(&self) -> bool {
        !self.files.is_empty() || !self.hostnames.is_empty() || !self.credentials.is_empty()
    }

    /// The tripwire a guest file read exposed, if any.
    ///
    /// Three things expose a canary: reading it, listing the directory that
    /// holds it, and reading anything else inside that directory. A *higher*
    /// directory does not: listing `/root` names `.ssh`, which is a step on the
    /// way, not the exposure, and firing on every listing the guest ever does
    /// would train an operator to ignore a high-severity signal.
    pub fn file_read(&self, path: &str) -> Option<CanaryTrip> {
        let path = path.trim_end_matches('/');
        // The root and an empty path match every prefix, so they are refused
        // before any comparison rather than after it.
        if path.is_empty() || path == "/" {
            return None;
        }
        for (index, canary) in self.files.iter().enumerate() {
            let canary_path = canary.path.as_str();
            let directory = canary_path
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .filter(|parent| !parent.is_empty())
                .unwrap_or("/");
            let in_canary_directory = path == canary_path
                || path
                    .strip_prefix(canary_path)
                    .is_some_and(|rest| rest.starts_with('/'))
                || (path == directory
                    || path
                        .strip_prefix(directory)
                        .is_some_and(|rest| rest.starts_with('/')));
            if in_canary_directory {
                return Some(trip(
                    CanaryKind::File,
                    index,
                    CanarySeverity::High,
                    CanaryResponse::Cut,
                    RULE_CANARY_FILE,
                    "canary file read, severity high, network cut",
                ));
            }
        }
        None
    }

    /// The tripwire a resolved hostname matched, if any.
    ///
    /// A canary and its subdomains both count: an agent that cannot reach
    /// `canary.invalid` should not reach `metrics.canary.invalid` either.
    pub fn hostname_resolved(&self, name: &str) -> Option<CanaryTrip> {
        let query = name.trim_end_matches('.').to_ascii_lowercase();
        for (index, canary) in self.hostnames.iter().enumerate() {
            // The canary is the *suffix*: `metrics.exfil.canary.invalid` is a
            // subdomain of `exfil.canary.invalid`, while a name that merely
            // begins with it belongs to somebody else entirely.
            let is_canary = query == canary.name
                || query
                    .strip_suffix(&canary.name)
                    .is_some_and(|prefix| prefix.ends_with('.'));
            if is_canary {
                return Some(trip(
                    CanaryKind::Hostname,
                    index,
                    CanarySeverity::High,
                    CanaryResponse::Cut,
                    RULE_CANARY_HOSTNAME,
                    "canary hostname resolution, severity high, network cut",
                ));
            }
        }
        None
    }

    /// The tripwire a presented credential matched, if any.
    ///
    /// Constant time, because the presented value is attacker-supplied and a
    /// byte-at-a-time comparison would leak the canary one byte at a time.
    pub fn credential_presented(&self, presented: &str) -> Option<CanaryTrip> {
        for (index, canary) in self.credentials.iter().enumerate() {
            if constant_time_eq(canary.name.as_bytes(), presented.as_bytes()) {
                return Some(trip(
                    CanaryKind::Credential,
                    index,
                    CanarySeverity::Critical,
                    CanaryResponse::Quarantine,
                    RULE_CANARY_CREDENTIAL,
                    "canary credential presented, severity critical, immediate quarantine",
                ));
            }
        }
        None
    }

    /// Replaces every canary value in `text` with a fixed marker.
    ///
    /// Longer values are replaced first so a value that is a prefix of another
    /// cannot leave the tail of the longer one behind.
    pub fn redact(&self, text: &str) -> String {
        let mut values: Vec<&str> = self
            .files
            .iter()
            .map(|canary| canary.value.as_str())
            .collect();
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        let mut out = text.to_owned();
        for value in values {
            if out.contains(value) {
                out = out.replace(value, "[canary]");
            }
        }
        out
    }
}

fn trip(
    kind: CanaryKind,
    index: usize,
    severity: CanarySeverity,
    response: CanaryResponse,
    rule: &'static str,
    reason: &'static str,
) -> CanaryTrip {
    CanaryTrip {
        kind,
        reference: format!("{kind}#{index}"),
        severity,
        response,
        rule,
        reason,
    }
}

fn validate_canary_path(path: &str, index: usize) -> Result<()> {
    if path.is_empty() || path.len() > MAX_CANARY_PATH_BYTES {
        return Err(canary_error(format!(
            "canaries.files[{index}].path must be 1..={MAX_CANARY_PATH_BYTES} bytes"
        )));
    }
    if !path.starts_with('/') {
        return Err(canary_error(format!(
            "canaries.files[{index}].path must be absolute inside the guest"
        )));
    }
    if !path.is_ascii() || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(canary_error(format!(
            "canaries.files[{index}].path must be printable ASCII"
        )));
    }
    if path.split('/').any(|segment| segment == "..") {
        return Err(canary_error(format!(
            "canaries.files[{index}].path must not contain a traversal segment"
        )));
    }
    Ok(())
}

fn validate_canary_value(value: &str, field: &str, index: usize) -> Result<()> {
    if value.len() > MAX_CANARY_VALUE_BYTES {
        return Err(canary_error(format!(
            "{field}[{index}].value is longer than {MAX_CANARY_VALUE_BYTES} bytes"
        )));
    }
    if !value.starts_with(CANARY_VALUE_PREFIX) {
        return Err(canary_error(format!(
            "{field}[{index}].value must start with {CANARY_VALUE_PREFIX:?}: a canary is \
             synthetic, and a value without the marker is indistinguishable from a real secret"
        )));
    }
    if !value.is_ascii() || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(canary_error(format!(
            "{field}[{index}].value must be printable ASCII without control characters"
        )));
    }
    Ok(())
}

fn validate_canary_hostname(name: &str, index: usize) -> Result<()> {
    crate::policy::validate_dns_name(name, &format!("canaries.hostnames[{index}]"), 2)?;
    let reserved = name
        .rsplit('.')
        .next()
        .is_some_and(|tld| CANARY_HOST_SUFFIXES.contains(&tld));
    if !reserved {
        return Err(canary_error(format!(
            "canaries.hostnames[{index}] must live under a reserved domain ({}) so it can never be \
             a real destination: {}",
            CANARY_HOST_SUFFIXES.join(", "),
            bounded(name)
        )));
    }
    Ok(())
}

fn validate_canary_credential(name: &str, index: usize) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        return Err(canary_error(format!(
            "canaries.credentials[{index}] must be 1..=128 bytes"
        )));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(canary_error(format!(
            "canaries.credentials[{index}] must be a bare credential name: {}",
            bounded(name)
        )));
    }
    Ok(())
}

fn bounded(value: &str) -> String {
    const LIMIT: usize = 64;
    if value.len() <= LIMIT {
        return value.to_owned();
    }
    let mut out: String = value.chars().take(LIMIT).collect();
    out.push('…');
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

/// The out-of-guest actions a firing is allowed to take.
///
/// A port, not an implementation: the guard gateway supplies the adapter that
/// cuts the attachment and one that hands the quarantine to the control plane.
/// Nothing in this crate can widen a policy or release a quarantine, and adding
/// a method here would be the only way to give it that power.
#[async_trait]
pub trait CanaryEnforcer: Send + Sync {
    /// Cuts the attachment's network.
    async fn cut(&self) -> Result<()>;

    /// Quarantines the sandbox described by `request`.
    async fn quarantine(&self, request: QuarantineRequest) -> Result<()>;
}

/// What one observation produced.
#[derive(Clone, Debug)]
pub struct CanaryOutcome {
    /// The firing, or `None` when nothing matched.
    pub trip: Option<CanaryTrip>,
    /// The record appended to the journal, when one was.
    pub event: Option<GuardEvent>,
    /// Whether the attachment's network was cut.
    pub cut: bool,
    /// Whether the sandbox was quarantined.
    pub quarantined: bool,
}

impl CanaryOutcome {
    fn clear() -> Self {
        Self {
            trip: None,
            event: None,
            cut: false,
            quarantined: false,
        }
    }
}

/// Watches guest actions against a policy's canaries and acts on a firing.
///
/// Cheap to hold and safe to share: it is immutable after construction, so every
/// task behind the gateway can hold the same one.
#[derive(Clone)]
pub struct CanaryMonitor {
    set: Arc<CanarySet>,
    identity: GuardIdentity,
    fence: GuardFence,
    events: Arc<dyn EventSink>,
    enforcer: Arc<dyn CanaryEnforcer>,
}

impl CanaryMonitor {
    /// Builds a monitor, or `None` when the policy configures no canary at all.
    ///
    /// Returning `None` rather than an inert monitor is deliberate: a caller
    /// cannot accidentally hold a monitor that observes and does nothing, which
    /// is the shape a silently-disarmed tripwire takes.
    pub fn new(
        config: &CanaryConfig,
        identity: GuardIdentity,
        fence: GuardFence,
        events: Arc<dyn EventSink>,
        enforcer: Arc<dyn CanaryEnforcer>,
    ) -> Result<Option<Self>> {
        let set = CanarySet::from_config(config)?;
        if !set.is_enabled() {
            return Ok(None);
        }
        Ok(Some(Self {
            set: Arc::new(set),
            identity,
            fence,
            events,
            enforcer,
        }))
    }

    /// The validated tripwire set, for a caller that wants to ask without
    /// recording or acting.
    pub fn canaries(&self) -> &CanarySet {
        &self.set
    }

    /// Scrubs every canary value out of `text`.
    pub fn redact(&self, text: &str) -> String {
        self.set.redact(text)
    }

    /// A guest read of `path` exposed a canary file.
    pub async fn observe_file_read(&self, path: &str) -> Result<CanaryOutcome> {
        self.observe(self.set.file_read(path)).await
    }

    /// A guest query for `name` resolved a canary hostname.
    pub async fn observe_dns_query(&self, name: &str) -> Result<CanaryOutcome> {
        self.observe(self.set.hostname_resolved(name)).await
    }

    /// A guest presented `presented` to the gateway and it named a canary
    /// credential.
    pub async fn observe_credential(&self, presented: &str) -> Result<CanaryOutcome> {
        self.observe(self.set.credential_presented(presented)).await
    }

    /// The one place a firing is turned into telemetry and an action.
    ///
    /// Cuts and journals before the durable quarantine callback. A slow sink
    /// cannot buy an egress window, and the callback can collect its evidence.
    async fn observe(&self, trip: Option<CanaryTrip>) -> Result<CanaryOutcome> {
        let Some(trip) = trip else {
            return Ok(CanaryOutcome::clear());
        };
        // Contain and journal before calling back into the control plane. The
        // callback may collect this very journal and pause the guest; holding
        // attachment locks or appending afterward would lose its evidence.
        tracing::warn!(
            sandbox_id = %self.identity.sandbox_id,
            canary = %trip.reference,
            rule = trip.rule,
            "guard canary tripped"
        );
        let input = self.event_input(&trip);
        let reference = trip.reference.clone();
        let sandbox_id = self.identity.sandbox_id;
        let enforcer = Arc::clone(&self.enforcer);
        let events = Arc::clone(&self.events);
        let request = QuarantineRequest {
            fence: self.fence,
            policy_hash: self.identity.policy_hash.clone(),
            rules: vec![RuleTrigger {
                rule: trip.rule.to_owned(),
                first_event_sequence: None,
                evidence_references: vec![reference.clone()],
            }],
        };
        // The whole containment sequence runs in a task of its own, and the
        // caller waits for it when it can. Two callers can otherwise cancel the
        // evidence mid-flight: a DNS server whose latched cut it selects on, or
        // a request handler whose client disconnected. Both drop this future,
        // which would leave a cut with no journal record and no durable
        // quarantine - a tripwire that fires and is then denied its own
        // evidence. A spawned task survives its parent being dropped.
        let contain = async move {
            enforcer.cut().await.map_err(|error| {
                tracing::error!(
                    %sandbox_id,
                    canary = %reference,
                    %error,
                    "guard canary cut failed before the journal record"
                );
                error
            })?;
            let event = events.append(input).await.map_err(|error| {
                tracing::error!(
                    %sandbox_id,
                    canary = %reference,
                    %error,
                    "guard canary journal append failed after the cut"
                );
                error
            })?;
            let mut request = request;
            let quarantined = match trip.response {
                CanaryResponse::Cut => false,
                CanaryResponse::Quarantine => {
                    request.rules[0]
                        .evidence_references
                        .push(event.current_hash.clone());
                    enforcer.quarantine(request).await?;
                    true
                }
            };
            Ok::<CanaryOutcome, crate::GuardError>(CanaryOutcome {
                trip: Some(trip),
                event: Some(event),
                cut: true,
                quarantined,
            })
        };
        Ok(match tokio::runtime::Handle::try_current() {
            Ok(_) => {
                let joined = tokio::spawn(contain).await.map_err(|error| {
                    crate::GuardError::Unavailable(format!(
                        "canary containment did not complete: {error}"
                    ))
                })?;
                joined?
            }
            // No runtime to spawn into, which is a synchronous caller such as a
            // test: containment still runs, it just cannot outlive this future.
            Err(_) => contain.await?,
        })
    }

    /// The journal record for a firing.
    ///
    /// Every field is either the identity the gateway already holds or a static
    /// string from this module. There is no path from guest input or from a
    /// canary value into this record, which is the property the redaction above
    /// exists to protect and the tests below exist to hold.
    fn event_input(&self, trip: &CanaryTrip) -> EventInput {
        EventInput {
            sandbox_id: self.identity.sandbox_id,
            tenant_id: self.identity.tenant_id,
            policy_hash: self.identity.policy_hash.clone(),
            category: trip.category(),
            decision: trip.decision(),
            reason: trip.reason.to_owned(),
            destination: Some(trip.reference.clone()),
            request_bytes: 0,
            response_bytes: 0,
            duration_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compiler::{OperatorBoundary, compile},
        events::{FileEventSink, read_events, verify_chain},
        policy::{CanarySpec, GuardPolicy},
    };
    use std::path::PathBuf;

    const SECRET: &str = "aiec-canary:ssh-private-key-0000000000000000";
    const HOST: &str = "exfil.canary.invalid";
    const CREDENTIAL: &str = "exfil-canary-credential";

    /// Records what it was asked to do, so a test can prove the order the
    /// monitor acts in rather than only that it acted.
    #[derive(Default)]
    struct Recorder {
        cuts: std::sync::Mutex<u32>,
        quarantines: std::sync::Mutex<Vec<QuarantineRequest>>,
        /// How long a cut takes, so a test can cancel a caller mid-containment.
        cut_delay_ms: std::sync::atomic::AtomicU64,
    }

    impl Recorder {
        fn slow_cut(&self, millis: u64) {
            self.cut_delay_ms
                .store(millis, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CanaryEnforcer for Recorder {
        async fn cut(&self) -> Result<()> {
            *self.cuts.lock().expect("recorder") += 1;
            let delay = self.cut_delay_ms.load(std::sync::atomic::Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            Ok(())
        }

        async fn quarantine(&self, request: QuarantineRequest) -> Result<()> {
            self.quarantines.lock().expect("recorder").push(request);
            Ok(())
        }
    }

    struct Fixture {
        directory: PathBuf,
        journal: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn config_with(
        files: Vec<CanarySpec>,
        hostnames: Vec<String>,
        credentials: Vec<String>,
    ) -> CanaryConfig {
        CanaryConfig {
            files,
            hostnames,
            credentials,
        }
    }

    fn default_config() -> CanaryConfig {
        config_with(
            vec![CanarySpec {
                path: "/root/.ssh/id_ed25519".into(),
                value: SECRET.into(),
            }],
            vec![HOST.into()],
            vec![CREDENTIAL.into()],
        )
    }

    async fn monitor(config: CanaryConfig) -> (CanaryMonitor, Arc<Recorder>, Fixture) {
        let directory = std::env::temp_dir().join(format!("aiec-canary-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("temp dir");
        let journal = directory.join("events.jsonl");
        let sink = Arc::new(FileEventSink::open(&journal).expect("journal"));
        let recorder = Arc::new(Recorder::default());
        let identity = GuardIdentity {
            sandbox_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            policy_hash: compile(&GuardPolicy::default(), &OperatorBoundary::default())
                .map(|compiled| compiled.policy_hash().to_owned())
                .unwrap_or_else(|_| "policy-hash".into()),
        };
        let enforcer: Arc<dyn CanaryEnforcer> = recorder.clone();
        let monitor = CanaryMonitor::new(
            &config,
            identity,
            GuardFence {
                lease_id: uuid::Uuid::new_v4(),
                generation: 7,
            },
            sink,
            enforcer,
        )
        .expect("monitor")
        .expect("a configured canary policy yields a monitor");
        (
            monitor,
            Arc::clone(&recorder),
            Fixture { directory, journal },
        )
    }

    fn set(config: CanaryConfig) -> CanarySet {
        CanarySet::from_config(&config).expect("valid canary set")
    }

    #[tokio::test]
    async fn reading_a_canary_file_is_high_severity_and_cuts() {
        let (monitor, recorder, fixture) = monitor(default_config()).await;
        let outcome = monitor
            .observe_file_read("/root/.ssh/id_ed25519")
            .await
            .expect("observation");
        let trip = outcome.trip.expect("the canary fired");
        assert_eq!(trip.kind, CanaryKind::File);
        assert_eq!(trip.severity, CanarySeverity::High);
        assert_eq!(trip.response, CanaryResponse::Cut);
        assert!(outcome.cut, "a high-severity firing cuts the network");
        assert!(!outcome.quarantined, "a file read is not a quarantine");
        assert_eq!(*recorder.cuts.lock().expect("cuts"), 1);
        assert!(recorder.quarantines.lock().expect("quarantines").is_empty());

        let events = read_events(&fixture.journal).expect("journal");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].category, Category::Credential);
        assert_eq!(events[0].decision, Decision::Cut);
        verify_chain(&events).expect("chain");
    }

    /// An enumeration finds the canary by listing the directory that holds it,
    /// so listing has to count as the exposure it is.
    #[tokio::test]
    async fn listing_the_directory_that_holds_a_canary_counts_as_reading_it() {
        let (monitor, _, _) = monitor(default_config()).await;
        assert!(
            monitor
                .observe_file_read("/root/.ssh")
                .await
                .expect("observation")
                .trip
                .is_some(),
            "a directory listing exposes the canary inside it"
        );
        assert!(
            monitor
                .observe_file_read("/root")
                .await
                .expect("observation")
                .trip
                .is_none(),
            "a parent of the canary's directory does not contain it"
        );
    }

    #[tokio::test]
    async fn resolving_a_canary_hostname_is_high_severity_and_cuts() {
        let (monitor, recorder, fixture) = monitor(default_config()).await;
        let outcome = monitor.observe_dns_query(HOST).await.expect("observation");
        let trip = outcome.trip.expect("the canary fired");
        assert_eq!(trip.kind, CanaryKind::Hostname);
        assert_eq!(trip.severity, CanarySeverity::High);
        assert!(outcome.cut);
        assert!(!outcome.quarantined);
        assert_eq!(*recorder.cuts.lock().expect("cuts"), 1);

        // A subdomain of the canary is the same tripwire, and the wire spelling
        // with a trailing root dot and mixed case is the same query.
        assert!(
            monitor
                .observe_dns_query("Metrics.Exfil.Canary.Invalid.")
                .await
                .expect("observation")
                .trip
                .is_some(),
            "a subdomain of a canary is the canary"
        );

        let events = read_events(&fixture.journal).expect("journal");
        assert_eq!(events[0].category, Category::Dns);
        verify_chain(&events).expect("chain");
    }

    /// A caller that abandons its observation takes nothing with it.
    ///
    /// The cut is what latches, and latching is what the DNS servers and the
    /// runtime's file-read handlers watch: a containment that ran inline could
    /// be cancelled by the very latch it installed, leaving the guest cut with
    /// no canary record and no durable quarantine behind it.
    #[tokio::test]
    async fn containment_completes_after_its_caller_is_cancelled() {
        let (monitor, recorder, fixture) = monitor(default_config()).await;
        recorder.slow_cut(250);
        let caller = tokio::spawn(async move { monitor.observe_dns_query(HOST).await });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        caller.abort();
        let _ = caller.await;

        let mut recorded = false;
        for _ in 0..200 {
            let events = read_events(&fixture.journal).expect("journal");
            recorded = events
                .iter()
                .any(|event| event.category == Category::Dns && event.decision == Decision::Cut);
            if recorded {
                verify_chain(&events).expect("chain");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            recorded,
            "a cancelled caller still leaves the canary record in the journal"
        );
        assert_eq!(
            *recorder.cuts.lock().expect("cuts"),
            1,
            "the network is cut exactly once"
        );
    }

    #[tokio::test]
    async fn presenting_a_canary_credential_quarantines_immediately() {
        let (monitor, recorder, fixture) = monitor(default_config()).await;
        let outcome = monitor
            .observe_credential(CREDENTIAL)
            .await
            .expect("observation");
        let trip = outcome.trip.expect("the canary fired");
        assert_eq!(trip.kind, CanaryKind::Credential);
        assert_eq!(trip.severity, CanarySeverity::Critical);
        assert_eq!(trip.response, CanaryResponse::Quarantine);
        assert!(
            outcome.quarantined,
            "a credential canary is an immediate quarantine"
        );
        assert!(outcome.cut, "quarantining also takes the network");

        let events = read_events(&fixture.journal).expect("journal");
        let quarantines = recorder.quarantines.lock().expect("quarantines");
        assert_eq!(quarantines.len(), 1);
        assert_eq!(quarantines[0].fence.generation, 7);
        assert_eq!(quarantines[0].rules[0].rule, RULE_CANARY_CREDENTIAL);
        // The reference binds the callback to the exact host event it cut for:
        // the opaque canary reference, then that event's own hash.
        assert_eq!(
            quarantines[0].rules[0].evidence_references,
            vec![trip.reference.clone(), events[0].current_hash.clone()]
        );
        drop(quarantines);
        assert_eq!(events[0].decision, Decision::Quarantine);
        verify_chain(&events).expect("chain");
    }

    #[tokio::test]
    async fn ordinary_guest_actions_trip_nothing_and_change_nothing() {
        let (monitor, recorder, fixture) = monitor(default_config()).await;
        for path in ["/workspace/main.rs", "/root/.bashrc", "/"] {
            let outcome = monitor.observe_file_read(path).await.expect("observation");
            assert!(outcome.trip.is_none(), "{path} is not a canary");
        }
        for name in [
            "model.example-model.com",
            "canary.example",
            "notexfil.canary.invalid",
        ] {
            let outcome = monitor.observe_dns_query(name).await.expect("observation");
            assert!(outcome.trip.is_none(), "{name} is not a canary");
        }
        for credential in [
            "model-main",
            "EXFIL-CANARY-CREDENTIAL",
            "exfil-canary-credentia",
        ] {
            let outcome = monitor
                .observe_credential(credential)
                .await
                .expect("observation");
            assert!(outcome.trip.is_none(), "{credential} is not a canary");
        }
        assert_eq!(*recorder.cuts.lock().expect("cuts"), 0);
        assert!(recorder.quarantines.lock().expect("quarantines").is_empty());
        assert!(read_events(&fixture.journal).expect("journal").is_empty());
    }

    /// The journal is the artefact that leaves the host, so neither a canary
    /// value nor the canary's own name may appear anywhere in it.
    #[tokio::test]
    async fn no_canary_value_or_name_ever_reaches_the_journal() {
        let (monitor, _, fixture) = monitor(default_config()).await;
        monitor
            .observe_file_read("/root/.ssh/id_ed25519")
            .await
            .expect("observation");
        monitor.observe_dns_query(HOST).await.expect("observation");
        monitor
            .observe_credential(CREDENTIAL)
            .await
            .expect("observation");
        let raw = std::fs::read(&fixture.journal).expect("journal bytes");
        let text = String::from_utf8(raw).expect("journal is utf-8");
        for forbidden in [SECRET, HOST, CREDENTIAL, "/root/.ssh/id_ed25519"] {
            assert!(
                !text.contains(forbidden),
                "{forbidden:?} reached the journal: {text}"
            );
        }
        // The opaque reference is what an operator correlates with their policy.
        assert!(text.contains("file#0"), "{text}");
        assert!(text.contains("hostname#0"), "{text}");
        assert!(text.contains("credential#0"), "{text}");
    }

    #[tokio::test]
    async fn a_failing_enforcer_does_not_leave_the_sandbox_running() {
        struct Refuses;
        #[async_trait]
        impl CanaryEnforcer for Refuses {
            async fn cut(&self) -> Result<()> {
                Err(crate::GuardError::Unavailable("no enforcement".into()))
            }
            async fn quarantine(&self, _: QuarantineRequest) -> Result<()> {
                Err(crate::GuardError::Unavailable("no enforcement".into()))
            }
        }
        let directory = std::env::temp_dir().join(format!("aiec-canary-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("temp dir");
        let journal = directory.join("events.jsonl");
        let monitor = CanaryMonitor::new(
            &default_config(),
            GuardIdentity {
                sandbox_id: uuid::Uuid::new_v4(),
                tenant_id: uuid::Uuid::new_v4(),
                policy_hash: "policy-hash".into(),
            },
            GuardFence {
                lease_id: uuid::Uuid::new_v4(),
                generation: 1,
            },
            Arc::new(FileEventSink::open(&journal).expect("journal")),
            Arc::new(Refuses),
        )
        .expect("monitor")
        .expect("monitor");
        // The failure surfaces to the caller rather than being swallowed into a
        // "recorded" that never happened.
        monitor
            .observe_credential(CREDENTIAL)
            .await
            .expect_err("an unenforceable quarantine is an error, not a success");
        // Nothing was recorded, because the action comes first and it failed.
        assert!(read_events(&journal).expect("journal").is_empty());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_policy_with_no_canaries_yields_no_monitor() {
        let empty = CanaryConfig::default();
        assert!(!CanarySet::from_config(&empty).expect("set").is_enabled());
    }

    #[test]
    fn a_value_without_the_synthetic_marker_is_refused() {
        let config = config_with(
            vec![CanarySpec {
                path: "/root/.ssh/id_rsa".into(),
                value: "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
            }],
            Vec::new(),
            Vec::new(),
        );
        let error = CanarySet::from_config(&config).expect_err("a real secret is not a canary");
        assert!(error.to_string().contains("synthetic"), "{error}");
    }

    #[test]
    fn a_canary_hostname_outside_a_reserved_domain_is_refused() {
        let config = config_with(
            Vec::new(),
            vec!["exfil.attacker.example.com".into()],
            Vec::new(),
        );
        let error = CanarySet::from_config(&config).expect_err("a real domain is not a canary");
        assert!(error.to_string().contains("reserved domain"), "{error}");
        for tld in CANARY_HOST_SUFFIXES {
            assert!(
                CanarySet::from_config(&config_with(
                    Vec::new(),
                    vec![format!("exfil.canary.{tld}")],
                    Vec::new()
                ))
                .is_ok(),
                "{tld} is reserved and must be accepted"
            );
        }
    }

    #[test]
    fn a_relative_or_traversing_canary_path_is_refused() {
        for path in [".ssh/id_rsa", "/root/../../etc/shadow", "/root/\u{7f}id"] {
            let error = CanarySet::from_config(&config_with(
                vec![CanarySpec {
                    path: path.into(),
                    value: SECRET.into(),
                }],
                Vec::new(),
                Vec::new(),
            ))
            .expect_err("only a plain absolute path inside the guest is a canary path");
            assert!(
                !error.to_string().is_empty(),
                "{path} must be refused with a reason"
            );
        }
    }

    #[test]
    fn duplicate_and_over_large_canary_sets_are_refused() {
        let spec = |path: &str| CanarySpec {
            path: path.into(),
            value: SECRET.into(),
        };
        let error = CanarySet::from_config(&config_with(
            vec![spec("/a/one"), spec("/a/one")],
            Vec::new(),
            Vec::new(),
        ))
        .expect_err("a repeated canary is a configuration mistake");
        assert!(error.to_string().contains("repeats"), "{error}");

        let error = CanarySet::from_config(&config_with(
            vec![spec("/a/one"); MAX_CANARY_FILES + 1],
            Vec::new(),
            Vec::new(),
        ))
        .expect_err("an unbounded canary list is refused");
        assert!(error.to_string().contains("maximum"), "{error}");
    }

    /// A credential name is compared against attacker-supplied bytes, so a
    /// prefix of the canary must not match: the comparison is over the whole
    /// value, not a prefix of it.
    #[test]
    fn a_credential_comparison_is_not_a_prefix_match() {
        let canaries = set(default_config());
        assert!(canaries.credential_presented(CREDENTIAL).is_some());
        for presented in [
            CREDENTIAL.to_owned() + "x",
            "x".to_owned() + CREDENTIAL,
            String::new(),
        ] {
            assert!(
                canaries.credential_presented(&presented).is_none(),
                "{presented:?} is not the canary"
            );
        }
    }

    /// Free text derived from guest input is scrubbed of every canary value
    /// before it can reach a log line or an error.
    #[tokio::test]
    async fn redaction_removes_every_canary_value_from_free_text() {
        let (monitor, _, _) = monitor(default_config()).await;
        let text = format!("read {SECRET} then {SECRET} again");
        let scrubbed = monitor.redact(&text);
        assert_eq!(scrubbed, "read [canary] then [canary] again");
        assert!(!scrubbed.contains(SECRET));

        // Text with nothing to hide is returned unchanged.
        assert_eq!(monitor.redact("nothing here"), "nothing here");
    }

    #[test]
    fn synthetic_values_are_distinguishable_and_carry_the_marker() {
        let first = CanarySet::synthetic_value("ssh-key");
        let second = CanarySet::synthetic_value("ssh-key");
        assert_ne!(first, second, "two canaries must be distinguishable");
        assert!(first.starts_with(CANARY_VALUE_PREFIX));
        let config = config_with(
            vec![CanarySpec {
                path: "/root/.ssh/id_rsa".into(),
                value: first,
            }],
            Vec::new(),
            Vec::new(),
        );
        assert!(CanarySet::from_config(&config).is_ok());
    }
}
