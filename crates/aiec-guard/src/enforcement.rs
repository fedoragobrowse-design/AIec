//! Out-of-guest network enforcement for one Guard attachment.
//!
//! Everything in this module runs on the host, outside the guest, and owns
//! nothing but the two nftables tables it creates per attachment. The host's
//! other tables are never read for a decision, never flushed and never deleted,
//! so enforcing or releasing a sandbox cannot change unrelated traffic.
//!
//! The rules enforce one property: the guest reaches the host only at the
//! gateway's DNS and model broker listeners, from the source address the
//! operator assigned to it. Everything else about that guest, including IPv6,
//! forwarded traffic, established flows and any address it claims to be, is
//! denied and counted.

use crate::compiler::CompiledPolicy;
use crate::{GuardError, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::timeout;
use uuid::Uuid;

mod render;

use render::{
    COUNTER_BLOCKED_RANGE, COUNTER_BROKER_PERMITTED, COUNTER_DNS_PERMITTED, COUNTER_IPV6,
    COUNTER_OTHER_DENIED, FAMILY_V4, FAMILY_V6, RuleModel, RuleParams,
};
pub use render::{Transport, Verdict};

/// The nft binary Guard drives. It is a fixed program name and never guest
/// input; a guest that could choose it would choose what enforces it.
const NFT_PROGRAM: &str = "nft";
/// Every nft invocation is bounded so a wedged or hostile host cannot hang the
/// gateway's control path.
const NFT_TIMEOUT: Duration = Duration::from_secs(10);
/// Diagnostics are read through a bounded pipe rather than into memory.
const NFT_STDERR_LIMIT: u64 = 8 * 1024;
/// Only this much of an nft diagnostic is kept in an error.
const NFT_DETAIL_LIMIT: usize = 200;
/// A JSON listing is read through a bounded pipe.
const NFT_STDOUT_LIMIT: u64 = 4 * 1024 * 1024;
/// Table used by `health` to prove both families can be created without
/// mutating the host: `nft --check` never sends a change.
const HEALTH_PROBE_TABLE: &str = "aiec_guard_health_probe";

/// One guest attached to the host through a TAP interface.
///
/// The Linux network backend hands this to the gateway, which persists it as
/// JSON outside the guest so a restart or a watchdog can re-derive exactly the
/// attachment whose ruleset is installed. Unknown fields are refused: a
/// document that describes an attachment Guard cannot reconstruct exactly is
/// not silently accepted as an older shape.
///
/// `interface` is a host side device name supplied by the network backend. It
/// is validated again before it reaches an nft expression, so a persisted or
/// hand-edited document cannot inject a rule.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardAttachment {
    pub sandbox_id: Uuid,
    pub tenant_id: Uuid,
    pub interface: String,
    pub guest_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub dns_port: u16,
    pub broker_port: u16,
}

impl GuardAttachment {
    /// The nftables table name Guard owns for this attachment. It contains the
    /// complete sandbox UUID.
    pub fn table_name(&self) -> String {
        render::table_name(&self.sandbox_id.simple().to_string())
    }

    /// Re-derives the model this attachment is enforced by, so a persisted
    /// document is only usable if it still describes a valid attachment.
    pub fn validate(&self) -> Result<()> {
        EnforcementModel::cut(self).map(|_| ())
    }
}

/// Named per-category packet counters an operator or watchdog can read.
///
/// The counters are objects in the attachment's own table, not in any host
/// table, and the snapshot below is read back from the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CounterKind {
    /// Packets aimed at a range the operator boundary blocks.
    BlockedRange,
    /// Packets denied for any other reason, spoofed sources included.
    OtherDenied,
    /// Every IPv6 packet seen on the guest interface.
    Ipv6,
    /// Permitted DNS traffic from the assigned guest source.
    DnsPermitted,
    /// Permitted model broker traffic from the assigned guest source.
    BrokerPermitted,
}

impl CounterKind {
    /// Every counter Guard maintains, in report order.
    pub const ALL: [CounterKind; 5] = [
        CounterKind::BlockedRange,
        CounterKind::OtherDenied,
        CounterKind::Ipv6,
        CounterKind::DnsPermitted,
        CounterKind::BrokerPermitted,
    ];

    /// The named nftables counter object this kind is stored in.
    pub fn nft_name(self) -> &'static str {
        match self {
            CounterKind::BlockedRange => COUNTER_BLOCKED_RANGE,
            CounterKind::OtherDenied => COUNTER_OTHER_DENIED,
            CounterKind::Ipv6 => COUNTER_IPV6,
            CounterKind::DnsPermitted => COUNTER_DNS_PERMITTED,
            CounterKind::BrokerPermitted => COUNTER_BROKER_PERMITTED,
        }
    }
    /// The nftables family holding this counter.
    pub fn family(self) -> &'static str {
        match self {
            CounterKind::Ipv6 => FAMILY_V6,
            _ => FAMILY_V4,
        }
    }

    fn from_nft_name(name: &str) -> Option<Self> {
        CounterKind::ALL
            .into_iter()
            .find(|kind| kind.nft_name() == name)
    }
}

/// Authoritative packet counts for one attachment, read back from the kernel.
///
/// Applying, cutting or restoring a policy replaces the attachment's rules but
/// keeps its named counters, so these counts are cumulative for as long as the
/// attachment is enforced: a watchdog can read the blocked-range and IPv6
/// attempts a guest made across a cut, not only since the last generation. A
/// snapshot is only meaningful together with the table it came from, which is
/// named by [`CounterSnapshot::table`], and a missing table is an error rather
/// than a silent zero.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterSnapshot {
    pub table: String,
    pub blocked_range: u64,
    pub other_denied: u64,
    pub ipv6: u64,
    pub dns_permitted: u64,
    pub broker_permitted: u64,
}

impl CounterSnapshot {
    pub fn get(&self, kind: CounterKind) -> u64 {
        match kind {
            CounterKind::BlockedRange => self.blocked_range,
            CounterKind::OtherDenied => self.other_denied,
            CounterKind::Ipv6 => self.ipv6,
            CounterKind::DnsPermitted => self.dns_permitted,
            CounterKind::BrokerPermitted => self.broker_permitted,
        }
    }
    /// Assigns the count the kernel reports for one counter.
    pub fn set(&mut self, kind: CounterKind, packets: u64) {
        match kind {
            CounterKind::BlockedRange => self.blocked_range = packets,
            CounterKind::OtherDenied => self.other_denied = packets,
            CounterKind::Ipv6 => self.ipv6 = packets,
            CounterKind::DnsPermitted => self.dns_permitted = packets,
            CounterKind::BrokerPermitted => self.broker_permitted = packets,
        }
    }

    /// Records one synthetic decision, used by the in-memory backend.
    fn record(&mut self, counter: &str) {
        if let Some(kind) = CounterKind::from_nft_name(counter) {
            let next = self.get(kind).saturating_add(1);
            self.set(kind, next);
        }
    }

    /// Permitted packets across both allowed listeners.
    pub fn permitted(&self) -> u64 {
        self.dns_permitted.saturating_add(self.broker_permitted)
    }

    /// Denied packets across every denied category.
    pub fn denied(&self) -> u64 {
        self.blocked_range
            .saturating_add(self.other_denied)
            .saturating_add(self.ipv6)
    }

    pub fn total(&self) -> u64 {
        self.permitted().saturating_add(self.denied())
    }
}

/// What a compiled policy allows this attachment to reach.
///
/// This is the decision model the generated nftables text implements, kept
/// public so a gateway, a watchdog or a test can ask the same question the
/// kernel will be asked, without parsing rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnforcementModel {
    inner: RuleModel,
}

impl EnforcementModel {
    /// Reduces a compiled policy and an attachment to the exact model that is
    /// enforced. `cut` builds the deny-everything generation a cut installs.
    ///
    /// A permit exists only where the policy itself gives the guest something
    /// to reach. The gateway listeners are the only permitted destination, so
    /// `permits_dns` is true exactly when the policy configures a DNS scope and
    /// `permits_broker` exactly when the policy gives the guest at least one
    /// destination to reach at all: a model endpoint, an allowlisted egress
    /// rule, or both. Both are read from the compiled policy rather than from a
    /// template name, so an explicit policy and a template-built one are judged
    /// identically.
    ///
    /// The broker is Guard's enforcement point, not a privilege. A policy that
    /// names an allowlisted destination without naming a model — the documented
    /// `read_only_api` shape, and what an OpenShell import produces — is
    /// governed entirely by rules the broker applies on the way through, so a
    /// broker permit that depended on a model endpoint would seal a guest whose
    /// allowlist it could otherwise enforce. What the guest can then reach is
    /// still only what its own policy permits, one rule at a time, inside the
    /// gateway. Only `no-network`, which has neither, keeps neither listener.
    pub fn build(policy: &CompiledPolicy, attachment: &GuardAttachment, cut: bool) -> Result<Self> {
        let permits_dns = !policy.dns().allowed_zones.is_empty();
        let permits_broker =
            policy.model_endpoint().is_some() || !policy.policy().network.egress.is_empty();
        // Blocked ranges are the boundary's own denied networks: the operator's
        // additions plus the ranges that can never be authorized, which the
        // runtime fills with the gateway, the assigned guest, peer sandboxes
        // and management addresses. A range in this set is denied at the kernel
        // whatever a policy or an operator test mapping says, and it is counted
        // as a blocked-range attempt rather than as generic denial.
        //
        // Anything outside this set is still denied, by the catch-all drop, so
        // this set classifies denials and never widens them.
        let boundary = policy.boundary();
        let mut blocked_ipv4: Vec<String> = boundary
            .denied_networks()
            .filter(|cidr| matches!(cidr, ipnet::IpNet::V4(_)))
            .map(|cidr| cidr.to_string())
            .collect();
        blocked_ipv4.sort();
        blocked_ipv4.dedup();
        let inner = RuleModel::new(RuleParams {
            sandbox: attachment.sandbox_id.simple().to_string(),
            interface: attachment.interface.clone(),
            guest_ip: attachment.guest_ip,
            gateway_ip: attachment.gateway_ip,
            dns_port: attachment.dns_port,
            broker_port: attachment.broker_port,
            permits_dns,
            permits_broker,
            cut,
            blocked_ipv4,
        })
        .map_err(GuardError::Policy)?;
        Ok(Self { inner })
    }

    /// The deny-everything model a cut installs, built from the attachment
    /// alone so cutting never depends on a policy still being available.
    pub fn cut(attachment: &GuardAttachment) -> Result<Self> {
        let inner = RuleModel::new(RuleParams {
            sandbox: attachment.sandbox_id.simple().to_string(),
            interface: attachment.interface.clone(),
            guest_ip: attachment.guest_ip,
            gateway_ip: attachment.gateway_ip,
            dns_port: attachment.dns_port,
            broker_port: attachment.broker_port,
            permits_dns: false,
            permits_broker: false,
            cut: true,
            blocked_ipv4: Vec::new(),
        })
        .map_err(GuardError::Policy)?;
        Ok(Self { inner })
    }

    /// The table this model owns.
    pub fn table(&self) -> &str {
        &self.inner.table
    }

    /// The `nft -f` batch that creates this model's tables and rules, assuming
    /// no generation is installed yet.
    pub fn ruleset(&self) -> Result<String> {
        self.inner.render().map_err(GuardError::Policy)
    }

    /// The `nft -f` batch that makes this model the attachment's only
    /// generation, replacing any previous one within a single transaction.
    pub fn flushable_ruleset(&self) -> Result<String> {
        self.inner.render_replace().map_err(GuardError::Policy)
    }

    /// Whether a packet from the guest to the host is permitted.
    pub fn permits(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        transport: Transport,
        port: u16,
    ) -> bool {
        self.inner.permits(source, destination, transport, port)
    }

    /// The verdict and the named counter that records it.
    pub fn verdict(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        transport: Transport,
        port: u16,
    ) -> Verdict {
        self.inner.verdict(source, destination, transport, port)
    }

    /// IPv6 is never permitted, in any state this model can be in.
    pub fn permits_ipv6(&self) -> bool {
        self.inner.permits_ipv6()
    }
}

/// The complete `nft -f` batch enforcing `policy` for `attachment`, or the
/// deny-everything batch when `cut` is set.
pub fn ruleset(policy: &CompiledPolicy, attachment: &GuardAttachment, cut: bool) -> Result<String> {
    EnforcementModel::build(policy, attachment, cut)?.ruleset()
}

/// Out-of-guest enforcement of one compiled policy.
#[async_trait]
pub trait EnforcementBackend: Send + Sync {
    /// Installs the ruleset for `attachment`, replacing any previous
    /// generation atomically.
    async fn apply_policy(
        &self,
        policy: &CompiledPolicy,
        attachment: &GuardAttachment,
    ) -> Result<()>;

    /// Removes every rule Guard installed for `attachment`. Idempotent: an
    /// attachment that is already removed succeeds, a real failure does not.
    async fn remove_policy(&self, attachment: &GuardAttachment) -> Result<()>;

    /// Drops every packet of `attachment` immediately.
    async fn cut_network(&self, attachment: &GuardAttachment) -> Result<()>;

    /// Reinstalls the permitted ruleset after a cut.
    async fn restore_network(
        &self,
        policy: &CompiledPolicy,
        attachment: &GuardAttachment,
    ) -> Result<()>;

    /// Proves the enforcement substrate is usable.
    async fn health(&self) -> Result<()>;
}

/// Reads the authoritative packet counters of an enforced attachment.
#[async_trait]
pub trait CounterSource: Send + Sync {
    /// The kernel's counters for `attachment`.
    ///
    /// Fails when the attachment has no enforcement table, because a missing
    /// table is a failed state and not a quiet zero.
    async fn counters(&self, attachment: &GuardAttachment) -> Result<CounterSnapshot>;

    /// A single counter, for callers that poll one category.
    async fn counter(&self, attachment: &GuardAttachment, kind: CounterKind) -> Result<u64> {
        Ok(self.counters(attachment).await?.get(kind))
    }
}

/// Enforces attachments with the host's nftables.
#[derive(Clone, Debug)]
pub struct NftablesBackend {
    program: String,
    timeout: Duration,
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NftablesBackend {
    pub fn new() -> Self {
        Self {
            program: NFT_PROGRAM.to_string(),
            timeout: NFT_TIMEOUT,
        }
    }
    /// Points the backend at another `nft` binary, so a test can prove a real
    /// failure propagates. Gated so the shipped library never carries it.
    #[cfg(test)]
    fn with_program(mut self, program: &str) -> Self {
        self.program = program.to_string();
        self
    }

    /// Installs `model` as the attachment's only generation, in one atomic
    /// nftables transaction that replaces whichever generation was there.
    ///
    /// The batch is `add table` then `flush table` then the full rule set. Every
    /// statement is idempotent, so one transaction is a complete replacement
    /// whether or not the table already existed, with no window in which a
    /// concurrent `cut_network` can interleave between deciding what to delete
    /// and deleting it. `flush table` removes the previous generation's rules
    /// while keeping the table, its chains and its named counters, so the
    /// counters accumulate across applies instead of restarting at zero and a
    /// watchdog can read one cumulative count per attachment.
    async fn install(&self, model: &EnforcementModel) -> Result<()> {
        let script = model.flushable_ruleset()?;
        self.apply_batch(&script).await
    }

    /// Removes only the tables this attachment owns, and only if they exist.
    ///
    /// This really removes them: an attachment with no table afterwards is no
    /// longer enforced at all, which is what releasing a sandbox means.
    async fn uninstall(&self, attachment: &GuardAttachment) -> Result<()> {
        let table = attachment.table_name();
        let present = self.existing_tables().await?;
        let batch = Self::removal_batch(&table, &present);
        if batch.is_empty() {
            // Already removed, or never enforced: both are the same end state,
            // so neither is a failure.
            return Ok(());
        }
        self.apply_batch(&batch).await
    }

    /// The delete statements for an attachment's own tables that are present.
    ///
    /// A table that is absent is simply not named, so a second removal is a no-op
    /// rather than an error, while a real nft failure still propagates.
    fn removal_batch(table: &str, present: &BTreeSet<(String, String)>) -> String {
        let mut batch = String::new();
        for family in [FAMILY_V4, FAMILY_V6] {
            if present.contains(&(family.to_string(), table.to_string())) {
                batch.push_str(&format!("delete table {family} {table}\n"));
            }
        }
        batch
    }

    async fn apply_batch(&self, script: &str) -> Result<()> {
        let (success, _stdout, detail) = self
            .run(&["-f", "-"], Some(script), false)
            .await
            .map_err(|error| {
                GuardError::Unavailable(format!(
                    "nft rejected the enforcement batch for a Guard attachment: {error}"
                ))
            })?;
        if success {
            Ok(())
        } else {
            Err(GuardError::Unavailable(format!(
                "nft did not apply the enforcement batch: {detail}"
            )))
        }
    }

    async fn existing_tables(&self) -> Result<BTreeSet<(String, String)>> {
        let (success, stdout, detail) = self.run(&["-j", "list", "tables"], None, true).await?;
        if !success {
            return Err(GuardError::Unavailable(format!(
                "nft could not list the host's tables: {detail}"
            )));
        }
        Ok(parse_tables(&stdout))
    }

    async fn counter_listing(&self, family: &str, table: &str) -> Result<HashMap<String, u64>> {
        let (success, stdout, detail) = self
            .run(
                &["-j", "list", "counters", "table", family, table],
                None,
                true,
            )
            .await?;
        if !success {
            return Err(GuardError::Unavailable(format!(
                "nft could not read the enforcement counters of table {table}: {detail}"
            )));
        }
        parse_counters(&stdout)
    }

    /// Runs nft with a bounded pipe in each direction and a bounded wait. The
    /// child is killed if the call is dropped or overruns, so a wedged
    /// nftables cannot outlive the control path that started it.
    async fn run(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        capture_stdout: bool,
    ) -> Result<(bool, Vec<u8>, String)> {
        let mut command = Command::new(&self.program);
        command
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(if capture_stdout {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| {
            GuardError::Unavailable(format!("{} could not be executed: {error}", self.program))
        })?;

        if let Some(script) = stdin
            && let Some(mut pipe) = child.stdin.take()
        {
            let written = timeout(self.timeout, pipe.write_all(script.as_bytes())).await;
            match written {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    let _ = child.start_kill();
                    return Err(GuardError::Unavailable(format!(
                        "{} did not accept the ruleset: {error}",
                        self.program
                    )));
                }
                Err(_) => {
                    let _ = child.start_kill();
                    return Err(GuardError::Unavailable(format!(
                        "{} did not accept the ruleset within {:?}",
                        self.program, self.timeout
                    )));
                }
            }
        }

        let stderr = child.stderr.take();
        let stdout = child.stdout.take();
        let collect = async {
            let mut error_bytes = Vec::new();
            let mut output_bytes = Vec::new();
            if let Some(pipe) = stderr {
                let _ = pipe
                    .take(NFT_STDERR_LIMIT)
                    .read_to_end(&mut error_bytes)
                    .await;
            }
            if let Some(pipe) = stdout {
                let _ = pipe
                    .take(NFT_STDOUT_LIMIT)
                    .read_to_end(&mut output_bytes)
                    .await;
            }
            (error_bytes, output_bytes)
        };
        let (status, (error_bytes, output_bytes)) =
            match timeout(self.timeout, async { tokio::join!(child.wait(), collect) }).await {
                Ok(joined) => (joined.0?, joined.1),
                Err(_) => {
                    let _ = child.start_kill();
                    return Err(GuardError::Unavailable(format!(
                        "{} did not finish within {:?}",
                        self.program, self.timeout
                    )));
                }
            };
        Ok((status.success(), output_bytes, summarize(&error_bytes)))
    }
}

#[async_trait]
impl EnforcementBackend for NftablesBackend {
    async fn apply_policy(
        &self,
        policy: &CompiledPolicy,
        attachment: &GuardAttachment,
    ) -> Result<()> {
        let model = EnforcementModel::build(policy, attachment, false)?;
        self.install(&model).await
    }

    async fn remove_policy(&self, attachment: &GuardAttachment) -> Result<()> {
        self.uninstall(attachment).await
    }

    async fn cut_network(&self, attachment: &GuardAttachment) -> Result<()> {
        // The cut is a whole table replacement in a single transaction, so the
        // guest's traffic is denied the moment the batch commits. It is built
        // from the attachment alone: a cut must still work when the policy that
        // permitted the traffic is gone.
        let model = EnforcementModel::cut(attachment)?;
        self.install(&model).await
    }

    async fn restore_network(
        &self,
        policy: &CompiledPolicy,
        attachment: &GuardAttachment,
    ) -> Result<()> {
        let model = EnforcementModel::build(policy, attachment, false)?;
        self.install(&model).await
    }

    async fn health(&self) -> Result<()> {
        // The binary must run, the kernel must answer, and both families Guard
        // enforces in must be creatable. `nft --check` validates without
        // changing the host, so health can never mutate the firewall.
        let (success, _stdout, detail) = self.run(&["--version"], None, false).await?;
        if !success {
            return Err(GuardError::Unavailable(format!(
                "{} did not report a version: {detail}",
                self.program
            )));
        }
        let (success, _stdout, detail) = self.run(&["list", "ruleset"], None, false).await?;
        if !success {
            return Err(GuardError::Unavailable(format!(
                "{} could not read the host ruleset: {detail}",
                self.program
            )));
        }
        for family in [FAMILY_V4, FAMILY_V6] {
            let probe = format!("add table {family} {HEALTH_PROBE_TABLE}");
            let (success, _stdout, detail) = self
                .run(&["--check", "-f", "-"], Some(&probe), false)
                .await?;
            if !success {
                return Err(GuardError::Unavailable(format!(
                    "{} cannot enforce the {family} family: {detail}",
                    self.program
                )));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CounterSource for NftablesBackend {
    async fn counters(&self, attachment: &GuardAttachment) -> Result<CounterSnapshot> {
        let table = attachment.table_name();
        let mut snapshot = CounterSnapshot {
            table: table.clone(),
            ..CounterSnapshot::default()
        };
        // Both families are required: a snapshot missing the IPv4 or the IPv6
        // half would under-report what the guest attempted. A counter is only
        // taken from the family it is declared in, so a name that somehow
        // appeared in both listings cannot overwrite the other family's count.
        for family in [FAMILY_V4, FAMILY_V6] {
            let listing = self.counter_listing(family, &table).await?;
            for (name, packets) in listing {
                if let Some(kind) = CounterKind::from_nft_name(&name)
                    && kind.family() == family
                {
                    snapshot.set(kind, packets);
                }
            }
        }
        Ok(snapshot)
    }
}

/// Extracts `(family, table)` pairs from `nft -j list tables`.
fn parse_tables(bytes: &[u8]) -> BTreeSet<(String, String)> {
    let mut tables = BTreeSet::new();
    // `nft -j list tables` wraps its output in an `nftables` object rather than
    // emitting the rule list bare, so both spellings are accepted.
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return tables;
    };
    let entries = match &value {
        Value::Array(entries) => entries.clone(),
        _ => match value.get("nftables") {
            Some(Value::Array(entries)) => entries.clone(),
            _ => return tables,
        },
    };
    for entry in &entries {
        let Some(table) = entry.get("table") else {
            continue;
        };
        let (Some(family), Some(name)) = (
            table.get("family").and_then(Value::as_str),
            table.get("name").and_then(Value::as_str),
        ) else {
            continue;
        };
        tables.insert((family.to_string(), name.to_string()));
    }
    tables
}

/// Extracts named counter packet counts from an nft JSON listing.
fn parse_counters(bytes: &[u8]) -> Result<HashMap<String, u64>> {
    let value: Value = serde_json::from_slice(bytes)?;
    let mut counters: HashMap<String, u64> = HashMap::new();
    let Some(entries) = value.get("nftables").and_then(Value::as_array) else {
        return Err(GuardError::Integrity(
            "nft returned a counter listing without a rule list".to_string(),
        ));
    };
    for entry in entries {
        let Some(counter) = entry.get("counter") else {
            continue;
        };
        let (Some(name), Some(packets)) = (
            counter.get("name").and_then(Value::as_str),
            counter.get("packets").and_then(Value::as_u64),
        ) else {
            continue;
        };
        let previous = counters.get(name).copied().unwrap_or(0);
        counters.insert(name.to_string(), previous.saturating_add(packets));
    }
    Ok(counters)
}

/// Keeps one bounded, single line diagnostic for an error message.
fn summarize(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no diagnostics");
    line.chars()
        .filter(|c| !c.is_control())
        .take(NFT_DETAIL_LIMIT)
        .collect()
}

/// The state an attachment is in under [`TestBackend`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforcementState {
    /// Nothing has been applied to this attachment.
    Unmanaged,
    /// The permitted ruleset is installed.
    Applied,
    /// A deny-everything generation is installed.
    Cut,
    /// Every rule has been removed.
    Removed,
}

/// An in-memory backend that models the same transitions as the nftables
/// backend, for tests only; never a production fallback without privileges.
///
/// It is a model, not a stub: every transition installs or removes a real
/// [`EnforcementModel`], permits and counters are answered from that model,
/// and a cut is observable as a change in what the attachment may do.
#[derive(Debug, Default)]
pub struct TestBackend {
    attachments: std::sync::Mutex<HashMap<Uuid, TestEntry>>,
}

#[derive(Debug)]
struct TestEntry {
    state: EnforcementState,
    model: Option<EnforcementModel>,
    counters: CounterSnapshot,
}

impl TestBackend {
    /// The state of an attachment.
    pub fn state(&self, sandbox_id: Uuid) -> EnforcementState {
        self.attachments
            .lock()
            .ok()
            .and_then(|entries| entries.get(&sandbox_id).map(|entry| entry.state))
            .unwrap_or(EnforcementState::Unmanaged)
    }

    /// The ruleset an attachment is currently enforced by.
    pub fn active_ruleset(&self, attachment: &GuardAttachment) -> Result<Option<String>> {
        let entries = self
            .attachments
            .lock()
            .map_err(|_| GuardError::Unavailable("test enforcement state is poisoned".into()))?;
        entries
            .get(&attachment.sandbox_id)
            .and_then(|entry| entry.model.as_ref())
            .map(EnforcementModel::ruleset)
            .transpose()
    }

    /// What the installed model permits for this attachment right now.
    pub fn permits(
        &self,
        attachment: &GuardAttachment,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        transport: Transport,
        port: u16,
    ) -> bool {
        self.attachments.lock().ok().is_some_and(|entries| {
            entries
                .get(&attachment.sandbox_id)
                .and_then(|entry| entry.model.as_ref())
                .is_some_and(|model| model.permits(source, destination, transport, port))
        })
    }

    /// Records one guest packet against the installed model's verdict and
    /// returns whether the model permitted it. `None` when nothing is enforced.
    pub fn record_packet(
        &self,
        attachment: &GuardAttachment,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        transport: Transport,
        port: u16,
    ) -> Option<bool> {
        let mut guard = self.attachments.lock().ok()?;
        let entry = guard.get_mut(&attachment.sandbox_id)?;
        let model = entry.model.as_ref()?;
        let verdict = model.verdict(source, destination, transport, port);
        entry.counters.record(verdict.counter);
        Some(verdict.permitted)
    }

    /// Records one IPv6 packet from the guest interface.
    pub fn record_ipv6_packet(&self, attachment: &GuardAttachment) -> Option<bool> {
        let mut guard = self.attachments.lock().ok()?;
        let entry = guard.get_mut(&attachment.sandbox_id)?;
        entry.model.as_ref()?;
        entry.counters.record(COUNTER_IPV6);
        Some(
            entry
                .model
                .as_ref()
                .is_some_and(|model| model.permits_ipv6()),
        )
    }

    /// The kernel-shaped counters of an attachment's current generation.
    pub fn snapshot(&self, attachment: &GuardAttachment) -> Result<CounterSnapshot> {
        let entries = self
            .attachments
            .lock()
            .map_err(|_| GuardError::Unavailable("test enforcement state is poisoned".into()))?;
        entries
            .get(&attachment.sandbox_id)
            .filter(|entry| entry.model.is_some())
            .map(|entry| entry.counters.clone())
            .ok_or_else(|| {
                GuardError::Unavailable(format!(
                    "no enforcement is installed for sandbox {}",
                    attachment.sandbox_id
                ))
            })
    }

    /// Installs a new generation, keeping the counts the previous one
    /// accumulated, which is what replacing the rules of the attachment's
    /// existing table does on the host.
    fn install(
        &self,
        attachment: &GuardAttachment,
        model: EnforcementModel,
        state: EnforcementState,
    ) -> Result<()> {
        let mut guard = self.attachments.lock().map_err(|_| {
            GuardError::Unavailable("the test enforcement state is poisoned".into())
        })?;
        let previous = guard
            .get(&attachment.sandbox_id)
            .map_or_else(CounterSnapshot::default, |entry| entry.counters.clone());
        let counters = CounterSnapshot {
            table: model.table().to_string(),
            ..previous
        };
        guard.insert(
            attachment.sandbox_id,
            TestEntry {
                state,
                model: Some(model),
                counters,
            },
        );
        Ok(())
    }
}

#[async_trait]
impl EnforcementBackend for TestBackend {
    async fn apply_policy(
        &self,
        policy: &CompiledPolicy,
        attachment: &GuardAttachment,
    ) -> Result<()> {
        let model = EnforcementModel::build(policy, attachment, false)?;
        self.install(attachment, model, EnforcementState::Applied)
    }

    async fn remove_policy(&self, attachment: &GuardAttachment) -> Result<()> {
        let mut guard = self.attachments.lock().map_err(|_| {
            GuardError::Unavailable("the test enforcement state is poisoned".into())
        })?;
        match guard.get_mut(&attachment.sandbox_id) {
            // Removing an attachment that is already removed, or never had
            // enforcement, is the same end state and succeeds.
            None => Ok(()),
            Some(entry) => {
                entry.state = EnforcementState::Removed;
                entry.model = None;
                entry.counters = CounterSnapshot::default();
                Ok(())
            }
        }
    }

    async fn cut_network(&self, attachment: &GuardAttachment) -> Result<()> {
        // Cutting is fail closed: an attachment that has no enforcement yet is
        // given the deny-everything generation rather than an error, so a cut
        // can never be lost to a restart or a failed apply.
        let model = EnforcementModel::cut(attachment)?;
        self.install(attachment, model, EnforcementState::Cut)
    }

    async fn restore_network(
        &self,
        policy: &CompiledPolicy,
        attachment: &GuardAttachment,
    ) -> Result<()> {
        let model = EnforcementModel::build(policy, attachment, false)?;
        self.install(attachment, model, EnforcementState::Applied)
    }

    async fn health(&self) -> Result<()> {
        let guard = self.attachments.lock().map_err(|_| {
            GuardError::Unavailable("the test enforcement state is poisoned".into())
        })?;
        for (sandbox_id, entry) in guard.iter() {
            let consistent = match entry.state {
                EnforcementState::Applied | EnforcementState::Cut => entry.model.is_some(),
                EnforcementState::Unmanaged | EnforcementState::Removed => entry.model.is_none(),
            };
            if !consistent {
                return Err(GuardError::Integrity(format!(
                    "sandbox {sandbox_id} is {} without a matching ruleset",
                    match entry.state {
                        EnforcementState::Applied => "applied",
                        EnforcementState::Cut => "cut",
                        EnforcementState::Unmanaged => "unmanaged",
                        EnforcementState::Removed => "removed",
                    }
                )));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CounterSource for TestBackend {
    async fn counters(&self, attachment: &GuardAttachment) -> Result<CounterSnapshot> {
        self.snapshot(attachment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{OperatorBoundary, compile};
    use crate::policy::{EgressRule, GuardPolicy, ModelEndpoint, PolicyTemplate};
    use render::{BlockedRange, MAX_INTERFACE_LEN};
    use std::collections::BTreeMap;
    use std::str::FromStr;

    fn attachment() -> GuardAttachment {
        GuardAttachment {
            sandbox_id: Uuid::parse_str("0192f0a1-0000-7000-8000-0000000000aa").expect("uuid"),
            tenant_id: Uuid::parse_str("0192f0a1-0000-7000-8000-0000000000bb").expect("uuid"),
            interface: "agtap0".to_string(),
            guest_ip: Ipv4Addr::new(172, 30, 8, 2),
            gateway_ip: Ipv4Addr::new(172, 30, 8, 1),
            dns_port: 5353,
            broker_port: 18080,
        }
    }

    /// A boundary holding the private, loopback, link-local, metadata and
    /// multicast ranges an operator never lets a guest reach directly.
    fn boundary() -> OperatorBoundary {
        OperatorBoundary {
            blocked_cidrs: [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "224.0.0.0/4",
                "0.0.0.0/8",
            ]
            .iter()
            .map(|cidr| ipnet::IpNet::from_str(cidr).expect("cidr"))
            .collect(),
            blocked_hosts: Vec::new(),
            protected_cidrs: Vec::new(),
            test_destinations: BTreeMap::new(),
        }
    }

    fn model_endpoint() -> ModelEndpoint {
        ModelEndpoint {
            host: "api.model.test".to_string(),
            port: 443,
            scheme: "https".to_string(),
            allowed_methods: vec!["POST".to_string()],
            allowed_paths: vec!["/v1/".to_string()],
            credential: "model-main".to_string(),
        }
    }

    /// The template for a sandbox with no selected policy: no allowances at
    /// all, not even on the gateway.
    fn no_network_policy() -> CompiledPolicy {
        let policy =
            GuardPolicy::template(PolicyTemplate::NoNetwork, None, Vec::new()).expect("template");
        compile(&policy, &boundary()).expect("compiled")
    }

    /// The recommended guarded template: the model endpoint and nothing else.
    fn model_only_policy() -> CompiledPolicy {
        let policy = GuardPolicy::template(
            PolicyTemplate::ModelOnly,
            Some(model_endpoint()),
            Vec::new(),
        )
        .expect("template");
        compile(&policy, &boundary()).expect("compiled")
    }

    /// A read-only egress destination is permitted and there is no model
    /// endpoint, so DNS works while the broker listener must stay denied. The
    /// zone is paired with the rule that serves it, because the compiler
    /// refuses a zone with no permitted destination.
    fn egress_only_policy() -> CompiledPolicy {
        let rule = crate::policy::EgressRule {
            host: "metrics.internal".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            allowed_methods: vec!["GET".to_string()],
            allowed_paths: Vec::new(),
        };
        let policy =
            GuardPolicy::template(PolicyTemplate::ReadOnlyApi, None, vec![rule]).expect("template");
        compile(&policy, &boundary()).expect("compiled")
    }
    /// Rule parameters for a model built without a compiled policy, used where
    /// the test needs to feed the renderer a value the policy types cannot hold.
    fn rule_params(blocked_ipv4: Vec<String>) -> RuleParams {
        RuleParams {
            sandbox: attachment().sandbox_id.simple().to_string(),
            interface: "agtap0".to_string(),
            guest_ip: Ipv4Addr::new(172, 30, 8, 2),
            gateway_ip: Ipv4Addr::new(172, 30, 8, 1),
            dns_port: 5353,
            broker_port: 18080,
            permits_dns: true,
            permits_broker: true,
            cut: false,
            blocked_ipv4,
        }
    }
    #[test]
    fn a_persisted_attachment_round_trips_and_still_refuses_injection() {
        let attached = attachment();
        let document = serde_json::to_string(&attached).expect("serialize");
        let restored: GuardAttachment = serde_json::from_str(&document).expect("deserialize");
        // The document is a boundary with the host, not an end in itself: what
        // matters is that a restored attachment still describes an enforceable
        // guest, with the same table and the same identity.
        assert_eq!(restored.sandbox_id, attached.sandbox_id);
        assert_eq!(restored.tenant_id, attached.tenant_id);
        assert_eq!(restored.table_name(), attached.table_name());
        restored
            .validate()
            .expect("a restored attachment is still enforceable");

        // A document that does not describe an attachment Guard can rebuild is
        // refused rather than reinterpreted as an older shape.
        assert!(
            serde_json::from_str::<GuardAttachment>(
                r#"{"sandbox_id":"0192f0a1-0000-7000-8000-0000000000aa","tenant_id":"0192f0a1-0000-7000-8000-0000000000bb","interface":"agtap0","guest_ip":"172.30.8.2","gateway_ip":"172.30.8.1","dns_port":5353,"broker_port":18080,"extra":true}"#
            )
            .is_err()
        );

        // A hand-edited interface is re-validated when the attachment is used.
        let tampered: GuardAttachment =
            serde_json::from_str(&document.replace("agtap0", "agtap0; drop all"))
                .expect("still valid JSON");
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn the_linux_backend_interface_naming_is_accepted() {
        // The Linux wrapper names guest interfaces `ag` plus 13 hex characters
        // of a digest of the full sandbox UUID: exactly the 15 byte shape Linux
        // allows for a device name.
        let mut attached = attachment();
        attached.interface = "ag0123456789abc".to_string();
        assert_eq!(attached.interface.len(), MAX_INTERFACE_LEN);
        attached
            .validate()
            .expect("the network backend's naming is enforceable");
        let model = EnforcementModel::build(&model_only_policy(), &attached, false).expect("model");
        assert!(
            model
                .ruleset()
                .expect("ruleset")
                .contains("\"ag0123456789abc\"")
        );
    }

    #[test]
    fn no_network_permits_nothing_even_on_the_gateway() {
        let model = EnforcementModel::build(&no_network_policy(), &attachment(), false)
            .expect("no-network model");
        let guest = attachment().guest_ip;
        let gateway = attachment().gateway_ip;
        for transport in [Transport::Tcp, Transport::Udp] {
            for port in [53, 5353, 18080, 443] {
                assert!(
                    !model.permits(guest, gateway, transport, port),
                    "no-network permitted {transport:?} port {port}"
                );
            }
        }
    }

    #[test]
    fn model_only_permits_only_the_assigned_source_at_the_gateway_listeners() {
        let attached = attachment();
        let model = EnforcementModel::build(&model_only_policy(), &attached, false)
            .expect("model-only model");
        let guest = attached.guest_ip;
        let gateway = attached.gateway_ip;
        let peer = Ipv4Addr::new(172, 30, 8, 3);

        assert!(model.permits(guest, gateway, Transport::Tcp, attached.broker_port));
        assert!(model.permits(guest, gateway, Transport::Tcp, attached.dns_port));
        assert!(model.permits(guest, gateway, Transport::Udp, attached.dns_port));

        // A different source address cannot borrow the permit, in raw socket
        // hands or otherwise.
        assert!(!model.permits(peer, gateway, Transport::Tcp, attached.broker_port));
        // A sibling port on the gateway is still the gateway's other service.
        assert!(!model.permits(guest, gateway, Transport::Tcp, attached.broker_port + 1));
        // The broker listener is TCP only.
        assert!(!model.permits(guest, gateway, Transport::Udp, attached.broker_port));
        // Only a protocol the gateway actually listens for is permitted.
        assert!(!model.permits(guest, gateway, Transport::Other, attached.broker_port));
        // The model endpoint itself is not reachable directly: the guest must go
        // through the broker, and the broker is on the gateway address.
        assert!(!model.permits(guest, Ipv4Addr::new(93, 184, 216, 34), Transport::Tcp, 443));
        // Nor is any host service.
        assert!(!model.permits(guest, Ipv4Addr::new(127, 0, 0, 1), Transport::Tcp, 22));
    }

    #[test]
    fn cut_denies_the_flows_the_policy_permitted() {
        let attached = attachment();
        let cut =
            EnforcementModel::build(&model_only_policy(), &attached, true).expect("cut model");
        for transport in [Transport::Tcp, Transport::Udp] {
            for port in [attached.dns_port, attached.broker_port] {
                assert!(!cut.permits(attached.guest_ip, attached.gateway_ip, transport, port));
            }
        }
    }

    #[test]
    fn ipv6_is_never_permitted_in_any_generation() {
        let attached = attachment();
        for cut in [false, true] {
            let model =
                EnforcementModel::build(&model_only_policy(), &attached, cut).expect("model");
            assert!(!model.permits_ipv6());
        }
    }

    #[test]
    fn an_allowlist_without_a_model_endpoint_still_reaches_the_broker_that_enforces_it() {
        let attached = attachment();
        let model = EnforcementModel::build(&egress_only_policy(), &attached, false)
            .expect("egress-only model");
        assert!(model.permits(
            attached.guest_ip,
            attached.gateway_ip,
            Transport::Udp,
            attached.dns_port
        ));
        // The allowlist is enforced inside the gateway, so the guest has to be
        // able to reach it. Whether any particular destination is then permitted
        // is the gateway's decision, not the kernel's.
        assert!(model.permits(
            attached.guest_ip,
            attached.gateway_ip,
            Transport::Tcp,
            attached.broker_port
        ));
        // A cut still denies it whatever the policy asked for.
        let cut = EnforcementModel::build(&egress_only_policy(), &attached, true).expect("cut");
        assert!(!cut.permits(
            attached.guest_ip,
            attached.gateway_ip,
            Transport::Tcp,
            attached.broker_port
        ));
    }

    #[test]
    fn verdicts_categorise_every_guest_packet() {
        let attached = attachment();
        let model = EnforcementModel::build(&model_only_policy(), &attached, false).expect("model");
        let guest = attached.guest_ip;
        let gateway = attached.gateway_ip;

        let permitted = model.verdict(guest, gateway, Transport::Tcp, attached.broker_port);
        assert!(permitted.permitted);
        assert_eq!(permitted.counter, COUNTER_BROKER_PERMITTED);

        let permitted_dns = model.verdict(guest, gateway, Transport::Udp, attached.dns_port);
        assert_eq!(permitted_dns.counter, COUNTER_DNS_PERMITTED);

        let blocked_range =
            model.verdict(guest, Ipv4Addr::new(169, 254, 169, 254), Transport::Tcp, 80);
        assert!(!blocked_range.permitted);
        assert_eq!(blocked_range.counter, COUNTER_BLOCKED_RANGE);

        let spoofed = model.verdict(
            Ipv4Addr::new(172, 30, 8, 66),
            Ipv4Addr::new(93, 184, 216, 34),
            Transport::Tcp,
            443,
        );
        assert!(!spoofed.permitted);
        assert_eq!(spoofed.counter, COUNTER_OTHER_DENIED);
    }

    #[test]
    fn a_spoofed_source_aiming_at_a_blocked_range_is_still_counted_as_blocked() {
        let attached = attachment();
        let model = EnforcementModel::build(&model_only_policy(), &attached, false).expect("model");
        let verdict = model.verdict(
            Ipv4Addr::new(172, 30, 8, 66),
            Ipv4Addr::new(169, 254, 169, 254),
            Transport::Tcp,
            80,
        );
        assert_eq!(verdict.counter, COUNTER_BLOCKED_RANGE);
        assert!(!verdict.permitted);
    }

    #[test]
    fn table_names_carry_the_complete_sandbox_identifier() {
        let attached = attachment();
        let table = attached.table_name();
        assert_eq!(
            table,
            format!("aiec_guard_{}", attached.sandbox_id.simple())
        );
        // Two sandboxes whose identifiers agree on their first characters, the
        // same collision a truncated name would create, stay distinct.
        let mut other = attached.clone();
        other.sandbox_id = Uuid::parse_str("0192f0a1-1111-7000-8000-0000000000aa").expect("uuid");
        assert_ne!(attached.table_name(), other.table_name());
        assert!(
            other
                .table_name()
                .ends_with("0192f0a11111700080000000000000aa")
        );
    }

    #[test]
    fn interface_names_cannot_inject_nft_syntax() {
        for hostile in [
            "tap0\"; delete table ip guard_filter; #",
            "tap0 -j",
            "tap0\ndelete table ip guard_filter",
            "tap0'",
            "",
            "tap0-very-long-interface-name",
            " tap0",
        ] {
            let mut attached = attachment();
            attached.interface = hostile.to_string();
            let error = EnforcementModel::build(&model_only_policy(), &attached, false)
                .expect_err("a hostile interface name must be refused");
            assert!(
                matches!(error, GuardError::Policy(_)),
                "{hostile:?} produced {error:?}"
            );
        }
    }
    #[test]
    fn protected_ranges_are_denied_at_the_kernel_too() {
        // The runtime adds the gateway, the guest, peer sandboxes and management
        // addresses as protected CIDRs, and they must be dropped by the ruleset
        // itself, not only refused by the gateway's own destination check.
        let mut operator = boundary();
        operator.protected_cidrs = vec![
            ipnet::IpNet::from_str("172.30.8.1/32").expect("cidr"),
            ipnet::IpNet::from_str("172.30.8.2/32").expect("cidr"),
        ];
        let policy = GuardPolicy::template(
            PolicyTemplate::ModelOnly,
            Some(model_endpoint()),
            Vec::new(),
        )
        .expect("template");
        let compiled = compile(&policy, &operator).expect("compiled");
        let attached = attachment();
        let model = EnforcementModel::build(&compiled, &attached, false).expect("model");

        // The gateway's own address is a protected range, yet the guest reaches
        // the two listeners on it and nothing else.
        assert!(model.permits(
            attached.guest_ip,
            attached.gateway_ip,
            Transport::Tcp,
            attached.broker_port
        ));
        // Every range renders canonically with an explicit prefix, including a
        // single address, so two spellings of one range cannot render twice.
        let script = model.ruleset().expect("ruleset");
        assert!(script.contains("ip daddr 172.30.8.1/32"));
        assert!(script.contains("ip daddr 172.30.8.2/32"));

        // A peer sandbox is a protected range and is counted as such.
        let peer = Ipv4Addr::new(172, 30, 9, 2);
        operator
            .protected_cidrs
            .push(ipnet::IpNet::from_str("172.30.9.0/24").expect("cidr"));
        let compiled = compile(&policy, &operator).expect("compiled");
        let model = EnforcementModel::build(&compiled, &attached, false).expect("model");
        let verdict = model.verdict(attached.guest_ip, peer, Transport::Tcp, 443);
        assert!(!verdict.permitted);
        assert_eq!(verdict.counter, COUNTER_BLOCKED_RANGE);
        assert!(
            model
                .ruleset()
                .expect("ruleset")
                .contains("ip daddr 172.30.9.0/24")
        );
    }

    #[test]
    fn an_attachment_needs_distinct_addresses_and_listeners() {
        let mut attached = attachment();
        attached.guest_ip = attached.gateway_ip;
        assert!(EnforcementModel::build(&model_only_policy(), &attached, false).is_err());

        let mut attached = attachment();
        attached.dns_port = attached.broker_port;
        assert!(EnforcementModel::build(&model_only_policy(), &attached, false).is_err());

        let mut attached = attachment();
        attached.broker_port = 0;
        assert!(EnforcementModel::build(&model_only_policy(), &attached, false).is_err());
    }

    #[test]
    fn a_boundary_range_cannot_inject_nft_syntax() {
        // A range that is not a plain CIDR never reaches an nft expression, so
        // even a boundary assembled from a hostile source cannot append a rule.
        let hostile = RuleModel::new(rule_params(vec![
            "169.254.169.254/32\" accept comment \"escaped".to_string(),
        ]));
        assert!(hostile.is_err(), "an injected boundary range was accepted");
    }

    #[test]
    fn ipv6_boundary_ranges_are_covered_by_the_unconditional_v6_drop() {
        let mut operator = boundary();
        operator
            .blocked_cidrs
            .push(ipnet::IpNet::from_str("::1/128").expect("cidr"));
        operator
            .blocked_cidrs
            .push(ipnet::IpNet::from_str("fe80::/10").expect("cidr"));
        let policy = GuardPolicy::template(
            PolicyTemplate::ModelOnly,
            Some(model_endpoint()),
            Vec::new(),
        )
        .expect("template");
        let compiled = compile(&policy, &operator).expect("compiled");
        let model = EnforcementModel::build(&compiled, &attachment(), false).expect("model");
        // An IPv6 range is never rendered as an IPv4 rule; the blanket IPv6 drop
        // is strictly stronger than any single range.
        let script = model.ruleset().expect("ruleset");
        assert!(!script.contains("::1"));
        assert!(!model.permits_ipv6());
    }

    #[test]
    fn the_replace_batch_is_idempotent_and_keeps_the_counters() {
        // `install` sends the same batch whether or not a generation exists, so
        // the batch must be valid against a fresh table and against one that
        // already holds a previous generation, and applying it twice must not
        // duplicate rules or reset the counts.
        let attached = attachment();
        let model = EnforcementModel::build(&model_only_policy(), &attached, false).expect("model");
        let batch = model.flushable_ruleset().expect("replace batch");
        assert!(batch.contains(&format!("add table ip {}", model.table())));
        assert!(batch.contains(&format!("flush table ip {}", model.table())));
        assert!(batch.contains(&format!("add table ip6 {}", model.table())));
        assert!(batch.contains(&format!("flush table ip6 {}", model.table())));

        // The replace batch and the create batch install the same rules, so a
        // first apply and a later apply cannot enforce different things.
        let created = model.ruleset().expect("ruleset");
        let install_lines: Vec<&str> = batch
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter(|line| !line.starts_with("add table ") && !line.starts_with("flush table "))
            .collect();
        let created_lines: Vec<&str> = created
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter(|line| !line.starts_with("add table "))
            .collect();
        assert_eq!(install_lines, created_lines);
    }

    /// A packet as the guest's kernel would put it on the wire.
    #[derive(Clone, Copy, Debug)]
    struct Packet {
        family: &'static str,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        proto: &'static str,
        port: u16,
    }

    /// Evaluates the generated ruleset the way nft does: within a chain, the
    /// first matching rule decides, and a chain with no match falls through to
    /// the base chain policy.
    ///
    /// This exists so the acceptance questions are asked of the text nft will
    /// actually receive, rather than of a separate model that could drift from
    /// it. The rules themselves are generated from the same `RuleModel` the
    /// public `permits`/`verdict` API answers from, so a test that passes here
    /// and fails there is a real inconsistency.
    fn evaluate(
        script: &str,
        chain: &str,
        interface: &str,
        packet: Packet,
    ) -> (String, Option<String>) {
        // The base chain's policy, read from its definition. The table name is
        // unique per attachment, so no other attachment's chain can match.
        let mut policy = String::new();
        for line in script.lines() {
            if line.starts_with("add chain ")
                && line.contains(&format!(" {chain} {{"))
                && let Some(position) = line.find("policy ")
            {
                policy = line[position + 7..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphabetic())
                    .collect();
            }
        }
        for line in script.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() < 6 || words[0] != "add" || words[1] != "rule" {
                continue;
            }
            if words[2] != packet.family || words[4] != chain {
                continue;
            }
            let mut iifname: Option<String> = None;
            let mut saddr: Option<String> = None;
            let mut saddr_ne: Option<String> = None;
            let mut daddr: Option<String> = None;
            let mut dport: Option<u16> = None;
            let mut proto: Option<String> = None;
            let mut counter: Option<String> = None;
            let verdict = words[words.len() - 1].to_string();
            let mut index = 5;
            while index < words.len() {
                match words[index] {
                    "iifname" => {
                        iifname = Some(words[index + 1].trim_matches('"').to_string());
                        index += 2;
                    }
                    "oifname" => index += 2,
                    // Rendered as `ip saddr <addr>` or `ip saddr != <addr>`.
                    "saddr" if index + 1 < words.len() && words[index + 1] == "!=" => {
                        saddr_ne = Some(words[index + 2].to_string());
                        index += 3;
                    }
                    "saddr" => {
                        saddr = Some(words[index + 1].to_string());
                        index += 2;
                    }
                    "daddr" => {
                        daddr = Some(words[index + 1].to_string());
                        index += 2;
                    }
                    "dport" => {
                        dport = words[index + 1].parse().ok();
                        index += 2;
                    }
                    "tcp" | "udp" => {
                        proto = Some(words[index].to_string());
                        index += 1;
                    }
                    // Rendered as `counter name "<object>"`.
                    "counter" => {
                        counter = Some(words[index + 2].trim_matches('"').to_string());
                        index += 3;
                    }
                    _ => index += 1,
                }
            }
            // A rule scoped to an interface only judges traffic on it; this
            // harness evaluates the attachment's own interface.
            if let Some(name) = &iifname
                && name != interface
            {
                continue;
            }
            if let Some(expected) = &proto
                && expected != packet.proto
            {
                continue;
            }
            if let Some(expected) = &saddr
                && expected != &packet.source.to_string()
            {
                continue;
            }
            if let Some(other) = &saddr_ne
                && other == &packet.source.to_string()
            {
                continue;
            }
            if let Some(expected) = &daddr
                && !address_in_cidr(packet.destination, expected)
            {
                continue;
            }
            if let Some(expected) = dport
                && expected != packet.port
            {
                continue;
            }
            return (verdict, counter);
        }
        (policy, None)
    }

    /// Whether an address falls in the rendered `a.b.c.d/len` or bare address.
    fn address_in_cidr(address: Ipv4Addr, cidr: &str) -> bool {
        let range = BlockedRange::parse(cidr).expect("rendered range must parse");
        range.contains(address)
    }

    fn guest_to(attached: &GuardAttachment, port: u16) -> Packet {
        Packet {
            family: FAMILY_V4,
            source: attached.guest_ip,
            destination: attached.gateway_ip,
            proto: "tcp",
            port,
        }
    }

    /// The acceptance questions, asked of the text nft actually receives.
    #[test]
    fn the_generated_ruleset_enforces_the_model_it_was_built_from() {
        let attached = attachment();
        let iface = attached.interface.clone();
        let script = ruleset(&model_only_policy(), &attached, false).expect("ruleset");

        // Permitted: the assigned guest source at the two gateway listeners.
        let broker = evaluate(
            &script,
            "input",
            &iface,
            guest_to(&attached, attached.broker_port),
        );
        assert_eq!(broker.0, "accept", "broker permit");
        assert_eq!(broker.1.as_deref(), Some(COUNTER_BROKER_PERMITTED));
        let dns = evaluate(
            &script,
            "input",
            &iface,
            guest_to(&attached, attached.dns_port),
        );
        assert_eq!(dns.0, "accept", "dns permit");
        assert_eq!(dns.1.as_deref(), Some(COUNTER_DNS_PERMITTED));

        // Denied: a different host, at any port, even a permitted one.
        let other_host = Packet {
            destination: Ipv4Addr::new(93, 184, 216, 34),
            ..guest_to(&attached, attached.broker_port)
        };
        assert_eq!(evaluate(&script, "input", &iface, other_host).0, "drop");
        // Denied: the metadata endpoint.
        let metadata = Packet {
            destination: Ipv4Addr::new(169, 254, 169, 254),
            ..guest_to(&attached, 80)
        };
        let verdict = evaluate(&script, "input", &iface, metadata);
        assert_eq!(verdict.0, "drop");
        assert_eq!(verdict.1.as_deref(), Some(COUNTER_BLOCKED_RANGE));
        // Denied: a sibling port on the gateway itself. The gateway address is
        // inside a blocked range and those rules are evaluated first, on
        // purpose, so a spoofed source cannot hide an attempt; this is counted
        // as a blocked-range attempt.
        let sibling = guest_to(&attached, attached.broker_port + 1);
        let verdict = evaluate(&script, "input", &iface, sibling);
        assert_eq!(verdict.0, "drop");
        assert_eq!(verdict.1.as_deref(), Some(COUNTER_BLOCKED_RANGE));
        // Denied: a source the operator never assigned, at a permitted port. It
        // cannot borrow the permit, because the permit names the assigned
        // source rather than only the destination.
        let unassigned = Packet {
            source: Ipv4Addr::new(172, 30, 8, 66),
            ..guest_to(&attached, attached.broker_port)
        };
        let verdict = evaluate(&script, "input", &iface, unassigned);
        assert_eq!(
            verdict.0, "drop",
            "an unassigned source must not borrow the permit"
        );
        assert_eq!(verdict.1.as_deref(), Some(COUNTER_BLOCKED_RANGE));
        // The assigned source reaching a public destination the policy never
        // authorized is the generic denial, counted on its own.
        let public = Packet {
            destination: Ipv4Addr::new(93, 184, 216, 34),
            ..guest_to(&attached, 443)
        };
        let verdict = evaluate(&script, "input", &iface, public);
        assert_eq!(verdict.0, "drop");
        assert_eq!(verdict.1.as_deref(), Some(COUNTER_OTHER_DENIED));
        // And so is an unassigned source reaching a public destination, which
        // is the anti-spoof rule the counter is really there to observe.
        let verdict = evaluate(
            &script,
            "input",
            &iface,
            Packet {
                source: Ipv4Addr::new(172, 30, 8, 66),
                ..public
            },
        );
        assert_eq!(
            verdict.0, "drop",
            "an unassigned source must not borrow the permit"
        );
        assert_eq!(verdict.1.as_deref(), Some(COUNTER_OTHER_DENIED));
        // Denied: the broker port over UDP, which the gateway does not serve.
        let wrong_proto = Packet {
            proto: "udp",
            ..guest_to(&attached, attached.broker_port)
        };
        assert_eq!(evaluate(&script, "input", &iface, wrong_proto).0, "drop");
    }

    #[test]
    fn the_generated_ruleset_drops_all_ipv6_and_all_forwarding() {
        let attached = attachment();
        let iface = attached.interface.clone();
        let script = ruleset(&model_only_policy(), &attached, false).expect("ruleset");

        // IPv6 is dropped unconditionally, whatever the destination.
        let v6 = Packet {
            family: FAMILY_V6,
            source: Ipv4Addr::new(172, 30, 8, 2),
            destination: Ipv4Addr::new(172, 30, 8, 1),
            proto: "tcp",
            port: attached.broker_port,
        };
        for chain in ["input", "forward"] {
            let verdict = evaluate(&script, chain, &iface, v6);
            assert_eq!(verdict.0, "drop", "IPv6 must be dropped in {chain}");
            assert_eq!(verdict.1.as_deref(), Some(COUNTER_IPV6));
        }

        // Forwarding is denied in both directions, including traffic the guest
        // could otherwise have been permitted to send, so it has no second path
        // out of the host.
        let forwarded_out = guest_to(&attached, attached.broker_port);
        assert_eq!(
            evaluate(&script, "forward", &iface, forwarded_out).0,
            "drop"
        );
        let routed_elsewhere = Packet {
            destination: Ipv4Addr::new(10, 9, 9, 2),
            ..forwarded_out
        };
        assert_eq!(
            evaluate(&script, "forward", &iface, routed_elsewhere).0,
            "drop"
        );
    }

    #[test]
    fn a_cut_ruleset_denies_everything_it_used_to_permit() {
        let attached = attachment();
        let iface = attached.interface.clone();
        let cut = ruleset(&model_only_policy(), &attached, true).expect("cut ruleset");
        let applied = ruleset(&model_only_policy(), &attached, false).expect("ruleset");

        // The applied generation permits the gateway listeners it exists for;
        // a cut must take that permission away and nothing else may grant it.
        assert_eq!(
            evaluate(
                &applied,
                "input",
                &iface,
                guest_to(&attached, attached.broker_port)
            )
            .0,
            "accept"
        );
        for script in [&cut] {
            for chain in ["input", "forward"] {
                for packet in [
                    guest_to(&attached, attached.broker_port),
                    guest_to(&attached, attached.dns_port),
                    Packet {
                        family: FAMILY_V6,
                        source: attached.guest_ip,
                        destination: attached.gateway_ip,
                        proto: "tcp",
                        port: attached.broker_port,
                    },
                ] {
                    assert_eq!(
                        evaluate(script, chain, &iface, packet).0,
                        "drop",
                        "a cut must deny in {chain}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_no_network_ruleset_denies_everything() {
        let attached = attachment();
        let iface = attached.interface.clone();
        let script = ruleset(&no_network_policy(), &attached, false).expect("ruleset");
        for chain in ["input", "forward"] {
            for port in [attached.dns_port, attached.broker_port, 443] {
                let verdict = evaluate(&script, chain, &iface, guest_to(&attached, port));
                assert_eq!(
                    verdict.0, "drop",
                    "no-network must deny port {port} in {chain}"
                );
            }
        }
    }

    #[test]
    fn the_generated_ruleset_only_ever_names_its_own_table() {
        let attached = attachment();
        let script = ruleset(&model_only_policy(), &attached, false).expect("ruleset");
        let table = attached.table_name();
        for line in script.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            assert!(
                matches!(words[2], "ip" | "ip6"),
                "unexpected family in {line:?}"
            );
            assert_eq!(words[3], table, "unexpected table in {line:?}");
        }
        // No address translation and no output hook: the guest is never routed
        // through the host's ordinary NAT path, and Guard never judges the
        // host's own traffic. Checked as the constructs a NAT path actually
        // needs, so no future rule can quietly reintroduce one.
        for forbidden in ["type nat", "type dstnat", "masquerade", "snat", "dnat"] {
            assert!(
                !script.contains(forbidden),
                "the ruleset reintroduces NAT through {forbidden:?}"
            );
        }
        assert!(!script.contains("hook output"));
        // Every chain Guard declares is a filter in the family it owns.
        for line in script.lines().filter(|line| line.starts_with("add chain ")) {
            assert!(line.contains("type filter"), "non-filter chain in {line:?}");
        }
    }

    #[tokio::test]
    async fn the_test_backend_models_every_transition() {
        let attached = attachment();
        let backend = TestBackend::default();
        let policy = model_only_policy();

        assert_eq!(
            backend.state(attached.sandbox_id),
            EnforcementState::Unmanaged
        );
        assert!(backend.counters(&attached).await.is_err());

        backend
            .apply_policy(&policy, &attached)
            .await
            .expect("apply");
        assert_eq!(
            backend.state(attached.sandbox_id),
            EnforcementState::Applied
        );
        assert!(backend.permits(
            &attached,
            attached.guest_ip,
            attached.gateway_ip,
            Transport::Tcp,
            attached.broker_port
        ));
        assert!(
            backend
                .active_ruleset(&attached)
                .expect("ruleset")
                .is_some()
        );
        backend.health().await.expect("health");

        backend.cut_network(&attached).await.expect("cut");
        assert_eq!(backend.state(attached.sandbox_id), EnforcementState::Cut);
        assert!(!backend.permits(
            &attached,
            attached.guest_ip,
            attached.gateway_ip,
            Transport::Tcp,
            attached.broker_port
        ));
        // A cut is fail closed even for an attachment that was never applied.
        let other = GuardAttachment {
            sandbox_id: Uuid::parse_str("0192f0a1-2222-7000-8000-0000000000aa").expect("uuid"),
            ..attached.clone()
        };
        backend.cut_network(&other).await.expect("cut");
        assert_eq!(backend.state(other.sandbox_id), EnforcementState::Cut);
        assert!(!backend.permits(
            &other,
            other.guest_ip,
            other.gateway_ip,
            Transport::Udp,
            other.dns_port
        ));

        backend
            .restore_network(&policy, &attached)
            .await
            .expect("restore");
        assert_eq!(
            backend.state(attached.sandbox_id),
            EnforcementState::Applied
        );
        assert!(backend.permits(
            &attached,
            attached.guest_ip,
            attached.gateway_ip,
            Transport::Tcp,
            attached.broker_port
        ));

        backend.remove_policy(&attached).await.expect("remove");
        assert_eq!(
            backend.state(attached.sandbox_id),
            EnforcementState::Removed
        );
        assert!(!backend.permits(
            &attached,
            attached.guest_ip,
            attached.gateway_ip,
            Transport::Tcp,
            attached.broker_port
        ));
        assert!(
            backend
                .active_ruleset(&attached)
                .expect("ruleset")
                .is_none()
        );
        // Removing again is the same end state, not a failure.
        backend.remove_policy(&attached).await.expect("idempotent");
        backend.remove_policy(&other).await.expect("idempotent");
        backend.health().await.expect("health");
    }

    #[tokio::test]
    async fn the_test_backend_counts_every_decision_of_its_model() {
        let attached = attachment();
        let backend = TestBackend::default();
        backend
            .apply_policy(&model_only_policy(), &attached)
            .await
            .expect("apply");

        let guest = attached.guest_ip;
        let gateway = attached.gateway_ip;
        assert_eq!(
            backend.record_packet(
                &attached,
                guest,
                gateway,
                Transport::Tcp,
                attached.broker_port
            ),
            Some(true)
        );
        assert_eq!(
            backend.record_packet(&attached, guest, gateway, Transport::Udp, attached.dns_port),
            Some(true)
        );
        assert_eq!(
            backend.record_packet(
                &attached,
                guest,
                Ipv4Addr::new(169, 254, 169, 254),
                Transport::Tcp,
                80
            ),
            Some(false)
        );
        assert_eq!(
            backend.record_packet(
                &attached,
                guest,
                Ipv4Addr::new(10, 1, 2, 3),
                Transport::Tcp,
                22
            ),
            Some(false)
        );
        assert_eq!(backend.record_ipv6_packet(&attached), Some(false));

        let snapshot = backend.counters(&attached).await.expect("counters");
        assert_eq!(snapshot.table, attached.table_name());
        assert_eq!(snapshot.broker_permitted, 1);
        assert_eq!(snapshot.dns_permitted, 1);
        // Both denied destinations sit inside Guard's own default blocked
        // ranges, so both are categorised as blocked-range attempts.
        assert_eq!(snapshot.blocked_range, 2);
        assert_eq!(snapshot.other_denied, 0);
        assert_eq!(snapshot.ipv6, 1);
        assert_eq!(snapshot.permitted(), 2);
        assert_eq!(snapshot.denied(), 3);
        assert_eq!(snapshot.total(), 5);
        assert_eq!(
            backend
                .counter(&attached, CounterKind::BlockedRange)
                .await
                .expect("counter"),
            2
        );
        assert_eq!(
            CounterKind::from_nft_name(COUNTER_IPV6),
            Some(CounterKind::Ipv6)
        );

        // Replacing the rules keeps the counts, exactly like `flush table`
        // keeps the named counters of the attachment's table on the host.
        backend.cut_network(&attached).await.expect("cut");
        let snapshot = backend.counters(&attached).await.expect("counters");
        assert_eq!(snapshot.total(), 5);
        assert_eq!(snapshot.blocked_range, 2);
        assert_eq!(snapshot.ipv6, 1);

        // Only removing the attachment discards them.
        backend.remove_policy(&attached).await.expect("remove");
        assert!(backend.counters(&attached).await.is_err());
    }

    #[tokio::test]
    async fn a_missing_nft_binary_is_reported_rather_than_ignored() {
        let backend = NftablesBackend::new().with_program("/nonexistent/aiec-nft");
        let attached = attachment();
        let error = backend
            .apply_policy(&model_only_policy(), &attached)
            .await
            .expect_err("a missing nft binary must not be ignored");
        assert!(matches!(error, GuardError::Unavailable(_)), "{error:?}");
        assert!(backend.health().await.is_err());
        assert!(backend.counters(&attached).await.is_err());
    }

    #[test]
    fn counter_names_are_unique_and_round_trip() {
        let mut seen = BTreeSet::new();
        for kind in CounterKind::ALL {
            assert!(seen.insert(kind.nft_name()), "duplicate counter name");
        }
        assert_eq!(seen.len(), CounterKind::ALL.len());
        for kind in CounterKind::ALL {
            assert_eq!(CounterKind::from_nft_name(kind.nft_name()), Some(kind));
        }
        assert_eq!(CounterKind::from_nft_name("cnt_other"), None);
    }

    #[test]
    fn nft_listings_are_parsed_without_guessing() {
        let tables = parse_tables(
            br#"{"nftables":[{"metainfo":{"version":"1.0.2"}},
                {"table":{"family":"ip","name":"aiec_guard_aa","handle":1}},
                {"table":{"family":"ip6","name":"aiec_guard_aa","handle":1}}]}"#,
        );
        assert_eq!(tables.len(), 2);
        assert!(tables.contains(&("ip".to_string(), "aiec_guard_aa".to_string())));
        assert!(tables.contains(&("ip6".to_string(), "aiec_guard_aa".to_string())));
        assert!(parse_tables(b"not json").is_empty());

        let counters = parse_counters(
            br#"{"nftables":[{"counter":{"family":"ip","name":"cnt_dns_permitted","packets":7,"bytes":70}},
                {"counter":{"family":"ip","name":"cnt_other_denied","packets":3,"bytes":300}},
                {"metainfo":{}}]}"#,
        )
        .expect("counters");
        assert_eq!(counters.get("cnt_dns_permitted"), Some(&7));
        assert_eq!(counters.get("cnt_other_denied"), Some(&3));
        assert!(parse_counters(b"[]").is_err());
    }

    #[test]
    fn blocked_ranges_match_the_way_nft_does() {
        let range = BlockedRange::parse("172.16.0.0/12").expect("range");
        assert!(range.contains(Ipv4Addr::new(172, 30, 8, 2)));
        assert!(range.contains(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!range.contains(Ipv4Addr::new(172, 15, 255, 255)));
        assert!(!range.contains(Ipv4Addr::new(172, 32, 0, 1)));

        let host = BlockedRange::parse("169.254.169.254/32").expect("range");
        assert!(host.contains(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(!host.contains(Ipv4Addr::new(169, 254, 169, 253)));

        let default = BlockedRange::parse("0.0.0.0/0").expect("range");
        assert!(default.contains(Ipv4Addr::new(203, 0, 113, 9)));

        // A single address is accepted with and without an explicit prefix: nft
        // reads a bare `ip daddr` as /32, so both render the same rule.
        let bare = BlockedRange::parse("169.254.169.254").expect("bare address");
        assert!(bare.contains(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(!bare.contains(Ipv4Addr::new(169, 254, 169, 253)));
        assert_eq!(
            bare,
            BlockedRange::parse("169.254.169.254/32").expect("host route")
        );

        for hostile in [
            "169.254.169.254/33",
            "169.254.169/24/32",
            "1.2.3.4.5/24",
            "metadata\" accept comment \"x/24",
            "1.2.3.4/x",
        ] {
            assert!(
                BlockedRange::parse(hostile).is_err(),
                "{hostile:?} was accepted"
            );
        }
    }

    #[test]
    fn an_allowlist_rule_cannot_bypass_the_gateway() {
        // Model plus allowlist still routes everything through the gateway: the
        // allowlisted destination is reached by the proxy, never directly.
        let policy = GuardPolicy::template(
            PolicyTemplate::ModelPlusAllowlist,
            Some(model_endpoint()),
            vec![EgressRule {
                host: "registry.test".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
                allowed_methods: Vec::new(),
                allowed_paths: Vec::new(),
            }],
        )
        .expect("template");
        let compiled = compile(&policy, &boundary()).expect("compiled");
        let attached = attachment();
        let model = EnforcementModel::build(&compiled, &attached, false).expect("model");
        assert!(!model.permits(
            attached.guest_ip,
            Ipv4Addr::new(93, 184, 216, 34),
            Transport::Tcp,
            443
        ));
        assert!(model.permits(
            attached.guest_ip,
            attached.gateway_ip,
            Transport::Tcp,
            attached.broker_port
        ));
    }

    #[test]
    fn attachments_of_different_sandboxes_never_share_a_table() {
        let one = attachment();
        let mut two = one.clone();
        two.tenant_id = Uuid::parse_str("0192f0a1-3333-7000-8000-0000000000bb").expect("uuid");
        two.sandbox_id = Uuid::parse_str("0192f0a1-3333-7000-8000-0000000000aa").expect("uuid");
        two.interface = "agtap1".to_string();
        // A real second attachment gets its own /30, so the peer's guest
        // address is genuinely not the first attachment's own source.
        two.guest_ip = Ipv4Addr::new(172, 30, 8, 6);
        two.gateway_ip = Ipv4Addr::new(172, 30, 8, 5);
        let first = EnforcementModel::build(&model_only_policy(), &one, false).expect("model");
        let second = EnforcementModel::build(&model_only_policy(), &two, false).expect("model");
        assert_ne!(first.table(), second.table());
        let script = first.ruleset().expect("ruleset");
        assert!(script.contains(&one.interface));
        assert!(!script.contains(&two.interface));
        // The second attachment's guest address is a peer, never a permit.
        assert!(!first.permits(
            two.guest_ip,
            one.gateway_ip,
            Transport::Tcp,
            one.broker_port
        ));
    }

    #[test]
    fn the_generated_ruleset_is_deterministic() {
        let attached = attachment();
        let policy = model_only_policy();
        assert_eq!(
            ruleset(&policy, &attached, false).expect("ruleset"),
            ruleset(&policy, &attached, false).expect("ruleset")
        );
        assert_ne!(
            ruleset(&policy, &attached, false).expect("ruleset"),
            ruleset(&policy, &attached, true).expect("ruleset")
        );
    }

    #[tokio::test]
    async fn a_shared_backend_enforces_several_attachments_independently() {
        let one = attachment();
        let mut two = one.clone();
        two.sandbox_id = Uuid::parse_str("0192f0a1-4444-7000-8000-0000000000aa").expect("uuid");
        two.interface = "agtap1".to_string();
        two.guest_ip = Ipv4Addr::new(172, 30, 8, 6);
        two.gateway_ip = Ipv4Addr::new(172, 30, 8, 5);
        let backend = TestBackend::default();
        let policy = model_only_policy();
        backend.apply_policy(&policy, &one).await.expect("apply");
        backend.apply_policy(&policy, &two).await.expect("apply");
        assert!(backend.permits(
            &one,
            one.guest_ip,
            one.gateway_ip,
            Transport::Tcp,
            one.broker_port
        ));
        assert!(backend.permits(
            &two,
            two.guest_ip,
            two.gateway_ip,
            Transport::Tcp,
            two.broker_port
        ));
        // Each attachment has its own /30, and the invariant is that one
        // attachment's guest address is never a permit for the other's
        // listener, whatever the addresses happen to be.
        assert!(!backend.permits(
            &one,
            two.guest_ip,
            one.gateway_ip,
            Transport::Tcp,
            one.broker_port
        ));
        assert_eq!(
            backend.counters(&one).await.expect("counters").table,
            one.table_name()
        );
        backend.remove_policy(&one).await.expect("remove");
        assert_eq!(backend.state(one.sandbox_id), EnforcementState::Removed);
        assert_eq!(backend.state(two.sandbox_id), EnforcementState::Applied);
        assert!(backend.permits(
            &two,
            two.guest_ip,
            two.gateway_ip,
            Transport::Tcp,
            two.broker_port
        ));
    }
}
