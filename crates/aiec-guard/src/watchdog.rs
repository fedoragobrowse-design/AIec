//! Independent, deterministic host-side Guard observer. No guest advisory input
//! enters this API, and observation failure never authorizes a heartbeat.
use crate::{
    GuardError, Result,
    control::{
        GuardFence, GuardIdentity, GuardIncident, GuardObservation, QuarantineRequest, RuleTrigger,
    },
    enforcement::{CounterKind, CounterSnapshot},
    events::{Category, Decision, GENESIS_HASH, GuardEvent, MAX_PAGE_EVENTS},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::IpAddr,
    path::Path,
    time::Duration,
};
use zeroize::Zeroizing;

pub const MAX_RESPONSE_BYTES: usize = 20 * 1024 * 1024;
const MAX_RULES: usize = 16;
const MAX_REFERENCES: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WatchdogConfig {
    pub poll_interval_ms: u64,
    pub request_timeout_ms: u64,
    pub heartbeat_ttl_ms: u64,
    pub observation_max_age_ms: u64,
    pub window_seconds: u64,
    pub denied_threshold: u64,
    pub nxdomain_threshold: u64,
    pub suspicious_dns_threshold: u64,
    pub credential_misuse_threshold: u64,
    pub model_requests_threshold: u64,
    pub model_bytes_threshold: u64,
    pub large_request_bytes: u64,
    pub long_dns_name_bytes: usize,
    pub entropy_min_label_bytes: usize,
    pub entropy_bits_milli: u32,
    /// Operator-provided expected names, not guest-supplied learning.
    pub expected_domains: Vec<String>,
}
impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 1000,
            request_timeout_ms: 2000,
            heartbeat_ttl_ms: 10000,
            observation_max_age_ms: 3000,
            window_seconds: 60,
            denied_threshold: 5,
            nxdomain_threshold: 5,
            suspicious_dns_threshold: 3,
            credential_misuse_threshold: 1,
            model_requests_threshold: 120,
            model_bytes_threshold: 16 * 1024 * 1024,
            large_request_bytes: 1024 * 1024,
            long_dns_name_bytes: 180,
            entropy_min_label_bytes: 24,
            entropy_bits_milli: 4000,
            expected_domains: Vec::new(),
        }
    }
}
impl WatchdogConfig {
    pub fn validate(&self) -> Result<()> {
        let thresholds = [
            self.denied_threshold,
            self.nxdomain_threshold,
            self.suspicious_dns_threshold,
            self.credential_misuse_threshold,
            self.model_requests_threshold,
            self.model_bytes_threshold,
            self.large_request_bytes,
        ];
        if !(100..=30000).contains(&self.poll_interval_ms)
            || !(100..=10000).contains(&self.request_timeout_ms)
            || !(1000..=60000).contains(&self.heartbeat_ttl_ms)
            || self.poll_interval_ms + 2 * self.request_timeout_ms >= self.heartbeat_ttl_ms
            || !(100..=30000).contains(&self.observation_max_age_ms)
            || !(1..=3600).contains(&self.window_seconds)
            || thresholds.iter().any(|n| *n == 0 || *n > 1_000_000_000_000)
            || !(32..=253).contains(&self.long_dns_name_bytes)
            || !(8..=63).contains(&self.entropy_min_label_bytes)
            || !(1000..=6000).contains(&self.entropy_bits_milli)
            || self.expected_domains.len() > 1024
            || self.expected_domains.iter().any(|d| !valid_domain(d))
        {
            return Err(GuardError::Policy(
                "watchdog configuration outside bounded limits".into(),
            ));
        }
        Ok(())
    }
}
fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn valid_identity(identity: &GuardIdentity) -> Result<()> {
    if identity.sandbox_id.is_nil()
        || identity.tenant_id.is_nil()
        || identity.policy_hash.len() != 64
        || !identity
            .policy_hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(GuardError::Integrity("invalid watchdog identity".into()));
    }
    Ok(())
}
fn integrity(message: &'static str) -> GuardError {
    GuardError::Integrity(message.into())
}

/// Validate a contiguous authoritative journal page against an independently
/// supplied control-plane count/head, preserving the original event hash scheme.
pub fn validate_event_page(
    identity: &GuardIdentity,
    events: &[GuardEvent],
    after: u64,
    previous_hash: &str,
    total: u64,
    head: &str,
) -> Result<()> {
    valid_identity(identity)?;
    if events.len() > MAX_PAGE_EVENTS || after.checked_add(events.len() as u64) != Some(total) {
        return Err(integrity(
            "journal missing, truncated, oversized or rolled back",
        ));
    }
    if previous_hash.len() != 64
        || !previous_hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || (after == 0 && previous_hash != GENESIS_HASH)
    {
        return Err(integrity("invalid authoritative journal anchor"));
    }
    let mut previous = previous_hash;
    for event in events {
        event.verify_bounds()?;
        if event.sandbox_id != identity.sandbox_id
            || event.tenant_id != identity.tenant_id
            || event.policy_hash != identity.policy_hash
            || event.previous_hash != previous
        {
            return Err(integrity("journal identity or chain mismatch"));
        }
        event.verify_self_hash()?;
        previous = &event.current_hash;
    }
    if previous != head
        || head.len() != 64
        || !head
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(integrity("journal does not reach authoritative head"));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub struct WatchdogDecision {
    pub identity: GuardIdentity,
    pub fence: GuardFence,
    pub observed_at: DateTime<Utc>,
    pub event_sequence: u64,
    pub alerts: Vec<RuleTrigger>,
    pub quarantine_rules: Vec<RuleTrigger>,
}
#[derive(Clone, Default)]
struct RuleCount {
    count: u64,
    first: Option<u64>,
    references: Vec<String>,
}
impl RuleCount {
    fn add(&mut self, count: u64, sequence: Option<u64>, reference: String) {
        self.count = self.count.saturating_add(count);
        if self.first.is_none() {
            self.first = sequence;
        }
        if self.references.len() < MAX_REFERENCES && !self.references.contains(&reference) {
            self.references.push(reference);
        }
    }
    fn trigger(&self, rule: &str) -> RuleTrigger {
        RuleTrigger {
            rule: rule.into(),
            first_event_sequence: self.first,
            evidence_references: self.references.clone(),
        }
    }
}
/// One identity has independent counter, event and fixed-window cursors. State
/// commits only after the complete observation is validated.
pub struct Watchdog {
    identity: GuardIdentity,
    config: WatchdogConfig,
    domains: BTreeSet<String>,
    sequence: u64,
    head: String,
    counters: Option<CounterSnapshot>,
    budget: Option<crate::control::GuardBudgetState>,
    fence: Option<GuardFence>,
    observed_at: Option<DateTime<Utc>>,
    window_start: Option<DateTime<Utc>>,
    counts: BTreeMap<&'static str, RuleCount>,
}
impl Watchdog {
    pub fn new(identity: GuardIdentity, config: WatchdogConfig) -> Result<Self> {
        valid_identity(&identity)?;
        config.validate()?;
        let domains = config.expected_domains.iter().cloned().collect();
        Ok(Self {
            identity,
            config,
            domains,
            sequence: 0,
            head: GENESIS_HASH.into(),
            counters: None,
            budget: None,
            fence: None,
            observed_at: None,
            window_start: None,
            counts: BTreeMap::new(),
        })
    }
    pub fn cursor(&self) -> u64 {
        self.sequence
    }
    pub fn observe(
        &mut self,
        observation: &GuardObservation,
        now: DateTime<Utc>,
    ) -> Result<WatchdogDecision> {
        if observation.identity != self.identity
            || observation.budget.identity != self.identity
            || observation.fence.lease_id.is_nil()
            || observation.fence.generation < 0
        {
            return Err(integrity("observation identity or ownership invalid"));
        }
        if let Some(fence) = self.fence
            && (observation.fence.lease_id != fence.lease_id
                || observation.fence.generation < fence.generation)
        {
            return Err(integrity("observation ownership rolled back or changed"));
        }
        if let Some(old) = &self.budget {
            let current = &observation.budget;
            if current.expires_at != old.expires_at
                || current.max_model_requests != old.max_model_requests
                || current.max_bytes_in != old.max_bytes_in
                || current.max_bytes_out != old.max_bytes_out
                || current.model_requests < old.model_requests
                || current.bytes_in < old.bytes_in
                || current.bytes_out < old.bytes_out
                || (old.quarantined && !current.quarantined)
            {
                return Err(integrity(
                    "durable budget counters or immutable limits changed",
                ));
            }
        }
        let age = now
            .signed_duration_since(observation.observed_at)
            .num_milliseconds();
        if age < -1000
            || age > self.config.observation_max_age_ms as i64
            || self
                .observed_at
                .is_some_and(|last| observation.observed_at < last)
        {
            return Err(integrity("observation stale, future or rolled back"));
        }
        // Re-derive the table via the attachment's existing naming convention.
        let attachment = crate::enforcement::GuardAttachment {
            sandbox_id: self.identity.sandbox_id,
            tenant_id: self.identity.tenant_id,
            interface: String::new(),
            guest_ip: std::net::Ipv4Addr::UNSPECIFIED,
            gateway_ip: std::net::Ipv4Addr::UNSPECIFIED,
            dns_port: 0,
            broker_port: 0,
        };
        if observation.counters.table != attachment.table_name() {
            return Err(integrity("kernel counters belong to another attachment"));
        }
        for kind in CounterKind::ALL {
            if self
                .counters
                .as_ref()
                .is_some_and(|old| observation.counters.get(kind) < old.get(kind))
            {
                return Err(integrity("kernel counter rollback"));
            }
        }
        let after = observation
            .event_start_sequence
            .checked_sub(1)
            .ok_or_else(|| integrity("journal start sequence invalid"))?;
        if self.observed_at.is_some()
            && (after != self.sequence || observation.event_previous_hash != self.head)
        {
            return Err(integrity("journal skipped known cursor or changed anchor"));
        }
        validate_event_page(
            &self.identity,
            &observation.events,
            after,
            &observation.event_previous_hash,
            observation.event_sequence,
            &observation.event_head,
        )?;
        if observation
            .events
            .iter()
            .any(|event| event.timestamp > observation.observed_at + chrono::Duration::seconds(1))
        {
            return Err(integrity("journal event timestamp beyond observation"));
        }
        let counts = &mut self.counts;
        let window_start = match self.window_start {
            Some(start)
                if observation
                    .observed_at
                    .signed_duration_since(start)
                    .num_seconds()
                    < self.config.window_seconds as i64 =>
            {
                start
            }
            _ => {
                counts.clear();
                observation.observed_at
            }
        };
        let delta = |kind| {
            observation
                .counters
                .get(kind)
                .saturating_sub(self.counters.as_ref().map_or(0, |old| old.get(kind)))
        };
        let mut alerts = BTreeMap::<&'static str, RuleTrigger>::new();
        let blocked = delta(CounterKind::BlockedRange);
        if blocked > 0 {
            let mut evidence = RuleCount::default();
            evidence.add(
                blocked,
                None,
                format!(
                    "counter:{}:blocked_range:{}",
                    observation.counters.table, observation.counters.blocked_range
                ),
            );
            alerts.insert("blocked_range", evidence.trigger("blocked_range"));
        }
        let denied = blocked
            .saturating_add(delta(CounterKind::OtherDenied))
            .saturating_add(delta(CounterKind::Ipv6));
        if denied > 0 {
            counts
                .entry("repeated_denied_connections")
                .or_default()
                .add(
                    denied,
                    None,
                    format!(
                        "counter:{}:denied:{}:{}:{}",
                        observation.counters.table,
                        observation.counters.blocked_range,
                        observation.counters.other_denied,
                        observation.counters.ipv6
                    ),
                );
        }
        for (index, event) in observation.events.iter().enumerate() {
            let sequence = observation.event_start_sequence + index as u64;
            let reference = format!("event:{sequence}:{}", event.current_hash);
            // Historical replay retains integrity, but cannot inflate current rate windows.
            let recent = observation
                .observed_at
                .signed_duration_since(event.timestamp)
                .num_seconds()
                <= self.config.window_seconds as i64;
            let mut hit = |rule: &'static str, amount: u64| {
                alerts.entry(rule).or_insert_with(|| RuleTrigger {
                    rule: rule.into(),
                    first_event_sequence: Some(sequence),
                    evidence_references: vec![reference.clone()],
                });
                if recent {
                    counts
                        .entry(rule)
                        .or_default()
                        .add(amount, Some(sequence), reference.clone());
                }
            };
            if event.category == Category::Dns {
                if event.reason == "DNS NXDOMAIN" {
                    hit("nxdomain_burst", 1);
                }
                if event.reason == "DNS record type denied" {
                    hit("forbidden_record_type", 1);
                }
                if event.reason == "DNS name denied"
                    || event.reason == "DNS name or record type denied"
                    || event.destination.as_ref().is_some_and(|name| {
                        !self.domains.is_empty() && !self.domains.contains(name)
                    })
                {
                    hit("unexpected_domain", 1);
                }
                if let Some(name) = &event.destination {
                    if name.len() >= self.config.long_dns_name_bytes {
                        hit("long_dns_name", 1);
                    }
                    if name
                        .split('.')
                        .any(|label| high_entropy(label, &self.config))
                    {
                        hit("high_entropy_dns_label", 1);
                    }
                }
                if event.reason == "DNS name too long" {
                    hit("long_dns_name", 1);
                }
            }
            if event.decision == Decision::Deny
                && matches!(
                    event.category,
                    Category::Network | Category::Model | Category::Credential
                )
            {
                hit("repeated_denied_connections", 1);
            }
            if event.decision == Decision::Deny
                && (event.category == Category::Credential
                    || matches!(
                        event.reason.as_str(),
                        "model binding mismatch"
                            | "credential destination mismatch"
                            | "credential placeholder mismatch"
                            | "credentials forbidden on proxy"
                    ))
            {
                hit("credential_misuse", 1);
            }
            if event.category == Category::Model {
                if event.reason == "bound upstream request" || event.decision == Decision::Deny {
                    hit("abnormal_model_rate", 1);
                }
                if event.request_bytes > 0 || event.response_bytes > 0 {
                    hit(
                        "abnormal_model_bytes",
                        event.request_bytes.saturating_add(event.response_bytes),
                    );
                }
            }
            if event.request_bytes >= self.config.large_request_bytes
                || matches!(
                    event.reason.as_str(),
                    "request body too large" | "request body limit exceeded or gateway cut"
                )
            {
                hit("large_request", 1);
            }
        }
        let mut quarantine_rules = Vec::new();
        for (&rule, count) in counts.iter() {
            let threshold = match rule {
                "repeated_denied_connections" => self.config.denied_threshold,
                "nxdomain_burst" => self.config.nxdomain_threshold,
                "credential_misuse" => self.config.credential_misuse_threshold,
                "abnormal_model_rate" => self.config.model_requests_threshold,
                "abnormal_model_bytes" => self.config.model_bytes_threshold,
                "large_request" => 1,
                _ => self.config.suspicious_dns_threshold,
            };
            if count.count >= threshold {
                quarantine_rules.push(count.trigger(rule));
            }
        }
        self.window_start = Some(window_start);
        self.sequence = observation.event_sequence;
        self.head.clone_from(&observation.event_head);
        self.counters = Some(observation.counters.clone());
        self.budget = Some(observation.budget.clone());
        self.fence = Some(observation.fence);
        self.observed_at = Some(observation.observed_at);
        Ok(WatchdogDecision {
            identity: self.identity.clone(),
            fence: observation.fence,
            observed_at: observation.observed_at,
            event_sequence: self.sequence,
            alerts: alerts.into_values().collect(),
            quarantine_rules,
        })
    }
}
fn high_entropy(label: &str, config: &WatchdogConfig) -> bool {
    if label.len() < config.entropy_min_label_bytes || !label.is_ascii() {
        return false;
    }
    let mut counts = [0u32; 128];
    for byte in label.bytes() {
        counts[byte as usize] += 1;
    }
    let size = label.len() as f64;
    let entropy: f64 = counts
        .into_iter()
        .filter(|n| *n > 0)
        .map(|n| {
            let p = n as f64 / size;
            -p * p.log2()
        })
        .sum();
    (entropy * 1000.0).floor() as u32 >= config.entropy_bits_milli
}

fn validate_rules(rules: &[RuleTrigger]) -> Result<()> {
    if rules.len() > MAX_RULES
        || rules.iter().any(|rule| {
            rule.rule.is_empty()
                || rule.rule.len() > 64
                || !rule
                    .rule
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || rule.evidence_references.len() > MAX_REFERENCES
                || rule.evidence_references.iter().any(|r| {
                    r.len() > 256 || !r.is_ascii() || r.bytes().any(|b| b.is_ascii_control())
                })
        })
    {
        return Err(integrity("incident rule evidence outside bounds"));
    }
    Ok(())
}
pub fn validate_incident(incident: &GuardIncident) -> Result<()> {
    validate_rules(&incident.rules)?;
    let after = incident
        .event_start_sequence
        .checked_sub(1)
        .ok_or_else(|| integrity("incident start sequence invalid"))?;
    validate_event_page(
        &incident.identity,
        &incident.events,
        after,
        &incident.event_previous_hash,
        incident.event_sequence,
        &incident.event_head,
    )?;
    if incident.id.is_nil()
        || incident.fence.lease_id.is_nil()
        || incident.fence.generation < 0
        || incident.snapshot_id.as_ref().is_some_and(|s| {
            s.len() > 256 || !s.is_ascii() || s.bytes().any(|b| b.is_ascii_control())
        })
        || incident.errors.len() > 32
        || incident.errors.iter().any(|s| s.len() > 512)
    {
        return Err(integrity("incident metadata outside bounds"));
    }
    for rule in &incident.rules {
        if let Some(sequence) = rule.first_event_sequence
            && (sequence == 0 || sequence > incident.event_sequence)
        {
            return Err(integrity(
                "first suspicious event absent from incident evidence",
            ));
        }
        for reference in &rule.evidence_references {
            if let Some(rest) = reference.strip_prefix("event:") {
                let (sequence, hash) = rest
                    .split_once(':')
                    .ok_or_else(|| integrity("invalid event reference"))?;
                let sequence: u64 = sequence
                    .parse()
                    .map_err(|_| integrity("invalid event reference"))?;
                if sequence == 0
                    || sequence > incident.event_sequence
                    || hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    || (sequence >= incident.event_start_sequence
                        && incident
                            .events
                            .get((sequence - incident.event_start_sequence) as usize)
                            .is_none_or(|event| event.current_hash != hash))
                {
                    return Err(integrity(
                        "event reference does not match authoritative journal",
                    ));
                }
            }
        }
    }
    if incident
        .network_cut_at
        .is_some_and(|time| time < incident.triggered_at)
        || incident
            .paused_at
            .is_some_and(|time| incident.network_cut_at.is_none_or(|cut| time < cut))
        || incident.completed_at.is_some_and(|time| {
            incident.paused_at.is_none_or(|pause| time < pause) || incident.snapshot_id.is_none()
        })
    {
        return Err(integrity("incident stage timestamps invalid"));
    }
    Ok(())
}
/// Encode every punctuation/control/non-ASCII byte as an HTML numeric entity:
/// no event string can create links, images, headings, HTML or table columns.
fn escaped(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == ' ' {
            out.push(ch);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "&#{};", ch as u32);
        }
    }
    out
}
fn timestamp(value: Option<DateTime<Utc>>) -> String {
    value.map_or_else(|| "pending".into(), |t| t.to_rfc3339())
}
pub fn generate_incident_report(incident: &GuardIncident) -> Result<String> {
    validate_incident(incident)?;
    use std::fmt::Write;
    let mut report = format!(
        "# Guard incident\n\n- Incident: {}\n- Sandbox: {}\n- Tenant: {}\n- Policy hash: {}\n- Lease: {}\n- Generation: {}\n\n## Timeline\n\n- Triggered: {}\n- Network cut: {}\n- Paused: {}\n- Snapshot: {}\n- Completed: {}\n\n## Rules and evidence\n\n",
        incident.id,
        incident.identity.sandbox_id,
        incident.identity.tenant_id,
        incident.identity.policy_hash,
        incident.fence.lease_id,
        incident.fence.generation,
        incident.triggered_at.to_rfc3339(),
        timestamp(incident.network_cut_at),
        timestamp(incident.paused_at),
        incident
            .snapshot_id
            .as_deref()
            .map(escaped)
            .unwrap_or_else(|| "pending".into()),
        timestamp(incident.completed_at)
    );
    for rule in &incident.rules {
        let _ = writeln!(report, "- Rule: {}", escaped(&rule.rule));
        for reference in &rule.evidence_references {
            let _ = writeln!(report, "  - Evidence: {}", escaped(reference));
        }
    }
    report.push_str("\n## First suspicious event\n\n");
    let first = incident
        .rules
        .iter()
        .filter_map(|r| r.first_event_sequence)
        .min();
    if let Some(sequence) = first.filter(|sequence| *sequence >= incident.event_start_sequence) {
        let event = &incident.events[(sequence - incident.event_start_sequence) as usize];
        let _ = writeln!(
            report,
            "- Sequence: {sequence}\n- Event: {}\n- Time: {}\n- Category: {}\n- Decision: {}\n- Reason: {}\n- Destination: {}\n- Request bytes: {}\n- Response bytes: {}\n- Hash: {}",
            event.event_id,
            event.timestamp.to_rfc3339(),
            event.category,
            event.decision,
            escaped(&event.reason),
            event
                .destination
                .as_deref()
                .map(escaped)
                .unwrap_or_else(|| "none".into()),
            event.request_bytes,
            event.response_bytes,
            event.current_hash
        );
    } else if let Some(sequence) = first {
        let _ = writeln!(
            report,
            "First suspicious event sequence: {sequence}; outside this bounded authoritative excerpt. Its rule evidence reference is retained above."
        );
    } else {
        report.push_str(
            "No event reference: see authoritative counter/control evidence references above.\n",
        );
    }
    let _ = writeln!(
        report,
        "\n## Authoritative journal\n\n- Records: {}\n- Earlier records omitted: {}\n- Excerpt previous hash: {}\n- Verified head: {}",
        incident.event_sequence,
        incident.event_start_sequence - 1,
        incident.event_previous_hash,
        incident.event_head
    );
    if !incident.errors.is_empty() {
        report.push_str("\n## Incomplete stages\n\n");
        for error in &incident.errors {
            let _ = writeln!(report, "- {}", escaped(error));
        }
    }
    Ok(report)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationOutcome {
    Disabled,
    Delivered,
}
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn notify(&self, incident: &GuardIncident) -> Result<NotificationOutcome>;
}
pub struct DisabledNotifier;
#[async_trait]
impl Notifier for DisabledNotifier {
    async fn notify(&self, incident: &GuardIncident) -> Result<NotificationOutcome> {
        validate_incident(incident)?;
        Ok(NotificationOutcome::Disabled)
    }
}
/// The endpoint must be operator-owned. No redirect, credential-bearing URL,
/// certificate bypass or arbitrary plaintext transport is allowed.
pub fn validate_transport_url(url: &url::Url, local_loopback_http: bool) -> Result<()> {
    let loopback = url
        .host_str()
        .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || !(url.scheme() == "https" || (local_loopback_http && url.scheme() == "http" && loopback))
    {
        return Err(GuardError::Policy(
            "transport requires verified HTTPS or explicit numeric-loopback HTTP".into(),
        ));
    }
    Ok(())
}
/// Largest control-plane CA this process will read, so an operator's flag
/// cannot make it load an unbounded file at startup.
const MAX_CA_BYTES: u64 = 1024 * 1024;
fn client(timeout_ms: u64, ca_cert: Option<&Path>) -> Result<reqwest::Client> {
    if !(100..=10000).contains(&timeout_ms) {
        return Err(GuardError::Policy("HTTP timeout outside bounds".into()));
    }
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .connect_timeout(Duration::from_millis(timeout_ms))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(path) = ca_cert {
        // A private certificate authority is an operator's own deployment
        // choice. Verification stays on: the certificate is added as a root, not
        // switched off, so an operator who points this at the wrong file gets a
        // refusal rather than an unverified connection.
        let file = std::fs::File::open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() > MAX_CA_BYTES {
            return Err(GuardError::Policy("invalid control-plane CA file".into()));
        }
        let mut pem = Vec::new();
        std::io::Read::take(file, MAX_CA_BYTES + 1).read_to_end(&mut pem)?;
        if pem.len() as u64 > MAX_CA_BYTES {
            return Err(GuardError::Policy(
                "control-plane CA file is too large".into(),
            ));
        }
        let certificate = reqwest::Certificate::from_pem(&pem)
            .map_err(|_| GuardError::Policy("invalid control-plane CA certificate".into()))?;
        builder = builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|_| GuardError::Unavailable("HTTP client initialization failed".into()))
}
/// Read tokens outside the guest. A file is owner-readable only; the secret is
/// never a CLI argument, URL, debug value, error body or notification payload.
pub fn load_operator_token(
    file: Option<&Path>,
    env_name: Option<&str>,
) -> Result<Zeroizing<String>> {
    if file.is_some() == env_name.is_some() {
        return Err(GuardError::Policy(
            "choose exactly one token file or environment variable name".into(),
        ));
    }
    let mut token = Zeroizing::new(String::new());
    if let Some(path) = file {
        let opened = std::fs::File::open(path)?;
        let meta = opened.metadata()?;
        if !meta.is_file() || meta.len() > 4096 {
            return Err(GuardError::Policy("token file outside bounds".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
                return Err(GuardError::Policy(
                    "token file must be owner-owned and owner-readable only".into(),
                ));
            }
        }
        opened.take(4097).read_to_string(&mut token)?;
    } else if let Some(name) = env_name {
        let value = std::env::var(name).map_err(|_| {
            GuardError::Policy("operator token environment variable unavailable".into())
        })?;
        *token = value;
    }
    // Only trim surrounding file/environment whitespace, without making a
    // second plaintext copy of the secret.
    let end = token
        .trim_end_matches(|c: char| c.is_ascii_whitespace())
        .len();
    token.truncate(end);
    let start = token.len()
        - token
            .trim_start_matches(|c: char| c.is_ascii_whitespace())
            .len();
    token.drain(..start);
    if token.is_empty()
        || token.len() > 4096
        || !token.is_ascii()
        || token
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(GuardError::Policy("operator token outside bounds".into()));
    }
    Ok(token)
}
async fn bounded_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T> {
    if !response.status().is_success() {
        return Err(GuardError::Unavailable(
            "control-plane request refused".into(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(integrity("HTTP evidence response oversized"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GuardError::Unavailable("HTTP evidence response interrupted".into()))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(integrity("HTTP evidence response oversized"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| integrity("invalid authoritative HTTP evidence"))
}
/// Parses and validates a webhook endpoint under the same transport rules the
/// notifier itself applies, so a caller can report an unusable URL as a
/// configuration fault rather than discovering it at first delivery.
pub fn parse_webhook_url(raw: &str, local_loopback_http: bool) -> Result<url::Url> {
    let endpoint =
        url::Url::parse(raw).map_err(|_| GuardError::Policy("webhook URL is not valid".into()))?;
    validate_transport_url(&endpoint, local_loopback_http)?;
    Ok(endpoint)
}
pub struct WebhookNotifier {
    client: reqwest::Client,
    endpoint: url::Url,
    token: Option<Zeroizing<String>>,
}
impl WebhookNotifier {
    pub fn new(
        endpoint: url::Url,
        token: Option<Zeroizing<String>>,
        timeout_ms: u64,
        local_loopback_http: bool,
    ) -> Result<Self> {
        Self::with_ca(endpoint, token, timeout_ms, local_loopback_http, None)
    }
    /// The notifier with an operator's private certificate authority, for a
    /// webhook endpoint behind the same CA as the rest of the deployment.
    pub fn with_ca(
        endpoint: url::Url,
        token: Option<Zeroizing<String>>,
        timeout_ms: u64,
        local_loopback_http: bool,
        ca_cert: Option<&Path>,
    ) -> Result<Self> {
        validate_transport_url(&endpoint, local_loopback_http)?;
        Ok(Self {
            client: client(timeout_ms, ca_cert)?,
            endpoint,
            token,
        })
    }
}
#[async_trait]
impl Notifier for WebhookNotifier {
    async fn notify(&self, incident: &GuardIncident) -> Result<NotificationOutcome> {
        validate_incident(incident)?;
        // No raw reasons/destinations, errors, prompts, credentials or report body.
        let rules: Vec<_> = incident
            .rules
            .iter()
            .map(|rule| {
                serde_json::json!({
                    "rule":rule.rule, "first_event_sequence":rule.first_event_sequence
                })
            })
            .collect();
        let payload = serde_json::json!({"incident_id":incident.id,"identity":incident.identity,"rules":rules,
            "triggered_at":incident.triggered_at,"network_cut_at":incident.network_cut_at,"paused_at":incident.paused_at,
            "snapshot_id":incident.snapshot_id,"completed_at":incident.completed_at,"event_sequence":incident.event_sequence,"event_head":incident.event_head});
        let mut request = self.client.post(self.endpoint.clone()).json(&payload);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_str());
        }
        let response = request
            .send()
            .await
            .map_err(|_| GuardError::Unavailable("incident webhook unavailable".into()))?;
        if !response.status().is_success() {
            return Err(GuardError::Unavailable("incident webhook refused".into()));
        }
        Ok(NotificationOutcome::Delivered)
    }
}
/// Outside-guest operator transport; authentication/tenant scope is enforced by
/// the control plane, and exact expected identity is verified by the observer.
pub struct ControlPlaneTransport {
    client: reqwest::Client,
    base: url::Url,
    token: Zeroizing<String>,
    identity: GuardIdentity,
}
impl ControlPlaneTransport {
    pub fn new(
        base: url::Url,
        token: Zeroizing<String>,
        identity: GuardIdentity,
        timeout_ms: u64,
        local_loopback_http: bool,
    ) -> Result<Self> {
        Self::with_ca(base, token, identity, timeout_ms, local_loopback_http, None)
    }
    /// The transport with an operator's private certificate authority. TLS
    /// verification is never disabled: a private CA is added as a root.
    pub fn with_ca(
        base: url::Url,
        token: Zeroizing<String>,
        identity: GuardIdentity,
        timeout_ms: u64,
        local_loopback_http: bool,
        ca_cert: Option<&Path>,
    ) -> Result<Self> {
        validate_transport_url(&base, local_loopback_http)?;
        valid_identity(&identity)?;
        if base.path() != "/" {
            return Err(GuardError::Policy(
                "control-plane URL must be an origin".into(),
            ));
        }
        Ok(Self {
            client: client(timeout_ms, ca_cert)?,
            base,
            token,
            identity,
        })
    }
    fn endpoint(&self, suffix: &str) -> Result<url::Url> {
        self.base
            .join(&format!(
                "/v1/sandboxes/{}/guard/{suffix}",
                self.identity.sandbox_id
            ))
            .map_err(|_| GuardError::Policy("invalid control-plane endpoint".into()))
    }
    pub async fn observe(&self, after: u64) -> Result<GuardObservation> {
        let response = self
            .client
            .get(self.endpoint("telemetry")?)
            .query(&[("after", after)])
            .bearer_auth(self.token.as_str())
            .send()
            .await
            .map_err(|_| GuardError::Unavailable("authoritative observation lost".into()))?;
        bounded_json(response).await
    }
    pub async fn heartbeat(&self, fence: GuardFence) -> Result<()> {
        let response = self
            .client
            .post(self.endpoint("heartbeat")?)
            .bearer_auth(self.token.as_str())
            .json(&serde_json::json!({"fence":fence,"policy_hash":self.identity.policy_hash}))
            .send()
            .await
            .map_err(|_| GuardError::Unavailable("watchdog heartbeat lost".into()))?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(GuardError::Unavailable("watchdog heartbeat refused".into()));
        }
        Ok(())
    }
    pub async fn quarantine(
        &self,
        fence: GuardFence,
        rules: Vec<RuleTrigger>,
    ) -> Result<GuardIncident> {
        validate_rules(&rules)?;
        let response = self
            .client
            .post(self.endpoint("quarantine")?)
            .bearer_auth(self.token.as_str())
            .json(&QuarantineRequest {
                fence,
                policy_hash: self.identity.policy_hash.clone(),
                rules,
            })
            .send()
            .await
            .map_err(|_| GuardError::Unavailable("quarantine dispatch lost".into()))?;
        let incident: GuardIncident = bounded_json(response).await?;
        if incident.identity != self.identity
            || incident.fence.lease_id != fence.lease_id
            || incident.fence.generation < fence.generation
        {
            return Err(integrity("quarantine result identity mismatch"));
        }
        validate_incident(&incident)?;
        Ok(incident)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{control::GuardBudgetState, events::EventInput};
    use uuid::Uuid;
    fn identity() -> GuardIdentity {
        GuardIdentity {
            sandbox_id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            policy_hash: "a".repeat(64),
        }
    }
    fn event(reason: &str, category: Category, previous: &str, now: DateTime<Utc>) -> GuardEvent {
        let id = identity();
        GuardEvent::new(
            now,
            Uuid::new_v4(),
            EventInput {
                sandbox_id: id.sandbox_id,
                tenant_id: id.tenant_id,
                policy_hash: id.policy_hash,
                category,
                decision: Decision::Deny,
                reason: reason.into(),
                ..Default::default()
            },
            previous.into(),
        )
        .unwrap()
    }
    fn observation(events: Vec<GuardEvent>, blocked: u64, now: DateTime<Utc>) -> GuardObservation {
        let id = identity();
        let attachment = crate::enforcement::GuardAttachment {
            sandbox_id: id.sandbox_id,
            tenant_id: id.tenant_id,
            interface: String::new(),
            guest_ip: std::net::Ipv4Addr::UNSPECIFIED,
            gateway_ip: std::net::Ipv4Addr::UNSPECIFIED,
            dns_port: 0,
            broker_port: 0,
        };
        GuardObservation {
            identity: id.clone(),
            fence: GuardFence {
                lease_id: Uuid::from_u128(3),
                generation: 1,
            },
            counters: CounterSnapshot {
                table: attachment.table_name(),
                blocked_range: blocked,
                ..Default::default()
            },
            event_start_sequence: 1,
            event_previous_hash: GENESIS_HASH.into(),
            event_sequence: events.len() as u64,
            event_head: events
                .last()
                .map_or_else(|| GENESIS_HASH.into(), |e| e.current_hash.clone()),
            events,
            observed_at: now,
            network_cut: false,
            paused: false,
            budget: GuardBudgetState {
                identity: id,
                expires_at: now + chrono::Duration::hours(1),
                max_model_requests: 1000,
                max_bytes_in: 1_000_000,
                max_bytes_out: 1_000_000,
                model_requests: 0,
                bytes_in: 0,
                bytes_out: 0,
                quarantined: false,
            },
        }
    }
    #[test]
    fn first_blocked_attempt_alerts_repeated_denials_quarantine() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut watchdog = Watchdog::new(identity(), WatchdogConfig::default()).unwrap();
        let first = watchdog
            .observe(&observation(Vec::new(), 1, now), now)
            .unwrap();
        assert_eq!(first.alerts[0].rule, "blocked_range");
        assert!(first.quarantine_rules.is_empty());
        let repeated = watchdog
            .observe(&observation(Vec::new(), 5, now), now)
            .unwrap();
        assert!(
            repeated
                .quarantine_rules
                .iter()
                .any(|r| r.rule == "repeated_denied_connections")
        );
        assert!(
            watchdog
                .observe(&observation(Vec::new(), 4, now), now)
                .is_err()
        );
    }
    #[test]
    fn rejects_tampering_crossidentity_and_unverifiable_tail_without_cursor_commit() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let one = event("DNS name denied", Category::Dns, GENESIS_HASH, now);
        let two = event(
            "DNS record type denied",
            Category::Dns,
            &one.current_hash,
            now,
        );
        let full = observation(vec![one.clone(), two], 0, now);
        let mut watchdog = Watchdog::new(identity(), WatchdogConfig::default()).unwrap();
        let mut truncated = full.clone();
        truncated.events.pop();
        assert!(watchdog.observe(&truncated, now).is_err());
        let mut altered = full.clone();
        altered.events[0].reason = "changed".into();
        assert!(watchdog.observe(&altered, now).is_err());
        let mut crossed = full.clone();
        crossed.events[0].tenant_id = Uuid::from_u128(9);
        crossed.events[0].current_hash = crossed.events[0].compute_hash();
        assert!(watchdog.observe(&crossed, now).is_err());
        assert_eq!(watchdog.cursor(), 0);
        watchdog.observe(&full, now).unwrap();
        let mut rollback = observation(Vec::new(), 0, now);
        rollback.event_sequence = 1;
        rollback.event_head = one.current_hash;
        assert!(watchdog.observe(&rollback, now).is_err());
    }
    #[test]
    fn failed_dns_attempts_reach_exact_threshold_and_advisory_is_rejected() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut events = Vec::new();
        let mut head = GENESIS_HASH.to_string();
        for _ in 0..5 {
            let e = event("DNS NXDOMAIN", Category::Dns, &head, now);
            head = e.current_hash.clone();
            events.push(e);
        }
        let full = observation(events, 0, now);
        let mut watchdog = Watchdog::new(identity(), WatchdogConfig::default()).unwrap();
        let decision = watchdog.observe(&full, now).unwrap();
        assert!(
            decision
                .quarantine_rules
                .iter()
                .any(|r| r.rule == "nxdomain_burst" && r.first_event_sequence == Some(1))
        );
        let mut wire = serde_json::to_value(&full).unwrap();
        wire["advisory"] = serde_json::json!({"guest_says":"safe"});
        assert!(serde_json::from_value::<GuardObservation>(wire).is_err());
    }
    #[test]
    fn bounded_configuration_stale_observations_and_foreign_counters_fail_closed() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let refused = WatchdogConfig {
            denied_threshold: 0,
            ..Default::default()
        };
        assert!(Watchdog::new(identity(), refused).is_err());
        let mut watchdog = Watchdog::new(identity(), WatchdogConfig::default()).unwrap();
        let mut old = observation(Vec::new(), 0, now - chrono::Duration::seconds(10));
        assert!(watchdog.observe(&old, now).is_err());
        old.observed_at = now;
        old.counters.table = "other_tenant_table".into();
        assert!(watchdog.observe(&old, now).is_err());
        let e = event("DNS NXDOMAIN", Category::Dns, GENESIS_HASH, now);
        assert!(
            validate_event_page(
                &identity(),
                &vec![e; MAX_PAGE_EVENTS + 1],
                0,
                GENESIS_HASH,
                (MAX_PAGE_EVENTS + 1) as u64,
                GENESIS_HASH
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn report_escapes_evidence_and_refuses_false_completion_or_tail() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let e = event(
            "[click](https://evil) <script>",
            Category::Network,
            GENESIS_HASH,
            now,
        );
        let mut incident = GuardIncident {
            id: Uuid::from_u128(4),
            identity: identity(),
            fence: GuardFence {
                lease_id: Uuid::from_u128(3),
                generation: 1,
            },
            rules: vec![RuleTrigger {
                rule: "repeated_denied_connections".into(),
                first_event_sequence: Some(1),
                evidence_references: vec![format!("event:1:{}", e.current_hash)],
            }],
            triggered_at: now,
            network_cut_at: Some(now),
            paused_at: Some(now),
            snapshot_id: Some("snapshot_1".into()),
            completed_at: Some(now),
            event_start_sequence: 1,
            event_previous_hash: GENESIS_HASH.into(),
            event_sequence: 1,
            event_head: e.current_hash.clone(),
            events: vec![e],
            errors: Vec::new(),
            notified_at: None,
            report: String::new(),
        };
        let report = generate_incident_report(&incident).unwrap();
        assert!(report.contains("&#91;click&#93;"));
        assert!(!report.contains("<script>"));
        assert!(!report.contains("[click]"));
        let next_event = event(
            "quarantine recorded",
            Category::Quarantine,
            &incident.event_head,
            now,
        );
        incident.event_start_sequence = 2;
        incident
            .event_previous_hash
            .clone_from(&incident.event_head);
        incident.event_sequence = 2;
        incident.event_head.clone_from(&next_event.current_hash);
        incident.events = vec![next_event];
        let suffix_report = generate_incident_report(&incident).unwrap();
        assert!(suffix_report.contains("outside this bounded authoritative excerpt"));
        assert_eq!(
            DisabledNotifier.notify(&incident).await.unwrap(),
            NotificationOutcome::Disabled
        );
        incident.paused_at = None;
        assert!(generate_incident_report(&incident).is_err());
        incident.paused_at = Some(now);
        incident.events.clear();
        assert!(generate_incident_report(&incident).is_err());
    }
    #[test]
    fn detects_dns_and_model_rules_without_payloads() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let config = WatchdogConfig {
            model_requests_threshold: 1,
            model_bytes_threshold: 100,
            suspicious_dns_threshold: 1,
            expected_domains: vec!["expected.example".into()],
            entropy_min_label_bytes: 8,
            entropy_bits_milli: 2000,
            long_dns_name_bytes: 32,
            ..Default::default()
        };
        let mut dns = event("DNS record type denied", Category::Dns, GENESIS_HASH, now);
        dns.destination = Some("abcdefghijklmnopqrstuvwxyz0123456789.unexpected.example".into());
        dns.current_hash = dns.compute_hash();
        let mut model = event(
            "bound upstream request",
            Category::Model,
            &dns.current_hash,
            now,
        );
        model.request_bytes = 2 * 1024 * 1024;
        model.current_hash = model.compute_hash();
        let mut watchdog = Watchdog::new(identity(), config).unwrap();
        let decision = watchdog
            .observe(&observation(vec![dns, model], 0, now), now)
            .unwrap();
        for rule in [
            "forbidden_record_type",
            "unexpected_domain",
            "high_entropy_dns_label",
            "long_dns_name",
            "abnormal_model_rate",
            "abnormal_model_bytes",
            "large_request",
        ] {
            assert!(
                decision.quarantine_rules.iter().any(|r| r.rule == rule),
                "{rule}"
            );
        }
    }
    #[test]
    fn authoritative_suffix_bootstraps_but_cannot_skip_a_known_cursor() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let one = event("DNS NXDOMAIN", Category::Dns, GENESIS_HASH, now);
        let two = event(
            "DNS record type denied",
            Category::Dns,
            &one.current_hash,
            now,
        );
        let three = event("DNS name denied", Category::Dns, &two.current_hash, now);
        let mut suffix = observation(vec![two.clone()], 0, now);
        suffix.event_start_sequence = 2;
        suffix.event_previous_hash = one.current_hash.clone();
        suffix.event_sequence = 2;
        let mut watchdog = Watchdog::new(identity(), WatchdogConfig::default()).unwrap();
        let first = watchdog.observe(&suffix, now).unwrap();
        assert!(
            first
                .alerts
                .iter()
                .any(|r| r.first_event_sequence == Some(2))
        );
        let mut skipped = observation(vec![three.clone()], 0, now);
        skipped.event_start_sequence = 4;
        skipped.event_previous_hash = two.current_hash.clone();
        skipped.event_sequence = 4;
        assert!(watchdog.observe(&skipped, now).is_err());
        skipped.event_start_sequence = 3;
        skipped.event_sequence = 3;
        watchdog.observe(&skipped, now).unwrap();
        assert_eq!(watchdog.cursor(), 3);
    }

    #[test]
    fn fixed_window_expires_and_budget_counter_rollback_withholds_authority() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut watchdog = Watchdog::new(identity(), WatchdogConfig::default()).unwrap();
        let mut first = observation(Vec::new(), 4, now);
        first.budget.model_requests = 3;
        watchdog.observe(&first, now).unwrap();
        let later = now + chrono::Duration::seconds(61);
        let mut next = observation(Vec::new(), 5, later);
        next.budget.expires_at = first.budget.expires_at;
        next.budget.model_requests = 3;
        assert!(
            watchdog
                .observe(&next, later)
                .unwrap()
                .quarantine_rules
                .is_empty()
        );
        next.budget.model_requests = 2;
        assert!(watchdog.observe(&next, later).is_err());
    }

    #[test]
    fn transport_requires_tls_and_explicit_loopback_plaintext() {
        assert!(
            validate_transport_url(&url::Url::parse("http://127.0.0.1:8080/").unwrap(), false)
                .is_err()
        );
        assert!(
            validate_transport_url(&url::Url::parse("http://127.0.0.1:8080/").unwrap(), true)
                .is_ok()
        );
        assert!(
            validate_transport_url(&url::Url::parse("http://example.com/").unwrap(), true).is_err()
        );
        assert!(
            validate_transport_url(
                &url::Url::parse("https://token@example.com/").unwrap(),
                false
            )
            .is_err()
        );
        assert!(
            validate_transport_url(
                &url::Url::parse("https://example.com/?token=secret").unwrap(),
                false
            )
            .is_err()
        );
    }
}
