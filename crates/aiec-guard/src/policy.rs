//! Strict, versioned Guard policy model.
//!
//! A policy is guest-independent operator configuration: it is parsed, validated
//! and canonicalized outside the sandbox, then hashed so the effective policy
//! can be stored next to a sandbox run.
//!
//! Design rules encoded here:
//!
//! * default deny - an empty policy is [`PolicyTemplate::NoNetwork`], never open
//!   internet;
//! * strict parsing - unknown and duplicate YAML keys are rejected, every input
//!   is bounded, and hosts/ports/protocols/paths/methods must be canonical;
//! * deterministic hashing - [`GuardPolicy::canonical_json`] and
//!   [`GuardPolicy::hash`] normalize semantic ordering (rule, zone, method, path
//!   and binding lists are sets) so two equivalent policies hash identically;
//! * no secrets - [`ModelEndpoint::credential`] is a *binding name*, never a
//!   secret value; error messages carry bounded metadata only.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{GuardError, Result};

/// The one grammar for a Guard rule name.
///
/// Rule names travel from the policy compiler, through the hash-chained
/// journal, into the watchdog's independent evidence checks, so the grammar
/// belongs to one definition. It was stated twice with two different charsets,
/// and the stricter of the two rejected `canary.credential-presented` - a rule
/// name this product emits - which stopped a canary incident from ever being
/// reported. `[A-Za-z0-9._-]` covers both families: the built-in detector
/// names (`repeated_denied_connections`) and the canary names
/// (`canary.credential-presented`). Rule names are identifiers, never data, so
/// nothing that could carry a value passes.
pub fn is_rule_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The only policy version this Guard understands.
pub const POLICY_VERSION: u32 = 1;

/// Maximum accepted size of a serialized policy document.
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
/// Maximum accepted DNS name length in bytes.
pub const MAX_HOST_BYTES: usize = 253;
/// Maximum accepted single DNS label length in bytes.
pub const MAX_LABEL_BYTES: usize = 63;
/// Maximum accepted HTTP path length in bytes.
pub const MAX_PATH_BYTES: usize = 512;
/// Maximum accepted HTTP method length in bytes.
pub const MAX_METHOD_BYTES: usize = 32;
/// Maximum accepted count of entries in any policy list.
pub const MAX_LIST_ITEMS: usize = 32;
/// Maximum accepted count of egress rules.
pub const MAX_EGRESS_RULES: usize = 128;
/// Maximum accepted count of DNS zones.
pub const MAX_DNS_ZONES: usize = 64;
/// Maximum accepted count of credential bindings.
pub const MAX_CREDENTIAL_BINDINGS: usize = 32;
/// Maximum accepted count of DNS record types.
pub const MAX_RECORD_TYPES: usize = 4;

/// Credential binding name used when a model endpoint does not name one.
pub const DEFAULT_CREDENTIAL_BINDING: &str = "model-main";
/// Header a credential binding uses when it does not name one.
pub const DEFAULT_CREDENTIAL_HEADER: &str = "authorization";
/// The only egress transport protocol of phase 1.
pub const EGRESS_PROTOCOL_TCP: &str = "tcp";
/// Scheme used by a model endpoint unless it opts into the operator test path.
pub const MODEL_SCHEME_HTTPS: &str = "https";
/// Scheme that is only ever valid behind an explicit operator test mapping.
pub const MODEL_SCHEME_HTTP: &str = "http";
/// Header names a credential binding may carry.
pub const ALLOWED_CREDENTIAL_HEADERS: [&str; 2] = ["authorization", "x-api-key"];
/// DNS record types the schema accepts. `ANY`, `NS`, `TXT` and `NULL` are not
/// accepted: refusing them is explicit, silently dropping them would be a
/// downgrade the operator cannot see.
pub const ALLOWED_RECORD_TYPES: [&str; 2] = ["A", "AAAA"];
/// Methods `PolicyTemplate::ReadOnlyApi` permits.
pub const READ_ONLY_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];

const LIMIT_MAX_REQUESTS_PER_MINUTE: u32 = 100_000;
const LIMIT_MAX_DNS_QUERIES_PER_MINUTE: u32 = 100_000;
const LIMIT_MAX_BYTES: u64 = 1 << 40;
const LIMIT_MAX_REQUEST_BYTES: u64 = 64 << 20;
const LIMIT_MAX_RESPONSE_BYTES: u64 = 512 << 20;
const LIMIT_MAX_CONCURRENT_REQUESTS: u32 = 1_024;

/// Parses an operator boundary document.
pub fn parse_boundary(text: &str) -> Result<crate::compiler::OperatorBoundary> {
    serde_yaml_ng::from_str(text)
        .map_err(|error| policy_error(format!("operator boundary: {error}")))
}

/// Serializes a policy as YAML.
pub fn to_yaml(policy: &GuardPolicy) -> Result<String> {
    serde_yaml_ng::to_string(policy)
        .map_err(|error| policy_error(format!("policy serialization: {error}")))
}

/// Serializes a layer 7 policy as YAML.
pub fn l7_to_yaml(policy: &L7Policy) -> Result<String> {
    serde_yaml_ng::to_string(policy)
        .map_err(|error| policy_error(format!("layer 7 policy serialization: {error}")))
}

fn policy_error(message: impl Into<String>) -> GuardError {
    GuardError::Policy(message.into())
}

/// Bounds a value embedded in an error or event so untrusted input cannot grow
/// evidence records without limit.
fn bounded(value: &str) -> String {
    const LIMIT: usize = 96;
    let mut out = String::with_capacity(LIMIT + 3);
    for (index, ch) in value.chars().enumerate() {
        if index >= LIMIT {
            out.push('…');
            break;
        }
        if ch.is_control() {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

fn check_count(len: usize, max: usize, field: &str) -> Result<()> {
    if len > max {
        return Err(policy_error(format!(
            "{field} has {len} entries, maximum is {max}"
        )));
    }
    Ok(())
}

/// ASCII case-insensitive equality, without allocating.
///
/// Policy hosts are canonical lowercase; guest and DNS queries arrive in
/// whatever case the caller used, so lookups fold case instead of allocating a
/// normalized copy on every check.
pub(crate) fn eq_ignore_case(canonical: &str, query: &str) -> bool {
    let query = query.strip_suffix('.').unwrap_or(query);
    canonical.len() == query.len() && canonical.as_bytes().eq_ignore_ascii_case(query.as_bytes())
}

/// ASCII case-insensitive suffix test, without allocating.
pub(crate) fn ends_with_ignore_case(text: &str, suffix: &str) -> bool {
    text.len() >= suffix.len()
        && text.as_bytes()[text.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

/// Strips the non-canonical trailing dot of a query name without allocating.
pub(crate) fn strip_trailing_dot(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

/// Validates a bare, canonical ASCII DNS name.
///
/// `min_labels` of `2` additionally requires an alphabetic final label, which
/// rejects IP literals and numeric "TLDs" in host fields.
pub fn validate_dns_name(raw: &str, field: &str, min_labels: usize) -> Result<()> {
    if raw.is_empty() {
        return Err(policy_error(format!("{field} must not be empty")));
    }
    if raw.len() > MAX_HOST_BYTES {
        return Err(policy_error(format!(
            "{field} is longer than {MAX_HOST_BYTES} bytes"
        )));
    }
    if !raw.is_ascii() {
        return Err(policy_error(format!("{field} must be ASCII")));
    }
    if raw.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(policy_error(format!(
            "{field} must be lowercase ASCII canonical form"
        )));
    }
    if raw.contains('*') {
        return Err(policy_error(format!(
            "{field} must not contain wildcards: {}",
            bounded(raw)
        )));
    }
    if raw.contains(['/', '@', ':', ' ']) {
        return Err(policy_error(format!(
            "{field} must be a bare DNS name without scheme, port, path or credentials: {}",
            bounded(raw)
        )));
    }
    if raw.ends_with('.') {
        return Err(policy_error(format!(
            "{field} must not use the trailing-dot form: {}",
            bounded(raw)
        )));
    }
    let labels: Vec<&str> = raw.split('.').collect();
    if labels.len() < min_labels {
        return Err(policy_error(format!(
            "{field} must have at least {min_labels} label(s): {}",
            bounded(raw)
        )));
    }
    for label in &labels {
        if label.is_empty() || label.len() > MAX_LABEL_BYTES {
            return Err(policy_error(format!(
                "{field} has an empty or over-long label: {}",
                bounded(raw)
            )));
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return Err(policy_error(format!(
                "{field} label must start and end with an alphanumeric character: {}",
                bounded(raw)
            )));
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(policy_error(format!(
                "{field} label has unsupported characters: {}",
                bounded(raw)
            )));
        }
    }
    if min_labels >= 2 {
        let tld = labels[labels.len() - 1];
        if !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(policy_error(format!(
                "{field} must end in an alphabetic label, not an address or number: {}",
                bounded(raw)
            )));
        }
    }
    Ok(())
}

/// Validates a host that arrived from a guest, DNS wire or HTTP request.
///
/// Same structural rules as [`validate_dns_name`], but the non-canonical
/// spellings a query may legitimately carry (any ASCII case and a trailing
/// root dot) are folded first. Normalization allocates only for those inputs,
/// never for canonical configuration.
pub fn validate_query_host(raw: &str, field: &str, min_labels: usize) -> Result<()> {
    let stripped = raw.strip_suffix('.').unwrap_or(raw);
    let canonical_case = !raw.bytes().any(|b| b.is_ascii_uppercase());
    if stripped.len() == raw.len() && canonical_case {
        return validate_dns_name(raw, field, min_labels);
    }
    let mut canonical = String::with_capacity(stripped.len());
    canonical.extend(stripped.bytes().map(|b| b.to_ascii_lowercase() as char));
    validate_dns_name(&canonical, field, min_labels)
}

fn validate_port(port: u16, field: &str) -> Result<()> {
    if port == 0 {
        return Err(policy_error(format!("{field} must not be 0")));
    }
    Ok(())
}

fn validate_protocol(protocol: &str, field: &str) -> Result<()> {
    if protocol != EGRESS_PROTOCOL_TCP {
        return Err(policy_error(format!(
            "{field} {protocol} is not supported; phase 1 egress is {EGRESS_PROTOCOL_TCP} only"
        )));
    }
    Ok(())
}

fn validate_scheme(scheme: &str, field: &str) -> Result<()> {
    if scheme != MODEL_SCHEME_HTTPS && scheme != MODEL_SCHEME_HTTP {
        return Err(policy_error(format!(
            "{field} {scheme} is not supported; use {MODEL_SCHEME_HTTPS} or the operator test \
             scheme {MODEL_SCHEME_HTTP}"
        )));
    }
    Ok(())
}

fn validate_method(method: &str, field: &str) -> Result<()> {
    if method.is_empty() || method.len() > MAX_METHOD_BYTES {
        return Err(policy_error(format!(
            "{field} method must be 1..={MAX_METHOD_BYTES} bytes"
        )));
    }
    if !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(policy_error(format!(
            "{field} method must be an uppercase ASCII token: {}",
            bounded(method)
        )));
    }
    Ok(())
}

/// Validates a path prefix. Paths are matched by segment prefix, so wildcards,
/// traversal, query and fragment syntax are refused rather than reinterpreted.
fn validate_path(path: &str, field: &str) -> Result<()> {
    if path.is_empty() {
        return Err(policy_error(format!("{field} must not be empty")));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(policy_error(format!(
            "{field} is longer than {MAX_PATH_BYTES} bytes"
        )));
    }
    if !path.is_ascii() {
        return Err(policy_error(format!("{field} must be ASCII")));
    }
    if !path.starts_with('/') {
        return Err(policy_error(format!(
            "{field} must start with '/': {}",
            bounded(path)
        )));
    }
    if path.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(policy_error(format!(
            "{field} must not contain control characters or spaces"
        )));
    }
    if path.contains(['\\', '?', '#', '*', ';', '\'', '"', '<', '>', '|', '{', '}']) {
        return Err(policy_error(format!(
            "{field} contains characters Guard does not match on: {}",
            bounded(path)
        )));
    }
    if path.contains("..") || path.contains("//") {
        return Err(policy_error(format!(
            "{field} must not contain traversal or empty segments: {}",
            bounded(path)
        )));
    }
    Ok(())
}

/// Validates a credential binding name. A binding name is an identifier, never
/// a secret, so credential-shaped values are rejected here.
fn validate_binding_name(name: &str, field: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(policy_error(format!("{field} must be 1..=64 bytes")));
    }
    if !is_rule_name(name) {
        return Err(policy_error(format!(
            "{field} must match [A-Za-z0-9._-] and must not carry a secret value"
        )));
    }
    Ok(())
}

fn validate_list(field: &str, items: &[String], max: usize) -> Result<()> {
    check_count(items.len(), max, field)?;
    for item in items {
        if item.is_empty() {
            return Err(policy_error(format!(
                "{field} must not contain empty entries"
            )));
        }
    }
    let mut sorted: Vec<&String> = items.iter().collect();
    sorted.sort();
    for pair in sorted.windows(2) {
        if pair[0] == pair[1] {
            return Err(policy_error(format!(
                "{field} contains duplicate entry: {}",
                bounded(pair[0])
            )));
        }
    }
    Ok(())
}

/// How much of a request Guard can see.
///
/// `Sni` is the default and the only mode that needs no operator trust in a
/// certificate authority: Guard matches the name the client asked for and
/// forwards the tunnel. `Intercept` terminates TLS inside Guard, which is what
/// makes method and path policy possible - and which means Guard holds a key
/// that can read every byte of the traffic it governs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L7Mode {
    #[default]
    Sni,
    Intercept,
}

/// One visible HTTP rule: this host, these verbs, these paths.
///
/// An empty `paths` list means every path on that host, which is a decision an
/// operator makes explicitly rather than one a parser infers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRule {
    pub host: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

/// Method and tool rules for visible MCP JSON-RPC traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpRules {
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub denied_tools: Vec<String>,
}

impl Default for McpRules {
    fn default() -> Self {
        Self {
            allowed_methods: vec![
                "initialize".into(),
                "tools/list".into(),
                "tools/call".into(),
            ],
            allowed_tools: Vec::new(),
            denied_tools: Vec::new(),
        }
    }
}

/// Bounded GraphQL rules: operation kind, operation name, root fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlRules {
    #[serde(default)]
    pub allow_mutations: bool,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub root_fields: Vec<String>,
}

/// Layer 7 governance, applied only to traffic Guard can actually see.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7Policy {
    #[serde(default)]
    pub mode: L7Mode,
    #[serde(default)]
    pub http: Vec<HttpRule>,
    #[serde(default)]
    pub mcp: McpRules,
    #[serde(default)]
    pub graphql: GraphqlRules,
    /// Explicit operator acknowledgement that Guard terminates TLS here.
    #[serde(default)]
    pub intercept_ack: bool,
}

/// What the watcher does when it cannot answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherFailureMode {
    #[default]
    ContinueWithRules,
    PauseIfUnavailable,
}

/// The optional second reviewer. Disabled by default; the product is complete
/// without it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub failure_mode: WatcherFailureMode,
    /// One window in `sample_rate` is reviewed.
    #[serde(default = "default_watcher_sample_rate")]
    pub sample_rate: u32,
    #[serde(default = "default_watcher_batch")]
    pub batch_size: u32,
    #[serde(default = "default_watcher_token_budget")]
    pub token_budget: u64,
    #[serde(default)]
    pub cost_budget_micros: u64,
}

fn default_watcher_sample_rate() -> u32 {
    10
}
fn default_watcher_batch() -> u32 {
    20
}
fn default_watcher_token_budget() -> u64 {
    200_000
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            failure_mode: WatcherFailureMode::default(),
            sample_rate: default_watcher_sample_rate(),
            batch_size: default_watcher_batch(),
            token_budget: default_watcher_token_budget(),
            cost_budget_micros: 0,
        }
    }
}

/// A synthetic secret the guest must never touch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanarySpec {
    /// Path inside the guest, absolute.
    pub path: String,
    /// The synthetic value a read would expose.
    pub value: String,
}

/// Optional in-guest tripwires. Every value is synthetic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryConfig {
    #[serde(default)]
    pub files: Vec<CanarySpec>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Placeholder credential names the guest must never present to the gateway.
    #[serde(default)]
    pub credentials: Vec<String>,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Topology {
    /// Topology B: trusted agent outside the sandbox, guest executes tools.
    #[default]
    Outside,
    /// Topology A: agent loop and model credential inside the sandbox.
    Inside,
}

/// The four shipped policy templates.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum PolicyTemplate {
    /// No egress at all. This is the default when nothing is selected.
    #[default]
    NoNetwork,
    /// Only the configured model endpoint, through the Guard broker.
    ModelOnly,
    /// The model endpoint plus an explicit operator allowlist.
    ModelPlusAllowlist,
    /// Explicit allowlist restricted to read-only HTTP methods.
    ReadOnlyApi,
}

impl PolicyTemplate {
    /// Whether this template requires a model endpoint.
    pub const fn requires_model(self) -> bool {
        matches!(self, Self::ModelOnly | Self::ModelPlusAllowlist)
    }
}

/// DNS enforcement scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPolicy {
    /// Exact names the guest may resolve. A leading-dot entry such as
    /// `.example.com` is an explicit suffix zone; nothing else is inherited by
    /// descendants.
    #[serde(default)]
    pub allowed_zones: Vec<String>,
    /// Allowed record types. Only `A` and `AAAA` are schema-accepted.
    #[serde(default = "default_record_types")]
    pub allowed_record_types: Vec<String>,
}

fn default_record_types() -> Vec<String> {
    ALLOWED_RECORD_TYPES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

impl Default for DnsPolicy {
    fn default() -> Self {
        Self {
            allowed_zones: Vec::new(),
            allowed_record_types: default_record_types(),
        }
    }
}

impl DnsPolicy {
    /// Whether a query name is inside the configured DNS scope.
    ///
    /// A plain entry matches that name exactly. An entry with a leading dot is
    /// an explicit suffix zone that matches its descendants only.
    pub fn allows_name(&self, name: &str) -> bool {
        let name = strip_trailing_dot(name);
        self.allowed_zones
            .iter()
            .any(|zone| zone_matches(zone, name))
    }

    fn validate(&self) -> Result<()> {
        check_count(
            self.allowed_zones.len(),
            MAX_DNS_ZONES,
            "network.dns.allowed_zones",
        )?;
        check_count(
            self.allowed_record_types.len(),
            MAX_RECORD_TYPES,
            "network.dns.allowed_record_types",
        )?;
        for zone in &self.allowed_zones {
            if let Some(suffix) = zone.strip_prefix('.') {
                validate_dns_name(suffix, "network.dns.allowed_zones suffix", 1)?;
            } else {
                validate_dns_name(zone, "network.dns.allowed_zones", 2)?;
            }
        }
        for record_type in &self.allowed_record_types {
            if !ALLOWED_RECORD_TYPES.contains(&record_type.as_str()) {
                return Err(policy_error(format!(
                    "network.dns.allowed_record_types does not accept {record_type}; Guard schema \
                     supports {} only (ANY/NS/TXT/NULL are refused)",
                    ALLOWED_RECORD_TYPES.join(", ")
                )));
            }
        }
        validate_list(
            "network.dns.allowed_zones",
            &self.allowed_zones,
            MAX_DNS_ZONES,
        )?;
        validate_list(
            "network.dns.allowed_record_types",
            &self.allowed_record_types,
            MAX_RECORD_TYPES,
        )?;
        Ok(())
    }
}

/// One destination the gateway may proxy for a sandbox.
///
/// An empty `allowed_methods`/`allowed_paths` list means an opaque
/// destination-only permission: the guest may reach that host and port through
/// Guard, and Guard cannot see inside it. It is never an unconstrained
/// credentialed model path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    /// Canonical DNS name.
    pub host: String,
    /// Destination TCP port.
    pub port: u16,
    /// Transport protocol, `tcp` only in phase 1.
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Allowed HTTP methods; empty means opaque destination-only permission.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Allowed path prefixes; empty means opaque destination-only permission.
    #[serde(default)]
    pub allowed_paths: Vec<String>,
}

fn default_protocol() -> String {
    EGRESS_PROTOCOL_TCP.to_string()
}

impl EgressRule {
    /// Builds the destination rule implied by a model endpoint.
    pub fn from_model(endpoint: &ModelEndpoint) -> Self {
        Self {
            host: endpoint.host.clone(),
            port: endpoint.port,
            protocol: default_protocol(),
            allowed_methods: endpoint.allowed_methods.clone(),
            allowed_paths: endpoint.allowed_paths.clone(),
        }
    }

    fn validate(&self, field: &str) -> Result<()> {
        validate_dns_name(&self.host, &format!("{field}.host"), 2)?;
        validate_port(self.port, &format!("{field}.port"))?;
        validate_protocol(&self.protocol, &format!("{field}.protocol"))?;
        validate_list(
            &format!("{field}.allowed_methods"),
            &self.allowed_methods,
            MAX_LIST_ITEMS,
        )?;
        validate_list(
            &format!("{field}.allowed_paths"),
            &self.allowed_paths,
            MAX_LIST_ITEMS,
        )?;
        for method in &self.allowed_methods {
            validate_method(method, &format!("{field}.allowed_methods"))?;
        }
        for path in &self.allowed_paths {
            validate_path(path, &format!("{field}.allowed_paths"))?;
        }
        Ok(())
    }
}

/// The first-class model endpoint of topology A.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEndpoint {
    /// Canonical DNS name of the provider.
    pub host: String,
    /// Provider TCP port.
    pub port: u16,
    /// `https`, or `http` only behind an explicit operator test mapping.
    #[serde(default = "default_scheme")]
    pub scheme: String,
    /// Allowed HTTP methods, non-empty for a credentialed model path.
    #[serde(default = "default_model_methods")]
    pub allowed_methods: Vec<String>,
    /// Allowed path prefixes matched by segment prefix, non-empty.
    #[serde(default = "default_model_paths")]
    pub allowed_paths: Vec<String>,
    /// Name of the credential binding Guard substitutes, never a secret value.
    #[serde(default = "default_credential_binding")]
    pub credential: String,
}

fn default_scheme() -> String {
    MODEL_SCHEME_HTTPS.to_string()
}

fn default_model_methods() -> Vec<String> {
    vec!["POST".to_string()]
}

fn default_model_paths() -> Vec<String> {
    vec!["/v1/".to_string()]
}

fn default_credential_binding() -> String {
    DEFAULT_CREDENTIAL_BINDING.to_string()
}

impl Default for ModelEndpoint {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 443,
            scheme: default_scheme(),
            allowed_methods: default_model_methods(),
            allowed_paths: default_model_paths(),
            credential: default_credential_binding(),
        }
    }
}

impl ModelEndpoint {
    fn validate(&self) -> Result<()> {
        validate_dns_name(&self.host, "model.host", 2)?;
        validate_port(self.port, "model.port")?;
        validate_scheme(&self.scheme, "model.scheme")?;
        if self.allowed_methods.is_empty() {
            return Err(policy_error(
                "model.allowed_methods must not be empty; a credentialed model path without a \
                 method restriction is refused",
            ));
        }
        if self.allowed_paths.is_empty() {
            return Err(policy_error(
                "model.allowed_paths must not be empty; a credentialed model path without a path \
                 restriction is refused",
            ));
        }
        validate_list(
            "model.allowed_methods",
            &self.allowed_methods,
            MAX_LIST_ITEMS,
        )?;
        validate_list("model.allowed_paths", &self.allowed_paths, MAX_LIST_ITEMS)?;
        for method in &self.allowed_methods {
            validate_method(method, "model.allowed_methods")?;
        }
        for path in &self.allowed_paths {
            validate_path(path, "model.allowed_paths")?;
        }
        validate_binding_name(&self.credential, "model.credential")?;
        Ok(())
    }
}

/// Binds a credential to one destination. Guard substitutes the real secret only
/// for the bound host, port and header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    /// Binding name used by the guest placeholder `placeholder://<name>`.
    pub name: String,
    /// Destination host the secret may be sent to.
    pub host: String,
    /// Destination port the secret may be sent to.
    pub port: u16,
    /// Header carrying the secret.
    #[serde(default = "default_credential_header")]
    pub header: String,
}

fn default_credential_header() -> String {
    DEFAULT_CREDENTIAL_HEADER.to_string()
}

impl CredentialBinding {
    fn validate(&self, field: &str) -> Result<()> {
        validate_binding_name(&self.name, &format!("{field}.name"))?;
        validate_dns_name(&self.host, &format!("{field}.host"), 2)?;
        validate_port(self.port, &format!("{field}.port"))?;
        let header = self.header.to_ascii_lowercase();
        if !ALLOWED_CREDENTIAL_HEADERS.contains(&header.as_str()) {
            return Err(policy_error(format!(
                "{field}.header {} is not allowed; use one of {}",
                bounded(&self.header),
                ALLOWED_CREDENTIAL_HEADERS.join(", ")
            )));
        }
        Ok(())
    }
}

/// Rate, byte and concurrency ceilings enforced on the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Model/API requests per minute.
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    /// DNS queries per minute.
    #[serde(default = "default_dns_queries_per_minute")]
    pub dns_queries_per_minute: u32,
    /// Total bytes the guest may send.
    #[serde(default = "default_bytes_out")]
    pub bytes_out: u64,
    /// Total bytes the guest may receive.
    #[serde(default = "default_bytes_in")]
    pub bytes_in: u64,
    /// Largest single request body.
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: u64,
    /// Largest single response body.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,
    /// Largest number of in-flight requests.
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: u32,
}

const fn default_requests_per_minute() -> u32 {
    60
}

const fn default_dns_queries_per_minute() -> u32 {
    120
}

const fn default_bytes_out() -> u64 {
    64 << 20
}

const fn default_bytes_in() -> u64 {
    256 << 20
}

const fn default_max_request_bytes() -> u64 {
    1 << 20
}

const fn default_max_response_bytes() -> u64 {
    64 << 20
}

const fn default_max_concurrent_requests() -> u32 {
    4
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            requests_per_minute: default_requests_per_minute(),
            dns_queries_per_minute: default_dns_queries_per_minute(),
            bytes_out: default_bytes_out(),
            bytes_in: default_bytes_in(),
            max_request_bytes: default_max_request_bytes(),
            max_response_bytes: default_max_response_bytes(),
            max_concurrent_requests: default_max_concurrent_requests(),
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<()> {
        let checks: [(u64, u64, &str); 7] = [
            (
                u64::from(self.requests_per_minute),
                u64::from(LIMIT_MAX_REQUESTS_PER_MINUTE),
                "limits.requests_per_minute",
            ),
            (
                u64::from(self.dns_queries_per_minute),
                u64::from(LIMIT_MAX_DNS_QUERIES_PER_MINUTE),
                "limits.dns_queries_per_minute",
            ),
            (self.bytes_out, LIMIT_MAX_BYTES, "limits.bytes_out"),
            (self.bytes_in, LIMIT_MAX_BYTES, "limits.bytes_in"),
            (
                self.max_request_bytes,
                LIMIT_MAX_REQUEST_BYTES,
                "limits.max_request_bytes",
            ),
            (
                self.max_response_bytes,
                LIMIT_MAX_RESPONSE_BYTES,
                "limits.max_response_bytes",
            ),
            (
                u64::from(self.max_concurrent_requests),
                u64::from(LIMIT_MAX_CONCURRENT_REQUESTS),
                "limits.max_concurrent_requests",
            ),
        ];
        for (value, max, field) in checks {
            if value == 0 {
                return Err(policy_error(format!("{field} must be greater than zero")));
            }
            if value > max {
                return Err(policy_error(format!(
                    "{field} is above the enforced maximum of {max}"
                )));
            }
        }
        if self.max_request_bytes > self.bytes_out {
            return Err(policy_error(
                "limits.max_request_bytes must not exceed limits.bytes_out",
            ));
        }
        if self.max_response_bytes > self.bytes_in {
            return Err(policy_error(
                "limits.max_response_bytes must not exceed limits.bytes_in",
            ));
        }
        Ok(())
    }
}

/// Network half of a policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// DNS enforcement scope.
    #[serde(default)]
    pub dns: DnsPolicy,
    /// Destinations the gateway may proxy.
    #[serde(default)]
    pub egress: Vec<EgressRule>,
}

/// A complete, versioned Guard policy: the single source every enforcement
/// artifact is compiled from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardPolicy {
    /// Policy schema version.
    #[serde(default = "default_version")]
    pub version: u32,
    /// DNS scope and destination permissions.
    #[serde(default)]
    pub network: NetworkPolicy,
    /// First-class model endpoint, topology A only.
    #[serde(default)]
    pub model: Option<ModelEndpoint>,
    /// Credential bindings Guard may substitute.
    #[serde(default)]
    pub credentials: Vec<CredentialBinding>,
    /// Rate, byte and concurrency ceilings.
    #[serde(default)]
    pub limits: Limits,
}

fn default_version() -> u32 {
    POLICY_VERSION
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION,
            network: NetworkPolicy::default(),
            model: None,
            credentials: Vec::new(),
            limits: Limits::default(),
        }
    }
}

impl GuardPolicy {
    /// Parses a strict YAML policy document and validates it.
    ///
    /// The document must be at most [`MAX_POLICY_BYTES`]; unknown and duplicate
    /// keys are rejected by the deserializer, never merged or ignored.
    pub fn from_yaml(text: &str) -> Result<Self> {
        if text.len() > MAX_POLICY_BYTES {
            return Err(policy_error(format!(
                "policy document is {} bytes, maximum is {MAX_POLICY_BYTES}",
                text.len()
            )));
        }
        if text.trim().is_empty() {
            return Err(policy_error("policy document is empty"));
        }
        let policy: Self = serde_yaml_ng::from_str(text).map_err(|err| {
            policy_error(format!("policy YAML is not a valid Guard policy: {err}"))
        })?;
        policy.validate()?;
        Ok(policy)
    }

    /// Builds one of the four shipped templates.
    ///
    /// * [`PolicyTemplate::NoNetwork`] permits nothing and refuses extra input.
    /// * [`PolicyTemplate::ModelOnly`] permits exactly the model endpoint.
    /// * [`PolicyTemplate::ModelPlusAllowlist`] adds operator allowlist rules.
    /// * [`PolicyTemplate::ReadOnlyApi`] permits only read-only allowlist rules.
    pub fn template(
        template: PolicyTemplate,
        model_endpoint: Option<ModelEndpoint>,
        allowlist: Vec<EgressRule>,
    ) -> Result<Self> {
        let mut egress: Vec<EgressRule> = Vec::new();
        let mut zones: Vec<String> = Vec::new();
        let mut credentials: Vec<CredentialBinding> = Vec::new();

        match template {
            PolicyTemplate::NoNetwork => {
                if model_endpoint.is_some() || !allowlist.is_empty() {
                    return Err(policy_error(
                        "no-network template accepts neither a model endpoint nor an allowlist; \
                         select model-only or model-plus-allowlist",
                    ));
                }
            }
            PolicyTemplate::ModelOnly => {
                let model = require_model(model_endpoint.clone())?;
                check_count(allowlist.len(), MAX_EGRESS_RULES, "allowlist")?;
                zones.push(model.host.clone());
                egress.push(EgressRule::from_model(&model));
                credentials.push(CredentialBinding {
                    name: model.credential.clone(),
                    host: model.host.clone(),
                    port: model.port,
                    header: DEFAULT_CREDENTIAL_HEADER.to_string(),
                });
            }
            PolicyTemplate::ModelPlusAllowlist => {
                let model = require_model(model_endpoint.clone())?;
                if allowlist.is_empty() {
                    return Err(policy_error(
                        "model-plus-allowlist template requires at least one allowlist rule",
                    ));
                }
                check_count(allowlist.len() + 1, MAX_EGRESS_RULES, "network.egress")?;
                zones.push(model.host.clone());
                egress.push(EgressRule::from_model(&model));
                credentials.push(CredentialBinding {
                    name: model.credential.clone(),
                    host: model.host.clone(),
                    port: model.port,
                    header: DEFAULT_CREDENTIAL_HEADER.to_string(),
                });
                for rule in allowlist {
                    zones.push(rule.host.clone());
                    egress.push(rule);
                }
            }
            PolicyTemplate::ReadOnlyApi => {
                if model_endpoint.is_some() {
                    return Err(policy_error(
                        "read-only-api template does not accept a model endpoint; use \
                         model-plus-allowlist for a credentialed model path",
                    ));
                }
                if allowlist.is_empty() {
                    return Err(policy_error(
                        "read-only-api template requires at least one allowlist rule",
                    ));
                }
                check_count(allowlist.len(), MAX_EGRESS_RULES, "allowlist")?;
                for rule in allowlist {
                    if rule.allowed_methods.is_empty() {
                        return Err(policy_error(format!(
                            "read-only-api requires explicit methods for {}:{}; add {}",
                            rule.host,
                            rule.port,
                            READ_ONLY_METHODS.join(", ")
                        )));
                    }
                    for method in &rule.allowed_methods {
                        if !READ_ONLY_METHODS.contains(&method.as_str()) {
                            return Err(policy_error(format!(
                                "read-only-api refuses method {} for {}:{}; allowed: {}",
                                method,
                                rule.host,
                                rule.port,
                                READ_ONLY_METHODS.join(", ")
                            )));
                        }
                    }
                    zones.push(rule.host.clone());
                    egress.push(rule);
                }
            }
        }

        let policy = Self {
            version: POLICY_VERSION,
            network: NetworkPolicy {
                dns: DnsPolicy {
                    allowed_zones: zones,
                    allowed_record_types: default_record_types(),
                },
                egress,
            },
            model: model_endpoint,
            credentials,
            limits: Limits::default(),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Deterministic canonical JSON: every list that is semantically a set is
    /// sorted, so equivalent documents hash identically regardless of the order
    /// the operator wrote them in.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.normalized()).map_err(GuardError::from)
    }

    /// Lowercase hex SHA-256 of [`GuardPolicy::canonical_json`].
    pub fn hash(&self) -> Result<String> {
        let canonical = self.canonical_json()?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        Ok(hex::encode(hasher.finalize()))
    }

    /// The semantically equivalent policy with every set-like list sorted.
    pub fn normalized(&self) -> Self {
        let mut network = self.network.clone();
        network.dns.allowed_zones.sort();
        network.dns.allowed_record_types.sort();
        network
            .egress
            .sort_by_cached_key(|rule| (rule.host.clone(), rule.port, rule.protocol.clone()));
        for rule in &mut network.egress {
            rule.allowed_methods.sort();
            rule.allowed_paths.sort();
        }
        let mut credentials = self.credentials.clone();
        credentials.sort_by(|a, b| a.name.cmp(&b.name));
        let mut normalized = self.clone();
        normalized.network = network;
        normalized.credentials = credentials;
        normalized
    }

    /// Full structural and cross-field validation.
    ///
    /// This is deliberately exhaustive over the finite rule model: every host,
    /// port, protocol, path, method, binding and zone is checked, duplicates are
    /// refused, and unreachable or ambiguous rule sets are rejected instead of
    /// being silently dropped at enforcement time.
    pub fn validate(&self) -> Result<()> {
        if self.version != POLICY_VERSION {
            return Err(policy_error(format!(
                "unsupported policy version {}; this Guard supports version {POLICY_VERSION}",
                self.version
            )));
        }
        self.network.dns.validate()?;
        check_count(
            self.network.egress.len(),
            MAX_EGRESS_RULES,
            "network.egress",
        )?;
        for (index, rule) in self.network.egress.iter().enumerate() {
            rule.validate(&format!("network.egress[{index}]"))?;
        }
        let mut destinations: Vec<String> = self
            .network
            .egress
            .iter()
            .map(|rule| format!("{}:{}", rule.host, rule.port))
            .collect();
        destinations.sort();
        for pair in destinations.windows(2) {
            if pair[0] == pair[1] {
                return Err(policy_error(format!(
                    "network.egress has duplicate destination {}",
                    bounded(&pair[0])
                )));
            }
        }

        check_count(
            self.credentials.len(),
            MAX_CREDENTIAL_BINDINGS,
            "credentials",
        )?;
        for (index, binding) in self.credentials.iter().enumerate() {
            binding.validate(&format!("credentials[{index}]"))?;
        }
        let mut names: Vec<&str> = self.credentials.iter().map(|b| b.name.as_str()).collect();
        names.sort_unstable();
        for pair in names.windows(2) {
            if pair[0] == pair[1] {
                return Err(policy_error(format!(
                    "credentials has duplicate binding {}",
                    pair[0]
                )));
            }
        }

        self.validate_model_binding()?;
        self.validate_dns_egress_consistency()?;
        self.limits.validate()?;
        Ok(())
    }

    /// The credential binding declared under `name`, if any.
    pub fn credential_binding(&self, name: &str) -> Option<&CredentialBinding> {
        self.credentials.iter().find(|binding| binding.name == name)
    }

    /// The egress rule permitting exactly `host:port`, if any.
    pub fn egress_rule(&self, host: &str, port: u16) -> Option<&EgressRule> {
        self.network
            .egress
            .iter()
            .find(|rule| rule.host == host && rule.port == port)
    }

    fn validate_model_binding(&self) -> Result<()> {
        let Some(model) = &self.model else {
            if !self.credentials.is_empty() {
                // A binding without a model endpoint would authorize a credential
                // against an opaque tunnel, which Guard never does.
                for binding in &self.credentials {
                    if !self
                        .network
                        .egress
                        .iter()
                        .any(|rule| rule.host == binding.host && rule.port == binding.port)
                    {
                        return Err(policy_error(format!(
                            "credentials[{}] binds {}:{} but no egress rule and no model endpoint \
                             covers that destination",
                            binding.name, binding.host, binding.port
                        )));
                    }
                }
            }
            return Ok(());
        };
        model.validate()?;
        let binding = self
            .credentials
            .iter()
            .find(|binding| binding.name == model.credential)
            .ok_or_else(|| {
                policy_error(
                    "model.credential does not name a declared credential binding; Guard refuses \
                     an unbound model credential",
                )
            })?;
        if binding.host != model.host || binding.port != model.port {
            return Err(policy_error(format!(
                "model endpoint {}:{} and credential binding {}:{} disagree; Guard substitutes a \
                 secret only for the exact bound destination",
                model.host, model.port, binding.host, binding.port
            )));
        }
        if !self
            .network
            .egress
            .iter()
            .any(|rule| rule.host == model.host && rule.port == model.port)
        {
            return Err(policy_error(format!(
                "model endpoint {}:{} has no matching network.egress rule",
                model.host, model.port
            )));
        }
        Ok(())
    }

    fn validate_dns_egress_consistency(&self) -> Result<()> {
        for rule in &self.network.egress {
            let covered = self
                .network
                .dns
                .allowed_zones
                .iter()
                .any(|zone| zone_matches(zone, &rule.host));
            if !covered {
                return Err(policy_error(format!(
                    "egress destination {}:{} is not inside any allowed DNS zone; it would never \
                     resolve for the guest",
                    rule.host, rule.port
                )));
            }
        }
        for zone in &self.network.dns.allowed_zones {
            let used = self
                .network
                .egress
                .iter()
                .any(|rule| zone_matches(zone, &rule.host));
            if !used {
                return Err(policy_error(format!(
                    "allowed DNS zone {zone} matches no egress destination and would only widen \
                     resolution without any permitted route"
                )));
            }
        }
        Ok(())
    }
}

fn require_model(model: Option<ModelEndpoint>) -> Result<ModelEndpoint> {
    model.ok_or_else(|| {
        policy_error(
            "this template requires a model endpoint; a sandbox without one has no model path",
        )
    })
}

/// Whether a configured zone entry covers a host, without allocating.
///
/// `zone` is canonical policy configuration; `host` may arrive in any case.
pub fn zone_matches(zone: &str, host: &str) -> bool {
    match zone.strip_prefix('.') {
        Some(suffix) => {
            host.len() > suffix.len()
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                && ends_with_ignore_case(host, suffix)
        }
        None => eq_ignore_case(zone, host),
    }
}

/// Operator-facing Guard selection for a sandbox.
///
/// Exactly one source of permissions may be present: an explicit
/// [`GuardPolicy`] or a template plus its inputs. Anything else is ambiguous
/// and refused, and no combination ever widens to open internet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    /// Whether the agent loop runs inside or outside the sandbox.
    #[serde(default)]
    pub topology: Topology,
    /// Template selected when no explicit policy is given.
    #[serde(default)]
    pub policy_template: PolicyTemplate,
    /// Explicit policy; mutually exclusive with the template inputs below.
    #[serde(default)]
    pub policy: Option<GuardPolicy>,
    /// Model endpoint for the selected template.
    #[serde(default)]
    pub model_endpoint: Option<ModelEndpoint>,
    /// Allowlist rules for the selected template.
    #[serde(default)]
    pub allowlist: Vec<EgressRule>,
    /// Outside-guest watchdog deadline; cannot disable the dead-man switch.
    #[serde(default = "default_watchdog_timeout_ms")]
    pub watchdog_timeout_ms: u64,
    /// Immutable durable model-admission ceiling for this sandbox.
    #[serde(default = "default_max_model_requests")]
    pub max_model_requests: u64,
    /// Layer 7 governance. Without an explicit L7 policy a policy is hashed
    /// exactly as it was before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l7: Option<L7Policy>,
    /// The optional watcher. Disabled unless an operator turns it on.
    #[serde(default)]
    pub watcher: WatcherConfig,
    /// Optional synthetic canaries.
    #[serde(default)]
    pub canaries: CanaryConfig,
    /// Refuse to boot an image whose manifest or digests are not trusted.
    #[serde(default)]
    pub require_signed_image: bool,
}

fn default_watchdog_timeout_ms() -> u64 {
    10_000
}

fn default_max_model_requests() -> u64 {
    10_000
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            topology: Topology::default(),
            policy_template: PolicyTemplate::default(),
            policy: None,
            model_endpoint: None,
            allowlist: Vec::new(),
            watchdog_timeout_ms: default_watchdog_timeout_ms(),
            max_model_requests: default_max_model_requests(),
            l7: None,
            watcher: WatcherConfig::default(),
            canaries: CanaryConfig::default(),
            require_signed_image: false,
        }
    }
}

impl GuardConfig {
    /// Parses a strict YAML [`GuardConfig`] document and returns the effective
    /// policy, applying the same bounds and strictness as policy parsing.
    pub fn from_yaml(text: &str) -> Result<Self> {
        if text.len() > MAX_POLICY_BYTES {
            return Err(policy_error(format!(
                "guard config document is {} bytes, maximum is {MAX_POLICY_BYTES}",
                text.len()
            )));
        }
        if text.trim().is_empty() {
            return Err(policy_error("guard config document is empty"));
        }
        let config: Self = serde_yaml_ng::from_str(text)
            .map_err(|err| policy_error(format!("guard config YAML is not valid: {err}")))?;
        config.effective_policy()?;
        Ok(config)
    }

    /// The validated policy this selection compiles to.
    pub fn effective_policy(&self) -> Result<GuardPolicy> {
        if !(1_000..=60_000).contains(&self.watchdog_timeout_ms) {
            return Err(policy_error(
                "watchdog_timeout_ms must be between 1000 and 60000",
            ));
        }
        if self.max_model_requests == 0 || self.max_model_requests > i64::MAX as u64 {
            return Err(policy_error(
                "max_model_requests must be between 1 and 9223372036854775807",
            ));
        }
        let template_inputs_present = self.policy_template != PolicyTemplate::NoNetwork
            || self.model_endpoint.is_some()
            || !self.allowlist.is_empty();
        if let Some(policy) = &self.policy {
            if template_inputs_present {
                return Err(policy_error(
                    "guard config selects both an explicit policy and a template; exactly one \
                     source of permissions is allowed",
                ));
            }
            policy.validate()?;
            return Ok(policy.normalized());
        }
        GuardPolicy::template(
            self.policy_template,
            self.model_endpoint.clone(),
            self.allowlist.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODEL_ONLY_YAML: &str = r#"
version: 1
network:
  dns:
    allowed_zones:
      - api.example-model.com
    allowed_record_types:
      - A
      - AAAA
  egress:
    - host: api.example-model.com
      port: 443
      protocol: tcp
      allowed_methods:
        - POST
      allowed_paths:
        - /v1/
model:
  host: api.example-model.com
  port: 443
  allowed_methods:
    - POST
  allowed_paths:
    - /v1/
  credential: model-main
credentials:
  - name: model-main
    host: api.example-model.com
    port: 443
    header: authorization
limits:
  requests_per_minute: 120
"#;

    fn reject(text: &str) -> String {
        GuardPolicy::from_yaml(text)
            .expect_err("policy must be rejected")
            .to_string()
    }

    fn model_endpoint(host: &str) -> ModelEndpoint {
        ModelEndpoint {
            host: host.to_string(),
            ..ModelEndpoint::default()
        }
    }

    #[test]
    fn minimal_document_gets_bounded_documented_defaults() {
        let policy = GuardPolicy::from_yaml("version: 1\n").expect("minimal policy");
        assert_eq!(policy.version, POLICY_VERSION);
        assert!(policy.model.is_none());
        assert!(policy.credentials.is_empty());
        assert!(policy.network.egress.is_empty());
        assert!(policy.network.dns.allowed_zones.is_empty());
        assert_eq!(policy.network.dns.allowed_record_types, vec!["A", "AAAA"]);
        assert_eq!(policy.limits, Limits::default());
        assert_eq!(policy.limits.requests_per_minute, 60);
        assert_eq!(policy.limits.dns_queries_per_minute, 120);
        assert_eq!(policy.limits.max_request_bytes, 1 << 20);
        assert_eq!(policy.limits.max_concurrent_requests, 4);
    }

    #[test]
    fn model_only_document_parses_with_explicit_bindings() {
        let policy = GuardPolicy::from_yaml(MODEL_ONLY_YAML).expect("model-only policy");
        assert_eq!(policy.network.egress.len(), 1);
        let model = policy.model.as_ref().expect("model endpoint");
        assert_eq!(model.scheme, MODEL_SCHEME_HTTPS);
        assert_eq!(model.credential, DEFAULT_CREDENTIAL_BINDING);
        let binding = policy
            .credential_binding(model.credential.as_str())
            .expect("binding");
        assert_eq!(binding.port, 443);
        assert_eq!(binding.header, DEFAULT_CREDENTIAL_HEADER);
        assert_eq!(policy.limits.requests_per_minute, 120);
    }

    #[test]
    fn parser_rejects_unknown_and_duplicate_fields() {
        let unknown = reject("version: 1\nextra_field: 2\n");
        assert!(unknown.contains("extra_field"), "{unknown}");
        let nested = reject("network:\n  dns:\n    allowed_zone: []\n");
        assert!(nested.contains("allowed_zone"), "{nested}");
        let duplicate = reject("version: 1\nnetwork:\n  dns: {}\nnetwork: {}\n");
        assert!(duplicate.contains("network"), "{duplicate}");
        let unknown_model = reject("version: 1\nmodel:\n  endpint: a.example.com\n");
        assert!(unknown_model.contains("endpint"), "{unknown_model}");
    }

    #[test]
    fn parser_enforces_document_bound() {
        let oversized = format!("version: 1\n# {}\n", "x".repeat(MAX_POLICY_BYTES));
        let message = GuardPolicy::from_yaml(&oversized)
            .expect_err("oversized")
            .to_string();
        assert!(message.contains("maximum is 65536"), "{message}");
        assert!(reject("   \n\n").contains("empty"));
    }

    #[test]
    fn parser_rejects_unbounded_lists() {
        let mut doc = String::from("version: 1\nnetwork:\n  dns:\n    allowed_zones:\n");
        for index in 0..=MAX_DNS_ZONES {
            doc.push_str(&format!("      - host{index}.example.com\n"));
        }
        let message = reject(&doc);
        assert!(message.contains("allowed_zones"), "{message}");
    }

    #[test]
    fn parser_rejects_non_canonical_hosts() {
        for host in [
            "API.example.com",
            "*.example.com",
            "api.example.com.",
            "http://api.example.com",
            "user:pass@api.example.com",
            "api.example.com/path",
            "api.example.com:443",
            "10.0.0.1",
            "-api.example.com",
            "api..example.com",
            "localhost",
        ] {
            let doc =
                format!("version: 1\nnetwork:\n  dns:\n    allowed_zones:\n      - \"{host}\"\n");
            let message = reject(&doc);
            assert!(message.contains("allowed_zones"), "{host}: {message}");
        }
    }

    #[test]
    fn parser_rejects_malformed_ports_protocols_methods_and_paths() {
        let zero_port =
            "version: 1\nnetwork:\n  egress:\n    - host: a.example.com\n      port: 0\n";
        assert!(reject(zero_port).contains("port"));
        let udp = "version: 1\nnetwork:\n  egress:\n    - host: a.example.com\n      port: 53\n      protocol: udp\n";
        assert!(reject(udp).contains("not supported"));
        let lower_method = "version: 1\nnetwork:\n  egress:\n    - host: a.example.com\n      port: 443\n      allowed_methods:\n        - post\n";
        assert!(reject(lower_method).contains("uppercase"));
        let bogus_method = "version: 1\nnetwork:\n  egress:\n    - host: a.example.com\n      port: 443\n      allowed_methods:\n        - \"PO ST\"\n";
        assert!(reject(bogus_method).contains("allowed_methods"));
        for path in [
            "v1/",
            "/v1/../admin",
            "/v1/*",
            "/v1/ x",
            "/v1/a?b=1",
            "/v1/a#f",
            "",
        ] {
            let doc = format!(
                "version: 1\nnetwork:\n  egress:\n    - host: a.example.com\n      port: 443\n      allowed_paths:\n        - \"{path}\"\n"
            );
            let message = reject(&doc);
            assert!(message.contains("allowed_paths"), "{path}: {message}");
        }
        let bad_scheme = "version: 1\nmodel:\n  host: a.example.com\n  port: 443\n  scheme: ftp\n";
        assert!(reject(bad_scheme).contains("scheme"));
        let bad_header = "version: 1\nnetwork:\n  egress:\n    - host: a.example.com\n      port: 443\ncredentials:\n  - name: x\n    host: a.example.com\n    port: 443\n    header: cookie\n";
        assert!(reject(bad_header).contains("header"));
    }

    #[test]
    fn dns_scope_refuses_unsupported_record_types() {
        for record_type in ["ANY", "NS", "TXT", "NULL", "a"] {
            let doc = format!(
                "version: 1\nnetwork:\n  dns:\n    allowed_record_types:\n      - {record_type}\n"
            );
            let message = reject(&doc);
            assert!(
                message.contains("allowed_record_types"),
                "{record_type}: {message}"
            );
        }
        let duplicate =
            "version: 1\nnetwork:\n  dns:\n    allowed_record_types:\n      - A\n      - A\n";
        assert!(reject(duplicate).contains("duplicate"));
    }

    #[test]
    fn limits_must_be_positive_and_within_enforced_bounds() {
        assert!(reject("version: 1\nlimits:\n  requests_per_minute: 0\n").contains("greater than"));
        assert!(reject("version: 1\nlimits:\n  bytes_in: 0\n").contains("greater than"));
        let too_many = format!("version: 1\nlimits:\n  requests_per_minute: {}\n", u32::MAX);
        assert!(reject(&too_many).contains("maximum"));
        assert!(
            reject("version: 1\nlimits:\n  max_request_bytes: 68719476736\n").contains("maximum")
        );
        assert!(
            reject("version: 1\nlimits:\n  max_response_bytes: 1073741824\n").contains("maximum")
        );
        assert!(reject("version: 1\nlimits:\n  bytes_out: 2199023255553\n").contains("maximum"));
        // Exactly at the enforced ceiling is still accepted.
        GuardPolicy::from_yaml("version: 1\nlimits:\n  bytes_out: 1099511627776\n")
            .expect("ceiling value is accepted");
        assert!(
            reject("version: 1\nlimits:\n  max_concurrent_requests: 1025\n").contains("maximum")
        );
    }

    #[test]
    fn hash_is_deterministic_across_semantic_ordering() {
        let first = GuardPolicy::from_yaml(MODEL_ONLY_YAML).expect("policy");
        let reordered = MODEL_ONLY_YAML.replace(
            "    allowed_record_types:\n      - A\n      - AAAA",
            "    allowed_record_types:\n      - AAAA\n      - A",
        );
        let second = GuardPolicy::from_yaml(&reordered).expect("reordered policy");
        assert_eq!(first.hash().expect("hash"), second.hash().expect("hash"));
        assert_eq!(
            first.canonical_json().expect("canonical"),
            second.canonical_json().expect("canonical")
        );
        assert!(
            first
                .canonical_json()
                .expect("canonical")
                .starts_with(b"{\"version\":1")
        );
    }

    #[test]
    fn hash_changes_with_meaningful_content() {
        let base = GuardPolicy::from_yaml(MODEL_ONLY_YAML).expect("policy");
        let stricter = GuardPolicy::from_yaml(
            &MODEL_ONLY_YAML.replace("requests_per_minute: 120", "requests_per_minute: 30"),
        )
        .expect("stricter policy");
        assert_ne!(base.hash().expect("hash"), stricter.hash().expect("hash"));
        assert_eq!(base.hash().expect("hash").len(), 64);
    }

    #[test]
    fn template_no_network_permits_nothing_and_refuses_extra_input() {
        let policy =
            GuardPolicy::template(PolicyTemplate::NoNetwork, None, Vec::new()).expect("policy");
        assert!(policy.network.egress.is_empty());
        assert!(policy.network.dns.allowed_zones.is_empty());
        assert!(policy.model.is_none());
        assert!(
            GuardPolicy::template(
                PolicyTemplate::NoNetwork,
                Some(model_endpoint("a.example.com")),
                Vec::new()
            )
            .is_err()
        );
        let allowlisted = vec![EgressRule {
            host: "a.example.com".to_string(),
            port: 443,
            protocol: EGRESS_PROTOCOL_TCP.to_string(),
            allowed_methods: Vec::new(),
            allowed_paths: Vec::new(),
        }];
        assert!(GuardPolicy::template(PolicyTemplate::NoNetwork, None, allowlisted).is_err());
    }

    #[test]
    fn template_model_only_requires_methods_and_covers_the_model_host() {
        let model = model_endpoint("api.example-model.com");
        let policy =
            GuardPolicy::template(PolicyTemplate::ModelOnly, Some(model.clone()), Vec::new())
                .expect("model-only");
        assert_eq!(
            policy.network.dns.allowed_zones,
            vec!["api.example-model.com"]
        );
        assert_eq!(policy.network.egress, vec![EgressRule::from_model(&model)]);
        assert_eq!(policy.credentials.len(), 1);
        assert_eq!(policy.credentials[0].name, model.credential);

        let mut opaque = model;
        opaque.allowed_methods = Vec::new();
        let message = GuardPolicy::template(PolicyTemplate::ModelOnly, Some(opaque), Vec::new())
            .expect_err("method-less model path must be refused")
            .to_string();
        assert!(message.contains("allowed_methods"), "{message}");
        assert!(GuardPolicy::template(PolicyTemplate::ModelOnly, None, Vec::new()).is_err());
    }

    #[test]
    fn template_model_plus_allowlist_requires_distinct_destinations() {
        let model = model_endpoint("api.example-model.com");
        assert!(
            GuardPolicy::template(
                PolicyTemplate::ModelPlusAllowlist,
                Some(model.clone()),
                Vec::new()
            )
            .is_err()
        );
        let policy = GuardPolicy::template(
            PolicyTemplate::ModelPlusAllowlist,
            Some(model.clone()),
            vec![EgressRule {
                host: "api.docs.example.com".to_string(),
                port: 443,
                protocol: EGRESS_PROTOCOL_TCP.to_string(),
                allowed_methods: vec!["GET".to_string()],
                allowed_paths: vec!["/v1/".to_string()],
            }],
        )
        .expect("model plus allowlist");
        assert_eq!(policy.network.egress.len(), 2);
        let mut zones = policy.network.dns.allowed_zones.clone();
        zones.sort();
        assert_eq!(zones, vec!["api.docs.example.com", "api.example-model.com"]);

        let duplicate = vec![EgressRule {
            host: model.host.clone(),
            port: model.port,
            protocol: EGRESS_PROTOCOL_TCP.to_string(),
            allowed_methods: vec!["GET".to_string()],
            allowed_paths: Vec::new(),
        }];
        let message =
            GuardPolicy::template(PolicyTemplate::ModelPlusAllowlist, Some(model), duplicate)
                .expect_err("duplicate destination")
                .to_string();
        assert!(message.contains("duplicate"), "{message}");
    }

    #[test]
    fn template_read_only_api_refuses_mutating_methods_and_models() {
        let read = EgressRule {
            host: "api.docs.example.com".to_string(),
            port: 443,
            protocol: EGRESS_PROTOCOL_TCP.to_string(),
            allowed_methods: vec!["GET".to_string(), "HEAD".to_string()],
            allowed_paths: vec!["/v1/".to_string()],
        };
        let policy = GuardPolicy::template(PolicyTemplate::ReadOnlyApi, None, vec![read.clone()])
            .expect("read-only policy");
        assert!(policy.model.is_none());
        assert_eq!(
            policy.network.dns.allowed_zones,
            vec!["api.docs.example.com"]
        );

        let mutation = EgressRule {
            allowed_methods: vec!["POST".to_string()],
            ..read.clone()
        };
        assert!(GuardPolicy::template(PolicyTemplate::ReadOnlyApi, None, vec![mutation]).is_err());
        let opaque = EgressRule {
            allowed_methods: Vec::new(),
            ..read.clone()
        };
        let message = GuardPolicy::template(PolicyTemplate::ReadOnlyApi, None, vec![opaque])
            .expect_err("opaque read-only rule")
            .to_string();
        assert!(message.contains("read-only-api"), "{message}");
        assert!(
            GuardPolicy::template(
                PolicyTemplate::ReadOnlyApi,
                Some(model_endpoint("api.example-model.com")),
                vec![read]
            )
            .is_err()
        );
        assert!(GuardPolicy::template(PolicyTemplate::ReadOnlyApi, None, Vec::new()).is_err());
    }

    #[test]
    fn model_credential_must_be_bound_to_the_exact_destination() {
        let mismatch = GuardPolicy::from_yaml(
            &MODEL_ONLY_YAML.replace("  port: 443\n    header", "  port: 8443\n    header"),
        )
        .expect_err("binding destination mismatch");
        assert!(mismatch.to_string().contains("disagree"), "{mismatch}");

        let unbound = GuardPolicy::from_yaml(&MODEL_ONLY_YAML.replace(
            "credentials:\n  - name: model-main\n    host: api.example-model.com\n    port: \
             443\n    header: authorization\n",
            "credentials: []\n",
        ))
        .expect_err("unbound model credential");
        assert!(unbound.to_string().contains("does not name"), "{unbound}");

        let secret = GuardPolicy::from_yaml(
            &MODEL_ONLY_YAML.replace("credential: model-main", "credential: sk-secret-value"),
        )
        .expect_err("secret-shaped credential binding");
        assert!(secret.to_string().contains("credential"), "{secret}");

        let no_route = GuardPolicy::from_yaml(&MODEL_ONLY_YAML.replace(
            "    - host: api.example-model.com\n      port: 443",
            "    - host: api.example-model.com\n      port: 8443",
        ))
        .expect_err("model endpoint without egress rule");
        assert!(
            no_route.to_string().contains("no matching network.egress"),
            "{no_route}"
        );
    }

    #[test]
    fn dns_scope_and_egress_must_agree_in_both_directions() {
        let uncovered = GuardPolicy::from_yaml(
            "version: 1\nnetwork:\n  dns:\n    allowed_zones:\n      - other.example.com\n  egress:\n    - host: api.example.com\n      port: 443\n",
        )
        .expect_err("egress outside zone");
        assert!(
            uncovered.to_string().contains("allowed DNS zone"),
            "{uncovered}"
        );

        let unused = GuardPolicy::from_yaml(
            "version: 1\nnetwork:\n  dns:\n    allowed_zones:\n      - other.example.com\n",
        )
        .expect_err("zone without route");
        assert!(unused.to_string().contains("matches no egress"), "{unused}");
    }

    #[test]
    fn suffix_zones_are_explicit_and_never_inherited_implicitly() {
        let scoped = DnsPolicy {
            allowed_zones: vec![".example.com".to_string()],
            allowed_record_types: vec!["A".to_string(), "AAAA".to_string()],
        };
        assert!(scoped.allows_name("api.example.com"));
        assert!(!scoped.allows_name("example.com"));
        assert!(!scoped.allows_name("evil-example.com"));
        assert!(!scoped.allows_name("api.example.com.evil.test"));

        let exact = DnsPolicy {
            allowed_zones: vec!["api.example.com".to_string()],
            ..scoped
        };
        assert!(exact.allows_name("API.EXAMPLE.COM"));
        assert!(exact.allows_name("api.example.com."));
        assert!(!exact.allows_name("other.example.com"));
        assert!(zone_matches(".example.com", "api.example.com"));
        assert!(!zone_matches(".example.com", "example.com"));
    }

    #[test]
    fn guard_config_precedence_is_unambiguous() {
        let default = GuardConfig::default();
        assert_eq!(default.topology, Topology::Outside);
        assert_eq!(default.policy_template, PolicyTemplate::NoNetwork);
        let effective = default
            .effective_policy()
            .expect("default effective policy");
        assert!(effective.network.egress.is_empty());
        assert!(effective.model.is_none());

        let explicit = GuardConfig {
            policy: Some(GuardPolicy::from_yaml(MODEL_ONLY_YAML).expect("policy")),
            ..GuardConfig::default()
        };
        assert!(
            explicit
                .effective_policy()
                .expect("explicit policy")
                .model
                .is_some()
        );

        let ambiguous = GuardConfig {
            policy: Some(GuardPolicy::from_yaml(MODEL_ONLY_YAML).expect("policy")),
            policy_template: PolicyTemplate::ModelOnly,
            ..GuardConfig::default()
        };
        let message = ambiguous
            .effective_policy()
            .expect_err("ambiguous selection")
            .to_string();
        assert!(
            message.contains("both an explicit policy and a template"),
            "{message}"
        );

        let template = GuardConfig {
            policy_template: PolicyTemplate::ModelOnly,
            model_endpoint: Some(model_endpoint("api.example-model.com")),
            ..GuardConfig::default()
        };
        assert!(
            template
                .effective_policy()
                .expect("template")
                .model
                .is_some()
        );
        // The template-built policy is the same shape as the explicit one, so a
        // sandbox selected either way compiles from equivalent inputs.
        let from_template = template.effective_policy().expect("template");
        assert_eq!(
            from_template.network.egress,
            explicit
                .effective_policy()
                .expect("explicit")
                .network
                .egress
        );
        assert_eq!(from_template.hash().expect("hash").len(), 64);
    }

    #[test]
    fn guard_config_yaml_parses_and_validates_effective_policy() {
        let config = GuardConfig::from_yaml(
            "topology: inside\npolicy_template: model-only\nmodel_endpoint:\n  host: api.example-model.com\n  port: 443\n  allowed_methods:\n    - POST\n  allowed_paths:\n    - /v1/\n  credential: model-main\n",
        )
        .expect("guard config");
        assert_eq!(config.topology, Topology::Inside);
        assert_eq!(
            config
                .effective_policy()
                .expect("effective policy")
                .network
                .egress
                .len(),
            1
        );
        assert!(GuardConfig::from_yaml("policy_template: bogus\n").is_err());
        assert!(GuardConfig::from_yaml("policy_template: model-only\n").is_err());
        assert!(GuardConfig::from_yaml("unknown: true\n").is_err());
    }

    #[test]
    fn topology_and_template_serde_forms_are_kebab_case() {
        assert_eq!(
            serde_yaml_ng::to_string(&PolicyTemplate::ModelPlusAllowlist)
                .expect("serde")
                .trim(),
            "model-plus-allowlist"
        );
        assert_eq!(
            serde_yaml_ng::to_string(&Topology::Inside)
                .expect("serde")
                .trim(),
            "inside"
        );
        assert_eq!(
            serde_yaml_ng::from_str::<PolicyTemplate>("no-network").expect("serde"),
            PolicyTemplate::NoNetwork
        );
        assert_eq!(PolicyTemplate::default(), PolicyTemplate::NoNetwork);
        assert_eq!(Topology::default(), Topology::Outside);
        assert!(PolicyTemplate::requires_model(PolicyTemplate::ModelOnly));
        assert!(!PolicyTemplate::requires_model(PolicyTemplate::ReadOnlyApi));
        assert!(serde_yaml_ng::from_str::<PolicyTemplate>("ModelOnly").is_err());
    }

    #[test]
    fn shipped_templates_parse_and_hash_stably() {
        let templates = [
            (
                "no-network",
                include_str!("../../../policies/guard/no-network.yaml"),
            ),
            (
                "model-only",
                include_str!("../../../policies/guard/model-only.yaml"),
            ),
            (
                "model-plus-allowlist",
                include_str!("../../../policies/guard/model-plus-allowlist.yaml"),
            ),
            (
                "read-only-api",
                include_str!("../../../policies/guard/read-only-api.yaml"),
            ),
            (
                "model-only.local-mock",
                include_str!("../../../policies/guard/model-only.local-mock.yaml"),
            ),
        ];
        let mut hashes = std::collections::BTreeMap::new();
        for (name, text) in templates {
            let policy = GuardPolicy::from_yaml(text)
                .unwrap_or_else(|err| panic!("shipped template {name} must parse: {err}"));
            let first = policy.hash().expect("hash");
            let second = GuardPolicy::from_yaml(text)
                .expect("reparse")
                .hash()
                .expect("hash");
            assert_eq!(first, second, "{name} hash must be deterministic");
            assert_eq!(first.len(), 64, "{name}");
            hashes.insert(name, first);
        }
        let no_network = GuardPolicy::from_yaml(templates[0].1).expect("no-network");
        assert!(no_network.network.egress.is_empty());
        assert!(no_network.model.is_none());
        let read_only = GuardPolicy::from_yaml(templates[3].1).expect("read-only");
        assert!(read_only.model.is_none());
        for rule in &read_only.network.egress {
            assert!(
                rule.allowed_methods
                    .iter()
                    .all(|m| READ_ONLY_METHODS.contains(&m.as_str())),
                "read-only template must only allow read methods"
            );
        }
        assert_ne!(hashes["no-network"], hashes["model-only"]);
        assert_ne!(hashes["model-only"], hashes["model-only.local-mock"]);
    }

    #[test]
    fn shipped_guard_config_examples_parse() {
        for text in [
            include_str!("../../../policies/guard/guard-config.model-only.yaml"),
            include_str!("../../../policies/guard/guard-config.no-network.yaml"),
        ] {
            GuardConfig::from_yaml(text).expect("shipped guard config");
        }
    }
}
