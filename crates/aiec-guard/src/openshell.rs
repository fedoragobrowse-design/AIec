//! Import of a public OpenShell sandbox policy into a Guard policy.
//!
//! Source of truth: the NVIDIA OpenShell policy schema reference, Apache-2.0,
//! read at commit `71440b28f48d5fefc569d779f70d6e63893aa80a` (2026-10-01):
//! <https://github.com/NVIDIA/OpenShell/blob/71440b28f48d5fefc569d779f70d6e63893aa80a/docs/how-it-works/policies/schema.mdx>.
//! No OpenShell code is copied; the mirror types below describe its documented
//! fields so that a field this build does not know about is refused rather than
//! ignored.
//!
//! Two rules govern everything here. A field that converts is recorded with
//! what it became. A field that cannot convert is recorded with its reason, and
//! when dropping it would change what the policy permits, the whole import is
//! refused - a converted policy that looks equivalent to a source policy and is
//! strictly more permissive is the failure mode this module exists to prevent.
//!
//! The conversions themselves are narrow on purpose. Destinations, ports,
//! TCP, the REST access presets, exact REST method and path rules, GraphQL
//! operation kinds and names, and MCP method and tool names convert. Everything
//! scoped to a binary, to the filesystem, to credentials Guard does not hold,
//! or to a deny list Guard has no way to express, is refused.

use crate::policy::{
    EgressRule, GraphqlRules, GuardPolicy, L7Policy, McpRules, POLICY_VERSION, validate_dns_name,
};
use crate::{GuardError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The pinned schema reference this importer was written against.
pub const SCHEMA_REFERENCE: &str = "https://github.com/NVIDIA/OpenShell/blob/\
71440b28f48d5fefc569d779f70d6e63893aa80a/docs/how-it-works/policies/schema.mdx";

/// The largest policy document the source schema accepts.
pub const MAX_IMPORT_BYTES: usize = 4 * 1024 * 1024;
/// Most fatal findings named in one refusal message.
pub const MAX_REPORTED_FINDINGS: usize = 16;
/// Most endpoints one import converts.
pub const MAX_ENDPOINTS: usize = crate::policy::MAX_EGRESS_RULES;

/// One field that converted, and what it became.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conversion {
    /// Dotted path of the field in the source document.
    pub field: String,
    /// The Guard field or rule it produced.
    pub mapped_to: String,
}

/// One field that did not convert.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedField {
    /// Dotted path of the field in the source document.
    pub field: String,
    /// Why it cannot be honoured, in the operator's terms.
    pub reason: String,
    /// True when dropping it would change what the policy permits, which is
    /// what refuses the import.
    pub fatal: bool,
}

/// Everything the import did and did not do.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportReport {
    /// The schema reference the conversion was written against.
    pub schema_reference: String,
    /// Every field that converted.
    pub converted: Vec<Conversion>,
    /// Every field that did not.
    pub unsupported: Vec<UnsupportedField>,
}

impl ImportReport {
    /// A report naming the pinned schema and nothing else, for a failure that
    /// happened before any field could be read.
    pub fn empty() -> Self {
        Self {
            schema_reference: SCHEMA_REFERENCE.to_owned(),
            converted: Vec::new(),
            unsupported: Vec::new(),
        }
    }

    /// Whether any dropped field would have changed what the policy permits.
    pub fn is_refused(&self) -> bool {
        self.unsupported.iter().any(|field| field.fatal)
    }

    fn converted(&mut self, field: String, mapped_to: String) {
        self.converted.push(Conversion { field, mapped_to });
    }

    fn dropped(&mut self, field: String, reason: String, fatal: bool) {
        self.unsupported.push(UnsupportedField {
            field,
            reason,
            fatal,
        });
    }
}

/// A converted policy and the report that explains it.
#[derive(Clone, Debug)]
pub struct ImportedPolicy {
    /// The Guard policy. Never present on a refused import.
    pub policy: GuardPolicy,
    /// The layer 7 rules the source policy's body inspection implies, if any.
    ///
    /// Guard's L7 policy is per attachment rather than per endpoint, so an
    /// import only produces it when every body-inspecting endpoint agrees.
    pub l7: Option<L7Policy>,
    /// What converted, what did not, and what was refused.
    pub report: ImportReport,
}

/// Why an import produced nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportFailure {
    /// Set when the document could not be read at all.
    pub document_error: Option<String>,
    /// The findings, which name every field that could not be honoured.
    pub report: ImportReport,
}

impl std::fmt::Display for ImportFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(error) = &self.document_error {
            return write!(formatter, "openshell import refused: {error}");
        }
        let fatal: Vec<&UnsupportedField> = self
            .report
            .unsupported
            .iter()
            .filter(|field| field.fatal)
            .collect();
        write!(
            formatter,
            "openshell import refused: {} unsupported field(s) carry security properties Guard \
             cannot enforce:",
            fatal.len()
        )?;
        for field in fatal.iter().take(MAX_REPORTED_FINDINGS) {
            write!(formatter, "\n  {}: {}", field.field, field.reason)?;
        }
        if fatal.len() > MAX_REPORTED_FINDINGS {
            write!(
                formatter,
                "\n  ... and {} more",
                fatal.len() - MAX_REPORTED_FINDINGS
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ImportFailure {}

/// Reads an OpenShell policy document and converts what it can.
///
/// The result is either a policy plus a complete report, or a failure carrying
/// the report that says why there is no policy. A field this build does not know
/// about is a refusal, never a silent omission.
pub fn import_openshell(document: &str) -> std::result::Result<ImportedPolicy, ImportFailure> {
    let mut report = ImportReport {
        schema_reference: SCHEMA_REFERENCE.to_owned(),
        converted: Vec::new(),
        unsupported: Vec::new(),
    };
    if document.len() > MAX_IMPORT_BYTES {
        report.dropped(
            "document".to_owned(),
            format!(
                "document is {} bytes and the source schema accepts at most {MAX_IMPORT_BYTES}",
                document.len()
            ),
            true,
        );
        return Err(ImportFailure {
            document_error: None,
            report,
        });
    }
    let source: SourcePolicy = match serde_yaml_ng::from_str(document) {
        Ok(source) => source,
        Err(error) => {
            return Err(ImportFailure {
                document_error: Some(format!("document is not a valid OpenShell policy: {error}")),
                report,
            });
        }
    };
    let mut import = Import {
        report: &mut report,
        egress: Vec::new(),
        zones: Vec::new(),
        mcp: None,
        graphql: None,
    };
    if source.version != POLICY_VERSION {
        import.report.dropped(
            "version".to_owned(),
            format!(
                "schema version {} is not the version {POLICY_VERSION} this importer understands",
                source.version
            ),
            true,
        );
    }
    import.sections(&source);
    if import.report.is_refused() {
        return Err(ImportFailure {
            document_error: None,
            report,
        });
    }
    let mut policy = GuardPolicy::default();
    policy.network.egress = import.egress;
    policy.network.dns.allowed_zones = import.zones;
    let l7 = match (import.mcp, import.graphql) {
        (None, None) => None,
        (mcp, graphql) => Some(L7Policy {
            mode: crate::policy::L7Mode::Sni,
            http: Vec::new(),
            mcp: mcp.unwrap_or_default(),
            graphql: graphql.unwrap_or_default(),
            intercept_ack: false,
        }),
    };
    if let Some(l7) = &l7 {
        crate::l7::validate(l7).map_err(|error| ImportFailure {
            document_error: Some(format!(
                "converted layer 7 rules are not enforceable: {error}"
            )),
            report: report.clone(),
        })?;
    }
    policy.validate().map_err(|error| ImportFailure {
        document_error: Some(format!(
            "converted policy is not a valid Guard policy: {error}"
        )),
        report: report.clone(),
    })?;
    Ok(ImportedPolicy { policy, l7, report })
}

struct Import<'a> {
    report: &'a mut ImportReport,
    egress: Vec<EgressRule>,
    zones: Vec<String>,
    mcp: Option<McpRules>,
    graphql: Option<GraphqlRules>,
}

impl Import<'_> {
    fn sections(&mut self, source: &SourcePolicy) {
        for (field, present) in [
            ("filesystem_policy", source.filesystem_policy.is_some()),
            ("landlock", source.landlock.is_some()),
            ("process", source.process.is_some()),
        ] {
            if present {
                self.report.dropped(
                    field.to_owned(),
                    "OpenShell enforces this inside the sandbox; an out-of-guest gateway can \
                     neither grant it nor observe it"
                        .to_owned(),
                    true,
                );
            }
        }
        if source.network_middlewares.is_some() {
            self.report.dropped(
                "network_middlewares".to_owned(),
                "middleware runs in-process on inspected traffic and Guard has no in-process \
                 middleware chain"
                    .to_owned(),
                true,
            );
        }
        self.report.dropped(
            "network_policies.*.dns".to_owned(),
            "OpenShell DNS controls are binary-scoped; Guard resolves only the hosts its egress \
             rules name, through its own default-deny resolver"
                .to_owned(),
            false,
        );
        let Some(policies) = &source.network_policies else {
            return;
        };
        for (name, rule) in policies {
            let path = format!("network_policies.{name}");
            if rule.name.is_some() {
                self.report.converted(
                    format!("{path}.name"),
                    "no equivalent: Guard names a rule by host and port".to_owned(),
                );
            }
            match &rule.binaries {
                None => self.report.converted(
                    format!("{path}.binaries"),
                    "absent: treated as unrestricted, which is Guard's per-sandbox scope"
                        .to_owned(),
                ),
                Some(binaries) if binaries.is_empty() => self.report.converted(
                    format!("{path}.binaries"),
                    "empty: an empty list matches no binary, so the rule contributes nothing and \
                     is dropped without widening anything"
                        .to_owned(),
                ),
                Some(binaries) => {
                    self.report.dropped(
                        format!("{path}.binaries"),
                        format!(
                            "{} binary-scoped clause(s) cannot be honoured: Guard runs outside the \
                             guest and cannot establish which executable opened a connection",
                            binaries.len()
                        ),
                        true,
                    );
                }
            }
            let Some(endpoints) = &rule.endpoints else {
                continue;
            };
            for (index, endpoint) in endpoints.iter().enumerate() {
                let path = format!("{path}.endpoints[{index}]");
                self.endpoint(&path, endpoint);
                if self.egress.len() > MAX_ENDPOINTS {
                    self.report.dropped(
                        "network_policies".to_owned(),
                        format!("more than {MAX_ENDPOINTS} endpoints in one policy"),
                        true,
                    );
                    return;
                }
            }
        }
    }

    fn endpoint(&mut self, path: &str, endpoint: &SourceEndpoint) {
        if endpoint.allowed_ips.is_some() {
            self.report.dropped(
                format!("{path}.allowed_ips"),
                "Guard resolves the destination itself and checks the address it actually \
                 pinned; it cannot additionally require the address to fall in a CIDR"
                    .to_owned(),
                true,
            );
        }
        if endpoint.path.is_some() {
            self.report.dropped(
                format!("{path}.path"),
                "an endpoint path glob selects among endpoints on one host and port, and Guard \
                 rules are per host and port"
                    .to_owned(),
                true,
            );
        }
        for (field, present) in [
            ("credential_binding", endpoint.credential_binding.is_some()),
            (
                "request_body_credential_rewrite",
                endpoint.request_body_credential_rewrite == Some(true),
            ),
            (
                "websocket_credential_rewrite",
                endpoint.websocket_credential_rewrite == Some(true),
            ),
            (
                "allow_uninspected_credentials",
                endpoint.allow_uninspected_credentials == Some(true),
            ),
            ("credential_signing", endpoint.credential_signing.is_some()),
            ("signing_service", endpoint.signing_service.is_some()),
            ("signing_region", endpoint.signing_region.is_some()),
            ("mcp", endpoint.mcp.is_some()),
            (
                "graphql_persisted_queries",
                endpoint.graphql_persisted_queries.is_some(),
            ),
            ("persisted_queries", endpoint.persisted_queries.is_some()),
            (
                "graphql_max_body_bytes",
                endpoint.graphql_max_body_bytes.is_some(),
            ),
            ("json_rpc", endpoint.json_rpc.is_some()),
        ] {
            if present {
                self.report.dropped(
                    format!("{path}.{field}"),
                    "provider-profile integration Guard does not implement: it binds one \
                     placeholder credential and has no provider profile, body rewriting or \
                     request signing"
                        .to_owned(),
                    true,
                );
            }
        }
        if endpoint.allow_encoded_slash == Some(true) {
            self.report.dropped(
                format!("{path}.allow_encoded_slash"),
                "Guard refuses percent-encoded request targets rather than decoding them, so a \
                 path rule can never be spelled two ways"
                    .to_owned(),
                true,
            );
        }
        if let Some(rules) = &endpoint.deny_rules
            && endpoint.protocol.as_deref() != Some("mcp")
        {
            self.report.dropped(
                format!("{path}.deny_rules"),
                format!(
                    "{} deny rule(s) cannot be expressed: Guard's destination rules are an allow \
                     list, and converting an allow list minus a deny list would report a \
                     restriction Guard does not apply",
                    rules.len()
                ),
                true,
            );
        }
        match endpoint.enforcement.as_deref() {
            Some("enforce") => self.report.converted(
                format!("{path}.enforcement"),
                "always enforced: a Guard rule either permits or refuses".to_owned(),
            ),
            other => self.report.dropped(
                format!("{path}.enforcement"),
                format!(
                    "enforcement is {}: Guard has no audit-only mode, because logging a rule it \
                     does not apply would report a restriction the sandbox never faced",
                    other.unwrap_or("audit (the schema default)")
                ),
                true,
            ),
        }
        let Some(host) = endpoint.host.clone() else {
            self.report.dropped(
                format!("{path}.host"),
                "an endpoint without a host can only be constrained by allowed_ips, which Guard \
                 cannot express"
                    .to_owned(),
                true,
            );
            return;
        };
        if host.contains('*') {
            self.report.dropped(
                format!("{path}.host"),
                "wildcard hosts cannot be expressed: Guard egress rules name one exact host, so \
                 an operator must enumerate the names the wildcard covers"
                    .to_owned(),
                true,
            );
            return;
        }
        if validate_dns_name(&host, &format!("{path}.host"), 2).is_err() {
            self.report.dropped(
                format!("{path}.host"),
                "host is not a canonical DNS name of at least two labels and cannot be \
                 authorized by Guard"
                    .to_owned(),
                true,
            );
            return;
        }
        let ports = match (&endpoint.port, &endpoint.ports) {
            (Some(_), Some(_)) => {
                self.report.dropped(
                    format!("{path}.ports"),
                    "port and ports cannot be combined".to_owned(),
                    true,
                );
                return;
            }
            (Some(port), None) => vec![*port],
            (None, Some(ports)) if !ports.is_empty() => {
                self.report.converted(
                    format!("{path}.ports"),
                    format!("{} exact destination rules, one per port", ports.len()),
                );
                ports.clone()
            }
            _ => {
                self.report.dropped(
                    format!("{path}.port"),
                    "endpoint names no port".to_owned(),
                    true,
                );
                return;
            }
        };
        let protocol = endpoint.protocol.as_deref().unwrap_or("tcp");
        for port in ports {
            let mut rule = EgressRule {
                host: host.clone(),
                port,
                protocol: crate::policy::EGRESS_PROTOCOL_TCP.to_owned(),
                allowed_methods: Vec::new(),
                allowed_paths: Vec::new(),
            };
            self.restrictions(path, protocol, endpoint, &mut rule);
            if self
                .egress
                .iter()
                .any(|existing| existing.host == rule.host && existing.port == rule.port)
            {
                self.report.dropped(
                    format!("{path}.host"),
                    format!(
                        "{}:{} is already produced by another endpoint in this policy, and Guard \
                         rules are per host and port",
                        rule.host, rule.port
                    ),
                    true,
                );
                continue;
            }
            self.zones.push(host.clone());
            self.egress.push(rule);
        }
    }

    /// Fills in what a destination rule may do, or records why it cannot.
    fn restrictions(
        &mut self,
        path: &str,
        protocol: &str,
        endpoint: &SourceEndpoint,
        rule: &mut EgressRule,
    ) {
        let request_fields_present = endpoint.access.is_some()
            || endpoint.rules.is_some()
            || endpoint.tls.is_some()
            || endpoint.allow_encoded_slash.is_some();
        match protocol {
            "tcp" => {
                if request_fields_present {
                    self.report.dropped(
                        format!("{path}.protocol"),
                        "a tcp endpoint accepts no request fields; Guard cannot tell an \
                         inconsistent source apart from one it would refuse"
                            .to_owned(),
                        true,
                    );
                    return;
                }
                match endpoint.tls.as_deref() {
                    Some("skip") => self.report.converted(
                        format!("{path}.tls"),
                        "destination-only rule: Guard forwards the tunnel and adds no TLS \
                         termination"
                            .to_owned(),
                    ),
                    None => self.report.converted(
                        format!("{path}.protocol"),
                        "destination-only tcp rule".to_owned(),
                    ),
                    other => self.report.dropped(
                        format!("{path}.tls"),
                        format!("tls: {} has no Guard equivalent", other.unwrap_or("unset")),
                        true,
                    ),
                }
            }
            "rest" => {
                if endpoint.tls.is_some() {
                    self.report.dropped(
                        format!("{path}.tls"),
                        "a request protocol cannot be combined with tls: skip, and Guard cannot \
                         terminate TLS to inspect the request it would skip"
                            .to_owned(),
                        true,
                    );
                    return;
                }
                let (mut methods, mut paths) =
                    match (endpoint.access.as_deref(), endpoint.rules.as_ref()) {
                        (Some(_), Some(_)) => {
                            self.report.dropped(
                                format!("{path}.access"),
                                "access and rules cannot be combined".to_owned(),
                                true,
                            );
                            return;
                        }
                        (Some(access), None) => match preset_methods(access) {
                            Some(methods) => (methods, Vec::new()),
                            None => {
                                self.report.dropped(
                                format!("{path}.access"),
                                format!(
                                    "access: {access} is not one of the documented presets, and \
                                     converting an unknown preset to an unrestricted \
                                     destination would permit more than the source policy does"
                                ),
                                true,
                            );
                                return;
                            }
                        },
                        (None, Some(entries)) if entries.is_empty() => {
                            self.report.dropped(
                                format!("{path}.rules"),
                                "an empty allow list permits nothing, and Guard cannot express a \
                             destination the guest may not reach at all"
                                    .to_owned(),
                                true,
                            );
                            return;
                        }
                        (None, Some(entries)) => {
                            let mut methods: Vec<String> = Vec::new();
                            let mut paths: Vec<String> = Vec::new();
                            for (index, entry) in entries.iter().enumerate() {
                                let matcher: SourceRestMatcher = match parse_matcher(
                                    &entry.allow,
                                    &format!("{path}.rules[{index}].allow"),
                                    self.report,
                                ) {
                                    Some(matcher) => matcher,
                                    None => continue,
                                };
                                if matcher.query.is_some() {
                                    self.report.dropped(
                                    format!("{path}.rules[{index}].allow.query"),
                                    "Guard matches no query parameter, so a query matcher would \
                                     be a restriction the converted policy does not carry"
                                        .to_owned(),
                                    true,
                                );
                                }
                                if matcher.method != "*" {
                                    methods.push(matcher.method.clone());
                                }
                                match path_glob(&matcher.path) {
                                    Ok(None) => {}
                                    Ok(Some(prefix)) => paths.push(prefix),
                                    Err(reason) => self.report.dropped(
                                        format!("{path}.rules[{index}].allow.path"),
                                        reason,
                                        true,
                                    ),
                                }
                            }
                            (methods, paths)
                        }
                        (None, None) => {
                            self.report.dropped(
                                format!("{path}.access"),
                                "a rest endpoint needs access or rules".to_owned(),
                                true,
                            );
                            return;
                        }
                    };
                methods.sort();
                methods.dedup();
                paths.sort();
                paths.dedup();
                rule.allowed_methods = methods;
                rule.allowed_paths = paths;
                self.report.converted(
                    format!("{path}.access"),
                    "network.egress allowed_methods and allowed_paths".to_owned(),
                );
            }
            "graphql" => {
                if endpoint.tls.is_some() {
                    self.report.dropped(
                        format!("{path}.tls"),
                        "a request protocol cannot be combined with tls: skip".to_owned(),
                        true,
                    );
                    return;
                }
                self.graphql_endpoint(path, endpoint);
            }
            "mcp" => self.mcp_endpoint(path, endpoint),
            "json-rpc" => self.json_rpc_endpoint(path, endpoint),
            "websocket" => self.report.dropped(
                format!("{path}.protocol"),
                "Guard does not inspect WebSocket upgrades or frames".to_owned(),
                true,
            ),
            other => self.report.dropped(
                format!("{path}.protocol"),
                format!("protocol {other} is not one Guard governs"),
                true,
            ),
        }
    }

    fn graphql_endpoint(&mut self, path: &str, endpoint: &SourceEndpoint) {
        let (allow_mutations, operations, root_fields) =
            match (endpoint.access.as_deref(), endpoint.rules.as_ref()) {
                (Some(_), Some(_)) => {
                    self.report.dropped(
                        format!("{path}.access"),
                        "access and rules cannot be combined".to_owned(),
                        true,
                    );
                    return;
                }
                (Some("read-only"), None) => (false, Vec::new(), Vec::new()),
                (Some("read-write"), None) => (true, Vec::new(), Vec::new()),
                (Some(other), None) => {
                    self.report.dropped(
                        format!("{path}.access"),
                        format!(
                            "access: {other} allows every operation including subscriptions, and \
                             Guard never permits a subscription"
                        ),
                        true,
                    );
                    return;
                }
                (None, Some(entries)) => {
                    let mut mutations = Vec::new();
                    let mut queries = Vec::new();
                    let mut operations: Vec<String> = Vec::new();
                    let mut root_fields: Vec<String> = Vec::new();
                    let mut every_field_free = false;
                    let mut unnamed = false;
                    for (index, entry) in entries.iter().enumerate() {
                        let matcher: SourceGraphqlMatcher = match parse_matcher(
                            &entry.allow,
                            &format!("{path}.rules[{index}].allow"),
                            self.report,
                        ) {
                            Some(matcher) => matcher,
                            None => continue,
                        };
                        match matcher.operation_type.as_str() {
                            "query" => queries.push(index),
                            "mutation" => mutations.push(index),
                            other => {
                                self.report.dropped(
                                    format!("{path}.rules[{index}].allow.operation_type"),
                                    format!("operation type {other} is not governed by Guard"),
                                    true,
                                );
                            }
                        }
                        match matcher.operation_name {
                            Some(name) => {
                                if name.contains('*') || name.contains('?') {
                                    self.report.dropped(
                                        format!("{path}.rules[{index}].allow.operation_name"),
                                        "Guard matches operation names exactly, and a glob would \
                                         authorize names the source policy does not"
                                            .to_owned(),
                                        true,
                                    );
                                } else {
                                    operations.push(name);
                                }
                            }
                            None => unnamed = true,
                        }
                        match matcher.fields {
                            Some(fields) => {
                                for field in fields {
                                    if field.contains('*') || field.contains('?') {
                                        self.report.dropped(
                                            format!("{path}.rules[{index}].allow.fields"),
                                            "Guard matches root field names exactly, and a glob \
                                             would authorize fields the source policy does not"
                                                .to_owned(),
                                            true,
                                        );
                                    } else {
                                        root_fields.push(field);
                                    }
                                }
                            }
                            None => every_field_free = true,
                        }
                    }
                    if unnamed && !operations.is_empty() {
                        self.report.dropped(
                            format!("{path}.rules"),
                            "some rules name an operation and some do not, and Guard cannot \
                             express both"
                                .to_owned(),
                            true,
                        );
                    }
                    if !mutations.is_empty() && queries.is_empty() {
                        self.report.dropped(
                            format!("{path}.rules"),
                            "the rules permit mutations but not queries, and Guard has no state \
                             in which a mutation is allowed and a query is not"
                                .to_owned(),
                            true,
                        );
                    }
                    operations.sort();
                    operations.dedup();
                    root_fields.sort();
                    root_fields.dedup();
                    (
                        !mutations.is_empty(),
                        if unnamed { Vec::new() } else { operations },
                        if every_field_free {
                            Vec::new()
                        } else {
                            root_fields
                        },
                    )
                }
                (None, None) => {
                    self.report.dropped(
                        format!("{path}.access"),
                        "a graphql endpoint needs access or rules".to_owned(),
                        true,
                    );
                    return;
                }
            };
        let rules = GraphqlRules {
            allow_mutations,
            operations,
            root_fields,
        };
        if let Some(existing) = &self.graphql
            && existing != &rules
        {
            self.report.dropped(
                format!("{path}.rules"),
                "Guard's graphql rules are per attachment and this policy scopes them per \
                 endpoint; converting both would authorize operations on the other endpoint"
                    .to_owned(),
                true,
            );
            return;
        }
        self.graphql = Some(rules);
        self.report.converted(
            format!("{path}.rules"),
            "l7.graphql operation kind, operation name and root fields".to_owned(),
        );
    }

    fn mcp_endpoint(&mut self, path: &str, endpoint: &SourceEndpoint) {
        let Some(entries) = &endpoint.rules else {
            self.report.dropped(
                format!("{path}.rules"),
                "an mcp endpoint needs rules unless it allows every known method, which Guard \
                 has no equivalent for"
                    .to_owned(),
                true,
            );
            return;
        };
        let mut allowed_methods: Vec<String> = Vec::new();
        let mut allowed_tools: Vec<String> = Vec::new();
        let mut denied_tools: Vec<String> = Vec::new();
        let mut unrestricted_tools = false;
        for (index, entry) in entries.iter().enumerate() {
            let matcher: SourceMcpMatcher = match parse_matcher(
                &entry.allow,
                &format!("{path}.rules[{index}].allow"),
                self.report,
            ) {
                Some(matcher) => matcher,
                None => continue,
            };
            let Some(method) = &matcher.method else {
                self.report.dropped(
                    format!("{path}.rules[{index}].allow.method"),
                    "a tool rule without a method cannot be attributed to tools/call".to_owned(),
                    true,
                );
                continue;
            };
            if !crate::l7::is_valid_json_rpc_method(method) {
                self.report.dropped(
                    format!("{path}.rules[{index}].allow.method"),
                    format!(
                        "method glob {method} cannot be honoured: Guard matches JSON-RPC methods \
                         exactly, because the source revision may define methods Guard does not"
                    ),
                    true,
                );
                continue;
            }
            allowed_methods.push(method.clone());
            let names = match (&matcher.tool, &matcher.params) {
                (Some(tool), _) => tool_names(tool),
                (None, Some(params)) => params_names(params),
                (None, None) => {
                    if method == "tools/call" {
                        unrestricted_tools = true;
                    }
                    None
                }
            };
            if let Some(names) = names {
                allowed_tools.extend(names);
            }
        }
        for (index, rule) in endpoint.deny_rules.iter().flatten().enumerate() {
            let matcher: SourceMcpMatcher =
                match parse_matcher(rule, &format!("{path}.deny_rules[{index}]"), self.report) {
                    Some(matcher) => matcher,
                    None => continue,
                };
            // The documented shape is `method: tools/call` plus a tool name;
            // a deny rule that names any other method has no Guard equivalent.
            if !matches!(matcher.method.as_deref(), None | Some("tools/call")) {
                self.report.dropped(
                    format!("{path}.deny_rules[{index}].method"),
                    "Guard denies tool names, not methods; a denied method would be reported as \
                     a restriction Guard does not apply"
                        .to_owned(),
                    true,
                );
                continue;
            }
            let names = match (&matcher.tool, &matcher.params) {
                (Some(tool), _) => tool_names(tool),
                (None, Some(params)) => params_names(params),
                (None, None) => {
                    self.report.dropped(
                        format!("{path}.deny_rules[{index}]"),
                        "a deny rule with no tool names denies every tools/call".to_owned(),
                        true,
                    );
                    continue;
                }
            };
            if let Some(names) = names {
                denied_tools.extend(names);
            }
        }
        if unrestricted_tools {
            self.report.dropped(
                format!("{path}.rules"),
                "a tools/call rule with no tool matcher permits every tool name, and Guard has no \
                 way to express that: an empty allow list denies them all"
                    .to_owned(),
                true,
            );
            return;
        }
        allowed_methods.sort();
        allowed_methods.dedup();
        allowed_tools.sort();
        allowed_tools.dedup();
        denied_tools.sort();
        denied_tools.dedup();
        let rules = McpRules {
            allowed_methods,
            allowed_tools,
            denied_tools,
        };
        if let Some(existing) = &self.mcp
            && existing != &rules
        {
            self.report.dropped(
                format!("{path}.rules"),
                "Guard's mcp rules are per attachment and this policy scopes them per endpoint; \
                 converting both would authorize tools on the other endpoint"
                    .to_owned(),
                true,
            );
            return;
        }
        self.mcp = Some(rules);
        self.report.converted(
            format!("{path}.rules"),
            "l7.mcp JSON-RPC methods and tool names".to_owned(),
        );
    }

    fn json_rpc_endpoint(&mut self, path: &str, endpoint: &SourceEndpoint) {
        let Some(entries) = &endpoint.rules else {
            self.report.dropped(
                format!("{path}.rules"),
                "a json-rpc endpoint needs rules".to_owned(),
                true,
            );
            return;
        };
        let mut allowed_methods: Vec<String> = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let matcher: SourceJsonRpcMatcher = match parse_matcher(
                &entry.allow,
                &format!("{path}.rules[{index}].allow"),
                self.report,
            ) {
                Some(matcher) => matcher,
                None => continue,
            };
            if !crate::l7::is_valid_json_rpc_method(&matcher.method) {
                self.report.dropped(
                    format!("{path}.rules[{index}].allow.method"),
                    format!(
                        "method {} cannot be honoured: Guard matches JSON-RPC methods exactly, \
                         and `*` would authorize every method the source policy does not name",
                        matcher.method
                    ),
                    true,
                );
                continue;
            }
            allowed_methods.push(matcher.method.clone());
        }
        let rules = McpRules {
            allowed_methods,
            allowed_tools: Vec::new(),
            denied_tools: Vec::new(),
        };
        if let Some(existing) = &self.mcp
            && existing != &rules
        {
            self.report.dropped(
                format!("{path}.rules"),
                "Guard's JSON-RPC method policy is per attachment and this policy scopes it per \
                 endpoint"
                    .to_owned(),
                true,
            );
            return;
        }
        self.mcp = Some(rules);
        self.report.converted(
            format!("{path}.rules"),
            "l7.mcp allowed JSON-RPC methods".to_owned(),
        );
    }
}

/// The methods an access preset permits, or `None` when the preset is not one
/// Guard knows - which is a refusal, because an unknown preset must never
/// become "no restriction".
fn preset_methods(access: &str) -> Option<Vec<String>> {
    match access {
        "read-only" => Some(
            crate::policy::READ_ONLY_METHODS
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
        ),
        "read-write" => Some(
            ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"]
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
        ),
        "full" => Some(Vec::new()),
        _ => None,
    }
}

/// A path glob converted into a Guard path prefix.
///
/// `None` means every path. A literal path is refused rather than converted:
/// Guard matches prefixes, so a literal OpenShell path would silently admit
/// everything under it, which is the one thing an import must never do.
fn path_glob(glob: &str) -> std::result::Result<Option<String>, String> {
    if glob.is_empty() || glob == "**" || glob == "/**" {
        return Ok(None);
    }
    if let Some(prefix) = glob.strip_suffix("/**") {
        if prefix.is_empty() || !prefix.starts_with('/') {
            return Err(format!("path glob {glob} is not an absolute prefix"));
        }
        // The trailing slash is kept: OpenShell's `**` needs at least one more
        // segment, and Guard's `/repos/` admits `/repos/x` but not `/repos`.
        return Ok(Some(format!("{prefix}/")));
    }
    if glob.contains('*') || glob.contains('?') || glob.contains('[') {
        return Err(format!(
            "path glob {glob} matches a shape Guard cannot express; only `**` and exact paths \
             convert"
        ));
    }
    Err(format!(
        "path {glob} matches exactly one path, and Guard matches path prefixes, so converting \
         it would also admit {glob}/... which the source policy does not"
    ))
}

fn tool_names(tool: &serde_yaml_ng::Value) -> Option<Vec<String>> {
    match tool {
        serde_yaml_ng::Value::String(name) => Some(vec![name.clone()]),
        serde_yaml_ng::Value::Mapping(map) => {
            let any = map.get(serde_yaml_ng::Value::String("any".to_owned()))?;
            let serde_yaml_ng::Value::Sequence(names) = any else {
                return None;
            };
            names
                .iter()
                .map(|name| match name {
                    serde_yaml_ng::Value::String(name) => Some(name.clone()),
                    _ => None,
                })
                .collect()
        }
        _ => None,
    }
}

/// The tool names a `params.name` matcher selects.
fn params_names(params: &serde_yaml_ng::Value) -> Option<Vec<String>> {
    tool_names(params.get("name")?)
}

/// Parses one rule matcher, recording the refusal when it does not fit the
/// matcher shape the protocol documents.
fn parse_matcher<T: for<'de> Deserialize<'de>>(
    value: &serde_yaml_ng::Value,
    path: &str,
    report: &mut ImportReport,
) -> Option<T> {
    // Round-tripping through text rather than `from_value` keeps the document's
    // own duplicate-key rejection in force for every nested matcher.
    let text = match serde_yaml_ng::to_string(value) {
        Ok(text) => text,
        Err(error) => {
            report.dropped(
                path.to_owned(),
                format!("rule could not be read: {error}"),
                true,
            );
            return None;
        }
    };
    match serde_yaml_ng::from_str::<T>(&text) {
        Ok(matcher) => Some(matcher),
        Err(error) => {
            report.dropped(
                path.to_owned(),
                format!("rule shape does not match this protocol's documented matcher: {error}"),
                true,
            );
            None
        }
    }
}

/// Mirror of the documented top level. Unknown fields are refused rather than
/// ignored, so a newer source schema fails loudly instead of converting into a
/// weaker policy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePolicy {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    filesystem_policy: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    landlock: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    process: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    network_policies: Option<BTreeMap<String, SourceRule>>,
    #[serde(default)]
    network_middlewares: Option<BTreeMap<String, serde_yaml_ng::Value>>,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRule {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    endpoints: Option<Vec<SourceEndpoint>>,
    #[serde(default)]
    binaries: Option<Vec<SourceBinary>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBinary {
    #[allow(dead_code)]
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEndpoint {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    ports: Option<Vec<u16>>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    allowed_ips: Option<Vec<String>>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    tls: Option<String>,
    #[serde(default)]
    enforcement: Option<String>,
    #[serde(default)]
    access: Option<String>,
    #[serde(default)]
    rules: Option<Vec<SourceAllowRule>>,
    #[serde(default)]
    deny_rules: Option<Vec<serde_yaml_ng::Value>>,
    #[serde(default)]
    allow_encoded_slash: Option<bool>,
    #[serde(default)]
    credential_binding: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    request_body_credential_rewrite: Option<bool>,
    #[serde(default)]
    websocket_credential_rewrite: Option<bool>,
    #[serde(default)]
    allow_uninspected_credentials: Option<bool>,
    #[serde(default)]
    credential_signing: Option<String>,
    #[serde(default)]
    signing_service: Option<String>,
    #[serde(default)]
    signing_region: Option<String>,
    #[serde(default)]
    mcp: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    persisted_queries: Option<String>,
    #[serde(default)]
    graphql_persisted_queries: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    graphql_max_body_bytes: Option<u64>,
    #[serde(default)]
    json_rpc: Option<serde_yaml_ng::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceAllowRule {
    allow: serde_yaml_ng::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRestMatcher {
    method: String,
    path: String,
    #[serde(default)]
    query: Option<serde_yaml_ng::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceGraphqlMatcher {
    operation_type: String,
    #[serde(default)]
    operation_name: Option<String>,
    #[serde(default)]
    fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMcpMatcher {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    tool: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    params: Option<serde_yaml_ng::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceJsonRpcMatcher {
    method: String,
}

/// Convenience for callers that want the converted policy only.
impl ImportedPolicy {
    /// The converted policy, already validated against Guard's own schema.
    pub fn into_policy(self) -> GuardPolicy {
        self.policy
    }
}

/// Serializes a converted policy as the Guard YAML an operator can install.
pub fn to_yaml(policy: &GuardPolicy) -> Result<String> {
    serde_yaml_ng::to_string(policy).map_err(GuardError::from)
}
