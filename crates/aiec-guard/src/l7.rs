//! Layer 7 governance, applied only to traffic Guard can actually see.
//!
//! Two modes, and the difference between them is a trust decision rather than
//! a setting. In [`L7Mode::Sni`] - the default - Guard matches the name the
//! client asked for against the compiled egress rules and forwards the tunnel.
//! Guard adds no TLS termination, holds no key for the destination, and
//! therefore cannot see the method or the path inside it. In
//! [`L7Mode::Intercept`] Guard terminates TLS inside itself, which is the only
//! way an out-of-guest gateway can read the request line and body of an HTTPS
//! request - and which means **Guard holds a key that can read every byte of the
//! traffic it governs**. That is why interception is explicit, why it requires
//! `intercept_ack`, and why a policy that asks for it without acknowledging it
//! is refused rather than silently downgraded.
//!
//! Where Guard can read a request - plaintext HTTP through the broker, and the
//! request line of an absolute-form HTTPS proxy request - the policy in
//! [`L7Policy`] governs it by method, by path, and, when the body is visible,
//! by JSON-RPC method, MCP tool name and GraphQL operation.
//!
//! Everything here is default-deny and bounded. Reasons are `&'static str`, so
//! no guest-supplied byte can reach an operator's event log through this
//! module; the gateway adds the destination separately. A construct Guard
//! cannot parse is refused rather than guessed at, because a guess about which
//! operation or tool a body carries is exactly the guess an attacker wants
//! Guard to make.

use crate::policy::{GraphqlRules, L7Mode, L7Policy, McpRules};
use crate::{GuardError, Result, policy::eq_ignore_case};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fmt;

/// Largest body Guard will buffer to apply a body rule. Beyond this the request
/// is refused rather than inspected partially.
pub const MAX_INSPECTED_BODY_BYTES: usize = 64 * 1024;
/// Deepest selection set, argument list and value nesting accepted.
pub const MAX_GRAPHQL_DEPTH: usize = 12;
/// Most field selections accepted across one document.
pub const MAX_GRAPHQL_FIELDS: usize = 256;
/// Most operations accepted in one document.
pub const MAX_GRAPHQL_OPERATIONS: usize = 8;
/// Most messages accepted in one JSON-RPC batch.
pub const MAX_JSONRPC_MESSAGES: usize = 64;
/// Longest JSON-RPC method name accepted.
pub const MAX_METHOD_BYTES: usize = 64;
/// Longest MCP tool name accepted.
pub const MAX_TOOL_NAME_BYTES: usize = 128;
/// Longest GraphQL operation or root field name accepted.
pub const MAX_OPERATION_NAME_BYTES: usize = 64;
/// Longest HTTP request target accepted by the path rules.
pub const MAX_TARGET_BYTES: usize = 2048;
/// Most entries accepted in one L7 rule list.
pub const MAX_L7_RULES: usize = 32;

/// Which governance layer answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Http,
    Mcp,
    Graphql,
}

impl Layer {
    /// Stable lowercase wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Mcp => "mcp",
            Self::Graphql => "graphql",
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a request was refused, in the terms a caller needs to answer it.
///
/// A malformed or oversized request is not a policy denial: it is a request
/// Guard declines to interpret, and reporting it as "forbidden" would hide the
/// difference between "you may not" and "I did not understand what this is".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The policy does not permit this request.
    Forbidden,
    /// Guard could not parse the request within its bounds.
    Malformed,
    /// The request exceeded a bound Guard enforces before inspecting it.
    TooLarge,
}

/// One decision. `Allow` and `Deny` reasons are static text, which is what
/// keeps request content out of the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow {
        reason: &'static str,
    },
    Deny {
        layer: Layer,
        refusal: Refusal,
        reason: &'static str,
    },
}

impl Verdict {
    /// Whether the request may proceed.
    pub fn allowed(self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// The static reason, for the audit record.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Allow { reason } | Self::Deny { reason, .. } => reason,
        }
    }

    /// The refusal class of a denial.
    pub fn refusal(self) -> Option<Refusal> {
        match self {
            Self::Allow { .. } => None,
            Self::Deny { refusal, .. } => Some(refusal),
        }
    }

    /// The layer that answered.
    pub fn layer(self) -> Option<Layer> {
        match self {
            Self::Allow { .. } => None,
            Self::Deny { layer, .. } => Some(layer),
        }
    }

    fn allow(reason: &'static str) -> Self {
        Self::Allow { reason }
    }

    fn deny(layer: Layer, refusal: Refusal, reason: &'static str) -> Self {
        Self::Deny {
            layer,
            refusal,
            reason,
        }
    }
}

/// A request Guard can see, with the body present only where Guard reads it.
#[derive(Clone, Copy, Debug)]
pub struct VisibleRequest<'a> {
    /// Canonical destination host the client asked for.
    pub host: &'a str,
    /// Request method, already validated by the HTTP parser.
    pub method: &'a str,
    /// Request target, without query.
    pub path: &'a str,
    /// Declared media type, if the client sent one.
    pub content_type: Option<&'a str>,
    /// The request body, present only for traffic Guard reads in the clear.
    pub body: Option<&'a [u8]>,
}

/// Validates an L7 policy, refusing anything ambiguous or unenforceable.
///
/// An interception mode without its acknowledgement is refused here, so no
/// caller has to remember the check.
pub fn validate(policy: &L7Policy) -> Result<()> {
    effective_mode(policy)?;
    if policy.http.len() > MAX_L7_RULES {
        return Err(l7_error("l7.http has more rules than the schema accepts"));
    }
    for rule in &policy.http {
        crate::policy::validate_dns_name(&rule.host, "l7.http.host", 2)?;
        if rule.methods.len() > MAX_L7_RULES || rule.paths.len() > MAX_L7_RULES {
            return Err(l7_error("an l7.http rule has more entries than it accepts"));
        }
        for method in &rule.methods {
            if !valid_method(method) {
                return Err(l7_error(
                    "l7.http.methods must be uppercase HTTP tokens such as GET or POST",
                ));
            }
        }
        for path in &rule.paths {
            if !valid_rule_path(path) {
                return Err(l7_error(
                    "l7.http.paths must be absolute, bounded paths without percent-encoding",
                ));
            }
        }
    }
    for (index, host) in policy
        .http
        .iter()
        .map(|rule| rule.host.to_ascii_lowercase())
        .enumerate()
    {
        if policy.http[..index]
            .iter()
            .any(|r| eq_ignore_case(&r.host, &host))
        {
            return Err(l7_error("two l7.http rules name the same host"));
        }
    }
    let mcp = &policy.mcp;
    for list in [&mcp.allowed_methods, &mcp.allowed_tools, &mcp.denied_tools] {
        if list.len() > MAX_L7_RULES {
            return Err(l7_error("an l7.mcp list has more entries than it accepts"));
        }
    }
    for method in &mcp.allowed_methods {
        if !valid_json_rpc_method(method) {
            return Err(l7_error(
                "l7.mcp.allowed_methods must be JSON-RPC method names",
            ));
        }
    }
    for tool in mcp.allowed_tools.iter().chain(mcp.denied_tools.iter()) {
        if !valid_tool_name(tool) {
            return Err(l7_error("l7.mcp tool names must match [A-Za-z0-9_.-]"));
        }
    }
    if mcp
        .allowed_tools
        .iter()
        .any(|tool| mcp.denied_tools.contains(tool))
    {
        return Err(l7_error("an l7.mcp tool cannot be both allowed and denied"));
    }
    let graphql = &policy.graphql;
    if graphql.operations.len() > MAX_L7_RULES || graphql.root_fields.len() > MAX_L7_RULES {
        return Err(l7_error(
            "an l7.graphql list has more entries than it accepts",
        ));
    }
    for name in graphql.operations.iter().chain(graphql.root_fields.iter()) {
        if !valid_graphql_name(name) {
            return Err(l7_error("l7.graphql names must be GraphQL names"));
        }
    }
    Ok(())
}

/// The mode a policy actually puts into force.
///
/// Interception that was not acknowledged has no mode: it is an error, not a
/// downgrade to [`L7Mode::Sni`], because the operator asked for something and
/// silently giving them something else is how a policy stops meaning what it
/// says.
pub fn effective_mode(policy: &L7Policy) -> Result<L7Mode> {
    match policy.mode {
        L7Mode::Sni => Ok(L7Mode::Sni),
        L7Mode::Intercept if policy.intercept_ack => Ok(L7Mode::Intercept),
        L7Mode::Intercept => Err(l7_error(
            "l7.mode intercept requires l7.intercept_ack: Guard holds a key able to read the \
             traffic it governs, and only an operator may acknowledge that",
        )),
    }
}

/// The decision for an opaque CONNECT tunnel.
///
/// A tunnel is never a plain HTTP request: Guard cannot see a method or a path
/// inside it, and treating one as if it could see them is how a destination ends
/// up governed by a rule that was never applied. A host whose L7 rules carry
/// methods or paths is therefore refused as a tunnel, in either mode, until the
/// operator either drops the rule or presents the governed requests in the
/// clear. Under [`L7Mode::Intercept`] that refusal covers every host the L7
/// policy names at all, because an acknowledged interception mode is a
/// statement that Guard reads this traffic.
pub fn tunnel_verdict(policy: Option<&L7Policy>, host: &str) -> Verdict {
    let Some(policy) = policy else {
        return Verdict::allow("l7: no layer 7 policy is configured");
    };
    if effective_mode(policy).is_err() {
        return Verdict::deny(Layer::Http, Refusal::Forbidden, INTERCEPTION_REFUSAL);
    }
    let Some(rule) = policy.http.iter().find(|r| eq_ignore_case(&r.host, host)) else {
        return Verdict::allow("l7: opaque tunnel to a host no http rule governs");
    };
    let governed = !rule.methods.is_empty() || !rule.paths.is_empty();
    if policy.mode == L7Mode::Intercept || governed {
        return Verdict::deny(
            Layer::Http,
            Refusal::Forbidden,
            "l7: TLS tunnel refused because Guard cannot read this host's method and path",
        );
    }
    Verdict::allow("l7: opaque tunnel forwarded to a host with no method or path rule")
}

/// The decision for a request Guard can see.
pub fn request_verdict(policy: Option<&L7Policy>, request: &VisibleRequest<'_>) -> Verdict {
    let Some(policy) = policy else {
        return Verdict::allow("l7: no layer 7 policy is configured");
    };
    if effective_mode(policy).is_err() {
        return Verdict::deny(Layer::Http, Refusal::Forbidden, INTERCEPTION_REFUSAL);
    }
    let http = http_verdict(policy, request.host, request.method, request.path);
    if !http.allowed() {
        return http;
    }
    let Some(body) = request.body.filter(|body| !body.is_empty()) else {
        return Verdict::allow("l7: request line allowed and no body is visible to inspect");
    };
    let graphql_media = graphql_media_type(request.content_type);
    if !graphql_media && !is_json(request.content_type, body) {
        return Verdict::allow("l7: request line allowed and the body is not an inspected type");
    }
    if body.len() > MAX_INSPECTED_BODY_BYTES {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::TooLarge,
            "l7: request body exceeds the inspection bound",
        );
    }
    if graphql_media {
        return match std::str::from_utf8(body) {
            Ok(text) => graphql_verdict(&policy.graphql, text),
            Err(_) => Verdict::deny(
                Layer::Graphql,
                Refusal::Malformed,
                "l7 graphql: document is not valid UTF-8",
            ),
        };
    }
    // A JSON body that does not parse is refused rather than forwarded: the
    // only reason to look inside a JSON body is to decide whether it is a
    // governed request, and an unparsable body has not answered that question.
    let Ok(text) = std::str::from_utf8(body) else {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Malformed,
            "l7: request body is not valid UTF-8",
        );
    };
    let Ok(StrictJson(value)) = serde_json::from_str::<StrictJson>(text) else {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Malformed,
            "l7: request body is not JSON without duplicate keys",
        );
    };
    match &value {
        // A GraphQL request over JSON: the envelope is not JSON-RPC.
        Value::Object(object) if object.contains_key("query") && !object.contains_key("method") => {
            match object.get("query") {
                Some(Value::String(document)) => graphql_verdict(&policy.graphql, document),
                Some(_) => Verdict::deny(
                    Layer::Graphql,
                    Refusal::Malformed,
                    "l7 graphql: query is not a string",
                ),
                None => Verdict::allow("l7: request line allowed and the body governs nothing"),
            }
        }
        // A JSON-RPC message, or a batch of them. A JSON body that claims
        // neither protocol governs nothing: MCP policy is about MCP traffic,
        // not about every document an API happens to accept.
        Value::Array(messages) if !messages.is_empty() => mcp_verdict(&policy.mcp, &value),
        Value::Object(object)
            if object.contains_key("method") || object.contains_key("jsonrpc") =>
        {
            mcp_verdict(&policy.mcp, &value)
        }
        _ => Verdict::allow("l7: request line allowed and the body governs nothing"),
    }
}

/// Method and path policy for one host.
///
/// A host no rule names is governed by the egress rule alone; an L7 rule that
/// names it is default-deny for everything the rule does not list.
pub fn http_verdict(policy: &L7Policy, host: &str, method: &str, path: &str) -> Verdict {
    let Some(rule) = policy.http.iter().find(|r| eq_ignore_case(&r.host, host)) else {
        return Verdict::allow("l7 http: no http rule governs this host");
    };
    if !valid_method(method) {
        return Verdict::deny(
            Layer::Http,
            Refusal::Malformed,
            "l7 http: request method is not an uppercase token",
        );
    }
    if !safe_path(path) {
        return Verdict::deny(
            Layer::Http,
            Refusal::Malformed,
            "l7 http: request target is not a bounded absolute path",
        );
    }
    if !rule.methods.is_empty() && !rule.methods.iter().any(|m| m == method) {
        return Verdict::deny(
            Layer::Http,
            Refusal::Forbidden,
            "l7 http: method is not allowed for this host",
        );
    }
    if !rule.paths.is_empty() && !rule.paths.iter().any(|p| path_matches(p, path)) {
        return Verdict::deny(
            Layer::Http,
            Refusal::Forbidden,
            "l7 http: path is not allowed for this host",
        );
    }
    Verdict::allow("l7 http: method and path are allowed for this host")
}

/// JSON-RPC method and MCP tool policy over a visible body.
pub fn mcp_verdict(rules: &McpRules, value: &Value) -> Verdict {
    match value {
        Value::Array(messages) => {
            if messages.is_empty() {
                return Verdict::deny(
                    Layer::Mcp,
                    Refusal::Malformed,
                    "l7 mcp: JSON-RPC batch is empty",
                );
            }
            if messages.len() > MAX_JSONRPC_MESSAGES {
                return Verdict::deny(
                    Layer::Mcp,
                    Refusal::TooLarge,
                    "l7 mcp: JSON-RPC batch exceeds the message bound",
                );
            }
            for message in messages {
                let verdict = message_verdict(rules, message);
                if !verdict.allowed() {
                    return verdict;
                }
            }
            Verdict::allow("l7 mcp: every message in the batch is allowed")
        }
        Value::Object(_) => message_verdict(rules, value),
        _ => Verdict::deny(
            Layer::Mcp,
            Refusal::Malformed,
            "l7 mcp: request body is not a JSON-RPC object or batch",
        ),
    }
}

fn message_verdict(rules: &McpRules, message: &Value) -> Verdict {
    let Value::Object(object) = message else {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Malformed,
            "l7 mcp: batch member is not a JSON-RPC object",
        );
    };
    if !matches!(object.get("jsonrpc"), Some(Value::String(version)) if version == "2.0") {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Malformed,
            "l7 mcp: request is not JSON-RPC 2.0",
        );
    }
    let Some(Value::String(method)) = object.get("method") else {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Malformed,
            "l7 mcp: request carries no method name",
        );
    };
    if !valid_json_rpc_method(method) {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Malformed,
            "l7 mcp: method name is not valid",
        );
    }
    if rules.denied_tools.iter().any(|tool| tool == method) {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Forbidden,
            "l7 mcp: method name is explicitly denied",
        );
    }
    if !rules
        .allowed_methods
        .iter()
        .any(|allowed| allowed == method)
    {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Forbidden,
            "l7 mcp: method is not in the allowed set",
        );
    }
    if method != "tools/call" {
        return Verdict::allow("l7 mcp: method is allowed");
    }
    let tool = object
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str);
    let Some(tool) = tool else {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Malformed,
            "l7 mcp: tools/call carries no params.name",
        );
    };
    if !valid_tool_name(tool) {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Malformed,
            "l7 mcp: tool name is not valid",
        );
    }
    if rules.denied_tools.iter().any(|denied| denied == tool) {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Forbidden,
            "l7 mcp: tool name is explicitly denied",
        );
    }
    if !rules.allowed_tools.iter().any(|allowed| allowed == tool) {
        return Verdict::deny(
            Layer::Mcp,
            Refusal::Forbidden,
            "l7 mcp: tool name is not in the allowed set",
        );
    }
    Verdict::allow("l7 mcp: method and tool name are allowed")
}

/// Operation kind, operation name and root field policy over a visible
/// document.
///
/// Every operation the document declares is checked, not only the one
/// `operationName` selects, so a batched document cannot hide a mutation behind
/// an allowed query.
pub fn graphql_verdict(rules: &GraphqlRules, document: &str) -> Verdict {
    let parsed = match parse_graphql(document) {
        Ok(parsed) => parsed,
        Err(error) => return Verdict::deny(Layer::Graphql, error.refusal, error.reason),
    };
    if parsed.operations.is_empty() {
        return Verdict::deny(
            Layer::Graphql,
            Refusal::Malformed,
            "l7 graphql: document declares no operation",
        );
    }
    for operation in &parsed.operations {
        match operation.kind {
            GraphqlKind::Subscription => {
                return Verdict::deny(
                    Layer::Graphql,
                    Refusal::Forbidden,
                    "l7 graphql: subscription is not supported",
                );
            }
            GraphqlKind::Mutation if !rules.allow_mutations => {
                return Verdict::deny(
                    Layer::Graphql,
                    Refusal::Forbidden,
                    "l7 graphql: mutation is not allowed",
                );
            }
            _ => {}
        }
        if !rules.operations.is_empty()
            && !operation
                .name
                .as_ref()
                .is_some_and(|name| rules.operations.iter().any(|allowed| allowed == name))
        {
            return Verdict::deny(
                Layer::Graphql,
                Refusal::Forbidden,
                "l7 graphql: operation name is not allowed",
            );
        }
        if !rules.root_fields.is_empty() {
            if operation.root_fields.is_empty() {
                return Verdict::deny(
                    Layer::Graphql,
                    Refusal::Forbidden,
                    "l7 graphql: operation selects no root field",
                );
            }
            if operation
                .root_fields
                .iter()
                .any(|field| !rules.root_fields.iter().any(|allowed| allowed == field))
            {
                return Verdict::deny(
                    Layer::Graphql,
                    Refusal::Forbidden,
                    "l7 graphql: root field is not allowed",
                );
            }
        }
    }
    Verdict::allow("l7 graphql: every declared operation is allowed")
}

/// What kind of operation a bounded parse found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphqlKind {
    Query,
    Mutation,
    Subscription,
}

impl GraphqlKind {
    /// Stable lowercase wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Mutation => "mutation",
            Self::Subscription => "subscription",
        }
    }
}

/// One operation a bounded parse found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphqlOperation {
    pub kind: GraphqlKind,
    /// Named operations carry their name; an anonymous selection set does not.
    pub name: Option<String>,
    /// Top-level field names, with aliases resolved to the real field.
    pub root_fields: Vec<String>,
}

/// A bounded parse of a GraphQL document.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GraphqlDocument {
    pub operations: Vec<GraphqlOperation>,
}

/// Why a document could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphqlParseError {
    pub refusal: Refusal,
    pub reason: &'static str,
}

/// Parses a GraphQL document far enough to decide its policy, and no further.
///
/// Fragments are refused rather than resolved: resolving a spread correctly
/// means tracking fragment definitions across the document, and a partially
/// resolved selection is a policy decision made on a field set that was never
/// checked. The parser is deliberately not a GraphQL implementation.
pub fn parse_graphql(document: &str) -> std::result::Result<GraphqlDocument, GraphqlParseError> {
    if document.len() > MAX_INSPECTED_BODY_BYTES {
        return Err(GraphqlParseError {
            refusal: Refusal::TooLarge,
            reason: "l7 graphql: document exceeds the inspection bound",
        });
    }
    let mut parser = Parser {
        input: document.as_bytes(),
        pos: 0,
        selected: 0,
    };
    let mut operations: Vec<GraphqlOperation> = Vec::new();
    loop {
        parser.skip_trivia();
        let Some(byte) = parser.input.get(parser.pos).copied() else {
            break;
        };
        if byte == b'{' {
            let root_fields = parser.selection_set(1)?;
            operations.push(GraphqlOperation {
                kind: GraphqlKind::Query,
                name: None,
                root_fields,
            });
        } else if parser.keyword(b"fragment") {
            return Err(unsupported(
                "l7 graphql: fragment definitions are not inspected",
            ));
        } else {
            let (kind, word) = if parser.keyword(b"query") {
                (GraphqlKind::Query, 5)
            } else if parser.keyword(b"mutation") {
                (GraphqlKind::Mutation, 8)
            } else if parser.keyword(b"subscription") {
                (GraphqlKind::Subscription, 12)
            } else {
                return Err(malformed("l7 graphql: document is not parsable"));
            };
            parser.pos += word;
            operations.push(parser.operation(kind)?);
        }
        if operations.len() > MAX_GRAPHQL_OPERATIONS {
            return Err(unsupported(
                "l7 graphql: document declares too many operations",
            ));
        }
    }
    Ok(GraphqlDocument { operations })
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    selected: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a [u8] {
        self.input.get(self.pos..).unwrap_or(&[])
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.input.get(self.pos).copied() {
                Some(b' ' | b'\t' | b'\r' | b'\n' | b',') => self.pos += 1,
                Some(b'#') => {
                    while let Some(byte) = self.input.get(self.pos) {
                        self.pos += 1;
                        if *byte == b'\n' {
                            break;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_trivia();
        self.input.get(self.pos).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        self.skip_trivia();
        if self.input.get(self.pos) == Some(&byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> std::result::Result<(), GraphqlParseError> {
        if self.eat(byte) {
            Ok(())
        } else {
            Err(malformed("l7 graphql: document is not parsable"))
        }
    }

    /// Whether the next word is exactly `word`.
    fn keyword(&mut self, word: &[u8]) -> bool {
        self.skip_trivia();
        let end = self.pos + word.len();
        if self.rest().len() < word.len() || &self.rest()[..word.len()] != word {
            return false;
        }
        !self
            .input
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    }

    fn name(&mut self) -> std::result::Result<String, GraphqlParseError> {
        self.skip_trivia();
        match self.input.get(self.pos) {
            Some(byte) if byte.is_ascii_alphabetic() || *byte == b'_' => {}
            _ => return Err(malformed("l7 graphql: document is not parsable")),
        }
        let start = self.pos;
        self.pos += 1;
        while let Some(byte) = self.input.get(self.pos) {
            if byte.is_ascii_alphanumeric() || *byte == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let name = String::from_utf8(self.input[start..self.pos].to_vec())
            .map_err(|_| malformed("l7 graphql: document is not parsable"))?;
        if name.len() > MAX_OPERATION_NAME_BYTES {
            return Err(unsupported("l7 graphql: name exceeds the length bound"));
        }
        Ok(name)
    }

    fn operation(
        &mut self,
        kind: GraphqlKind,
    ) -> std::result::Result<GraphqlOperation, GraphqlParseError> {
        let name = match self.peek() {
            Some(b'(') | Some(b'@') | Some(b'{') => None,
            _ => Some(self.name()?),
        };
        if self.peek() == Some(b'(') {
            self.variable_definitions(0)?;
        }
        self.directives()?;
        let root_fields = self.selection_set(1)?;
        Ok(GraphqlOperation {
            kind,
            name,
            root_fields,
        })
    }

    fn selection_set(
        &mut self,
        depth: usize,
    ) -> std::result::Result<Vec<String>, GraphqlParseError> {
        if depth > MAX_GRAPHQL_DEPTH {
            return Err(unsupported("l7 graphql: selection set nests too deeply"));
        }
        self.expect(b'{')?;
        let mut roots: Vec<String> = Vec::new();
        loop {
            self.skip_trivia();
            match self.input.get(self.pos).copied() {
                None => return Err(malformed("l7 graphql: document is not parsable")),
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(roots);
                }
                Some(b'.') => {
                    return Err(unsupported(
                        "l7 graphql: fragment spreads are not inspected",
                    ));
                }
                _ => {}
            }
            let field = self.name()?;
            self.selected += 1;
            if self.selected > MAX_GRAPHQL_FIELDS {
                return Err(unsupported("l7 graphql: document selects too many fields"));
            }
            if self.eat(b':') {
                self.name()?;
            }
            if depth == 1 && !roots.contains(&field) {
                roots.push(field);
            }
            if self.peek() == Some(b'(') {
                self.arguments(0)?;
            }
            self.directives()?;
            if self.peek() == Some(b'{') {
                self.selection_set(depth + 1)?;
            }
        }
    }

    fn arguments(&mut self, depth: usize) -> std::result::Result<(), GraphqlParseError> {
        self.expect(b'(')?;
        loop {
            self.skip_trivia();
            match self.input.get(self.pos).copied() {
                Some(b')') => {
                    self.pos += 1;
                    return Ok(());
                }
                None => return Err(malformed("l7 graphql: document is not parsable")),
                _ => {}
            }
            self.name()?;
            self.expect(b':')?;
            self.value(depth)?;
        }
    }

    fn variable_definitions(&mut self, depth: usize) -> std::result::Result<(), GraphqlParseError> {
        self.expect(b'(')?;
        loop {
            self.skip_trivia();
            match self.input.get(self.pos).copied() {
                Some(b')') => {
                    self.pos += 1;
                    return Ok(());
                }
                None => return Err(malformed("l7 graphql: document is not parsable")),
                Some(b'$') => {
                    self.pos += 1;
                    self.name()?;
                    self.expect(b':')?;
                    self.type_ref(depth)?;
                    if self.input.get(self.pos) == Some(&b'=') {
                        self.pos += 1;
                        self.value(depth)?;
                    }
                }
                _ => return Err(malformed("l7 graphql: document is not parsable")),
            }
        }
    }

    fn type_ref(&mut self, depth: usize) -> std::result::Result<(), GraphqlParseError> {
        if depth > MAX_GRAPHQL_DEPTH {
            return Err(unsupported("l7 graphql: type nests too deeply"));
        }
        self.skip_trivia();
        if self.input.get(self.pos) == Some(&b'[') {
            self.pos += 1;
            self.type_ref(depth + 1)?;
            self.expect(b']')?;
        } else {
            self.name()?;
        }
        if self.input.get(self.pos) == Some(&b'!') {
            self.pos += 1;
        }
        Ok(())
    }

    fn directives(&mut self) -> std::result::Result<(), GraphqlParseError> {
        loop {
            self.skip_trivia();
            if self.input.get(self.pos) != Some(&b'@') {
                return Ok(());
            }
            self.pos += 1;
            self.name()?;
            if self.peek() == Some(b'(') {
                self.arguments(0)?;
            }
        }
    }

    fn value(&mut self, depth: usize) -> std::result::Result<(), GraphqlParseError> {
        if depth > MAX_GRAPHQL_DEPTH {
            return Err(unsupported("l7 graphql: value nests too deeply"));
        }
        self.skip_trivia();
        match self.input.get(self.pos).copied() {
            Some(b'"') => self.string(),
            Some(open @ (b'[' | b'{')) => {
                let close = if open == b'[' { b']' } else { b'}' };
                self.pos += 1;
                loop {
                    self.skip_trivia();
                    match self.input.get(self.pos).copied() {
                        Some(byte) if byte == close => {
                            self.pos += 1;
                            return Ok(());
                        }
                        None => return Err(malformed("l7 graphql: document is not parsable")),
                        _ => self.value(depth + 1)?,
                    }
                }
            }
            Some(b'$') => {
                self.pos += 1;
                self.name().map(|_| ())
            }
            Some(byte) if byte.is_ascii_alphabetic() || byte == b'_' => self.name().map(|_| ()),
            Some(byte) if byte.is_ascii_digit() || byte == b'-' || byte == b'+' => self.number(),
            _ => Err(malformed("l7 graphql: document is not parsable")),
        }
    }

    fn number(&mut self) -> std::result::Result<(), GraphqlParseError> {
        while let Some(byte) = self.input.get(self.pos) {
            if byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E') {
                self.pos += 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn string(&mut self) -> std::result::Result<(), GraphqlParseError> {
        if self.rest().starts_with(b"\"\"\"") {
            self.pos += 3;
            loop {
                match self.input.get(self.pos).copied() {
                    None => return Err(malformed("l7 graphql: document is not parsable")),
                    Some(b'\\') => self.pos += 2,
                    Some(b'"') if self.rest().starts_with(b"\"\"\"") => {
                        self.pos += 3;
                        return Ok(());
                    }
                    Some(_) => self.pos += 1,
                }
            }
        }
        self.pos += 1;
        loop {
            match self.input.get(self.pos).copied() {
                None | Some(b'\n') => {
                    return Err(malformed("l7 graphql: document is not parsable"));
                }
                Some(b'\\') => self.pos += 2,
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(_) => self.pos += 1,
            }
        }
    }
}

fn malformed(reason: &'static str) -> GraphqlParseError {
    GraphqlParseError {
        refusal: Refusal::Malformed,
        reason,
    }
}

fn unsupported(reason: &'static str) -> GraphqlParseError {
    GraphqlParseError {
        refusal: Refusal::Forbidden,
        reason,
    }
}

/// Whether a path is a bounded absolute target safe to compare against a rule.
///
/// Percent-encoding, backslashes, dot segments and control bytes are refused
/// rather than normalized: a rule matched against a decoded path is a rule
/// matched against something the operator did not write, and a path a client
/// can spell two ways is a path whose allowed answer is "no".
pub fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_TARGET_BYTES
        && !path.contains('%')
        && !path.contains('\\')
        && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        && !path.bytes().any(|byte| byte <= 32 || byte == 127)
}

fn valid_rule_path(path: &str) -> bool {
    safe_path(path) && path.len() <= crate::policy::MAX_PATH_BYTES
}

/// Segment-prefix matching: an exact path, a prefix ending in `/`, or a
/// prefix followed by another segment. Never a raw string prefix, so `/v1` does
/// not admit `/v10`.
fn path_matches(rule: &str, path: &str) -> bool {
    path == rule
        || (rule.ends_with('/') && path.starts_with(rule))
        || path
            .strip_prefix(rule)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= MAX_METHOD_BYTES
        && method.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
        && method
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
}

fn valid_json_rpc_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= MAX_METHOD_BYTES
        && method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./".contains(&byte))
}

fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOOL_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

fn valid_graphql_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_OPERATION_NAME_BYTES
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_json(content_type: Option<&str>, body: &[u8]) -> bool {
    match content_type {
        Some(value) => {
            let value = value.to_ascii_lowercase();
            value.contains("json") || value.contains("graphql")
        }
        None => matches!(body.first(), Some(b'{') | Some(b'[')),
    }
}

fn graphql_media_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("graphql")
    })
}

fn l7_error(message: &'static str) -> GuardError {
    GuardError::Policy(message.to_string())
}

/// Why an interception request without its acknowledgement is refused. Static,
/// so a refusal reason in an event journal cannot carry text back out of the
/// policy file.
const INTERCEPTION_REFUSAL: &str =
    "l7: interception requires l7.intercept_ack: Guard holds a key able to read this traffic";

/// A JSON value that cannot contain a duplicate object key at any depth.
///
/// `serde_json::Value` keeps the last of two identical keys, and the server on
/// the other end of the connection may keep the first. That gap is a policy
/// bypass: a body carrying two `method` fields can pass an allow check as one
/// method and execute as another.
struct StrictJson(Value);

impl<'de> serde::Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(StrictJson(Value::Bool(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJson(Value::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJson(Value::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJson(Value::from(value)))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(StrictJson(Value::from(value)))
    }

    fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor)
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(StrictJson(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJson(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let StrictJson(value) = map.next_value()?;
            object.insert(key, value);
        }
        Ok(StrictJson(Value::Object(object)))
    }
}

/// Whether a JSON-RPC method name is in the syntax Guard accepts.
pub fn is_valid_json_rpc_method(method: &str) -> bool {
    valid_json_rpc_method(method)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> McpRules {
        McpRules {
            allowed_methods: vec!["tools/list".into(), "tools/call".into()],
            allowed_tools: vec!["read_file".into()],
            denied_tools: vec!["delete_repository".into()],
        }
    }

    fn verdict_for(body: &str) -> Verdict {
        mcp_verdict(
            &rules(),
            &serde_json::from_str(body).expect("test body parses"),
        )
    }

    #[test]
    fn mcp_tools_list_and_allowed_tool_pass_and_the_write_tool_does_not() {
        assert!(verdict_for(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).allowed());
        assert!(
            verdict_for(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#
            )
            .allowed()
        );
        let denied = verdict_for(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repository"}}"#,
        );
        assert_eq!(denied.refusal(), Some(Refusal::Forbidden));
        assert_eq!(
            verdict_for(r#"{"jsonrpc":"2.0","id":1,"method":"resources/read"}"#).refusal(),
            Some(Refusal::Forbidden)
        );
    }

    #[test]
    fn duplicate_keys_are_refused_rather_than_resolved() {
        let body = r#"{"jsonrpc":"2.0","method":"tools/list","method":"tools/call","params":{"name":"delete_repository"}}"#;
        let text = serde_json::from_str::<StrictJson>(body);
        assert!(text.is_err(), "a duplicated method must not parse");
    }

    #[test]
    fn graphql_query_is_allowed_and_mutation_is_not() {
        let rules = GraphqlRules::default();
        assert!(graphql_verdict(&rules, "{ viewer { login } }").allowed());
        assert!(graphql_verdict(&rules, "query Read { repo { id } }").allowed());
        assert_eq!(
            graphql_verdict(&rules, "mutation Delete { deleteRepository(id: 1) { ok } }").refusal(),
            Some(Refusal::Forbidden)
        );
        assert_eq!(
            graphql_verdict(
                &rules,
                "query Read { ...Frag } fragment Frag on Repo { id }"
            )
            .refusal(),
            Some(Refusal::Forbidden)
        );
    }

    #[test]
    fn every_declared_operation_is_checked_not_only_the_named_one() {
        let rules = GraphqlRules::default();
        let document =
            "query Read { repo { id } } mutation Delete { deleteRepository(id: 1) { ok } }";
        assert_eq!(
            graphql_verdict(&rules, document).refusal(),
            Some(Refusal::Forbidden)
        );
        let allowed = GraphqlRules {
            allow_mutations: true,
            ..GraphqlRules::default()
        };
        assert!(graphql_verdict(&allowed, document).allowed());
    }

    #[test]
    fn oversized_and_unparsable_documents_are_refused() {
        let rules = GraphqlRules::default();
        let huge = format!(
            "{{ viewer {{ login {} }} }}",
            "x".repeat(MAX_INSPECTED_BODY_BYTES)
        );
        assert_eq!(
            graphql_verdict(&rules, &huge).refusal(),
            Some(Refusal::TooLarge)
        );
        assert_eq!(
            graphql_verdict(&rules, "{ viewer { login ").refusal(),
            Some(Refusal::Malformed)
        );
        let deep = format!(
            "{{ viewer {} login {} }}",
            "{ a ".repeat(MAX_GRAPHQL_DEPTH + 2),
            "}".repeat(MAX_GRAPHQL_DEPTH + 2)
        );
        assert!(parse_graphql(&deep).is_err());
    }

    #[test]
    fn interception_without_acknowledgement_is_refused() {
        let policy = L7Policy {
            mode: L7Mode::Intercept,
            ..L7Policy::default()
        };
        assert!(effective_mode(&policy).is_err());
        assert!(validate(&policy).is_err());
        let acknowledged = L7Policy {
            mode: L7Mode::Intercept,
            intercept_ack: true,
            ..L7Policy::default()
        };
        assert!(matches!(
            effective_mode(&acknowledged),
            Ok(L7Mode::Intercept)
        ));
    }

    #[test]
    fn a_tunnel_is_never_treated_as_a_plain_request() {
        let policy = L7Policy {
            http: vec![crate::policy::HttpRule {
                host: "api.example.com".into(),
                methods: vec!["POST".into()],
                paths: vec!["/v1/".into()],
            }],
            ..L7Policy::default()
        };
        assert_eq!(
            tunnel_verdict(Some(&policy), "api.example.com").refusal(),
            Some(Refusal::Forbidden)
        );
        assert!(tunnel_verdict(Some(&policy), "other.example.com").allowed());
    }
}
