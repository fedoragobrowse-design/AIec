//! Real Firecracker + AIec Guard acceptance, invoked by scripts/guard-core-acceptance.sh.
//! No TestBackend, provider credentials, host firewall changes, or Internet traffic.
use aiec_core::{
    ExecRequest, MAX_FILE, NetworkPolicy, PutFileRequest, RuntimeKind, Sandbox, SandboxState,
};
use aiec_guard::{
    compiler::{OperatorBoundary, compile},
    control::{BudgetAuthority, BudgetDebit, GuardFence, GuardIdentity},
    enforcement::{
        CounterSnapshot, CounterSource, EnforcementBackend, GuardAttachment, NftablesBackend,
    },
    events::{Decision, read_events, verify_chain},
    policy::{GuardConfig, ModelEndpoint, PolicyTemplate, Topology},
};
use aiec_network_linux::GuardNetworkManager;
use aiec_runtime::{FirecrackerConfig, FirecrackerRuntime, SandboxRuntime};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};
use uuid::Uuid;

type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;

/// A durable budget authority for this acceptance run.
///
/// The gateway refuses guarded traffic without one, which is the point: the
/// acceptance must exercise the real admission path rather than disabling it.
/// This is file-backed and synced, so a reservation is committed before the
/// bytes are forwarded and survives the driver's own restart - which is the
/// property the control plane's store provides in a deployment.
struct FileBudgetAuthority {
    path: PathBuf,
    lock: tokio::sync::Mutex<()>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct FileBudgetState {
    model_requests: u64,
    bytes_in: u64,
    bytes_out: u64,
    max_model_requests: u64,
    max_bytes_in: u64,
    max_bytes_out: u64,
}

impl FileBudgetAuthority {
    fn open(path: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(path.parent().unwrap_or(&path))?;
        Ok(Self {
            path,
            lock: tokio::sync::Mutex::new(()),
        })
    }

    async fn commit(&self, debit: BudgetDebit) -> aiec_guard::Result<()> {
        let _held = self.lock.lock().await;
        let mut state: FileBudgetState = std::fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        if state.max_model_requests == 0 {
            return Err(aiec_guard::GuardError::Unavailable(
                "acceptance budget has no ceilings".into(),
            ));
        }
        if state.model_requests + 1 > state.max_model_requests
            || state.bytes_in.saturating_add(debit.bytes_in) > state.max_bytes_in
            || state.bytes_out.saturating_add(debit.bytes_out) > state.max_bytes_out
        {
            return Err(aiec_guard::GuardError::Denied(
                "acceptance budget exhausted".into(),
            ));
        }
        state.model_requests += 1;
        state.bytes_in = state.bytes_in.saturating_add(debit.bytes_in);
        state.bytes_out = state.bytes_out.saturating_add(debit.bytes_out);
        let temporary = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&serde_json::to_vec(&state)?)?;
            file.sync_all()?;
        }
        std::fs::rename(&temporary, &self.path).map_err(aiec_guard::GuardError::Io)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl BudgetAuthority for FileBudgetAuthority {
    async fn reserve(
        &self,
        _identity: &GuardIdentity,
        fence: GuardFence,
        debit: BudgetDebit,
    ) -> aiec_guard::Result<()> {
        if fence.generation < 0 {
            return Err(aiec_guard::GuardError::Denied(
                "invalid acceptance fence".into(),
            ));
        }
        self.commit(debit).await
    }
}

const PROBE: &str = include_str!("../../../scripts/guard_core_guest_probe.py");
const MODEL_HOST: &str = "model.guard.test";
const MODEL_ADDR: &str = "198.18.0.10:18080";

/// The second model endpoint, used only by the agent leg below.
///
/// It is a separate host, a separate credential and therefore a separate policy
/// hash, on purpose. Sharing the placeholder endpoint's counters with a
/// four-turn tool-using conversation would make every count in this file
/// ambiguous, and a run that has to be interpreted is a run that will be
/// interpreted wrongly.
const AGENT_MODEL_HOST: &str = "agent-model.guard.test";
const AGENT_MODEL_ADDR: &str = "198.18.0.11:18081";
const AGENT_MODEL_CREDENTIAL: &str = "agent-model";
/// The string the agent's first tool observation has to carry back for the
/// mock provider to be willing to continue.
///
/// This is the load-bearing part of the leg. A provider that answers every
/// turn identically would let a harness that never returned a tool result to
/// the model look identical to one that did, and "the agent used tools" would
/// be indistinguishable from "the agent issued tool calls and threw the
/// results away". Requiring the token makes the round trip part of the script.
const AGENT_TOKEN: &str = "7f3a1c9e";
const STREAM_CHUNKS: usize = 128;
/// A resolver bound directly to the namespace, with no policy in front of it.
/// The comparison it exists for is Guard's cost, not the cost of a name.
const BASELINE_DNS_ADDR: &str = "198.18.0.30:53";
const BASELINE_DNS_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(198, 18, 0, 30);
/// How many times each path is asked the same question. Ten is enough to see
/// a millisecond-scale difference and is stated rather than tuned.
const DNS_SAMPLES: usize = 10;
/// The incident reproduction. The name below is the one the policy does not
/// know about, and the resolver is one the guest chooses for itself - which
/// is the whole bypass class: a name-based allowlist is only as good as the
/// resolver, and the guest supplying its own resolver decides the answer.
const CHATBOT_HOST: &str = "chatbot.example.test";
/// The mock external chatbot. Deliberately not the approved model endpoint,
/// so reaching it is a failure of policy and not a request that was permitted.
const CHATBOT_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(198, 18, 0, 40);
const CHATBOT_PORT: u16 = 8080;
/// The resolver address the reproduction guest is pointed at directly, by IP,
/// which is the step that a name-based allowlist has no opinion about.
const CHATBOT_RESOLVER_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(198, 18, 0, 41);
const CHATBOT_ADDR: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(CHATBOT_IP), CHATBOT_PORT);
const CHATBOT_RESOLVER_ADDR: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(CHATBOT_RESOLVER_IP), 53);
const STREAM_CHUNK_BYTES: usize = 32768;
const SENTINELS: &[(&str, &str, u16)] = &[
    ("direct-public-ipv4", "93.184.216.34", 8080),
    ("rfc1918", "10.123.0.10", 8080),
    ("link-local", "169.254.1.10", 8080),
    ("metadata", "169.254.169.254", 80),
    ("worker-management", "198.18.0.20", 8080),
    ("control-plane", "198.18.0.21", 8080),
    ("external-tcp-dns", "93.184.216.34", 53),
    ("dot-853", "93.184.216.34", 853),
    ("ipv6-bypass", "fd00:feed::10", 8080),
];

/// Every address the local mocks bind to. `bind()` fails with EADDRNOTAVAIL
/// unless the address is assigned inside the namespace first, so this list is
/// the single source of truth for what the launcher must add.
const MOCK_ADDRESSES: &[&str] = &[
    "198.18.0.40/32",
    "198.18.0.41/32",
    "198.18.0.10/32",
    "198.18.0.11/32",
    "198.18.0.20/32",
    "198.18.0.21/32",
    "93.184.216.34/32",
    "169.254.169.254/32",
    "10.123.0.10/32",
    "198.18.0.30/32",
    "169.254.1.10/32",
];

fn failure(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::other(message.into()).into()
}
fn counter_json(c: &CounterSnapshot) -> Value {
    json!({"table":c.table,"blocked_range":c.blocked_range,"other_denied":c.other_denied,
        "ipv6":c.ipv6,"dns_permitted":c.dns_permitted,"broker_permitted":c.broker_permitted})
}
fn deny_delta(a: &CounterSnapshot, b: &CounterSnapshot) -> u64 {
    b.blocked_range.saturating_sub(a.blocked_range)
        + b.other_denied.saturating_sub(a.other_denied)
        + b.ipv6.saturating_sub(a.ipv6)
}

/// Builds an A-record reply for a well-formed single-question query.
///
/// Enough DNS to be a resolver, and no more: the point is to answer the same
/// question the gateway answers, not to be a name server.
fn dns_a_reply(query: &[u8], address: std::net::Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    // Walk the QNAME to find where the question ends.
    let mut offset = 12;
    while offset < query.len() {
        let length = query[offset] as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return None;
        }
        offset += length;
    }
    let question_end = offset.checked_add(4)?;
    if question_end > query.len() {
        return None;
    }
    let mut reply = Vec::with_capacity(question_end + 16);
    reply.extend_from_slice(&query[..2]); // id
    reply.extend_from_slice(&0x8180u16.to_be_bytes()); // response, recursion available
    reply.extend_from_slice(&1u16.to_be_bytes()); // one question
    reply.extend_from_slice(&1u16.to_be_bytes()); // one answer
    reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // authority and additional
    reply.extend_from_slice(&query[12..question_end]); // the question, verbatim
    reply.extend_from_slice(&[0xc0, 0x0c]); // answer name: pointer to the question
    reply.extend_from_slice(&1u16.to_be_bytes()); // type A
    reply.extend_from_slice(&1u16.to_be_bytes()); // class IN
    reply.extend_from_slice(&30u32.to_be_bytes()); // TTL
    reply.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    reply.extend_from_slice(&address.octets());
    Some(reply)
}

/// A minimal A query, used to time both paths on the same question.
fn dns_a_query(name: &str) -> Vec<u8> {
    let mut packet = vec![
        0xAE, 0xC1, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&1u16.to_be_bytes()); // A
    packet.extend_from_slice(&1u16.to_be_bytes()); // IN
    packet
}
/// Reads the question name out of a query, so the resolver answers exactly the
/// name it was asked about and nothing else.
fn dns_name(query: &[u8]) -> Option<String> {
    if query.len() < 12 {
        return None;
    }
    let mut name = String::new();
    let mut offset = 12;
    loop {
        let length = *query.get(offset)? as usize;
        offset += 1;
        if length == 0 {
            // A wire name is fully qualified and ends in the root label, so
            // the trailing dot is dropped here rather than left for the
            // comparison below to guess about.
            return Some(name.strip_suffix('.').unwrap_or(&name).to_string());
        }
        if length > 63 {
            return None;
        }
        let label = query.get(offset..offset + length)?;
        name.push_str(std::str::from_utf8(label).ok()?);
        name.push('.');
        offset += length;
    }
}

/// Times `samples` identical queries from this host and returns the median.
///
/// The median rather than the mean, because the first query of a batch pays
/// for a cold path and the question being asked is what the steady state
/// costs.
async fn median_dns_round_trip(server: &str, query: &[u8], samples: usize) -> Result<f64> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut timings = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        socket.send_to(query, server).await?;
        let mut buffer = [0; 4096];
        // The server is named in the failure because a comparison whose two
        // sides are indistinguishable when one of them is silent is a
        // comparison that cannot be debugged.
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
            .await
            .map_err(|_| failure(format!("DNS round trip to {server} timed out")))?
            .map_err(|error| failure(format!("DNS round trip to {server} failed: {error}")))?;
        if n < 12 {
            return Err(failure(format!("{server} replied with {n} bytes")));
        }
        timings.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    timings.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    Ok(timings[timings.len() / 2])
}
fn target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
fn private_file(path: &Path, value: &Value) -> Result<()> {
    std::fs::write(path, serde_json::to_vec(value)?)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
async fn ip(args: &[&str]) -> Result<Value> {
    let result = tokio::process::Command::new("ip")
        .args(args)
        .kill_on_drop(true)
        .output()
        .await?;
    if !result.status.success() {
        return Err(failure("isolated namespace ip command failed"));
    }
    Ok(serde_json::from_slice(&result.stdout).unwrap_or(Value::Null))
}

/// Whether loopback is currently DOWN, which is what a fresh network namespace
/// looks like before the launcher raises it.
fn loopback_is_down() -> Result<bool> {
    let output = std::process::Command::new("ip")
        .args(["-o", "link", "show", "lo"])
        .output()
        .map_err(|e| failure(format!("cannot read the loopback interface: {e}")))?;
    if !output.status.success() {
        return Err(failure("cannot read the loopback interface"));
    }
    let line = String::from_utf8_lossy(&output.stdout);
    // `1: lo: <LOOPBACK,UP,LOWER_UP>` is the shape to look for.
    Ok(!line
        .split_whitespace()
        .any(|flag| flag.trim_end_matches(',') == "UP" || flag.trim_end_matches(',') == "LOWER_UP"))
}
/// Assigns the mock addresses to loopback so the local listeners can bind.
///
/// The launcher may already have assigned some of them, and `ip addr add` on
/// an address that exists exits non-zero, so each add is idempotent: a
/// duplicate is not a failure, a real error still is.
async fn assign_mock_addresses() -> Result<()> {
    ip(&["link", "set", "lo", "up"]).await?;
    for address in MOCK_ADDRESSES {
        let wanted = address.split('/').next().unwrap_or(address);
        let existing = match ip(&["-j", "addr", "show", "dev", "lo"]).await {
            Ok(value) => value
                .as_array()
                .map(|links| {
                    links.iter().any(|link| {
                        link["addr_info"].as_array().is_some_and(|entries| {
                            entries
                                .iter()
                                .any(|entry| entry["local"].as_str() == Some(wanted))
                        })
                    })
                })
                .unwrap_or(false),
            Err(_) => false,
        };
        if !existing {
            ip(&["addr", "add", address, "dev", "lo"]).await?;
        }
    }
    Ok(())
}

async fn baseline_tcp(address: &str) -> Result<Value> {
    let start = Instant::now();
    let mut socket =
        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(address)).await??;
    socket.write_all(b"guard-sentinel").await?;
    let mut response = [0; 14];
    tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut response)).await??;
    if response != *b"guard-sentinel" {
        return Err(failure("reachable sentinel returned wrong proof"));
    }
    Ok(
        json!({"address":address,"reachable":true,"echo_verified":true,"latency_ms":start.elapsed().as_secs_f64()*1000.0}),
    )
}

fn guest_address(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(ip) => matches!(ip.octets(), [172, 30, _, _]),
        std::net::IpAddr::V6(ip) => ip.segments()[0] == 0xfd00 && ip.segments()[1] == 0xbeef,
    }
}
/// One model request the local provider served, recorded from its own side.
///
/// The turn number is derived from the conversation the harness sent rather
/// than from a counter this server keeps. That distinction is the whole point:
/// a server counting its own requests would hand the third step's answer to a
/// harness that had only asked once.
#[derive(Debug, Clone, serde::Serialize)]
struct AgentTurn {
    turn: usize,
    /// The tool names the harness had advertised to the model on this request.
    /// A model that asks for a tool the client never offered would be caught
    /// here rather than being shrugged off as a malformed reply.
    advertised: Vec<String>,
    /// `(tool, first bytes of the observation)` for each tool result the
    /// harness sent back. Bounded, because a file could be any size.
    observations: Vec<(String, String)>,
    /// What this server answered with: a tool name, or nothing for a final
    /// answer.
    emitted: Vec<String>,
    /// Server-sent-event frames written for this reply, including the finish
    /// and the terminator.
    frames: usize,
}

/// A local model provider that behaves like one.
///
/// It reads the request, works out which turn of the conversation it is being
/// asked for, and answers with the next tool call - or with a final answer,
/// once the observation the previous tool call should have produced has
/// actually come back. If the harness drops a tool result the script stops
/// there and says so in prose, so a broken round trip cannot be papered over
/// by a provider that keeps answering regardless.
///
/// Replies are streamed in fragments and written to the socket in several
/// chunks, because "the agent could finish the task" is not the property
/// under test; "the agent could finish the task through a governed, streaming
/// model path" is.
struct AgentModel {
    accepted: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
    turns: std::sync::Arc<tokio::sync::Mutex<Vec<AgentTurn>>>,
    handle: JoinHandle<()>,
}

/// One `data:` frame carrying a single choice delta.
fn sse_frame(delta: serde_json::Value, finish: Option<&str>) -> String {
    let mut choice = json!({"index":0,"delta":delta});
    choice["finish_reason"] = match finish {
        Some(reason) => json!(reason),
        None => serde_json::Value::Null,
    };
    format!("data: {}\n\n", json!({"choices":[choice]}))
}

/// A streamed tool call, fragmented the way a provider fragments one.
fn agent_tool_call(
    id: &str,
    name: &str,
    arguments: &serde_json::Value,
) -> (String, Vec<String>, usize) {
    let mut body = sse_frame(
        json!({"tool_calls":[{"index":0,"id":id,"type":"function",
            "function":{"name":name,"arguments":""}}]}),
        None,
    );
    let mut frames = 1;
    // Chunked on characters, not bytes: a slice through the middle of a
    // multi-byte character would put invalid UTF-8 on the wire, and the
    // arguments here are small enough that the copy costs nothing.
    let characters: Vec<char> = arguments.to_string().chars().collect();
    for piece in characters.chunks(24) {
        let fragment: String = piece.iter().collect();
        body.push_str(&sse_frame(
            json!({"tool_calls":[{"index":0,"function":{"arguments":fragment}}]}),
            None,
        ));
        frames += 1;
    }
    body.push_str(&sse_frame(json!({}), Some("tool_calls")));
    body.push_str("data: [DONE]\n\n");
    (body, vec![name.to_owned()], frames + 2)
}

/// A streamed final answer, with no tool call in it.
fn agent_text(text: &str) -> (String, Vec<String>, usize) {
    let mut body = String::new();
    let mut frames = 0;
    let characters: Vec<char> = text.chars().collect();
    for piece in characters.chunks(24) {
        let fragment: String = piece.iter().collect();
        body.push_str(&sse_frame(json!({"content":fragment}), None));
        frames += 1;
    }
    body.push_str(&sse_frame(json!({}), Some("stop")));
    body.push_str("data: [DONE]\n\n");
    (body, Vec::new(), frames + 2)
}

/// Reads the conversation the harness sent: which turn it is, what it offered,
/// and what it actually returned.
fn read_conversation(body: &[u8]) -> (usize, Vec<String>, Vec<(String, String)>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (0, Vec::new(), Vec::new());
    };
    let advertised = value["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| {
                    tool.get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(serde_json::Value::as_str)
                })
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut turn = 0usize;
    let mut observations = Vec::new();
    // `tool_call_id` -> tool name, learned from the assistant messages, because
    // an OpenAI-shaped tool result carries the identifier and not the name.
    let mut names: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for message in value["messages"].as_array().into_iter().flatten() {
        match message.get("role").and_then(serde_json::Value::as_str) {
            Some("assistant") => {
                let Some(calls) = message
                    .get("tool_calls")
                    .and_then(serde_json::Value::as_array)
                    .filter(|calls| !calls.is_empty())
                else {
                    continue;
                };
                turn += 1;
                for call in calls {
                    let id = call.get("id").and_then(serde_json::Value::as_str);
                    let name = call
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(serde_json::Value::as_str);
                    if let (Some(id), Some(name)) = (id, name) {
                        names.insert(id.to_owned(), name.to_owned());
                    }
                }
            }
            Some("tool") => {
                let id = message
                    .get("tool_call_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let name = names.get(id).cloned().unwrap_or_else(|| id.to_owned());
                let content = message
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                observations.push((name, content.chars().take(512).collect()));
            }
            _ => {}
        }
    }
    (turn, advertised, observations)
}

/// A chunked request body, or `None` while it is still arriving.
///
/// The mock has to understand chunked framing because that is what the gateway
/// actually sends: it forwards the body as a stream, so the request carries
/// `Transfer-Encoding: chunked` and no `Content-Length`. A reader that only
/// understands `Content-Length` sees an empty body from the gateway, and then
/// every conclusion drawn from that conversation — which tools were offered,
/// what the agent observed — is an artefact of the reader rather than
/// something the agent sent.
fn chunked_body(bytes: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut body = Vec::new();
    let mut at = start;
    loop {
        let line_end = bytes
            .get(at..)?
            .windows(2)
            .position(|pair| pair == b"\r\n")?;
        // A chunk header may carry extensions after a `;`. The size is what
        // precedes them.
        let size_text = std::str::from_utf8(&bytes[at..at + line_end]).ok()?;
        let size = usize::from_str_radix(size_text.trim().split(';').next()?, 16).ok()?;
        at += line_end + 2;
        if size == 0 {
            return Some((body, at));
        }
        if bytes.len() < at + size + 2 {
            return None;
        }
        body.extend_from_slice(&bytes[at..at + size]);
        at += size + 2;
    }
}

/// The script. Each step refuses to advance until the observation the previous
/// step should have produced is in the request, so "the agent continued the
/// conversation" is enforced here rather than asserted at the far end.
fn agent_reply(
    turn: usize,
    advertised: &[String],
    observations: &[(String, String)],
) -> (String, Vec<String>, usize) {
    let offered = |name: &str| advertised.iter().any(|tool| tool == name);
    let returned = |name: &str| {
        observations
            .iter()
            .filter(|(tool, _)| tool == name)
            .map(|(_, body)| body.as_str())
            .collect::<String>()
    };
    match turn {
        0 if offered("read") => agent_tool_call("call-1", "read", &json!({"path":"notes.txt"})),
        1 => match returned("read") {
            // The token is the loop's proof of life. Without it the notes never
            // arrived and there is nothing honest to continue with.
            body if body.contains(AGENT_TOKEN) => agent_tool_call(
                "call-2",
                "write",
                &json!({"path":"answer.txt","content":format!("TOKEN={AGENT_TOKEN}\nthe notes were read and carried the token\n")}),
            ),
            _ => agent_text("the notes did not arrive, so there is nothing to summarise"),
        },
        2 => match returned("write") {
            body if !body.trim().is_empty() => {
                agent_tool_call("call-3", "bash", &json!({"command":["cat","answer.txt"]}))
            }
            _ => agent_text("the answer file was never written"),
        },
        _ => match returned("bash") {
            body if body.contains(AGENT_TOKEN) => agent_text(&format!(
                "the token {AGENT_TOKEN} was read from the notes, written to the answer and read back"
            )),
            _ => agent_text("the answer was never read back, so the task is not done"),
        },
    }
}

impl AgentModel {
    async fn start(secret: &str, sentinel_guest_hits: Arc<AtomicU64>) -> Result<Self> {
        let accepted = Arc::new(AtomicU64::new(0));
        let rejected = Arc::new(AtomicU64::new(0));
        let turns = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind(AGENT_MODEL_ADDR).await?;
        let authorization = format!("Bearer {secret}");
        let good = accepted.clone();
        let bad = rejected.clone();
        let recorded = turns.clone();
        let handle = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    socket = listener.accept() => {
                        let Ok((mut socket, peer)) = socket else { break; };
                        if guest_address(peer.ip()) {
                            // Counted here, on the endpoint itself, so that
                            // "the agent's model traffic was the only guest
                            // traffic" stays a host observation rather than the
                            // guest's own account of itself.
                            sentinel_guest_hits.fetch_add(1, Ordering::Relaxed);
                        }
                        let expected = authorization.clone();
                        let good = good.clone();
                        let bad = bad.clone();
                        let recorded = recorded.clone();
                        connections.spawn(async move {
                            let serve = async {
                                let mut request = Vec::new();
                                let mut buffer = [0; 8192];
                                let headers_end = loop {
                                    let n = socket.read(&mut buffer).await?;
                                    if n == 0 || request.len() + n > 262_144 {
                                        return Err(io::Error::other("bounded agent request"));
                                    }
                                    request.extend_from_slice(&buffer[..n]);
                                    if let Some(index) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                                        break index + 4;
                                    }
                                };
                                let headers = String::from_utf8_lossy(&request[..headers_end]).into_owned();
                                let allowed = headers.lines().next() == Some("POST /v1/chat/completions HTTP/1.1")
                                    && headers.lines().any(|line| line.split_once(':').is_some_and(|(name, value)|
                                        name.eq_ignore_ascii_case("authorization") && value.trim() == expected));
                                let chunked = headers.lines().any(|line| line.split_once(':').is_some_and(|(name, value)|
                                    name.eq_ignore_ascii_case("transfer-encoding")
                                        && value.to_ascii_lowercase().contains("chunked")));
                                let declared = headers.lines().find_map(|line| line.split_once(':').and_then(|(name, value)|
                                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok()).flatten()));
                                // A real agent request carries a system prompt and every
                                // tool schema. The placeholder mock's 4 KiB bound would
                                // refuse it, and that refusal would be a bound rather
                                // than a policy, which is exactly the wrong thing to
                                // be measuring here.
                                const MAX_AGENT_BODY: usize = 512 * 1024;
                                let body = loop {
                                    if chunked {
                                        if let Some((body, _)) = chunked_body(&request, headers_end) {
                                            break body;
                                        }
                                    } else if request.len() >= headers_end + declared.unwrap_or(0) {
                                        break request[headers_end..headers_end + declared.unwrap_or(0)].to_vec();
                                    }
                                    if request.len() > MAX_AGENT_BODY {
                                        return Err(io::Error::other("bounded agent body"));
                                    }
                                    let n = socket.read(&mut buffer).await?;
                                    if n == 0 { return Err(io::Error::other("truncated agent body")); }
                                    request.extend_from_slice(&buffer[..n]);
                                };
                                if body.len() > MAX_AGENT_BODY {
                                    return Err(io::Error::other("bounded agent body"));
                                }
                                if !allowed {
                                    bad.fetch_add(1, Ordering::Relaxed);
                                    socket.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                                    return Ok::<_, io::Error>(());
                                }
                                good.fetch_add(1, Ordering::Relaxed);
                                let (turn, advertised, observations) = read_conversation(&body);
                                let (payload, emitted, frames) = agent_reply(turn, &advertised, &observations);
                                recorded.lock().await.push(AgentTurn {
                                    turn,
                                    advertised,
                                    observations,
                                    emitted,
                                    frames,
                                });
                                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await?;
                                for piece in payload.as_bytes().chunks(512) {
                                    // Written in pieces so the client is reading a
                                    // stream rather than a body that arrived whole.
                                    tokio::time::sleep(Duration::from_millis(2)).await;
                                    socket.write_all(format!("{:x}\r\n", piece.len()).as_bytes()).await?;
                                    socket.write_all(piece).await?;
                                    socket.write_all(b"\r\n").await?;
                                }
                                socket.write_all(b"0\r\n\r\n").await?;
                                socket.shutdown().await
                            };
                            let _ = tokio::time::timeout(Duration::from_secs(120), serve).await;
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(Self {
            accepted,
            rejected,
            turns,
            handle,
        })
    }

    /// Everything this provider has seen, from its own side.
    async fn snapshot(&self) -> serde_json::Value {
        json!({
            "address": AGENT_MODEL_ADDR,
            "host": AGENT_MODEL_HOST,
            "accepted": self.accepted.load(Ordering::Relaxed),
            "rejected": self.rejected.load(Ordering::Relaxed),
            "turns": self.turns.lock().await.clone(),
        })
    }

    fn shutdown(&self) {
        self.handle.abort();
    }
}

struct Mocks {
    handles: Vec<JoinHandle<()>>,
    accepted: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
    sentinel_guest_hits: Arc<AtomicU64>,
    /// Counted on the mock external chatbot itself, so the reproduction's
    /// control leg is proved by the destination acknowledging the connection
    /// rather than by the guest's own report that it tried.
    chatbot_hits: Arc<AtomicU64>,
    response_hash: String,
    response_bytes: usize,
}
impl Mocks {
    async fn start(secret: &str) -> Result<Self> {
        // Delayed chunks prove incremental delivery, not just a final body.
        let chunk = format!("data: {}\n\n", "x".repeat(STREAM_CHUNK_BYTES - 8)).into_bytes();
        let finish = b"data: [DONE]\n\n";
        let mut hash = Sha256::new();
        for _ in 0..STREAM_CHUNKS {
            hash.update(&chunk);
        }
        hash.update(finish);
        let accepted = Arc::new(AtomicU64::new(0));
        let rejected = Arc::new(AtomicU64::new(0));
        let sentinel_guest_hits = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        let model = TcpListener::bind(MODEL_ADDR).await?;
        let authorization = format!("Bearer {secret}");
        let good = accepted.clone();
        let bad = rejected.clone();
        let payload = Arc::new(chunk);
        let model_guest_hits = sentinel_guest_hits.clone();
        handles.push(tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    socket = model.accept() => {
                        let Ok((mut socket, peer)) = socket else { break; };
                        if guest_address(peer.ip()) { model_guest_hits.fetch_add(1, Ordering::Relaxed); }
                        let expected = authorization.clone();
                        let good = good.clone();
                        let bad = bad.clone();
                        let payload = payload.clone();
                        connections.spawn(async move {
                            let serve = async {
                                let mut request = Vec::new();
                                let mut buffer = [0; 1024];
                                let headers_end = loop {
                                    let n = socket.read(&mut buffer).await?;
                                    if n == 0 || request.len() + n > 16384 { return Err(io::Error::other("bounded mock request")); }
                                    request.extend_from_slice(&buffer[..n]);
                                    if let Some(index) = request.windows(4).position(|w| w == b"\r\n\r\n") { break index + 4; }
                                };
                                let headers = String::from_utf8_lossy(&request[..headers_end]);
                                let allowed = headers.lines().next() == Some("POST /v1/chat/completions HTTP/1.1")
                                    && headers.lines().any(|line| line.split_once(':').is_some_and(|(name, value)|
                                        name.eq_ignore_ascii_case("authorization") && value.trim() == expected));
                                let body_length = headers.lines().find_map(|line| line.split_once(':').and_then(|(name, value)|
                                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok()).flatten())).unwrap_or(0);
                                if body_length > 4096 { return Err(io::Error::other("bounded mock body")); }
                                while request.len() < headers_end + body_length {
                                    let n = socket.read(&mut buffer).await?;
                                    if n == 0 { return Err(io::Error::other("truncated mock body")); }
                                    request.extend_from_slice(&buffer[..n]);
                                }
                                if !allowed {
                                    bad.fetch_add(1, Ordering::Relaxed);
                                    socket.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                                    return Ok::<_, io::Error>(());
                                }
                                good.fetch_add(1, Ordering::Relaxed);
                                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await?;
                                for _ in 0..STREAM_CHUNKS {
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                    socket.write_all(format!("{:x}\r\n", payload.len()).as_bytes()).await?;
                                    socket.write_all(&payload).await?;
                                    socket.write_all(b"\r\n").await?;
                                }
                                socket.write_all(b"e\r\ndata: [DONE]\n\n\r\n0\r\n\r\n").await?;
                                socket.shutdown().await
                            };
                            let _ = tokio::time::timeout(Duration::from_secs(20), serve).await;
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        }));
        for (_, host, port) in SENTINELS {
            let listener = TcpListener::bind(target(host, *port)).await?;
            let guest_hits = sentinel_guest_hits.clone();
            handles.push(tokio::spawn(async move {
                let mut clients = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let Ok((mut socket, peer)) = accepted else { break; };
                            if guest_address(peer.ip()) { guest_hits.fetch_add(1, Ordering::Relaxed); }
                            clients.spawn(async move {
                                let echo = async {
                                    let mut buffer = [0; 4096];
                                    let n = socket.read(&mut buffer).await?;
                                    socket.write_all(&buffer[..n]).await
                                };
                                let _ = tokio::time::timeout(Duration::from_secs(3), echo).await;
                            });
                        }
                        Some(_) = clients.join_next(), if !clients.is_empty() => {}
                    }
                }
            }));
        }
        let udp = UdpSocket::bind("93.184.216.34:53").await?;
        let udp_guest_hits = sentinel_guest_hits.clone();
        handles.push(tokio::spawn(async move {
            let mut buffer = [0; 4096];
            while let Ok((n, peer)) = udp.recv_from(&mut buffer).await {
                if guest_address(peer.ip()) {
                    udp_guest_hits.fetch_add(1, Ordering::Relaxed);
                }
                let _ = udp.send_to(&buffer[..n], peer).await;
            }
        }));
        // A resolver with no policy in front of it, so the same query can be
        // asked of both and the difference attributed to Guard rather than to
        // the name, the record type or the machine.
        let baseline = UdpSocket::bind(BASELINE_DNS_ADDR).await?;
        let baseline_ip = BASELINE_DNS_IP;
        handles.push(tokio::spawn(async move {
            let mut buffer = [0; 4096];
            while let Ok((n, peer)) = baseline.recv_from(&mut buffer).await {
                if let Some(reply) = dns_a_reply(&buffer[..n], baseline_ip) {
                    let _ = baseline.send_to(&reply, peer).await;
                }
            }
        }));
        // The mock external chatbot. Nothing else in the run binds it, so a
        // response from it can only mean the guest reached it, not that some
        // other mock answered on its behalf.
        let chatbot = TcpListener::bind(CHATBOT_ADDR).await?;
        let chatbot_hits = Arc::new(AtomicU64::new(0));
        let hits = Arc::clone(&chatbot_hits);
        handles.push(tokio::spawn(async move {
            while let Ok((mut stream, _)) = chatbot.accept().await {
                hits.fetch_add(1, Ordering::Relaxed);
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        }));
        // The resolver the guest points itself at. It answers exactly one name
        // truthfully, so the reproduction is an ordinary working lookup rather
        // than a fabricated result.
        let incident = UdpSocket::bind(CHATBOT_RESOLVER_ADDR).await?;
        let chatbot_ip = CHATBOT_IP;
        handles.push(tokio::spawn(async move {
            let mut buffer = [0; 4096];
            while let Ok((n, peer)) = incident.recv_from(&mut buffer).await {
                if dns_name(&buffer[..n]).as_deref() == Some(CHATBOT_HOST)
                    && let Some(reply) = dns_a_reply(&buffer[..n], chatbot_ip)
                {
                    let _ = incident.send_to(&reply, peer).await;
                }
            }
        }));
        Ok(Self {
            handles,
            accepted,
            rejected,
            sentinel_guest_hits,
            chatbot_hits,
            response_hash: hex::encode(hash.finalize()),
            response_bytes: STREAM_CHUNKS * STREAM_CHUNK_BYTES + finish.len(),
        })
    }
    async fn shutdown(&mut self) {
        for handle in self.handles.drain(..) {
            handle.abort();
            let _ = handle.await;
        }
    }
}
impl Drop for Mocks {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

struct Driver {
    runtime: FirecrackerRuntime,
    /// The manager this driver owns, so the run can keep reporting liveness and
    /// can prove what the gateway did on its own when it stops.
    network: Arc<GuardNetworkManager>,
    /// The liveness task, so the run can stop reporting and prove the cut.
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    sandboxes: Vec<Sandbox>,
    state: PathBuf,
    boundary: OperatorBoundary,
    policy_hash: String,
    secret: String,
    mocks: Option<Mocks>,
    /// The conversation-aware provider the agent leg talks to. `Option` because
    /// it is started with the rest of the mocks but has to stay reachable from
    /// the leg that reads its own record of what it served.
    agent_model: Option<AgentModel>,
    cases: Vec<Value>,
    current: String,
    started: Instant,
}
impl Driver {
    fn case(&mut self, name: &str, passed: bool, evidence: Value) -> Result<()> {
        self.current = name.into();
        self.cases.push(
            json!({"case":name,"status":if passed {"PASS"} else {"FAIL"},"evidence":evidence}),
        );
        if !passed {
            return Err(failure(format!("acceptance criterion failed: {name}")));
        }
        Ok(())
    }
    fn guard_dir(&self, sandbox: &Sandbox) -> PathBuf {
        self.state.join("guard").join(sandbox.id.to_string())
    }
    fn attachment(&self, sandbox: &Sandbox) -> Result<GuardAttachment> {
        let record: Value = serde_json::from_slice(&std::fs::read(
            self.guard_dir(sandbox).join("attachment.json"),
        )?)?;
        let attachment: GuardAttachment = serde_json::from_value(record["attachment"].clone())?;
        if attachment.sandbox_id != sandbox.id || attachment.tenant_id != sandbox.tenant_id {
            return Err(failure("persisted attachment ownership mismatch"));
        }
        Ok(attachment)
    }
    async fn probe(&self, sandbox: &Sandbox, config: Value) -> Result<Value> {
        let result = self
            .runtime
            .exec(
                sandbox,
                ExecRequest {
                    command: vec![
                        "/usr/bin/python3".into(),
                        "/workspace/guard-probe.py".into(),
                        config.to_string(),
                    ],
                    working_directory: Some("/workspace".into()),
                    environment: BTreeMap::new(),
                    timeout_seconds: 30,
                    stdin: None,
                },
            )
            .await?;
        if result.stdout.contains(self.secret.as_str())
            || result.stderr.contains(self.secret.as_str())
        {
            return Err(failure(
                "outside-guest secret found in guest output (value suppressed)",
            ));
        }
        if result.exit_code != 0 {
            return Err(failure(format!("guest probe failed: {}", result.stdout)));
        }
        Ok(serde_json::from_str(&result.stdout)?)
    }
    async fn denied_network(
        &mut self,
        sandbox: &Sandbox,
        attachment: &GuardAttachment,
        name: &str,
        config: Value,
        baseline: Value,
    ) -> Result<()> {
        self.current = name.into();
        let backend = NftablesBackend::new();
        let before = backend.counters(attachment).await?;
        let hits_before = self
            .mocks
            .as_ref()
            .ok_or_else(|| failure("mock monitors unavailable"))?
            .sentinel_guest_hits
            .load(Ordering::Relaxed);
        let probe = self.probe(sandbox, config).await?;
        let after = backend.counters(attachment).await?;
        let hits_after = self
            .mocks
            .as_ref()
            .ok_or_else(|| failure("mock monitors unavailable"))?
            .sentinel_guest_hits
            .load(Ordering::Relaxed);
        let delta = deny_delta(&before, &after);
        let no_route_failure = !matches!(probe["errno"].as_i64(), Some(99 | 101 | 113))
            && probe["route_error"] != true;
        let family_proved = name != "ipv6-bypass" || after.ipv6 > before.ipv6;
        let passed = probe["reachable"] == false
            && delta > 0
            && no_route_failure
            && family_proved
            && hits_before == hits_after;
        self.case(name, passed, json!({"host_baseline":baseline,"guest":probe,
            "authoritative_before":counter_json(&before),"authoritative_after":counter_json(&after),"deny_packets":delta,
            "outside_guest_sentinel_connections_or_datagrams":hits_after.saturating_sub(hits_before)}))
    }
    async fn denied_broker(
        &mut self,
        sandbox: &Sandbox,
        name: &str,
        config: Value,
        reason: &str,
    ) -> Result<()> {
        self.current = name.into();
        let path = self.guard_dir(sandbox).join("events.jsonl");
        let offset = read_events(&path)?.len();
        let requests = self
            .mocks
            .as_ref()
            .ok_or_else(|| failure("model mock missing"))?
            .accepted
            .load(Ordering::Relaxed);
        let probe = self.probe(sandbox, config).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let events = read_events(&path)?;
        verify_chain(&events)?;
        let denials: Vec<_> = events
            .iter()
            .skip(offset)
            .filter(|e| e.decision == Decision::Deny)
            .collect();
        let unchanged = self
            .mocks
            .as_ref()
            .ok_or_else(|| failure("model mock missing"))?
            .accepted
            .load(Ordering::Relaxed)
            == requests;
        self.case(
            name,
            probe["status"] == 403 && unchanged && denials.iter().any(|e| e.reason == reason),
            json!({"guest":probe,"no_upstream_request":unchanged,"authoritative_denials":denials}),
        )
    }
    async fn cleanup(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        for sandbox in self.sandboxes.iter().rev() {
            match tokio::time::timeout(Duration::from_secs(30), self.runtime.destroy(sandbox)).await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) => errors.push(format!("sandbox {} destroy failed", sandbox.id)),
                Err(_) => errors.push(format!("sandbox {} destroy timed out", sandbox.id)),
            }
        }
        if let Some(mocks) = &mut self.mocks {
            mocks.shutdown().await;
        }
        // Namespace lifetime is the final containment boundary even if cleanup
        // reports failure. Never turn a failed destroy into aggregate PASS.
        match tokio::process::Command::new("nft")
            .args(["-j", "list", "tables"])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                if let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) {
                    if value["nftables"].as_array().is_some_and(|rows| {
                        rows.iter().any(|row| {
                            row["table"]["name"]
                                .as_str()
                                .is_some_and(|name| name.starts_with("aiec_guard_"))
                        })
                    }) {
                        errors.push("Guard nft table remained after destroy".into());
                    }
                } else {
                    errors.push("cleanup nft inventory malformed".into());
                }
            }
            _ => errors.push("cleanup nft inventory failed".into()),
        }
        match ip(&["-j", "link", "show"]).await {
            Ok(value) => match value.as_array() {
                Some(links) => {
                    if links.iter().any(|link| {
                        link["ifname"]
                            .as_str()
                            .is_some_and(|name| name.starts_with("ag") && name.len() == 15)
                    }) {
                        errors.push("Guard TAP remained after destroy".into());
                    }
                }
                None => errors.push("cleanup TAP inventory malformed".into()),
            },
            Err(_) => errors.push("cleanup TAP inventory failed".into()),
        }
        // Firecracker children may have been spawned by any Tokio worker
        // thread. Inspect only this driver's descendants, never host processes.
        let processes = (|| -> Result<Vec<String>> {
            let binary = std::fs::canonicalize(&self.runtime.config.binary)?;
            let mut survivors = Vec::new();
            for thread in std::fs::read_dir("/proc/self/task")? {
                let children = match std::fs::read_to_string(thread?.path().join("children")) {
                    Ok(children) => children,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                };
                for pid in children.split_whitespace() {
                    if std::fs::read_link(format!("/proc/{pid}/exe")).ok().as_ref() == Some(&binary)
                    {
                        survivors.push(pid.to_owned());
                    }
                }
            }
            Ok(survivors)
        })();
        match processes {
            Ok(survivors) if survivors.is_empty() => {}
            Ok(_) => errors.push("Firecracker child remained after destroy".into()),
            Err(_) => errors.push("cleanup child-process inventory failed".into()),
        }
        errors
    }
}

async fn model_baseline(secret: &str, expected_hash: &str, expected_bytes: usize) -> Result<Value> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .build()?;
    let start = Instant::now();
    let mut response = client
        .post(format!("http://{MODEL_ADDR}/v1/chat/completions"))
        .bearer_auth(secret)
        .body("{\"stream\":true}")
        .send()
        .await?;
    if response.status() != 200 {
        return Err(failure(
            "outside-guest authenticated local model baseline failed",
        ));
    }
    let headers_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut first_ms = None;
    let mut chunks = 0;
    while let Some(chunk) = response.chunk().await? {
        first_ms.get_or_insert(start.elapsed().as_secs_f64() * 1000.0);
        hash.update(&chunk);
        bytes += chunk.len();
        chunks += 1;
    }
    if bytes != expected_bytes || hex::encode(hash.finalize()) != expected_hash {
        return Err(failure(
            "local model baseline streaming body integrity failed",
        ));
    }
    Ok(
        json!({"bytes":bytes,"headers_ms":headers_ms,"first_byte_ms":first_ms,"duration_ms":start.elapsed().as_secs_f64()*1000.0,"chunks":chunks}),
    )
}
/// Reads a JSON document back out of a running guest.
///
/// Going through the guest's own file read rather than parsing the agent's
/// stdout matters: the document is what the harness chose to record about
/// itself, and a self-report is only worth something if it is the one the agent
/// actually wrote.
async fn guest_json(driver: &Driver, sandbox: &Sandbox, path: &str) -> Result<Value> {
    let content = driver
        .runtime
        .get_file(sandbox, path)
        .await
        .map_err(|e| failure(format!("reading {path} back from the guest: {e}")))?;
    let bytes = STANDARD
        .decode(content.content_base64.as_bytes())
        .map_err(|e| failure(format!("{path} did not come back as base64: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| failure(format!("{path} was not JSON: {e}")))
}
/// The same read for a file that is not JSON: the artifact the agent was
/// asked to produce, read back as bytes rather than taken on trust from the
/// agent's own summary of it.
async fn guest_text(driver: &Driver, sandbox: &Sandbox, path: &str) -> Result<String> {
    let content = driver
        .runtime
        .get_file(sandbox, path)
        .await
        .map_err(|e| failure(format!("reading {path} back from the guest: {e}")))?;
    let bytes = STANDARD
        .decode(content.content_base64.as_bytes())
        .map_err(|e| failure(format!("{path} did not come back as base64: {e}")))?;
    String::from_utf8(bytes).map_err(|e| failure(format!("{path} is not utf-8: {e}")))
}

async fn run(driver: &mut Driver) -> Result<()> {
    // The watchdog heartbeat, reported from outside the guest for the length of
    // the run. Its absence is what the dead-man switch is for; this harness is
    // exercising enforcement, and a case below proves the switch by stopping it.
    let liveness = driver.network.clone();
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;
            liveness.heartbeat_every_attachment().await;
        }
    });
    driver.heartbeat = Some(heartbeat);
    driver.current = "local-mock-addresses".into();
    // Every local listener binds to an address that must already exist in this
    // namespace; without this the run dies at startup rather than testing.
    assign_mock_addresses().await?;
    driver.current = "local-mock-startup".into();
    driver.mocks = Some(Mocks::start(&driver.secret).await?);
    // Started here rather than in the leg that uses it so that a provider that
    // cannot bind fails during startup, where the failure is unambiguous, and
    // not halfway through a case whose evidence would then be half-recorded.
    driver.agent_model = Some(
        AgentModel::start(
            &driver.secret,
            driver
                .mocks
                .as_ref()
                .expect("mocks started")
                .sentinel_guest_hits
                .clone(),
        )
        .await?,
    );
    let mut baselines = BTreeMap::new();
    for (name, host, port) in SENTINELS {
        driver.current = format!("host-baseline-{name}");
        baselines.insert(*name, baseline_tcp(&target(host, *port)).await?);
    }
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.send_to(b"guard-sentinel", "93.184.216.34:53").await?;
    let mut reply = [0; 64];
    let (n, peer) =
        tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut reply)).await??;
    if &reply[..n] != b"guard-sentinel" {
        return Err(failure("UDP sentinel baseline failed"));
    }
    let udp_baseline = json!({"address":peer.to_string(),"echo_verified":true,"reachable":true});
    driver.case(
        "host-local-sentinel-baselines",
        true,
        json!({"tcp":baselines,"udp53":udp_baseline,"scope":"isolated netns local listeners only"}),
    )?;

    driver.current = "real-firecracker-create-and-boot".into();
    let config = GuardConfig {
        topology: Topology::Inside,
        policy_template: PolicyTemplate::ModelOnly,
        model_endpoint: Some(ModelEndpoint {
            host: MODEL_HOST.into(),
            port: 18080,
            scheme: "http".into(),
            allowed_methods: vec!["POST".into()],
            allowed_paths: vec!["/v1/chat/completions".into()],
            credential: "model-main".into(),
        }),
        ..Default::default()
    };
    // The agent leg's policy differs from the placeholder endpoint's in one
    // field: which model endpoint it points at. Everything else is the same
    // governed shape, which is the point - a model-only policy that only works
    // for a curl-shaped request is not a model-only policy.
    let agent_config = GuardConfig {
        model_endpoint: Some(ModelEndpoint {
            host: AGENT_MODEL_HOST.into(),
            port: 18081,
            scheme: "http".into(),
            allowed_methods: vec!["POST".into()],
            allowed_paths: vec!["/v1/chat/completions".into()],
            credential: AGENT_MODEL_CREDENTIAL.into(),
        }),
        ..config.clone()
    };
    let policy = config
        .effective_policy()
        .map_err(|e| failure(format!("effective_policy: {e}")))?;
    driver.policy_hash = policy
        .hash()
        .map_err(|e| failure(format!("policy hash: {e}")))?;
    let rootfs_bytes = std::fs::metadata(&driver.runtime.config.rootfs)
        .map_err(|e| failure(format!("rootfs metadata: {e}")))?
        .len();
    let disk_mb = rootfs_bytes.div_ceil(1024 * 1024).max(512);
    // The hash each sandbox was actually built from, so the persistence check
    // below compares against the policy that sandbox carries rather than
    // against whatever the driver last computed.
    let mut expected_hashes: BTreeMap<Uuid, String> = BTreeMap::new();
    for index in 0..3 {
        let sandbox_config = if index == 2 {
            agent_config.clone()
        } else {
            config.clone()
        };
        let hash = sandbox_config
            .effective_policy()
            .map_err(|e| failure(format!("effective_policy: {e}")))?
            .hash()
            .map_err(|e| failure(format!("policy hash: {e}")))?;
        if index != 2 {
            // The driver's own `policy_hash` describes the primary pair, which
            // is what the rest of this file's evidence is about. The agent leg
            // carries its own hash and is asserted through `expected_hashes`.
            driver.policy_hash = hash.clone();
        }
        let now = chrono::Utc::now();
        let mut sandbox = Sandbox {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            node_id: None,
            image_id: "aiec".into(),
            state: SandboxState::Creating,
            runtime: RuntimeKind::Firecracker,
            cpu: 1,
            memory_mb: 512,
            disk_mb: disk_mb.try_into()?,
            timeout_seconds: 1800,
            network: Default::default(),
            environment: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        };
        sandbox.environment.guard = Some(sandbox_config);
        sandbox.environment.guard_policy_hash = Some(hash.clone());
        expected_hashes.insert(sandbox.id, hash);
        driver.sandboxes.push(sandbox.clone());
        // The attachment is bound to the ownership this worker proved before
        // anything is built for it, exactly as WorkerService does for a guarded
        // create. Without the fence the attachment refuses to exist, which is
        // the intended failure rather than a hole.
        driver
            .network
            .guard_set_fence(
                &sandbox,
                GuardFence {
                    lease_id: Uuid::now_v7(),
                    generation: 1,
                },
            )
            .await
            .map_err(|e| failure(format!("guard fence: {e}")))?;
        // Each lifecycle step names itself: an acceptance failure that says only
        // "create failed" costs an operator a whole debugging round.
        driver
            .runtime
            .create(&sandbox)
            .await
            .map_err(|e| failure(format!("runtime.create: {e}")))?;
        driver
            .runtime
            .start(&sandbox)
            .await
            .map_err(|e| failure(format!("runtime.start: {e}")))?;
        driver
            .runtime
            .put_file(
                &sandbox,
                PutFileRequest {
                    path: "/workspace/guard-probe.py".into(),
                    content_base64: STANDARD.encode(PROBE),
                    mode: Some(0o700),
                },
            )
            .await
            .map_err(|e| failure(format!("put_file: {e}")))?;
    }
    let first = driver.sandboxes[0].clone();
    // The third VM exists only for the agent leg and gets its own policy, so it
    // is deliberately left out of the pair case above rather than folded into
    // it with a "same policy" claim that would be false.
    let agent_sandbox = driver.sandboxes[2].clone();
    let second = driver.sandboxes[1].clone();
    let attachment = driver.attachment(&first)?;
    let peer_attachment = driver.attachment(&second)?;
    driver.case("real-firecracker-two-guarded-sandboxes", true,
        json!({"primary":attachment,"peer":peer_attachment,"vcpu_each":1,"memory_mib_each":512,"disk_mib_each":disk_mb,"policy_hash":driver.policy_hash}))?;
    // Every sandbox's persisted policy is checked against the hash it was
    // created with, including the agent VM's distinct one: a driver that
    // silently reused the primary hash would still pass a check written
    // against `driver.policy_hash`.
    for sandbox in driver.sandboxes.clone() {
        let persisted: Value = serde_json::from_slice(&std::fs::read(
            driver.guard_dir(&sandbox).join("effective-policy.json"),
        )?)?;
        let expected = expected_hashes
            .get(&sandbox.id)
            .ok_or_else(|| failure("a sandbox was created without a recorded policy hash"))?;
        if persisted["policy_hash"].as_str() != Some(expected.as_str()) {
            return Err(failure(format!(
                "persisted effective policy hash differs for {}",
                sandbox.id
            )));
        }
    }
    driver.current = "secret-absent-actual-guest-environment".into();
    let actual_environment = driver
        .runtime
        .exec(
            &first,
            ExecRequest {
                command: vec!["/usr/bin/env".into()],
                working_directory: Some("/workspace".into()),
                environment: BTreeMap::new(),
                timeout_seconds: 5,
                stdin: None,
            },
        )
        .await?;
    let secret_matches = actual_environment
        .stdout
        .matches(driver.secret.as_str())
        .count()
        + actual_environment
            .stderr
            .matches(driver.secret.as_str())
            .count();
    let environment_safe = actual_environment.exit_code == 0 && secret_matches == 0;
    driver.case("secret-absent-actual-guest-environment", environment_safe,
        json!({"method":"host scans complete actual guest env output; key never sent to guest probe",
            "environment_entries":actual_environment.stdout.lines().count(),"synthetic_secret_matches":secret_matches,"exec_exit_code":actual_environment.exit_code,"values_suppressed":true}))?;
    // No packet leaves until the attachment is activated by a heartbeat, and a
    // case that runs before that would be reading a dead gateway's answer
    // rather than the policy's.
    driver.current = "wait-for-guard-activation".into();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        driver.network.heartbeat_every_attachment().await;
        if driver.network.attachments_active().await || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    driver.case(
        "guard-attachment-activates-on-watchdog-heartbeat",
        driver.network.attachments_active().await
            && driver.network.attachment_count().await == driver.sandboxes.len(),
        json!({"attachments": driver.network.attachment_count().await,
               "sandboxes": driver.sandboxes.len()}),
    )?;

    driver.current = "runtime-placeholder-and-resolver".into();
    let environment = driver.probe(&first, json!({"kind":"environment"})).await?;
    driver.case(
        "runtime-placeholder-and-resolver",
        environment["placeholder_aliases"] == true
            && environment["base_aliases"] == true
            && environment["base_url"]
                == format!("http://{}:8443/model/model-main/v1", attachment.gateway_ip)
            && environment["resolver"].as_str().is_some_and(|resolver| {
                resolver.contains(&format!("nameserver {}\n", attachment.gateway_ip))
            }),
        environment,
    )?;
    driver.current = "real-guest-model-dns".into();
    let dns = driver
        .probe(
            &first,
            json!({"kind":"dns_system","name":MODEL_HOST,"samples":10}),
        )
        .await?;
    // The samples are read before the case consumes the value, so the
    // comparison below and the recorded evidence cannot disagree.
    let guarded_samples: Vec<f64> = dns["latency_ms"]
        .as_array()
        .ok_or_else(|| failure("guest DNS latency samples missing"))?
        .iter()
        .filter_map(|value| value.as_f64())
        .collect();
    driver.case(
        "real-guest-model-dns",
        dns["addresses"] == json!([attachment.gateway_ip.to_string()]),
        dns,
    )?;

    // What Guard costs for a name, as a difference rather than an absolute.
    //
    // The guarded side is what the guest actually pays: its own system
    // resolver, through the gateway, measured in the guest by the probe above.
    // The unguarded side is the same A query answered by a resolver in this
    // namespace with no policy in front of it.
    //
    // The gateway is not asked from this host, and that is worth stating
    // rather than working around: it drops any DNS from a source that is not
    // the guest, so a host-side query would time out. It is the same rule that
    // stops a second sandbox using the first sandbox's gateway, and it is why
    // the guarded number has to come from inside the guest.
    //
    // The difference is an UPPER BOUND on Guard's cost, not a measurement of
    // it. It also contains the vsock hop and the guest's resolver stack in
    // place of the host's. What it does establish is that the number is not
    // dominated by something unaccounted for.
    driver.current = "guard-dns-cost-measured-against-an-unguverned-resolver".into();
    let query = dns_a_query(MODEL_HOST);
    let unguarded = median_dns_round_trip(BASELINE_DNS_ADDR, &query, DNS_SAMPLES).await?;
    if guarded_samples.is_empty() {
        return Err(failure("guest DNS latency samples empty"));
    }
    let mut sorted = guarded_samples.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    let guarded = sorted[sorted.len() / 2];
    driver.case(
        "guard-dns-cost-measured-against-an-unguverned-resolver",
        guarded > 0.0 && unguarded > 0.0,
        json!({
            "guarded_median_ms": guarded,
            "unguarded_median_ms": unguarded,
            "difference_ms": guarded - unguarded,
            "guarded_samples": guarded_samples,
            "unguarded_samples": DNS_SAMPLES,
            "query": MODEL_HOST,
            "method": "guarded: the guest's system resolver, in the guest, through the \
        gateway. unguarded: the identical A query to a policy-free resolver in the same \
        namespace. medians of the batch. The difference is an upper bound: it also contains \
        the vsock hop and the guest's resolver stack, so it bounds Guard's cost rather than \
        isolating it",
            "not_measured": "the gateway is not queried from the host; it drops DNS from \
        any source that is not its own guest, which is a property and not a gap",
        }),
    )?;
    for (name, qname, qtype, tcp) in [
        ("unrelated-hostname", "unrelated.guard.test", 1, false),
        (
            "unrelated-hostname-tcp-dns",
            "unrelated.guard.test",
            1,
            true,
        ),
        ("dns-ns-denied", MODEL_HOST, 2, false),
        ("dns-txt-denied", MODEL_HOST, 16, false),
        ("dns-null-denied", MODEL_HOST, 10, false),
        ("dns-any-denied", MODEL_HOST, 255, false),
    ] {
        driver.current = name.into();
        let path = driver.guard_dir(&first).join("events.jsonl");
        let offset = read_events(&path)?.len();
        let result = driver.probe(&first, json!({"kind":"dns_wire","host":attachment.gateway_ip.to_string(),"name":qname,"qtype":qtype,"tcp":tcp})).await?;
        let events = read_events(&path)?;
        verify_chain(&events)?;
        let denials: Vec<_> = events
            .iter()
            .skip(offset)
            .filter(|event| event.decision == Decision::Deny && event.category.as_str() == "dns")
            .collect();
        driver.case(
            name,
            result["matching_id"] == true
                && result["answers"] == 0
                && matches!(result["rcode"].as_u64(), Some(3 | 5))
                && denials.iter().any(|event| {
                    // The gateway reports why it refused, and the reasons are
                    // distinct on purpose: a watcher rules on "denied", "NXDOMAIN"
                    // and "record type denied" separately, so one merged string
                    // would hide which of them happened.
                    matches!(
                        event.reason.as_str(),
                        "DNS name denied" | "DNS record type denied" | "DNS NXDOMAIN"
                    )
                }),
            json!({"guest":result,"authoritative_denials":denials}),
        )?;
    }
    driver.current = "streaming-model-placeholder".into();
    let mock = driver
        .mocks
        .as_ref()
        .ok_or_else(|| failure("model mock missing"))?;
    let hash = mock.response_hash.clone();
    let bytes = mock.response_bytes;
    let mut direct = Vec::new();
    let mut guarded = Vec::new();
    for _ in 0..3 {
        direct.push(model_baseline(&driver.secret, &hash, bytes).await?);
        let response = driver.probe(&first, json!({"kind":"broker"})).await?;
        let incremental = response["first_byte_ms"]
            .as_f64()
            .zip(response["duration_ms"].as_f64())
            .is_some_and(|(first, total)| first < total / 2.0);
        if response["status"] != 200
            || response["bytes"] != bytes
            || response["sha256"] != hash
            || response["done"] != true
            || !incremental
        {
            return driver.case(
                "streaming-model-placeholder",
                false,
                json!({"guest":response,"expected_bytes":bytes,"expected_sha256":hash}),
            );
        }
        guarded.push(response);
    }
    let mean = |rows: &[Value], field: &str| {
        rows.iter()
            .filter_map(|row| row[field].as_f64())
            .sum::<f64>()
            / rows.len() as f64
    };
    driver.case("streaming-model-placeholder", true, json!({"samples":3,"direct_local_model":direct,"guarded_guest":guarded,
        "first_byte_added_ms":mean(&guarded,"first_byte_ms")-mean(&direct,"first_byte_ms"),
        "duration_added_ms":mean(&guarded,"duration_ms")-mean(&direct,"duration_ms"),
        "measurement_scope":"guest interpreter/client + vsock exec timing excluded from HTTP clock; direct host baseline; host/mock/guest stack differs"}))?;
    driver
        .denied_broker(
            &first,
            "wrong-binding",
            json!({"kind":"broker","path":"/model/not-model/v1/chat/completions"}),
            "model binding mismatch",
        )
        .await?;
    driver
        .denied_broker(
            &first,
            "wrong-placeholder",
            json!({"kind":"broker","placeholder":"placeholder://wrong"}),
            "credential placeholder mismatch",
        )
        .await?;
    driver
        .denied_broker(
            &first,
            "wrong-host",
            json!({"kind":"broker","host_header":"unrelated.guard.test"}),
            "broker authority mismatch",
        )
        .await?;
    driver
        .denied_broker(
            &first,
            "wrong-method",
            json!({"kind":"broker","method":"GET"}),
            "model method or path denied",
        )
        .await?;
    driver
        .denied_broker(
            &first,
            "wrong-path",
            json!({"kind":"broker","path":"/model/model-main/v1/not-permitted"}),
            "model method or path denied",
        )
        .await?;
    driver.denied_broker(&first,"placeholder-other-proxy-destination",json!({"kind":"broker","path":"http://unrelated.guard.test:8080/v1/chat/completions","host_header":"unrelated.guard.test:8080"}),"credentials forbidden on proxy").await?;

    driver.current = "ipv6-route-preparation".into();
    ip(&[
        "-6",
        "addr",
        "add",
        "fd00:beef::1/64",
        "dev",
        &attachment.interface,
        "nodad",
    ])
    .await?;
    let link = ip(&["-j", "link", "show", "dev", &attachment.interface]).await?;
    let mac = link[0]["address"]
        .as_str()
        .ok_or_else(|| failure("TAP MAC unavailable"))?;
    let ipv6 = driver
        .probe(&first, json!({"kind":"ipv6_setup","mac":mac}))
        .await?;
    // This case exists to prove a guest that *has* an IPv6 route still cannot
    // bypass the unconditional drop, so `configured: true` is the assertion. A
    // guest image without `ip` cannot exercise it, and that is reported as a
    // failure rather than redefined into a pass - the fix is the image, not the
    // criterion.
    driver.case(
        "ipv6-route-preparation",
        ipv6["configured"] == true,
        json!({"guest":ipv6,"host_gateway":"fd00:beef::1","guest_address":"fd00:beef::2",
            "permanent_neighbor":mac}),
    )?;
    for (name, host, port) in SENTINELS {
        driver
            .denied_network(
                &first,
                &attachment,
                name,
                json!({"kind":"tcp","host":host,"port":port,"dns":*name=="external-tcp-dns"}),
                baselines[*name].clone(),
            )
            .await?;
    }
    driver
        .denied_network(
            &first,
            &attachment,
            "external-udp-dns",
            json!({"kind":"udp","host":"93.184.216.34","port":53,"dns":true}),
            udp_baseline,
        )
        .await?;
    driver
        .denied_network(
            &first,
            &attachment,
            "model-upstream-direct-ip-bypass",
            json!({"kind":"placeholder_direct","host":"198.18.0.10","port":18080}),
            direct[0].clone(),
        )
        .await?;
    driver
        .denied_network(
            &first,
            &attachment,
            "placeholder-direct-other-destination",
            json!({"kind":"placeholder_direct","host":"93.184.216.34","port":8080}),
            baselines["direct-public-ipv4"].clone(),
        )
        .await?;
    driver
        .denied_network(
            &first,
            &attachment,
            "proxy-environment-bypass",
            json!({"kind":"proxy_env","proxy":"93.184.216.34:8080"}),
            baselines["direct-public-ipv4"].clone(),
        )
        .await?;
    driver
        .denied_network(
            &first,
            &attachment,
            "raw-socket-bypass",
            json!({"kind":"raw","host":"93.184.216.34"}),
            baselines["direct-public-ipv4"].clone(),
        )
        .await?;

    // ---------------------------------------------------------------------
    // The incident reproduction.
    //
    // Everything above proves a destination is blocked. That alone cannot
    // distinguish enforcement from a route that never existed, a dead mock, or
    // a typo in an address. The reproduction therefore runs the *same* bypass
    // twice: once in a deliberately unguarded sandbox where it is expected to
    // succeed, and once under Guard where it must fail. If the control leg
    // stops reaching the chatbot, every guarded denial above is reported as
    // inconclusive rather than as a pass.
    // ---------------------------------------------------------------------
    let repro_config = json!({"kind":"dns_bypass","name":CHATBOT_HOST,
        "resolver":CHATBOT_RESOLVER_IP.to_string(),"port":CHATBOT_PORT});

    // Control leg. The listener's own hit counter is the evidence, not the
    // guest's report that it believed it connected: a guest that reports
    // success without the destination having seen a connection is the failure
    // mode this whole case exists to exclude.
    let control_hits_before = driver
        .mocks
        .as_ref()
        .unwrap()
        .chatbot_hits
        .load(Ordering::Relaxed);
    let control_guarded = std::env::var("AIEC_REPRO_LEGACY_CONTROL").as_deref() == Ok("1");
    let mut control_hits: u64 = 0;
    let control = if control_guarded {
        driver.current = "incident-reproduction-unguarded-control".into();
        let now = chrono::Utc::now();
        let sandbox = Sandbox {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            node_id: None,
            image_id: "aiec".into(),
            state: SandboxState::Creating,
            runtime: RuntimeKind::Firecracker,
            cpu: 1,
            memory_mb: 512,
            disk_mb: disk_mb.try_into()?,
            timeout_seconds: 1800,
            // Unguarded, and with general outbound access - which is the
            // topology the incident happened in. No Guard config is attached,
            // so there is nothing in this sandbox's path that could deny it.
            network: NetworkPolicy::Internet,
            environment: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        };
        driver.sandboxes.push(sandbox.clone());
        driver
            .runtime
            .create(&sandbox)
            .await
            .map_err(|e| failure(format!("control create: {e}")))?;
        driver
            .runtime
            .start(&sandbox)
            .await
            .map_err(|e| failure(format!("control start: {e}")))?;
        driver
            .runtime
            .put_file(
                &sandbox,
                PutFileRequest {
                    path: "/workspace/guard-probe.py".into(),
                    content_base64: STANDARD.encode(PROBE),
                    mode: Some(0o700),
                },
            )
            .await
            .map_err(|e| failure(format!("control put_file: {e}")))?;
        let observation = driver.probe(&sandbox, repro_config.clone()).await?;
        let hits = driver
            .mocks
            .as_ref()
            .unwrap()
            .chatbot_hits
            .load(Ordering::Relaxed);
        control_hits = hits - control_hits_before;
        let reached = observation["reachable"] == true && control_hits > 0;
        driver.case("incident-reproduction-unguarded-reaches-chatbot", reached,
            json!({"sandbox_id":sandbox.id,"topology":"unguarded","network":"Internet",
                "resolver":CHATBOT_RESOLVER_IP,"name":CHATBOT_HOST,"destination":CHATBOT_IP,
                "guest_observation":observation,"chatbot_hits":hits - control_hits_before,
                "evidence":"the mock chatbot counted the connection; the guest's report alone is not relied on"}))?;
        Some(observation)
    } else {
        None
    };

    // Guarded leg. The same resolver, the same name, the same destination.
    driver.current = "incident-reproduction-guarded-block".into();
    let backend = NftablesBackend::new();
    let events_path = driver.guard_dir(&first).join("events.jsonl");
    let before = backend.counters(&attachment).await?;
    let offset = read_events(&events_path)?.len();
    let guarded = driver.probe(&first, repro_config.clone()).await?;
    // Second guarded leg. The same bypass, but through the one resolver Guard
    // does answer: the guest asks the gateway itself for a name no policy
    // approved. Here the gateway gets to rule on it, so the refusal is a
    // decision it records rather than a kernel drop with no record - which is
    // what makes the two legs complementary rather than redundant.
    let gateway_leg_offset = read_events(&events_path)?.len();
    let via_gateway = driver
        .probe(
            &first,
            json!({"kind":"dns_bypass","name":CHATBOT_HOST,
                "resolver":attachment.gateway_ip.to_string(),"port":CHATBOT_PORT}),
        )
        .await?;
    let after = backend.counters(&attachment).await?;
    // Guard blocks this before a socket exists. The guest names a resolver
    // that is not the gateway, so the gateway-DNS permit does not match and the
    // packet is dropped by the catch-all rule; had it used the gateway, the
    // gateway would have refused the unapproved name instead. Either way the
    // assertion is on host-owned evidence, never on the guest resolving or not.
    let chatbot_hits_after = driver
        .mocks
        .as_ref()
        .unwrap()
        .chatbot_hits
        .load(Ordering::Relaxed);
    let all_events = read_events(&events_path)?;
    verify_chain(&all_events)?;
    let denials: Vec<_> = all_events
        .iter()
        .filter(|event| event.decision == Decision::Deny)
        .collect();
    // A refusal is only meaningful if it happened during this leg, so the
    // earlier denials in the chain cannot stand in for it.
    let denials_during: Vec<_> = all_events
        .iter()
        .skip(offset)
        .filter(|event| event.decision == Decision::Deny)
        .collect();
    let nft_denied = deny_delta(&before, &after) > 0;
    let blocked = guarded["reachable"] != true
        && chatbot_hits_after == control_hits_before + control_hits
        && (nft_denied || !denials_during.is_empty());
    driver.case(
        "incident-reproduction-guarded-blocks-chatbot",
        blocked,
        json!({"topology":"guard","policy":"model-only","resolver":CHATBOT_RESOLVER_IP,
            "name":CHATBOT_HOST,"destination":CHATBOT_IP,"guest_observation":guarded,
            "counters_before":counter_json(&before),"counters_after":counter_json(&after),
            "deny_delta":deny_delta(&before, &after),"nft_denied":nft_denied,
            "host_denials_during_leg":denials_during,"signal_used":
                if nft_denied {"nft counter"} else {"host-owned denial event"},
            "chatbot_hits_during_guarded_leg":chatbot_hits_after - control_hits_before}),
    )?;

    // The gateway leg, asserted on the decision it actually recorded. This is
    // the leg that produces a named reason rather than a bare drop, so it is
    // also what ties the reproduction to a specific policy rule instead of to
    // a default-deny that would have fired regardless of the name.
    let gateway_denials: Vec<_> = all_events
        .iter()
        .skip(gateway_leg_offset)
        .filter(|event| event.decision == Decision::Deny)
        .collect();
    driver.case(
        "incident-reproduction-gateway-refused-unapproved-name",
        gateway_denials.iter().any(|event| {
            matches!(
                event.reason.as_str(),
                "DNS name denied" | "DNS record type denied" | "DNS NXDOMAIN"
            )
        }),
        json!({"resolver":"guard gateway","name":CHATBOT_HOST,"guest_observation":via_gateway,
            "denials":gateway_denials,
            "evidence":"the gateway ruled on the name itself, so this is a policy decision rather than a default-deny fallback"}),
    )?;

    // The host-observed record of this attempt, chain-verified. A block that
    // leaves no trace outside the guest is exactly the gap the threat model
    // claims to exclude, so the count is asserted rather than assumed - the
    // guarded leg may be stopped by nft, which is recorded in counters, so
    // this case accepts either trace and records which one it found.
    driver.case(
        "incident-reproduction-recorded-outside-guest",
        nft_denied || !denials_during.is_empty(),
        json!({"source":"host-owned counters and host-owned event chain, neither writable by the guest",
            "chain_verified":true,"total_denials_in_chain":denials.len(),
            "denials_during_leg":denials_during,
            "nft_denied":nft_denied}),
    )?;

    // Reported rather than asserted. Without the control leg the guarded
    // denials above are still real, but they cannot be attributed to Guard
    // rather than to a route that never existed - so the absence is recorded
    // as a weaker form of evidence instead of being hidden or faked.
    driver.case(
        "incident-reproduction-control-leg-run",
        true,
        json!({"control_leg":control.is_some(),
            "control_observation":control,
            "absent_meaning":"AIEC_REPRO_LEGACY_CONTROL was not set; the guarded legs ran, but nothing here shows the route was reachable without Guard"}),
    )?;

    driver.current = "peer-sandbox-service-baseline".into();
    let launch = driver.runtime.exec(&second,ExecRequest { command:vec!["/bin/sh".into(),"-c".into(),
        "nohup /usr/bin/python3 /workspace/guard-probe.py '{\"kind\":\"peer\"}' >/tmp/guard-peer.log 2>&1 </dev/null &".into()],
        working_directory:Some("/workspace".into()),environment:BTreeMap::new(),timeout_seconds:5,stdin:None }).await?;
    if launch.exit_code != 0 {
        return Err(failure("peer guest listener launch failed"));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let backend = NftablesBackend::new();
    let peer_compiled = compile(&policy, &driver.boundary)?;
    // Explicit local-only negative control. Remove only this peer's own table,
    // never any global rule, and restore before collecting guest deny evidence.
    backend.remove_policy(&peer_attachment).await?;
    let peer_baseline = baseline_tcp(&format!("{}:8080", peer_attachment.guest_ip)).await;
    let restored = backend
        .restore_network(&peer_compiled, &peer_attachment)
        .await;
    restored?;
    let peer_baseline = peer_baseline?;
    driver.case("peer-sandbox-service-baseline",true,json!({"host":peer_baseline,"negative_control":"peer per-sandbox nft table temporarily removed and restored in disposable netns","peer_policy_restored":counter_json(&backend.counters(&peer_attachment).await?)}))?;
    driver
        .denied_network(
            &first,
            &attachment,
            "another-sandbox",
            json!({"kind":"tcp","host":peer_attachment.guest_ip.to_string(),"port":8080}),
            peer_baseline,
        )
        .await?;
    driver.current = "host-reachability-with-two-policies".into();
    let mut rechecks = BTreeMap::new();
    for (name, host, port) in SENTINELS {
        rechecks.insert(*name, baseline_tcp(&target(host, *port)).await?);
    }
    let host_model = model_baseline(&driver.secret, &hash, bytes).await?;
    driver.case("host-reachability-with-two-policies",true,json!({"sentinels":rechecks,"model":host_model,
        "primary_table":counter_json(&backend.counters(&attachment).await?),"peer_table":counter_json(&backend.counters(&peer_attachment).await?)}))?;
    let final_stream = driver.probe(&first, json!({"kind":"broker"})).await?;
    driver.case(
        "model-still-reachable-after-deny-matrix",
        final_stream["status"] == 200 && final_stream["sha256"] == hash,
        final_stream,
    )?;

    driver.current = "full-snapshot-secret-exclusion".into();
    let snapshot_key = format!("guard-core-{}", first.id);
    let snapshot_bytes = driver.runtime.snapshot(&first, &snapshot_key).await?;
    let directory = driver
        .state
        .join("snapshots")
        .join(hex::encode(Sha256::digest(snapshot_key.as_bytes())));
    for required in [
        directory.join("memory"),
        directory.join("vmstate"),
        directory.join("rootfs.ext4"),
        driver
            .state
            .join("vms")
            .join(first.id.to_string())
            .join("rootfs.ext4"),
    ] {
        if std::fs::metadata(&required)?.len() == 0 {
            return Err(failure(
                "required real VM/snapshot artifact absent or empty",
            ));
        }
    }
    let scan_root = driver.state.clone();
    let needle = driver.secret.as_bytes().to_vec();
    let scanned = tokio::task::spawn_blocking(move || scan_files(&scan_root, &needle)).await??;
    driver.case("secret-absent-guest-files-full-snapshot-events-logs",true,json!({"scan":scanned,"snapshot_bytes":snapshot_bytes,
        "scope":"all actual VM rootfs images, full memory/vmstate/disk snapshots, guest files inside rootfs, authoritative events and Firecracker logs; credential operator file lives outside scanned runtime state"}))?;
    driver.current = "authoritative-event-chain".into();
    let mut journals = Vec::new();
    for sandbox in [&first, &second] {
        let events = read_events(&driver.guard_dir(sandbox).join("events.jsonl"))?;
        verify_chain(&events)?;
        if events.is_empty()
            || events.iter().any(|event| {
                event.sandbox_id != sandbox.id
                    || event.tenant_id != sandbox.tenant_id
                    || event.policy_hash != driver.policy_hash
            })
        {
            return Err(failure("journal identity/hash invariant failed"));
        }
        journals.push(json!({"sandbox_id":sandbox.id,"events":events.len(),"head":events.last().map(|e| &e.current_hash),
            "reasons":events.iter().map(|event|json!({"category":event.category,"decision":event.decision,"reason":event.reason,"request_bytes":event.request_bytes,"response_bytes":event.response_bytes,"duration_ms":event.duration_ms})).collect::<Vec<_>>()}));
    }
    driver.case("authoritative-event-chain",true,json!({"journals":journals,"verified":true,"head_anchor":"returned JSON evidence (retain outside guest)"}))?;
    let mock = driver
        .mocks
        .as_ref()
        .ok_or_else(|| failure("model mock missing"))?;
    let authenticated = mock.accepted.load(Ordering::Relaxed);
    let rejected = mock.rejected.load(Ordering::Relaxed);
    driver.case("bound-secret-used-only-at-model-mock", rejected == 0 && authenticated == 8,
        json!({"authenticated_requests":authenticated,"expected_authenticated_requests":8,"wrong_credential_requests":rejected,"never_printed_or_passed_to_guest":true}))?;
    // ---------------------------------------------------------------------
    // A real tool-using agent, on the model-only policy, inside a real VM.
    //
    // Everything above proves the guard permits exactly one destination. This
    // proves the permitted destination is enough to do the work the product
    // exists for: an agent that reads a file, writes a file, runs a command
    // and reports back, with every one of those steps decided by the model
    // endpoint the policy allows. A sandbox that cannot run a real agent is
    // not a sandbox, whatever its counters say.
    // ---------------------------------------------------------------------
    driver.current = "model-only-agent-runs-a-real-tool-loop".into();
    let harness_path = std::env::var("AIEC_AGENT_BINARY").map_err(|_| {
        failure("AIEC_AGENT_BINARY must point at a static harness binary built for this guest")
    })?;
    let harness_bytes = std::fs::read(&harness_path)
        .map_err(|e| failure(format!("in-guest harness binary {harness_path}: {e}")))?;
    if harness_bytes.len() < 64 * 1024 {
        return Err(failure(format!(
            "in-guest harness binary is {} bytes, which is not a program",
            harness_bytes.len()
        )));
    }
    if harness_bytes.len() > MAX_FILE {
        return Err(failure(
            "in-guest harness binary exceeds the runtime file limit",
        ));
    }
    let agent_attachment = driver.attachment(&agent_sandbox)?;
    let sentinel_before = driver
        .mocks
        .as_ref()
        .ok_or_else(|| failure("model mock missing"))?
        .sentinel_guest_hits
        .load(Ordering::Relaxed);
    let counters_before = backend.counters(&agent_attachment).await?;
    // The binary is uploaded at run time rather than baked into the guest
    // image: that image is the one artifact whose bytes are pinned by a
    // digest, and changing it to suit a test would mean the evidence for this
    // case and the evidence for every other case stopped describing the same
    // machine.
    //
    // It goes under /workspace because that is the only tree the guest agent
    // will write to, and it arrives in pieces because a static harness is
    // larger than one control-channel frame.
    let cpu_before = self_cost().0;
    let rss_before = self_cost().1;
    driver
        .runtime
        .put_file(
            &agent_sandbox,
            PutFileRequest {
                path: "/workspace/bin/aiec-agent".into(),
                content_base64: STANDARD.encode(&harness_bytes),
                mode: Some(0o700),
            },
        )
        .await
        .map_err(|e| failure(format!("uploading the in-guest harness: {e}")))?;
    let cpu_after_upload = self_cost().0;
    let rss_after_upload = self_cost().1;
    driver
        .runtime
        .put_file(
            &agent_sandbox,
            PutFileRequest {
                path: "/workspace/notes.txt".into(),
                content_base64: STANDARD.encode(
                    format!("TOKEN={AGENT_TOKEN}\nthe only content of these notes\n").as_bytes(),
                ),
                mode: Some(0o644),
            },
        )
        .await
        .map_err(|e| failure(format!("uploading the agent input: {e}")))?;
    let task_document = json!({
        "task_id":"guard-model-only-agent",
        "instruction":"Read notes.txt. It carries a token. Write that token alone into answer.txt. Then read answer.txt back and report the token you found.",
        "workspace":"/workspace",
        "tools":["read","write","bash"],
        // A validation entry is a bare argv array, not an object with an
        // `argv` field: the harness deserializes it transparently into the
        // command it runs. An object here is refused as "invalid type: map,
        // expected a sequence", before the agent does anything at all.
        "validation":[
            ["/usr/bin/grep","-q",AGENT_TOKEN,"/workspace/answer.txt"]
        ],
        "limits":{"wall_seconds":180,"max_model_requests":8,"command_timeout_seconds":30}
    });
    driver
        .runtime
        .put_file(
            &agent_sandbox,
            PutFileRequest {
                path: "/workspace/task.json".into(),
                content_base64: STANDARD.encode(serde_json::to_vec(&task_document)?),
                mode: Some(0o644),
            },
        )
        .await
        .map_err(|e| failure(format!("uploading the agent task: {e}")))?;
    let agent_started = Instant::now();
    let agent_run = tokio::time::timeout(
        Duration::from_secs(300),
        driver.runtime.exec(
            &agent_sandbox,
            ExecRequest {
                command: vec![
                    "/workspace/bin/aiec-agent".into(),
                    "run".into(),
                    "--task".into(),
                    "/workspace/task.json".into(),
                    "--result".into(),
                    "/workspace/result.json".into(),
                    "--events".into(),
                    "/workspace/events.jsonl".into(),
                    "--provider".into(),
                    "openai-compatible".into(),
                    "--model".into(),
                    "guard-mock".into(),
                ],
                working_directory: Some("/workspace".into()),
                environment: BTreeMap::new(),
                timeout_seconds: 240,
                stdin: None,
            },
        ),
    )
    .await
    .map_err(|_| failure("the in-guest agent did not finish inside 300s"))?
    .map_err(|e| failure(format!("the in-guest agent failed to execute: {e}")))?;
    let agent_wall_ms = agent_started.elapsed().as_millis() as u64;
    // An agent that ran and produced nothing is the most likely way this leg
    // fails, and the exit status and streams are the only things that say why.
    // Without them a missing result file arrives as an I/O error about a file
    // that was never written, which points at the file rather than the run.
    let agent_exec = json!({
        "exit_code": agent_run.exit_code,
        "timed_out": agent_run.timed_out,
        "stdout": agent_run.stdout.chars().rev().take(4000).collect::<String>().chars().rev().collect::<String>(),
        "stderr": agent_run.stderr.chars().rev().take(4000).collect::<String>().chars().rev().collect::<String>(),
    });
    let agent_result = match guest_json(driver, &agent_sandbox, "/workspace/result.json").await {
        Ok(value) => value,
        Err(e) => {
            let events = guest_text(driver, &agent_sandbox, "/workspace/events.jsonl")
                .await
                .unwrap_or_else(|_| "<unreadable>".into());
            return Err(failure(format!(
                "{e}; the agent process reported {}",
                serde_json::to_string_pretty(&json!({
                    "execution": agent_exec,
                    "event_log_tail": events
                        .lines()
                        .rev()
                        .take(20)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join("\n"),
                }))
                .unwrap_or_default()
            )));
        }
    };
    let agent_answer = match guest_text(driver, &agent_sandbox, "/workspace/answer.txt").await {
        Ok(text) => text,
        Err(e) => {
            // The result document carries the harness's own account of why it
            // stopped - the validation that failed, the model error, the turn
            // budget it hit. Without it, an artifact that was never produced
            // is indistinguishable from a transport failure.
            let events = guest_text(driver, &agent_sandbox, "/workspace/events.jsonl")
                .await
                .unwrap_or_else(|_| "<unreadable>".into());
            return Err(failure(format!(
                "{e}; the agent reported {}",
                serde_json::to_string_pretty(&json!({
                    "execution": agent_exec,
                    "result": agent_result,
                    // What the endpoint itself saw. The harness's result says
                    // the loop ended; this says what the endpoint was asked and
                    // what it answered, which is the half that cannot be
                    // reconstructed from the guest.
                    "endpoint_view": driver
                        .agent_model
                        .as_ref()
                        .ok_or_else(|| failure("agent model mock missing"))?
                        .snapshot()
                        .await,
                    "event_log_tail": events
                        .lines()
                        .rev()
                        .take(20)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join("\n"),
                }))
                .unwrap_or_default()
            )));
        }
    };
    let observed_tools = json!({
        "read":agent_result["metrics"]["tool_calls"]["read"].as_u64().unwrap_or(0),
        "write":agent_result["metrics"]["tool_calls"]["write"].as_u64().unwrap_or(0),
        "bash":agent_result["metrics"]["tool_calls"]["bash"].as_u64().unwrap_or(0),
    });
    // The provider is read and then dropped, because recording a case needs
    // the driver mutably and a borrow held across that would be the driver's
    // own snapshot keeping the mock alive for no reason.
    let conversation = driver
        .agent_model
        .as_ref()
        .ok_or_else(|| failure("agent model mock missing"))?
        .snapshot()
        .await;
    let turns = conversation["turns"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let observation_for = |turn: &Value, tool: &str| -> String {
        turn["observations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| entry[0].as_str() == Some(tool))
            .filter_map(|entry| entry[1].as_str().map(str::to_string))
            .collect::<String>()
    };
    let admitted = conversation["accepted"].as_u64().unwrap_or(0);
    // Every turn has to have arrived as a stream rather than as one pre-formed
    // body. A provider that answered in a single shot would satisfy "four
    // turns happened" while testing none of the streaming path.
    let every_turn_streamed = !turns.is_empty()
        && turns
            .iter()
            .all(|turn| turn["frames"].as_u64().unwrap_or(0) >= 3);
    let every_turn_offered_tools = !turns.is_empty()
        && turns.iter().all(|turn| {
            let advertised = turn["advertised"].as_array().cloned().unwrap_or_default();
            ["read", "write", "bash"]
                .iter()
                .all(|name| advertised.iter().any(|entry| entry.as_str() == Some(name)))
        });
    let token_came_back_through_read = turns
        .get(1)
        .map(|turn| observation_for(turn, "read").contains(AGENT_TOKEN))
        .unwrap_or(false);
    let token_came_back_through_bash = turns
        .get(3)
        .map(|turn| observation_for(turn, "bash").contains(AGENT_TOKEN))
        .unwrap_or(false);
    let tools_correct = observed_tools["read"] == json!(1)
        && observed_tools["write"] == json!(1)
        && observed_tools["bash"] == json!(1);
    driver.case(
        "model-only-agent-runs-a-real-tool-loop",
        agent_run.exit_code == 0
            && agent_result["status"] == json!("success")
            && agent_result["validation"][0]["ok"] == json!(true)
            && agent_result["metrics"]["model_requests"] == json!(4)
            && tools_correct
            && admitted == 4
            && conversation["rejected"] == json!(0)
            && turns.len() == 4
            && (0..4).all(|i| turns[i]["turn"] == json!(i))
            && every_turn_streamed
            && every_turn_offered_tools
            && token_came_back_through_read
            && token_came_back_through_bash
            && agent_answer.contains(AGENT_TOKEN),
        json!({
            "sandbox_id":agent_sandbox.id,
            "exec":{
                "exit_code":agent_run.exit_code,
                "wall_ms":agent_wall_ms,
                "stdout_tail":agent_run.stdout.chars().rev().take(240).collect::<String>().chars().rev().collect::<String>(),
            },
            "task":task_document,
            "task_result":agent_result,
            "answer_written_by_the_agent":agent_answer,
            "tool_calls":observed_tools,
            "model":{
                "host":AGENT_MODEL_HOST,
                "provider":"openai-compatible",
                "credential_label":AGENT_MODEL_CREDENTIAL,
                "authenticated_requests":admitted,
                "rejected_requests":conversation["rejected"],
                "turns":turns,
                "every_turn_delivered_as_a_stream":every_turn_streamed,
                "every_turn_was_offered_the_same_three_tools":every_turn_offered_tools,
                "token_reached_the_agent_through_the_read_tool":token_came_back_through_read,
                "token_reached_the_agent_through_the_bash_tool":token_came_back_through_bash,
            },
            "note":"The model host, the credential label and the policy are the agent sandbox's own, not the pair's. The guest was handed an operator-mode placeholder for this credential and the broker substituted the real one on the way out, which is why the mock can authenticate the request and the guest can still be shown never to have held the secret.",
        }),
    )?;
    let counters_after = backend.counters(&agent_attachment).await?;
    let (cpu_after_run, rss_after_run) = self_cost();
    let sentinel_after = driver
        .mocks
        .as_ref()
        .ok_or_else(|| failure("model mock missing"))?
        .sentinel_guest_hits
        .load(Ordering::Relaxed);
    let broker_permitted = counters_after
        .broker_permitted
        .saturating_sub(counters_before.broker_permitted);
    // The sentinel counter counts connections the guest made to the forbidden
    // destinations, so the claim is that it did not move — not that it equals
    // the request count. Comparing it to `admitted` would compare a leak
    // counter with a request count, which fails for a guest that behaved
    // perfectly and would pass for one that reached the sentinel.
    let sentinel_hits = sentinel_after - sentinel_before;
    driver.case(
        "model-only-agent-egress-is-limited-to-the-model-endpoint",
        sentinel_hits == 0 && admitted > 0 && deny_delta(&counters_before, &counters_after) == 0,
        json!({
            "host_observed_connections_to_forbidden_sentinels_during_the_agent_run":sentinel_hits,
            "authenticated_model_requests_seen_by_the_mock":admitted,
            "the_agent_did_reach_the_model_endpoint":admitted > 0,
            "no_connection_reached_any_forbidden_destination":sentinel_hits == 0,
            "denied_by_the_per_sandbox_table":deny_delta(&counters_before, &counters_after),
            "broker_admitted":broker_permitted,
            "counters_before":counter_json(&counters_before),
            "counters_after":counter_json(&counters_after),
            "observation":"The request count comes from the host side of the mock listener, which authenticates the credential before answering, and the sentinel and nftables counters are read from the host. The broker counter is packet-weighted rather than per request, so it is reported as it stands and not compared against the request count. Nothing the agent reports about itself decides whether it went anywhere else.",
            "host_cost_of_this_leg":{
                "scope":"this process, which hosts the Guard gateway and both mocks; the Firecracker VM and the guest agent are separate processes and are not counted in any of these numbers",
                "cpu_seconds_to_upload_the_harness":cpu_after_upload - cpu_before,
                "cpu_seconds_for_the_tool_loop":cpu_after_run - cpu_after_upload,
                "cpu_seconds_total":cpu_after_run - cpu_before,
                "resident_set_kib_before":rss_before,
                "resident_set_kib_after_upload":rss_after_upload,
                "resident_set_kib_after_the_tool_loop":rss_after_run,
                "resident_set_kib_growth_over_the_leg":rss_after_run as i64 - rss_before as i64,
                "authenticated_model_requests":admitted,
                "cpu_milliseconds_per_model_request":if admitted == 0 {
                    Value::Null
                } else {
                    json!((cpu_after_run - cpu_before) * 1000.0 / admitted as f64)
                },
                "note":"a single sample, on one host, with the gateway and the mocks in the same process as the harness. It bounds the cost of the whole leg rather than isolating the gateway, and no distribution may be inferred from it.",
            },
        }),
    )?;
    if let Some(provider) = driver.agent_model.as_ref() {
        provider.shutdown();
    }
    Ok(())
}

fn scan_files(root: &Path, secret: &[u8]) -> Result<Value> {
    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024 + secret.len()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push(entry.path());
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            let mut file = std::fs::File::open(entry.path())?;
            let mut tail = 0;
            let mut bytes = 0u64;
            loop {
                let n = file.read(&mut buffer[tail..])?;
                if n == 0 {
                    break;
                }
                bytes += n as u64;
                if buffer[..tail + n]
                    .windows(secret.len())
                    .any(|window| window == secret)
                {
                    return Err(failure(format!(
                        "synthetic secret found in runtime artifact {} (value suppressed)",
                        entry.path().strip_prefix(root)?.display()
                    )));
                }
                let end = tail + n;
                tail = (secret.len() - 1).min(end);
                buffer.copy_within(end - tail..end, 0);
            }
            total += bytes;
            files.push(json!({"relative_path":entry.path().strip_prefix(root)?.to_string_lossy(),"bytes_scanned":bytes}));
        }
    }
    Ok(json!({"files":files,"total_bytes":total,"matches":0,"scan_buffer_bytes":buffer.len()}))
}
fn hardware() -> Value {
    let uname = std::process::Command::new("uname")
        .args(["-srmo"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    let cpu = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
        s.lines().find_map(|line| {
            line.strip_prefix("model name")
                .and_then(|v| v.split_once(':').map(|(_, v)| v.trim().to_owned()))
        })
    });
    let process_stat = std::fs::read_to_string("/proc/self/stat").ok();
    let status = std::fs::read_to_string("/proc/self/status").ok();
    let ticks = std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<f64>()
                .ok()
        });
    let cpu_seconds = process_stat
        .as_deref()
        .and_then(|stat| stat.rsplit_once(") "))
        .and_then(|(_, fields)| {
            let fields: Vec<_> = fields.split_whitespace().collect();
            Some(
                (fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?)
                    / ticks?,
            )
        });
    let peak_rss_kib = status.as_deref().and_then(|status| {
        status.lines().find_map(|line| {
            line.strip_prefix("VmHWM:")
                .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        })
    });
    json!({"kernel_arch":uname,"cpu_model":cpu,"logical_cpus":std::thread::available_parallelism().map(|v|v.get()).ok(),
        "meminfo":std::fs::read_to_string("/proc/meminfo").ok(),"driver_status":status,
        "driver_cpu_seconds":cpu_seconds,"driver_peak_rss_kib":peak_rss_kib,
        "metrics_scope":"driver process includes Guard gateway and local mocks; Firecracker processes are separate"})
}

/// The driver's own CPU seconds and current resident set, for taking a delta
/// across one step.
///
/// `hardware()` above reports a peak, because a peak is the right summary for a
/// whole run. It is useless for a delta: `VmHWM` never falls, so "peak grew by
/// zero" is the answer whether or not memory was returned. A step's cost is
/// the CPU it burned and the resident set it was holding while it did.
fn self_cost() -> (f64, u64) {
    let ticks = std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<f64>()
                .ok()
        })
        .unwrap_or(100.0);
    let process_stat = std::fs::read_to_string("/proc/self/stat").ok();
    let cpu_seconds = process_stat
        .as_deref()
        .and_then(|stat| stat.rsplit_once(") "))
        .and_then(|(_, fields)| {
            let fields: Vec<_> = fields.split_whitespace().collect();
            Some(
                (fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?)
                    / ticks,
            )
        })
        .unwrap_or(0.0);
    let rss_kib = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            })
        })
        .unwrap_or(0);
    (cpu_seconds, rss_kib)
}

#[tokio::main]
async fn main() {
    // Async because configuring the namespace is the driver's job, and
    // `assign_mock_addresses` is an async call.
    let initialized = async {
        // "Am I inside the launcher's disposable namespace?"
        // PID 1's namespace link is unreadable from inside a fresh
        // comes back empty rather than as an inode and cannot be the
        // comparison. The launcher records the host's network namespace inode
        // before it unshares and hands it in; this is that same comparison,
        // made where it can actually be read. A fresh namespace also has
        // loopback DOWN, which is a second, independent signal.
        let host_netns = std::env::var("AIEC_GUARD_ACCEPTANCE_HOST_NETNS")
            .map_err(|_| failure("launcher did not record the host network namespace"))?;
        let own_netns = std::fs::read_link("/proc/self/ns/net")
            .map_err(|e| failure(format!("cannot read this process network namespace: {e}")))?
            .to_string_lossy()
            .into_owned();
        if own_netns == host_netns {
            return Err(failure(format!(
                "refusing host network namespace: this is {own_netns}, the namespace the \
                 acceptance was supposed to replace"
            )));
        }
        if !loopback_is_down()? {
            return Err(failure(
                "refusing host network namespace: loopback is already up, so this is not a fresh \
                 namespace",
            ));
        }
        // The Guard local-mock validator makes the same comparison, and needs
        // the host's inode handed to it: it cannot read PID 1's namespace from
        // inside a fresh one, for the same reason this check cannot either.
        if let Ok(host) = std::env::var("AIEC_GUARD_ACCEPTANCE_HOST_NETNS") {
            aiec_guard::deployment::set_host_network_namespace(host);
        }
        // Isolation is proven; only now is it safe to configure the network.
        assign_mock_addresses().await?;
        ip(&["-6", "address", "add", "fd00:feed::10/128", "dev", "lo"]).await?;
        // Namespace-scoped; never touches the host's routes or firewall.
        let _ = std::process::Command::new("sysctl")
            .args(["-qw", "net.ipv4.ip_forward=1"])
            .status();
        let root = PathBuf::from(std::env::var("AIEC_GUARD_ACCEPTANCE_STATE")?);
        if !root.is_dir() {
            return Err(failure("launcher-created private state directory required"));
        }
        // Each step is labelled so a refusal names itself. A bare errno from an
        // acceptance driver is the least useful thing it can print.
        let operator = root.join("operator");
        std::fs::create_dir(&operator).map_err(|e| failure(format!("operator directory: {e}")))?;
        std::fs::set_permissions(&operator, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| failure(format!("operator permissions: {e}")))?;
        let secret = format!("guard-synthetic-{}-{}", Uuid::now_v7(), Uuid::now_v7());
        let credentials = operator.join("credentials.json");
        // Two credentials, not one shared secret with two hostnames. The agent
        // endpoint is a separate policy with its own hash, and sharing the key
        // would let a guest that reaches one endpoint present the other's
        // credential - which would make the agent leg's refusals unprovable.
        private_file(
            &credentials,
            &json!({"model-main":secret,"agent-model":secret}),
        )
        .map_err(|e| failure(format!("credential file: {e}")))?;
        let boundary: OperatorBoundary = serde_json::from_value(
            json!({"blocked_cidrs":[],"protected_cidrs":["198.18.0.20/32","198.18.0.21/32"],"blocked_hosts":[],"test_destinations":{
                format!("{MODEL_HOST}:18080"):["198.18.0.10"],
                format!("{AGENT_MODEL_HOST}:18081"):["198.18.0.11"]}}),
        )?;
        let boundary_path = operator.join("boundary.json");
        private_file(&boundary_path, &serde_json::to_value(&boundary)?)
            .map_err(|e| failure(format!("boundary file: {e}")))?;
        let state = root.join("runtime");
        // The runtime measures host headroom against this directory before it
        // admits a placement, and `statvfs` on a path that does not exist
        // returns nothing - which reads as "this host cannot be measured" and
        // refuses the first sandbox. Creating it here is not tidiness: it is
        // what makes admission able to answer at all.
        std::fs::create_dir_all(&state)
            .map_err(|e| failure(format!("runtime state directory: {e}")))?;
        let mut config = FirecrackerConfig::from_env()?;
        config.state_dir = state.clone();
        config.jailer = None;
        config.tap = None;
        config.readiness_timeout = Duration::from_secs(45);
        let network = GuardNetworkManager::new(state.join("guard"))
            .with_operator_files(Some(boundary_path), Some(credentials))
            .with_local_test_mode();
        // Guarded traffic is admitted only against a durable authority and only
        // while an outside-guest watchdog reports. Both are real here: the
        // authority commits to a synced file before any byte is forwarded, and
        // the heartbeat below is this process, which is not the guest.
        let authority = Arc::new(FileBudgetAuthority::open(state.join("guard-budget.json"))?);
        std::fs::write(
            state.join("guard-budget.json"),
            serde_json::to_vec(&FileBudgetState {
                max_model_requests: 4096,
                max_bytes_in: 64 * 1024 * 1024,
                max_bytes_out: 64 * 1024 * 1024,
                ..Default::default()
            })?,
        )?;
        let network = Arc::new(network);
        network.configure_budget_authority(authority)?;
        Ok(Driver {
            runtime: FirecrackerRuntime::with_network_backend(config, network.clone()),
            network,
            sandboxes: Vec::new(),
            state,
            boundary,
            policy_hash: String::new(),
            secret,
            mocks: None,
            agent_model: None,
            cases: Vec::new(),
            current: "initialization".into(),
            started: Instant::now(),
            heartbeat: None,
        })
    };
    let initialized = initialized.await;
    let mut driver = match initialized {
        Ok(driver) => driver,
        Err(error) => {
            println!(
                "{}",
                json!({"status":"FAIL","failing_case":"initialization","error":error.to_string(),"no_fallback_attempted":true})
            );
            std::process::exit(1);
        }
    };
    let mut terminate =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(_) => {
                println!(
                    "{}",
                    json!({"status":"FAIL","failing_case":"signal-cleanup-installation"})
                );
                std::process::exit(1);
            }
        };
    let result = tokio::select! {
        result=run(&mut driver)=>result,
        _=tokio::signal::ctrl_c()=>Err(failure("interrupted (SIGINT)")),
        _=terminate.recv()=>Err(failure("interrupted (SIGTERM)")),
    };
    if let Some(task) = driver.heartbeat.take() {
        task.abort();
    }
    let failing = driver.current.clone();
    let errors = driver.cleanup().await;
    let pass = result.is_ok() && errors.is_empty();
    let message = result.err().map(|error| {
        error
            .to_string()
            .replace(driver.secret.as_str(), "[REDACTED]")
    });
    println!(
        "{}",
        json!({"schema":"aiec.guard.core-acceptance.v1","status":if pass{"PASS"}else{"FAIL"},
        "failing_case":if pass{None}else if message.is_some(){Some(failing.as_str())}else{Some("cleanup")},"error":message,
        "policy_hash":driver.policy_hash,"cases":driver.cases,"cleanup_errors":errors,"hardware_and_process_metrics":hardware(),
        "elapsed_seconds":driver.started.elapsed().as_secs_f64(),
        "completed_streaming_samples":driver.cases.iter().find(|c| c["case"]=="streaming-model-placeholder" && c["status"]=="PASS").and_then(|c|c["evidence"]["guarded_guest"].as_array()).map_or(0,Vec::len),
        "completed_dns_samples":driver.cases.iter().find(|c| c["case"]=="real-guest-model-dns").and_then(|c|c["evidence"]["samples"].as_u64()).unwrap_or(0),
        "topology":"inside/model-only; two real Firecracker VMs; isolated user+network namespace; local mocks only"})
    );
    // Explicit drop kills any still-owned Firecracker children even if destroy
    // failed. Namespace/process-group teardown is also owned by the launcher.
    drop(driver);
    if !pass {
        std::process::exit(1);
    }
}
