//! Real Firecracker + AIec Guard acceptance, invoked by scripts/guard-core-acceptance.sh.
//! No TestBackend, provider credentials, host firewall changes, or Internet traffic.
use aiec_core::{ExecRequest, PutFileRequest, RuntimeKind, Sandbox, SandboxState};
use aiec_guard::{
    compiler::{OperatorBoundary, compile},
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
const PROBE: &str = include_str!("../../../scripts/guard_core_guest_probe.py");
const MODEL_HOST: &str = "model.guard.test";
const MODEL_ADDR: &str = "198.18.0.10:18080";
const STREAM_CHUNKS: usize = 128;
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
    "198.18.0.10/32",
    "198.18.0.20/32",
    "198.18.0.21/32",
    "93.184.216.34/32",
    "169.254.169.254/32",
    "10.123.0.10/32",
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
struct Mocks {
    handles: Vec<JoinHandle<()>>,
    accepted: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
    sentinel_guest_hits: Arc<AtomicU64>,
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
        Ok(Self {
            handles,
            accepted,
            rejected,
            sentinel_guest_hits,
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
    sandboxes: Vec<Sandbox>,
    state: PathBuf,
    boundary: OperatorBoundary,
    policy_hash: String,
    secret: String,
    mocks: Option<Mocks>,
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

async fn run(driver: &mut Driver) -> Result<()> {
    driver.current = "local-mock-addresses".into();
    // Every local listener binds to an address that must already exist in this
    // namespace; without this the run dies at startup rather than testing.
    assign_mock_addresses().await?;
    driver.current = "local-mock-startup".into();
    driver.mocks = Some(Mocks::start(&driver.secret).await?);
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
    let policy = config.effective_policy()?;
    driver.policy_hash = policy.hash()?;
    let rootfs_bytes = std::fs::metadata(&driver.runtime.config.rootfs)?.len();
    let disk_mb = rootfs_bytes.div_ceil(1024 * 1024).max(512);
    for _ in 0..2 {
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
        sandbox.environment.guard = Some(config.clone());
        sandbox.environment.guard_policy_hash = Some(driver.policy_hash.clone());
        driver.sandboxes.push(sandbox.clone());
        driver.runtime.create(&sandbox).await?;
        driver.runtime.start(&sandbox).await?;
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
            .await?;
    }
    let first = driver.sandboxes[0].clone();
    let second = driver.sandboxes[1].clone();
    let attachment = driver.attachment(&first)?;
    let peer_attachment = driver.attachment(&second)?;
    driver.case("real-firecracker-two-guarded-sandboxes", true,
        json!({"primary":attachment,"peer":peer_attachment,"vcpu_each":1,"memory_mib_each":512,"disk_mib_each":disk_mb,"policy_hash":driver.policy_hash}))?;
    for sandbox in [&first, &second] {
        let persisted: Value = serde_json::from_slice(&std::fs::read(
            driver.guard_dir(sandbox).join("effective-policy.json"),
        )?)?;
        if persisted["policy_hash"] != driver.policy_hash {
            return Err(failure("persisted effective policy hash differs"));
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
    driver.case(
        "real-guest-model-dns",
        dns["addresses"] == json!([attachment.gateway_ip.to_string()]),
        dns,
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
                && denials
                    .iter()
                    .any(|event| event.reason == "DNS name or record type denied"),
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
    driver.case("ipv6-route-preparation",ipv6["configured"]==true,json!({"guest":ipv6,"host_gateway":"fd00:beef::1","guest_address":"fd00:beef::2","permanent_neighbor":mac}))?;
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

#[tokio::main]
async fn main() {
    let initialized = (|| -> Result<Driver> {
        if std::fs::read_link("/proc/self/ns/net")? == std::fs::read_link("/proc/1/ns/net")? {
            return Err(failure("refusing host network namespace"));
        }
        let root = PathBuf::from(std::env::var("AIEC_GUARD_ACCEPTANCE_STATE")?);
        if !root.is_dir() {
            return Err(failure("launcher-created private state directory required"));
        }
        let operator = root.join("operator");
        std::fs::create_dir(&operator)?;
        std::fs::set_permissions(&operator, std::fs::Permissions::from_mode(0o700))?;
        let secret = format!("guard-synthetic-{}-{}", Uuid::now_v7(), Uuid::now_v7());
        let credentials = operator.join("credentials.json");
        private_file(&credentials, &json!({"model-main":secret}))?;
        let boundary: OperatorBoundary = serde_json::from_value(
            json!({"blocked_cidrs":[],"protected_cidrs":["198.18.0.20/32","198.18.0.21/32"],"blocked_hosts":[],"test_destinations":{format!("{MODEL_HOST}:18080"):["198.18.0.10"]}}),
        )?;
        let boundary_path = operator.join("boundary.json");
        private_file(&boundary_path, &serde_json::to_value(&boundary)?)?;
        let state = root.join("runtime");
        let mut config = FirecrackerConfig::from_env()?;
        config.state_dir = state.clone();
        config.jailer = None;
        config.tap = None;
        config.readiness_timeout = Duration::from_secs(45);
        let network = GuardNetworkManager::new(state.join("guard"))
            .with_operator_files(Some(boundary_path), Some(credentials))
            .with_local_test_mode();
        Ok(Driver {
            runtime: FirecrackerRuntime::with_network_backend(config, Arc::new(network)),
            sandboxes: Vec::new(),
            state,
            boundary,
            policy_hash: String::new(),
            secret,
            mocks: None,
            cases: Vec::new(),
            current: "initialization".into(),
            started: Instant::now(),
        })
    })();
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
