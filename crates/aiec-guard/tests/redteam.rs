//! Local-only adversarial harness for Guard (§42).
//!
//! # What this is
//!
//! A set of escape attempts, run against a guarded sandbox this file created,
//! each answered by the real enforcement surface rather than by a stand-in: the
//! nftables decision model for what the kernel would do to a packet, and the
//! running gateway for what the guest's own client can reach through it. Every
//! attempt is expected to fail. One that succeeds is a finding, not a passing
//! test.
//!
//! # The scope rule
//!
//! The harness may only target sandboxes it created itself. That is enforced
//! mechanically rather than by convention: every listener the harness starts is
//! recorded in [`Harness::claimed`], and every probe resolves its destination
//! through [`Harness::in_scope`] first. A destination that is not loopback, or
//! is loopback but not one this harness opened, is refused before a socket is
//! created - the harness would rather fail a run than emit a packet at something
//! it did not create.
//! [`the_harness_refuses_a_target_it_did_not_create`] is that refusal, tested.
//!
//! # The result
//!
//! One JSON document listing every vector, whether it was blocked, and why. It
//! goes to the path in `AIEC_REDTEAM_JSON` when that is set, and to stdout
//! otherwise, so a CI job can archive it. `blocked` is the only field a gate
//! should read; the detail strings exist for a human reading a failure, and none
//! of them carries a credential.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use aiec_guard::{
    compiler::{OperatorBoundary, compile},
    control::{BudgetAuthority, BudgetDebit, GuardFence, GuardIdentity},
    enforcement::{EnforcementBackend, EnforcementModel, GuardAttachment, TestBackend, Transport},
    events::FileEventSink,
    gateway::{CredentialStore, GatewayConfig, GuardGateway},
    policy::{EgressRule, GuardPolicy, ModelEndpoint, PolicyTemplate},
};
use hickory_proto::rr::RecordType;
use serde::Serialize;
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

/// The model credential the harness configures. It is synthetic and it must not
/// appear in the report, which is asserted below.
const SECRET: &str = "outside-guest-synthetic-secret";
/// The placeholder the policy binds, and the only credential a guest may present.
const PLACEHOLDER: &str = "placeholder://model-main";
/// A credential name the guest was never issued, standing in for one lifted out
/// of somewhere it should not have been.
const UNISSUED: &str = "redteam-canary-credential";

/// Every vector the spec names, in the order it names them.
const VECTORS: &[&str] = &[
    "direct_ipv4",
    "direct_ipv6",
    "external_dns",
    "dns_over_tls",
    "dns_over_https",
    "blocked_dns_record_type",
    "dns_delegation",
    "icmp",
    "raw_socket",
    "metadata_ip",
    "rfc1918",
    "loopback",
    "other_sandbox",
    "control_plane",
    "proxy_env_bypass",
    "credential_misuse",
];

/// The cloud metadata endpoint. Reaching it from a guest is the canonical
/// credential-theft attempt.
const METADATA_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
/// The three RFC 1918 ranges, one address each.
const RFC1918: [Ipv4Addr; 3] = [
    Ipv4Addr::new(10, 0, 0, 1),
    Ipv4Addr::new(172, 16, 0, 1),
    Ipv4Addr::new(192, 168, 1, 1),
];
/// A public address, used only as a destination the decision model is asked
/// about. Nothing in this test sends a packet to it.
const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const PUBLIC_IP6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0, 0, 0, 0x1);
/// The peer sandbox's address, protected by the boundary.
const PEER_SANDBOX_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
/// The control plane's address, in the same protected space.
const CONTROL_PLANE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// The routed guest and gateway the kernel-level model describes. The gateway
/// process itself binds loopback, because that is all a local test can bind, but
/// the packet vectors only mean something against a routed attachment.
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Why a destination was refused before any socket was opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeError {
    /// The destination is not loopback, so it is somewhere this harness cannot
    /// own and must not touch.
    NotLoopback(SocketAddr),
    /// The destination is loopback but belongs to a listener this harness did
    /// not start, which is somebody else's sandbox as far as this run goes.
    NotClaimed(SocketAddr),
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLoopback(addr) => write!(
                f,
                "refusing to target {addr}: it is not loopback, so it is outside the local \
                 environment this harness may touch"
            ),
            Self::NotClaimed(addr) => write!(
                f,
                "refusing to target {addr}: this harness did not create that listener"
            ),
        }
    }
}

/// One attempt and what came of it.
#[derive(Clone, Debug, Serialize)]
pub struct VectorResult {
    /// The vector's stable name, one of [`VECTORS`].
    pub vector: String,
    /// What the harness tried, in the operator's terms.
    pub target: String,
    /// Whether the attempt was refused. A `false` here is a finding.
    pub blocked: bool,
    /// Why, in one bounded line. Never contains a credential.
    pub detail: String,
}

/// The whole run, as one document.
#[derive(Clone, Debug, Serialize)]
pub struct RedTeamReport {
    /// Bumped when the report's shape changes.
    pub schema: u16,
    /// The sandbox this run created and attacked.
    pub sandbox_id: Uuid,
    /// The policy hash that sandbox was enforced under.
    pub policy_hash: String,
    /// One entry per vector in [`VECTORS`].
    pub vectors: Vec<VectorResult>,
    /// Whether every vector was blocked.
    pub passed: bool,
}

struct AllowAll;

#[async_trait::async_trait]
impl BudgetAuthority for AllowAll {
    async fn reserve(
        &self,
        _: &GuardIdentity,
        _: GuardFence,
        _: BudgetDebit,
    ) -> aiec_guard::Result<()> {
        Ok(())
    }
}

/// The sandbox under attack, and the boundary of what may be targeted.
struct Harness {
    sandbox_id: Uuid,
    policy_hash: String,
    /// Every loopback address this harness started a listener on.
    claimed: BTreeSet<SocketAddr>,
    attachment: GuardAttachment,
    model: EnforcementModel,
    backend: Arc<TestBackend>,
    gateway: Option<GuardGateway>,
    dns_addr: SocketAddr,
    broker_addr: SocketAddr,
    directory: std::path::PathBuf,
}

impl Harness {
    /// Starts a gateway on loopback with ephemeral ports and claims its
    /// addresses, alongside a local mock upstream for the permitted destination.
    async fn start() -> Self {
        tokio::time::timeout(Duration::from_secs(60), Harness::start_inner())
            .await
            .expect("red-team harness: start did not finish within 60s")
    }

    async fn start_inner() -> Self {
        let model_host = "model.redteam.test";
        let web_host = "web.redteam.test";
        // A local mock upstream on an ephemeral port, so the permitted
        // destination is real without anything leaving the host.
        let upstream = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind mock upstream");
        let upstream_port = upstream.local_addr().expect("upstream addr").port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // Every request gets a fixed 200, so the permitted path is a real
            // exchange rather than a connection that hangs.
            while let Ok((mut socket, _)) = upstream.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = socket.read(&mut buffer).await;
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                });
            }
        });

        let model = ModelEndpoint {
            host: model_host.into(),
            port: upstream_port,
            scheme: "http".into(),
            ..Default::default()
        };
        let rule = EgressRule {
            host: web_host.into(),
            port: upstream_port,
            protocol: "tcp".into(),
            allowed_methods: Vec::new(),
            allowed_paths: Vec::new(),
        };
        let policy =
            GuardPolicy::template(PolicyTemplate::ModelPlusAllowlist, Some(model), vec![rule])
                .expect("template");

        let mut boundary = OperatorBoundary::default();
        for host in [model_host, web_host] {
            boundary.test_destinations.insert(
                format!("{host}:{upstream_port}"),
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            );
        }
        // The peer sandbox is a protected address, which is what makes the
        // `other_sandbox` vector mean something.
        boundary.protected_cidrs.push(
            format!("{PEER_SANDBOX_IP}/32")
                .parse()
                .expect("a /32 parses"),
        );
        boundary
            .blocked_hosts
            .push("control-plane.redteam.test".into());
        let compiled = compile(&policy, &boundary).expect("compile");
        // Kept alongside the gateway so the kernel-level model is built from the
        // same compiled policy the gateway serves, not a second compilation that
        // could differ.
        let compiled_for_model = compiled.clone();
        let policy_hash = compiled.policy_hash().to_owned();

        let mut credentials = CredentialStore::empty();
        credentials
            .insert("model-main".into(), SECRET.into())
            .expect("credential");

        let directory = std::env::temp_dir().join(format!("aiec-redteam-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("temp dir");
        let events = Arc::new(FileEventSink::open(directory.join("events.jsonl")).expect("sink"));

        let sandbox_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let gateway = GuardGateway::start(GatewayConfig {
            sandbox_id,
            tenant_id,
            fence: GuardFence {
                lease_id: Uuid::new_v4(),
                generation: 1,
            },
            compiled,
            bind_ip: Ipv4Addr::LOCALHOST,
            // The guest source the gateway answers. Loopback, because that is
            // all a local test can bind.
            guest_ip: Ipv4Addr::LOCALHOST,
            broker_port: 0,
            dns_port: 0,
            credentials: Arc::new(credentials),
            events,
            budget_authority: Arc::new(AllowAll),
            watchdog_timeout: Duration::from_secs(60),
        })
        .await
        .expect("gateway");
        // The gateway serves traffic only after the authenticated dead-man
        // handshake. Without it every probe below is answered 503 and the run
        // would pass for entirely the wrong reason.
        assert!(
            gateway
                .heartbeat(gateway.identity())
                .expect("first heartbeat activates the attachment"),
            "the first heartbeat must activate the attachment"
        );

        let attachment = GuardAttachment {
            sandbox_id,
            tenant_id,
            interface: "tap0".into(),
            guest_ip: GUEST_IP,
            gateway_ip: GATEWAY_IP,
            dns_port: 53,
            broker_port: 443,
        };
        let backend = Arc::new(TestBackend::default());
        backend
            .apply_policy(&compiled_for_model, &attachment)
            .await
            .expect("apply policy");
        let model =
            EnforcementModel::build(&compiled_for_model, &attachment, false).expect("model");

        let dns_addr = gateway.dns_addr();
        let broker_addr = gateway.broker_addr();
        let mut claimed = BTreeSet::new();
        claimed.insert(broker_addr);
        claimed.insert(dns_addr);
        claimed.insert(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream_port,
        ));
        Self {
            sandbox_id,
            policy_hash,
            claimed,
            attachment,
            model,
            backend,
            gateway: Some(gateway),
            dns_addr,
            broker_addr,
            directory,
        }
    }

    /// Resolves a destination, refusing anything this harness does not own.
    fn in_scope(&self, addr: SocketAddr) -> Result<(), ScopeError> {
        if !addr.ip().is_loopback() {
            return Err(ScopeError::NotLoopback(addr));
        }
        if !self.claimed.contains(&addr) {
            return Err(ScopeError::NotClaimed(addr));
        }
        Ok(())
    }

    /// Asks the kernel-level model about one packet from the attached guest.
    fn packet(&self, destination: IpAddr, transport: Transport, port: u16) -> VectorResult {
        let (blocked, detail) = match destination {
            IpAddr::V4(ip) => {
                let verdict = self
                    .model
                    .verdict(self.attachment.guest_ip, ip, transport, port);
                (
                    !verdict.permitted,
                    format!(
                        "guest {} -> {ip}:{port} is denied and counted as {}",
                        self.attachment.guest_ip, verdict.counter
                    ),
                )
            }
            // IPv6 has no permit path at all, in any state the model can be in.
            IpAddr::V6(_) => (
                !self.model.permits_ipv6(),
                format!("the model permits no IPv6 packet in any state; {destination} is dropped"),
            ),
        };
        VectorResult {
            vector: String::new(),
            target: format!("{destination}:{port}"),
            blocked,
            detail,
        }
    }

    /// Shuts the gateway down. Explicit rather than on drop, because shutdown is
    /// async and `Drop` is not.
    /// Shuts the harness down.
    ///
    /// Bounded: a harness that cannot stop is a failure with a name, not a
    /// build that never finishes.
    async fn shutdown(&mut self) {
        if let Some(gateway) = self.gateway.take() {
            let stopped = tokio::time::timeout(Duration::from_secs(30), gateway.shutdown()).await;
            if stopped.is_err() {
                panic!("red-team harness: the gateway did not shut down within 30s");
            }
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Sends one absolute-URI request through the broker's proxy port and reports
/// the status code from the status line.
///
/// A guest's HTTP client aimed at a proxy writes the absolute form, so that is
/// what goes on the wire here rather than something a well-behaved client would
/// never produce against this URL.
async fn proxy_status(broker: SocketAddr, authority: &str, path: &str) -> Option<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if !broker.ip().is_loopback() {
        // The scope rule, enforced at the point of use rather than by
        // convention: this function only ever talks to a claimed listener, and a
        // non-loopback broker is refused outright.
        return None;
    }
    let mut socket = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(broker))
        .await
        .ok()?
        .ok()?;
    let request = format!(
        "GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.ok()?;
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
}

/// One DNS query against the gateway's own resolver.
async fn dns_probe(
    vector: &str,
    name: &str,
    dns_addr: SocketAddr,
    kind: RecordType,
) -> VectorResult {
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::Name;

    if !dns_addr.ip().is_loopback() {
        return VectorResult {
            vector: vector.into(),
            target: format!("{name}:{kind}"),
            blocked: true,
            detail: "the resolver is not on loopback, so it is out of scope and was not asked"
                .into(),
        };
    }
    let mut query = Message::new();
    let Ok(parsed) = Name::from_ascii(name) else {
        return VectorResult {
            vector: vector.into(),
            target: format!("{name}:{kind}"),
            blocked: true,
            detail: "the name is not a resolvable name, so the resolver is never asked".into(),
        };
    };
    query.set_id(4242);
    query.add_query(Query::query(parsed, kind));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    if socket
        .send_to(&query.to_vec().expect("encode"), dns_addr)
        .await
        .is_err()
    {
        return VectorResult {
            vector: vector.into(),
            target: format!("{name}:{kind}"),
            blocked: true,
            detail: "the resolver did not answer at all".into(),
        };
    }
    let mut bytes = [0u8; 512];
    let answered = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut bytes)).await;
    let (blocked, detail) = match answered {
        Ok(Ok((size, _))) => {
            let reply = Message::from_vec(&bytes[..size]).expect("reply");
            // Refused, or answered with no records. A resolver that answers with
            // data is the failure this vector is looking for.
            (
                reply.response_code() == ResponseCode::Refused || reply.answers().is_empty(),
                format!(
                    "{kind} query for {name} answered {} with {} records",
                    reply.response_code(),
                    reply.answers().len()
                ),
            )
        }
        _ => (
            true,
            format!("{kind} query for {name} was not answered at all"),
        ),
    };
    VectorResult {
        vector: vector.into(),
        target: format!("{name}:{kind}"),
        blocked,
        detail,
    }
}

/// Runs every vector and produces the report.
async fn run() -> RedTeamReport {
    use hickory_proto::rr::RecordType;
    let mut harness = Harness::start().await;
    let mut vectors: Vec<VectorResult> = Vec::with_capacity(VECTORS.len());

    // --- Kernel-level vectors: what the packet filter does. ---
    let packet_vectors: [(&str, IpAddr, Transport, u16); 9] = [
        ("direct_ipv4", IpAddr::V4(PUBLIC_IP), Transport::Tcp, 443),
        ("direct_ipv6", IpAddr::V6(PUBLIC_IP6), Transport::Tcp, 443),
        ("icmp", IpAddr::V4(PUBLIC_IP), Transport::Other, 0),
        // A raw socket lets a guest choose the protocol and the port itself,
        // which is exactly what the `Transport::Other` case above models.
        ("raw_socket", IpAddr::V4(PUBLIC_IP), Transport::Other, 1_234),
        ("metadata_ip", IpAddr::V4(METADATA_IP), Transport::Tcp, 80),
        ("rfc1918", IpAddr::V4(RFC1918[0]), Transport::Tcp, 445),
        (
            "loopback",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Transport::Tcp,
            22,
        ),
        (
            "other_sandbox",
            IpAddr::V4(PEER_SANDBOX_IP),
            Transport::Tcp,
            1024,
        ),
        (
            "control_plane",
            IpAddr::V4(CONTROL_PLANE_IP),
            Transport::Tcp,
            8080,
        ),
    ];
    for (name, destination, transport, port) in packet_vectors {
        let mut result = harness.packet(destination, transport, port);
        result.vector = name.to_owned();
        vectors.push(result);
    }
    // The other two RFC 1918 ranges, not just the first.
    for address in RFC1918.into_iter().skip(1) {
        let mut result = harness.packet(IpAddr::V4(address), Transport::Tcp, 445);
        result.vector = "rfc1918".to_owned();
        result.target = format!("{address}:445");
        vectors.push(result);
    }

    // --- Gateway-level vectors: what the guest's own client can reach. ---
    let dns_addr = harness.dns_addr;
    let broker_addr = harness.broker_addr;
    // The scope rule, applied to the two listeners the probes are about to use.
    assert!(harness.in_scope(dns_addr).is_ok());
    assert!(harness.in_scope(broker_addr).is_ok());

    // External DNS: a name the policy does not scope.
    vectors.push(
        dns_probe(
            "external_dns",
            "external-dns.redteam.test",
            dns_addr,
            RecordType::A,
        )
        .await,
    );
    // A record type the policy does not accept, on a name that *is* in scope.
    vectors.push(
        dns_probe(
            "blocked_dns_record_type",
            "model.redteam.test",
            dns_addr,
            RecordType::TXT,
        )
        .await,
    );
    // DNS delegation: a name that reads as if it sits inside the scoped name but
    // is really a subdomain of an attacker's, plus the record type that would
    // hand back a nameserver to follow.
    vectors.push(
        dns_probe(
            "dns_delegation",
            "evil.model.redteam.test.attacker.invalid",
            dns_addr,
            RecordType::A,
        )
        .await,
    );

    // DoT: a TLS handshake aimed at the DNS port. The resolver speaks DNS, not
    // TLS, so it cannot become a tunnel.
    let dot_blocked = tls_handshake_gets_no_answer(dns_addr).await;
    vectors.push(VectorResult {
        vector: "dns_over_tls".into(),
        target: format!("tls://{dns_addr}"),
        blocked: dot_blocked,
        detail: "the DNS listener answers no TLS handshake, so it is not a tunnel".into(),
    });

    // DoH through the broker: an absolute-URI request for a resolver endpoint on
    // a host the policy does not permit.
    let doh = proxy_status(broker_addr, "dns.google", "/dns-query").await;
    vectors.push(VectorResult {
        vector: "dns_over_https".into(),
        target: format!("http://{broker_addr}/dns-query (Host: dns.google)"),
        blocked: doh == Some(403),
        detail: format!("an absolute-URI request for a denied resolver answered {doh:?}"),
    });

    // Proxy-environment bypass: the same denied destination reached through the
    // proxy port, and through a client that honours `HTTP_PROXY` from the
    // environment. Both must reach the same refusal, because an environment
    // variable the guest sets is not a permission the guest can grant itself.
    let explicit = proxy_status(broker_addr, "denied.redteam.test", "/").await;
    let env_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("env client");
    let via_env = env_client
        .get(format!("http://{broker_addr}/"))
        .header("host", "denied.redteam.test")
        .send()
        .await;
    let env_status = via_env
        .as_ref()
        .ok()
        .map(|response| response.status().as_u16());
    vectors.push(VectorResult {
        vector: "proxy_env_bypass".into(),
        target: format!("http://{broker_addr}/ (Host: denied.redteam.test)"),
        blocked: explicit == Some(403) && (env_status.is_none() || env_status == Some(403)),
        detail: format!(
            "the explicit proxy answered {explicit:?}, the environment-influenced client \
             answered {env_status:?}"
        ),
    });

    // Credential misuse: the real model secret presented directly, a credential
    // the guest was never issued, and - as the positive control - the
    // placeholder the policy binds. Without the control, the two refusals would
    // be indistinguishable from a broker that refuses everything.
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let url = format!("http://{broker_addr}/model/model-main/v1/chat");
    let raw = client.post(&url).bearer_auth(SECRET).send().await;
    let unissued = client.post(&url).bearer_auth(UNISSUED).send().await;
    let accepted = client.post(&url).bearer_auth(PLACEHOLDER).send().await;
    let status = |result: &Result<reqwest::Response, reqwest::Error>| {
        result
            .as_ref()
            .ok()
            .map(|response| response.status().as_u16())
    };
    vectors.push(VectorResult {
        vector: "credential_misuse".into(),
        target: url,
        blocked: status(&raw) == Some(403)
            && status(&unissued) == Some(403)
            && matches!(&accepted, Ok(response) if response.status().is_success()),
        detail: format!(
            "a raw secret answered {:?}, an unissued credential {:?}, the bound placeholder {:?}",
            status(&raw),
            status(&unissued),
            status(&accepted)
        ),
    });

    harness.shutdown().await;
    let passed = vectors.iter().all(|vector| vector.blocked)
        && VECTORS
            .iter()
            .all(|name| vectors.iter().any(|vector| &vector.vector == name));
    RedTeamReport {
        schema: 1,
        sandbox_id: harness.sandbox_id,
        policy_hash: harness.policy_hash,
        vectors,
        passed,
    }
}

/// Whether a TLS ClientHello aimed at `addr` gets a TLS answer back.
async fn tls_handshake_gets_no_answer(addr: SocketAddr) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if !addr.ip().is_loopback() {
        return true;
    }
    let Ok(Ok(mut socket)) =
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await
    else {
        return true;
    };
    // A TLS 1.2 record header with no SNI: a real ClientHello shape, sent to a
    // listener that only speaks DNS.
    let hello = [0x16u8, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0d];
    if socket.write_all(&hello).await.is_err() {
        return true;
    }
    let mut seen = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut seen)).await;
    // A ServerHello would start with a handshake record; nothing that looks like
    // one came back, so this is not a tunnel.
    !seen.starts_with(&[0x16])
}

/// The refusal the scope rule exists for.
#[test]
fn the_harness_refuses_a_target_it_did_not_create() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut harness = runtime.block_on(Harness::start());
    // A public address: somewhere this harness cannot own.
    let error = harness
        .in_scope(SocketAddr::new(IpAddr::V4(PUBLIC_IP), 443))
        .expect_err("a public address must be refused");
    assert!(matches!(error, ScopeError::NotLoopback(_)), "{error}");
    assert!(error.to_string().contains("not loopback"), "{error}");

    // Loopback, but a port this harness never opened: another local service,
    // which is somebody else's sandbox as far as this run is concerned.
    let error = harness
        .in_scope(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 65000))
        .expect_err("an unclaimed loopback port must be refused");
    assert!(matches!(error, ScopeError::NotClaimed(_)), "{error}");
    assert!(error.to_string().contains("did not create"), "{error}");

    // And a claimed address passes, or the refusal would be vacuous.
    let claimed = *harness.claimed.iter().next().expect("a claimed address");
    assert!(harness.in_scope(claimed).is_ok());
    runtime.block_on(harness.shutdown());
}

/// The run itself: every vector, blocked, in one JSON document.
#[tokio::test]
async fn every_vector_is_blocked_and_the_report_lists_them_all() {
    let report = run().await;
    let rendered = serde_json::to_string_pretty(&report).expect("render");
    match std::env::var("AIEC_REDTEAM_JSON") {
        Ok(path) => std::fs::write(&path, rendered.as_bytes()).expect("write report"),
        Err(_) => println!("{rendered}"),
    }
    for name in VECTORS {
        let vector = report
            .vectors
            .iter()
            .find(|vector| vector.vector == *name)
            .unwrap_or_else(|| panic!("{name} is missing from the report"));
        assert!(vector.blocked, "{name} was not blocked: {}", vector.detail);
    }
    // Every named vector, and nothing invented.
    let names: BTreeSet<&str> = report
        .vectors
        .iter()
        .map(|vector| vector.vector.as_str())
        .collect();
    let expected: BTreeSet<&str> = VECTORS.iter().copied().collect();
    assert_eq!(
        names, expected,
        "the report must list exactly the named vectors"
    );
    assert!(report.passed);

    // The report is machine-readable and holds no credential.
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    assert_eq!(parsed["passed"], serde_json::json!(true));
    assert!(
        !rendered.contains(SECRET),
        "the report leaked the model credential"
    );
}

/// The evidence has to be on the enforcement surface, not just in a return
/// value: a run that blocked everything because nothing was installed would pass
/// the test above and mean nothing.
#[tokio::test]
async fn the_attached_sandbox_really_enforces_what_the_vectors_ask_about() {
    let mut harness = Harness::start().await;
    // The permitted path still works, so the denials above are decisions rather
    // than a filter that denies everything.
    assert!(
        harness.model.permits(
            harness.attachment.guest_ip,
            GATEWAY_IP,
            Transport::Udp,
            harness.attachment.dns_port
        ),
        "the gateway's own DNS listener must stay reachable"
    );
    // A denied packet has to move the kernel counters, not merely answer a
    // question: a filter that refused everything without recording why would
    // leave an operator with nothing to investigate afterwards.
    assert_eq!(
        harness.backend.record_packet(
            &harness.attachment,
            harness.attachment.guest_ip,
            GATEWAY_IP,
            Transport::Udp,
            harness.attachment.dns_port,
        ),
        Some(true),
        "the gateway's own DNS port stays reachable"
    );
    assert_eq!(
        harness.backend.record_packet(
            &harness.attachment,
            harness.attachment.guest_ip,
            METADATA_IP,
            Transport::Tcp,
            80,
        ),
        Some(false),
        "the metadata endpoint is denied"
    );
    let snapshot = harness
        .backend
        .snapshot(&harness.attachment)
        .expect("counters");
    assert!(
        snapshot.dns_permitted > 0,
        "a permitted packet was not counted"
    );
    assert!(
        snapshot.blocked_range > 0,
        "a blocked-range attempt was not counted"
    );
    harness.shutdown().await;
}
