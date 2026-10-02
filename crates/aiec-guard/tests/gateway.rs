use aiec_guard::{
    compiler::{OperatorBoundary, compile},
    control::{BudgetAuthority, BudgetDebit, GuardFence, GuardIdentity},
    enforcement::{GuardAttachment, TestBackend},
    events::{EventInput, EventSink, FileEventSink, GuardEvent, read_events},
    gateway::{CredentialStore, GatewayConfig, GuardGateway},
    policy::{EgressRule, GuardPolicy, ModelEndpoint, PolicyTemplate},
    proposals::{
        AgentCredential, EgressGrant, HumanApproval, ProposalRequest, ProposalStore,
        ProposalStoreConfig,
    },
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, Response},
};
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Notify,
    task::JoinHandle,
};
use uuid::Uuid;

const SECRET: &str = "outside-guest-synthetic-secret";

struct SeenRequest {
    authorization: String,
    host: String,
    body: Vec<u8>,
}

#[derive(Clone)]
struct Mock {
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    release: Arc<Notify>,
}

async fn upstream(State(mock): State<Mock>, request: Request<Body>) -> Response<Body> {
    let path = request.uri().path().to_owned();
    let auth = request
        .headers()
        .get("authorization")
        .or_else(|| request.headers().get("x-api-key"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let host = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let Ok(body) = to_bytes(request.into_body(), 1024 * 1024).await else {
        return Response::builder().status(400).body(Body::empty()).unwrap();
    };
    mock.seen.lock().push(SeenRequest {
        authorization: auth,
        host,
        body: body.to_vec(),
    });
    if path == "/v1/redirect" {
        return Response::builder()
            .status(302)
            .header("location", "http://denied.guard.test/stolen")
            .body(Body::empty())
            .unwrap();
    }
    if path == "/v1/stream" {
        let release = mock.release.clone();
        let stream = stream::unfold((0, release), |(n, release)| async move {
            match n {
                0 => Some((
                    Ok::<_, std::io::Error>(Bytes::from_static(b"data: first\n\n")),
                    (1, release),
                )),
                1 => {
                    release.notified().await;
                    Some((Ok(Bytes::from_static(b"data: [DONE]\n\n")), (2, release)))
                }
                _ => None,
            }
        });
        return Response::builder()
            .header("content-type", "text/event-stream")
            .body(Body::from_stream(stream))
            .unwrap();
    }
    if path == "/v1/oversize" {
        let stream = stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"12345678")),
            Ok(Bytes::from_static(b"12345678")),
            Ok(Bytes::from_static(b"12345678")),
        ]);
        return Response::new(Body::from_stream(stream));
    }
    Response::new(Body::from("ok"))
}
struct Fixture {
    gateway: Option<GuardGateway>,
    identity: GuardIdentity,
    control: aiec_guard::gateway::GatewayControl,
    mock: Mock,
    server: JoinHandle<()>,
    port: u16,
    directory: std::path::PathBuf,
}

struct AllowAllAuthority;

#[async_trait::async_trait]
impl BudgetAuthority for AllowAllAuthority {
    async fn reserve(
        &self,
        _: &GuardIdentity,
        _: GuardFence,
        _: BudgetDebit,
    ) -> aiec_guard::Result<()> {
        Ok(())
    }
}

/// Records every reservation so a test can prove what was committed before bytes moved.
struct RecordingAuthority {
    admitted: Mutex<Vec<BudgetDebit>>,
    reachable: bool,
}

impl RecordingAuthority {
    fn debits(&self) -> Vec<BudgetDebit> {
        self.admitted.lock().clone()
    }
}

#[async_trait::async_trait]
impl BudgetAuthority for RecordingAuthority {
    async fn reserve(
        &self,
        _: &GuardIdentity,
        _: GuardFence,
        debit: BudgetDebit,
    ) -> aiec_guard::Result<()> {
        if !self.reachable {
            return Err(aiec_guard::GuardError::Unavailable(
                "durable authority unreachable".into(),
            ));
        }
        self.admitted.lock().push(debit);
        Ok(())
    }
}

struct DeadAuthority {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait::async_trait]
impl BudgetAuthority for DeadAuthority {
    async fn reserve(
        &self,
        _: &GuardIdentity,
        _: GuardFence,
        _: BudgetDebit,
    ) -> aiec_guard::Result<()> {
        self.started.notify_one();
        self.release.notified().await;
        Err(aiec_guard::GuardError::Unavailable(
            "durable authority unreachable".into(),
        ))
    }
}
impl Fixture {
    async fn new(adjust: impl FnOnce(&mut GuardPolicy)) -> Self {
        let fixture = Self::configured(adjust, |sink| sink, None, 60_000).await;
        // Every fixture activates only through the authenticated dead-man path.
        assert!(
            fixture
                .gateway()
                .heartbeat(&fixture.identity)
                .expect("first heartbeat")
        );
        fixture
    }

    async fn with_authority(
        adjust: impl FnOnce(&mut GuardPolicy),
        authority: Arc<dyn BudgetAuthority>,
    ) -> Self {
        Self::configured(adjust, |sink| sink, Some(authority), 60_000).await
    }

    async fn configured(
        adjust: impl FnOnce(&mut GuardPolicy),
        map_sink: impl FnOnce(Arc<FileEventSink>) -> Arc<dyn EventSink>,
        authority: Option<Arc<dyn BudgetAuthority>>,
        watchdog_timeout_ms: u64,
    ) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mock = Mock {
            seen: Arc::new(Mutex::new(Vec::new())),
            release: Arc::new(Notify::new()),
        };
        let router = Router::new().fallback(upstream).with_state(mock.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let model = ModelEndpoint {
            host: "model.guard.test".into(),
            port,
            scheme: "http".into(),
            ..Default::default()
        };
        let rule = EgressRule {
            host: "web.guard.test".into(),
            port,
            protocol: "tcp".into(),
            allowed_methods: Vec::new(),
            allowed_paths: Vec::new(),
        };
        let mut policy =
            GuardPolicy::template(PolicyTemplate::ModelPlusAllowlist, Some(model), vec![rule])
                .unwrap();
        adjust(&mut policy);
        let mut boundary = OperatorBoundary::default();
        for host in ["model.guard.test", "web.guard.test"] {
            boundary.test_destinations.insert(
                format!("{host}:{port}"),
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            );
        }
        let compiled = compile(&policy, &boundary).unwrap();
        let mut credentials = CredentialStore::empty();
        credentials
            .insert("model-main".into(), SECRET.into())
            .unwrap();
        let directory = std::env::temp_dir().join(format!("aiec-guard-gateway-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let events = Arc::new(FileEventSink::open(directory.join("events.jsonl")).unwrap());
        let gateway = GuardGateway::start(GatewayConfig {
            sandbox_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            fence: GuardFence {
                lease_id: Uuid::new_v4(),
                generation: 1,
            },
            compiled,
            bind_ip: Ipv4Addr::LOCALHOST,
            guest_ip: Ipv4Addr::LOCALHOST,
            broker_port: 0,
            dns_port: 0,
            credentials: Arc::new(credentials),
            events: map_sink(events.clone()),
            budget_authority: authority.unwrap_or_else(|| Arc::new(AllowAllAuthority)),
            watchdog_timeout: Duration::from_millis(watchdog_timeout_ms),
        })
        .await
        .unwrap();
        let control = gateway.control();
        Self {
            gateway: Some(gateway),
            identity: control.identity(),
            control,
            mock,
            server,
            port,
            directory,
        }
    }

    async fn with_sink(
        adjust: impl FnOnce(&mut GuardPolicy),
        map_sink: impl FnOnce(Arc<FileEventSink>) -> Arc<dyn EventSink>,
    ) -> Self {
        Self::configured(adjust, map_sink, None, 60_000).await
    }
    fn gateway(&self) -> &GuardGateway {
        self.gateway.as_ref().unwrap()
    }
    fn url(&self, path: &str) -> String {
        format!(
            "http://{}/model/model-main{path}",
            self.gateway().broker_addr()
        )
    }
    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }
    async fn finish(mut self) -> Vec<aiec_guard::events::GuardEvent> {
        self.gateway.take().unwrap().shutdown().await.unwrap();
        read_events(&self.directory.join("events.jsonl")).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn bound_placeholder_streams_before_upstream_completion_and_never_leaks_secret() {
    let f = Fixture::new(|_| {}).await;
    let response = f
        .client()
        .post(f.url("/v1/stream"))
        .bearer_auth("placeholder://model-main")
        .body("prompt")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut stream = response.bytes_stream();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Bytes::from_static(b"data: first\n\n")
    );
    f.mock.release.notify_one();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(b"data: [DONE]\n\n")
    );
    assert!(stream.next().await.is_none());
    {
        let seen = f.mock.seen.lock();
        assert_eq!(seen[0].authorization, format!("Bearer {SECRET}"));
        assert_eq!(seen[0].host, format!("model.guard.test:{}", f.port));
        assert_eq!(seen[0].body, b"prompt");
    }
    let events = f.finish().await;
    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains(SECRET));
    assert!(!serialized.contains("prompt"));
    assert!(
        events
            .iter()
            .any(|e| e.request_bytes == 6 && e.response_bytes == 27)
    );
}

#[tokio::test]
async fn mismatched_binding_authority_path_redirect_and_proxy_credentials_are_denied() {
    let f = Fixture::new(|_| {}).await;
    let c = f.client();
    for (path, placeholder, host) in [
        ("/v1/echo", "placeholder://wrong", None),
        ("/v10/echo", "placeholder://model-main", None),
        (
            "/v1/echo",
            "placeholder://model-main",
            Some("model.guard.test"),
        ),
    ] {
        let mut request = c.post(f.url(path)).bearer_auth(placeholder);
        if let Some(host) = host {
            request = request.header("host", host);
        }
        assert_eq!(request.send().await.unwrap().status(), 403);
    }
    assert_eq!(
        c.post(f.url("/v1/redirect"))
            .bearer_auth("placeholder://model-main")
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    let proxy = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::http(format!("http://{}", f.gateway().broker_addr())).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        proxy
            .get(format!("http://web.guard.test:{}/echo", f.port))
            .bearer_auth("placeholder://model-main")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        proxy
            .get(format!("http://model.guard.test:{}/v1/echo", f.port))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        proxy
            .get(format!("http://web.guard.test:{}/echo", f.port))
            .header("host", "denied.guard.test")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        proxy
            .get(format!("http://web.guard.test:{}/echo", f.port))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    assert_eq!(f.mock.seen.lock().len(), 2);
    f.finish().await;
}

#[tokio::test]
async fn known_and_chunked_request_sizes_and_streaming_response_budget_are_enforced() {
    let f = Fixture::new(|p| {
        p.limits.max_request_bytes = 8;
        p.limits.max_response_bytes = 16;
    })
    .await;
    let c = f.client();
    assert_eq!(
        c.post(f.url("/v1/echo"))
            .bearer_auth("placeholder://model-main")
            .body("123456789")
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    let upload = stream::iter([
        Ok::<_, std::io::Error>(Bytes::from_static(b"12345")),
        Ok(Bytes::from_static(b"67890")),
    ]);
    let result = c
        .post(f.url("/v1/echo"))
        .bearer_auth("placeholder://model-main")
        .body(reqwest::Body::wrap_stream(upload))
        .send()
        .await;
    if let Ok(response) = result {
        assert!(!response.status().is_success());
    }
    if let Ok(response) = c
        .post(f.url("/v1/oversize"))
        .bearer_auth("placeholder://model-main")
        .send()
        .await
    {
        assert!(response.bytes().await.is_err());
    }
    f.finish().await;
}

#[tokio::test]
async fn concurrency_cut_restore_and_nonrefundable_session_budgets_hold() {
    let f = Fixture::new(|p| {
        p.limits.max_concurrent_requests = 1;
        p.limits.bytes_in = 16;
        p.limits.max_response_bytes = 16;
    })
    .await;
    let c = f.client();
    let first = c
        .post(f.url("/v1/stream"))
        .bearer_auth("placeholder://model-main")
        .send()
        .await
        .unwrap();
    let mut stream = first.bytes_stream();
    assert_eq!(stream.next().await.unwrap().unwrap().len(), 13);
    assert_eq!(
        c.post(f.url("/v1/echo"))
            .bearer_auth("placeholder://model-main")
            .send()
            .await
            .unwrap()
            .status(),
        429
    );
    f.gateway().cut().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .is_none_or(|r| r.is_err())
    );
    drop(stream);
    // A release takes effect only after its audit record is durable, and
    // `restore` returns only once that has happened, so the next request here
    // is not racing the audit worker.
    f.gateway().restore().await.unwrap();
    // The first stream debited 13 bytes; disconnect leaves only three bytes available.
    let response = c
        .post(f.url("/v1/echo"))
        .bearer_auth("placeholder://model-main")
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "ok");
    if let Ok(response) = c
        .post(f.url("/v1/echo"))
        .bearer_auth("placeholder://model-main")
        .send()
        .await
    {
        assert!(response.bytes().await.is_err());
    }
    f.finish().await;
}

async fn udp_query(f: &Fixture, name: &str, kind: RecordType) -> Message {
    let mut query = Message::new();
    query
        .set_id(55)
        .add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(&query.to_vec().unwrap(), f.gateway().dns_addr())
        .await
        .unwrap();
    let mut bytes = [0; 512];
    let (size, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&bytes[..size]).unwrap()
}
#[tokio::test]
async fn authoritative_dns_maps_model_and_refuses_unknown_names_and_types() {
    let f = Fixture::new(|_| {}).await;
    let model = udp_query(&f, "model.guard.test", RecordType::A).await;
    assert_eq!(model.response_code(), ResponseCode::NoError);
    assert!(!model.recursion_available());
    assert_eq!(
        model.answers()[0].data(),
        &RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::LOCALHOST))
    );
    assert_eq!(
        udp_query(&f, "not-allowed.guard.test", RecordType::A)
            .await
            .response_code(),
        ResponseCode::Refused
    );
    assert_eq!(
        udp_query(&f, "model.guard.test", RecordType::TXT)
            .await
            .response_code(),
        ResponseCode::Refused
    );
    let web = udp_query(&f, "web.guard.test", RecordType::A).await;
    assert_eq!(web.response_code(), ResponseCode::NoError);
    let mut socket = TcpStream::connect(f.gateway().dns_addr()).await.unwrap();
    socket.write_u16(4097).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(
            &[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1],
            f.gateway().dns_addr(),
        )
        .await
        .unwrap();
    let mut bytes = [0; 512];
    let (size, _) = socket.recv_from(&mut bytes).await.unwrap();
    assert_eq!(
        Message::from_vec(&bytes[..size]).unwrap().response_code(),
        ResponseCode::FormErr
    );
    f.finish().await;
}

#[tokio::test]
async fn dns_rate_and_record_type_policy_apply_before_resolution() {
    let f = Fixture::new(|p| {
        p.limits.dns_queries_per_minute = 2;
        p.network.dns.allowed_record_types = vec!["A".into()];
    })
    .await;
    assert_eq!(
        udp_query(&f, "model.guard.test", RecordType::AAAA)
            .await
            .response_code(),
        ResponseCode::Refused
    );
    assert_eq!(
        udp_query(&f, "model.guard.test", RecordType::A)
            .await
            .response_code(),
        ResponseCode::NoError
    );
    assert_eq!(
        udp_query(&f, "model.guard.test", RecordType::A)
            .await
            .response_code(),
        ResponseCode::Refused
    );
    f.finish().await;
}

#[tokio::test]
async fn connect_rejects_sni_mismatch_before_contacting_upstream() {
    let f = Fixture::new(|_| {}).await;
    let mut socket = TcpStream::connect(f.gateway().broker_addr()).await.unwrap();
    socket
        .write_all(
            format!(
                "CONNECT web.guard.test:{} HTTP/1.1\r\nHost: web.guard.test:{}\r\n\r\n",
                f.port, f.port
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(socket.read_u8().await.unwrap());
    }
    assert!(header.starts_with(b"HTTP/1.1 200"));
    // A valid-looking TLS record with no ClientHello SNI is not a usable tunnel.
    socket
        .write_all(&[22, 3, 3, 0, 4, 1, 0, 0, 0])
        .await
        .unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(f.mock.seen.lock().is_empty());
    f.finish().await;
}

#[test]
fn credential_file_rejects_duplicates_insecure_permissions_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = std::env::temp_dir().join(format!("aiec-guard-credentials-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let file = directory.join("secret");
    std::fs::write(&file, r#"{"model-main":"one","model-main":"two"}"#).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(CredentialStore::from_file(&file).is_err());
    std::fs::write(&file, r#"{"model-main":"outside-only"}"#).unwrap();
    assert!(CredentialStore::from_file(&file).is_ok());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(CredentialStore::from_file(&file).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.join("link");
    symlink(&file, &link).unwrap();
    assert!(CredentialStore::from_file(&link).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn proxy_direct_ip_wrong_port_and_guest_source_cannot_bypass_policy() {
    let f = Fixture::new(|_| {}).await;
    let proxy = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::http(format!("http://{}", f.gateway().broker_addr())).unwrap())
        .build()
        .unwrap();
    for url in [
        format!("http://127.0.0.1:{}/echo", f.port),
        format!(
            "http://web.guard.test:{}/echo",
            if f.port == 65535 { 65534 } else { f.port + 1 }
        ),
    ] {
        assert_eq!(proxy.get(url).send().await.unwrap().status(), 403);
    }
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket
        .bind((Ipv4Addr::new(127, 0, 0, 2), 0).into())
        .unwrap();
    let mut socket = socket.connect(f.gateway().broker_addr()).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(f.mock.seen.lock().is_empty());
    let events = f.finish().await;
    assert!(
        events
            .iter()
            .any(|event| event.reason == "guest source mismatch")
    );
}

#[tokio::test]
async fn rejected_requests_count_toward_rate_and_disconnected_uploads_keep_outbound_debits() {
    let f = Fixture::new(|p| {
        p.limits.requests_per_minute = 3;
        p.limits.bytes_out = 8;
        p.limits.max_request_bytes = 8;
    })
    .await;
    let c = f.client();
    assert_eq!(
        c.post(f.url("/v1/echo"))
            .bearer_auth("placeholder://wrong")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        c.post(f.url("/v1/echo"))
            .bearer_auth("placeholder://model-main")
            .body("123456")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    if let Ok(response) = c
        .post(f.url("/v1/echo"))
        .bearer_auth("placeholder://model-main")
        .body("789")
        .send()
        .await
    {
        assert!(!response.status().is_success());
    }
    assert_eq!(
        c.post(f.url("/v1/echo"))
            .bearer_auth("placeholder://model-main")
            .send()
            .await
            .unwrap()
            .status(),
        429
    );
    assert_eq!(f.mock.seen.lock().len(), 1);
    f.finish().await;
}

#[tokio::test]
async fn visible_absolute_https_enforces_read_only_rules_and_does_not_fall_back_to_plaintext() {
    let f = Fixture::new(|p| {
        let rule = p
            .network
            .egress
            .iter_mut()
            .find(|r| r.host == "web.guard.test")
            .unwrap();
        rule.allowed_methods = vec!["GET".into()];
        rule.allowed_paths = vec!["/readonly/".into()];
    })
    .await;
    for (method, path, status) in [
        ("POST", "/readonly/item", 403),
        ("GET", "/elsewhere", 403),
        ("GET", "/readonly/item", 502),
    ] {
        let mut socket = TcpStream::connect(f.gateway().broker_addr()).await.unwrap();
        socket.write_all(format!("{method} https://web.guard.test:{}{path} HTTP/1.1\r\nHost: web.guard.test:{}\r\nConnection: close\r\n\r\n",f.port,f.port).as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(7), socket.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
    }
    // The upstream is HTTP-only: a secure request must fail TLS, never retry as cleartext.
    assert!(f.mock.seen.lock().is_empty());
    f.finish().await;
}

#[tokio::test]
async fn api_key_binding_is_exact_and_cannot_accept_an_alternate_authorization_header() {
    let f = Fixture::new(|p| {
        p.credentials[0].header = "x-api-key".into();
    })
    .await;
    let c = f.client();
    assert_eq!(
        c.post(f.url("/v1/echo"))
            .bearer_auth("placeholder://model-main")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        c.post(f.url("/v1/echo"))
            .header("x-api-key", "placeholder://wrong")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        c.post(f.url("/v1/echo"))
            .header("x-api-key", "placeholder://model-main")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    assert_eq!(f.mock.seen.lock()[0].authorization, SECRET);
    let events = f.finish().await;
    assert!(!serde_json::to_string(&events).unwrap().contains(SECRET));
}

struct FailOnceSink {
    inner: Arc<FileEventSink>,
    calls: AtomicUsize,
    failed: Arc<Notify>,
}

#[async_trait::async_trait]
impl EventSink for FailOnceSink {
    async fn append(&self, input: EventInput) -> aiec_guard::Result<GuardEvent> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            self.failed.notify_one();
            return Err(aiec_guard::GuardError::Unavailable(
                "injected journal outage".into(),
            ));
        }
        self.inner.append(input).await
    }
}

#[tokio::test]
async fn audit_failure_cannot_be_released_by_restore_after_the_sink_recovers() {
    let failed = Arc::new(Notify::new());
    let notify = failed.clone();
    let mut fixture = Fixture::with_sink(
        |_| {},
        move |inner| {
            Arc::new(FailOnceSink {
                inner,
                calls: AtomicUsize::new(0),
                failed: notify,
            })
        },
    )
    .await;
    assert!(
        fixture
            .gateway()
            .heartbeat(&fixture.identity)
            .expect("first heartbeat")
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let _ = client
        .post(fixture.url("/v1/echo"))
        .bearer_auth("placeholder://unknown")
        .body("{}")
        .send()
        .await;
    tokio::time::timeout(Duration::from_secs(2), failed.notified())
        .await
        .unwrap();
    let restored = fixture.gateway().restore().await;
    let _ = client
        .post(fixture.url("/v1/echo"))
        .bearer_auth("placeholder://model-main")
        .body("{}")
        .send()
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(1), fixture.gateway().restore()).await;
    let stopped = fixture.gateway.take().unwrap().shutdown().await;
    assert_eq!(
        fixture.mock.seen.lock().len(),
        0,
        "no request may reach upstream after lost authoritative evidence"
    );
    assert!(
        restored.is_err(),
        "a recovered sink is not a recovered gateway"
    );
    assert!(
        stopped.is_err(),
        "shutdown must retain the terminal audit fault"
    );
}

#[tokio::test]
async fn a_gateway_denies_until_the_first_authenticated_heartbeat_and_then_latches_closed() {
    let f = Fixture::configured(|_| {}, |sink| sink, None, 1_000).await;
    let client = f.client();
    let denied = client
        .post(f.url("/v1/echo"))
        .bearer_auth("placeholder://model-main")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 503);
    assert!(f.mock.seen.lock().is_empty(), "no watchdog means no egress");

    let foreign = GuardIdentity {
        sandbox_id: Uuid::new_v4(),
        tenant_id: f.identity.tenant_id,
        policy_hash: f.identity.policy_hash.clone(),
    };
    assert!(f.gateway().heartbeat(&foreign).is_err());
    assert!(f.mock.seen.lock().is_empty());

    assert!(f.gateway().heartbeat(&f.identity).expect("first heartbeat"));
    let allowed = client
        .post(f.url("/v1/echo"))
        .bearer_auth("placeholder://model-main")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.text().await.unwrap(), "ok");

    // A silently killed watchdog cuts every path and latches.
    tokio::time::sleep(Duration::from_millis(1_600)).await;
    assert!(f.control.network_cut());
    let refused = client
        .post(f.url("/v1/echo"))
        .bearer_auth("placeholder://model-main")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 503);
    assert_eq!(f.mock.seen.lock().len(), 1);

    // No heartbeat, and no ordinary release, can reopen it.
    assert!(f.gateway().heartbeat(&f.identity).is_err());
    assert!(f.gateway().restore().await.is_err());
    assert!(f.control.network_cut());
    assert_eq!(f.mock.seen.lock().len(), 1);
    let _ = f.finish().await;
}

/// Liveness and containment are different questions. A watchdog that is
/// healthy proves the watcher is there; it says nothing about a quarantine, and
/// a heartbeat that reopened a held cut would hand the machine back to a party
/// that never decided anything about it.
#[tokio::test]
async fn a_heartbeat_reports_liveness_without_reopening_a_held_cut() {
    let f = Fixture::configured(|_| {}, |sink| sink, None, 1_000).await;
    assert!(f.gateway().heartbeat(&f.identity).expect("first heartbeat"));
    f.control
        .hold_cut("guard quarantine")
        .expect("the containment decision is applied");
    assert!(f.control.network_cut());

    // Repeated healthy heartbeats, as a running watchdog produces them.
    for _ in 0..3 {
        f.gateway().heartbeat(&f.identity).expect("still reporting");
        assert!(
            f.control.network_cut(),
            "a heartbeat must not clear a cut a containment decision holds"
        );
    }
    // An ordinary release is an operator's convenience and cannot undo it
    // either; only the authorized one can.
    assert!(f.gateway().restore().await.is_err());
    assert!(f.control.network_cut());
    assert!(f.gateway().authorized_release().await.is_ok());
    assert!(!f.control.network_cut());
    let _ = f.finish().await;
}

/// The dead-man's cut is the other kind: the watchdog is the thing that went
/// wrong, so a watchdog that comes back legitimately reopens it. Holding every
/// cut would make a healthy attachment unusable for the life of its lease.
#[tokio::test]
async fn a_heartbeat_still_reopens_an_ordinary_cut() {
    let f = Fixture::configured(|_| {}, |sink| sink, None, 1_000).await;
    assert!(f.gateway().heartbeat(&f.identity).expect("first heartbeat"));
    f.gateway().control().cut().expect("cut");
    assert!(f.control.network_cut());
    f.gateway().heartbeat(&f.identity).expect("still reporting");
    assert!(
        !f.control.network_cut(),
        "an ordinary cut is the watchdog's to reopen"
    );
    f.gateway().authorized_release().await.expect("release");
    let _ = f.finish().await;
}

#[tokio::test]
async fn a_model_request_reserves_durably_before_any_byte_reaches_upstream() {
    let authority = Arc::new(RecordingAuthority {
        admitted: Mutex::new(Vec::new()),
        reachable: true,
    });
    let f = Fixture::with_authority(|_| {}, authority.clone()).await;
    assert!(f.gateway().heartbeat(&f.identity).expect("first heartbeat"));
    let response = f
        .client()
        .post(f.url("/v1/stream"))
        .bearer_auth("placeholder://model-main")
        .body("prompt")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut stream = response.bytes_stream();
    use futures_util::StreamExt as _;
    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&first[..], b"data: first\n\n");
    let debits = authority.debits();
    assert_eq!(
        debits[0].model_requests, 1,
        "one durable model reservation per request"
    );
    assert!(
        debits.iter().any(|debit| debit.bytes_out > 0),
        "request bytes are debited before forwarding"
    );
    assert!(
        debits.iter().any(|debit| debit.bytes_in > 0),
        "response bytes are debited before delivery"
    );
    let _ = f.finish().await;
}

#[tokio::test]
async fn an_unreachable_budget_authority_refuses_the_request_without_reaching_upstream() {
    let authority = Arc::new(RecordingAuthority {
        admitted: Mutex::new(Vec::new()),
        reachable: false,
    });
    let f = Fixture::with_authority(|_| {}, authority.clone()).await;
    assert!(f.gateway().heartbeat(&f.identity).expect("first heartbeat"));
    let refused = f
        .client()
        .post(f.url("/v1/echo"))
        .bearer_auth("placeholder://model-main")
        .body("prompt")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 503);
    assert!(f.mock.seen.lock().is_empty());
    assert!(authority.debits().is_empty());
    let _ = f.finish().await;
}

#[tokio::test]
async fn a_reservation_uncertain_at_cut_is_cancelled_rather_than_waited_out() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let f = Fixture::with_authority(
        |_| {},
        Arc::new(DeadAuthority {
            started: started.clone(),
            release: release.clone(),
        }),
    )
    .await;
    assert!(f.gateway().heartbeat(&f.identity).expect("first heartbeat"));
    let pending = tokio::spawn({
        let client = f.client();
        let url = f.url("/v1/echo");
        async move {
            client
                .post(url)
                .bearer_auth("placeholder://model-main")
                .body("prompt")
                .send()
                .await
                .unwrap()
                .status()
        }
    });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    f.gateway().cut().expect("cut");
    let status = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, 503);
    assert!(f.mock.seen.lock().is_empty());
    release.notify_one();
    let _ = f.finish().await;
}

#[tokio::test]
async fn an_in_flight_tunnel_is_cancelled_by_the_watchdog_without_closing_the_gateway() {
    let f = Fixture::new(|_| {}).await;
    let mut socket = TcpStream::connect(f.gateway().broker_addr()).await.unwrap();
    socket
        .write_all(
            format!(
                "CONNECT web.guard.test:{} HTTP/1.1\r\nHost: web.guard.test:{}\r\n\r\n",
                f.port, f.port
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(socket.read_u8().await.unwrap());
    }
    assert!(header.starts_with(b"HTTP/1.1 200"));
    // The tunnel holds a connection permit until the latched cut cancels it.
    f.gateway().cut().expect("cut");
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut byte)).await;
    assert!(closed.is_ok(), "an in-flight tunnel is cancelled at cut");
    assert!(f.control.network_cut());
    let _ = f.finish().await;
}

#[tokio::test]
async fn an_approved_proposal_moves_the_enforcement_generation_and_nothing_else() {
    // An approved proposal installs a new policy into a gateway that keeps
    // running. Without the rebind, every watchdog heartbeat and every budget
    // reservation would be refused against a generation that no longer
    // exists. With it, the generation moves and the ownership it is built on
    // does not.
    const OPERATOR_CREDENTIAL: &str = "operator-approval";
    const OPERATOR_SECRET: &str = "operator-only-synthetic-secret";
    const GRANTED_HOST: &str = "api.guard.test";

    let f = Fixture::with_sink(|_| {}, |sink| sink).await;
    let base = f.gateway().identity();
    let directory = std::env::temp_dir().join(format!("aiec-guard-adopt-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let sink: Arc<dyn EventSink> =
        Arc::new(FileEventSink::open(directory.join("events.jsonl")).unwrap());
    let mut credentials = CredentialStore::empty();
    credentials
        .insert(OPERATOR_CREDENTIAL.into(), OPERATOR_SECRET.into())
        .unwrap();
    let store = ProposalStore::new(ProposalStoreConfig {
        sandbox_id: base.sandbox_id,
        tenant_id: base.tenant_id,
        boundary: {
            // The proposal is verified against the same boundary the fixture
            // compiled its own policy under.
            let mut boundary = OperatorBoundary::default();
            for host in ["model.guard.test", "web.guard.test"] {
                boundary.test_destinations.insert(
                    format!("{host}:{}", f.port),
                    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                );
            }
            boundary
        },
        policy: f.control.policy(),
        enforcement: Arc::new(TestBackend::default()),
        attachment: GuardAttachment {
            sandbox_id: base.sandbox_id,
            tenant_id: base.tenant_id,
            interface: "veth-guard".into(),
            guest_ip: Ipv4Addr::new(10, 0, 2, 2),
            gateway_ip: Ipv4Addr::new(10, 0, 2, 1),
            dns_port: 53,
            broker_port: 8080,
        },
        events: sink,
    })
    .expect("proposal store");
    let agent = AgentCredential::new(base.sandbox_id, base.tenant_id, "planner-1").unwrap();
    let proposal = store
        .submit(
            &agent,
            ProposalRequest {
                summary: format!("please allow {GRANTED_HOST}:443"),
                allow: vec![EgressGrant {
                    host: GRANTED_HOST.to_owned(),
                    port: 443,
                    methods: vec!["POST".into()],
                    paths: vec!["/v2/".into()],
                }],
            },
        )
        .await
        .expect("an agent may submit");
    let outcome = store
        .approve(
            &HumanApproval::operator(
                "ops-oncall",
                OPERATOR_CREDENTIAL,
                OPERATOR_SECRET,
                &credentials,
            )
            .unwrap(),
            proposal.id,
        )
        .await
        .expect("a safe proposal applies");

    // The rebind only ever names a policy that is actually in force.
    assert!(
        f.gateway().adopt_policy(&base.policy_hash).is_err(),
        "a generation that is no longer in force cannot be named"
    );
    // Until the new generation is named, the superseded one cannot report.
    assert!(
        f.gateway().heartbeat(&base).is_err(),
        "the superseded generation cannot keep reporting"
    );
    f.gateway()
        .adopt_policy(&outcome.policy_hash)
        .expect("the installed generation is named");
    let rebound = f.gateway().identity();
    assert_ne!(rebound.policy_hash, base.policy_hash);
    assert_eq!(rebound.policy_hash, outcome.policy_hash);
    assert_eq!(rebound.sandbox_id, base.sandbox_id);
    assert_eq!(rebound.tenant_id, base.tenant_id);
    f.gateway()
        .heartbeat(&rebound)
        .expect("the watchdog keeps reporting across an approval");
    let _ = std::fs::remove_dir_all(&directory);
    let _ = f.finish().await;
}
