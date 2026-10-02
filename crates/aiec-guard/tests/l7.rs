//! Behavioural tests for layer 7 governance against a real gateway and a real
//! local upstream. Nothing here asserts wiring: each test sends a request and
//! reads the answer, the upstream's view of it, and the journal record.

use aiec_guard::{
    compiler::{OperatorBoundary, compile},
    control::{BudgetAuthority, BudgetDebit, GuardFence},
    events::{FileEventSink, read_events},
    gateway::{CredentialStore, GatewayConfig, GuardGateway},
    l7,
    policy::L7Policy,
    policy::{
        EgressRule, GraphqlRules, GuardPolicy, HttpRule, McpRules, ModelEndpoint, PolicyTemplate,
    },
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::Request,
};
use bytes::Bytes;
use futures_util::stream;
use parking_lot::Mutex;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use uuid::Uuid;

const SECRET: &str = "outside-guest-synthetic-secret";
const UPSTREAM_BODY: &str = "upstream saw the request";

struct AllowAllAuthority;

#[async_trait::async_trait]
impl BudgetAuthority for AllowAllAuthority {
    async fn reserve(
        &self,
        _: &aiec_guard::control::GuardIdentity,
        _: GuardFence,
        _: BudgetDebit,
    ) -> aiec_guard::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Upstream {
    seen: Arc<Mutex<Vec<String>>>,
}

async fn serve(State(upstream): State<Upstream>, request: Request<Body>) -> String {
    let body = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default();
    upstream
        .seen
        .lock()
        .push(String::from_utf8_lossy(&body).into_owned());
    UPSTREAM_BODY.to_owned()
}

struct Fixture {
    gateway: Option<GuardGateway>,
    upstream: Upstream,
    broker: std::net::SocketAddr,
    port: u16,
    directory: std::path::PathBuf,
    server: JoinHandle<()>,
}

/// An L7 policy that governs one MCP host and one GraphQL host, leaving every
/// other destination to the egress rule alone.
fn l7_policy() -> L7Policy {
    L7Policy {
        http: vec![HttpRule {
            host: "api.guard.test".into(),
            methods: vec!["POST".into()],
            paths: vec!["/v1/".into()],
        }],
        mcp: McpRules {
            allowed_methods: vec!["tools/list".into(), "tools/call".into()],
            allowed_tools: vec!["read_file".into(), "search".into()],
            denied_tools: vec!["delete_repository".into()],
        },
        graphql: GraphqlRules {
            allow_mutations: false,
            operations: Vec::new(),
            root_fields: Vec::new(),
        },
        ..L7Policy::default()
    }
}

impl Fixture {
    async fn start(l7: Option<L7Policy>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = Upstream::default();
        let router = Router::new().fallback(serve).with_state(upstream.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let model = ModelEndpoint {
            host: "model.guard.test".into(),
            port,
            scheme: "http".into(),
            ..Default::default()
        };
        let rules = ["mcp.guard.test", "api.guard.test"]
            .into_iter()
            .map(|host| EgressRule {
                host: host.into(),
                port,
                protocol: "tcp".into(),
                allowed_methods: Vec::new(),
                allowed_paths: Vec::new(),
            })
            .collect();
        let policy =
            GuardPolicy::template(PolicyTemplate::ModelPlusAllowlist, Some(model), rules).unwrap();
        let mut boundary = OperatorBoundary::default();
        for host in ["model.guard.test", "mcp.guard.test", "api.guard.test"] {
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
        let directory = std::env::temp_dir().join(format!("aiec-guard-l7-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let events = Arc::new(FileEventSink::open(directory.join("events.jsonl")).unwrap());
        let gateway = GuardGateway::start_with_l7(
            GatewayConfig {
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
                events,
                budget_authority: Arc::new(AllowAllAuthority),
                watchdog_timeout: Duration::from_millis(60_000),
            },
            l7,
        )
        .await
        .unwrap();
        let identity = gateway.control().identity().clone();
        assert!(gateway.heartbeat(&identity).expect("first heartbeat"));
        let broker = gateway.broker_addr();
        Self {
            gateway: Some(gateway),
            upstream,
            broker,
            port,
            directory,
            server,
        }
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .proxy(reqwest::Proxy::http(format!("http://{}", self.broker)).unwrap())
            .build()
            .unwrap()
    }

    async fn post(&self, host: &str, path: &str, body: &str) -> reqwest::Response {
        self.client()
            .post(format!("http://{host}:{}{path}", self.port))
            .header("content-type", "application/json")
            .body(body.to_owned())
            .send()
            .await
            .unwrap()
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

fn rpc(method: &str, tool: Option<&str>) -> String {
    match tool {
        Some(tool) => format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\",\"params\":{{\"name\":\"{tool}\"}}}}"
        ),
        None => format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\"}}"),
    }
}

#[tokio::test]
async fn an_allowed_mcp_tool_call_reaches_the_upstream_and_a_write_tool_does_not() {
    let f = Fixture::start(Some(l7_policy())).await;

    let listed = f
        .post("mcp.guard.test", "/mcp", &rpc("tools/list", None))
        .await;
    assert_eq!(listed.status(), 200);
    assert_eq!(listed.text().await.unwrap(), UPSTREAM_BODY);

    let read = f
        .post(
            "mcp.guard.test",
            "/mcp",
            &rpc("tools/call", Some("read_file")),
        )
        .await;
    assert_eq!(read.status(), 200);

    let deleted = f
        .post(
            "mcp.guard.test",
            "/mcp",
            &rpc("tools/call", Some("delete_repository")),
        )
        .await;
    assert_eq!(deleted.status(), 403);
    assert_eq!(
        deleted.text().await.unwrap(),
        "l7 mcp: tool name is explicitly denied"
    );

    let unlisted = f
        .post(
            "mcp.guard.test",
            "/mcp",
            &rpc("tools/call", Some("rotate_key")),
        )
        .await;
    assert_eq!(unlisted.status(), 403);
    assert_eq!(
        unlisted.text().await.unwrap(),
        "l7 mcp: tool name is not in the allowed set"
    );

    let unlisted_method = f
        .post("mcp.guard.test", "/mcp", &rpc("resources/read", None))
        .await;
    assert_eq!(unlisted_method.status(), 403);
    assert_eq!(
        unlisted_method.text().await.unwrap(),
        "l7 mcp: method is not in the allowed set"
    );

    let seen = f.upstream.seen.lock().clone();
    assert_eq!(
        seen.len(),
        2,
        "only the permitted calls reached the upstream"
    );
    assert!(
        seen.iter()
            .all(|body| body.contains("read_file") || body.contains("tools/list"))
    );
    assert!(!seen.iter().any(|body| body.contains("delete_repository")));

    let events = f.finish().await;
    let refusals: Vec<_> = events
        .iter()
        .filter(|event| event.reason.starts_with("l7 mcp"))
        .collect();
    assert_eq!(refusals.len(), 3);
    // The journal carries the decision, never the request.
    let journal = serde_json::to_string(&events).unwrap();
    assert!(!journal.contains("delete_repository"));
    assert!(!journal.contains("rotate_key"));
}

#[tokio::test]
async fn a_graphql_query_is_forwarded_and_a_mutation_is_refused() {
    let f = Fixture::start(Some(l7_policy())).await;

    let query = f
        .post(
            "mcp.guard.test",
            "/graphql",
            &serde_json::json!({"query": "query ReadRepo { repository { id } }"}).to_string(),
        )
        .await;
    assert_eq!(query.status(), 200);

    let mutation = f
        .post(
            "mcp.guard.test",
            "/graphql",
            &serde_json::json!({"query": "mutation DeleteRepo { deleteRepository { ok } }"})
                .to_string(),
        )
        .await;
    assert_eq!(mutation.status(), 403);
    assert_eq!(
        mutation.text().await.unwrap(),
        "l7 graphql: mutation is not allowed"
    );

    let seen = f.upstream.seen.lock().clone();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].contains("ReadRepo"));
    f.finish().await;
}

#[tokio::test]
async fn an_unparsable_an_undeclared_and_an_oversized_graphql_body_are_all_refused() {
    let f = Fixture::start(Some(l7_policy())).await;

    let truncated = f
        .client()
        .post(format!("http://mcp.guard.test:{}/graphql", f.port))
        .header("content-type", "application/graphql")
        .body("{ viewer { login ")
        .send()
        .await
        .unwrap();
    assert_eq!(truncated.status(), 400);
    assert_eq!(
        truncated.text().await.unwrap(),
        "l7 graphql: document is not parsable"
    );

    // A JSON body that is neither JSON-RPC nor GraphQL is not MCP traffic; one
    // that claims JSON-RPC and cannot be read is refused rather than forwarded.
    let not_json_rpc = f
        .post("mcp.guard.test", "/mcp", r#"{"items":[1,2,3]}"#)
        .await;
    assert_eq!(not_json_rpc.status(), 200);
    let truncated_json = f
        .post(
            "mcp.guard.test",
            "/mcp",
            r#"{"jsonrpc":"2.0","method":"tools/l"#,
        )
        .await;
    assert_eq!(truncated_json.status(), 400);
    assert_eq!(
        truncated_json.text().await.unwrap(),
        "l7: request body is not JSON without duplicate keys"
    );
    let duplicated = f
        .post(
            "mcp.guard.test",
            "/mcp",
            r#"{"jsonrpc":"2.0","method":"tools/list","method":"tools/call","params":{"name":"delete_repository"}}"#,
        )
        .await;
    assert_eq!(duplicated.status(), 400, "a duplicated key is not resolved");
    assert_eq!(
        duplicated.text().await.unwrap(),
        "l7: request body is not JSON without duplicate keys"
    );

    let oversized = f
        .post(
            "mcp.guard.test",
            "/graphql",
            &format!(
                "{{\"query\":\"{{ viewer {{ login {} }} }}\"}}",
                "x".repeat(l7::MAX_INSPECTED_BODY_BYTES)
            ),
        )
        .await;
    assert_eq!(oversized.status(), 413);
    assert_eq!(
        oversized.text().await.unwrap(),
        "l7: request body exceeds the inspection bound"
    );

    // A body whose length is not declared cannot be bounded, so it is refused
    // rather than inspected as a prefix.
    let chunked = f
        .client()
        .post(format!("http://mcp.guard.test:{}/graphql", f.port))
        .header("content-type", "application/json")
        .body(reqwest::Body::wrap_stream(stream::once(async {
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"{\"query\":\"{ viewer { id } }\"}"))
        })))
        .send()
        .await
        .unwrap();
    assert_eq!(chunked.status(), 400);
    assert_eq!(
        chunked.text().await.unwrap(),
        "l7: request body length is not declared and cannot be inspected"
    );

    assert!(
        !f.upstream
            .seen
            .lock()
            .iter()
            .any(|body| body.contains("viewer") || body.contains("jsonrpc")),
        "no refused body reached the upstream"
    );
    f.finish().await;
}

#[tokio::test]
async fn a_governed_host_denies_every_method_and_path_its_rule_does_not_name() {
    let f = Fixture::start(Some(l7_policy())).await;

    let allowed = f
        .client()
        .post(format!("http://api.guard.test:{}/v1/read", f.port))
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), 200);

    let wrong_path = f
        .client()
        .post(format!("http://api.guard.test:{}/admin/delete", f.port))
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_path.status(), 403);
    assert_eq!(
        wrong_path.text().await.unwrap(),
        "l7 http: path is not allowed for this host"
    );

    let wrong_method = f
        .client()
        .get(format!("http://api.guard.test:{}/v1/read", f.port))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_method.status(), 403);
    assert_eq!(
        wrong_method.text().await.unwrap(),
        "l7 http: method is not allowed for this host"
    );

    // A host no http rule names is left to the egress rule, which permits it.
    let ungoverned = f
        .client()
        .post(format!("http://mcp.guard.test:{}/admin", f.port))
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(ungoverned.status(), 200);

    // A destination no egress rule covers is refused before any of this.
    let denied = f
        .client()
        .post(format!("http://other.guard.test:{}/v1/read", f.port))
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(denied.text().await.unwrap(), "proxy destination denied");

    let seen = f.upstream.seen.lock().clone();
    assert_eq!(
        seen.len(),
        2,
        "only the permitted requests reached upstream"
    );
    assert!(!seen.iter().any(|body| body.contains("delete")));
    f.finish().await;
}

#[tokio::test]
async fn a_tunnel_to_a_governed_host_is_refused_rather_than_forwarded_opaquely() {
    let f = Fixture::start(Some(l7_policy())).await;
    let mut socket = tokio::net::TcpStream::connect(f.broker).await.unwrap();
    socket
        .write_all(
            format!(
                "CONNECT api.guard.test:{} HTTP/1.1\r\nhost: api.guard.test:{}\r\n\r\n",
                f.port, f.port
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = vec![0u8; 512];
    let size = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response[..size]).into_owned();
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response.contains("TLS tunnel refused"), "{response}");
    f.finish().await;
}

#[tokio::test]
async fn a_gateway_asking_for_interception_without_acknowledgement_refuses_to_start() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let upstream = Upstream::default();
    let router = Router::new().fallback(serve).with_state(upstream.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let policy = GuardPolicy::template(
        PolicyTemplate::ModelPlusAllowlist,
        Some(ModelEndpoint {
            host: "model.guard.test".into(),
            port,
            scheme: "http".into(),
            ..Default::default()
        }),
        vec![EgressRule {
            host: "mcp.guard.test".into(),
            port,
            protocol: "tcp".into(),
            allowed_methods: Vec::new(),
            allowed_paths: Vec::new(),
        }],
    )
    .unwrap();
    let mut boundary = OperatorBoundary::default();
    for host in ["model.guard.test", "mcp.guard.test"] {
        boundary.test_destinations.insert(
            format!("{host}:{port}"),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );
    }
    let compiled = compile(&policy, &boundary).unwrap();
    let directory = std::env::temp_dir().join(format!("aiec-guard-l7-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let config = |events: Arc<dyn aiec_guard::events::EventSink>| {
        let mut credentials = CredentialStore::empty();
        credentials
            .insert("model-main".into(), SECRET.into())
            .unwrap();
        GatewayConfig {
            sandbox_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            fence: GuardFence {
                lease_id: Uuid::new_v4(),
                generation: 1,
            },
            compiled: compiled.clone(),
            bind_ip: Ipv4Addr::LOCALHOST,
            guest_ip: Ipv4Addr::LOCALHOST,
            broker_port: 0,
            dns_port: 0,
            credentials: Arc::new(credentials),
            events,
            budget_authority: Arc::new(AllowAllAuthority),
            watchdog_timeout: Duration::from_millis(60_000),
        }
    };
    let sink = || -> Arc<dyn aiec_guard::events::EventSink> {
        Arc::new(FileEventSink::open(directory.join(format!("{}.jsonl", Uuid::new_v4()))).unwrap())
    };

    let unacknowledged = L7Policy {
        mode: aiec_guard::policy::L7Mode::Intercept,
        intercept_ack: false,
        ..l7_policy()
    };
    let error = match GuardGateway::start_with_l7(config(sink()), Some(unacknowledged)).await {
        Ok(_) => panic!("interception without acknowledgement must be refused"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("intercept_ack"), "{error}");

    let acknowledged = L7Policy {
        mode: aiec_guard::policy::L7Mode::Intercept,
        intercept_ack: true,
        ..l7_policy()
    };
    let gateway = GuardGateway::start_with_l7(config(sink()), Some(acknowledged))
        .await
        .expect("an acknowledged interception mode starts");
    // The acknowledged gateway is a running gateway: dropping it closes the
    // listeners and cancels its services.
    let identity = gateway.control().identity().clone();
    assert!(gateway.heartbeat(&identity).expect("first heartbeat"));
    assert!(
        !gateway.control().network_cut(),
        "an acknowledged gateway is live"
    );
    drop(gateway);
    server.abort();
    let _ = std::fs::remove_dir_all(&directory);
}
