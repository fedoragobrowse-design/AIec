//! Offline contract tests for the hosted E2B runtime.
//!
//! Every test drives the real `reqwest` client against a hand-rolled HTTP
//! server on loopback, so the request paths, headers, bodies and error mapping
//! are all exercised without a network or an E2B account.

use aiec_core::runtime::{RuntimeCapabilities, RuntimeIsolation, RuntimeRegistry};
use aiec_core::{
    CoreError, DeleteFileRequest, ExecRequest, MakeDirectoryRequest, NetworkPolicy, PutFileRequest,
    RuntimeKind, Sandbox, SandboxState, new_id,
};
use aiec_runtime::{E2bConfig, E2bRuntime, RuntimePathProvider, SandboxRuntime};
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// One request the mock provider received.
#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Recorded {
    fn body_contains(&self, needle: &str) -> bool {
        String::from_utf8_lossy(&self.body).contains(needle)
    }
}

#[derive(Clone, Debug)]
struct MockResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl MockResponse {
    fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into(),
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "application/octet-stream",
            body: Vec::new(),
        }
    }
}

type Handler = Arc<dyn Fn(&Recorded) -> MockResponse + Send + Sync>;

struct MockProvider {
    base_url: String,
    recorded: Arc<Mutex<Vec<Recorded>>>,
    server: JoinHandle<()>,
}

impl MockProvider {
    async fn start(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock provider");
        let address = listener.local_addr().expect("mock address");
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let sink = recorded.clone();
        let server = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = handler.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, handler, sink).await;
                });
            }
        });
        Self {
            base_url: format!("http://{address}"),
            recorded,
            server,
        }
    }

    fn requests(&self) -> Vec<Recorded> {
        self.recorded.lock().expect("recorded requests").clone()
    }

    fn count(&self, method: &str, path: &str) -> usize {
        self.requests()
            .iter()
            .filter(|request| request.method == method && request.path == path)
            .count()
    }

    fn runtime(&self) -> E2bRuntime {
        E2bRuntime::new(test_config(self.base_url.clone())).expect("E2B runtime")
    }
}

impl Drop for MockProvider {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn test_config(api_base_url: String) -> E2bConfig {
    E2bConfig {
        api_base_url: api_base_url.clone(),
        api_key: "e2b_test_key".into(),
        default_template: "base".into(),
        timeout_seconds: 900,
        request_timeout: Duration::from_secs(5),
        envd_port: 49983,
        envd_domain: "e2b.app".into(),
        // The guest agent is served from the same mock, one path segment per
        // provider sandbox, exactly as a private gateway would route it.
        envd_base_url: Some(api_base_url),
        coding_guest: true,
    }
}

async fn serve(
    mut stream: TcpStream,
    handler: Handler,
    sink: Arc<Mutex<Vec<Recorded>>>,
) -> std::io::Result<()> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    while raw.len() < head_end + 4 + length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let (path, _query) = target
        .split_once('?')
        .map(|(path, query)| (path.to_owned(), query.to_owned()))
        .unwrap_or((target.clone(), String::new()));
    let request = Recorded {
        method,
        path,
        headers,
        body: raw[head_end + 4..].to_vec(),
    };
    let response = handler(&request);
    sink.lock().expect("recorded requests").push(request);
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    head.push_str(&String::from_utf8_lossy(&response.body));
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn sandbox_for(network: NetworkPolicy) -> Sandbox {
    let now = chrono::Utc::now();
    Sandbox {
        id: new_id(),
        tenant_id: new_id(),
        node_id: None,
        image_id: "afimg1_test".into(),
        state: SandboxState::Creating,
        runtime: RuntimeKind::Hosted,
        cpu: 1,
        memory_mb: 512,
        disk_mb: 1024,
        timeout_seconds: 300,
        network,
        environment: Default::default(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    }
}

/// Provider sandbox the mock reports for every create.
const PROVIDER_ID: &str = "sbx_mock1";

fn created_sandbox_body() -> String {
    format!(
        r#"{{"sandboxID":"{PROVIDER_ID}","templateID":"base","envdVersion":"0.1.1","envdAccessToken":"envd-token","state":"running"}}"#
    )
}

/// Routes the lifecycle calls a successful create performs.
fn lifecycle_handler(create_status: u16, create_body: String) -> Handler {
    Arc::new(
        move |request: &Recorded| match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v2/sandboxes") => MockResponse::json(create_status, create_body.clone()),
            ("GET", "/sandboxes/sbx_mock1") => MockResponse::json(200, created_sandbox_body()),
            ("POST", "/sbx_mock1/filesystem.Filesystem/MakeDir") => MockResponse::json(200, "{}"),
            ("POST", "/v2/sandboxes/sbx_mock1/connect") => {
                MockResponse::json(200, created_sandbox_body())
            }
            ("POST", "/sandboxes/sbx_mock1/pause") => MockResponse::empty(204),
            ("DELETE", "/sandboxes/sbx_mock1") => MockResponse::empty(204),
            _ => MockResponse::json(404, r#"{"code":404,"message":"unhandled"}"#),
        },
    )
}

#[tokio::test]
async fn create_binds_the_provider_identity_without_exposing_it() {
    let provider = MockProvider::start(lifecycle_handler(201, created_sandbox_body())).await;
    let runtime = provider.runtime();
    let sandbox = sandbox_for(NetworkPolicy::Internet);

    runtime.create(&sandbox).await.expect("create");

    assert_eq!(provider.count("POST", "/v2/sandboxes"), 1);
    let handle = runtime
        .runtime_path(&sandbox)
        .expect("provider handle after create");
    assert_eq!(handle, format!("e2b://{PROVIDER_ID}"));
    // The public identity stays AIec's own sandbox id.
    assert_ne!(handle, sandbox.id.to_string());
    assert!(!handle.contains(&sandbox.id.to_string()));
    // The guest agent is addressed with the provider id and its token.
    let make_dir = provider
        .requests()
        .into_iter()
        .find(|request| request.path.ends_with("MakeDir"))
        .expect("workspace creation call");
    assert_eq!(
        make_dir.headers.get("e2b-sandbox-id").map(String::as_str),
        Some(PROVIDER_ID)
    );
    assert_eq!(
        make_dir.headers.get("e2b-sandbox-port").map(String::as_str),
        Some("49983")
    );
    assert_eq!(
        make_dir.headers.get("x-access-token").map(String::as_str),
        Some("envd-token")
    );
    let create = provider
        .requests()
        .into_iter()
        .find(|request| request.path == "/v2/sandboxes")
        .expect("create call");
    assert_eq!(
        create.headers.get("x-api-key").map(String::as_str),
        Some("e2b_test_key")
    );
    // The AIec content address never reaches the provider: it is
    // translated into the configured E2B template.
    assert!(
        !create.body_contains("afimg1"),
        "{}",
        String::from_utf8_lossy(&create.body)
    );
    assert!(
        create.body_contains(r#""templateID":"base""#),
        "{}",
        String::from_utf8_lossy(&create.body)
    );
    assert!(
        create.body_contains(r#""allow_internet_access":true"#),
        "{}",
        String::from_utf8_lossy(&create.body)
    );
    assert!(
        create.body_contains(r#""aiec_sandbox_id""#),
        "{}",
        String::from_utf8_lossy(&create.body)
    );
}

#[tokio::test]
async fn a_second_create_never_allocates_a_second_provider_sandbox() {
    let provider = MockProvider::start(lifecycle_handler(201, created_sandbox_body())).await;
    let runtime = provider.runtime();
    let mut sandbox = sandbox_for(NetworkPolicy::Disabled);

    runtime.create(&sandbox).await.expect("first create");
    // The control plane persists the handle; a later request reloads the
    // sandbox from the database and retries the create.
    sandbox.runtime_path = runtime.runtime_path(&sandbox);
    runtime.create(&sandbox).await.expect("retried create");
    // Even a process that lost its cache resolves the provider sandbox.
    let reloaded = E2bRuntime::new(test_config(provider.base_url.clone())).expect("runtime");
    reloaded
        .create(&sandbox)
        .await
        .expect("create after restart");

    assert_eq!(provider.count("POST", "/v2/sandboxes"), 1);
    // The retry reused the handle this process already held; the process that
    // lost its cache re-read the same sandbox from the provider.
    assert_eq!(provider.count("GET", "/sandboxes/sbx_mock1"), 1);
    assert_eq!(
        reloaded.runtime_path(&sandbox),
        Some(format!("e2b://{PROVIDER_ID}"))
    );
}

#[tokio::test]
async fn destroy_is_idempotent_once_the_provider_sandbox_is_gone() {
    let provider = MockProvider::start(Arc::new(|request: &Recorded| {
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v2/sandboxes") => MockResponse::json(201, created_sandbox_body()),
            ("POST", "/sbx_mock1/filesystem.Filesystem/MakeDir") => MockResponse::json(200, "{}"),
            // A sandbox killed by its own timeout is already absent.
            ("DELETE", "/sandboxes/sbx_mock1") => {
                MockResponse::json(404, r#"{"code":404,"message":"not found"}"#)
            }
            _ => MockResponse::json(404, r#"{"code":404,"message":"unhandled"}"#),
        }
    }))
    .await;
    let runtime = provider.runtime();
    let mut sandbox = sandbox_for(NetworkPolicy::Internet);
    runtime.create(&sandbox).await.expect("create");
    sandbox.runtime_path = runtime.runtime_path(&sandbox);

    runtime.destroy(&sandbox).await.expect("first destroy");
    runtime.destroy(&sandbox).await.expect("second destroy");

    assert_eq!(provider.count("DELETE", "/sandboxes/sbx_mock1"), 2);
    // A sandbox that never reached the provider has nothing to release.
    let untouched = sandbox_for(NetworkPolicy::Internet);
    runtime
        .destroy(&untouched)
        .await
        .expect("destroy without binding");
}

#[tokio::test]
async fn provider_failures_map_to_aiec_errors() {
    // (status, provider body, matches AIec error, human description)
    type Case = (u16, String, fn(&CoreError) -> bool, &'static str);
    let cases: Vec<Case> = vec![
        (
            503,
            r#"{"code":503,"message":"no capacity","error_code":"sandbox_capacity_unavailable"}"#
                .to_owned(),
            |error| matches!(error, CoreError::Unavailable(_)),
            "capacity exhausted",
        ),
        (
            429,
            r#"{"code":429,"message":"slow down","error_code":"sandbox_placement_timeout"}".to_owned(),
            |error| matches!(error, CoreError::Unavailable(_)),
            "placement timed out",
        ),
        (
            429,
            r#"{"code":429,"message":"too many requests"}"#.to_owned(),
            |error| matches!(error, CoreError::Unavailable(_)),
            "rate limited",
        ),
        (
            401,
            r#"{"code":401,"message":"invalid api key"}"#.to_owned(),
            |error| matches!(error, CoreError::Forbidden(_)),
            "bad credentials",
        ),
        (
            500,
            r#"{"code":500,"message":"boom","error_code":"sandbox_create_failed"}"#.to_owned(),
            |error| matches!(error, CoreError::Backend(_)),
            "create failed",
        ),
    ];
    for (status, body, expected, label) in cases {
        let provider = MockProvider::start(lifecycle_handler(status, body)).await;
        let runtime = provider.runtime();
        let outcome = runtime.create(&sandbox_for(NetworkPolicy::Disabled)).await;
        assert!(
            matches!(&outcome, Err(error) if expected(error)),
            "{label} (HTTP {status}) mapped to {outcome:?}"
        );
        assert_eq!(provider.count("POST", "/v2/sandboxes"), 1);
    }
}

#[tokio::test]
async fn a_removed_provider_sandbox_is_reported_as_not_found() {
    let provider = MockProvider::start(Arc::new(|request: &Recorded| {
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v2/sandboxes") => MockResponse::json(201, created_sandbox_body()),
            ("POST", "/sbx_mock1/filesystem.Filesystem/MakeDir") => MockResponse::json(200, "{}"),
            _ => MockResponse::json(404, r#"{"code":404,"message":"not found"}"#),
        }
    }))
    .await;
    let runtime = provider.runtime();
    let mut sandbox = sandbox_for(NetworkPolicy::Disabled);
    runtime.create(&sandbox).await.expect("create");
    sandbox.runtime_path = runtime.runtime_path(&sandbox);
    // A sandbox that died with its provider timeout cannot be restarted.
    assert!(matches!(
        runtime.start(&sandbox).await,
        Err(CoreError::NotFound(_))
    ));
}

#[tokio::test]
async fn capabilities_refuse_the_snapshot_features_e2b_cannot_provide() {
    let provider = MockProvider::start(lifecycle_handler(201, created_sandbox_body())).await;
    let runtime = provider.runtime();
    let capabilities = runtime.capabilities();
    assert_eq!(capabilities.isolation, RuntimeIsolation::MicroVm);
    assert!(capabilities.full_kernel_isolation);
    assert!(capabilities.guest_agent);
    assert!(capabilities.exec && capabilities.files && capabilities.pause);
    // E2B snapshots its own microVM internally; it cannot hand AIec a
    // virtual machine or memory snapshot, nor enforce a host allowlist.
    assert!(!capabilities.vm_snapshot);
    assert!(!capabilities.memory_resume);
    assert!(!capabilities.network_policy);
    assert!(!capabilities.portable_workspace);

    let mut registry = RuntimeRegistry::new();
    registry.register(RuntimeKind::Hosted, Arc::new(runtime));
    let error = registry
        .select(
            Some(RuntimeKind::Hosted),
            &RuntimeCapabilities {
                vm_snapshot: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("a virtual machine snapshot cannot be served");
    assert!(matches!(error, CoreError::Unsupported(_)), "{error:?}");
}

#[tokio::test]
async fn a_network_allowlist_fails_closed_instead_of_running_unrestricted() {
    let provider = MockProvider::start(lifecycle_handler(201, created_sandbox_body())).await;
    let runtime = provider.runtime();
    let restricted = sandbox_for(NetworkPolicy::Restricted {
        allowed_hosts: vec!["example.com".into()],
    });
    let error = runtime
        .create(&restricted)
        .await
        .expect_err("restricted network is unsupported");
    assert!(matches!(error, CoreError::Unsupported(_)), "{error:?}");
    assert_eq!(provider.count("POST", "/v2/sandboxes"), 0);
}

#[tokio::test]
async fn exec_runs_through_the_guest_agent_and_keeps_its_bounds() {
    let provider = MockProvider::start(Arc::new(|request: &Recorded| {
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v2/sandboxes") => MockResponse::json(201, created_sandbox_body()),
            ("POST", "/sbx_mock1/filesystem.Filesystem/MakeDir") => MockResponse::json(200, "{}"),
            ("POST", "/sbx_mock1/process.Process/Start") => MockResponse::json(
                200,
                stream_body(&[("stdout", "hello\n"), ("stderr", "careful\n")], 7),
            ),
            _ => MockResponse::json(404, r#"{"code":404,"message":"unhandled"}"#),
        }
    }))
    .await;
    let runtime = provider.runtime();
    let mut sandbox = sandbox_for(NetworkPolicy::Disabled);
    runtime.create(&sandbox).await.expect("create");
    sandbox.runtime_path = runtime.runtime_path(&sandbox);

    let result = runtime
        .exec(
            &sandbox,
            ExecRequest {
                command: vec!["echo".into(), "hello".into()],
                working_directory: Some("/workspace".into()),
                environment: Default::default(),
                timeout_seconds: 30,
                stdin: Some("input".into()),
            },
        )
        .await
        .expect("exec");
    assert_eq!(result.exit_code, 7);
    assert_eq!(result.stdout, "hello\n");
    assert_eq!(result.stderr, "careful\n");
    assert!(!result.timed_out);

    let start = provider
        .requests()
        .into_iter()
        .find(|request| request.path.ends_with("process.Process/Start"))
        .expect("exec call");
    assert_eq!(
        start.headers.get("e2b-sandbox-id").map(String::as_str),
        Some(PROVIDER_ID)
    );
    assert_eq!(
        start
            .headers
            .get("connect-protocol-version")
            .map(String::as_str),
        Some("1")
    );
    let body = String::from_utf8_lossy(&start.body).into_owned();
    assert!(body.contains(r#""cmd":"echo""#), "{body}");
    assert!(body.contains(r#""args":["hello"]"#), "{body}");
    assert!(body.contains(r#""cwd":"/workspace""#), "{body}");
    assert!(
        body.contains("aW5wdXQ="),
        "stdin must reach the guest: {body}"
    );
}

#[tokio::test]
async fn exec_output_beyond_the_aiec_bound_is_refused() {
    let provider = MockProvider::start(Arc::new(|request: &Recorded| {
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v2/sandboxes") => MockResponse::json(201, created_sandbox_body()),
            ("POST", "/sbx_mock1/filesystem.Filesystem/MakeDir") => MockResponse::json(200, "{}"),
            ("POST", "/sbx_mock1/process.Process/Start") => {
                MockResponse::json(200, noisy_stream_body())
            }
            _ => MockResponse::json(404, r#"{"code":404,"message":"unhandled"}"#),
        }
    }))
    .await;
    let runtime = provider.runtime();
    let mut sandbox = sandbox_for(NetworkPolicy::Disabled);
    runtime.create(&sandbox).await.expect("create");
    sandbox.runtime_path = runtime.runtime_path(&sandbox);
    let error = runtime
        .exec(
            &sandbox,
            ExecRequest {
                command: vec!["yes".into()],
                working_directory: None,
                environment: Default::default(),
                timeout_seconds: 30,
                stdin: None,
            },
        )
        .await
        .expect_err("unbounded output is refused");
    assert!(matches!(error, CoreError::LimitExceeded(_)), "{error:?}");
}

#[tokio::test]
async fn a_guest_agent_rejects_an_expired_token() {
    let provider = MockProvider::start(Arc::new(|request: &Recorded| {
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v2/sandboxes") => MockResponse::json(201, created_sandbox_body()),
            ("POST", "/sbx_mock1/filesystem.Filesystem/MakeDir") => MockResponse::json(200, "{}"),
            ("POST", "/sbx_mock1/filesystem.Filesystem/ListDir") => MockResponse::json(
                401,
                r#"{"code":"unauthenticated","message":"invalid token"}"#,
            ),
            _ => MockResponse::json(404, r#"{"code":404,"message":"unhandled"}"#),
        }
    }))
    .await;
    let runtime = provider.runtime();
    let mut sandbox = sandbox_for(NetworkPolicy::Disabled);
    runtime.create(&sandbox).await.expect("create");
    sandbox.runtime_path = runtime.runtime_path(&sandbox);
    let error = runtime
        .list_files(&sandbox, "/workspace")
        .await
        .expect_err("an expired guest token is not a listing");
    assert!(matches!(error, CoreError::Forbidden(_)), "{error:?}");
}

#[tokio::test]
async fn workspace_files_round_trip_through_the_guest_agent() {
    let provider = MockProvider::start(Arc::new(|request: &Recorded| {
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v2/sandboxes") => MockResponse::json(201, created_sandbox_body()),
            ("POST", "/sbx_mock1/filesystem.Filesystem/MakeDir") => MockResponse::json(200, "{}"),
            ("POST", "/sbx_mock1/filesystem.Filesystem/ListDir") => MockResponse::json(
                200,
                r#"{"entries":[
                    {"name":"notes.md","path":"/workspace/notes.md","type":"FILE_TYPE_FILE","size":"5"},
                    {"name":"src","path":"/workspace/src","type":"FILE_TYPE_DIRECTORY","size":0}
                ]}"#,
            ),
            ("POST", "/sbx_mock1/filesystem.Filesystem/Remove") => MockResponse::json(200, "{}"),
            ("POST", "/sbx_mock1/files") => MockResponse::json(200, "{}"),
            ("GET", "/sbx_mock1/files") => MockResponse::json(200, b"plain body".to_vec()),
            _ => MockResponse::json(404, r#"{"code":404,"message":"unhandled"}"#),
        }
    }))
    .await;
    let runtime = provider.runtime();
    let mut sandbox = sandbox_for(NetworkPolicy::Disabled);
    runtime.create(&sandbox).await.expect("create");
    sandbox.runtime_path = runtime.runtime_path(&sandbox);

    runtime
        .put_file(
            &sandbox,
            PutFileRequest {
                path: "/workspace/notes.md".into(),
                content_base64: "aGVsbG8=".into(),
                mode: None,
            },
        )
        .await
        .expect("write file");
    let content = runtime
        .get_file(&sandbox, "/workspace/notes.md")
        .await
        .expect("read file");
    assert_eq!(content.path, "/workspace/notes.md");
    assert_eq!(content.content_base64, "cGxhaW4gYm9keQ==");
    let entries = runtime
        .list_files(&sandbox, "/workspace")
        .await
        .expect("list files");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "notes.md");
    assert_eq!(entries[0].kind, "file");
    assert_eq!(entries[0].size, 5);
    assert_eq!(entries[1].kind, "directory");
    runtime
        .make_directory(
            &sandbox,
            MakeDirectoryRequest {
                path: "/workspace/src".into(),
            },
        )
        .await
        .expect("make directory");
    runtime
        .delete_file(
            &sandbox,
            DeleteFileRequest {
                path: "/workspace/notes.md".into(),
            },
        )
        .await
        .expect("delete file");

    let upload = provider
        .requests()
        .into_iter()
        .find(|request| request.method == "POST" && request.path == "/sbx_mock1/files")
        .expect("upload call");
    assert_eq!(upload.body, b"hello");
    // Paths outside the workspace are refused before any guest call.
    assert!(matches!(
        runtime.get_file(&sandbox, "/etc/passwd").await,
        Err(CoreError::Forbidden(_))
    ));
}

#[tokio::test]
async fn a_workspace_archive_is_staged_before_it_is_installed() {
    let provider = MockProvider::start(Arc::new(|request: &Recorded| {
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v2/sandboxes") => MockResponse::json(201, created_sandbox_body()),
            ("POST", "/sbx_mock1/filesystem.Filesystem/MakeDir") => MockResponse::json(200, "{}"),
            ("POST", "/sbx_mock1/process.Process/Start") => {
                MockResponse::json(200, stream_body(&[], 0))
            }
            ("POST", "/sbx_mock1/files") => MockResponse::json(200, "{}"),
            _ => MockResponse::json(404, r#"{"code":404,"message":"unhandled"}"#),
        }
    }))
    .await;
    let runtime = provider.runtime();
    let mut sandbox = sandbox_for(NetworkPolicy::Disabled);
    runtime.create(&sandbox).await.expect("create");
    sandbox.runtime_path = runtime.runtime_path(&sandbox);

    runtime
        .import_workspace_archive(&sandbox, b"archive-bytes")
        .await
        .expect("import workspace");

    let commands: Vec<String> = provider
        .requests()
        .into_iter()
        .filter(|request| request.path.ends_with("process.Process/Start"))
        .map(|request| String::from_utf8_lossy(&request.body).into_owned())
        .collect();
    // Extract, verify, clear, install, clean up: the workspace is only replaced
    // once the staged copy is known to be complete.
    assert!(commands.iter().any(|body| body.contains(r#""cmd":"tar""#)));
    assert!(commands.iter().any(|body| body.contains(r#""cmd":"test""#)));
    assert!(commands.iter().any(|body| body.contains(r#""cmd":"mv""#)));
    let install = commands
        .iter()
        .position(|body| body.contains(r#""cmd":"mv""#))
        .expect("install command");
    let clear = commands
        .iter()
        .position(|body| body.contains(r#""cmd":"rm""#) && body.contains("-rf"))
        .expect("clear command");
    assert!(clear < install, "the old workspace is cleared last");
    let upload = provider
        .requests()
        .into_iter()
        .find(|request| request.method == "POST" && request.path == "/sbx_mock1/files")
        .expect("archive upload");
    assert_eq!(upload.body, b"archive-bytes");
}

#[tokio::test]
async fn pause_and_resume_use_the_provider_lifecycle_calls() {
    let provider = MockProvider::start(lifecycle_handler(201, created_sandbox_body())).await;
    let runtime = provider.runtime();
    let mut sandbox = sandbox_for(NetworkPolicy::Disabled);
    runtime.create(&sandbox).await.expect("create");
    sandbox.runtime_path = runtime.runtime_path(&sandbox);

    runtime.pause(&sandbox).await.expect("pause");
    runtime.resume(&sandbox).await.expect("resume");
    // E2B has no terminal stop: stopping keeps the workspace by pausing, and
    // starting again resumes the same provider sandbox.
    runtime.stop(&sandbox).await.expect("stop");
    runtime.start(&sandbox).await.expect("start");

    assert_eq!(provider.count("POST", "/sandboxes/sbx_mock1/pause"), 2);
    assert_eq!(provider.count("POST", "/v2/sandboxes/sbx_mock1/connect"), 2);
    assert_eq!(provider.count("POST", "/v2/sandboxes"), 1);
}

#[tokio::test]
async fn health_reports_real_provider_reachability() {
    let reachable = MockProvider::start(Arc::new(|request: &Recorded| {
        if request.path == "/v2/sandboxes" {
            MockResponse::json(200, format!("[{}]", created_sandbox_body()))
        } else {
            MockResponse::json(404, r#"{"code":404,"message":"unhandled"}"#)
        }
    }))
    .await;
    assert!(reachable.runtime().health().await.healthy);

    let broken = MockProvider::start(Arc::new(|_: &Recorded| {
        MockResponse::json(500, r#"{"code":500,"message":"control plane down"}"#)
    }))
    .await;
    let health = broken.runtime().health().await;
    assert!(!health.healthy);
    let message = health.message.unwrap_or_default();
    assert!(message.contains("control plane down"), "{message}");
    assert!(!message.contains("e2b_test_key"), "{message}");
}

/// Builds a Connect stream body carrying stdout/stderr chunks and an end event.
fn stream_body(chunks: &[(&str, &str)], exit_code: i32) -> Vec<u8> {
    let mut body = Vec::new();
    for (stream, text) in chunks {
        let encoded = base64::engine::general_purpose::STANDARD.encode(text);
        push_frame(
            &mut body,
            &format!(r#"{{"event":{{"data":{{"{stream}":"{encoded}"}}}}}}"#),
        );
    }
    push_frame(
        &mut body,
        &format!(r#"{{"event":{{"end":{{"exitCode":{exit_code}}}}}}}"#),
    );
    body
}

/// A guest that keeps writing past the bound AIec enforces.
fn noisy_stream_body() -> Vec<u8> {
    let chunk = "x".repeat(64 * 1024);
    let chunks: Vec<(&str, &str)> = vec![("stdout", chunk.as_str()); 24];
    stream_body(&chunks, 0)
}

fn push_frame(body: &mut Vec<u8>, message: &str) {
    body.push(0);
    body.extend_from_slice(&(message.len() as u32).to_be_bytes());
    body.extend_from_slice(message.as_bytes());
}
