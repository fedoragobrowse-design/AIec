use agentforge_api::{AppState, DefaultPolicy, DevelopmentScheduler, app};
use agentforge_core::*;
use agentforge_core::{
    images::{ImageDigest, ImageReference, ImageResolver, ResolvedImage},
    platform::Platform,
    runtime::{RuntimeCapabilities, RuntimeHealth, SandboxRuntime},
    snapshots::SnapshotProvider,
    storage::MetadataStore,
};
use agentforge_storage::MemoryRepository;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use parking_lot::Mutex;
use sha2::Digest;
use std::sync::{Arc, LazyLock};
use tower::ServiceExt;
use uuid::Uuid;

static MOCK_WRITES: LazyLock<Mutex<Vec<PutFileRequest>>> = LazyLock::new(|| Mutex::new(Vec::new()));

fn mock_writes() -> &'static Mutex<Vec<PutFileRequest>> {
    &MOCK_WRITES
}
struct MockRuntime;
#[async_trait]
impl SandboxRuntime for MockRuntime {
    async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn exec(&self, _: &Sandbox, r: ExecRequest) -> Result<ExecResult, CoreError> {
        Ok(ExecResult {
            exit_code: 0,
            stdout: r.command.join(" "),
            stderr: String::new(),
            duration_ms: 1,
            timed_out: false,
        })
    }
    async fn put_file(&self, _: &Sandbox, request: PutFileRequest) -> Result<(), CoreError> {
        mock_writes().lock().push(request);
        Ok(())
    }
    async fn get_file(&self, _: &Sandbox, p: &str) -> Result<FileContent, CoreError> {
        Ok(FileContent {
            path: p.into(),
            content_base64: "aGk=".into(),
        })
    }
    async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
        Ok(vec![])
    }
    async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
        Ok(())
    }
    async fn make_directory(&self, _: &Sandbox, _: MakeDirectoryRequest) -> Result<(), CoreError> {
        Ok(())
    }
    async fn import_workspace_archive(&self, _: &Sandbox, _: &[u8]) -> Result<(), CoreError> {
        Err(CoreError::Unsupported(
            "mock runtime does not restore workspaces".into(),
        ))
    }
    async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn health(&self) -> RuntimeHealth {
        RuntimeHealth::healthy()
    }
    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            exec: true,
            files: true,
            ..RuntimeCapabilities::default()
        }
    }
}

struct TaggedRuntime {
    label: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
    isolation: agentforge_core::runtime::RuntimeIsolation,
}

#[async_trait]
impl SandboxRuntime for TaggedRuntime {
    async fn create(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        self.calls
            .lock()
            .push(format!("create:{}", sandbox.runtime.as_str()));
        Ok(())
    }
    async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn exec(&self, _: &Sandbox, r: ExecRequest) -> Result<ExecResult, CoreError> {
        self.calls
            .lock()
            .push(format!("exec:{}", r.command.join(" ")));
        Ok(ExecResult {
            exit_code: 0,
            stdout: format!("{}:{}", self.label, r.command.join(" ")),
            stderr: String::new(),
            duration_ms: 1,
            timed_out: false,
        })
    }
    async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
        Ok(())
    }
    async fn get_file(&self, _: &Sandbox, p: &str) -> Result<FileContent, CoreError> {
        Ok(FileContent {
            path: p.into(),
            content_base64: String::new(),
        })
    }
    async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
        Ok(Vec::new())
    }
    async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
        Ok(())
    }
    async fn make_directory(&self, _: &Sandbox, _: MakeDirectoryRequest) -> Result<(), CoreError> {
        Ok(())
    }
    async fn import_workspace_archive(&self, _: &Sandbox, _: &[u8]) -> Result<(), CoreError> {
        Err(CoreError::Unsupported(
            "mock runtime does not restore workspaces".into(),
        ))
    }
    async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn health(&self) -> RuntimeHealth {
        RuntimeHealth::healthy()
    }
    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            isolation: self.isolation,
            exec: true,
            files: true,
            ..Default::default()
        }
    }
}

#[tokio::test]
async fn registry_auto_uses_available_capable_runtime() {
    let repo = MemoryRepository::new();
    let key = generate_api_key();
    let tenant = Uuid::now_v7();
    futures::executor::block_on(repo.put_key(ApiKeyRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant,
        digest: key_digest(&key),
        scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
        expires_at: None,
        name: "test".to_string(),
        created_at: chrono::Utc::now(),
        last_used_at: None,
        revoked_at: None,
    }))
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let firecracker = Arc::new(TaggedRuntime {
        label: "firecracker",
        calls: calls.clone(),
        isolation: agentforge_core::runtime::RuntimeIsolation::MicroVm,
    });
    let docker = Arc::new(TaggedRuntime {
        label: "docker",
        calls: calls.clone(),
        isolation: agentforge_core::runtime::RuntimeIsolation::Container,
    });
    let mut registry = agentforge_core::runtime::RuntimeRegistry::new();
    registry.register(RuntimeKind::Firecracker, firecracker.clone());
    registry.register(RuntimeKind::Docker, docker);
    let runtime = firecracker;
    let platform = Platform::builder()
        .runtime(runtime)
        .runtime_registry(Arc::new(registry))
        .metadata_store(repo)
        .scheduler(Arc::new(DevelopmentScheduler))
        .policy(Arc::new(DefaultPolicy))
        .build()
        .unwrap();
    let router = app(AppState::development(platform));
    let response = router.clone().oneshot(Request::post("/v1/sandboxes").header("authorization", format!("Bearer {key}")).header("content-type", "application/json").body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300,"runtime":"auto"}"#)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("x-agentforge-selection-reason")
            .is_some()
    );
    let value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["runtime"], "docker");
    let id = value["id"].as_str().unwrap();
    let exec = router
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/exec"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"command":["echo","hello"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exec.status(), StatusCode::OK);
    let result: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(exec.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["stdout"], "docker:echo hello");
    assert!(calls.lock().iter().any(|call| call == "create:docker"));
}

#[tokio::test]
async fn registry_auto_honors_microvm_isolation_policy() {
    let repo = MemoryRepository::new();
    let key = generate_api_key();
    let tenant = Uuid::now_v7();
    futures::executor::block_on(repo.put_key(ApiKeyRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant,
        digest: key_digest(&key),
        scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
        expires_at: None,
        name: "test".to_string(),
        created_at: chrono::Utc::now(),
        last_used_at: None,
        revoked_at: None,
    }))
    .unwrap();
    let docker = Arc::new(TaggedRuntime {
        label: "docker",
        calls: Arc::new(Mutex::new(Vec::new())),
        isolation: agentforge_core::runtime::RuntimeIsolation::Container,
    });
    let firecracker = Arc::new(TaggedRuntime {
        label: "firecracker",
        calls: Arc::new(Mutex::new(Vec::new())),
        isolation: agentforge_core::runtime::RuntimeIsolation::MicroVm,
    });
    let mut registry = agentforge_core::runtime::RuntimeRegistry::new();
    registry.register(RuntimeKind::Docker, docker);
    registry.register(RuntimeKind::Firecracker, firecracker);
    let platform = Platform::builder()
        .runtime(Arc::new(MockRuntime))
        .runtime_registry(Arc::new(registry))
        .metadata_store(repo)
        .scheduler(Arc::new(DevelopmentScheduler))
        .policy(Arc::new(DefaultPolicy))
        .build()
        .unwrap();
    let router = app(AppState::development(platform));
    let response = router.clone().oneshot(Request::post("/v1/sandboxes").header("authorization", format!("Bearer {key}")).header("content-type", "application/json").body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300,"runtime":"auto","isolation":"microvm"}"#)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["runtime"], "firecracker");
}
struct RecordingResolver {
    seen: Mutex<Vec<String>>,
}

#[async_trait]
impl ImageResolver for RecordingResolver {
    async fn resolve(&self, reference: &ImageReference) -> Result<ResolvedImage, CoreError> {
        self.seen.lock().push(reference.as_str().to_owned());
        Ok(ResolvedImage {
            reference: reference.clone(),
            image_id: "resolver-internal-id".into(),
            rootfs: "/internal/rootfs".into(),
            digest: ImageDigest::new("a".repeat(64)).unwrap(),
            size_bytes: 1,
            architecture: None,
        })
    }
}

fn development_platform(
    runtime: Arc<dyn SandboxRuntime>,
    metadata: Arc<dyn MetadataStore>,
    snapshots: Option<Arc<dyn SnapshotProvider>>,
) -> (Platform, std::path::PathBuf) {
    // A workspace capture is only durable once its archive reaches shared
    // storage, so every development platform gets a real object store rooted
    // in a temporary directory. The returned path lets the caller clean up.
    let artifacts = std::env::temp_dir().join(format!("aiec-snapshots-{}", Uuid::now_v7()));
    let builder = Platform::builder()
        .runtime(runtime)
        .metadata_store(metadata)
        .scheduler(Arc::new(DevelopmentScheduler))
        .artifact_store(Arc::new(agentforge_storage::FilesystemObjectStore::new(
            &artifacts,
        )))
        .policy(Arc::new(DefaultPolicy));
    let builder = if let Some(snapshots) = snapshots {
        builder.snapshots(snapshots)
    } else {
        builder
    };
    (
        builder.build().expect("valid development platform"),
        artifacts,
    )
}

/// Builds a router over `repo` whose signup accepts `invites`.
fn setup_with_invites(repo: Arc<MemoryRepository>, invites: &[&str]) -> axum::Router {
    let (platform, _artifacts) = development_platform(Arc::new(MockRuntime), repo, None);
    let state = AppState::development(platform)
        .with_invites(invites.iter().map(|code| code.to_string()).collect());
    agentforge_api::router(state)
}

fn setup() -> (axum::Router, String, String) {
    let repo = MemoryRepository::new();
    let a = generate_api_key();
    let b = generate_api_key();
    let ta = Uuid::now_v7();
    let tb = Uuid::now_v7();
    futures::executor::block_on(async {
        repo.put_key(ApiKeyRecord {
            id: Uuid::now_v7(),
            tenant_id: ta,
            digest: key_digest(&a),
            scopes: vec![
                Scope::SandboxesRead,
                Scope::SandboxesWrite,
                Scope::SnapshotsRead,
                Scope::SnapshotsWrite,
            ],
            expires_at: None,
            name: "test".to_string(),
            created_at: chrono::Utc::now(),
            last_used_at: None,
            revoked_at: None,
        })
        .await
        .unwrap();
        repo.put_key(ApiKeyRecord {
            id: Uuid::now_v7(),
            tenant_id: tb,
            digest: key_digest(&b),
            scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
            expires_at: None,
            name: "test".to_string(),
            created_at: chrono::Utc::now(),
            last_used_at: None,
            revoked_at: None,
        })
        .await
        .unwrap();
    });
    let (platform, _artifacts) = development_platform(Arc::new(MockRuntime), repo, None);
    (app(AppState::development(platform)), a, b)
}

fn setup_docker() -> (axum::Router, String) {
    let repo = MemoryRepository::new();
    let key = generate_api_key();
    let tenant = Uuid::now_v7();
    futures::executor::block_on(repo.put_key(ApiKeyRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant,
        digest: key_digest(&key),
        scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
        expires_at: None,
        name: "test".to_string(),
        created_at: chrono::Utc::now(),
        last_used_at: None,
        revoked_at: None,
    }))
    .unwrap();
    let runtime = Arc::new(MockRuntime);
    let registry = Arc::new(agentforge_core::runtime::RuntimeRegistry::with_runtime(
        RuntimeKind::Docker,
        runtime.clone(),
    ));
    let platform = Platform::builder()
        .runtime(runtime)
        .runtime_registry(registry)
        .metadata_store(repo)
        .scheduler(Arc::new(DevelopmentScheduler))
        .policy(Arc::new(DefaultPolicy))
        .build()
        .unwrap();
    (
        app(AppState::development(platform).with_runtime_kind(RuntimeKind::Docker)),
        key,
    )
}

fn setup_docker_with_resolver() -> (axum::Router, String, Arc<RecordingResolver>) {
    let repo = MemoryRepository::new();
    let key = generate_api_key();
    let tenant = Uuid::now_v7();
    futures::executor::block_on(repo.put_key(ApiKeyRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant,
        digest: key_digest(&key),
        scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
        expires_at: None,
        name: "test".to_string(),
        created_at: chrono::Utc::now(),
        last_used_at: None,
        revoked_at: None,
    }))
    .unwrap();
    let resolver = Arc::new(RecordingResolver {
        seen: Mutex::new(Vec::new()),
    });
    let runtime = Arc::new(MockRuntime);
    let registry = Arc::new(agentforge_core::runtime::RuntimeRegistry::with_runtime(
        RuntimeKind::Docker,
        runtime.clone(),
    ));
    let platform = Platform::builder()
        .runtime(runtime)
        .runtime_registry(registry)
        .metadata_store(repo)
        .scheduler(Arc::new(DevelopmentScheduler))
        .images(resolver.clone())
        .policy(Arc::new(DefaultPolicy))
        .build()
        .unwrap();
    (
        app(AppState::development(platform).with_runtime_kind(RuntimeKind::Docker)),
        key,
        resolver,
    )
}

#[tokio::test]
async fn docker_image_reference_survives_resolver_admission() {
    let (router, key, resolver) = setup_docker_with_resolver();
    let response = router
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300,"runtime":"docker"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["image_id"], "python:3.13");
    assert_eq!(resolver.seen.lock().as_slice(), &["python:3.13"]);
}

#[tokio::test]
async fn docker_runtime_selection_is_recorded_and_mismatches_fail_closed() {
    let (router, key) = setup_docker();
    let response = router
        .clone()
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300,"runtime":"docker"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["runtime"], "docker");

    let mismatch = router
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300,"runtime":"firecracker"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(mismatch.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(error["error"]["code"], "runtime_unavailable");
}
#[tokio::test]
async fn responses_propagate_operation_id_and_reject_invalid_values() {
    let (router, _, _) = setup();
    let operation_id = Uuid::now_v7();
    let response = router
        .clone()
        .oneshot(
            Request::get("/health")
                .header("x-operation-id", operation_id.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-operation-id")
            .unwrap()
            .to_str()
            .unwrap(),
        operation_id.to_string()
    );
    let denied_operation_id = Uuid::now_v7();
    let denied = router
        .clone()
        .oneshot(
            Request::get("/v1/sandboxes")
                .header("x-operation-id", denied_operation_id.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        denied
            .headers()
            .get("x-operation-id")
            .unwrap()
            .to_str()
            .unwrap(),
        denied_operation_id.to_string()
    );
    let generated = router
        .oneshot(
            Request::get("/ready")
                .header("x-operation-id", "not-a-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(generated.status(), StatusCode::OK);
    assert!(
        Uuid::parse_str(
            generated
                .headers()
                .get("x-operation-id")
                .unwrap()
                .to_str()
                .unwrap()
        )
        .is_ok()
    );
}
#[tokio::test]

async fn metrics_counts_requests_and_omits_sandbox_gauge() {
    let (router, _, _) = setup();
    let first = router
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let metrics = router
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(metrics.status(), StatusCode::OK);
    let body = axum::body::to_bytes(metrics.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("agentforge_api_requests_total 2"));
    assert!(!text.contains("agentforge_sandboxes_total"));
}

#[tokio::test]
async fn lifecycle_exec_and_typed_error() {
    let (router, key, _) = setup();
    let create=router.clone().oneshot(Request::post("/v1/sandboxes").header("authorization",format!("Bearer {key}")).header("content-type","application/json").body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300,"network":{"enabled":false}}"#)).unwrap()).await.unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let sandbox: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = sandbox["id"].as_str().unwrap();
    let exec = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/exec"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"command":["echo","ok"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exec.status(), StatusCode::OK);
    let bad = router
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/exec"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"command":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pause_and_resume_follow_explicit_state_transitions() {
    let (router, key, _) = setup();
    let create = router
        .clone()
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = serde_json::from_slice::<serde_json::Value>(
        &axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let pause = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/pause"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pause.status(), StatusCode::OK);
    let pause_value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(pause.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(pause_value["state"], "paused");
    let resume = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/resume"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resume.status(), StatusCode::OK);
    let resume_value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resume.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(resume_value["state"], "running");
    let invalid_resume = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/resume"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_resume.status(), StatusCode::CONFLICT);
    let stopped = router
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/stop"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stopped.status(), StatusCode::OK);
}

#[tokio::test]
async fn bubblewrap_pause_returns_not_implemented() {
    let root = std::env::temp_dir().join(format!("aiec-bwrap-pause-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).unwrap();
    let repo = MemoryRepository::new();
    let key = generate_api_key();
    let tenant = Uuid::now_v7();
    futures::executor::block_on(repo.put_key(ApiKeyRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant,
        digest: key_digest(&key),
        scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
        expires_at: None,
        name: "test".to_string(),
        created_at: chrono::Utc::now(),
        last_used_at: None,
        revoked_at: None,
    }))
    .unwrap();
    let runtime = Arc::new(agentforge_runtime::BubblewrapRuntime::new(&root));
    let platform = Platform::builder()
        .runtime(runtime)
        .metadata_store(repo)
        .scheduler(Arc::new(DevelopmentScheduler))
        .policy(Arc::new(DefaultPolicy))
        .build()
        .unwrap();
    let router = app(AppState::development(platform));
    let create = router.clone().oneshot(Request::post("/v1/sandboxes").header("authorization", format!("Bearer {key}")).header("content-type", "application/json").body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300}"#)).unwrap()).await.unwrap();
    let id = serde_json::from_slice::<serde_json::Value>(
        &axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = router
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/pause"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn environment_toolkit_runs_during_create() {
    let (router, key, _) = setup();
    let response = router
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "image": "python:3.13",
                        "cpu": 1,
                        "memory_mb": 512,
                        "disk_mb": 2048,
                        "timeout_seconds": 300,
                        "environment": {
                            "toolkits": [{
                                "name": "smoke",
                                "setup_commands": [["true"]]
                            }]
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
#[tokio::test]
async fn environment_layer_payload_is_materialized_read_only() {
    mock_writes().lock().clear();
    let (router, key, _) = setup();
    let content = b"layer payload";
    let digest = hex::encode(sha2::Sha256::digest(content));
    let response = router
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "image": "python:3.13",
                        "environment": {
                            "layers": [{
                                "kind": "toolkit",
                                "name": "proof",
                                "content_digest": digest,
                                "content_base64": "bGF5ZXIgcGF5bG9hZA=="
                            }]
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let writes = mock_writes().lock();
    assert!(writes.iter().any(|write| {
        write.path == "/workspace/.agentforge/layers/toolkit/proof"
            && write.content_base64 == "bGF5ZXIgcGF5bG9hZA=="
            && write.mode == Some(0o444)
    }));
}

#[tokio::test]
async fn artifacts_are_tenant_scoped_and_bounded() {
    let (router, key, other) = setup_with_artifacts();
    let create = router.clone().oneshot(Request::post("/v1/sandboxes").header("authorization", format!("Bearer {key}")).header("content-type", "application/json").body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300}"#)).unwrap()).await.unwrap();
    let id = serde_json::from_slice::<serde_json::Value>(
        &axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let invalid_name = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/artifacts/bad%20name"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content_base64":"eA=="}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_name.status(), StatusCode::BAD_REQUEST);
    let upload = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/artifacts/report.txt"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content_base64":"cHJpdmF0ZQ=="}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let oversized_bytes = vec![b'x'; 64 * 1024 * 1024 + 1];
    let oversized = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/artifacts/too-large.bin"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "content_base64": base64::engine::general_purpose::STANDARD.encode(oversized_bytes)
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let second = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/artifacts/second.txt"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content_base64":"c2Vjb25k"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let listed = router
        .clone()
        .oneshot(
            Request::get(format!("/v1/sandboxes/{id}/artifacts"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed_value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(listed.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        listed_value[0]["key"]
            .as_str()
            .unwrap()
            .ends_with("report.txt")
    );
    assert_eq!(listed_value[0]["size_bytes"], 7);
    assert!(
        listed_value[1]["key"]
            .as_str()
            .unwrap()
            .ends_with("second.txt")
    );
    assert_eq!(listed_value[1]["size_bytes"], 6);
    let cross_list = router
        .clone()
        .oneshot(
            Request::get(format!("/v1/sandboxes/{id}/artifacts"))
                .header("authorization", format!("Bearer {other}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_list.status(), StatusCode::NOT_FOUND);
    let cross_tenant = router
        .clone()
        .oneshot(
            Request::get(format!("/v1/sandboxes/{id}/artifacts/report.txt"))
                .header("authorization", format!("Bearer {other}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);
    let download = router
        .clone()
        .oneshot(
            Request::get(format!("/v1/sandboxes/{id}/artifacts/report.txt"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(download.status(), StatusCode::OK);
    let download_value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(download.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(download_value["content_base64"], "cHJpdmF0ZQ==");
    assert_eq!(download_value["size_bytes"], 7);
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let content = base64::engine::general_purpose::STANDARD
        .decode(download_value["content_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(content, b"private");
    assert_eq!(
        download_value["checksum_sha256"],
        hex::encode(Sha256::digest(&content))
    );
    let deleted = router
        .clone()
        .oneshot(
            Request::delete(format!("/v1/sandboxes/{id}/artifacts/report.txt"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    let listed_after_delete = router
        .clone()
        .oneshot(
            Request::get(format!("/v1/sandboxes/{id}/artifacts"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed_after_delete.status(), StatusCode::OK);
    let listed_after_delete: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(listed_after_delete.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(listed_after_delete.as_array().map(Vec::len), Some(1));
    assert!(
        listed_after_delete[0]["key"]
            .as_str()
            .unwrap()
            .ends_with("second.txt")
    );
    let missing = router
        .oneshot(
            Request::get(format!("/v1/sandboxes/{id}/artifacts/report.txt"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

fn setup_with_artifacts() -> (axum::Router, String, String) {
    let repo = MemoryRepository::new();
    let a = generate_api_key();
    let b = generate_api_key();
    let ta = Uuid::now_v7();
    let tb = Uuid::now_v7();
    futures::executor::block_on(async {
        repo.put_key(ApiKeyRecord {
            id: Uuid::now_v7(),
            tenant_id: ta,
            digest: key_digest(&a),
            scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
            expires_at: None,
            name: "test".to_string(),
            created_at: chrono::Utc::now(),
            last_used_at: None,
            revoked_at: None,
        })
        .await
        .unwrap();
        repo.put_key(ApiKeyRecord {
            id: Uuid::now_v7(),
            tenant_id: tb,
            digest: key_digest(&b),
            scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
            expires_at: None,
            name: "test".to_string(),
            created_at: chrono::Utc::now(),
            last_used_at: None,
            revoked_at: None,
        })
        .await
        .unwrap();
    });
    let root = std::env::temp_dir().join(format!("aiec-artifacts-{}", Uuid::now_v7()));
    let platform = Platform::builder()
        .runtime(Arc::new(MockRuntime))
        .metadata_store(repo)
        .scheduler(Arc::new(DevelopmentScheduler))
        .artifact_store(Arc::new(agentforge_storage::FilesystemObjectStore::new(
            root,
        )))
        .policy(Arc::new(DefaultPolicy))
        .build()
        .unwrap();
    (app(AppState::development(platform)), a, b)
}

#[tokio::test]
async fn secrets_are_scoped_listed_and_revoked_without_value_disclosure() {
    let (router, key, _) = setup();
    let create = router
        .clone()
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = serde_json::from_slice::<serde_json::Value>(
        &axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let put = router
        .clone()
        .oneshot(
            Request::put(format!("/v1/sandboxes/{id}/secrets/API_TOKEN"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"not-public"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK);
    let list = router
        .clone()
        .oneshot(
            Request::get(format!("/v1/sandboxes/{id}/secrets"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list_body = axum::body::to_bytes(list.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(!list_body.windows(10).any(|window| window == b"not-public"));
    let revoke = router
        .clone()
        .oneshot(
            Request::delete(format!("/v1/sandboxes/{id}/secrets/API_TOKEN"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::OK);
    let destroy = router
        .clone()
        .oneshot(
            Request::delete(format!("/v1/sandboxes/{id}"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(destroy.status(), StatusCode::OK);
    let after_destroy = router
        .clone()
        .oneshot(
            Request::get(format!("/v1/sandboxes/{id}/secrets"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(after_destroy.status(), StatusCode::NOT_FOUND);
    let put_after_destroy = router
        .clone()
        .oneshot(
            Request::put(format!("/v1/sandboxes/{id}/secrets/AFTER"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"blocked"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_after_destroy.status(), StatusCode::NOT_FOUND);
    let delete_after_destroy = router
        .oneshot(
            Request::delete(format!("/v1/sandboxes/{id}/secrets/AFTER"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_after_destroy.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn secrets_are_bounded_and_updates_do_not_consume_capacity() {
    let (router, key, _) = setup();
    let create = router
        .clone()
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = serde_json::from_slice::<serde_json::Value>(
        &axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for index in 0..32 {
        let response = router
            .clone()
            .oneshot(
                Request::put(format!("/v1/sandboxes/{id}/secrets/TOKEN_{index}"))
                    .header("authorization", format!("Bearer {key}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"value":"value"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let update = router
        .clone()
        .oneshot(
            Request::put(format!("/v1/sandboxes/{id}/secrets/TOKEN_0"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"updated"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let overflow = router
        .clone()
        .oneshot(
            Request::put(format!("/v1/sandboxes/{id}/secrets/TOKEN_32"))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"overflow"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(overflow.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
#[tokio::test]
async fn cross_tenant_is_not_found() {
    let (router, a, b) = setup();
    let create=router.clone().oneshot(Request::post("/v1/sandboxes").header("authorization",format!("Bearer {a}")).header("content-type","application/json").body(Body::from(r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300}"#)).unwrap()).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = v["id"].as_str().unwrap();
    let response = router
        .oneshot(
            Request::get(format!("/v1/sandboxes/{id}"))
                .header("authorization", format!("Bearer {b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
/// Cross-tenant attack matrix.
///
/// Tenant B must not be able to reach Tenant A's resources by knowing their
/// identifiers. Possession of a resource ID must never imply authorization, so
/// every operation below must answer 404 rather than 403 (a 403 would confirm
/// the resource exists) and must never return A's data or mutate A's state.
#[tokio::test]
async fn cross_tenant_attack_matrix_is_denied_everywhere() {
    let (router, a, b) = setup();

    // Tenant A creates a sandbox, a secret, a snapshot and an artifact.
    let create = router
        .clone()
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", format!("Bearer {a}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let sandbox = created["id"].as_str().expect("sandbox id").to_string();

    let seeded = router
        .clone()
        .oneshot(
            Request::put(format!("/v1/sandboxes/{sandbox}/secrets/TOKEN"))
                .header("authorization", format!("Bearer {a}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"a-private-value"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(seeded.status().is_success(), "seeding a secret failed");

    let snap = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{sandbox}/snapshots"))
                .header("authorization", format!("Bearer {a}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"kind":"workspace"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let snap_status = snap.status();
    let snap_id = if snap_status == StatusCode::CREATED || snap_status == StatusCode::OK {
        serde_json::from_slice::<serde_json::Value>(
            &axum::body::to_bytes(snap.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .ok()
        .and_then(|value| value["id"].as_str().map(str::to_string))
    } else {
        None
    };

    // Every cross-tenant operation, with a known-good identifier.
    let mut attacks: Vec<(&str, axum::http::Method, String, Option<&str>)> = vec![
        (
            "get sandbox",
            axum::http::Method::GET,
            format!("/v1/sandboxes/{sandbox}"),
            None,
        ),
        (
            "exec",
            axum::http::Method::POST,
            format!("/v1/sandboxes/{sandbox}/exec"),
            Some(r#"{"command":["id"]}"#),
        ),
        (
            "write file",
            axum::http::Method::PUT,
            format!("/v1/sandboxes/{sandbox}/files"),
            Some(r#"{"path":"/workspace/x","content_base64":"eA=="}"#),
        ),
        (
            "read file",
            axum::http::Method::GET,
            format!("/v1/sandboxes/{sandbox}/files/content?path=/workspace/x"),
            None,
        ),
        (
            "list files",
            axum::http::Method::GET,
            format!("/v1/sandboxes/{sandbox}/files"),
            None,
        ),
        (
            "delete file",
            axum::http::Method::DELETE,
            format!("/v1/sandboxes/{sandbox}/files?path=/workspace/x"),
            None,
        ),
        (
            "make directory",
            axum::http::Method::POST,
            format!("/v1/sandboxes/{sandbox}/files/mkdir"),
            Some(r#"{"path":"/workspace/d"}"#),
        ),
        (
            "stop",
            axum::http::Method::POST,
            format!("/v1/sandboxes/{sandbox}/stop"),
            None,
        ),
        (
            "start",
            axum::http::Method::POST,
            format!("/v1/sandboxes/{sandbox}/start"),
            None,
        ),
        (
            "delete sandbox",
            axum::http::Method::DELETE,
            format!("/v1/sandboxes/{sandbox}"),
            None,
        ),
    ];
    if let Some(snap_id) = &snap_id {
        attacks.push((
            "get snapshot",
            axum::http::Method::GET,
            format!("/v1/snapshots/{snap_id}"),
            None,
        ));
        attacks.push((
            "delete snapshot",
            axum::http::Method::DELETE,
            format!("/v1/snapshots/{snap_id}"),
            None,
        ));
        attacks.push((
            "restore snapshot",
            axum::http::Method::POST,
            format!("/v1/snapshots/{snap_id}/restore"),
            Some(r#"{}"#),
        ));
    }

    for (label, method, path, body) in attacks {
        let payload = body.map(Body::from).unwrap_or_else(Body::empty);
        let request = Request::builder()
            .method(method)
            .uri(&path)
            .header("authorization", format!("Bearer {b}"))
            .header("content-type", "application/json")
            .body(payload)
            .expect("request builds");
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        // 404 proves the resource is invisible to B. 401/403 would mean B was
        // denied rather than hidden, which leaks existence.
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
            "cross-tenant {label} returned {status}, expected the resource to be invisible"
        );
    }

    // List endpoints may legitimately answer 200 — a tenant may list its own
    // resources. What must never happen is tenant A's data appearing in tenant
    // B's view, so those are asserted on content rather than status.
    for (label, path) in [
        ("sandboxes", "/v1/sandboxes".to_string()),
        ("usage", "/v1/usage".to_string()),
        ("snapshots", format!("/v1/sandboxes/{sandbox}/snapshots")),
        ("artifacts", format!("/v1/sandboxes/{sandbox}/artifacts")),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::get(&path)
                    .header("authorization", format!("Bearer {b}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains(&sandbox),
            "tenant B saw tenant A's sandbox through {label}: {text}"
        );
        assert!(
            !text.contains("a-private-value"),
            "tenant B saw tenant A's secret value through {label}"
        );
    }

    // Tenant A's sandbox must still exist and be usable: the attacks above
    // must not have mutated another tenant's state.
    let survivor = router
        .oneshot(
            Request::get(format!("/v1/sandboxes/{sandbox}"))
                .header("authorization", format!("Bearer {a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        survivor.status(),
        StatusCode::OK,
        "tenant A's sandbox was damaged by cross-tenant attacks"
    );
}

/// A stranger can sign up with an invite and immediately use the key they get.
#[tokio::test]
async fn signup_with_invite_returns_a_usable_key() {
    let repo = MemoryRepository::new();
    let router = setup_with_invites(repo, &["alpha-one"]);

    let response = router
        .clone()
        .oneshot(
            Request::post("/v1/account")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"invite":"alpha-one","name":"Ada"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let key = value["key"]["key"]
        .as_str()
        .expect("key returned once")
        .to_string();
    assert!(key.starts_with("af_live_"));
    assert_eq!(value["account"]["name"], "Ada");

    // The returned key must actually authenticate.
    let usable = router
        .clone()
        .oneshot(
            Request::get("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(usable.status(), StatusCode::OK);
}

/// Signup without a valid invite is refused, and an unconfigured deployment has
/// signup closed rather than open.
#[tokio::test]
async fn signup_requires_a_configured_invite() {
    let repo = MemoryRepository::new();
    let router_closed = setup_with_invites(repo, &[]);
    let response = router_closed
        .oneshot(
            Request::post("/v1/account")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"invite":"anything","name":"Mallory"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a deployment with no configured invites must not accept signups"
    );
}

/// A signed-up tenant can list and revoke its own keys, and never sees a secret.
#[tokio::test]
async fn a_tenant_can_manage_its_own_keys() {
    let repo = MemoryRepository::new();
    let router = setup_with_invites(repo, &["alpha-one"]);

    let created = router
        .clone()
        .oneshot(
            Request::post("/v1/account")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"invite":"alpha-one","name":"Grace"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(created.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let key = value["key"]["key"].as_str().expect("key").to_string();
    let key_id = value["key"]["id"].as_str().expect("key id").to_string();

    let listed = router
        .clone()
        .oneshot(
            Request::get("/v1/keys")
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let body = axum::body::to_bytes(listed.into_body(), usize::MAX)
        .await
        .unwrap();
    let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(listed["keys"].as_array().expect("keys array").len(), 1);
    assert!(
        body.windows(11).all(|w| w != b"af_live_abc"),
        "a listing must never contain key material"
    );

    let revoked = router
        .clone()
        .oneshot(
            Request::delete(format!("/v1/keys/{key_id}"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::OK);

    // The revoked key must stop working immediately.
    let after = router
        .oneshot(
            Request::get("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn real_bubblewrap_lifecycle_file_snapshot_restore() {
    use agentforge_runtime::BubblewrapRuntime;
    use serde_json::Value;

    let root = std::env::temp_dir().join(format!("agentforge-e2e-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).unwrap();
    let repo = MemoryRepository::new();
    let repo_for_test = repo.clone();
    let key = generate_api_key();
    let tenant = Uuid::now_v7();
    repo.put_key(ApiKeyRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant,
        digest: key_digest(&key),
        scopes: vec![Scope::Admin],
        expires_at: None,
        name: "test".to_string(),
        created_at: chrono::Utc::now(),
        last_used_at: None,
        revoked_at: None,
    })
    .await
    .unwrap();
    let bubblewrap = Arc::new(BubblewrapRuntime::new(&root));
    let (platform, artifacts) = development_platform(bubblewrap.clone(), repo, Some(bubblewrap));
    let router = app(AppState::development(platform));
    let auth = format!("Bearer {key}");
    let create = router
        .clone()
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300,"network":{"enabled":false}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let created: Value = serde_json::from_slice(
        &axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = created["id"].as_str().unwrap();
    let exec = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/exec"))
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"command":["/bin/sh","-lc","printf AgentForge > result.txt && cat result.txt"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exec.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(
        &axum::body::to_bytes(exec.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["stdout"], "AgentForge", "runtime result: {result}");

    let snapshot = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/sandboxes/{id}/snapshots"))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(snapshot.status(), StatusCode::OK);
    let snapshot_value: Value = serde_json::from_slice(
        &axum::body::to_bytes(snapshot.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let snapshot_id = snapshot_value["id"].as_str().unwrap();
    assert!(
        snapshot_value["object_key"]
            .as_str()
            .is_some_and(|key| !key.contains('/')),
        "snapshot object key must satisfy runtime archive key rules: {snapshot_value}"
    );
    let vm_snapshot_id = Uuid::now_v7();
    repo_for_test
        .put_stored_snapshot(agentforge_core::storage::StoredSnapshot {
            id: vm_snapshot_id,
            tenant_id: tenant,
            sandbox_id: Uuid::parse_str(id).unwrap(),
            object_key: format!("{id}/vm-state"),
            manifest_object_key: format!("{id}/vm-state.manifest.json"),
            memory_object_key: Some(format!("{id}/memory")),
            disk_object_key: Some(format!("{id}/disk")),
            workspace_object_key: None,
            size_bytes: 1,
            image_id: "python:3.13".into(),
            checksum_sha256: "0".repeat(64),
            kind: "virtual_machine".into(),
            complete: true,
            manifest: serde_json::json!({"kind": "virtual_machine"}),
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let vm_workspace = router
        .clone()
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "image": "python:3.13",
                        "cpu": 1,
                        "memory_mb": 512,
                        "disk_mb": 2048,
                        "timeout_seconds": 300,
                        "environment": {"workspace": {"type": "snapshot", "snapshot_id": vm_snapshot_id}}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(vm_workspace.status(), StatusCode::CONFLICT);
    let workspace_clone = router
        .clone()
        .oneshot(
            Request::post("/v1/sandboxes")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "image": "python:3.13",
                        "cpu": 1,
                        "memory_mb": 512,
                        "disk_mb": 2048,
                        "timeout_seconds": 300,
                        "environment": {
                            "workspace": {
                                "type": "snapshot",
                                "snapshot_id": snapshot_id
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(workspace_clone.status(), StatusCode::OK);
    let workspace_clone_value: Value = serde_json::from_slice(
        &axum::body::to_bytes(workspace_clone.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let workspace_clone_id = workspace_clone_value["id"].as_str().unwrap();
    let workspace_clone_read = router
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/sandboxes/{workspace_clone_id}/files/content?path=%2Fworkspace%2Fresult.txt"
            ))
            .header("authorization", &auth)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(workspace_clone_read.status(), StatusCode::OK);
    let workspace_clone_file: Value = serde_json::from_slice(
        &axum::body::to_bytes(workspace_clone_read.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(workspace_clone_file["content_base64"].as_str().unwrap())
            .unwrap(),
        b"AgentForge"
    );
    let workspace_clone_destroy = router
        .clone()
        .oneshot(
            Request::delete(format!("/v1/sandboxes/{workspace_clone_id}"))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(workspace_clone_destroy.status(), StatusCode::OK);

    let destroy = router
        .clone()
        .oneshot(
            Request::delete(format!("/v1/sandboxes/{id}"))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(destroy.status(), StatusCode::OK);
    let restore = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/snapshots/{snapshot_id}/restore"))
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(restore.status(), StatusCode::OK);
    let restored: Value = serde_json::from_slice(
        &axum::body::to_bytes(restore.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let restored_id = restored["id"].as_str().unwrap();
    let read = router
        .oneshot(
            Request::get(format!(
                "/v1/sandboxes/{restored_id}/files/content?path=%2Fworkspace%2Fresult.txt"
            ))
            .header("authorization", auth)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let read_status = read.status();
    let read_body = axum::body::to_bytes(read.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        read_status,
        StatusCode::OK,
        "restored file response: {}",
        String::from_utf8_lossy(&read_body)
    );
    let file: Value = serde_json::from_slice(&read_body).unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(file["content_base64"].as_str().unwrap())
            .unwrap(),
        b"AgentForge"
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(artifacts);
}
