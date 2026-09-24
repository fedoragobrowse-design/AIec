use agentforge_api::{AppState, DefaultPolicy, DevelopmentScheduler, app};
use agentforge_core::*;
use agentforge_core::{
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
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

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
    async fn exec(&self, _: &Sandbox, r: ExecRequest) -> Result<ExecResult, CoreError> {
        Ok(ExecResult {
            exit_code: 0,
            stdout: r.command.join(" "),
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
            content_base64: "aGk=".into(),
        })
    }
    async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
        Ok(vec![])
    }
    async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
        Ok(())
    }
    async fn make_directory(
        &self,
        _: &Sandbox,
        _: MakeDirectoryRequest,
    ) -> Result<(), CoreError> {
        Ok(())
    }
    async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
        Ok(())
    }
    async fn health(&self) -> RuntimeHealth {
        RuntimeHealth::healthy()
    }
    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::default()
    }
}

fn development_platform(
    runtime: Arc<dyn SandboxRuntime>,
    metadata: Arc<dyn MetadataStore>,
    snapshots: Option<Arc<dyn SnapshotProvider>>,
) -> Platform {
    let builder = Platform::builder()
        .runtime(runtime)
        .metadata_store(metadata)
        .scheduler(Arc::new(DevelopmentScheduler))
        .policy(Arc::new(DefaultPolicy));
    let builder = if let Some(snapshots) = snapshots {
        builder.snapshots(snapshots)
    } else {
        builder
    };
    builder.build().expect("valid development platform")
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
            revoked_at: None,
        })
        .await
        .unwrap();
    });
    let platform = development_platform(
        Arc::new(MockRuntime),
        repo,
        None,
    );
    (app(AppState::development(platform)), a, b)
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

#[tokio::test]
async fn real_bubblewrap_lifecycle_file_snapshot_restore() {
    use agentforge_runtime::BubblewrapRuntime;
    use serde_json::Value;

    let root = std::env::temp_dir().join(format!("agentforge-e2e-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).unwrap();
    let repo = MemoryRepository::new();
    let key = generate_api_key();
    let tenant = Uuid::now_v7();
    repo.put_key(ApiKeyRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant,
        digest: key_digest(&key),
        scopes: vec![Scope::Admin],
        expires_at: None,
        revoked_at: None,
    })
    .await
    .unwrap();
    let bubblewrap = Arc::new(BubblewrapRuntime::new(&root));
    let platform = development_platform(bubblewrap.clone(), repo, Some(bubblewrap));
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
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(file["content_base64"].as_str().unwrap())
            .unwrap(),
        b"AgentForge"
    );
    let _ = std::fs::remove_dir_all(root);
}
