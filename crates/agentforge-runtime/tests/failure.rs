use agentforge_core::*;
use agentforge_runtime::{FirecrackerConfig, SandboxRuntime};
use std::time::Duration;

fn sandbox(runtime: RuntimeKind) -> Sandbox {
    let now = chrono::Utc::now();
    Sandbox {
        id: new_id(),
        tenant_id: new_id(),
        node_id: None,
        image_id: "afimg1_test".into(),
        state: SandboxState::Creating,
        runtime,
        cpu: 1,
        memory_mb: 128,
        disk_mb: 512,
        timeout_seconds: 60,
        network: NetworkPolicy::default(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    }
}

#[test]
fn firecracker_fails_closed_without_prerequisites() {
    let config = FirecrackerConfig {
        binary: "/missing/firecracker".into(),
        kernel: "/missing/kernel".into(),
        rootfs: "/missing/rootfs".into(),
        jailer: None,
        tap: None,
        state_dir: "/tmp/agentforge-fail-closed".into(),
        guest_secret: vec![1; 32],
        guest_cid: 3,
        readiness_timeout: Duration::from_millis(1),
    };
    let error = config.check().expect_err("missing prerequisites must fail");
    assert!(error.to_string().contains("Firecracker binary"));
}

#[tokio::test]
async fn bwrap_rejects_giant_output_without_allocating_unbounded_result() {
    use agentforge_runtime::BubblewrapRuntime;
    let root = std::env::temp_dir().join(format!("agentforge-output-{}", new_id()));
    std::fs::create_dir_all(&root).unwrap();
    let runtime = BubblewrapRuntime::new(&root);
    let value = sandbox(RuntimeKind::BwrapDev);
    runtime.create(&value).await.unwrap();
    let result = runtime
        .exec(
            &value,
            ExecRequest {
                command: vec!["/usr/bin/head".into(), "-c".into(), "10000000".into()],
                working_directory: Some("/workspace".into()),
                environment: Default::default(),
                timeout_seconds: 10,
                stdin: None,
            },
        )
        .await
        .unwrap();
    assert!(result.stdout.len() <= MAX_STDOUT);
    let _ = std::fs::remove_dir_all(root);
}
