use agentforge_core::*;
use agentforge_runtime::{FirecrackerConfig, FirecrackerRuntime, SandboxRuntime};
use std::collections::BTreeMap;
use uuid::Uuid;

#[tokio::test]
async fn real_firecracker_exec_file_snapshot_restore() {
    if std::env::var("AGENTFORGE_RUN_FIRECRACKER_TESTS").as_deref() != Ok("1") {
        eprintln!("set AGENTFORGE_RUN_FIRECRACKER_TESTS=1 to run the KVM integration test");
        return;
    }
    let mut config = FirecrackerConfig::from_env().expect("Firecracker environment");
    config.state_dir = std::env::temp_dir().join(format!("agentforge-fc-{}", Uuid::now_v7()));
    config.readiness_timeout = std::time::Duration::from_secs(20);
    let runtime = FirecrackerRuntime::new(config);
    let now = chrono::Utc::now();
    let sandbox = Sandbox {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        node_id: None,
        image_id: "agentforge".into(),
        state: SandboxState::Creating,
        runtime: RuntimeKind::Firecracker,
        cpu: 1,
        memory_mb: 256,
        disk_mb: 512,
        timeout_seconds: 120,
        network: NetworkPolicy::default(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    };
    runtime.create(&sandbox).await.expect("create rootfs");
    runtime
        .start(&sandbox)
        .await
        .expect("boot Firecracker and guest agent");
    let result = runtime
        .exec(
            &sandbox,
            ExecRequest {
                command: vec![
                    "/bin/busybox".into(),
                    "printf".into(),
                    "hello-from-firecracker".into(),
                ],
                working_directory: Some("/workspace".into()),
                environment: BTreeMap::new(),
                timeout_seconds: 10,
                stdin: None,
            },
        )
        .await
        .expect("exec in guest");
    assert_eq!(result.stdout, "hello-from-firecracker");
    let environment = runtime
        .exec(
            &sandbox,
            ExecRequest {
                command: vec!["/bin/busybox".into(), "env".into()],
                working_directory: Some("/workspace".into()),
                environment: BTreeMap::new(),
                timeout_seconds: 10,
                stdin: None,
            },
        )
        .await
        .expect("exec env in guest");
    assert!(!environment.stdout.contains("AGENTFORGE_GUEST_SECRET="));
    let stdin_result = runtime
        .exec(
            &sandbox,
            ExecRequest {
                command: vec!["/bin/busybox".into(), "cat".into()],
                working_directory: Some("/workspace".into()),
                environment: BTreeMap::new(),
                timeout_seconds: 10,
                stdin: Some("guest-stdin\n".into()),
            },
        )
        .await
        .expect("exec stdin in guest");
    assert_eq!(stdin_result.stdout, "guest-stdin\n");
    runtime
        .put_file(
            &sandbox,
            PutFileRequest {
                path: "/workspace/proof.txt".into(),
                content_base64: "cGVyc2lzdGVudC1kYXRh".into(),
                mode: None,
            },
        )
        .await
        .expect("write in guest");
    assert_eq!(
        runtime
            .get_file(&sandbox, "/workspace/proof.txt")
            .await
            .expect("read in guest")
            .content_base64,
        "cGVyc2lzdGVudC1kYXRh"
    );
    let key = format!("smoke-{}", Uuid::now_v7());
    runtime
        .snapshot(&sandbox, &key)
        .await
        .expect("full Firecracker snapshot");
    runtime.destroy(&sandbox).await.expect("destroy source VM");
    let restored = Sandbox {
        id: Uuid::now_v7(),
        ..sandbox.clone()
    };
    runtime
        .create(&restored)
        .await
        .expect("create restored rootfs");
    runtime
        .restore(&restored, &key)
        .await
        .expect("restore Firecracker snapshot");
    assert_eq!(
        runtime
            .get_file(&restored, "/workspace/proof.txt")
            .await
            .expect("read restored file")
            .content_base64,
        "cGVyc2lzdGVudC1kYXRh"
    );
    runtime
        .destroy(&restored)
        .await
        .expect("destroy restored VM");
    let _ = tokio::fs::remove_dir_all(runtime.config.state_dir).await;
}
