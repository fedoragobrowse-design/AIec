use agentforge_core::*;
use agentforge_runtime::{DockerRuntime, FirecrackerConfig, FirecrackerRuntime, SandboxRuntime};
use uuid::Uuid;

fn sandbox(runtime: RuntimeKind) -> Sandbox {
    let now = chrono::Utc::now();
    Sandbox {
        id: new_id(),
        tenant_id: new_id(),
        node_id: None,
        image_id: "alpine:3.21".into(),
        state: SandboxState::Creating,
        runtime,
        cpu: 1,
        memory_mb: 128,
        disk_mb: 512,
        timeout_seconds: 120,
        network: NetworkPolicy::Disabled,
        environment: Default::default(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    }
}

#[tokio::test]
async fn docker_firecracker_workspace_archive_exchange() {
    if std::env::var("AGENTFORGE_RUN_CROSS_RUNTIME_TESTS").as_deref() != Ok("1") {
        eprintln!("set AGENTFORGE_RUN_CROSS_RUNTIME_TESTS=1 to run cross-runtime integration");
        return;
    }
    let docker_root = std::env::temp_dir().join(format!("af-x-docker-{}", Uuid::new_v4()));
    let firecracker_state = std::env::temp_dir().join(format!("af-x-fc-{}", Uuid::new_v4()));
    let docker = DockerRuntime::new(&docker_root).expect("Docker daemon and client");
    let mut config = FirecrackerConfig::from_env().expect("Firecracker environment");
    config.state_dir = firecracker_state;
    config.readiness_timeout = std::time::Duration::from_secs(20);
    let firecracker = FirecrackerRuntime::new(config);

    let docker_source = sandbox(RuntimeKind::Docker);
    docker
        .create(&docker_source)
        .await
        .expect("create Docker source");
    docker
        .start(&docker_source)
        .await
        .expect("start Docker source");
    docker
        .put_file(
            &docker_source,
            PutFileRequest {
                path: "/workspace/cross-runtime.txt".into(),
                content_base64: "ZG9ja2Vy".into(),
                mode: None,
            },
        )
        .await
        .expect("write Docker workspace");
    let docker_bytes = docker
        .export_workspace_archive(&docker_source)
        .await
        .expect("export Docker archive");
    docker
        .destroy(&docker_source)
        .await
        .expect("destroy Docker source");

    let firecracker_target = sandbox(RuntimeKind::Firecracker);
    firecracker
        .create(&firecracker_target)
        .await
        .expect("create Firecracker target");
    firecracker
        .start(&firecracker_target)
        .await
        .expect("start Firecracker target");
    firecracker
        .import_workspace_archive(&firecracker_target, &docker_bytes)
        .await
        .expect("import Docker archive into Firecracker");
    let file = firecracker
        .get_file(&firecracker_target, "/workspace/cross-runtime.txt")
        .await
        .expect("read Firecracker imported file");
    assert_eq!(file.content_base64, "ZG9ja2Vy");
    firecracker
        .destroy(&firecracker_target)
        .await
        .expect("destroy Firecracker target");

    let firecracker_source = sandbox(RuntimeKind::Firecracker);
    firecracker
        .create(&firecracker_source)
        .await
        .expect("create Firecracker source");
    firecracker
        .start(&firecracker_source)
        .await
        .expect("start Firecracker source");
    firecracker
        .put_file(
            &firecracker_source,
            PutFileRequest {
                path: "/workspace/cross-runtime.txt".into(),
                content_base64: "ZmlyZWNyYWNrZXI=".into(),
                mode: None,
            },
        )
        .await
        .expect("write Firecracker workspace");
    let firecracker_bytes = firecracker
        .export_workspace_archive(&firecracker_source)
        .await
        .expect("export Firecracker archive");
    firecracker
        .destroy(&firecracker_source)
        .await
        .expect("destroy Firecracker source");

    let docker_target = sandbox(RuntimeKind::Docker);
    docker
        .create(&docker_target)
        .await
        .expect("create Docker target");
    docker
        .start(&docker_target)
        .await
        .expect("start Docker target");
    docker
        .import_workspace_archive(&docker_target, &firecracker_bytes)
        .await
        .expect("import Firecracker archive into Docker");
    let file = docker
        .get_file(&docker_target, "/workspace/cross-runtime.txt")
        .await
        .expect("read Docker imported file");
    assert_eq!(file.content_base64, "ZmlyZWNyYWNrZXI=");
    docker
        .destroy(&docker_target)
        .await
        .expect("destroy Docker target");

    let _ = tokio::fs::remove_dir_all(docker_root).await;
    let _ = tokio::fs::remove_dir_all(firecracker.config.state_dir).await;
}
