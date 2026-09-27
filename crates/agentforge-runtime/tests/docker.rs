use agentforge_core::snapshots::SnapshotProvider;
use agentforge_core::*;
use agentforge_runtime::{DockerRuntime, SandboxRuntime};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bollard::Docker;
use std::time::Duration;
use uuid::Uuid;

fn docker_sandbox(image: &str) -> Sandbox {
    let now = chrono::Utc::now();
    Sandbox {
        id: new_id(),
        tenant_id: new_id(),
        node_id: None,
        image_id: image.into(),
        state: SandboxState::Creating,
        runtime: RuntimeKind::Docker,
        cpu: 1,
        memory_mb: 128,
        disk_mb: 512,
        timeout_seconds: 60,
        network: NetworkPolicy::Disabled,
        environment: Default::default(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    }
}

#[tokio::test]
async fn real_docker_lifecycle_files_and_security() {
    if std::env::var("AGENTFORGE_RUN_DOCKER_TESTS").as_deref() != Ok("1") {
        return;
    }
    let image =
        std::env::var("AGENTFORGE_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "alpine:3.21".into());
    let root = std::env::temp_dir().join(format!("agentforge-docker-{}", Uuid::new_v4()));
    let runtime = DockerRuntime::new(&root).expect("Docker daemon and client");
    let sandbox = docker_sandbox(&image);
    let mut created = false;
    let operation = async {
        assert!(runtime.health().await.healthy);
        runtime.create(&sandbox).await?;
        created = true;
        runtime.start(&sandbox).await?;
        let exec = runtime
            .exec(
                &sandbox,
                ExecRequest {
                    command: vec!["/bin/sh".into(), "-c".into(), "printf docker-ok".into()],
                    working_directory: Some("/workspace".into()),
                    environment: Default::default(),
                    timeout_seconds: 10,
                    stdin: None,
                },
            )
            .await?;
        assert_eq!(exec.stdout, "docker-ok");
        let content = b"docker file proof\x00";
        runtime
            .put_file(
                &sandbox,
                PutFileRequest {
                    path: "/workspace/nested/proof.bin".into(),
                    content_base64: STANDARD.encode(content),
                    mode: None,
                },
            )
            .await?;
        let downloaded = runtime
            .get_file(&sandbox, "/workspace/nested/proof.bin")
            .await?;
        assert_eq!(downloaded.content_base64, STANDARD.encode(content));
        let entries = runtime.list_files(&sandbox, "/workspace/nested").await?;
        assert!(entries.iter().any(|entry| entry.name == "proof.bin"));
        runtime
            .delete_file(
                &sandbox,
                DeleteFileRequest {
                    path: "/workspace/nested/proof.bin".into(),
                },
            )
            .await?;
        assert!(
            runtime
                .get_file(&sandbox, "/workspace/nested/proof.bin")
                .await
                .is_err()
        );
        runtime.pause(&sandbox).await?;
        runtime.resume(&sandbox).await?;
        let docker = Docker::connect_with_unix_defaults().map_err(|error| {
            CoreError::Unavailable(format!("Docker inspect connection failed: {error}"))
        })?;
        let name = format!("agentforge-{}", sandbox.id);
        let inspected = docker
            .inspect_container(&name, None)
            .await
            .map_err(|error| CoreError::Unavailable(format!("Docker inspect failed: {error}")))?;
        let host = inspected
            .host_config
            .ok_or_else(|| CoreError::Backend("Docker returned no host configuration".into()))?;
        assert_eq!(host.network_mode.as_deref(), Some("none"));
        assert_eq!(host.privileged, Some(false));
        assert_eq!(host.readonly_rootfs, Some(true));
        assert!(
            host.cap_drop
                .as_ref()
                .is_some_and(|caps| caps.iter().any(|cap| cap == "ALL"))
        );
        assert!(inspected.config.as_ref().is_some_and(|config| {
            config.labels.as_ref().is_some_and(|labels| {
                labels.get("com.agentforge.managed").map(String::as_str) == Some("true")
            })
        }));
        Ok::<(), CoreError>(())
    }
    .await;
    let cleanup = if created {
        runtime.destroy(&sandbox).await
    } else {
        Ok(())
    };
    if let Err(operation_error) = operation {
        if let Err(cleanup_error) = cleanup {
            panic!(
                "Docker operation failed: {operation_error}; cleanup also failed: {cleanup_error}"
            );
        }
        panic!("Docker operation failed: {operation_error}");
    }
    cleanup.expect("Docker cleanup");
    let docker = Docker::connect_with_unix_defaults().expect("Docker inspect connection");
    let name = format!("agentforge-{}", sandbox.id);
    assert!(docker.inspect_container(&name, None).await.is_err());
    assert!(!root.join(sandbox.id.to_string()).exists());
    let _ = tokio::time::timeout(Duration::from_secs(5), tokio::fs::remove_dir_all(root)).await;
}

#[tokio::test]
async fn real_docker_hundred_container_churn() {
    if std::env::var("AGENTFORGE_RUN_DOCKER_CHURN").as_deref() != Ok("1") {
        return;
    }
    let image =
        std::env::var("AGENTFORGE_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "alpine:3.21".into());
    let root = std::env::temp_dir().join(format!("agentforge-docker-churn-{}", Uuid::new_v4()));
    let runtime = DockerRuntime::new(&root).expect("Docker daemon and client");
    for _ in 0..100 {
        let sandbox = docker_sandbox(&image);
        let mut created = false;
        let operation = async {
            runtime.create(&sandbox).await?;
            created = true;
            runtime.start(&sandbox).await
        }
        .await;
        if created {
            let cleanup = runtime.destroy(&sandbox).await;
            if let Err(error) = operation {
                cleanup.expect("Docker churn cleanup after operation failure");
                panic!("Docker churn operation failed: {error}");
            }
            cleanup.expect("Docker churn cleanup");
        } else {
            operation.expect("Docker churn create/start");
        }
        assert!(!root.join(sandbox.id.to_string()).exists());
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), tokio::fs::remove_dir_all(root)).await;
}

#[tokio::test]
async fn real_docker_portable_workspace_snapshot_restore() {
    if std::env::var("AGENTFORGE_RUN_DOCKER_TESTS").as_deref() != Ok("1") {
        return;
    }
    let image =
        std::env::var("AGENTFORGE_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "alpine:3.21".into());
    let root = std::env::temp_dir().join(format!("agentforge-docker-snapshot-{}", Uuid::new_v4()));
    let runtime = DockerRuntime::new(&root).expect("Docker daemon and client");
    let source = docker_sandbox(&image);
    let snapshot_key = format!("portable-workspace-{}", Uuid::new_v4());
    let restored = Sandbox {
        id: new_id(),
        ..source.clone()
    };
    let operation = async {
        runtime.create(&source).await?;
        runtime.start(&source).await?;
        runtime
            .put_file(
                &source,
                PutFileRequest {
                    path: "/workspace/portable.txt".into(),
                    content_base64: STANDARD.encode(b"portable-workspace"),
                    mode: None,
                },
            )
            .await?;
        let captured = runtime
            .capture(
                &source,
                &agentforge_core::snapshots::SnapshotRequest {
                    kind: agentforge_core::snapshots::SnapshotKind::Workspace,
                    object_key: snapshot_key.clone(),
                },
            )
            .await?;
        runtime.destroy(&source).await?;
        runtime.create(&restored).await?;
        runtime.start(&restored).await?;
        runtime
            .restore(
                &restored,
                &agentforge_core::snapshots::SnapshotMetadata {
                    id: captured.id,
                    kind: captured.kind,
                    object_key: captured.object_key,
                    checksum_sha256: captured.checksum_sha256,
                },
            )
            .await?;
        let file = runtime
            .get_file(&restored, "/workspace/portable.txt")
            .await?;
        assert_eq!(file.content_base64, STANDARD.encode(b"portable-workspace"));
        runtime.destroy(&restored).await
    }
    .await;
    if let Err(error) = operation {
        let _ = runtime.destroy(&restored).await;
        let _ = runtime.destroy(&source).await;
        panic!("Docker portable workspace snapshot failed: {error}");
    }
    assert!(!root.join(source.id.to_string()).exists());
    assert!(!root.join(restored.id.to_string()).exists());
    let _ = tokio::time::timeout(Duration::from_secs(5), tokio::fs::remove_dir_all(root)).await;
}
