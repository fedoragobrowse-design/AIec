use aiec_core::snapshots::SnapshotProvider;
use aiec_core::*;
use aiec_runtime::{DockerRuntime, SandboxRuntime};
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
    if std::env::var("AIEC_RUN_DOCKER_TESTS").as_deref() != Ok("1") {
        return;
    }
    let image = std::env::var("AIEC_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "alpine:3.21".into());
    let root = std::env::temp_dir().join(format!("aiec-docker-{}", Uuid::new_v4()));
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
        let name = format!("aiec-{}", sandbox.id);
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
                labels.get("com.aiec.managed").map(String::as_str) == Some("true")
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
    let name = format!("aiec-{}", sandbox.id);
    assert!(docker.inspect_container(&name, None).await.is_err());
    assert!(!root.join(sandbox.id.to_string()).exists());
    let _ = tokio::time::timeout(Duration::from_secs(5), tokio::fs::remove_dir_all(root)).await;
}

#[tokio::test]
async fn real_docker_hundred_container_churn() {
    if std::env::var("AIEC_RUN_DOCKER_CHURN").as_deref() != Ok("1") {
        return;
    }
    let image = std::env::var("AIEC_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "alpine:3.21".into());
    let root = std::env::temp_dir().join(format!("aiec-docker-churn-{}", Uuid::new_v4()));
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
    if std::env::var("AIEC_RUN_DOCKER_TESTS").as_deref() != Ok("1") {
        return;
    }
    let image = std::env::var("AIEC_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "alpine:3.21".into());
    let root = std::env::temp_dir().join(format!("aiec-docker-snapshot-{}", Uuid::new_v4()));
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
                &aiec_core::snapshots::SnapshotRequest {
                    kind: aiec_core::snapshots::SnapshotKind::Workspace,
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
                &aiec_core::snapshots::SnapshotMetadata {
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

/// A listing answers a question about metadata, so its size must be a function
/// of what is directly inside the directory, never of what those descendants
/// weigh. Three 12 MiB files are three entries, and a directory holding a
/// 12 MiB file is one entry.
#[tokio::test]
async fn real_docker_listing_is_independent_of_descendant_contents() {
    if std::env::var("AIEC_RUN_DOCKER_TESTS").as_deref() != Ok("1") {
        return;
    }
    let image = std::env::var("AIEC_DOCKER_TEST_IMAGE").unwrap_or_else(|_| "alpine:3.21".into());
    let root = std::env::temp_dir().join(format!("aiec-docker-listing-{}", Uuid::new_v4()));
    let runtime = DockerRuntime::new(&root).expect("Docker daemon and client");
    let sandbox = docker_sandbox(&image);
    let mut created = false;
    let operation = async {
        runtime.create(&sandbox).await?;
        created = true;
        runtime.start(&sandbox).await?;
        // Written the way a guest would write them, through ordinary
        // execution: 36 MiB of descendants under a directory with four
        // entries in it.
        let mut script = String::from("mkdir -p /workspace/data/sub &&");
        let names = ["a.bin", "b.bin", "c.bin", "sub/deep.bin"];
        for name in names {
            // A trailing `&&` with nothing after it is a syntax error in sh,
            // not a no-op, so the separator belongs between commands rather
            // than after the last one.
            script.push_str(&format!(
                "dd if=/dev/zero of=/workspace/data/{name} bs=1M count=12 2>/dev/null"
            ));
            if name != names[names.len() - 1] {
                script.push_str(" &&");
            }
        }
        runtime
            .exec(
                &sandbox,
                ExecRequest {
                    command: vec!["/bin/sh".into(), "-c".into(), script],
                    working_directory: Some("/workspace".into()),
                    environment: Default::default(),
                    timeout_seconds: 120,
                    stdin: None,
                },
            )
            .await?;

        let entries = runtime.list_files(&sandbox, "/workspace/data").await?;
        let listed: std::collections::BTreeMap<&str, (String, u64)> = entries
            .iter()
            .map(|entry| (entry.name.as_str(), (entry.kind.clone(), entry.size)))
            .collect();
        for name in ["a.bin", "b.bin", "c.bin"] {
            assert_eq!(
                listed.get(name),
                Some(&("file".to_owned(), 12 * 1024 * 1024)),
                "{listed:?}"
            );
        }
        assert_eq!(
            listed.get("sub").map(|(kind, _)| kind.as_str()),
            Some("directory"),
            "{listed:?}"
        );
        assert_eq!(entries.len(), 4, "{listed:?}");

        // The parent whose listing is one entry, whatever its child weighs.
        let parent = runtime.list_files(&sandbox, "/workspace").await?;
        assert!(
            parent
                .iter()
                .any(|entry| entry.name == "data" && entry.kind == "directory"),
            "{parent:?}"
        );
        Ok::<(), CoreError>(())
    }
    .await;
    // The container is removed first and waited for: on a tmpfs-backed root the
    // bind mount's files are still open inside it, so deleting the tree while
    // the container is going away is a permission error rather than a leak.
    let cleanup = if created {
        runtime.destroy(&sandbox).await
    } else {
        Ok(())
    };
    if let Err(operation_error) = operation {
        if let Err(cleanup_error) = cleanup {
            panic!(
                "Docker listing failed: {operation_error}; cleanup also failed: {cleanup_error}"
            );
        }
        panic!("Docker listing failed: {operation_error}");
    }
    cleanup.expect("Docker cleanup");
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match std::fs::remove_dir_all(&root) {
                Ok(()) => return,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    assert!(!root.exists(), "the test left its state directory behind");
}
