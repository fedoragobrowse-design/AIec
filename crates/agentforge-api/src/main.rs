use agentforge_api::{
    AppState, DefaultPolicy, HttpWorkerClient, WorkerClient, WorkerRuntime, bootstrap_api_key,
    serve_tls,
};
use agentforge_core::{
    RuntimeKind, Scope,
    images::ImageResolver,
    network::NetworkBackend,
    platform::Platform,
    policy::PlatformPolicy,
    runtime::RuntimeCapabilities,
    runtime::SandboxRuntime,
    snapshots::SnapshotProvider,
    storage::{ArtifactStore, MetadataStore},
};
use agentforge_network_linux::LinuxNetworkManager;
use agentforge_runtime::FirecrackerConfig;
use agentforge_storage::{
    PostgresRepository, PostgresScheduler, S3Config, S3ObjectStore, SignedImageResolver,
};
use std::{sync::Arc, time::Duration};

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("{name} is required in production").into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let bind = std::env::var("AGENTFORGE_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let bind: std::net::SocketAddr = bind.parse()?;
    let tenant_id = required("AGENTFORGE_TENANT_ID")?.parse()?;
    let runtime_config = std::env::var("AGENTFORGE_RUNTIMES").or_else(|_| {
        std::env::var("AGENTFORGE_RUNTIME")
            .map_err(|_| "AGENTFORGE_RUNTIME or AGENTFORGE_RUNTIMES is required".to_owned())
    })?;
    let runtime_kinds: Vec<RuntimeKind> = runtime_config
        .split(',')
        .filter(|value| !value.is_empty())
        .map(|value| match value {
            "firecracker" => Ok(RuntimeKind::Firecracker),
            "docker" => Ok(RuntimeKind::Docker),
            other => Err(format!(
                "unsupported production runtime {other}; use firecracker or docker"
            )
            .into()),
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    if runtime_kinds.is_empty() {
        return Err("at least one production runtime is required".into());
    }
    let runtime_kind = runtime_kinds[0];
    let database_url = required("DATABASE_URL")?;
    let api_key = required("AGENTFORGE_API_KEY")?;
    agentforge_core::validate_api_key(&api_key)?;
    let worker_token = required("AGENTFORGE_WORKER_TOKEN")?;
    if worker_token.len() < 32 {
        return Err("AGENTFORGE_WORKER_TOKEN must contain at least 32 bytes".into());
    }
    let lease_ttl_seconds = std::env::var("AGENTFORGE_LEASE_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300)
        .clamp(1, 3600);

    let artifact_store: Arc<dyn ArtifactStore> = Arc::new(S3ObjectStore::new(S3Config {
        endpoint: required("AGENTFORGE_S3_ENDPOINT")?,
        region: required("AGENTFORGE_S3_REGION")?,
        bucket: required("AGENTFORGE_S3_BUCKET")?,
        access_key_id: required("AGENTFORGE_S3_ACCESS_KEY_ID")?,
        secret_access_key: required("AGENTFORGE_S3_SECRET_ACCESS_KEY")?,
        prefix: std::env::var("AGENTFORGE_S3_PREFIX").unwrap_or_default(),
        request_timeout: Duration::from_secs(30),
    })?);

    let postgres = PostgresRepository::connect(&database_url).await?;
    postgres.migrate().await?;
    let metadata_store: Arc<dyn MetadataStore> = Arc::new(postgres.clone());
    let scheduler: Arc<dyn agentforge_core::scheduler::Scheduler> =
        Arc::new(PostgresScheduler::new(postgres));
    let worker_client: Arc<dyn WorkerClient> =
        Arc::new(HttpWorkerClient::new_secure(worker_token.clone())?);
    let mut registry = agentforge_core::runtime::RuntimeRegistry::new();
    let base_worker_runtime = Arc::new(WorkerRuntime::new(
        worker_client,
        scheduler.clone(),
        RuntimeCapabilities::default(),
    ));
    let mut primary_runtime: Option<Arc<dyn SandboxRuntime>> = None;
    for kind in runtime_kinds.iter().copied() {
        let capabilities = match kind {
            RuntimeKind::Docker => agentforge_core::runtime::RuntimeCapabilities {
                isolation: agentforge_core::runtime::RuntimeIsolation::Container,
                exec: true,
                files: true,
                docker_image: true,
                portable_workspace: true,
                workspace_snapshot: true,
                ..Default::default()
            },
            RuntimeKind::Firecracker => match agentforge_runtime::FirecrackerConfig::from_env() {
                Ok(firecracker_config) => {
                    // The guest image digest is verified once below, where the
                    // Firecracker image resolver is configured. Only the already
                    // loaded metadata is needed to describe the capability here.
                    agentforge_core::runtime::RuntimeCapabilities {
                        isolation: agentforge_core::runtime::RuntimeIsolation::MicroVm,
                        exec: true,
                        files: true,
                        guest_agent: true,
                        full_kernel_isolation: true,
                        vm_snapshot: true,
                        memory_resume: true,
                        vsock: true,
                        coding_guest: firecracker_config.guest_artifact.as_ref().is_some_and(
                            agentforge_runtime::guest_artifact::GuestArtifact::is_coding_guest,
                        ),
                        ..Default::default()
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "firecracker configuration incomplete; reporting a guest-less capability profile");
                    agentforge_core::runtime::RuntimeCapabilities {
                        isolation: agentforge_core::runtime::RuntimeIsolation::MicroVm,
                        exec: true,
                        files: true,
                        guest_agent: true,
                        full_kernel_isolation: true,
                        vm_snapshot: true,
                        memory_resume: true,
                        vsock: true,
                        ..Default::default()
                    }
                }
            },
            RuntimeKind::BwrapDev => RuntimeCapabilities::default(),
        };
        let runtime = Arc::new(base_worker_runtime.with_capabilities(capabilities));
        registry.register(kind, runtime.clone());
        if primary_runtime.is_none() {
            primary_runtime = Some(runtime);
        }
    }
    let runtime = primary_runtime.ok_or("no production runtime configured")?;
    let snapshots: Arc<dyn SnapshotProvider> = base_worker_runtime;
    let network: Arc<dyn NetworkBackend> = Arc::new(LinuxNetworkManager::new());

    let images: Option<Arc<dyn ImageResolver>> =
        if runtime_kinds.contains(&RuntimeKind::Firecracker) {
            let config = FirecrackerConfig::from_env()?;
            // Structural admission: binary, kernel, rootfs, guest secret length,
            // /dev/kvm, jailer and network tooling. The full image digest is
            // verified by the worker that boots the guest, not on every API boot.
            config.check()?;
            let image_manifest = required("AGENTFORGE_IMAGE_MANIFEST")?;
            let image_secret = required("AGENTFORGE_IMAGE_MANIFEST_SECRET")?;
            Some(Arc::new(SignedImageResolver::from_manifest(
                config.rootfs.display().to_string(),
                image_manifest,
                image_secret.as_bytes(),
            )?))
        } else {
            None
        };
    let registry = Arc::new(registry);
    let policy: Arc<dyn PlatformPolicy> = Arc::new(DefaultPolicy);
    let mut platform_builder = Platform::builder()
        .runtime(runtime)
        .runtime_registry(registry)
        .scheduler(scheduler)
        .metadata_store(metadata_store.clone())
        .artifact_store(artifact_store)
        .network(network);
    if let Some(images) = images {
        platform_builder = platform_builder.images(images);
    }
    let platform = platform_builder
        .snapshots(snapshots)
        .policy(policy)
        .build()?;
    metadata_store
        .put_tenant(agentforge_core::storage::TenantRecord {
            id: tenant_id,
            name: std::env::var("AGENTFORGE_TENANT_NAME").unwrap_or_else(|_| "default".into()),
            created_at: chrono::Utc::now(),
        })
        .await?;
    let state = AppState::new(platform)
        .with_runtime_kind(runtime_kind)
        .with_lease_ttl(lease_ttl_seconds)
        .with_worker_token(worker_token);
    bootstrap_api_key(
        metadata_store.as_ref(),
        &api_key,
        tenant_id,
        &[
            Scope::SandboxesRead,
            Scope::SandboxesWrite,
            Scope::SnapshotsRead,
            Scope::SnapshotsWrite,
            Scope::Admin,
        ],
    )
    .await?;
    let cert = required("AGENTFORGE_TLS_CERT_FILE")?;
    let key = required("AGENTFORGE_TLS_KEY_FILE")?;
    println!("agentforge production server listening on https://{bind}");
    serve_tls(state, bind, cert, key).await?;
    Ok(())
}
