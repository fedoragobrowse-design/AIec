use aiec_api::{
    AppState, DefaultPolicy, HttpWorkerClient, WorkerClient, WorkerRuntime, bootstrap_api_key,
    serve_tls,
};
use aiec_core::{
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
use aiec_network_linux::LinuxNetworkManager;
use aiec_runtime::FirecrackerConfig;
use aiec_storage::{
    PostgresRepository, PostgresScheduler, S3Config, S3ObjectStore, SignedImageResolver,
};
use std::{sync::Arc, time::Duration};

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("{name} is required in production").into())
}

/// Sustained public API rate, from `AIEC_RATE_LIMIT_RPS` and
/// `AIEC_RATE_LIMIT_BURST`. Unset means the built-in default.
fn rate_limit() -> aiec_api::ratelimit::RateLimit {
    let rps = std::env::var("AIEC_RATE_LIMIT_RPS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(20.0);
    let burst = std::env::var("AIEC_RATE_LIMIT_BURST")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(60);
    aiec_api::ratelimit::RateLimit::new(rps, burst)
}

/// Invite codes accepted by public signup, from `AIEC_INVITE_CODES`.
///
/// Comma-separated. When unset, signup is closed: a missing configuration must
/// never silently become "anyone can create an account".
fn invite_codes() -> Vec<String> {
    std::env::var("AIEC_INVITE_CODES")
        .unwrap_or_default()
        .split(',')
        .map(|code| code.trim().to_string())
        .filter(|code| !code.is_empty())
        .collect()
}

/// Global hosted-execution budget, from `AIEC_CLOUD_EXECUTION_BUDGET`.
///
/// Unset means no ceiling is configured, which is only appropriate for a
/// self-hosted deployment with its own capacity. A Cloud deployment should
/// always set it: it is the stop-loss that turns a finite provider allowance
/// into a clean refusal instead of an unexpected charge.
fn execution_budget_units() -> Option<i64> {
    std::env::var("AIEC_CLOUD_EXECUTION_BUDGET")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|value| *value > 0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    // Defaults to `info` for this crate rather than trusting the environment to
    // be set. `from_default_env` with no RUST_LOG means no directives at all, so
    // every structured log line the control plane emits - placement decisions,
    // lease sweeps, teardown failures - is silently discarded and the service
    // looks like a black box that only ever prints its listening line. A
    // background task that dies is then invisible, which is the worst possible
    // failure mode for the one whose job is preventing leaks.
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        "info,aiec_api=info,aiec_core=info,aiec_storage=info,sqlx=warn".to_owned()
    });
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();
    let bind = std::env::var("AIEC_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let bind: std::net::SocketAddr = bind.parse()?;
    let tenant_id = required("AIEC_TENANT_ID")?.parse()?;
    let runtime_config = std::env::var("AIEC_RUNTIMES").or_else(|_| {
        std::env::var("AIEC_RUNTIME")
            .map_err(|_| "AIEC_RUNTIME or AIEC_RUNTIMES is required".to_owned())
    })?;
    let runtime_kinds: Vec<RuntimeKind> = runtime_config
        .split(',')
        .filter(|value| !value.is_empty())
        .map(|value| match value {
            "firecracker" => Ok(RuntimeKind::Firecracker),
            "docker" => Ok(RuntimeKind::Docker),
            "hosted" => Ok(RuntimeKind::Hosted),
            other => Err(format!(
                "unsupported production runtime {other}; use firecracker, docker or hosted"
            )
            .into()),
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    if runtime_kinds.is_empty() {
        return Err("at least one production runtime is required".into());
    }
    let runtime_kind = runtime_kinds[0];
    let database_url = required("DATABASE_URL")?;
    let api_key = required("AIEC_API_KEY")?;
    aiec_core::validate_api_key(&api_key)?;
    let worker_token = required("AIEC_WORKER_TOKEN")?;
    if worker_token.len() < 32 {
        return Err("AIEC_WORKER_TOKEN must contain at least 32 bytes".into());
    }
    let lease_ttl_seconds = std::env::var("AIEC_LEASE_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300)
        .clamp(1, 3600);

    let artifact_store: Arc<dyn ArtifactStore> = Arc::new(S3ObjectStore::new(S3Config {
        endpoint: required("AIEC_S3_ENDPOINT")?,
        region: required("AIEC_S3_REGION")?,
        bucket: required("AIEC_S3_BUCKET")?,
        access_key_id: required("AIEC_S3_ACCESS_KEY_ID")?,
        secret_access_key: required("AIEC_S3_SECRET_ACCESS_KEY")?,
        prefix: std::env::var("AIEC_S3_PREFIX").unwrap_or_default(),
        request_timeout: Duration::from_secs(30),
    })?);

    let postgres = PostgresRepository::connect(&database_url).await?;
    postgres.migrate().await?;
    let metadata_store: Arc<dyn MetadataStore> = Arc::new(postgres.clone());
    let scheduler: Arc<dyn aiec_core::scheduler::Scheduler> =
        Arc::new(PostgresScheduler::new(postgres));
    let worker_client: Arc<dyn WorkerClient> =
        Arc::new(HttpWorkerClient::new_secure(worker_token.clone())?);
    let mut registry = aiec_core::runtime::RuntimeRegistry::new();
    let base_worker_runtime = Arc::new(WorkerRuntime::new(
        worker_client,
        scheduler.clone(),
        RuntimeCapabilities::default(),
    ));
    let mut primary_runtime: Option<Arc<dyn SandboxRuntime>> = None;
    for kind in runtime_kinds.iter().copied() {
        if kind == RuntimeKind::Hosted {
            // The hosted provider owns the isolation boundary and the guest
            // agent, so this runtime runs in the API process instead of being
            // proxied to a worker node. It is env-gated: without
            // AIEC_E2B_API_KEY the deployment behaves exactly as before.
            let hosted = Arc::new(aiec_runtime::E2bRuntime::new(
                aiec_runtime::E2bConfig::from_env()?,
            )?);
            tracing::info!(
                template = %hosted.provider_template(),
                "hosted sandbox runtime registered"
            );
            registry.register(kind, hosted.clone());
            if primary_runtime.is_none() {
                primary_runtime = Some(hosted);
            }
            continue;
        }
        let capabilities = match kind {
            RuntimeKind::Docker => aiec_core::runtime::RuntimeCapabilities {
                isolation: aiec_core::runtime::RuntimeIsolation::Container,
                exec: true,
                files: true,
                docker_image: true,
                portable_workspace: true,
                workspace_snapshot: true,
                ..Default::default()
            },
            RuntimeKind::Firecracker => match aiec_runtime::FirecrackerConfig::from_env() {
                Ok(firecracker_config) => {
                    // The guest image digest is verified once below, where the
                    // Firecracker image resolver is configured. Only the already
                    // loaded metadata is needed to describe the capability here.
                    aiec_core::runtime::RuntimeCapabilities {
                        isolation: aiec_core::runtime::RuntimeIsolation::MicroVm,
                        exec: true,
                        files: true,
                        guest_agent: true,
                        full_kernel_isolation: true,
                        vm_snapshot: true,
                        memory_resume: true,
                        vsock: true,
                        minimum_disk_mb: firecracker_config.minimum_disk_mb(),
                        coding_guest: firecracker_config.guest_artifact.as_ref().is_some_and(
                            aiec_runtime::guest_artifact::GuestArtifact::is_coding_guest,
                        ),
                        ..Default::default()
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "firecracker configuration incomplete; reporting a guest-less capability profile");
                    aiec_core::runtime::RuntimeCapabilities {
                        isolation: aiec_core::runtime::RuntimeIsolation::MicroVm,
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
            // Handled above: a hosted runtime never becomes a worker proxy.
            RuntimeKind::Hosted => RuntimeCapabilities::default(),
        };
        let runtime = Arc::new(base_worker_runtime.with_capabilities(capabilities));
        registry.register(kind, runtime.clone());
        if primary_runtime.is_none() {
            primary_runtime = Some(runtime);
        }
    }
    // Runtimes that isolate the workload themselves, such as the hosted
    // provider, have no worker node and therefore no worker-backed snapshot
    // provider to advertise.
    let worker_backed = runtime_kinds
        .iter()
        .any(|kind| !matches!(kind, RuntimeKind::Hosted));
    let runtime = primary_runtime.ok_or("no production runtime configured")?;
    let snapshots: Option<Arc<dyn SnapshotProvider>> = if worker_backed {
        let provider: Arc<dyn SnapshotProvider> = base_worker_runtime.clone();
        Some(provider)
    } else {
        None
    };
    let network: Arc<dyn NetworkBackend> = Arc::new(LinuxNetworkManager::new());

    let images: Option<Arc<dyn ImageResolver>> =
        if runtime_kinds.contains(&RuntimeKind::Firecracker) {
            let config = FirecrackerConfig::from_env()?;
            // Structural admission: binary, kernel, rootfs, guest secret length,
            // /dev/kvm, jailer and network tooling. The full image digest is
            // verified by the worker that boots the guest, not on every API boot.
            config.check()?;
            let image_manifest = required("AIEC_IMAGE_MANIFEST")?;
            let image_secret = required("AIEC_IMAGE_MANIFEST_SECRET")?;
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
    if let Some(snapshots) = snapshots {
        platform_builder = platform_builder.snapshots(snapshots);
    }
    let platform = platform_builder.policy(policy).build()?;
    metadata_store
        .put_tenant(aiec_core::storage::TenantRecord {
            id: tenant_id,
            name: std::env::var("AIEC_TENANT_NAME").unwrap_or_else(|_| "default".into()),
            created_at: chrono::Utc::now(),
        })
        .await?;
    // Public Cloud policy: external tenants get microVM isolation only, and
    // hosted execution runs against a global budget so a finite free allowance
    // can never turn into an unexpected charge. A self-hoster can opt out of
    // the runtime restriction with AIEC_ALLOW_CONTAINER_RUNTIMES=1.
    let hosted_only = std::env::var("AIEC_ALLOW_CONTAINER_RUNTIMES").as_deref() != Ok("1");
    let mut state = AppState::new(platform)
        .with_runtime_kind(runtime_kind)
        .with_lease_ttl(lease_ttl_seconds)
        .with_worker_token(worker_token)
        .with_hosted_only(hosted_only)
        .with_invites(invite_codes())
        .with_rate_limit(rate_limit());
    state = state
        .with_run_secrets(aiec_api::run_secrets::RunSecretResolver::from_env()?)
        .with_run_queue_limits(aiec_core::run_queue::RunQueueLimits::from_env()?);
    if let Some(limit) = execution_budget_units() {
        state = state.with_execution_budget(limit);
    }
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
    let cert = required("AIEC_TLS_CERT_FILE")?;
    let key = required("AIEC_TLS_KEY_FILE")?;
    println!("aiec production server listening on https://{bind}");
    serve_tls(state, bind, cert, key).await?;
    Ok(())
}
