use agentforge_api::{
    AppState, DefaultPolicy, HttpWorkerClient, WorkerClient, WorkerRuntime, bootstrap_api_key, serve,
};
use agentforge_core::{
    Scope,
    images::ImageResolver,
    network::NetworkBackend,
    platform::Platform,
    policy::PlatformPolicy,
    runtime::SandboxRuntime,
    snapshots::SnapshotProvider,
    storage::{ArtifactStore, MetadataStore},
};
use agentforge_network_linux::LinuxNetworkManager;
use agentforge_runtime::FirecrackerConfig;
use agentforge_storage::{
    PostgresRepository, PostgresScheduler, S3Config, S3ObjectStore, StandardImageResolver,
};
use std::{sync::Arc, time::Duration};

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("{name} is required in production").into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let bind = std::env::var("AGENTFORGE_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let bind: std::net::SocketAddr = bind.parse()?;
    let tenant_id = required("AGENTFORGE_TENANT_ID")?.parse()?;
    if required("AGENTFORGE_RUNTIME")? != "firecracker" {
        return Err("AGENTFORGE_RUNTIME must be firecracker; bwrap-dev is only available through `agentforge server`".into());
    }
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
        Arc::new(HttpWorkerClient::new(worker_token.clone())?);
    let worker_runtime = Arc::new(WorkerRuntime::new(worker_client, scheduler.clone()));
    let runtime: Arc<dyn SandboxRuntime> = worker_runtime.clone();
    let snapshots: Arc<dyn SnapshotProvider> = worker_runtime;
    let network: Arc<dyn NetworkBackend> = Arc::new(LinuxNetworkManager::new());

    let config = FirecrackerConfig::from_env()?;
    config.check()?;
    let images: Arc<dyn ImageResolver> = Arc::new(StandardImageResolver::new(
        config.rootfs.display().to_string(),
    ));
    let policy: Arc<dyn PlatformPolicy> = Arc::new(DefaultPolicy);
    let platform = Platform::builder()
        .runtime(runtime)
        .scheduler(scheduler)
        .metadata_store(metadata_store.clone())
        .artifact_store(artifact_store)
        .network(network)
        .images(images)
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
    println!("agentforge production server listening on {bind}");
    serve(state, bind).await?;
    Ok(())
}
