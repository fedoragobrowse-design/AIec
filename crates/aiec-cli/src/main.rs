use aiec_api::{
    HttpOwnershipVerifier, WorkerGuestProfile, WorkerHeartbeat, WorkerRegistration, WorkerService,
    WorkerStatus, serve_worker_tls,
};
use aiec_client::AIecClient;
use aiec_core::*;
use aiec_core::{
    platform::Platform,
    runtime::SandboxRuntime,
    snapshots::SnapshotProvider,
    storage::{MetadataStore, WorkerAssignment},
};
use aiec_runtime::DockerRuntime;
use aiec_runtime::{BubblewrapRuntime, FirecrackerConfig, FirecrackerRuntime};
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "aiec", version, about = "AIec sandbox cloud CLI")]
struct Cli {
    #[arg(long, env = "AIEC_URL", default_value = "http://127.0.0.1:8080")]
    url: String,
    #[arg(long, env = "AIEC_API_KEY")]
    api_key: Option<String>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Server(ServerArgs),
    Worker(WorkerArgs),
    Doctor,
    Migrate,
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
    File {
        #[command(subcommand)]
        command: FileCommand,
    },
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommand,
    },
    Benchmark(BenchmarkArgs),
}
#[derive(Args)]
struct ServerArgs {
    #[arg(long, env = "AIEC_BIND", default_value = "127.0.0.1:8080")]
    bind: String,
    #[arg(long, env = "AIEC_RUNTIME", default_value = "bwrap-dev")]
    runtime: String,
    #[arg(long, default_value = ".aiec")]
    state_dir: PathBuf,
}

#[derive(Args)]
struct WorkerArgs {
    #[arg(long, env = "AIEC_RUNTIME", default_value = "bwrap-dev")]
    runtime: String,
    #[arg(long, default_value = ".aiec")]
    state_dir: PathBuf,
    #[arg(long, env = "AIEC_WORKER_ADVERTISE_URL")]
    advertise_url: String,
    #[arg(long, env = "AIEC_WORKER_BIND", default_value = "127.0.0.1:9090")]
    bind: String,
    #[arg(long, env = "AIEC_WORKER_NAME", default_value = "worker")]
    name: String,
    #[arg(long, env = "AIEC_WORKER_CAPACITY", default_value_t = 1)]
    capacity: u32,
    #[arg(long, env = "AIEC_WORKER_TOKEN")]
    token: Option<String>,
    #[arg(long, env = "AIEC_WORKER_NODE_ID")]
    node_id: Option<Uuid>,
}
#[derive(Args)]
struct BenchmarkArgs {
    #[arg(long, default_value_t = 10)]
    sandboxes: usize,
    #[arg(long, default_value_t = 1)]
    concurrency: usize,
}
#[derive(Subcommand)]
enum KeyCommand {
    Create {
        #[arg(long, default_value = "default")]
        name: String,
    },
    Revoke {
        key_id: Uuid,
    },
    Rotate {
        key_id: Uuid,
    },
}
#[derive(Subcommand)]
enum SandboxCommand {
    Create {
        #[arg(long, default_value = "python:3.13")]
        image: String,
        #[arg(long, default_value_t = 1)]
        cpu: u32,
        #[arg(long, default_value_t = 512)]
        memory_mb: u32,
        #[arg(long, default_value = "bwrap-dev")]
        runtime: String,
        #[arg(long, default_value_t = 2048)]
        disk_mb: u32,
        #[arg(long, default_value_t = 900)]
        timeout_seconds: u64,
        #[arg(long)]
        network: bool,
    },
    List,
    Show {
        id: Uuid,
    },
    Exec {
        id: Uuid,
        #[arg(last = true)]
        command: Vec<String>,
    },
    Destroy {
        id: Uuid,
    },
    Stop {
        id: Uuid,
    },
    Start {
        id: Uuid,
    },
    Resume {
        id: Uuid,
    },
}
#[derive(Subcommand)]
enum FileCommand {
    Put {
        id: Uuid,
        path: String,
        file: PathBuf,
    },
    Get {
        id: Uuid,
        path: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    List {
        id: Uuid,
        #[arg(default_value = "/workspace")]
        path: String,
    },
    Delete {
        id: Uuid,
        path: String,
    },
    Mkdir {
        id: Uuid,
        path: String,
    },
}
#[derive(Subcommand)]
enum SnapshotCommand {
    Create { sandbox_id: Uuid },
    List { sandbox_id: Uuid },
    Restore { snapshot_id: Uuid },
    Delete { snapshot_id: Uuid },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let url = cli.url.clone();
    let api_key = cli.api_key.clone();
    match cli.command {
        Command::Server(args) => server(args).await,
        Command::Worker(args) => worker(&url, args).await,
        Command::Doctor => doctor().await,
        Command::Migrate => migrate().await,
        Command::Key { command } => key_command(command),
        Command::Sandbox { command } => sandbox_command(&url, api_key.clone(), command).await,
        Command::File { command } => file_command(&url, api_key.clone(), command).await,
        Command::Snapshot { command } => snapshot_command(&url, api_key.clone(), command).await,
        Command::Benchmark(args) => benchmark(&url, api_key, args).await,
    }
}

async fn server(args: ServerArgs) -> Result<()> {
    if !matches!(args.runtime.as_str(), "bwrap-dev" | "docker") {
        anyhow::bail!("server supports bwrap-dev or docker; production uses a server launcher")
    }
    std::fs::create_dir_all(&args.state_dir)?;
    let artifacts: Arc<dyn aiec_core::storage::ArtifactStore> = Arc::new(
        aiec_storage::FilesystemObjectStore::new(args.state_dir.join("artifacts")),
    );
    let (runtime, snapshots, runtime_kind): (
        Arc<dyn SandboxRuntime>,
        Arc<dyn SnapshotProvider>,
        RuntimeKind,
    ) = match args.runtime.as_str() {
        "bwrap-dev" => {
            let backend = Arc::new(BubblewrapRuntime::new(&args.state_dir));
            (backend.clone(), backend, RuntimeKind::BwrapDev)
        }
        "docker" => {
            let backend = Arc::new(
                DockerRuntime::new(&args.state_dir)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            );
            (backend.clone(), backend, RuntimeKind::Docker)
        }
        other => anyhow::bail!("unsupported server runtime {other}"),
    };
    let metadata_store: Arc<dyn MetadataStore> = aiec_storage::MemoryRepository::new();
    let scheduler: Arc<dyn aiec_core::scheduler::Scheduler> =
        Arc::new(aiec_api::DevelopmentScheduler);
    let registry = Arc::new(aiec_core::runtime::RuntimeRegistry::with_runtime(
        runtime_kind,
        runtime.clone(),
    ));
    let platform = Platform::builder()
        .runtime(runtime)
        .runtime_registry(registry)
        .metadata_store(metadata_store)
        .scheduler(scheduler)
        .snapshots(snapshots)
        .artifact_store(artifacts)
        .policy(Arc::new(aiec_api::DefaultPolicy))
        .build()?;
    let worker_token = std::env::var("AIEC_WORKER_TOKEN").unwrap_or_else(|_| generate_api_key());
    let state = aiec_api::AppState::development(platform)
        .with_runtime_kind(runtime_kind)
        .with_worker_token(worker_token.clone());
    let addr = args.bind.parse().context("invalid bind address")?;
    let key = std::env::var("AIEC_API_KEY").unwrap_or_else(|_| generate_api_key());
    aiec_api::bootstrap_api_key(
        state.repository().as_ref(),
        &key,
        Uuid::nil(),
        &[Scope::Admin],
    )
    .await?;
    println!(
        "aiec server listening on {addr}\nbootstrap API key: {key}\nworker token: {worker_token}"
    );
    aiec_api::serve(state, addr).await.context("serve API")
}

async fn client(url: &str, api_key: Option<String>) -> Result<AIecClient> {
    let key = api_key
        .or_else(|| std::env::var("AIEC_API_KEY").ok())
        .context("set --api-key or AIEC_API_KEY")?;
    AIecClient::new(url, key).context("create API client")
}
async fn worker(control_url: &str, args: WorkerArgs) -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    let token = args
        .token
        .or_else(|| std::env::var("AIEC_WORKER_TOKEN").ok())
        .context("set --token or AIEC_WORKER_TOKEN")?;
    if args.capacity == 0 {
        anyhow::bail!("--capacity must be greater than zero");
    }
    let advertised = reqwest::Url::parse(&args.advertise_url)
        .context("--advertise-url must be an absolute HTTP(S) URL")?;
    if args.runtime == "firecracker" && advertised.scheme() != "https" {
        anyhow::bail!("Firecracker worker --advertise-url must use HTTPS")
    }
    if !matches!(advertised.scheme(), "http" | "https")
        || advertised.host_str().is_none()
        || !advertised.username().is_empty()
        || advertised.password().is_some()
        || advertised.query().is_some()
        || advertised.fragment().is_some()
        || !matches!(advertised.path(), "" | "/")
    {
        anyhow::bail!(
            "--advertise-url must be an HTTP(S) origin without credentials, path, query, or fragment"
        );
    }
    let advertise_url = advertised.as_str().trim_end_matches('/').to_owned();
    let tls_config = match (
        std::env::var("AIEC_TLS_CERT_FILE"),
        std::env::var("AIEC_TLS_KEY_FILE"),
    ) {
        (Ok(cert), Ok(key)) => Some((cert, key)),
        _ if args.runtime == "bwrap-dev" => None,
        _ => anyhow::bail!("TLS certificate and key are required for non-development workers"),
    };
    if args.runtime != "bwrap-dev" && advertised.scheme() != "https" {
        anyhow::bail!("non-development workers must advertise HTTPS");
    }
    let control = control_url.trim_end_matches('/').to_owned();
    let node_id = match args.node_id {
        Some(id) => id,
        None => durable_node_id(&args.state_dir)?,
    };
    let mut startup_report = None;
    let mut guest_profile = None;
    let (runtime, snapshots, runtime_kind): (
        Arc<dyn SandboxRuntime>,
        Arc<dyn SnapshotProvider>,
        RuntimeKind,
    ) = match args.runtime.as_str() {
        "bwrap-dev" => {
            let backend = Arc::new(BubblewrapRuntime::new(&args.state_dir));
            (backend.clone(), backend, RuntimeKind::BwrapDev)
        }
        "docker" => {
            let backend = Arc::new(
                DockerRuntime::new(&args.state_dir)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            );
            (backend.clone(), backend, RuntimeKind::Docker)
        }
        "firecracker" => {
            let config = FirecrackerConfig::from_env()
                .map_err(|error| anyhow::anyhow!("invalid Firecracker configuration: {error}"))?;
            // The runtime already verified the artifact against the rootfs, so
            // the profile it resolved is what /health reports.
            guest_profile = config
                .guest_artifact
                .as_ref()
                .map(guest_profile_from)
                .or_else(|| {
                    tracing::warn!("no Firecracker guest artifact metadata is configured");
                    None
                });
            // Verify the guest image before this worker serves anything. A
            // worker that cannot verify its image must fail to start, not fail
            // its first sandbox on the control plane's request timeout.
            config.verify_guest_image()?;
            let backend = Arc::new(FirecrackerRuntime::new(config));
            // Runs before registration because its report is part of the
            // registration metadata. On a restart the persisted id is already
            // the adopted one, so this is owner-scoped correctly.
            let report = backend.reconcile_local(node_id)?;
            startup_report = Some(report.clone());
            if !report.orphan_candidates.is_empty() {
                tracing::warn!(owner_id = %report.owner_id, orphan_candidates = ?report.orphan_candidates, "owner-scoped Firecracker reconciliation found VM directories for operator review");
            }
            (backend.clone(), backend, RuntimeKind::Firecracker)
        }
        other => anyhow::bail!(
            "unsupported worker runtime {other}; use bwrap-dev, docker, or firecracker"
        ),
    };
    let capabilities = runtime.capabilities();
    let mut client_builder =
        reqwest::Client::builder().connect_timeout(std::time::Duration::from_secs(5));
    if let Ok(path) = std::env::var("AIEC_TLS_CA_CERT") {
        let pem = std::fs::read(&path).with_context(|| format!("read {path}"))?;
        let certificate =
            reqwest::Certificate::from_pem(&pem).with_context(|| format!("parse {path}"))?;
        client_builder = client_builder.add_root_certificate(certificate);
    }
    let client = client_builder.build().context("build worker API client")?;
    let now = chrono::Utc::now();
    // One version base for this process, shared by the registration and every
    // heartbeat it sends. The control plane rejects a re-registration that does
    // not outrank the stored version, so registration and heartbeat must never
    // derive their versions separately.
    let version_base = worker_version_base();
    // Measured, not assumed.
    //
    // These used to be `capacity x 1 GiB` and `capacity x 10 GiB`: arithmetic
    // from the same flag that sets the vCPU count, with nothing on the host
    // asked whether it agreed. A node on a host with four spare gigabytes would
    // advertise eight and hand out eight, and the failure would arrive at boot -
    // after the tenant's quota and the node's capacity had already been charged
    // for work that could never start.
    let (measured_memory, measured_disk) = host_capacity();
    if let (Some(memory), Some(disk)) = (measured_memory, measured_disk) {
        tracing::info!(
            memory_bytes = memory,
            disk_bytes = disk,
            "declaring capacity measured from the host"
        );
    } else {
        tracing::warn!(
            "could not measure the host; falling back to the configured capacity, \
             which may overstate what this node can actually run"
        );
    }
    let total_memory_bytes = measured_memory.unwrap_or_else(|| u64::from(args.capacity) * GIB);
    let total_disk_bytes = measured_disk.unwrap_or_else(|| u64::from(args.capacity) * 10 * GIB);
    let registration = WorkerRegistration {
        node_id,
        name: args.name,
        runtime: runtime_kind,
        capabilities: capabilities.clone(),
        control_endpoint: advertise_url.clone(),
        total_vcpus: args.capacity,
        total_memory_bytes,
        total_disk_bytes,
        available_vcpus: args.capacity,
        available_memory_bytes: total_memory_bytes,
        available_disk_bytes: total_disk_bytes,
        healthy: true,
        version: version_base,
        metadata: serde_json::json!({
            "state_dir": args.state_dir,
            "startup_reconciliation": startup_report,
        }),
        started_at: now,
        last_heartbeat: now,
    };
    let registration_response = client
        .post(format!("{control}/v1/workers/register"))
        .bearer_auth(&token)
        .json(&registration)
        .send()
        .await
        .context("register worker")?;
    if !registration_response.status().is_success() {
        // Surface the control plane's reason: a version conflict and a bad
        // endpoint look identical in a bare 409.
        let status = registration_response.status();
        let body = registration_response.text().await.unwrap_or_default();
        anyhow::bail!("worker registration rejected ({status}): {body}");
    }
    // The control plane is authoritative about a worker's identity: if the name
    // was already registered it hands back the id it holds, and this worker
    // adopts it. Persisting it keeps the two in step across later restarts.
    let assigned: WorkerRegistration = registration_response
        .json()
        .await
        .context("worker registration response")?;
    let node_id = assigned.node_id;
    persist_node_id(&args.state_dir, node_id).context("persist the assigned node id")?;

    // Built only after the id is settled: the ownership verifier and the service
    // both capture it, and a worker that adopted a different id than it proposed
    // would otherwise authorize every operation against an id the control plane
    // does not use.
    let verifier = HttpOwnershipVerifier::new(control.clone(), token.clone(), node_id)
        .map_err(|error| anyhow::anyhow!("build worker ownership verifier: {error}"))?;
    let mut service = WorkerService::new(
        runtime,
        runtime_kind,
        capabilities.clone(),
        Some(snapshots),
        token.clone(),
        node_id,
        args.capacity,
    )
    .with_state_dir(&args.state_dir)
    .with_ownership_verifier(Arc::new(verifier));
    if let Some(profile) = guest_profile {
        service = service.with_guest_profile(profile);
    }
    client
        .post(format!("{control}/v1/workers/reconcile"))
        .bearer_auth(&token)
        .send()
        .await
        .context("initial worker reconciliation")?
        .error_for_status()
        .context("initial worker reconciliation rejected")?;
    let owned_leases: Arc<Mutex<HashMap<Uuid, OwnedLease>>> = Arc::new(Mutex::new(HashMap::new()));
    match claim_assignments(&client, &control, &token, node_id, args.capacity).await {
        Ok(leases) => {
            tracing::info!(leases = leases.len(), "claimed worker assignments");
            owned_leases.lock().await.extend(leases);
        }
        Err(error) => {
            tracing::warn!(%error, "worker assignment claim failed; retrying with the heartbeat")
        }
    }
    let loop_leases = owned_leases.clone();
    let loop_capacity = args.capacity;
    // Heartbeats continue the version sequence the registration started, so a
    // worker that restarts outranks the version it last reported.
    let heartbeat_version = Arc::new(AtomicU64::new(version_base));
    let heartbeat_token = token.clone();
    let heartbeat_client = client.clone();
    let heartbeat_url = control.clone();
    // Liveness and maintenance run on separate tasks on purpose. The control
    // plane treats a node as dead once its heartbeat is older than
    // NODE_HEARTBEAT_TTL_SECONDS, so a slow reconcile, claim, or renewal must
    // never delay the heartbeat that keeps this node schedulable.
    let liveness_node = node_id;
    let liveness_version = heartbeat_version.clone();
    let liveness_token = token.clone();
    let liveness_client = client.clone();
    let liveness_url = control.clone();
    let liveness_health_url = format!("{}/health", advertise_url);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let Ok(status) = liveness_client
                .get(&liveness_health_url)
                .bearer_auth(&liveness_token)
                .send()
                .await
            else {
                continue;
            };
            let Ok(status) = status.json::<WorkerStatus>().await else {
                continue;
            };
            let active = status.sandbox_count as u32;
            let heartbeat = WorkerHeartbeat {
                node_id: liveness_node,
                sandbox_count: active,
                healthy: status.healthy,
                version: liveness_version.fetch_add(1, Ordering::Relaxed) + 1,
                metadata: serde_json::json!({}),
                last_error: None,
            };
            if let Err(error) = liveness_client
                .post(format!(
                    "{liveness_url}/v1/workers/{liveness_node}/heartbeat"
                ))
                .bearer_auth(&liveness_token)
                .json(&heartbeat)
                .send()
                .await
                .and_then(|response| response.error_for_status())
            {
                tracing::warn!(%error, "worker heartbeat failed");
            }
        }
    });

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let _ = heartbeat_client
                .post(format!("{heartbeat_url}/v1/workers/reconcile"))
                .bearer_auth(&heartbeat_token)
                .send()
                .await;
            match claim_assignments(
                &heartbeat_client,
                &heartbeat_url,
                &heartbeat_token,
                node_id,
                loop_capacity,
            )
            .await
            {
                Ok(leases) if !leases.is_empty() => {
                    tracing::info!(leases = leases.len(), "claimed worker assignments");
                    loop_leases.lock().await.extend(leases);
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "worker assignment claim failed"),
            }
            let leases: Vec<OwnedLease> = loop_leases.lock().await.values().cloned().collect();
            let renewal = renew_leases(
                &heartbeat_client,
                &heartbeat_url,
                &heartbeat_token,
                node_id,
                &leases,
            )
            .await;
            let mut owned = loop_leases.lock().await;
            // Write the generation the control plane just assigned back into the
            // tracked lease. Renewal bumps the generation server-side, so
            // replaying the old one would fence this worker out of its own
            // sandbox and abandon a lease it still legitimately holds.
            for (sandbox_id, generation) in &renewal.renewed {
                if let Some(lease) = owned.get_mut(sandbox_id) {
                    lease.generation = *generation;
                }
            }
            if !renewal.superseded.is_empty() {
                for sandbox_id in &renewal.superseded {
                    owned.remove(sandbox_id);
                }
                tracing::info!(
                    released = renewal.superseded.len(),
                    "dropped leases the control plane no longer owns"
                );
            }
            let tracked = owned.len();
            drop(owned);
            if let Some(error) = renewal.failure {
                tracing::warn!(%error, leases = leases.len(), tracked, "worker lease renewal failed");
            }
        }
    });
    let bind = args.bind.parse().context("invalid worker bind address")?;
    if let Some((cert, key)) = tls_config {
        serve_worker_tls(service, bind, cert, key)
            .await
            .context("serve worker operations over TLS")
    } else {
        aiec_api::serve_worker(service, bind)
            .await
            .context("serve worker operations")
    }
}

/// Lease lifetime requested when this worker claims assignments.
const WORKER_LEASE_TTL_SECONDS: u64 = 300;

/// A lease this worker currently holds for a sandbox.
#[derive(Clone)]
struct OwnedLease {
    sandbox_id: Uuid,
    lease_id: Uuid,
    tenant_id: Uuid,
    generation: i64,
}

/// Claims the assignments reserved for this worker.
async fn claim_assignments(
    client: &reqwest::Client,
    control: &str,
    token: &str,
    node_id: Uuid,
    capacity: u32,
) -> Result<Vec<(Uuid, OwnedLease)>, reqwest::Error> {
    let assignments: Vec<WorkerAssignment> = client
        .post(format!(
            "{control}/v1/workers/{node_id}/assignments/claim?limit={}&lease_ttl_seconds={}",
            capacity.clamp(1, 128),
            WORKER_LEASE_TTL_SECONDS
        ))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(assignments
        .into_iter()
        .map(|assignment| {
            (
                assignment.sandbox.id,
                OwnedLease {
                    sandbox_id: assignment.sandbox.id,
                    lease_id: assignment.lease.id,
                    tenant_id: assignment.lease.tenant_id,
                    generation: assignment.lease.generation,
                },
            )
        })
        .collect())
}

/// Renews every owned lease, reporting the first transport failure without
/// skipping the remaining leases, and collecting the sandboxes whose lease the
/// control plane no longer recognizes.
#[derive(Default)]
struct RenewalOutcome {
    superseded: Vec<Uuid>,
    /// The generation each successfully renewed lease now holds. Renewal bumps
    /// the server-side generation, so a client that kept the old one would be
    /// fenced out on the very next cycle and would drop the lease it still owns.
    renewed: Vec<(Uuid, i64)>,
    failure: Option<reqwest::Error>,
}

async fn renew_leases(
    client: &reqwest::Client,
    control: &str,
    token: &str,
    node_id: Uuid,
    leases: &[OwnedLease],
) -> RenewalOutcome {
    let mut outcome = RenewalOutcome::default();
    for lease in leases {
        let response = match client
            .post(format!(
                "{control}/v1/workers/{node_id}/leases/{}/renew",
                lease.lease_id
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "tenant_id": lease.tenant_id,
                "generation": lease.generation,
            }))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                if outcome.failure.is_none() {
                    outcome.failure = Some(error);
                }
                continue;
            }
        };
        if response.status() == reqwest::StatusCode::CONFLICT {
            // The sandbox was destroyed, reassigned, or fenced: stop tracking it
            // instead of failing every later cycle.
            outcome.superseded.push(lease.sandbox_id);
            continue;
        }
        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                if outcome.failure.is_none() {
                    outcome.failure = Some(error);
                }
                continue;
            }
        };
        match response.json::<aiec_core::storage::WorkerLease>().await {
            Ok(lease) => outcome.renewed.push((lease.sandbox_id, lease.generation)),
            // The lease is extended; only the reported generation is unknown, so
            // keep the lease rather than dropping a sandbox we still own.
            Err(error) if outcome.failure.is_none() => {
                outcome.failure = Some(error);
            }
            Err(_) => {}
        }
    }
    outcome
}

/// Base value for this process's node version.
///
/// Derived from the process start time so a restarted worker always outranks
/// the version it last reported, which the control plane requires before it
/// will accept the re-registration.
/// Bytes in a gibibyte.
const GIB: u64 = 1024 * 1024 * 1024;

/// Held back from every node so the host itself is never scheduled to zero.
///
/// Memory: the operating system, page cache, and this worker's own processes.
/// Disk: room for logs, images, and the workspace archives a snapshot writes.
/// Scheduling a node to its last byte is how a host starts refusing I/O in the
/// middle of running somebody's job.
const MEMORY_RESERVE_BYTES: u64 = 512 * 1024 * 1024;
const DISK_RESERVE_BYTES: u64 = 2 * GIB;

/// What the host actually has, minus the reserve.
///
/// Returns `None` for either measurement it cannot take, and the caller decides
/// what to do about it. Guessing is the failure this replaces, so a missing
/// measurement is reported as missing rather than silently replaced with
/// arithmetic - the fallback exists and says so in the log.
fn host_capacity() -> (Option<u64>, Option<u64>) {
    (measure_available_memory(), measure_free_disk("/"))
}

/// Memory the kernel says is available, not `MemFree`.
///
/// `MemFree` is memory nothing happens to be using, which on a healthy host is
/// near zero precisely because the page cache is doing its job. `MemAvailable`
/// is the estimate of what a new allocation can actually get.
fn measure_available_memory() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let available_kb: u64 = meminfo.lines().find_map(|line| {
        let rest = line.strip_prefix("MemAvailable:")?;
        rest.split_whitespace().next()?.parse().ok()
    })?;
    available_kb
        .checked_mul(1024)?
        .checked_sub(MEMORY_RESERVE_BYTES)
}

/// Free bytes on the filesystem holding `path`, minus the reserve.
fn measure_free_disk(path: &str) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(std::ffi::OsStr::new(path).as_bytes().to_vec()).ok()?;
    // SAFETY: `stat` is zeroed before the call and `c_path` is a valid,
    // NUL-terminated string that outlives it. `statvfs` only writes through the
    // pointer we hand it.
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return None;
        }
        // `f_bavail` rather than `f_bfree`: blocks reserved for root are not
        // available to a workload.
        let block = stat.f_frsize;
        let free = stat.f_bavail.checked_mul(block)?;
        free.checked_sub(DISK_RESERVE_BYTES)
    }
}

fn worker_version_base() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or_default();
    // Leave headroom above the millisecond clock so the counter can never
    // overflow a u64 through normal operation.
    u64::try_from(millis).unwrap_or(u64::MAX / 2)
}
async fn doctor() -> Result<()> {
    println!("os: {}", std::env::consts::OS);
    println!(
        "runtime: {}",
        std::env::var("AIEC_RUNTIME").unwrap_or_else(|_| "bwrap-dev".into())
    );
    println!(
        "bwrap: {}",
        if std::path::Path::new("/usr/bin/bwrap").exists() {
            "available"
        } else {
            "missing (install bubblewrap)"
        }
    );
    println!(
        "docker: {}",
        match aiec_runtime::DockerRuntime::new(std::env::temp_dir()) {
            Ok(runtime) => match runtime.health().await {
                health if health.healthy => "ready".to_owned(),
                health => health.message.unwrap_or_else(|| "not ready".into()),
            },
            Err(error) => format!("not ready ({error})"),
        }
    );
    println!(
        "kvm: {}",
        if std::path::Path::new("/dev/kvm").exists() {
            "available"
        } else {
            "unavailable"
        }
    );
    println!(
        "database: {}",
        if std::env::var("DATABASE_URL").is_ok() {
            "configured"
        } else {
            "not configured (in-memory API)"
        }
    );
    let require_coding_guest = std::env::var("AIEC_REQUIRE_CODING_GUEST").as_deref() == Ok("1");
    let mut coding_guest = false;
    match FirecrackerConfig::from_env() {
        Ok(config) => {
            match config.check() {
                Ok(()) => println!(
                    "firecracker: ready (binary {}, kernel {})",
                    config.binary.display(),
                    config.kernel.display()
                ),
                Err(error) => println!("firecracker: {error}"),
            }
            match config.guest_artifact.as_ref() {
                Some(artifact) => {
                    coding_guest = artifact.is_coding_guest();
                    println!(
                        "firecracker guest: base {} profile {} (artifact {})",
                        artifact.base, artifact.profile, artifact.artifact_version
                    );
                    println!(
                        "firecracker guest capabilities: {}",
                        artifact.capabilities.join(", ")
                    );
                    println!(
                        "firecracker guest git: {}",
                        artifact
                            .git_version
                            .clone()
                            .unwrap_or_else(|| "missing".into())
                    );
                    println!("firecracker guest agent: {}", artifact.guest_agent_version);
                }
                None => println!(
                    "firecracker guest image: no guest artifact metadata (set AIEC_GUEST_ARTIFACT_DIR)"
                ),
            }
        }
        Err(error) => println!(
            "firecracker: {error} (set AIEC_FIRECRACKER_BIN, AIEC_KERNEL, AIEC_ROOTFS, AIEC_GUEST_SECRET)"
        ),
    }
    if require_coding_guest && !coding_guest {
        anyhow::bail!(
            "AIEC_REQUIRE_CODING_GUEST=1 requires a verified Firecracker guest image that provides git"
        );
    }
    Ok(())
}

fn guest_profile_from(
    artifact: &aiec_runtime::guest_artifact::GuestArtifact,
) -> WorkerGuestProfile {
    WorkerGuestProfile {
        artifact_version: artifact.artifact_version.clone(),
        base: artifact.base.clone(),
        profile: artifact.profile.clone(),
        capabilities: artifact.capabilities.clone(),
        git_version: artifact.git_version.clone(),
        guest_agent_version: artifact.guest_agent_version.clone(),
    }
}
async fn migrate() -> Result<()> {
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL is required for `aiec migrate`")?;
    let repository = aiec_storage::PostgresRepository::connect(&database_url)
        .await
        .context("connect to PostgreSQL")?;
    repository
        .migrate()
        .await
        .context("apply AIec database migrations")?;
    println!("AIec database migrations are current.");
    Ok(())
}
fn key_command(command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Create { name } => {
            let key = generate_api_key();
            println!("{name}: {key}");
            println!(
                "Store only a SHA-256 digest in production; this local CLI cannot revoke an unpersisted key."
            );
        }
        KeyCommand::Revoke { key_id } => {
            println!("revoked {key_id} (persist this operation in your key store)")
        }
        KeyCommand::Rotate { key_id } => {
            let key = generate_api_key();
            println!("rotated {key_id}: {key}");
        }
    }
    Ok(())
}
async fn sandbox_command(url: &str, key: Option<String>, command: SandboxCommand) -> Result<()> {
    let raw_key = key.clone().or_else(|| std::env::var("AIEC_API_KEY").ok());
    let c = client(url, key).await?;
    match command {
        SandboxCommand::Create {
            image,
            cpu,
            memory_mb,
            runtime,
            disk_mb,
            timeout_seconds,
            network,
        } => {
            if !matches!(runtime.as_str(), "bwrap-dev" | "docker" | "firecracker") {
                anyhow::bail!(
                    "unsupported sandbox runtime {runtime}; use bwrap-dev, docker, or firecracker"
                )
            }
            let request = CreateSandboxRequest {
                image,
                cpu,
                memory_mb,
                disk_mb,
                timeout_seconds,
                network: if network {
                    NetworkPolicy::Internet
                } else {
                    NetworkPolicy::Disabled
                },
                environment: Default::default(),
            };
            let sandbox = if matches!(runtime.as_str(), "firecracker" | "docker") {
                let api_key = raw_key.context("set --api-key or AIEC_API_KEY")?;
                let mut payload = serde_json::to_value(&request)?;
                payload["runtime"] = serde_json::json!(runtime);
                let response = reqwest::Client::new()
                    .post(format!("{}/v1/sandboxes", url.trim_end_matches('/')))
                    .bearer_auth(api_key)
                    .json(&payload)
                    .send()
                    .await?;
                if !response.status().is_success() {
                    anyhow::bail!("sandbox creation rejected: {}", response.text().await?);
                }
                response.json::<Sandbox>().await?
            } else {
                c.create_sandbox(&request).await?
            };
            println!("{}", serde_json::to_string_pretty(&sandbox)?)
        }
        SandboxCommand::List => println!(
            "{}",
            serde_json::to_string_pretty(&c.list_sandboxes().await?)?
        ),
        SandboxCommand::Show { id } => println!(
            "{}",
            serde_json::to_string_pretty(&c.get_sandbox(id).await?)?
        ),
        SandboxCommand::Exec { id, command } => {
            let result = c
                .exec(
                    id,
                    &ExecRequest {
                        command,
                        working_directory: None,
                        environment: BTreeMap::new(),
                        timeout_seconds: 60,
                        stdin: None,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        SandboxCommand::Destroy { id } => {
            c.delete_sandbox(id).await?;
            println!("destroyed")
        }
        SandboxCommand::Stop { id } => {
            println!("{}", serde_json::to_string_pretty(&c.stop(id).await?)?)
        }
        SandboxCommand::Start { id } => {
            println!("{}", serde_json::to_string_pretty(&c.start(id).await?)?)
        }
        SandboxCommand::Resume { id } => {
            println!("{}", serde_json::to_string_pretty(&c.resume(id).await?)?)
        }
    }
    Ok(())
}
async fn file_command(url: &str, key: Option<String>, command: FileCommand) -> Result<()> {
    let c = client(url, key).await?;
    match command {
        FileCommand::Put { id, path, file } => {
            let bytes = std::fs::read(file)?;
            c.put_file(
                id,
                &PutFileRequest {
                    path,
                    content_base64: base64_encode(&bytes),
                    mode: None,
                },
            )
            .await?;
            println!("written")
        }
        FileCommand::Get { id, path, output } => {
            let value = c.get_file(id, &path).await?;
            let bytes = base64_decode(&value.content_base64)?;
            match output {
                Some(path) => std::fs::write(path, bytes)?,
                None => print!("{}", String::from_utf8_lossy(&bytes)),
            }
        }
        FileCommand::List { id, path } => println!(
            "{}",
            serde_json::to_string_pretty(&c.list_files(id, &path).await?)?
        ),
        FileCommand::Delete { id, path } => {
            c.delete_file(id, &path).await?;
            println!("deleted")
        }
        FileCommand::Mkdir { id, path } => {
            c.make_directory(id, &path).await?;
            println!("created")
        }
    }
    Ok(())
}
async fn snapshot_command(url: &str, key: Option<String>, command: SnapshotCommand) -> Result<()> {
    let c = client(url, key).await?;
    match command {
        SnapshotCommand::Create { sandbox_id } => println!(
            "{}",
            serde_json::to_string_pretty(&c.create_snapshot(sandbox_id).await?)?
        ),
        SnapshotCommand::List { sandbox_id } => println!(
            "{}",
            serde_json::to_string_pretty(&c.list_snapshots(sandbox_id).await?)?
        ),
        SnapshotCommand::Restore { snapshot_id } => println!(
            "{}",
            serde_json::to_string_pretty(
                &c.restore_snapshot(
                    snapshot_id,
                    &RestoreSnapshotRequest {
                        image: None,
                        cpu: None,
                        memory_mb: None,
                        disk_mb: None,
                        runtime: None,
                    }
                )
                .await?
            )?
        ),
        SnapshotCommand::Delete { snapshot_id } => {
            c.delete_snapshot(snapshot_id).await?;
            println!("deleted")
        }
    }
    Ok(())
}
async fn benchmark(url: &str, key: Option<String>, args: BenchmarkArgs) -> Result<()> {
    if args.sandboxes == 0 || args.concurrency == 0 {
        anyhow::bail!("sandboxes and concurrency must be positive")
    }
    if args.sandboxes > 10_000 || args.concurrency > 1_000 {
        anyhow::bail!("benchmark limits: sandboxes <= 10000 and concurrency <= 1000")
    }
    let client = client(url, key).await?;
    let started = Instant::now();
    let permits = Arc::new(Semaphore::new(args.concurrency));
    let mut tasks: JoinSet<Result<(u64, bool)>> = JoinSet::new();
    for _ in 0..args.sandboxes {
        let client = client.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits
                .acquire_owned()
                .await
                .map_err(|error| anyhow::Error::msg(error.to_string()))?;
            let request = CreateSandboxRequest {
                image: "ubuntu:24.04".into(),
                cpu: 1,
                memory_mb: 512,
                disk_mb: 2048,
                timeout_seconds: 300,
                network: NetworkPolicy::default(),
                environment: Default::default(),
            };
            let started = Instant::now();
            match client.create_sandbox(&request).await {
                Ok(sandbox) => {
                    let _ = client.delete_sandbox(sandbox.id).await;
                    Ok((started.elapsed().as_micros() as u64, true))
                }
                Err(_) => Ok((started.elapsed().as_micros() as u64, false)),
            }
        });
    }
    let mut durations = Vec::with_capacity(args.sandboxes);
    let mut success = 0usize;
    while let Some(result) = tasks.join_next().await {
        let (duration, created) = result??;
        durations.push(duration);
        success += usize::from(created);
    }
    durations.sort_unstable();
    let p = |q: f64| {
        if durations.is_empty() {
            0
        } else {
            durations[((durations.len() - 1) as f64 * q).round() as usize]
        }
    };
    println!(
        "samples={} concurrency={} success={} success_rate={:.3} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} total_ms={:.3}",
        durations.len(),
        args.concurrency,
        success,
        success as f64 / durations.len().max(1) as f64,
        p(0.50) as f64 / 1000.0,
        p(0.95) as f64 / 1000.0,
        p(0.99) as f64 / 1000.0,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn base64_decode(value: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(anyhow::Error::from)
}

/// Records the node id the control plane assigned to this worker.
fn persist_node_id(state_dir: &std::path::Path, node_id: Uuid) -> anyhow::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(state_dir.join("node-id"), format!("{node_id}\n"))?;
    Ok(())
}

/// Returns this worker's node id, minting and persisting one on first start.
///
/// A worker's name is unique in the control plane, so a restart that invented a
/// fresh id would collide on that name. Persisting the id keeps the sandboxes
/// this worker placed attached to its node record instead of orphaning them.
fn durable_node_id(state_dir: &std::path::Path) -> anyhow::Result<Uuid> {
    let path = state_dir.join("node-id");
    if let Some(existing) = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| Uuid::parse_str(text.trim()).ok())
    {
        return Ok(existing);
    }

    let minted = Uuid::now_v7();
    persist_node_id(state_dir, minted)?;
    Ok(minted)
}

#[cfg(test)]
mod node_identity_tests {
    use super::durable_node_id;

    /// A worker that invents a fresh id on every start collides with the
    /// control plane's unique name and can never re-register, so the id has to
    /// outlive the process.
    #[test]
    fn a_restarted_worker_keeps_its_node_id() {
        let dir = std::env::temp_dir().join(format!("aiec-node-id-{}", uuid::Uuid::now_v7()));
        let first = durable_node_id(&dir).expect("first start mints an id");
        let second = durable_node_id(&dir).expect("second start reads it back");
        assert_eq!(first, second, "the node id must survive a restart");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn separate_state_dirs_get_separate_identities() {
        let suffix = uuid::Uuid::now_v7();
        let a = durable_node_id(&std::env::temp_dir().join(format!("aiec-a-{suffix}"))).unwrap();
        let b = durable_node_id(&std::env::temp_dir().join(format!("aiec-b-{suffix}"))).unwrap();
        assert_ne!(a, b, "two workers must not share an identity");
    }
}
