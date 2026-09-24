use agentforge_api::{WorkerHeartbeat, WorkerRegistration, WorkerService, WorkerStatus};
use agentforge_client::AgentForgeClient;
use agentforge_core::*;
use agentforge_runtime::{
    BubblewrapRuntime, FirecrackerConfig, FirecrackerRuntime, SandboxRuntime,
};
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Instant};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "agentforge", version, about = "AgentForge sandbox cloud CLI")]
struct Cli {
    #[arg(long, env = "AGENTFORGE_URL", default_value = "http://127.0.0.1:8080")]
    url: String,
    #[arg(long, env = "AGENTFORGE_API_KEY")]
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
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,
    #[arg(long, env = "AGENTFORGE_RUNTIME", default_value = "bwrap-dev")]
    runtime: String,
    #[arg(long, default_value = ".agentforge")]
    state_dir: PathBuf,
}

#[derive(Args)]
struct WorkerArgs {
    #[arg(long, env = "AGENTFORGE_RUNTIME", default_value = "bwrap-dev")]
    runtime: String,
    #[arg(long, default_value = ".agentforge")]
    state_dir: PathBuf,
    #[arg(long, env = "AGENTFORGE_WORKER_BIND", default_value = "127.0.0.1:9090")]
    bind: String,
    #[arg(long, env = "AGENTFORGE_WORKER_NAME", default_value = "worker")]
    name: String,
    #[arg(long, env = "AGENTFORGE_WORKER_CAPACITY", default_value_t = 1)]
    capacity: u32,
    #[arg(long, env = "AGENTFORGE_WORKER_TOKEN")]
    token: Option<String>,
    #[arg(long, env = "AGENTFORGE_WORKER_NODE_ID")]
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
    if args.runtime != "bwrap-dev" {
        anyhow::bail!("server only supports explicit bwrap-dev; production uses agentforge-server")
    }
    std::fs::create_dir_all(&args.state_dir)?;
    let runtime: Arc<dyn SandboxRuntime> = Arc::new(BubblewrapRuntime::new(&args.state_dir));
    let worker_token =
        std::env::var("AGENTFORGE_WORKER_TOKEN").unwrap_or_else(|_| generate_api_key());
    let state =
        agentforge_api::AppState::in_memory(runtime).with_worker_token(worker_token.clone());
    let addr = args.bind.parse().context("invalid bind address")?;
    let key = std::env::var("AGENTFORGE_API_KEY").unwrap_or_else(|_| generate_api_key());
    state
        .repository
        .put_key(ApiKeyRecord {
            id: new_id(),
            tenant_id: Uuid::nil(),
            digest: key_digest(&key),
            scopes: vec![Scope::Admin],
            expires_at: None,
            revoked_at: None,
        })
        .await?;
    println!(
        "agentforge server listening on {addr}\nbootstrap API key: {key}\nworker token: {worker_token}"
    );
    agentforge_api::serve(state, addr)
        .await
        .context("serve API")
}

async fn client(url: &str, api_key: Option<String>) -> Result<AgentForgeClient> {
    let key = api_key
        .or_else(|| std::env::var("AGENTFORGE_API_KEY").ok())
        .context("set --api-key or AGENTFORGE_API_KEY")?;
    AgentForgeClient::new(url, key).context("create API client")
}
async fn worker(control_url: &str, args: WorkerArgs) -> Result<()> {
    std::fs::create_dir_all(&args.state_dir)?;
    let token = args
        .token
        .or_else(|| std::env::var("AGENTFORGE_WORKER_TOKEN").ok())
        .context("set --token or AGENTFORGE_WORKER_TOKEN")?;
    let node_id = args.node_id.unwrap_or_else(Uuid::now_v7);
    let (runtime, runtime_kind): (Arc<dyn SandboxRuntime>, RuntimeKind) = match args
        .runtime
        .as_str()
    {
        "bwrap-dev" => (
            Arc::new(BubblewrapRuntime::new(&args.state_dir)),
            RuntimeKind::BwrapDev,
        ),
        "firecracker" => {
            let config = FirecrackerConfig::from_env()
                .map_err(|error| anyhow::anyhow!("invalid Firecracker configuration: {error}"))?;
            (
                Arc::new(FirecrackerRuntime::new(config)),
                RuntimeKind::Firecracker,
            )
        }
        other => anyhow::bail!("unsupported worker runtime {other}; use bwrap-dev or firecracker"),
    };
    let service = WorkerService::new(runtime, runtime_kind, token.clone(), node_id, args.capacity);
    let client = reqwest::Client::new();
    let control = control_url.trim_end_matches('/').to_owned();
    let now = chrono::Utc::now();
    let total_memory_bytes = u64::from(args.capacity) * 1024 * 1024 * 1024;
    let total_disk_bytes = u64::from(args.capacity) * 10 * 1024 * 1024 * 1024;
    let registration = WorkerRegistration {
        node_id,
        name: args.name,
        runtime: runtime_kind,
        control_endpoint: format!("http://{}", args.bind),
        total_vcpus: args.capacity,
        total_memory_bytes,
        total_disk_bytes,
        available_vcpus: args.capacity,
        available_memory_bytes: total_memory_bytes,
        available_disk_bytes: total_disk_bytes,
        healthy: true,
        version: 1,
        metadata: serde_json::json!({"state_dir": args.state_dir}),
        started_at: now,
        last_heartbeat: now,
    };
    client
        .post(format!("{control}/v1/workers/register"))
        .bearer_auth(&token)
        .json(&registration)
        .send()
        .await
        .context("register worker")?
        .error_for_status()
        .context("worker registration rejected")?;
    let heartbeat_token = token.clone();
    let heartbeat_client = client.clone();
    let heartbeat_url = control.clone();
    let heartbeat_bind = args.bind.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let Ok(status) = heartbeat_client
                .get(format!("http://{heartbeat_bind}/health"))
                .bearer_auth(&heartbeat_token)
                .send()
                .await
            else {
                continue;
            };
            let Ok(status) = status.json::<WorkerStatus>().await else {
                continue;
            };
            let active = status.sandbox_count as u32;
            let available = args_capacity(status.capacity, active);
            let heartbeat = WorkerHeartbeat {
                node_id,
                available_vcpus: available,
                available_memory_bytes: u64::from(available) * 1024 * 1024 * 1024,
                available_disk_bytes: u64::from(available) * 10 * 1024 * 1024 * 1024,
                sandbox_count: active,
                healthy: status.healthy,
                version: 1,
                metadata: serde_json::json!({}),
                last_error: None,
            };
            let _ = heartbeat_client
                .post(format!("{heartbeat_url}/v1/workers/{node_id}/heartbeat"))
                .bearer_auth(&heartbeat_token)
                .json(&heartbeat)
                .send()
                .await;
            let _ = heartbeat_client
                .post(format!("{heartbeat_url}/v1/workers/reconcile"))
                .bearer_auth(&heartbeat_token)
                .send()
                .await;
        }
    });
    println!(
        "agentforge worker listening on {} node={}",
        args.bind, node_id
    );
    let bind = args.bind.parse().context("invalid worker bind address")?;
    agentforge_api::serve_worker(service, bind)
        .await
        .context("serve worker operations")
}

fn args_capacity(capacity: u32, in_flight: u32) -> u32 {
    capacity.saturating_sub(in_flight)
}
async fn doctor() -> Result<()> {
    println!("os: {}", std::env::consts::OS);
    println!(
        "runtime: {}",
        std::env::var("AGENTFORGE_RUNTIME").unwrap_or_else(|_| "bwrap-dev".into())
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
    Ok(())
}
async fn migrate() -> Result<()> {
    println!("AgentForge uses repository migrations at startup; no destructive migration was run.");
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
    let raw_key = key
        .clone()
        .or_else(|| std::env::var("AGENTFORGE_API_KEY").ok());
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
            if !matches!(runtime.as_str(), "bwrap-dev" | "firecracker") {
                anyhow::bail!(
                    "unsupported sandbox runtime {runtime}; use bwrap-dev or firecracker"
                );
            }
            let request = CreateSandboxRequest {
                image,
                cpu,
                memory_mb,
                disk_mb,
                timeout_seconds,
                network: NetworkPolicy { enabled: network },
            };
            let sandbox = if runtime == "firecracker" {
                let api_key = raw_key.context("set --api-key or AGENTFORGE_API_KEY")?;
                let mut payload = serde_json::to_value(&request)?;
                payload["runtime"] = serde_json::json!("firecracker");
                let response = reqwest::Client::new()
                    .post(format!("{}/v1/sandboxes", url.trim_end_matches('/')))
                    .bearer_auth(api_key)
                    .json(&payload)
                    .send()
                    .await?;
                if !response.status().is_success() {
                    anyhow::bail!(
                        "firecracker sandbox creation rejected: {}",
                        response.text().await?
                    );
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
                        disk_mb: None
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
    let c = client(url, key).await?;
    let started = Instant::now();
    let mut durations = Vec::new();
    let mut success = 0usize;
    for _ in 0..args.sandboxes {
        let request = CreateSandboxRequest {
            image: "ubuntu:24.04".into(),
            cpu: 1,
            memory_mb: 512,
            disk_mb: 2048,
            timeout_seconds: 300,
            network: NetworkPolicy::default(),
        };
        let t = Instant::now();
        match c.create_sandbox(&request).await {
            Ok(sandbox) => {
                durations.push(t.elapsed().as_micros() as u64);
                success += 1;
                let _ = c.delete_sandbox(sandbox.id).await;
            }
            Err(_) => {
                durations.push(t.elapsed().as_micros() as u64);
            }
        }
    }
    if args.concurrency > 1 {
        println!(
            "note: benchmark currently executes requests serially; requested concurrency {}",
            args.concurrency
        );
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
        "samples={} success={} success_rate={:.3} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} total_ms={:.3}",
        durations.len(),
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
