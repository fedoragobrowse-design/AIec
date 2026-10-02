use aiec_guard::{
    GuardError, Result,
    budget_client::HttpBudgetAuthority,
    compiler::{OperatorBoundary, compile},
    control::{BudgetAuthority, GuardControlCommand, GuardFence},
    deployment::validate_operator_test_mode,
    events::FileEventSink,
    gateway::{CredentialStore, GatewayConfig, GuardGateway},
    policy::GuardPolicy,
};
use clap::Parser;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::Ipv4Addr,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Outside-guest gateway. Sandbox packet enforcement is owned by AIec's
/// Linux network backend, not implied merely by starting this listener.
///
/// The listener is only half of the dead-man switch: an external owner must
/// also cut the sandbox's nftables attachment when this process dies, which
/// the control-plane-owned attachment does. Nothing here ever heartbeats for
/// the watchdog.
#[derive(Parser)]
struct Args {
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    operator_boundary: Option<PathBuf>,
    #[arg(long)]
    credentials: Option<PathBuf>,
    #[arg(long)]
    events: Option<PathBuf>,
    #[arg(long)]
    sandbox_id: Option<Uuid>,
    #[arg(long)]
    tenant_id: Option<Uuid>,
    #[arg(long)]
    bind_ip: Option<Ipv4Addr>,
    #[arg(long)]
    guest_ip: Option<Ipv4Addr>,
    #[arg(long, default_value_t = 8443)]
    broker_port: u16,
    #[arg(long, default_value_t = 53)]
    dns_port: u16,
    #[arg(long)]
    local_test_mode: bool,
    #[arg(long)]
    verify_only: bool,
    /// Durable control-plane base URL that reserves this sandbox's budget.
    #[arg(long, env = "AIEC_GUARD_BUDGET_API_URL")]
    budget_api_url: Option<String>,
    /// Private file holding the worker service credential.
    #[arg(long, env = "AIEC_GUARD_WORKER_TOKEN_FILE")]
    worker_token_file: Option<PathBuf>,
    /// Node this worker credential is bound to.
    #[arg(long, env = "AIEC_GUARD_WORKER_NODE_ID")]
    worker_node_id: Option<Uuid>,
    /// Lease authorizing this attachment; reservations and control commands
    /// are refused unless they carry it.
    #[arg(long, env = "AIEC_GUARD_LEASE_ID")]
    lease_id: Option<Uuid>,
    #[arg(long, default_value_t = 0)]
    generation: i64,
    #[arg(long)]
    control_plane_ca_cert: Option<PathBuf>,
    /// Permit numeric-loopback plain HTTP for the budget authority.
    #[arg(long)]
    local_loopback_http: bool,
    /// Private outside-guest control socket for an authenticated owner.
    #[arg(long)]
    control_socket: Option<PathBuf>,
    #[arg(long, default_value_t = 10_000)]
    watchdog_timeout_ms: u64,
}

fn bounded_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 65536 {
        return Err(GuardError::Policy(
            "configuration must be a regular file of at most64KiB".into(),
        ));
    }
    let mut text = String::new();
    file.take(65537).read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(GuardError::Policy("configuration exceeded64KiB".into()));
    }
    Ok(text)
}

/// Reads a worker credential that only this account may read.
fn private_token(path: &Path) -> Result<Zeroizing<String>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > 4096 || metadata.mode() & 0o077 != 0 {
        return Err(GuardError::Policy(
            "worker credential file must be private and at most 4KiB".into(),
        ));
    }
    let mut text = Zeroizing::new(String::new());
    std::fs::File::open(path)?
        .take(4097)
        .read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(GuardError::Policy(
            "worker credential file is too large".into(),
        ));
    }
    Ok(Zeroizing::new(text.trim().to_owned()))
}

/// One outside-guest control request: a fence plus a shared protocol command.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    fence: GuardFence,
    command: GuardControlCommand,
}

/// Answers control requests over a credential-free UNIX socket.
///
/// Authorization is the socket's own peer credentials: the path is created
/// mode `0600`, so nothing inside the guest can open it. This is deliberately
/// not a network control endpoint and holds no token of its own.
async fn serve_control(path: &Path, gateway: Arc<GuardGateway>, lease: GuardFence) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept()?;
        let gateway = gateway.clone();
        tokio::spawn(async move {
            let authorized = peer_is_owner(&stream);
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let outcome: Result<()> = if !authorized {
                Err(GuardError::Denied(
                    "control caller is not the owning account".into(),
                ))
            } else if reader.read_line(&mut line).is_err() || line.len() > 65536 {
                Err(GuardError::Policy("invalid control request".into()))
            } else {
                match serde_json::from_str::<ControlRequest>(&line) {
                    Ok(request)
                        if request.fence.lease_id == lease.lease_id
                            && request.fence.generation >= lease.generation =>
                    {
                        match request.command {
                            GuardControlCommand::Heartbeat { policy_hash } => {
                                if policy_hash != gateway.control().policy_hash() {
                                    return Err(GuardError::Denied("policy hash mismatch".into()));
                                }
                                gateway.heartbeat(&gateway.control().identity()).map(|_| ())
                            }
                            GuardControlCommand::Cut { policy_hash } => {
                                if policy_hash != gateway.control().policy_hash() {
                                    return Err(GuardError::Denied("policy hash mismatch".into()));
                                }
                                gateway.control().cut()
                            }
                            GuardControlCommand::AppendEvent { policy_hash, event } => {
                                if policy_hash != gateway.control().policy_hash() {
                                    return Err(GuardError::Denied("policy hash mismatch".into()));
                                }
                                gateway.control().append(event).await.map(|_| ())
                            }
                            _ => Err(GuardError::Policy(
                                "this gateway accepts only heartbeat, cut and event appends".into(),
                            )),
                        }
                    }
                    Ok(_) => Err(GuardError::Denied(
                        "control request is not fenced by the active lease".into(),
                    )),
                    Err(_) => Err(GuardError::Policy("invalid control request".into())),
                }
            };
            let reply = match outcome {
                Ok(()) => serde_json::json!({"result": "ok"}),
                Err(error) => serde_json::json!({"result": "error", "error": error.to_string()}),
            };
            let mut stream = reader.into_inner();
            let _ = stream.write_all(format!("{reply}\n").as_bytes());
            let _ = stream.flush();
            Ok::<(), GuardError>(())
        });
    }
}

/// Whether the connected peer runs as this process's own account.
fn peer_is_owner(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &raw mut credentials as *mut libc::c_void,
            &mut length,
        )
    };
    result == 0 && credentials.uid == unsafe { libc::geteuid() }
}

async fn run(args: Args) -> Result<()> {
    let policy = match &args.policy {
        Some(path) => GuardPolicy::from_yaml(&bounded_file(path)?)?,
        None => GuardPolicy::default(),
    };
    let boundary = match &args.operator_boundary {
        Some(path) => serde_yaml_ng::from_str::<OperatorBoundary>(&bounded_file(path)?)?,
        None => OperatorBoundary::production(),
    };
    validate_operator_test_mode(&boundary, args.local_test_mode)?;
    let compiled = compile(&policy, &boundary)?;
    if args.verify_only {
        println!(
            "{}",
            serde_json::json!({"verification":"PASS","policy_hash":compiled.policy_hash(),"network_default":"deny","local_test_mode":args.local_test_mode})
        );
        return Ok(());
    }
    let sandbox_id = args
        .sandbox_id
        .ok_or_else(|| GuardError::Policy("--sandbox-id required".into()))?;
    let tenant_id = args
        .tenant_id
        .ok_or_else(|| GuardError::Policy("--tenant-id required".into()))?;
    let bind_ip = args
        .bind_ip
        .ok_or_else(|| GuardError::Policy("--bind-ip required".into()))?;
    let guest_ip = args
        .guest_ip
        .ok_or_else(|| GuardError::Policy("--guest-ip required".into()))?;
    if args.generation < 0 {
        return Err(GuardError::Policy(
            "--generation may not be negative".into(),
        ));
    }
    let fence = GuardFence {
        lease_id: args
            .lease_id
            .ok_or_else(|| GuardError::Policy("--lease-id required".into()))?,
        generation: args.generation,
    };
    let events =
        Arc::new(FileEventSink::open(args.events.ok_or_else(|| {
            GuardError::Policy("--events required".into())
        })?)?);
    let credentials = match &args.credentials {
        Some(path) => CredentialStore::from_file(path)?,
        None => CredentialStore::empty(),
    };
    let authority: Arc<dyn BudgetAuthority> = Arc::new(HttpBudgetAuthority::new(
        args.budget_api_url
            .as_deref()
            .ok_or_else(|| GuardError::Policy("--budget-api-url required".into()))?,
        private_token(
            args.worker_token_file
                .as_deref()
                .ok_or_else(|| GuardError::Policy("--worker-token-file required".into()))?,
        )?,
        args.worker_node_id
            .ok_or_else(|| GuardError::Policy("--worker-node-id required".into()))?,
        args.control_plane_ca_cert.as_deref(),
        args.local_loopback_http,
    )?);
    let hash = compiled.policy_hash().to_owned();
    let gateway = GuardGateway::start(GatewayConfig {
        sandbox_id,
        tenant_id,
        fence,
        compiled,
        bind_ip,
        guest_ip,
        broker_port: args.broker_port,
        dns_port: args.dns_port,
        credentials: Arc::new(credentials),
        events,
        budget_authority: authority,
        watchdog_timeout: Duration::from_millis(args.watchdog_timeout_ms),
    })
    .await?;
    println!(
        "{}",
        serde_json::json!({"gateway":"ready","sandbox_id":sandbox_id,"tenant_id":tenant_id,"policy_hash":hash,"broker":gateway.broker_addr(),"dns":gateway.dns_addr(),"network":"deny-all until the first authenticated watchdog heartbeat","packet_enforcement":"owned-by-aiec-network-backend"})
    );
    let socket_path = args.control_socket.clone();
    let mut gateway = Arc::new(gateway);
    let held = gateway.clone();
    let control = tokio::spawn(async move {
        match socket_path {
            Some(path) => serve_control(&path, held, fence).await,
            None => {
                tokio::signal::ctrl_c().await?;
                Ok(())
            }
        }
    });
    let outcome = match control.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(GuardError::Unavailable(
            "gateway control task failed".into(),
        )),
    };
    if let Some(path) = &args.control_socket {
        let _ = std::fs::remove_file(path);
    }
    let _ = gateway.cut();
    // A connection handler that is mid-reply still holds the gateway, and
    // shutting down underneath it would cut its own socket. Handing the value
    // back is therefore bounded rather than assumed.
    let mut owned = None;
    for _ in 0..50 {
        match Arc::try_unwrap(gateway) {
            Ok(gateway) => {
                owned = Some(gateway);
                break;
            }
            Err(shared) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                gateway = shared;
            }
        }
    }
    let Some(gateway) = owned else {
        // Dropping the last reference closes and cuts the gateway rather than
        // leaving listeners bound after this process stopped supervising them.
        return outcome.and(Err(GuardError::Unavailable(
            "gateway still had in-flight control connections".into(),
        )));
    };
    outcome.and(gateway.shutdown().await)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
