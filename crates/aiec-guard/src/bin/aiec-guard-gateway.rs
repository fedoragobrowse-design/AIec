use aiec_guard::{
    GuardError, Result,
    compiler::{OperatorBoundary, compile},
    deployment::validate_operator_test_mode,
    events::FileEventSink,
    gateway::{CredentialStore, GatewayConfig, GuardGateway},
    policy::GuardPolicy,
};
use clap::Parser;
use std::{
    io::Read,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

/// Outside-guest gateway. Sandbox packet enforcement is owned by AIec's
/// Linux network backend, not implied merely by starting this listener.
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
    let events =
        Arc::new(FileEventSink::open(args.events.ok_or_else(|| {
            GuardError::Policy("--events required".into())
        })?)?);
    let credentials = match &args.credentials {
        Some(path) => CredentialStore::from_file(path)?,
        None => CredentialStore::empty(),
    };
    let hash = compiled.policy_hash().to_owned();
    let gateway = GuardGateway::start(GatewayConfig {
        sandbox_id,
        tenant_id,
        compiled,
        bind_ip,
        guest_ip,
        broker_port: args.broker_port,
        dns_port: args.dns_port,
        credentials: Arc::new(credentials),
        events,
    })
    .await?;
    println!(
        "{}",
        serde_json::json!({"gateway":"ready","sandbox_id":sandbox_id,"tenant_id":tenant_id,"policy_hash":hash,"broker":gateway.broker_addr(),"dns":gateway.dns_addr(),"packet_enforcement":"owned-by-aiec-network-backend"})
    );
    tokio::signal::ctrl_c().await?;
    gateway.cut()?;
    gateway.shutdown().await
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
