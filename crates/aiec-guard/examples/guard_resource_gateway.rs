//! Resource acceptance only: production GuardGateway in an isolated process.
//! The launcher records the host namespace before unsharing, as the core
//! acceptance launcher does. This handoff is not a production daemon option.
use aiec_guard::{
    budget_client::HttpBudgetAuthority,
    compiler::{OperatorBoundary, compile},
    control::GuardFence,
    deployment::{set_host_network_namespace, validate_operator_test_mode},
    events::FileEventSink,
    gateway::{CredentialStore, GatewayConfig, GuardGateway},
    policy::GuardPolicy,
};
use serde::Deserialize;
use std::{net::Ipv4Addr, path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    policy: PathBuf,
    boundary: PathBuf,
    credentials: PathBuf,
    worker_token: PathBuf,
    events: PathBuf,
    sandbox_id: Uuid,
    tenant_id: Uuid,
    fence: GuardFence,
    worker_node_id: Uuid,
    budget_url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = serde_json::from_slice(&std::fs::read(
        std::env::args().nth(1).ok_or("configuration required")?,
    )?)?;
    set_host_network_namespace(std::env::var("AIEC_GUARD_ACCEPTANCE_HOST_NETNS")?);
    let boundary: OperatorBoundary =
        serde_yaml_ng::from_str(&std::fs::read_to_string(&config.boundary)?)?;
    validate_operator_test_mode(&boundary, true)?;
    let policy = GuardPolicy::from_yaml(&std::fs::read_to_string(&config.policy)?)?;
    let compiled = compile(&policy, &boundary)?;
    let gateway = GuardGateway::start(GatewayConfig {
        sandbox_id: config.sandbox_id,
        tenant_id: config.tenant_id,
        fence: config.fence,
        compiled,
        bind_ip: Ipv4Addr::LOCALHOST,
        guest_ip: Ipv4Addr::LOCALHOST,
        broker_port: 0,
        dns_port: 0,
        credentials: Arc::new(CredentialStore::from_file(&config.credentials)?),
        events: Arc::new(FileEventSink::open(config.events)?),
        budget_authority: Arc::new(HttpBudgetAuthority::new(
            &config.budget_url,
            Zeroizing::new(std::fs::read_to_string(config.worker_token)?),
            config.worker_node_id,
            None,
            true,
        )?),
        watchdog_timeout: Duration::from_secs(60),
    })
    .await?;
    // Owner-side activation, not a guest-supplied heartbeat or relaxed policy.
    gateway.heartbeat(gateway.control().identity())?;
    println!(
        "{}",
        serde_json::json!({"gateway":"ready", "policy_hash":gateway.control().policy_hash(),
                           "broker":gateway.broker_addr(), "dns":gateway.dns_addr()})
    );
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                gateway.heartbeat(gateway.control().identity())?;
            }
        }
    }
    gateway.shutdown().await?;
    Ok(())
}
