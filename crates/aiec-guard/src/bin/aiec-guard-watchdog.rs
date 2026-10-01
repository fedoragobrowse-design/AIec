use aiec_guard::{
    GuardError, Result,
    control::{GuardIdentity, RuleTrigger},
    watchdog::{ControlPlaneTransport, Watchdog, WatchdogConfig, load_operator_token},
};
use chrono::Utc;
use clap::Parser;
use std::{io::Read, path::PathBuf, time::Duration};
use uuid::Uuid;

/// Independent host-side observer. Never run inside a sandbox. Only the control
/// plane may quarantine; this process cannot approve, restore or release egress.
#[derive(Parser)]
struct Args {
    #[arg(long)]
    control_plane: url::Url,
    #[arg(long)]
    sandbox_id: Uuid,
    #[arg(long)]
    tenant_id: Uuid,
    #[arg(long)]
    policy_hash: String,
    /// Owner-readable outside-guest file containing an operator-scoped token.
    #[arg(long, conflicts_with = "token_env")]
    token_file: Option<PathBuf>,
    /// Name of an environment variable; never supply the token as an argument.
    #[arg(long, conflicts_with = "token_file")]
    token_env: Option<String>,
    /// Bounded JSON WatchdogConfig; unknown fields are rejected.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Permit plaintext only to a numeric loopback address for local mocks.
    #[arg(long)]
    local_loopback_http: bool,
    /// Operator's private certificate authority for the control plane. TLS
    /// verification stays on; this adds a root rather than removing the check.
    #[arg(long, env = "AIEC_TLS_CA_CERT")]
    control_plane_ca_cert: Option<PathBuf>,
}
fn config(path: Option<PathBuf>) -> Result<WatchdogConfig> {
    let Some(path) = path else {
        return Ok(WatchdogConfig::default());
    };
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 65536 {
        return Err(GuardError::Policy(
            "watchdog config must be a regular file at most 64KiB".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(GuardError::Policy("watchdog config oversized".into()));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| GuardError::Policy("invalid watchdog JSON configuration".into()))
}
async fn run(args: Args) -> Result<()> {
    let configuration = config(args.config)?;
    configuration.validate()?;
    let identity = GuardIdentity {
        sandbox_id: args.sandbox_id,
        tenant_id: args.tenant_id,
        policy_hash: args.policy_hash,
    };
    let token = load_operator_token(args.token_file.as_deref(), args.token_env.as_deref())?;
    let transport = ControlPlaneTransport::with_ca(
        args.control_plane,
        token,
        identity.clone(),
        configuration.request_timeout_ms,
        args.local_loopback_http,
        args.control_plane_ca_cert.as_deref(),
    )?;
    let interval = Duration::from_millis(configuration.poll_interval_ms);
    let heartbeat_age = configuration
        .heartbeat_ttl_ms
        .saturating_sub(configuration.request_timeout_ms) as i64;
    let mut watchdog = Watchdog::new(identity.clone(), configuration)?;
    let mut pending_rules: Vec<RuleTrigger> = Vec::new();
    let mut quarantine_completed = false;
    let mut interval = tokio::time::interval(interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    println!(
        "{}",
        serde_json::json!({"watchdog":"starting","identity":identity,"authority":"control_plane","guest_advisory":"excluded"})
    );
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { return Ok(()); }
            _ = interval.tick() => {}
        }
        // A lost or invalid observation withholds the heartbeat. The gateway's
        // independent deadman expires and cuts; there is no fallback and no
        // release. The process does not exit on the first failure: a watchdog
        // that gives up after one refused request is indistinguishable from one
        // that was never started, and the sandbox is already cut either way -
        // what is lost by stopping is the chance to report why, and to be the
        // thing an operator sees come back.
        let observation = match transport.observe(watchdog.cursor()).await {
            Ok(observation) => observation,
            Err(_) => {
                println!(
                    "{}",
                    serde_json::json!({"watchdog":"observation_unavailable","identity":identity,"heartbeat":"withheld","network":"deadman_fail_closed"})
                );
                tokio::time::sleep(interval.period()).await;
                continue;
            }
        };
        let decision = match watchdog.observe(&observation, Utc::now()) {
            Ok(decision) => decision,
            Err(_) => {
                println!(
                    "{}",
                    serde_json::json!({"watchdog":"observation_rejected","identity":identity,"heartbeat":"withheld","network":"deadman_fail_closed"})
                );
                tokio::time::sleep(interval.period()).await;
                continue;
            }
        };
        for alert in &decision.alerts {
            println!(
                "{}",
                serde_json::json!({"alert":alert,"identity":identity,"observed_at":decision.observed_at,"event_sequence":decision.event_sequence})
            );
        }
        if !quarantine_completed
            && pending_rules.is_empty()
            && !decision.quarantine_rules.is_empty()
        {
            pending_rules = decision.quarantine_rules.clone();
        }
        if !pending_rules.is_empty() {
            // Cut/pause/preserve is one authoritative idempotent action. Keep
            // retrying incomplete stages, but never call a cut-only result done.
            match transport
                .quarantine(decision.fence, pending_rules.clone())
                .await
            {
                Ok(incident) => {
                    let completed = incident.completed_at.is_some()
                        && incident.network_cut_at.is_some()
                        && incident.paused_at.is_some()
                        && incident.snapshot_id.is_some()
                        && !incident.report.is_empty();
                    println!(
                        "{}",
                        serde_json::json!({"action":"quarantine","status":if completed {"completed"} else {"incomplete"},
                        "identity":identity,"incident_id":incident.id,"network_cut_at":incident.network_cut_at,"paused_at":incident.paused_at,
                        "completed_at":incident.completed_at,"event_sequence":incident.event_sequence,"event_head":incident.event_head})
                    );
                    if completed {
                        quarantine_completed = true;
                        pending_rules.clear();
                    }
                }
                Err(_) => {
                    // Never echo transport diagnostics, response bodies or URLs.
                    println!(
                        "{}",
                        serde_json::json!({"action":"quarantine","status":"failed","identity":identity})
                    );
                }
            }
            // Do not renew access while quarantine is requested or incomplete.
            continue;
        }
        // A cut attachment is still reported to: an attachment starts cut, and
        // the heartbeat is the only thing that releases it. The gateway applies
        // the rules that matter - it refuses a heartbeat once the cut is latched
        // and refuses-and-latches once the deadline has passed - so the watcher
        // does not second-guess a cut by declining to speak.
        if observation.budget.quarantined {
            println!(
                "{}",
                serde_json::json!({"watchdog":"heartbeat_withheld","identity":identity,
                    "reason":"budget_quarantined"})
            );
            continue;
        }
        if !quarantine_completed {
            if Utc::now()
                .signed_duration_since(decision.observed_at)
                .num_milliseconds()
                >= heartbeat_age
            {
                return Err(GuardError::Unavailable(
                    "verified observation expired before heartbeat".into(),
                ));
            }
            transport.heartbeat(decision.fence).await?;
        }
    }
}
#[tokio::main]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        // Static category only: no token, operator URL, guest text or prompt data.
        let category = match error {
            GuardError::Integrity(_) => "integrity",
            GuardError::Policy(_) => "configuration",
            _ => "unavailable",
        };
        eprintln!(
            "{}",
            serde_json::json!({"watchdog":"stopped","reason":category,"heartbeat":"withheld","network":"deadman_fail_closed"})
        );
        std::process::exit(1);
    }
}
