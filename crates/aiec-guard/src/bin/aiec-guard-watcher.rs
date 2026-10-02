//! Optional host-side watcher. Run alongside (not instead of) the deterministic
//! watchdog; this process has no heartbeat, approval, restore or release path.
use aiec_guard::{
    GuardError, Result,
    control::{GuardIdentity, RuleTrigger},
    policy::WatcherConfig,
    watchdog::{ControlPlaneTransport, Watchdog, WatchdogConfig, load_operator_token},
    watcher::{
        DeterministicState, HttpReviewer, ReviewWindow, ReviewerEndpoint, Watcher, WatcherAction,
    },
};
use chrono::Utc;
use clap::Parser;
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

/// Explicit opt-in, outside-guest reviewer. Keep a separate watchdog running.
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
    #[arg(long, conflicts_with = "token_env")]
    token_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "token_file")]
    token_env: Option<String>,
    /// WatcherConfig JSON. Omission uses the disabled production default.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Same deterministic rule configuration as the companion watchdog.
    #[arg(long)]
    rules_config: Option<PathBuf>,
    /// Task description and final claims only; never trusted for host state.
    #[arg(long)]
    evidence: Option<PathBuf>,
    #[arg(long)]
    reviewer: url::Url,
    #[arg(long, default_value = "cheap")]
    cheap_model: String,
    #[arg(long, default_value = "strong")]
    strong_model: String,
    #[arg(long)]
    reviewer_token_file: Option<PathBuf>,
    #[arg(long)]
    cost_micros_per_1k_tokens: Option<u64>,
    #[arg(long, default_value_t = 1000)]
    reviewer_timeout_ms: u64,
    /// Explicit loopback HTTP opt-in, for local reviewers only.
    #[arg(long)]
    local_loopback_http: bool,
    #[arg(long, env = "AIEC_TLS_CA_CERT")]
    control_plane_ca_cert: Option<PathBuf>,
    #[arg(long)]
    reviewer_ca_cert: Option<PathBuf>,
    /// Optional bounded operator run; zero keeps watching until interrupted.
    #[arg(long, default_value_t = 0)]
    iterations: u64,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Advisory {
    task_description: String,
    agent_claims: Vec<String>,
}
fn json_file<T: serde::de::DeserializeOwned + Default>(path: Option<&Path>) -> Result<T> {
    let Some(path) = path else {
        return Ok(T::default());
    };
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 65536 {
        return Err(GuardError::Policy(
            "watcher input must be a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(GuardError::Policy("watcher input oversized".into()));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| GuardError::Policy("invalid watcher input JSON".into()))
}
async fn run(args: Args) -> Result<()> {
    let configuration: WatcherConfig = json_file(args.config.as_deref())?;
    let rules: WatchdogConfig = json_file(args.rules_config.as_deref())?;
    rules.validate()?;
    let identity = GuardIdentity {
        sandbox_id: args.sandbox_id,
        tenant_id: args.tenant_id,
        policy_hash: args.policy_hash,
    };
    let transport = ControlPlaneTransport::with_ca(
        args.control_plane,
        load_operator_token(args.token_file.as_deref(), args.token_env.as_deref())?,
        identity.clone(),
        rules.request_timeout_ms,
        args.local_loopback_http,
        args.control_plane_ca_cert.as_deref(),
    )?;
    let reviewer = HttpReviewer::with_ca(
        ReviewerEndpoint {
            base: args.reviewer,
            cheap_model: args.cheap_model,
            strong_model: args.strong_model,
            token: args
                .reviewer_token_file
                .as_deref()
                .map(|path| load_operator_token(Some(path), None))
                .transpose()?,
            timeout_ms: args.reviewer_timeout_ms,
            local_loopback_http: args.local_loopback_http,
            cost_micros_per_1k_tokens: args.cost_micros_per_1k_tokens,
        },
        args.reviewer_ca_cert.as_deref(),
    )?;
    let watcher = Watcher::new(configuration, Arc::new(reviewer))?;
    let mut deterministic = Watchdog::new(identity.clone(), rules.clone())?;
    let mut quarantine_completed = false;
    let mut held = false;
    let mut ticks = 0u64;
    // Rules a deterministic trigger has raised, held until the control plane
    // reports the quarantine durably complete. A partial cut is not a cut, so
    // these are retried rather than dropped.
    let mut pending_rules = Vec::new();
    let mut interval = tokio::time::interval(Duration::from_millis(rules.poll_interval_ms));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { _ = tokio::signal::ctrl_c() => return Ok(()), _ = interval.tick() => {} }
        let observation = transport.observe(deterministic.cursor()).await?;
        let decision = deterministic.observe(&observation, Utc::now())?;
        if pending_rules.is_empty() && !decision.quarantine_rules.is_empty() {
            pending_rules = decision.quarantine_rules.clone();
        }
        // Apply deterministic restrictions before any model socket is opened,
        // and never call an incomplete cut done.
        if !pending_rules.is_empty() {
            if !quarantine_completed && !observation.budget.quarantined {
                let incident = transport
                    .quarantine(decision.fence, pending_rules.clone())
                    .await?;
                quarantine_completed = incident.completed_at.is_some()
                    && incident.network_cut_at.is_some()
                    && incident.paused_at.is_some()
                    && incident.snapshot_id.is_some()
                    && !incident.report.is_empty();
                println!(
                    "{}",
                    serde_json::json!({"watcher":"deterministic_quarantine","identity":identity,
                    "status":if quarantine_completed {"completed"} else {"incomplete"},
                    "incident_id":incident.id,"completed_at":incident.completed_at,
                    "network_cut_at":incident.network_cut_at,"paused_at":incident.paused_at,
                    "snapshot_id":incident.snapshot_id})
                );
                if quarantine_completed {
                    pending_rules.clear();
                }
            }
            if !quarantine_completed {
                // Reviewer input is not offered while the deterministic cut is
                // still outstanding; the rules own this window's authority.
                continue;
            }
        }
        // The deterministic floor for a window the rules have already cut.
        let state = if held || quarantine_completed || observation.budget.quarantined {
            DeterministicState::Quarantined
        } else if !decision.alerts.is_empty() || observation.network_cut {
            // Rules fired, or the attachment is already cut. Either way this
            // window's deterministic floor is above clear.
            DeterministicState::Alerted
        } else {
            DeterministicState::Clear
        };
        let advisory: Advisory = json_file(args.evidence.as_deref())?;
        // Every host event is included in bounded windows; no evidence is silently
        // truncated. Guest text stays advisory and cannot supply identities/rules.
        let count = observation
            .events
            .len()
            .div_ceil(aiec_guard::watcher::MAX_EVIDENCE_ITEMS)
            .max(1);
        for index in 0..count {
            let start = index * aiec_guard::watcher::MAX_EVIDENCE_ITEMS;
            let end =
                (start + aiec_guard::watcher::MAX_EVIDENCE_ITEMS).min(observation.events.len());
            let events = &observation.events[start..end];
            let mut window = ReviewWindow::new(identity.clone(), state);
            window.start_sequence = observation.event_start_sequence
                + (index * aiec_guard::watcher::MAX_EVIDENCE_ITEMS) as u64;
            window.events = events.to_vec();
            window.task_description = advisory.task_description.clone();
            window.agent_claims = advisory.agent_claims.clone();
            let outcome = watcher.submit(window).await?;
            let action = outcome.action();
            match action {
                WatcherAction::RecordOnly => {}
                WatcherAction::Pause => transport.pause(decision.fence).await?,
                WatcherAction::Quarantine
                    if held || quarantine_completed || observation.budget.quarantined =>
                {
                    // The deterministic floor already quarantined it, so there
                    // is nothing left for a verdict to escalate to.
                }
                WatcherAction::Quarantine => {
                    let incident = transport
                        .quarantine(
                            decision.fence,
                            vec![RuleTrigger {
                                rule: "watcher_quarantine".into(),
                                first_event_sequence: None,
                                evidence_references: vec![format!(
                                    "journal:{}:{}",
                                    decision.event_sequence, observation.event_head
                                )],
                            }],
                        )
                        .await?;
                    let complete = incident.completed_at.is_some()
                        && incident.network_cut_at.is_some()
                        && incident.paused_at.is_some()
                        && incident.snapshot_id.is_some()
                        && !incident.report.is_empty();
                    held = complete;
                    println!(
                        "{}",
                        serde_json::json!({"watcher":"verdict_quarantine","identity":identity,
                        "status":if complete {"completed"} else {"incomplete"},
                        "incident_id":incident.id,"completed_at":incident.completed_at,
                        "network_cut_at":incident.network_cut_at,"paused_at":incident.paused_at,
                        "snapshot_id":incident.snapshot_id})
                    );
                    if !complete {
                        // Retried on the next tick; an incomplete cut is never
                        // reported as a completed one.
                        break;
                    }
                }
            }
            let host = transport.observe(deterministic.cursor()).await?;
            if host.identity != identity || host.fence.lease_id != decision.fence.lease_id {
                return Err(GuardError::Integrity(
                    "watcher post-action identity mismatch".into(),
                ));
            }
            println!(
                "{}",
                serde_json::json!({"watcher":"outcome","identity":identity,"outcome":outcome,
                "budget":watcher.budget(identity.sandbox_id),"pending":watcher.pending(),"provenance":"control-plane/worker/guard",
                "host":{"network_cut":host.network_cut,"paused":host.paused,"quarantined":host.budget.quarantined,
                    "event_sequence":host.event_sequence,"event_head":host.event_head,"fence":host.fence}})
            );
        }
        ticks += 1;
        if args.iterations != 0 && ticks >= args.iterations {
            // Windows held for a batch are reviewed rather than silently dropped.
            if let Some(outcome) = watcher.flush().await? {
                let host = transport.observe(deterministic.cursor()).await?;
                println!(
                    "{}",
                    serde_json::json!({"watcher":"outcome","identity":identity,"outcome":outcome,
                    "budget":watcher.budget(identity.sandbox_id),"pending":watcher.pending(),"flushed":true,
                    "provenance":"control-plane/worker/guard",
                    "host":{"network_cut":host.network_cut,"paused":host.paused,"quarantined":host.budget.quarantined,
                        "event_sequence":host.event_sequence,"event_head":host.event_head,"fence":host.fence}})
                );
            }
            return Ok(());
        }
    }
}
#[tokio::main]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        let reason = match error {
            GuardError::Policy(_) => "configuration",
            GuardError::Integrity(_) => "integrity",
            _ => "unavailable",
        };
        eprintln!(
            "{}",
            serde_json::json!({"watcher":"stopped","reason":reason,"authority":"restriction_only"})
        );
        std::process::exit(1);
    }
}
