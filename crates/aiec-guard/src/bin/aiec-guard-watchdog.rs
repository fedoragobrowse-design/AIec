use aiec_guard::{
    GuardError, Result,
    control::{GuardIdentity, RuleTrigger},
    watchdog::{ControlPlaneTransport, Watchdog, WatchdogConfig, load_operator_token},
};
use chrono::Utc;
use clap::Parser;
use std::{
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};
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

/// Doubles the quarantine retry delay, capped at ten seconds. The first retry
/// is immediate, so a stage that failed once in a moment is retried at once.
fn next_backoff(current: Duration) -> Duration {
    match current {
        Duration::ZERO => Duration::from_secs(1),
        current => (current * 2).min(Duration::from_secs(10)),
    }
}

/// How long one incident's quarantine is retried before the watchdog gives up
/// on it, and how many attempts fit in that window.
///
/// The retry is not free and it is not the containment. A refused incident -
/// an authorization that does not change, a fence that no longer matches - is
/// answered the same way every time, so retrying it every ten seconds forever
/// turns one incident into thousands of identical requests and still never
/// completes one. An incomplete incident is genuinely resumable, so it is
/// retried, but on a deadline rather than at a fixed rate: a stage the control
/// plane cannot finish is a fact about the control plane, and no number of
/// retries from here changes it.
///
/// Giving up is fail-closed rather than an escape. The gateway's independent
/// deadman already cuts an attachment whose heartbeat stops, and this process
/// stops heartbeating the moment quarantine is requested, so a terminal exit
/// loses nothing that was still to happen and is visible to the operator
/// instead of being a watchdog that looks alive and has stopped working.
const QUARANTINE_RETRY_WINDOW: Duration = Duration::from_secs(120);
const QUARANTINE_RETRY_LIMIT: u32 = 12;

/// Whether one incident's quarantine stage has spent its retry budget.
///
/// Both bounds matter and neither subsumes the other: the count bounds a
/// control plane that fails instantly, the window bounds one that is slow
/// enough to answer every attempt in time.
fn quarantine_exhausted(attempts: u32, elapsed: Duration) -> bool {
    attempts >= QUARANTINE_RETRY_LIMIT || elapsed >= QUARANTINE_RETRY_WINDOW
}

/// A closed, data-free label for why one quarantine dispatch produced no
/// usable incident.
///
/// The watchdog deliberately never logs transport diagnostics, response
/// bodies or URLs, which is right for what those can contain and wrong if it
/// leaves an operator with "failed" for four different situations. Matching the
/// locally authored constants keeps the label set closed: an unrecognised
/// message falls back to a label that says nothing rather than to one that
/// guesses, so a new failure mode cannot become a misleading label.
fn quarantine_failure_class(error: &GuardError) -> &'static str {
    match error {
        GuardError::Unavailable(_) => "control_plane_unreachable",
        GuardError::Integrity(message) => match message.as_str() {
            "quarantine result identity mismatch" => "identity_mismatch",
            "invalid authoritative HTTP evidence" => "evidence_unreadable",
            "HTTP evidence response oversized" => "evidence_oversized",
            _ => "evidence_rejected",
        },
        GuardError::Json(_) => "evidence_unparsable",
        _ => "dispatch_rejected",
    }
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
    // An incomplete stage is retried, but not at the poll rate: the retry is a
    // second attempt at a durable transition, and hammering it turns one
    // incident into hundreds of attempts in the journal and on the control
    // plane. The first retry is immediate; the delay doubles up to ten seconds
    // and the whole stage is bounded by QUARANTINE_RETRY_WINDOW.
    let mut quarantine_backoff = Duration::ZERO;
    let mut quarantine_attempts = 0u32;
    let mut quarantine_started: Option<Instant> = None;
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
            let started = *quarantine_started.get_or_insert_with(Instant::now);
            if !quarantine_backoff.is_zero() {
                tokio::time::sleep(quarantine_backoff).await;
            }
            quarantine_attempts += 1;
            // Cut/pause/preserve is one authoritative idempotent action. Keep
            // retrying incomplete stages, but never call a cut-only result done.
            let outcome = match transport
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
                        quarantine_backoff = Duration::ZERO;
                        None
                    } else {
                        quarantine_backoff = next_backoff(quarantine_backoff);
                        Some("incomplete")
                    }
                }
                Err(error) => {
                    // The label is a closed set and never carries transport
                    // diagnostics, response bodies or URLs. Without one of
                    // these, "quarantine failed" is a symptom: an unreachable
                    // control plane, a refused one and one whose evidence this
                    // watcher refuses all look identical in the log, and the
                    // first of those is worth a retry while the last two are
                    // worth a look at the control plane.
                    let reason = quarantine_failure_class(&error);
                    println!(
                        "{}",
                        serde_json::json!({"action":"quarantine","status":"failed","identity":identity,"reason":reason})
                    );
                    quarantine_backoff = next_backoff(quarantine_backoff);
                    Some(reason)
                }
            };
            // A stage that is neither complete nor making progress across the
            // whole window is terminal, and the process says so instead of
            // continuing to look like a working observer. Exiting also stops
            // the heartbeat, which is the direction every one of these states
            // should end in: the gateway deadman cuts what this process was
            // still heartbeating.
            if let Some(reason) = outcome
                && quarantine_exhausted(quarantine_attempts, started.elapsed())
            {
                println!(
                    "{}",
                    serde_json::json!({"action":"quarantine","status":"terminal","identity":identity,
                        "reason":reason,"attempts":quarantine_attempts,
                        "heartbeat":"withheld","network":"deadman_fail_closed"})
                );
                return Err(GuardError::Unavailable(
                    "quarantine did not complete within the retry window".into(),
                ));
            }
            // Do not renew access while quarantine is requested or incomplete.
            continue;
        }
        quarantine_backoff = Duration::ZERO;
        quarantine_attempts = 0;
        quarantine_started = None;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_incomplete_incident_stops_being_retried() {
        // Well inside the budget: the stage is still worth resuming.
        assert!(!quarantine_exhausted(1, Duration::from_secs(1)));
        assert!(!quarantine_exhausted(
            QUARANTINE_RETRY_LIMIT - 1,
            Duration::from_secs(30)
        ));
        // A control plane that refuses or stalls is terminal on the count.
        assert!(quarantine_exhausted(
            QUARANTINE_RETRY_LIMIT,
            Duration::from_secs(1)
        ));
        // And on the window, for one that answers promptly and never finishes.
        assert!(quarantine_exhausted(2, QUARANTINE_RETRY_WINDOW));
        assert!(quarantine_exhausted(
            2,
            QUARANTINE_RETRY_WINDOW + Duration::from_secs(1)
        ));
    }

    #[test]
    fn the_retry_backoff_grows_and_then_stops_growing() {
        let mut delay = next_backoff(Duration::ZERO);
        assert_eq!(delay, Duration::from_secs(1));
        for expected in [2, 4, 8, 10, 10] {
            delay = next_backoff(delay);
            assert_eq!(delay, Duration::from_secs(expected));
        }
    }

    #[test]
    fn every_quarantine_failure_has_a_closed_data_free_label() {
        assert_eq!(
            quarantine_failure_class(&GuardError::Unavailable("transport".into())),
            "control_plane_unreachable"
        );
        assert_eq!(
            quarantine_failure_class(&GuardError::Integrity(
                "quarantine result identity mismatch".into()
            )),
            "identity_mismatch"
        );
        assert_eq!(
            quarantine_failure_class(&GuardError::Integrity(
                "invalid authoritative HTTP evidence".into()
            )),
            "evidence_unreadable"
        );
        // An unrecognised message is labelled as unrecognised rather than as
        // whichever specific cause it might turn out to be.
        assert_eq!(
            quarantine_failure_class(&GuardError::Integrity("new cause".into())),
            "evidence_rejected"
        );
        assert_eq!(
            quarantine_failure_class(&GuardError::Denied("no".into())),
            "dispatch_rejected"
        );
    }
}
