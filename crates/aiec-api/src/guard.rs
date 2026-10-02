//! Control-plane Guard orchestration: telemetry, heartbeat, quarantine and the
//! durable lifetime/budget reaper.
//!
//! Everything here is authoritative. The watchdog observes this surface, and
//! the guest is never asked what happened.

use std::sync::Arc;

use aiec_core::{CoreError, Sandbox, SandboxState, Scope, storage::MetadataStore};
use aiec_guard::{
    control::{
        BudgetDebit, GuardControlCommand, GuardControlResponse, GuardFence, GuardIdentity,
        GuardIncident, GuardObservation, QuarantineRequest,
    },
    watchdog::{NotificationOutcome, Notifier},
};
use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ApiFailure, ApiResult, AppState, Principal};

/// Bound on the events one telemetry response may carry, matching the journal's
/// own page size. A cursor that far behind is a conflict, not a silent skip.
pub(crate) const TELEMETRY_PAGE: u64 = 4096;
/// A quarantine names the rules that fired; there are never many.
const MAX_INCIDENT_RULES: usize = 16;

/// Derives the durable ceilings a guarded sandbox is held to.
///
/// The initialisation is idempotent and immutable: a re-initialisation with the
/// same identity returns the stored state, and one that would change a ceiling
/// or the expiry is refused. That is what makes a worker restart unable to hand
/// a machine a fresh budget.
pub(crate) async fn initialize_guard_budget(
    store: &dyn MetadataStore,
    sandbox: &Sandbox,
) -> Result<(), CoreError> {
    let Some(guard) = &sandbox.environment.guard else {
        return Ok(());
    };
    // `hash` canonicalizes, which is the same normalization `compile` applies,
    // so this is the identity the worker's attachment checks against.
    let policy = guard
        .effective_policy()
        .map_err(|error| CoreError::InvalidRequest(format!("guard policy is unusable: {error}")))?;
    let state = aiec_guard::control::GuardBudgetState {
        identity: GuardIdentity {
            sandbox_id: sandbox.id,
            tenant_id: sandbox.tenant_id,
            policy_hash: policy.hash().map_err(|error| {
                CoreError::InvalidRequest(format!("guard policy is unhashable: {error}"))
            })?,
        },
        // The sandbox's own timeout is the ceiling the operator asked for, and
        // it was already accepted at creation.
        expires_at: sandbox.created_at + Duration::seconds(sandbox.timeout_seconds as i64),
        max_model_requests: guard.max_model_requests,
        max_bytes_in: policy.limits.bytes_in,
        max_bytes_out: policy.limits.bytes_out,
        model_requests: 0,
        bytes_in: 0,
        bytes_out: 0,
        quarantined: false,
    };
    store.put_guard_budget(state).await.map(|_| ())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BudgetReserveBody {
    pub identity: GuardIdentity,
    pub fence: GuardFence,
    pub debit: BudgetDebit,
}

/// Worker-authenticated durable reservation. A refusal is a denial, not an
/// error to retry: the gateway must not forward bytes it could not reserve.
pub(crate) async fn reserve_guard_budget(
    State(state): State<AppState>,
    Path(node): Path<Uuid>,
    Json(body): Json<BudgetReserveBody>,
) -> Result<StatusCode, ApiFailure> {
    let sandbox = state
        .repository()
        .get_sandbox(body.identity.tenant_id, body.identity.sandbox_id)
        .await
        .map_err(ApiFailure::from)?;
    if sandbox.node_id != Some(node) {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "sandbox is not owned by this worker",
        ));
    }
    if sandbox.state == SandboxState::Quarantined {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "sandbox is quarantined",
        ));
    }
    state
        .repository()
        .reserve_guard_budget(body.identity.clone(), body.fence, body.debit)
        .await
        .map_err(ApiFailure::from)?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkerQuarantineBody {
    identity: GuardIdentity,
    request: QuarantineRequest,
}

/// The assigned host worker may restrict its sandbox after a critical canary.
/// It cannot supply a release, arbitrary rule, or unanchored guest assertion.
pub(crate) async fn worker_guard_quarantine(
    State(state): State<AppState>,
    Path(node): Path<Uuid>,
    Json(body): Json<WorkerQuarantineBody>,
) -> Result<StatusCode, ApiFailure> {
    let sandbox = state
        .repository()
        .get_sandbox(body.identity.tenant_id, body.identity.sandbox_id)
        .await
        .map_err(ApiFailure::from)?;
    if sandbox.node_id != Some(node)
        || body.identity.policy_hash != body.request.policy_hash
        || guard_policy_hash(&sandbox)? != body.identity.policy_hash
    {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "canary quarantine is not bound to this worker and policy",
        ));
    }
    let fence = current_fence(&state, sandbox.tenant_id, sandbox.id).await?;
    // A different lease is a reassignment and is refused. A generation *behind*
    // the current one on the same lease is a renewal the attachment could not
    // observe yet: refusing it would leave a critical canary with a cut network
    // and no durable quarantine, which is the worse outcome. This request can
    // only restrict, never release, and the durable write below always uses the
    // fence this read resolved rather than the one the caller supplied.
    if fence.lease_id != body.request.fence.lease_id
        || body.request.fence.generation > fence.generation
    {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "canary quarantine names an unissued or stale lease",
        ));
    }
    let [rule] = body.request.rules.as_slice() else {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "worker quarantine requires one critical credential-canary rule",
        ));
    };
    if rule.rule != aiec_guard::canaries::RULE_CANARY_CREDENTIAL
        || rule.evidence_references.len() != 2
    {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "worker quarantine requires an opaque canary reference and journal hash",
        ));
    }
    let observation = observe(state.clone(), sandbox.tenant_id, sandbox.id, 0).await?;
    if !observation.network_cut
        || !observation.events.iter().any(|event| {
            event.category == aiec_guard::events::Category::Credential
                && event.decision == aiec_guard::events::Decision::Quarantine
                && event.destination.as_ref() == Some(&rule.evidence_references[0])
                && event.current_hash == rule.evidence_references[1]
                && event.policy_hash == body.identity.policy_hash
        })
    {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "critical canary lacks a verified cut and matching host journal event",
        ));
    }
    begin_quarantine(state.clone(), sandbox.tenant_id, sandbox.id, body.request).await?;
    // Acknowledgment means durable restriction, not merely queued work. The
    // latched budget is also picked up by the existing recovery reaper.
    state
        .repository()
        .mark_guard_quarantined(sandbox.tenant_id, sandbox.id, fence)
        .await
        .map_err(ApiFailure::from)?;
    tokio::spawn(async move {
        if let Err(error) = advance_quarantine(state, sandbox.tenant_id, sandbox.id).await {
            tracing::warn!(
                sandbox_id = %sandbox.id,
                reason = %error.message,
                "critical canary forensic stages remain incomplete"
            );
        }
    });
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub(crate) struct TelemetryQuery {
    #[serde(default)]
    pub after: u64,
}

pub(crate) async fn guard_telemetry(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Query(query): Query<TelemetryQuery>,
) -> ApiResult<GuardObservation> {
    principal
        .authorize(Scope::GuardRead)
        .map_err(ApiFailure::from)?;
    Ok(Json(
        observe(state, principal.tenant_id, id, query.after).await?,
    ))
}

/// Reads the worker-side observation and settles it against durable state.
///
/// The worker's journal has already been verified against its acknowledged
/// head inside the manager; what is added here is the ownership read and the
/// budget, both of which only the control plane can authorise.
async fn observe(
    state: AppState,
    tenant: Uuid,
    id: Uuid,
    after: u64,
) -> Result<GuardObservation, ApiFailure> {
    let sandbox = state
        .repository()
        .get_sandbox(tenant, id)
        .await
        .map_err(ApiFailure::from)?;
    let policy_hash = guard_policy_hash(&sandbox)?;
    let fence = current_fence(&state, tenant, id).await?;
    let runtime = state.runtime_for(&sandbox).map_err(ApiFailure::from)?;
    let observed = runtime
        .guard_control(
            &sandbox,
            fence,
            GuardControlCommand::Observe {
                policy_hash: policy_hash.clone(),
                after,
            },
        )
        .await
        .map_err(ApiFailure::from)?;
    let GuardControlResponse::Observation(observed) = observed else {
        return Err(ApiFailure::new(
            StatusCode::BAD_GATEWAY,
            "runtime_unavailable",
            "worker returned no authoritative observation",
        ));
    };
    if observed
        .event_sequence
        .saturating_sub(observed.event_start_sequence)
        >= TELEMETRY_PAGE
    {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "observation exceeds one telemetry page",
        ));
    }
    let budget = state
        .repository()
        .get_guard_budget(tenant, id)
        .await
        .map_err(ApiFailure::from)?;
    if budget.identity.policy_hash != policy_hash {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "guard policy hash changed under an existing sandbox",
        ));
    }
    Ok(GuardObservation {
        identity: budget.identity.clone(),
        fence,
        counters: observed.counters,
        events: observed.events,
        observed_at: observed.observed_at,
        event_start_sequence: observed.event_start_sequence,
        event_previous_hash: observed.event_previous_hash,
        event_sequence: observed.event_sequence,
        event_head: observed.event_head,
        network_cut: observed.network_cut,
        paused: sandbox.state == SandboxState::Paused,
        budget,
    })
}

async fn current_fence(state: &AppState, tenant: Uuid, id: Uuid) -> Result<GuardFence, ApiFailure> {
    let dispatch = state
        .scheduler()
        .dispatch_target(tenant, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(GuardFence {
        lease_id: dispatch.lease_id,
        generation: dispatch.generation,
    })
}

fn guard_policy_hash(sandbox: &Sandbox) -> Result<String, ApiFailure> {
    let guard = sandbox.environment.guard.as_ref().ok_or_else(|| {
        ApiFailure::new(StatusCode::CONFLICT, "conflict", "sandbox is not guarded")
    })?;
    // `hash` canonicalizes, which is the same normalization `compile` applies,
    // so this is the identity the worker's own attachment check compares against.
    guard
        .effective_policy()
        .and_then(|policy| policy.hash())
        .map_err(|error| {
            ApiFailure::new(
                StatusCode::CONFLICT,
                "conflict",
                format!("guard policy is unusable: {error}"),
            )
        })
}

/// The watchdog's liveness lease. Every accepted heartbeat is proof that a
/// live outside-guest process read an observation it could verify.
pub(crate) async fn guard_heartbeat(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiFailure> {
    principal
        .authorize(Scope::GuardHeartbeat)
        .map_err(ApiFailure::from)?;
    // The heartbeat is a claim about liveness, so it is only issued after an
    // observation the watchdog's own caller has just read and verified.
    let observation = observe(state.clone(), principal.tenant_id, id, 0).await?;
    let sandbox = state
        .repository()
        .get_sandbox(principal.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let runtime = state.runtime_for(&sandbox).map_err(ApiFailure::from)?;
    runtime
        .guard_control(
            &sandbox,
            observation.fence,
            GuardControlCommand::Heartbeat {
                policy_hash: observation.identity.policy_hash.clone(),
            },
        )
        .await
        .map_err(ApiFailure::from)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn guard_incident(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<GuardIncident> {
    principal
        .authorize(Scope::GuardRead)
        .map_err(ApiFailure::from)?;
    let incident = state
        .repository()
        .get_guard_incident(principal.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(incident))
}

pub(crate) async fn guard_quarantine(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(request): Json<QuarantineRequest>,
) -> ApiResult<GuardIncident> {
    principal
        .authorize(Scope::GuardQuarantine)
        .map_err(ApiFailure::from)?;
    if request.rules.is_empty() || request.rules.len() > MAX_INCIDENT_RULES {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "a quarantine must name between one and sixteen triggered rules",
        ));
    }
    let incident = quarantine(state, principal.tenant_id, id, request).await?;
    Ok(Json(incident))
}

/// One authoritative quarantine path, in the order the threat model requires.
///
/// The cut comes first and is never gated on the audit succeeding: an unrecorded
/// cut is better than an uncut machine. Each later stage is attempted whether or
/// not an earlier one succeeded, because a half-finished quarantine is exactly
/// the state a second call must finish - and a repeat call that finds every
/// stage already done returns the incident it produced.
pub(crate) async fn quarantine(
    state: AppState,
    tenant: Uuid,
    id: Uuid,
    request: QuarantineRequest,
) -> Result<GuardIncident, ApiFailure> {
    // A capture of a full VM takes minutes. Holding an HTTP request open across
    // it would abandon work the server is still doing - and the caller, a
    // watchdog with a one-second budget, would give up on exactly the request
    // that matters. So the stages run on their own task and the caller polls
    // the incident, which is the same record the stages are updating.
    let incident = begin_quarantine(state.clone(), tenant, id, request).await?;
    let worker = state.clone();
    let sandbox_id = id;
    tokio::spawn(async move {
        let tenant_id = tenant;
        if let Err(error) = advance_quarantine(worker, tenant_id, sandbox_id).await {
            tracing::warn!(
                %sandbox_id,
                reason = %error.message,
                "guard quarantine stages did not complete; the incident records why"
            );
        }
    });
    Ok(incident)
}

/// Validates the request, seeds the incident from authoritative evidence and
/// persists it. Everything after this point is repeatable.
async fn begin_quarantine(
    state: AppState,
    tenant: Uuid,
    id: Uuid,
    request: QuarantineRequest,
) -> Result<GuardIncident, ApiFailure> {
    let sandbox = state
        .repository()
        .get_sandbox(tenant, id)
        .await
        .map_err(ApiFailure::from)?;
    let policy_hash = guard_policy_hash(&sandbox)?;
    if policy_hash != request.policy_hash {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "quarantine names a different policy than the sandbox runs",
        ));
    }
    if let Some(incident) = existing_incident(&state, tenant, id).await
        && incident.completed_at.is_some()
    {
        return Ok(incident);
    }
    let fence = current_fence(&state, tenant, id).await?;
    // The fence is compared the way every other action is: a different lease is
    // a reassignment and is refused, and a generation ahead of the stored one
    // belongs to no issued state. A generation *behind* the current one is a
    // renewal race - the watchdog read its fence a moment before the worker
    // renewed - and refusing it would mean a healthy watcher could never
    // quarantine anything.
    if fence.lease_id != request.fence.lease_id || request.fence.generation > fence.generation {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "quarantine is fenced to a lease that is no longer current",
        ));
    }
    // The incident is created carrying the evidence that triggered it. A store
    // that accepted an incident with an empty anchor would be accepting an
    // unverifiable claim, so the first write has to be anchored in the
    // authoritative stream rather than asserted.
    let seed = observe(state.clone(), tenant, id, 0).await?;
    if seed.event_head.is_empty() {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "guard journal produced no verifiable head to anchor the incident",
        ));
    }
    let started = match existing_incident(&state, tenant, id).await {
        Some(incident) => incident,
        None => GuardIncident {
            id: aiec_core::new_id(),
            identity: seed.identity.clone(),
            fence,
            rules: request.rules.clone(),
            triggered_at: Utc::now(),
            network_cut_at: None,
            paused_at: None,
            snapshot_id: None,
            completed_at: None,
            events: seed.events.clone(),
            event_start_sequence: seed.event_start_sequence,
            event_previous_hash: seed.event_previous_hash.clone(),
            event_sequence: seed.event_sequence,
            event_head: seed.event_head.clone(),
            errors: Vec::new(),
            notified_at: None,
            report: String::new(),
        },
    };
    persist(&state, started).await
}

/// Runs every stage that has not yet succeeded, and returns the incident.
async fn advance_quarantine(
    state: AppState,
    tenant: Uuid,
    id: Uuid,
) -> Result<GuardIncident, ApiFailure> {
    let sandbox = state
        .repository()
        .get_sandbox(tenant, id)
        .await
        .map_err(ApiFailure::from)?;
    let policy_hash = guard_policy_hash(&sandbox)?;
    let fence = current_fence(&state, tenant, id).await?;
    let runtime = state.runtime_for(&sandbox).map_err(ApiFailure::from)?;
    let request = QuarantineRequest {
        fence,
        policy_hash: policy_hash.clone(),
        rules: existing_incident(&state, tenant, id)
            .await
            .map(|incident| incident.rules)
            .unwrap_or_default(),
    };
    let mut incident = existing_incident(&state, tenant, id)
        .await
        .ok_or_else(|| ApiFailure::from(CoreError::NotFound("no guard incident".into())))?;

    // 1. network cut.
    let mut failures: Vec<String> = Vec::new();
    if incident.network_cut_at.is_none() {
        match runtime
            .guard_control(
                &sandbox,
                fence,
                GuardControlCommand::Cut {
                    policy_hash: policy_hash.clone(),
                },
            )
            .await
        {
            Ok(_) => incident.network_cut_at = Some(Utc::now()),
            Err(error) => failures.push(format!("network cut: {error}")),
        }
    }
    incident = record_stage(&state, incident, failures).await?;

    // 2. capture while paused. The worker pauses and snapshots inside one
    //    fenced action, so a capture that fails after the pause still leaves the
    //    machine frozen - and the retry re-runs only the capture, which is why
    //    the gate here is the capture rather than the pause.
    let mut failures: Vec<String> = Vec::new();
    if incident.snapshot_id.is_none() {
        let snapshot_id = incident.id.to_string();
        match runtime
            .guard_control(
                &sandbox,
                fence,
                GuardControlCommand::CapturePaused {
                    snapshot_id: snapshot_id.clone(),
                },
            )
            .await
        {
            Ok(GuardControlResponse::Forensics { snapshot_id, .. }) => {
                incident.snapshot_id = Some(snapshot_id);
                incident.paused_at = Some(Utc::now());
            }
            Ok(_) => failures.push("worker did not confirm a forensic capture".into()),
            Err(error) => failures.push(format!("forensic capture: {error}")),
        }
    }
    incident = record_stage(&state, incident, failures).await?;

    // 3. durable quarantine mark. This is the state every later authority reads,
    //    so it is not "attempted": until it holds, the sandbox is still a
    //    sandbox, and the incident stays incomplete so it is tried again.
    if state
        .repository()
        .mark_guard_quarantined(tenant, id, fence)
        .await
        .is_err()
    {
        let incident =
            record_stage(&state, incident, vec!["durable quarantine mark".into()]).await?;
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            format!(
                "quarantine could not be marked durably: {}",
                incident
                    .errors
                    .last()
                    .map(String::as_str)
                    .unwrap_or("unknown")
            ),
        ));
    }
    incident = record_stage(&state, incident, Vec::new()).await?;

    // 4. the authoritative event, appended outside the guest. Appended once per
    //    incident: a stage that is still being retried must not add a second
    //    "quarantine" to a hash-chained stream, because every reader counts
    //    those rows and a retry storm would read as repeated decisions. Whether
    //    one is already there is answered by re-reading the stream, not by what
    //    this process remembers doing.
    let already_recorded = observe(state.clone(), tenant, id, 0)
        .await?
        .events
        .iter()
        .any(|event| event.category == aiec_guard::events::Category::Quarantine);
    let mut failures: Vec<String> = Vec::new();
    if already_recorded {
        tracing::warn!("quarantine event already recorded for {id}; not appending a duplicate");
    } else {
        let event = aiec_guard::events::EventInput {
            sandbox_id: id,
            tenant_id: tenant,
            policy_hash: policy_hash.clone(),
            category: aiec_guard::events::Category::Quarantine,
            decision: aiec_guard::events::Decision::Quarantine,
            reason: "watchdog quarantine".into(),
            destination: request.rules.first().map(|rule| rule.rule.clone()),
            request_bytes: 0,
            response_bytes: 0,
            duration_ms: 0,
        };
        if let Err(error) = runtime
            .guard_control(
                &sandbox,
                fence,
                GuardControlCommand::AppendEvent {
                    policy_hash: policy_hash.clone(),
                    event,
                },
            )
            .await
        {
            failures.push(format!("guard event: {error}"));
        }
    }
    // The incident's evidence is re-read from the authoritative stream rather
    // than assembled from what this process happened to be told.
    match observe(state.clone(), tenant, id, incident.event_sequence).await {
        Ok(fresh) => {
            // Extend the incident's window, never replace it. The incident is
            // anchored at the page that triggered it, and a continuation page
            // carries a different starting anchor; replacing the anchors would
            // rewrite the evidence the incident was opened with, which is the
            // one thing the store refuses to let a caller do.
            let continues = fresh
                .events
                .first()
                .map(|event| event.previous_hash == incident.event_head)
                .unwrap_or(true);
            if continues {
                incident.events.extend(fresh.events);
                incident.event_sequence = fresh.event_sequence;
                incident.event_head = fresh.event_head;
            } else {
                failures.push("authoritative evidence did not continue the incident window".into());
            }
        }
        Err(error) => failures.push(format!("authoritative evidence: {}", error.message)),
    }
    match aiec_guard::watchdog::generate_incident_report(&incident) {
        Ok(report) => incident.report = report,
        Err(error) => failures.push(format!("incident report: {error}")),
    }
    incident = record_stage(&state, incident, failures).await?;

    let complete = incident.network_cut_at.is_some()
        && incident.paused_at.is_some()
        && incident.snapshot_id.is_some()
        && !incident.report.is_empty();
    let incident = if complete && incident.completed_at.is_none() {
        record_stage(&state, incident, Vec::new()).await?
    } else {
        incident
    };

    // 5. notification is last and never blocks the incident from being durable.
    if incident.completed_at.is_some()
        && incident.notified_at.is_none()
        && let Some(notifier) = state.guard_notifier()
    {
        match notifier.notify(&incident).await {
            Ok(NotificationOutcome::Delivered) => {
                return persist(
                    &state,
                    GuardIncident {
                        notified_at: Some(Utc::now()),
                        ..incident.clone()
                    },
                )
                .await;
            }
            Ok(NotificationOutcome::Disabled) => {}
            Err(error) => tracing::warn!(%id, %error, "guard incident notification failed"),
        }
    }
    Ok(incident)
}

async fn existing_incident(state: &AppState, tenant: Uuid, id: Uuid) -> Option<GuardIncident> {
    state.repository().get_guard_incident(tenant, id).await.ok()
}

/// Folds one pass's stage outcomes into the durable incident.
///
/// A stage that has succeeded leaves no error behind: only stages that have
/// never succeeded contribute text, and that text is appended once per distinct
/// message so a repeated failure does not fill the incident.
async fn record_stage(
    state: &AppState,
    mut incident: GuardIncident,
    failures: Vec<String>,
) -> Result<GuardIncident, ApiFailure> {
    for failure in failures {
        if !incident.errors.contains(&failure) {
            incident.errors.push(failure);
        }
    }
    persist(state, incident).await
}

async fn persist(state: &AppState, incident: GuardIncident) -> Result<GuardIncident, ApiFailure> {
    let completed = incident.completed_at;
    let stored = state
        .repository()
        .put_guard_incident(incident)
        .await
        .map_err(ApiFailure::from)?;
    if completed.is_some() {
        return Ok(stored);
    }
    // Completion is derived here rather than trusted from the caller, so a
    // report that failed to generate cannot present itself as finished.
    let complete = stored.network_cut_at.is_some()
        && stored.paused_at.is_some()
        && stored.snapshot_id.is_some()
        && !stored.report.is_empty();
    if !complete {
        return Ok(stored);
    }
    state
        .repository()
        .put_guard_incident(GuardIncident {
            completed_at: Some(Utc::now()),
            ..stored
        })
        .await
        .map_err(ApiFailure::from)
}

/// Quarantines every guarded sandbox whose durable lifetime or budget is spent.
///
/// The reaper holds no timers of its own: what is expired is read from the same
/// durable rows a worker restart does not reset, so neither a worker restart nor
/// a control-plane restart hands a machine a fresh allowance.
pub async fn reap_guard_budgets(state: &AppState, now: chrono::DateTime<Utc>) {
    let Ok(expired) = state.repository().list_expired_guard_budgets(now).await else {
        tracing::warn!("durable Guard budget reaper could not read expired budgets");
        return;
    };
    for budget in expired.into_iter().take(64) {
        if budget.quarantined {
            continue;
        }
        let Ok(fence) =
            current_fence(state, budget.identity.tenant_id, budget.identity.sandbox_id).await
        else {
            tracing::warn!(
                sandbox_id = %budget.identity.sandbox_id,
                "expired guarded sandbox has no current owner; leaving it to lease reconciliation"
            );
            continue;
        };
        let Ok(sandbox) = state
            .repository()
            .get_sandbox(budget.identity.tenant_id, budget.identity.sandbox_id)
            .await
        else {
            continue;
        };
        let Ok(policy_hash) = guard_policy_hash(&sandbox) else {
            continue;
        };
        let rule = if budget.model_requests >= budget.max_model_requests
            || budget.bytes_in >= budget.max_bytes_in
            || budget.bytes_out >= budget.max_bytes_out
        {
            "durable_budget_exhausted"
        } else {
            "sandbox_lifetime_expired"
        };
        let request = QuarantineRequest {
            fence,
            policy_hash,
            rules: vec![aiec_guard::control::RuleTrigger {
                rule: rule.into(),
                first_event_sequence: None,
                evidence_references: vec!["durable-control-plane-budget".into()],
            }],
        };
        if let Err(error) = quarantine(
            state.clone(),
            budget.identity.tenant_id,
            budget.identity.sandbox_id,
            request,
        )
        .await
        {
            tracing::warn!(
                sandbox_id = %budget.identity.sandbox_id,
                reason = %error.message,
                "durable Guard reaper could not quarantine an expired sandbox"
            );
        }
    }
}

/// Bounded, secret-free watcher configuration an operator may attach.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardNotifierConfig {
    /// Webhook endpoint for incident notifications; absent means disabled.
    pub webhook_url: Option<String>,
    /// Delivery timeout in milliseconds.
    pub webhook_timeout_ms: u64,
    /// Whether plaintext HTTP to a numeric loopback address is permitted.
    #[serde(default)]
    pub local_loopback_http: bool,
}

impl GuardNotifierConfig {
    /// Builds the notifier, or an explicit disabled outcome.
    pub fn notifier(&self) -> Option<Arc<dyn Notifier>> {
        let raw = self.webhook_url.as_ref()?;
        let Ok(url) = aiec_guard::watchdog::parse_webhook_url(raw, self.local_loopback_http) else {
            tracing::warn!("configured Guard webhook URL is not usable");
            return None;
        };
        match aiec_guard::watchdog::WebhookNotifier::new(
            url,
            None,
            self.webhook_timeout_ms.clamp(500, 30_000),
            self.local_loopback_http,
        ) {
            Ok(notifier) => Some(Arc::new(notifier)),
            Err(error) => {
                tracing::warn!(%error, "configured Guard webhook notifier is unusable");
                None
            }
        }
    }
}

/// The tenant- and watchdog-facing Guard surface. Every route resolves the
/// tenant from the authenticated principal before reading anything, so a
/// foreign sandbox is a 404 rather than a filtered list.
pub fn routes() -> axum::Router<crate::AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/sandboxes/{id}/guard/telemetry", get(guard_telemetry))
        .route("/sandboxes/{id}/guard/heartbeat", post(guard_heartbeat))
        .route("/sandboxes/{id}/guard/quarantine", post(guard_quarantine))
        .route("/sandboxes/{id}/guard/incident", get(guard_incident))
}
