//! Executing a run: the workflow a caller actually asked for.
//!
//! This is the orchestration layer sitting above the sandbox API, not beside it.
//! Every machine it uses is obtained through the same `create_sandbox` path the
//! low-level API already uses, and every command runs through the same runtime,
//! so none of the isolation, fencing or tenant guarantees below that line are
//! re-implemented or weakened here.
//!
//! The shape is deliberately boring: reserve durable state, do slow I/O outside
//! any transaction, then settle the result. A run that dies halfway leaves a
//! record saying how far it got, which is the only thing that makes a failure
//! debuggable.

use std::collections::BTreeMap;
use std::time::Instant;

use aiec_core::RuntimeKind;
use aiec_core::network::NetworkPolicy;
use aiec_core::run::{
    CapabilityRequirements, CleanupReport, CommandOutcome, Placement, RepoSpec,
    ResourceRequirements, RetentionPolicy, Run, RunArtifactRef, RunAttempt, RunEvent, RunResults,
    RunSandbox, RunState, WorkloadSpec,
};
use aiec_core::runtime::{RuntimeCapabilities, RuntimeIsolation, SandboxRuntime};
use aiec_core::{ExecRequest, Sandbox, TenantId, WorkspaceSpec, new_id};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, CoreError};

/// A default retention window for a machine kept for debugging.
///
/// Bounded because a failure is not a licence to hold compute: the point of
/// keeping the machine is that somebody is about to look at it, and if nobody
/// is, the capacity is better spent on the next run.
const DEFAULT_RETENTION_SECONDS: i64 = 3600;

/// A run with no stated timeout still gets one, so a task cannot hold a machine
/// until the cluster notices.
const DEFAULT_TIMEOUT_SECONDS: u64 = 600;

/// Everything a caller supplies to start a run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunRequest {
    #[serde(default)]
    pub workload: WorkloadSpec,
    #[serde(default)]
    pub resources: ResourceRequirements,
    #[serde(default)]
    pub requirements: CapabilityRequirements,
    #[serde(default)]
    pub retention: RetentionPolicy,
    /// Reusing a key returns the run that already exists instead of executing
    /// the work twice.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub parent_run_id: Option<Uuid>,
    #[serde(default)]
    pub matrix_id: Option<Uuid>,
    /// Advanced use only. A caller stating requirements does not pick a runtime.
    #[serde(default)]
    pub requested_runtime: Option<String>,
    /// Where a repository clone lands, and whether there is one.
    #[serde(default)]
    pub retained_seconds: Option<i64>,
    /// How many fresh machines to try before giving up. One means no retry.
    ///
    /// A retry is a *fresh* machine, not a second run of the same one: the
    /// evidence that an attempt failed is usually about that machine, and
    /// re-running it would produce the same answer.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
}

/// One. A second attempt is not free: the run's wall-clock budget is sliced
/// across attempts, so asking for two halves the time a workload legitimately
/// has, and a task that needed its full stated timeout would time out, retry on
/// a second machine, time out again, and fail having paid for both. Placement
/// races get their own retry instead, because nothing has run yet when they
/// happen.
fn default_max_attempts() -> u32 {
    1
}

/// The run's own view of its progress, for a caller polling or streaming.
#[derive(Clone, Debug, Serialize)]
pub struct RunProgress {
    pub run: Run,
    pub phase: String,
    pub percent: u8,
}

/// Creates a run and drives it to a terminal state.
///
/// Returns the settled run. Failures inside the run are reported through the
/// run's own state and `failure_reason` rather than as an error, because "the
/// work failed" is an outcome a caller asked for, not a problem with the
/// request; an error is reserved for the run not being executable at all.
pub async fn submit_and_execute(
    state: &AppState,
    tenant: TenantId,
    request: RunRequest,
) -> Result<Run, CoreError> {
    request
        .workload
        .validate()
        .map_err(|error| CoreError::InvalidRequest(error.to_string()))?;

    let (run, is_new) = create_run(state, tenant, &request).await?;

    // An idempotent hit is an existing run, not an error, and definitely not a
    // second execution.
    //
    // Keyed on whether this call created the row rather than on the run being
    // finished. A client retrying while the first request is still in flight
    // gets that in-flight row back, and a terminal check waves it through: the
    // workload runs again on a second machine, both placements are billed, and
    // the two executions then fight over one row - the loser's terminal write
    // is rejected and its final `fail` overwrites the winner's outcome.
    if !is_new {
        return Ok(run);
    }

    // A run has a deadline, not just a command timeout.
    //
    // Without this a run whose worker became unreachable - a restart, a drained
    // node - never settles: it sits in `running` holding a sandbox that never
    // started, and the tenant's capacity stays consumed until that sandbox's own
    // TTL runs out. That is a cleanup failure, not a slow run, and it is
    // precisely what three abandoned runs on a live cluster turned out to be.
    let deadline = request
        .workload
        .timeout_seconds
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS)
        .saturating_add(PLACEMENT_GRACE_SECONDS);
    // A retry gets a fresh machine, and every attempt is recorded rather than
    // overwritten: "it failed twice then passed" and "it passed" are different
    // facts, and collapsing them is how a flaky agent looks reliable.
    // Capped, and not for politeness. A placement refusal returns in
    // milliseconds, so the per-attempt deadline never fires and an unbounded
    // `max_attempts` becomes a tight loop: every iteration is a scheduling
    // transaction that takes the tenant quota row `FOR UPDATE`, scans nodes,
    // inserts a row and rolls back, and every iteration writes an attempt row.
    // One request could drive thousands of those for the whole run budget.
    // Repeating a task is a legitimate ask; doing it thousands of times per
    // second is not, and the caller does not get to decide the difference.
    let max_attempts = request.max_attempts.clamp(1, MAX_RUN_ATTEMPTS);
    let store = state.repository();
    let mut last_error: Option<CoreError> = None;

    // One budget for the whole run, sliced across attempts.
    //
    // A per-attempt deadline would multiply: five attempts of a ten-minute task
    // is fifty minutes of wall time, and the run would stop being bounded -
    // which is the one property the deadline exists to provide. A run that wants
    // more wall time asks for a longer timeout, not more attempts.
    let run_budget = std::time::Duration::from_secs(deadline);
    // The whole budget is available to an attempt. Dividing it by `max_attempts`
    // is what made "ask for two attempts" a trap: each attempt got half the time
    // regardless of whether the first had actually used any, so a workload that
    // needed its stated timeout would be cut short and then repeated. Attempts
    // are for when a machine is at fault; the caller who wants more wall time
    // asks for a longer timeout.
    let per_attempt = run_budget;
    let started = std::time::Instant::now();
    // Placement attempts that never reached a machine. A lease resync or an
    // exhausted cluster is decided in milliseconds and costs no compute, so
    // these are retried inside the run's existing budget rather than by
    // splitting it - a second full attempt would be the expensive kind.
    let mut placement_retries = PLACEMENT_RETRIES;

    for attempt in 1..=max_attempts {
        // Never hand an attempt more than the run has left.
        let remaining = run_budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            last_error = Some(CoreError::Unavailable(format!(
                "the run exhausted its {deadline}s budget"
            )));
            break;
        }
        let slice = per_attempt.min(remaining);

        let outcome =
            tokio::time::timeout(slice, execute(state, tenant, run.clone(), request.clone())).await;

        let attempt_error = match outcome {
            Ok(Ok(finished)) => {
                let _ = store
                    .record_run_attempt(RunAttempt {
                        id: Uuid::now_v7(),
                        run_id: run.id,
                        attempt_number: attempt as i32,
                        sandbox_id: finished.retained_sandbox_id,
                        state: finished.state,
                        failure_reason: finished.failure_reason.clone(),
                        started_at: Utc::now(),
                        completed_at: Some(Utc::now()),
                    })
                    .await;
                return Ok(finished);
            }
            Ok(Err(error)) => error,
            Err(_elapsed) => {
                CoreError::Unavailable(format!("the run exceeded its {deadline}s deadline"))
            }
        };

        let retryable = is_retryable(&attempt_error);
        let _ = store
            .record_run_attempt(RunAttempt {
                id: Uuid::now_v7(),
                run_id: run.id,
                attempt_number: attempt as i32,
                sandbox_id: None,
                state: RunState::Failed,
                failure_reason: Some(attempt_error.to_string()),
                started_at: Utc::now(),
                completed_at: Some(Utc::now()),
            })
            .await;
        last_error = Some(attempt_error);

        // Free retry: the attempt placed nothing, so there is no work to repeat
        // and no bill to pay twice. Only for the case where the run never got a
        // machine - checked against what the run actually holds, not inferred
        // from the error type.
        let placed_nothing = store
            .list_run_sandboxes(tenant, run.id)
            .await
            .map(|linked| linked.is_empty())
            .unwrap_or(false);
        if retryable && placed_nothing && placement_retries > 0 {
            placement_retries -= 1;
            tracing::info!(
                run_id = %run.id,
                attempt,
                remaining = placement_retries,
                "retrying placement; no work has run yet"
            );
            let pause = std::time::Duration::from_millis(150 * (attempt as u64 + 1)).min(remaining);
            tokio::time::sleep(pause).await;
            continue;
        }

        if !retryable || attempt == max_attempts {
            break;
        }
        tracing::info!(
            run_id = %run.id,
            attempt,
            max_attempts,
            "retrying a run on a fresh machine"
        );
        // Backing off matters most for exactly the case that retries fastest.
        // A placement refusal is immediate, so without a pause the loop spins
        // at the speed of the database while the cluster is full - hammering
        // the same locks it is waiting on to be released. Bounded by the
        // remaining budget so the backoff can never extend a run past its
        // deadline.
        let backoff =
            std::time::Duration::from_millis((100u64 * 2u64.pow(attempt.min(6) - 1)).min(5_000))
                .min(remaining);
        tokio::time::sleep(backoff).await;
    }

    // Everything the attempts could not explain becomes the run's reason, and
    // the run is settled through the same path as any other failure.
    let mut run = run;
    let mut results = RunResults::default();
    let mut phases = BTreeMap::new();
    phases.insert("attempts".to_owned(), max_attempts as u64);
    fail(
        state,
        tenant,
        &mut run,
        last_error.map(|error| error.to_string()),
        &mut results,
        &mut phases,
    )
    .await?;
    state.repository().get_run(tenant, run.id).await
}

/// Ceiling on a single run's attempts, whatever the caller asks for.
const MAX_RUN_ATTEMPTS: u32 = 10;

/// How many times a run may retry *placement* when it never reached a machine.
///
/// Separate from `max_attempts` because it costs nothing: no sandbox is created,
/// no command runs, and the run's wall-clock budget is untouched. What it is
/// not is a second full attempt.
const PLACEMENT_RETRIES: u32 = 2;

/// Grace on top of the command timeout for placement and teardown.
const PLACEMENT_GRACE_SECONDS: u64 = 120;

/// Whether a failed attempt is worth repeating on a fresh machine.
fn is_retryable(error: &CoreError) -> bool {
    // The producer decides. A capacity refusal, a lease race and a database
    // deadlock all arrive as `Transient` because whoever raised them knows
    // whether asking again could work. Reading the message instead meant each
    // new transient failure was a new leak, discovered by a cluster running
    // dry rather than by a test.
    matches!(
        error,
        CoreError::Transient(_) | CoreError::Unavailable(_) | CoreError::Backend(_)
    )
}

/// Persists the run before any work starts.
/// Returns the run, and whether this call is the one that created it.
///
/// The second value is what makes an idempotency key mean anything. The store
/// resolves a duplicate key to the existing row, so "the run is not terminal"
/// does not imply "nobody is working on it" - a client retrying while the
/// first request is still in flight gets that row back, and treating it as
/// permission to start again runs the workload twice on two machines and bills
/// for both.
async fn create_run(
    state: &AppState,
    tenant: TenantId,
    request: &RunRequest,
) -> Result<(Run, bool), CoreError> {
    let now = Utc::now();
    let run = Run {
        id: new_id(),
        tenant_id: tenant,
        state: RunState::Queued,
        requested_at: now,
        queued_at: Some(now),
        started_at: None,
        completed_at: None,
        workload: request.workload.clone(),
        resources: request.resources.clone(),
        requirements: request.requirements.clone(),
        placement: Default::default(),
        results: Default::default(),
        failure_reason: None,
        retention: request.retention,
        retained_sandbox_id: None,
        retained_until: None,
        idempotency_key: request.idempotency_key.clone(),
        parent_run_id: request.parent_run_id,
        matrix_id: request.matrix_id,
    };
    let store = state.repository();
    let created = store.create_run(run.clone()).await?;

    let is_new = created.id == run.id;
    if is_new {
        event(
            state,
            &created,
            "run.created",
            serde_json::json!({
                "image": request.workload.image,
                "has_repo": request.workload.repo.is_some(),
                "retention": created.retention.as_str(),
                "requirements": request.requirements.reasons(),
            }),
        )
        .await;
    }
    Ok((created, is_new))
}

/// Records a run event. Detail is shapes and names; a value that could be a
/// credential never gets this far.
pub async fn event(state: &AppState, run: &Run, event_type: &str, detail: serde_json::Value) {
    let record = RunEvent {
        id: new_id(),
        run_id: run.id,
        sandbox_id: run.retained_sandbox_id,
        event_type: event_type.to_owned(),
        occurred_at: Utc::now(),
        detail,
    };
    // A history write must never fail the work it describes.
    let _ = state.repository().append_run_event(record).await;
}

/// Moves the run to the next state, tolerating a lost race.
async fn advance(state: &AppState, run: &mut Run, next: RunState) -> Result<(), CoreError> {
    let store = state.repository();
    match store
        .update_run_state(run.tenant_id, run.id, run.state, next)
        .await
    {
        Ok(updated) => {
            *run = updated;
            Ok(())
        }
        // A concurrent actor already moved it; adopt their state rather than
        // fighting, because a run has one truth and two writers is a bug
        // elsewhere, not a reason to overwrite.
        Err(CoreError::Conflict(_)) | Err(CoreError::NotFound(_)) => {
            if let Ok(current) = store.get_run(run.tenant_id, run.id).await {
                *run = current;
            }
            Ok(())
        }
        Err(other) => Err(other),
    }
}

/// Drives one run from queued to a terminal state.
async fn execute(
    state: &AppState,
    tenant: TenantId,
    run: Run,
    request: RunRequest,
) -> Result<Run, CoreError> {
    let store = state.repository();
    let mut run = run;
    let mut results = RunResults::default();
    let mut phases: BTreeMap<String, u64> = BTreeMap::new();

    advance(state, &mut run, RunState::Preparing).await?;

    // -- placement -----------------------------------------------------------
    let placement_started = Instant::now();
    let (sandbox, placement) = match acquire_sandbox(state, tenant, &run, &request).await {
        Ok(pair) => pair,
        Err((error, reasons)) => {
            run.placement.reasons = reasons;
            // Refusing to place is a real outcome, not an internal error: the
            // requirement could not be met and the run is not going to happen.
            fail(
                state,
                tenant,
                &mut run,
                Some(error.to_string()),
                &mut results,
                &mut phases,
            )
            .await?;
            return store.get_run(tenant, run.id).await;
        }
    };
    phases.insert(
        "placement".to_owned(),
        placement_started.elapsed().as_millis() as u64,
    );
    run.placement = placement.clone();
    // Written on its own rather than smuggled into the results: placement is
    // decided before any work runs, and a later write of results must not be
    // able to rewrite where the run went.
    if let Err(error) = store.set_run_placement(tenant, run.id, placement).await {
        tracing::warn!(run_id = %run.id, error = %error, "could not record a run's placement");
    }
    if let Err(error) = store
        .record_run_results(tenant, run.id, results.clone(), run.state)
        .await
    {
        tracing::warn!(run_id = %run.id, error = %error, "could not record a run's results");
    }

    let sandbox_id = sandbox.id;
    let _ = store
        .link_run_sandbox(RunSandbox {
            run_id: run.id,
            sandbox_id,
            role: "primary".to_owned(),
        })
        .await;
    event(
        state,
        &run,
        "sandbox.assigned",
        serde_json::json!({
            "sandbox_id": sandbox_id,
            "runtime": sandbox.runtime.as_str(),
            "worker": sandbox.node_id,
            "reasons": run.placement.reasons,
        }),
    )
    .await;

    // From here on the run owns a machine, so every exit releases it. Doing the
    // work in one place and cleaning up in another is what let eight `?` exits
    // after placement return without destroying anything, each leaking a machine
    // and each error being retryable - so a failed run burned one machine per
    // attempt and reported only that it failed.
    let attempt = post_placement(
        state,
        tenant,
        &mut run,
        &request,
        &sandbox,
        &mut results,
        &mut phases,
    )
    .await;
    if let Err(error) = &attempt {
        // Decided before cleanup, because retention is judged on it. A caller
        // that asked to keep a failed machine should not have it destroyed
        // because the failure arrived as an error rather than a non-zero exit.
        run.failure_reason = Some(error.to_string());
    }
    let cleanup_started = Instant::now();
    cleanup(state, tenant, &mut run, &[sandbox.id], &mut results).await;
    phases.insert(
        "cleanup".to_owned(),
        cleanup_started.elapsed().as_millis() as u64,
    );

    let succeeded = results.task.as_ref().is_some_and(|task| task.ok)
        && results.validations.iter().all(|validation| validation.ok);
    let reason = (!succeeded).then(|| {
        results
            .task
            .as_ref()
            .filter(|task| !task.ok)
            .map(|_| "the task did not succeed".to_owned())
            .unwrap_or_else(|| "a validation failed".to_owned())
    });

    match attempt {
        Ok(()) => {
            if succeeded {
                settle(state, tenant, &mut run, &mut results, &mut phases).await?;
            } else {
                fail(state, tenant, &mut run, reason, &mut results, &mut phases).await?;
            }
        }
        Err(error) => {
            // The machine is already released above; this records why the run
            // stopped, and re-raises so the attempt loop can decide about a
            // retry with the caller's budget.
            fail(
                state,
                tenant,
                &mut run,
                Some(error.to_string()),
                &mut results,
                &mut phases,
            )
            .await?;
            return Err(error);
        }
    }

    store.get_run(tenant, run.id).await
}

/// Everything a run does once it holds a machine.
///
/// Split out so `execute` can own the teardown. Returning an error from here
/// used to skip cleanup entirely, because the cleanup call sat at the bottom of
/// the same function and every `?` above it returned past it.
#[allow(clippy::too_many_arguments)]
async fn post_placement(
    state: &AppState,
    tenant: TenantId,
    run: &mut Run,
    request: &RunRequest,
    sandbox: &Sandbox,
    results: &mut RunResults,
    phases: &mut BTreeMap<String, u64>,
) -> Result<(), CoreError> {
    let runtime = state.runtime_for(sandbox)?;

    // -- setup ---------------------------------------------------------------
    if !request.workload.setup.is_empty() {
        advance(state, run, RunState::Running).await?;
        let phase_started = Instant::now();
        for command in &request.workload.setup {
            let outcome = run_command(state, tenant, run, sandbox, command, None).await?;
            let ok = outcome.ok;
            results.setup.push(outcome);
            if !ok {
                // An environment that never built makes every later measurement
                // meaningless, so stop here rather than report a task result
                // from a machine that is not the one asked for.
                phases.insert(
                    "setup".to_owned(),
                    phase_started.elapsed().as_millis() as u64,
                );
                return Err(CoreError::Backend("a setup command failed".into()));
            }
        }
    }

    if run.started_at.is_none() {
        advance(state, run, RunState::Running).await?;
    }

    // -- the task ------------------------------------------------------------
    let task_started = Instant::now();
    let task = run_command(
        state,
        tenant,
        run,
        sandbox,
        &request.workload.command,
        request.workload.timeout_seconds,
    )
    .await?;
    phases.insert("task".to_owned(), task_started.elapsed().as_millis() as u64);
    event(
        state,
        run,
        "task.finished",
        serde_json::json!({
            "exit_code": task.exit_code,
            "duration_ms": task.duration_ms,
            "truncated": task.truncated,
        }),
    )
    .await;
    results.task = Some(task);

    // -- validation ----------------------------------------------------------
    if !request.workload.validations.is_empty() {
        advance(state, run, RunState::Validating).await?;
        let validate_started = Instant::now();
        for command in &request.workload.validations {
            // Every validation runs even after one fails, so a caller can tell a
            // loud failure from a silent one.
            let outcome = run_command(state, tenant, run, sandbox, command, None).await?;
            results.validations.push(outcome);
        }
        phases.insert(
            "validation".to_owned(),
            validate_started.elapsed().as_millis() as u64,
        );
    }

    // -- collection ----------------------------------------------------------
    advance(state, run, RunState::Collecting).await?;
    let collect_started = Instant::now();
    if request.workload.git_evidence {
        let evidence =
            git_evidence(runtime.as_ref(), sandbox, request.workload.repo.as_ref()).await;
        results.commit = evidence.head;
        results.git_status = evidence.status;
        results.git_diff = evidence.diff;
        results.changed_files = evidence.changed_files;
    }
    let artifacts = collect_artifacts(state, tenant, run, sandbox, &request.workload).await;
    results.artifacts = artifacts;
    phases.insert(
        "collection".to_owned(),
        collect_started.elapsed().as_millis() as u64,
    );

    Ok(())
}

/// Marks a run failed and records why.
async fn fail(
    state: &AppState,
    tenant: TenantId,
    run: &mut Run,
    reason: Option<String>,
    results: &mut RunResults,
    phases: &mut BTreeMap<String, u64>,
) -> Result<(), CoreError> {
    event(
        state,
        run,
        "run.failed",
        serde_json::json!({ "reason": reason.clone().unwrap_or_default() }),
    )
    .await;
    run.failure_reason = reason;
    results.phase_ms = phases.clone();
    // Persisted rather than held in memory. Two separate omissions showed up as
    // a failed run with a blank reason: the outcome was only ever recorded on a
    // local copy that was then re-read from the store, and the reason column
    // had no writer at all.
    if let Err(error) = state
        .repository()
        .record_run_results(tenant, run.id, results.clone(), run.state)
        .await
    {
        tracing::warn!(run_id = %run.id, error = %error, "could not record a run's results");
    }
    if let Err(error) = state
        .repository()
        .set_run_failure(tenant, run.id, run.failure_reason.clone(), RunState::Failed)
        .await
    {
        tracing::warn!(run_id = %run.id, error = %error, "could not record why a run failed");
    }
    if let Ok(updated) = state.repository().get_run(tenant, run.id).await {
        *run = updated;
    }
    Ok(())
}

/// Writes the final results and settles the run in one statement.
///
/// `record_run_results` takes the terminal state and writes it with the results,
/// so the outcome and the timestamp that says when it happened cannot disagree.
/// Writing results and then transitioning separately would leave a window where
/// a run is finished but still looks like it is collecting.
async fn settle(
    state: &AppState,
    tenant: TenantId,
    run: &mut Run,
    results: &mut RunResults,
    phases: &mut BTreeMap<String, u64>,
) -> Result<(), CoreError> {
    results.phase_ms = phases.clone();
    let target = if run.failure_reason.is_some() {
        RunState::Failed
    } else {
        RunState::Succeeded
    };
    *run = state
        .repository()
        .record_run_results(tenant, run.id, results.clone(), target)
        .await?;
    event(
        state,
        run,
        "run.completed",
        serde_json::json!({ "state": target.as_str() }),
    )
    .await;
    Ok(())
}

/// Obtains a machine that satisfies the run's requirements.
///
/// Requirements, not a provider: the caller says what it needs and the existing
/// registry decides. The reason it decided is kept, because "the scheduler
/// refused it" is otherwise unanswerable.
/// Keeps a placement refusal distinguishable from a placement failure.
///
/// Everything used to arrive as `Unavailable`, which is the one kind the run
/// loop retries. So a tenant over quota with `max_attempts: 5` made five
/// placement attempts, each reserving and releasing scheduler state, for a
/// refusal that cannot succeed on the sixth - and the run then reported an
/// outage, when the cause was a limit the caller can act on.
fn placement_error(failure: &crate::ApiFailure) -> CoreError {
    match failure.code {
        "quota_exceeded" => CoreError::QuotaExceeded(failure.message.clone()),
        "invalid_request" | "unsupported" => CoreError::InvalidRequest(failure.message.clone()),
        // A scheduler that cannot answer right now, or a lease lost to a
        // resync, is worth another machine.
        _ => CoreError::Unavailable(failure.message.clone()),
    }
}

async fn acquire_sandbox(
    state: &AppState,
    tenant: TenantId,
    run: &Run,
    request: &RunRequest,
) -> Result<(Sandbox, Placement), (CoreError, Vec<String>)> {
    let reasons = run.requirements.reasons();
    let required = required_capabilities(&run.requirements);
    let minimum = if run.requirements.full_kernel_isolation {
        Some(RuntimeIsolation::MicroVm)
    } else {
        None
    };

    let requested = match &request.requested_runtime {
        Some(raw) => Some(parse_runtime(raw).map_err(|error| (error, reasons.clone()))?),
        None => None,
    };

    let (runtime_kind, reason) = match state.runtime_registry() {
        Some(registry) => {
            let selection = registry
                .select(requested, &required, minimum)
                .await
                .map_err(|error| (error, reasons.clone()))?;
            (selection.runtime, selection.reason)
        }
        None => {
            let kind = state.runtime_kind;
            (
                kind,
                format!("single runtime deployment: {}", kind.as_str()),
            )
        }
    };

    // The workload's network policy is the sandbox's; a run that asks for
    // isolation must not be handed a machine with a wider one than it expects.
    let network = if run.resources.network.is_enabled() {
        run.resources.network.clone()
    } else {
        NetworkPolicy::Disabled
    };

    let environment = match &request.workload.repo {
        Some(repo) => aiec_core::EnvironmentSpec {
            workspace: WorkspaceSpec::Git {
                repo: repo.url.clone(),
                reference: repo.reference.clone(),
                shallow: true,
            },
            ..Default::default()
        },
        None => aiec_core::EnvironmentSpec::default(),
    };

    let sandbox = Sandbox {
        id: new_id(),
        tenant_id: tenant,
        node_id: None,
        image_id: request
            .workload
            .image
            .clone()
            .unwrap_or_else(|| "aiec-coding:latest".to_owned()),
        state: aiec_core::SandboxState::Creating,
        runtime: runtime_kind,
        cpu: run.resources.cpu.max(1),
        memory_mb: run.resources.memory_mb.max(512),
        disk_mb: run.resources.disk_mb.max(1024),
        timeout_seconds: request
            .workload
            .timeout_seconds
            .unwrap_or(DEFAULT_TIMEOUT_SECONDS)
            .clamp(30, 86_400),
        network,
        environment,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        runtime_path: None,
    };

    // The shared path: schedule or create, then create, start, prepare the
    // workspace and lease. Going straight to the repository took the development
    // route, which takes no worker lease, so every command afterwards failed
    // with "active sandbox lease not found".
    let placed = crate::provision_sandbox(state, tenant, run.id, sandbox)
        .await
        .map_err(|failure| (placement_error(&failure), reasons.clone()))?;

    // The reasons are kept on the run: a refused placement is otherwise the
    // hardest thing to answer without re-running the scheduler by hand.
    let mut placement_reasons = reasons;
    placement_reasons.push(reason);
    if request.workload.repo.is_some() {
        placement_reasons.push("repository workspace required".to_owned());
    }
    let worker = placed.node_id.map(|id| id.to_string());
    Ok((
        placed,
        Placement {
            runtime: Some(runtime_kind.as_str().to_owned()),
            worker,
            reasons: placement_reasons,
        },
    ))
}

/// Maps requirements onto the capabilities the registry understands.
fn required_capabilities(requirements: &CapabilityRequirements) -> RuntimeCapabilities {
    RuntimeCapabilities {
        exec: true,
        files: true,
        full_kernel_isolation: requirements.full_kernel_isolation,
        coding_guest: requirements.coding_guest,
        network_policy: requirements.network_policy,
        vm_snapshot: requirements.workspace_snapshot,
        portable_workspace: requirements.portable_workspace,
        memory_resume: requirements.memory_resume,
        pty: requirements.pty,
        pause: requirements.pause,
        ..Default::default()
    }
}

fn parse_runtime(raw: &str) -> Result<RuntimeKind, CoreError> {
    match raw {
        "firecracker" => Ok(RuntimeKind::Firecracker),
        "docker" => Ok(RuntimeKind::Docker),
        "bwrap-dev" => Ok(RuntimeKind::BwrapDev),
        other => Err(CoreError::InvalidRequest(format!(
            "unknown runtime `{other}`"
        ))),
    }
}

/// Runs one command inside the machine and records how it went.
async fn run_command(
    state: &AppState,
    tenant: TenantId,
    run: &Run,
    sandbox: &Sandbox,
    command: &[String],
    timeout: Option<u64>,
) -> Result<CommandOutcome, CoreError> {
    if command.is_empty() {
        return Err(CoreError::InvalidRequest("a command is empty".into()));
    }
    event(
        state,
        run,
        "task.started",
        serde_json::json!({ "sandbox_id": sandbox.id, "argv_len": command.len() }),
    )
    .await;

    let runtime = state.runtime_for(sandbox)?;
    // Secrets are resolved here and injected into the guest, never stored on
    // the run, so they never reach the event log or a results document.
    let mut environment = state.secret_values(tenant, sandbox.id).await;
    environment.extend(run.workload.environment.clone());

    let result = runtime
        .exec(
            sandbox,
            ExecRequest {
                command: command.to_vec(),
                working_directory: run.workload.repo.as_ref().map(|repo| repo.path.clone()),
                environment,
                timeout_seconds: timeout.unwrap_or(600).clamp(1, 3600),
                stdin: None,
            },
        )
        .await?;

    Ok(CommandOutcome {
        command: command.to_vec(),
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
        duration_ms: result.duration_ms,
        truncated: false,
        // A clipped run is evidence of a truncated command, so it never counts
        // as a pass.
        ok: result.exit_code == 0 && !result.timed_out,
    })
}

/// Git evidence, collected inside the machine.
///
/// The control plane never shells out to git on the host; these run in the
/// sandbox like everything else.
struct GitEvidence {
    head: Option<String>,
    status: String,
    diff: String,
    changed_files: Vec<String>,
}

async fn git_evidence(
    runtime: &dyn SandboxRuntime,
    sandbox: &Sandbox,
    repo: Option<&RepoSpec>,
) -> GitEvidence {
    let Some(repo) = repo else {
        return GitEvidence {
            head: None,
            status: String::new(),
            diff: String::new(),
            changed_files: Vec::new(),
        };
    };
    let path = repo.path.replace('\'', "'\\''");
    let mut evidence = GitEvidence {
        head: None,
        status: String::new(),
        diff: String::new(),
        changed_files: Vec::new(),
    };
    for (key, script) in [
        ("head", format!("cd {path} && git rev-parse HEAD")),
        (
            "status",
            format!("cd {path} && git --no-pager status --porcelain=v1"),
        ),
        ("diff", format!("cd {path} && git --no-pager diff")),
    ] {
        let Ok(result) = runtime
            .exec(
                sandbox,
                ExecRequest {
                    command: vec!["/bin/sh".into(), "-lc".into(), script],
                    working_directory: None,
                    environment: BTreeMap::new(),
                    timeout_seconds: 60,
                    stdin: None,
                },
            )
            .await
        else {
            continue;
        };
        if result.exit_code != 0 {
            continue;
        }
        match key {
            "head" => evidence.head = Some(result.stdout.trim().to_owned()),
            "status" => {
                evidence.changed_files = result
                    .stdout
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| {
                        line.split_once(' ')
                            .map(|(_, rest)| rest.trim().to_owned())
                            .unwrap_or_else(|| line.trim().to_owned())
                    })
                    .collect()
            }
            _ => evidence.diff = result.stdout,
        }
    }
    evidence
}

/// Collects the requested artifacts into object storage.
async fn collect_artifacts(
    state: &AppState,
    tenant: TenantId,
    run: &Run,
    sandbox: &Sandbox,
    workload: &WorkloadSpec,
) -> Vec<RunArtifactRef> {
    if workload.artifacts.is_empty() {
        return Vec::new();
    }
    let Some(store) = state.artifact_store() else {
        return Vec::new();
    };
    let runtime = match state.runtime_for(sandbox) {
        Ok(runtime) => runtime,
        Err(_) => return Vec::new(),
    };
    let mut collected = Vec::new();
    for path in &workload.artifacts {
        let Ok(file) = runtime.get_file(sandbox, path).await else {
            continue;
        };
        let object_key = format!("tenants/{tenant}/runs/{}/{path}", run.id);
        let bytes = file.content_base64.as_bytes().to_vec();
        let size = bytes.len() as i64;
        if store.put(&object_key, &bytes).await.is_err() {
            continue;
        }
        collected.push(RunArtifactRef {
            name: path.clone(),
            object_key,
            size_bytes: size,
            checksum_sha256: None,
            content_type: Some("application/octet-stream".to_owned()),
        });
    }
    let _ = state
        .repository()
        .put_run_artifacts(tenant, run.id, collected.clone())
        .await;
    collected
}

/// Destroys the machine, or retains it under the policy when it failed.
///
/// A cleanup that fails is reported rather than logged and dropped: the caller
/// has to know a machine is still alive, or they will stop watching it and
/// assume its capacity is free.
/// Whether a failed destroy is worth another attempt.
///
/// Two things go wrong transiently here. A sandbox whose worker is resyncing
/// its lease refuses the first destroy and accepts the second. And the storage
/// layer can deadlock or fail to serialise, which clears as soon as the other
/// transaction commits. Treating either as terminal is how a finished run ends
/// up outliving the machine it was supposed to release.
fn is_transient_destroy_error(error: &CoreError) -> bool {
    matches!(error, CoreError::Transient(_))
}

/// Destroys a sandbox, retrying the lease race.
///
/// A sandbox whose lease is being resynced by its worker comes back "worker
/// lease generation or status changed", and the identical call a moment later
/// succeeds. Retrying is not a nicety here: this path is the watchdog's, and a
/// watchdog whose destroy fails once without retrying is a watchdog that does
/// not reclaim, which is the failure it exists to prevent.
/// Stops the machine, hands the capacity back, and only then forgets it.
///
/// The order is the point, and it is why this is one function rather than a
/// snippet copied into each caller. Deleting the row first is cheap and looks
/// finished, but the container or microVM keeps executing while the control
/// plane already reports the sandbox gone - which is exactly what happened. A
/// run's cleanup marked its sandbox destroyed and left seventeen containers
/// running on the worker, holding capacity that had already been credited back.
pub(crate) async fn tear_down_sandbox(
    state: &AppState,
    tenant: TenantId,
    sandbox_id: Uuid,
    sandbox: &Sandbox,
) -> Result<(), CoreError> {
    state.runtime_for(sandbox)?.destroy(sandbox).await?;
    // Hosted capacity is never leased from a worker, so there is no lease to
    // release; asking the scheduler would fail for a lease that never existed.
    if state.is_production() && sandbox.runtime != RuntimeKind::Hosted {
        state.scheduler().release(tenant, sandbox_id).await?;
    }
    state
        .repository()
        .delete_sandbox(tenant, sandbox_id)
        .await?;
    Ok(())
}

/// Gives up on a sandbox nothing is holding any more.
///
/// Different from `tear_down_sandbox` on purpose. A worker that has lost the
/// lease also refuses to stop the machine and reports "not found", but by the
/// time this is called the lease is gone by definition, so the worker has
/// already forgotten the machine and there is nothing left on that host to stop.
/// Tolerant on destroy, and deliberately does not ask the scheduler to release
/// anything - the capacity was returned when the lease expired, and asking
/// again is the error this function exists to survive.
///
/// A normal teardown is not tolerant, because tolerating a lost lease there
/// would flip the row to `destroyed` while a machine kept running, which is the
/// exact failure this whole path was rewritten to prevent.
pub(crate) async fn abandon_sandbox(
    state: &AppState,
    tenant: TenantId,
    sandbox_id: Uuid,
    sandbox: &Sandbox,
) -> Result<(), CoreError> {
    let stop = match state.runtime_for(sandbox) {
        Ok(runtime) => runtime.destroy(sandbox).await,
        Err(error) => Err(error),
    };
    match stop {
        Ok(()) | Err(CoreError::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    state
        .repository()
        .delete_sandbox(tenant, sandbox_id)
        .await?;
    Ok(())
}

async fn destroy_with_retry(
    state: &AppState,
    tenant: TenantId,
    sandbox_id: Uuid,
) -> Result<(), String> {
    const ATTEMPTS: usize = 4;
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        // Through the shared teardown, not straight to the row. Calling the
        // repository directly marked the sandbox destroyed while its container
        // or microVM kept running on the worker.
        let outcome = match state.repository().get_sandbox(tenant, sandbox_id).await {
            Ok(sandbox) => tear_down_sandbox(state, tenant, sandbox_id, &sandbox).await,
            // Already gone, which is the outcome the caller wanted.
            Err(CoreError::NotFound(_)) => return Ok(()),
            Err(error) => Err(error),
        };
        match outcome {
            Ok(()) => return Ok(()),
            Err(error) => {
                let message = error.to_string();
                // Worth another try: a lease the worker is resyncing, and a
                // database deadlock or serialization failure. A deadlock is the
                // textbook transient error - it is a conflict between two
                // transactions that resolves when one commits - and treating it
                // as terminal is exactly how a finished run ends up leaking the
                // machine it was supposed to release.
                let transient = is_transient_destroy_error(&error);
                last = message;
                if !transient || attempt + 1 == ATTEMPTS {
                    return Err(last);
                }
                tokio::time::sleep(std::time::Duration::from_millis(400 * (attempt as u64 + 1)))
                    .await;
            }
        }
    }
    Err(last)
}

/// Reclaims every machine a run holds, on every exit path.
///
/// One function, deliberately. A cleanup path that only some exits take is how a
/// machine survives its run: the timeout path once had its own, and it ignored
/// retention, so a `keep_on_failure` run that timed out had its machine destroyed
/// anyway.
///
/// Retention is honoured first, because a run that failed is exactly the one a
/// caller asked to be able to open.
async fn cleanup(
    state: &AppState,
    tenant: TenantId,
    run: &mut Run,
    sandbox_ids: &[Uuid],
    results: &mut RunResults,
) {
    if sandbox_ids.is_empty() {
        return;
    }
    let succeeded = run.failure_reason.is_none();
    if run.retention.should_retain(succeeded) {
        let until = Utc::now() + Duration::seconds(DEFAULT_RETENTION_SECONDS);
        let kept = sandbox_ids.first().copied();
        // Persisted, not just set on the in-memory run. `record_run_results`
        // writes only results and state, so before this the fields stayed null
        // in the database: the sweeper selects on `retained_until` and never saw
        // the run, so a kept machine was never reclaimed, and the response
        // carried `retained_sandbox_id: null`, telling the caller there was
        // nothing to open.
        if let Some(kept) = kept {
            match state
                .repository()
                .retain_run_sandbox(tenant, run.id, kept, until)
                .await
            {
                Ok(updated) => {
                    run.retained_sandbox_id = updated.retained_sandbox_id;
                    run.retained_until = updated.retained_until;
                }
                Err(error) => {
                    // The machine is held on the caller's behalf and nothing
                    // will find it later, so say so rather than losing it.
                    tracing::warn!(
                        run_id = %run.id,
                        sandbox_id = %kept,
                        error = %error,
                        "could not record a retained sandbox, so nothing will reclaim it"
                    );
                    results.cleanup_failed = Some(CleanupReport {
                        sandbox_id: kept,
                        error: format!("could not record the retained sandbox: {error}"),
                    });
                }
            }
        }
        event(
            state,
            run,
            "sandbox.retained",
            serde_json::json!({ "sandbox_ids": sandbox_ids, "until": until }),
        )
        .await;
        return;
    }

    for sandbox_id in sandbox_ids {
        match destroy_with_retry(state, tenant, *sandbox_id).await {
            Ok(()) => {
                event(
                    state,
                    run,
                    "sandbox.destroyed",
                    serde_json::json!({ "sandbox_id": sandbox_id }),
                )
                .await;
            }
            Err(error) => {
                tracing::warn!(
                    run_id = %run.id,
                    sandbox_id = %sandbox_id,
                    error = %error,
                    "could not destroy a run's sandbox"
                );
                results.cleanup_failed = Some(CleanupReport {
                    sandbox_id: *sandbox_id,
                    error: error.to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod retry_policy {
    use super::{is_retryable, is_transient_destroy_error};
    use aiec_core::CoreError;

    /// A finished run whose destroy hit a database deadlock kept its machine
    /// A finished run whose destroy hit a database deadlock kept its machine
    /// alive, because the retry treated a deadlock as terminal. A deadlock is
    /// the textbook transient failure: it clears when the other transaction
    /// commits, so refusing to retry is what leaks.
    #[test]
    fn a_database_deadlock_is_worth_retrying() {
        let deadlock = CoreError::Transient("transient database failure: deadlock detected".into());
        // The run-level policy and the destroy path must agree that this is
        // transient, or a finished run outlives the machine it owned.
        assert!(is_retryable(&deadlock));
        assert!(is_transient_destroy_error(&deadlock));

        for transient in [
            CoreError::Transient("stale sandbox lease generation".into()),
            CoreError::Transient("no schedulable worker has capacity".into()),
            CoreError::Transient("transient database failure: serialization failure".into()),
        ] {
            assert!(
                is_transient_destroy_error(&transient),
                "{transient} must be retried"
            );
        }
    }

    /// The set is closed. Anything not explicitly transient is fatal, so a new
    /// kind of failure cannot be quietly added to the retry list by whoever
    /// happens to be reading a log that day.
    #[test]
    fn everything_else_is_fatal_on_destroy() {
        for permanent in [
            CoreError::NotFound("no such sandbox".into()),
            CoreError::Conflict("sandbox is not running".into()),
            CoreError::QuotaExceeded("disk quota exceeded".into()),
            CoreError::InvalidRequest("bad id".into()),
        ] {
            assert!(
                !is_transient_destroy_error(&permanent),
                "{permanent} must not be retried"
            );
        }
    }

    #[test]
    fn infrastructure_failures_are_worth_another_machine() {
        assert!(is_retryable(&CoreError::Unavailable("worker gone".into())));
        assert!(is_retryable(&CoreError::Backend("transport".into())));
        assert!(is_retryable(&CoreError::Transient(
            "no schedulable worker has capacity".into()
        )));
    }

    #[test]
    fn a_refusal_or_a_bad_request_is_not() {
        // These fail identically every time; retrying only delays the answer.
        assert!(!is_retryable(&CoreError::Conflict(
            "stale lease generation".into()
        )));
        assert!(!is_retryable(&CoreError::InvalidRequest(
            "no command".into()
        )));
        assert!(!is_retryable(&CoreError::QuotaExceeded(
            "too many sandboxes".into()
        )));
        assert!(!is_retryable(&CoreError::Unsupported("nope".into())));
    }
}
