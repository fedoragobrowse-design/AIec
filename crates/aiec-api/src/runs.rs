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
    CapabilityRequirements, CleanupReport, CommandOutcome, MAX_SETUP_COMMAND_PREVIEW_BYTES,
    MAX_SETUP_PREVIEW_BYTES, MAX_TASK_PREVIEW_BYTES, MAX_VALIDATION_COMMAND_PREVIEW_BYTES,
    MAX_VALIDATION_PREVIEW_BYTES, MatrixCellIdentity, Placement, PreviewBudget, RepoSpec,
    ResourceRequirements, RetentionPolicy, Run, RunArtifactRef, RunAttempt, RunEvent, RunResults,
    RunState, WorkloadSpec, bound_git_evidence,
};
use aiec_core::runtime::{FileChunk, RuntimeCapabilities, RuntimeIsolation, SandboxRuntime};
use aiec_core::storage::ArtifactStore;
use aiec_core::{ExecRequest, Sandbox, TenantId, WorkspaceSpec, new_id};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::run_secrets::SecretRedactor;
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// Which cell of a matrix this request is, when it is one.
    ///
    /// Carried onto the Run at build time so the axis values are stored with
    /// the run's own insert rather than attached to it afterwards: a matrix
    /// whose labels are written only once every cell has finished loses every
    /// label belonging to a cell that failed, or to a submission whose
    /// response was lost.
    #[serde(default)]
    pub matrix_cell: Option<MatrixCellIdentity>,
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

/// Retry attempts share the run's deadline; the default does not repeat work.
fn default_max_attempts() -> u32 {
    1
}

impl Default for RunRequest {
    fn default() -> Self {
        Self {
            workload: Default::default(),
            resources: Default::default(),
            requirements: Default::default(),
            retention: Default::default(),
            idempotency_key: None,
            parent_run_id: None,
            matrix_id: None,
            matrix_cell: None,
            requested_runtime: None,
            retained_seconds: None,
            max_attempts: default_max_attempts(),
        }
    }
}

/// The run's own view of its progress, for a caller polling or streaming.
#[derive(Clone, Debug, Serialize)]
pub struct RunProgress {
    pub run: Run,
    pub phase: String,
    pub percent: u8,
}

/// Validates a request, reserves the run, then lets the queue execute it.
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
    validate(state, tenant, &request).await?;
    // A durable store admits a Run and its queue row in one transaction, so
    // the Run must not be inserted here first: a second insert of the same id
    // is a unique violation, and a Run admitted but never queued would be
    // invisible to the dispatcher. The direct path below still reserves it
    // itself, because it executes in this request and owns the write.
    if state.repository().supports_run_queue() {
        let proposed = build_run(tenant, &request);
        return crate::run_queue::enqueue_and_wait(
            state,
            proposed,
            request,
            state.run_queue_limits(),
        )
        .await;
    }
    let (run, is_new) = create_run(state, tenant, &request).await?;
    if !is_new {
        return Ok(run);
    }
    execute_created(state, tenant, run, request).await
}

/// Rejects a request that could never be executed, before anything is reserved.
///
/// The secret references are resolved here rather than at the first exec, even
/// though the values are handed out again per command. A name the tenant does
/// not hold, a name the store has no file for, or a name the workload also
/// spells out as a literal are all knowable now, and finding out after a
/// machine has been placed means the caller pays for a sandbox to be told their
/// own request was malformed. The resolution here is dropped immediately; the
/// values that reach the guest are the ones resolved again at exec time.
async fn validate(
    state: &AppState,
    tenant: TenantId,
    request: &RunRequest,
) -> Result<(), CoreError> {
    request
        .workload
        .validate()
        .map_err(|error| CoreError::InvalidRequest(error.to_string()))?;
    request
        .resources
        .validate()
        .map_err(|error| CoreError::InvalidRequest(error.to_string()))?;
    if request
        .retained_seconds
        .is_some_and(|seconds| !(1..=86_400).contains(&seconds))
    {
        return Err(CoreError::InvalidRequest(
            "retained_seconds must be between 1 and 86400".into(),
        ));
    }
    if !(1..=MAX_RUN_ATTEMPTS).contains(&request.max_attempts) {
        return Err(CoreError::InvalidRequest(format!(
            "max_attempts must be between 1 and {MAX_RUN_ATTEMPTS}"
        )));
    }
    let resolved = state
        .run_secrets()
        .resolve(tenant, &request.workload.secrets)
        .await?;
    resolved.merge(&request.workload.environment)?;
    Ok(())
}

/// Drives an already-reserved run to a terminal state.
///
/// Takes ownership of execution rather than admitting it, which is why it is
/// separated from the queue: the dispatcher calls this for a claimed run, and
/// the direct path calls it for a run nobody queued. A run that reached a
/// terminal state before this was called is returned untouched, so a stale
/// future can never resurrect settled work.
pub(crate) async fn execute_created(
    state: &AppState,
    tenant: TenantId,
    mut run: Run,
    request: RunRequest,
) -> Result<Run, CoreError> {
    let store = state.repository();
    if run.state.is_terminal() {
        return Ok(run);
    }
    let budget = std::time::Duration::from_secs(
        request
            .workload
            .timeout_seconds
            .unwrap_or(DEFAULT_TIMEOUT_SECONDS)
            .saturating_add(PLACEMENT_GRACE_SECONDS),
    );
    let started = Instant::now();
    let mut last_error = None;
    for number in 1..=request.max_attempts {
        run = store.get_run(tenant, run.id).await?;
        if run.state.is_terminal() {
            return Ok(run);
        }
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            last_error = Some(CoreError::Unavailable("run deadline exhausted".into()));
            break;
        }
        let mut evidence = RunAttempt {
            id: new_id(),
            run_id: run.id,
            attempt_number: number as i32,
            sandbox_id: None,
            state: RunState::Running,
            failure_reason: None,
            started_at: Utc::now(),
            completed_at: None,
            placement: Placement::default(),
            results: RunResults::default(),
        };
        // Scheduling links this existing attempt before slow provisioning starts.
        store.record_run_attempt(evidence.clone()).await?;
        let result = tokio::time::timeout(
            remaining,
            execute(
                state,
                tenant,
                run,
                &request,
                evidence.id,
                number == request.max_attempts,
            ),
        )
        .await;
        let (mut current, error, succeeded, expired) = match result {
            Ok(Ok(outcome)) => (outcome.run, None, outcome.succeeded, false),
            Ok(Err(error)) => (
                store.get_run(tenant, evidence.run_id).await?,
                Some(error),
                false,
                false,
            ),
            Err(_) => (
                store.get_run(tenant, evidence.run_id).await?,
                Some(CoreError::Unavailable(
                    "run execution deadline exceeded".into(),
                )),
                false,
                true,
            ),
        };
        // Outside the timed future: timeout/cancellation cannot skip reclamation.
        // Also covers partial provisioning and failed teardown before another try.
        if error.is_some() || current.state == RunState::Cancelled {
            let links = store.list_run_sandboxes(tenant, current.id).await?;
            let ids: Vec<_> = links
                .iter()
                .filter(|link| {
                    expired
                        || current.state == RunState::Cancelled
                        || current.retained_sandbox_id != Some(link.sandbox_id)
                })
                .map(|link| link.sandbox_id)
                .collect();
            let mut results = std::mem::take(&mut current.results);
            cleanup(state, tenant, &mut current, &ids, &mut results, None).await;
            current = store
                .record_run_results(tenant, current.id, results, current.state)
                .await?;
        }
        evidence.state = if current.state == RunState::Cancelled {
            RunState::Cancelled
        } else if succeeded {
            RunState::Succeeded
        } else {
            RunState::Failed
        };
        evidence.failure_reason = error
            .as_ref()
            .map(ToString::to_string)
            .or_else(|| current.failure_reason.clone());
        evidence.completed_at = Some(Utc::now());
        evidence.placement = current.placement.clone();
        evidence.results = current.results.clone();
        store.complete_run_attempt(tenant, evidence).await?;
        if current.state == RunState::Cancelled {
            return Ok(current);
        }
        if error.is_none() {
            let mut results = std::mem::take(&mut current.results);
            let mut phases = results.phase_ms.clone();
            if succeeded {
                settle(state, tenant, &mut current, &mut results, &mut phases).await?;
            } else {
                let reason = current.failure_reason.take();
                fail(
                    state,
                    tenant,
                    &mut current,
                    reason,
                    &mut results,
                    &mut phases,
                )
                .await?;
            }
            return store.get_run(tenant, current.id).await;
        }
        let retryable = error.as_ref().is_some_and(is_retryable)
            && !expired
            && current.results.cleanup_failed.is_none();
        last_error = error;
        run = current;
        if !retryable || number == request.max_attempts {
            break;
        }
        let pause = std::time::Duration::from_millis(100 * (1u64 << number.min(6)))
            .min(budget.saturating_sub(started.elapsed()));
        tokio::time::sleep(pause).await;
    }
    let mut results = std::mem::take(&mut run.results);
    let mut phases = results.phase_ms.clone();
    fail(
        state,
        tenant,
        &mut run,
        last_error.map(|error| error.to_string()),
        &mut results,
        &mut phases,
    )
    .await?;
    store.get_run(tenant, run.id).await
}

/// The image a Run boots when it named none.
///
/// Per runtime, because the names are not interchangeable: `aiec-coding:latest`
/// is the reference the Firecracker guest image is admitted and signed under,
/// and no container registry has ever heard of it.
pub(crate) fn default_image_for(runtime: RuntimeKind) -> &'static str {
    match runtime {
        // The guest image, admitted and signed under this reference.
        RuntimeKind::Firecracker => "aiec-coding:latest",
        // The development container and a hosted provider both boot a normal
        // container image, and the guest is built from this same Debian base, so
        // a Run moved between runtimes lands on a comparable userland.
        RuntimeKind::Docker | RuntimeKind::BwrapDev | RuntimeKind::Hosted => "debian:bookworm-slim",
    }
}

/// Ceiling on a single run's attempts, whatever the caller asks for.
const MAX_RUN_ATTEMPTS: u32 = 10;

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
    let run = build_run(tenant, request);
    let store = state.repository();
    let created = store.create_run(run.clone()).await?;

    let is_new = created.id == run.id;
    if is_new {
        announce_created(state, &created, request).await;
    }
    Ok((created, is_new))
}

/// The Run a request asks for, before any store has seen it.
///
/// Building and persisting are separate steps because the durable queue commits
/// the Run and its queue row together, while the direct path writes the Run on
/// its own. Both start from exactly this value, so a queued Run and an
/// immediately-executed one are the same object.
fn build_run(tenant: TenantId, request: &RunRequest) -> Run {
    let now = Utc::now();
    Run {
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
        matrix_cell: request.matrix_cell.clone(),
    }
}

/// Records that a Run exists, with the shape of the work and nothing else.
pub(crate) async fn announce_created(state: &AppState, created: &Run, request: &RunRequest) {
    event(
        state,
        created,
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
            *run = store.get_run(run.tenant_id, run.id).await?;
            if run.state == next {
                Ok(())
            } else {
                Err(CoreError::Conflict(
                    "run progression stopped because its durable state changed".to_owned(),
                ))
            }
        }
        Err(other) => Err(other),
    }
}

struct AttemptOutcome {
    run: Run,
    succeeded: bool,
}
/// Drives one run from queued to a terminal state.
async fn execute(
    state: &AppState,
    tenant: TenantId,
    run: Run,
    request: &RunRequest,
    attempt_id: Uuid,
    final_attempt: bool,
) -> Result<AttemptOutcome, CoreError> {
    let store = state.repository();
    let mut run = run;
    let mut results = RunResults::default();
    let mut phases: BTreeMap<String, u64> = BTreeMap::new();

    advance(state, &mut run, RunState::Preparing).await?;

    // -- placement -----------------------------------------------------------
    let placement_started = Instant::now();
    let (sandbox, placement, timings) =
        match acquire_sandbox(state, tenant, &run, request, attempt_id).await {
            Ok(pair) => pair,
            Err((error, reasons)) => {
                run.placement.reasons = reasons;
                store
                    .set_run_placement(tenant, run.id, run.placement)
                    .await?;
                return Err(error);
            }
        };
    phases.insert(
        "placement".to_owned(),
        placement_started.elapsed().as_millis() as u64,
    );
    for (phase, duration) in [
        ("placement.scheduler", timings.scheduler_ms),
        ("placement.allocation", timings.allocation_ms),
        ("placement.boot", timings.boot_ms),
        ("placement.workspace", timings.workspace_ms),
    ] {
        phases.insert(phase.to_owned(), duration);
    }
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

    event(
        state,
        &run,
        "sandbox.assigned",
        serde_json::json!({
            "sandbox_id": sandbox.id,
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
        request,
        &sandbox,
        &mut results,
        &mut phases,
    )
    .await;
    let succeeded = attempt.is_ok()
        && results.task.as_ref().is_some_and(|task| task.ok)
        && results.validations.iter().all(|validation| validation.ok);
    // Retention must see task and validation failures, not just transport errors.
    run.failure_reason = match &attempt {
        Err(error) => Some(error.to_string()),
        Ok(()) if !succeeded => Some(
            if results.task.as_ref().is_some_and(|task| !task.ok) {
                "the task did not succeed"
            } else {
                "a validation failed"
            }
            .to_owned(),
        ),
        Ok(()) => None,
    };
    let cleanup_started = Instant::now();
    let allow_retention = results.setup.iter().any(|command| !command.ok)
        || attempt
            .as_ref()
            .err()
            .is_none_or(|error| !is_retryable(error) || final_attempt);
    cleanup(
        state,
        tenant,
        &mut run,
        &[sandbox.id],
        &mut results,
        allow_retention.then_some(
            request
                .retained_seconds
                .unwrap_or(DEFAULT_RETENTION_SECONDS),
        ),
    )
    .await;
    phases.insert(
        "cleanup".to_owned(),
        cleanup_started.elapsed().as_millis() as u64,
    );
    results.phase_ms = phases;
    let reason = run.failure_reason.take();
    run = store
        .record_run_results(tenant, run.id, results, run.state)
        .await?;
    run.failure_reason = reason;
    // Cleanup above ran on every path that reached a machine, so every outcome
    // here has already released it - including the error arm, which propagates
    // for retry classification rather than because anything is still held.
    match attempt {
        Ok(()) => Ok(AttemptOutcome { run, succeeded }),
        Err(_) if run.state == RunState::Cancelled => Ok(AttemptOutcome {
            run,
            succeeded: false,
        }),
        Err(error) if run.results.setup.iter().any(|command| !command.ok) => {
            let _ = error;
            Ok(AttemptOutcome {
                run,
                succeeded: false,
            })
        }
        Err(error) => Err(error),
    }
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

    // Every phase's stored output is bounded as it is produced, not on the way
    // into the database. The machine already clips at a megabyte per stream,
    // which bounds one command; what it does not bound is the run document,
    // which is the sum of every phase and is read back by every list, poll and
    // matrix aggregation in the control plane.
    //
    // -- setup ---------------------------------------------------------------
    if !request.workload.setup.is_empty() {
        advance(state, run, RunState::Running).await?;
        let phase_started = Instant::now();
        let mut setup_budget = PreviewBudget::new(MAX_SETUP_PREVIEW_BYTES);
        for command in &request.workload.setup {
            let mut outcome = run_command(state, tenant, run, sandbox, command, None).await?;
            // Clipped here rather than on the way into the database, so the
            // large copy is never written and then thrown away. `ok` is
            // untouched: a step whose output did not fit is still a step that
            // ran, and reporting it otherwise would turn a working setup into a
            // failure the moment the install log grew past a kilobyte.
            setup_budget.clip(&mut outcome, MAX_SETUP_COMMAND_PREVIEW_BYTES);
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
        phases.insert(
            "setup".to_owned(),
            phase_started.elapsed().as_millis() as u64,
        );
    }

    if run.state == RunState::Preparing {
        advance(state, run, RunState::Running).await?;
    }

    // -- the task ------------------------------------------------------------
    let task_started = Instant::now();
    let mut task = run_command(
        state,
        tenant,
        run,
        sandbox,
        &request.workload.command,
        request.workload.timeout_seconds,
    )
    .await?;
    phases.insert("task".to_owned(), task_started.elapsed().as_millis() as u64);
    // The task gets the bulk of the budget rather than a share of a per-command
    // one: it is the output the caller came for, and the one part of a run they
    // cannot recompute by running the sandbox again.
    PreviewBudget::new(MAX_TASK_PREVIEW_BYTES).clip(&mut task, MAX_TASK_PREVIEW_BYTES);
    event(
        state,
        run,
        "task.finished",
        serde_json::json!({
            "exit_code": task.exit_code,
            "duration_ms": task.duration_ms,
            "truncated": task.truncated,
            // Reported in the event, not only in the stored document: a caller
            // streaming a run's progress reads events, and being handed a
            // clipped preview with no mention of it is how a partial log gets
            // quoted as the whole one.
            "output_preview_truncated": task.output_preview_truncated,
            "output_preview_bytes": task.stdout.len() + task.stderr.len(),
        }),
    )
    .await;
    results.task = Some(task);

    // -- validation ----------------------------------------------------------
    if !request.workload.validations.is_empty() {
        advance(state, run, RunState::Validating).await?;
        let validate_started = Instant::now();
        let mut budget = PreviewBudget::new(MAX_VALIDATION_PREVIEW_BYTES);
        for command in &request.workload.validations {
            // Every validation runs even after one fails, so a caller can tell a
            // loud failure from a silent one.
            let mut outcome = run_command(state, tenant, run, sandbox, command, None).await?;
            budget.clip(&mut outcome, MAX_VALIDATION_COMMAND_PREVIEW_BYTES);
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
        // Resolved once for the collection phase, and the redactor is built
        // from that resolution rather than from a re-read: the task wrote these
        // files with the values it was given, so the values to scrub with are
        // the ones it was given, not whatever the file says a moment later.
        let redactor = state
            .run_secrets()
            .resolve(tenant, &request.workload.secrets)
            .await?
            .redactor();
        let evidence = git_evidence(
            runtime.as_ref(),
            sandbox,
            request.workload.repo.as_ref(),
            &redactor,
        )
        .await;
        results.commit = evidence.head;
        let bounded = bound_git_evidence(&evidence.status, &evidence.diff, &evidence.changed_files);
        results.git_status = bounded.status;
        results.git_diff = bounded.diff;
        results.changed_files = bounded.changed_files;
        // One flag for all three, because they share one budget: telling a
        // caller which of three fields was cut, when any of them being cut is
        // the fact that matters, is three states nobody acts on differently.
        results.git_evidence_truncated = bounded.truncated;
    }
    // The phase is recorded whether or not collection worked, and the failure is
    // raised afterwards: a failed collection that also lost its timing tells a
    // caller debugging a slow run less than it could have. Artifacts collected
    // before the failure are kept in the run document, so it and the artifact
    // listing agree about what was stored.
    let collected = collect_artifacts(state, tenant, run, sandbox, &request.workload).await;
    phases.insert(
        "collection".to_owned(),
        collect_started.elapsed().as_millis() as u64,
    );
    results.artifacts = match collected {
        Ok(artifacts) => artifacts,
        Err(failure) => {
            results.artifacts = failure.collected;
            return Err(failure.error);
        }
    };

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
        "runtime_not_permitted" => CoreError::Forbidden(failure.message.clone()),
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
    attempt_id: Uuid,
) -> Result<(Sandbox, Placement, crate::ProvisionTimings), (CoreError, Vec<String>)> {
    let reasons = run.requirements.reasons();
    let required = required_capabilities(&run.requirements);
    // A Guard selection is enforced by the runtime that owns the guest's
    // network attachment, and there is no weaker fallback: asking for Guard and
    // landing on a runtime that cannot install the rules would be a sandbox
    // that believes it is governed and is not. Demand the isolation level
    // rather than discovering the mismatch at boot.
    let minimum = if run.requirements.full_kernel_isolation || run.resources.guard.is_some() {
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
            let actual = state.runtime().capabilities();
            if requested.is_some_and(|requested| requested != kind)
                || !aiec_core::runtime::capabilities_satisfy(&actual, &required, minimum)
            {
                return Err((
                    CoreError::Unsupported(
                        "configured runtime does not satisfy requested runtime or capabilities"
                            .to_owned(),
                    ),
                    reasons,
                ));
            }
            (
                kind,
                format!("single runtime deployment: {}", kind.as_str()),
            )
        }
    };

    // The workload's network policy is the sandbox's; a run that asks for
    // isolation must not be handed a machine with a wider one than it expects.
    //
    // A Guard selection replaces that policy rather than sitting beside it. Two
    // descriptions of the same egress would be two ways to reach the internet,
    // and the wider one would be the one that applied.
    let mut environment = match &request.workload.repo {
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
    let network = if run.resources.guard.is_some() {
        // Guard owns the attachment and decides what may be reached; the
        // ordinary policy would be an ungoverned second path.
        environment.guard = run.resources.guard.clone();
        NetworkPolicy::Disabled
    } else if run.resources.network.is_enabled() {
        run.resources.network.clone()
    } else {
        NetworkPolicy::Disabled
    };

    let sandbox = Sandbox {
        id: new_id(),
        tenant_id: tenant,
        node_id: None,
        // The default image depends on the runtime it will be booted on.
        // `aiec-coding:latest` names the Firecracker guest image and is not a
        // container image at all, so a Run that named no image and was placed on
        // a container runtime asked the registry for an image that does not
        // exist there - and the failure arrived as an opaque pull error long
        // after the Run had been admitted. The container default is the same
        // Debian base the guest image is built from, so a Run that is moved
        // between runtimes lands on a comparable userland.
        image_id: request
            .workload
            .image
            .clone()
            .unwrap_or_else(|| default_image_for(runtime_kind).to_owned()),
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
    let placed = crate::provision_sandbox(
        state,
        tenant,
        attempt_id,
        sandbox,
        required,
        Some(run.id),
        !request.workload.secrets.is_empty() || !request.workload.environment.is_empty(),
    )
    .await
    .map_err(|failure| (placement_error(&failure), reasons.clone()))?;

    // The reasons are kept on the run: a refused placement is otherwise the
    // hardest thing to answer without re-running the scheduler by hand.
    let mut placement_reasons = reasons;
    placement_reasons.push(reason);
    if request.workload.repo.is_some() {
        placement_reasons.push("repository workspace required".to_owned());
    }
    let worker = placed.sandbox.node_id.map(|id| id.to_string());
    Ok((
        placed.sandbox,
        Placement {
            runtime: Some(runtime_kind.as_str().to_owned()),
            worker,
            reasons: placement_reasons,
        },
        placed.timings,
    ))
}

/// Maps requirements onto the capabilities the registry understands.
pub(crate) fn required_capabilities(requirements: &CapabilityRequirements) -> RuntimeCapabilities {
    RuntimeCapabilities {
        // Only an explicitly requested isolation class is part of the demand.
        // JSON containment is exact-match, so naming a class nobody asked for
        // refuses every worker advertising a different one - including a
        // stronger one. `Process` is the "unspecified" default and is omitted
        // for the same reason.
        isolation: match requirements.full_kernel_isolation {
            true => RuntimeIsolation::MicroVm,
            false => RuntimeIsolation::Process,
        },
        exec: true,
        files: true,
        full_kernel_isolation: requirements.full_kernel_isolation,
        coding_guest: requirements.coding_guest,
        network_policy: requirements.network_policy,
        workspace_snapshot: requirements.workspace_snapshot,
        portable_workspace: requirements.portable_workspace,
        memory_resume: requirements.memory_resume,
        pty: requirements.pty,
        pause: requirements.pause,
        ..Default::default()
    }
}

/// The runtime a run asked for by name, or an error naming the one it did.
///
/// Shared with batch sizing, which has to resolve the same runtime the
/// placement path will: reading the name a second way is how a batch ends up
/// sized against workers the run can never be placed on.
pub(crate) fn parse_runtime(raw: &str) -> Result<RuntimeKind, CoreError> {
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
    // Resolved once, here, and the redactor below is built from the very same
    // set. Building it by re-reading the file afterwards would scrub against a
    // second read of a file the operator can change under the run: the value
    // that ran would not be the value replaced, and the one that ran is the one
    // in the output.
    let resolved = state
        .run_secrets()
        .resolve(tenant, &run.workload.secrets)
        .await?;
    let mut base = state.secret_values(tenant, sandbox.id).await;
    base.extend(run.workload.environment.clone());
    // Refuses rather than picks a winner: a literal in the run document is
    // exactly what must not be stored, and a sandbox secret losing to a run
    // secret is a race nobody can debug.
    let environment = resolved.merge(&base)?;
    let redactor = resolved.redactor();

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
        // A transport error can quote the environment it was handed, so it is
        // scrubbed on the way out too. The variant is preserved, because that
        // is what the retry policy branches on.
        .await
        .map_err(|error| redactor.redact_error(&error))?;

    let exit_code = result.exit_code;
    let duration_ms = result.duration_ms;
    let timed_out = result.timed_out;
    // Nothing resolved, so nothing to replace: moving the streams rather than
    // copying a megabyte each, per command, is the difference between free and
    // not for every workload that asks for no secrets.
    let (stdout, stderr) = if redactor.is_empty() {
        (result.stdout, result.stderr)
    } else {
        redactor.redact_output_uncapped(&result.stdout, &result.stderr)
    };

    Ok(CommandOutcome {
        command: command.to_vec(),
        exit_code,
        stdout,
        stderr,
        duration_ms,
        truncated: false,
        // Set by the phase budget, which is what knows how much of this the
        // run's row can hold. Redaction is not truncation: a replaced
        // credential makes a smaller result, not an incomplete one.
        output_preview_truncated: false,
        // A clipped run is evidence of a truncated command, so it never counts
        // as a pass.
        ok: exit_code == 0 && !timed_out,
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
    redactor: &SecretRedactor,
) -> GitEvidence {
    let Some(repo) = repo else {
        return GitEvidence {
            head: None,
            status: String::new(),
            diff: String::new(),
            changed_files: Vec::new(),
        };
    };
    let mut evidence = GitEvidence {
        head: None,
        status: String::new(),
        diff: String::new(),
        changed_files: Vec::new(),
    };
    // The repository path is the exec's working directory, not a word spliced
    // into a shell command. It used to be `cd {escaped} && git ...` with the
    // apostrophes escaped but the value itself unquoted, which broke in two
    // ways at once: any path containing a space made git fail to start and the
    // run silently recorded no evidence at all, and any caller-chosen path was
    // a command line. `run_command` already hands the same field over this way.
    for (key, argv) in [
        ("head", vec!["git", "rev-parse", "HEAD"]),
        (
            "status",
            // `-z`: NUL-separated and unquoted, so a path is reported exactly
            // as it exists. Without it git C-quotes any path holding a space, a
            // backslash or a non-ASCII byte, and a caller copying that back out
            // of `changed_files` gets a name that was never touched.
            vec!["git", "--no-pager", "status", "--porcelain=v1", "-z"],
        ),
        ("diff", vec!["git", "--no-pager", "diff"]),
    ] {
        let Ok(result) = runtime
            .exec(
                sandbox,
                ExecRequest {
                    command: argv.into_iter().map(str::to_owned).collect(),
                    working_directory: Some(repo.path.clone()),
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
                // Redacted before it is parsed, not after: a task that writes
                // its token into a filename puts the value in the status, and a
                // path is exactly what a caller later feeds back into a copy.
                let stdout = redactor.redact_text_uncapped(&result.stdout);
                evidence.changed_files = porcelain_paths(&stdout);
                // NUL written as a newline, because that is what separates the
                // records anyway. `changed_files` above holds the exact paths;
                // this is the same stream rendered for a human reading a stored
                // preview.
                evidence.status = stdout.replace('\0', "\n");
            }
            _ => evidence.diff = redactor.redact_text_uncapped(&result.stdout),
        }
    }
    evidence
}

/// The paths `git status --porcelain=v1 -z` reported, exactly as it printed them.
///
/// Each record is two status characters, a space, then the path - and for a
/// rename or a copy the *original* path follows as its own NUL-terminated
/// field. Splitting the ordinary way and trimming the remainder turned both
/// cases into something that is not a path: a rename came back as `old -> new`,
/// and a path with a space in it came back with its tail lopped off, so
/// `changed_files` disagreed with the repository about what the run touched.
///
/// Only the destination is kept. That is the path the run left behind; the
/// original is what was there when it started, which the caller already has
/// from the commit.
fn porcelain_paths(porcelain: &str) -> Vec<String> {
    let mut fields = porcelain.split('\0');
    let mut paths = Vec::new();
    while let Some(record) = fields.next() {
        let bytes = record.as_bytes();
        // The shortest possible record is `XY ` plus one byte of path.
        if bytes.len() < 4 || bytes[2] != b' ' {
            continue;
        }
        // `bytes[2]` is ASCII, so index 3 is a character boundary and this
        // slice can never split one.
        paths.push(record[3..].to_owned());
        if matches!(bytes[0], b'R' | b'C') {
            let _ = fields.next();
        }
    }
    paths
}

/// Collects the requested artifacts into object storage.
///
/// Errors are returned, not swallowed. A run that asked for `/workspace/report.txt`
/// and reported success with no artifact is the same answer as a run that never ran,
/// and the caller has no way to tell them apart - which is what happened on a live
/// cluster: the task wrote the file, the run exited 0, and both `results.artifacts`
/// and `GET /v1/runs/{id}/artifacts` were empty because one `put` failed and was
/// skipped like the rest.
async fn collect_artifacts(
    state: &AppState,
    tenant: TenantId,
    run: &Run,
    sandbox: &Sandbox,
    workload: &WorkloadSpec,
) -> Result<Vec<RunArtifactRef>, ArtifactCollectionError> {
    if workload.artifacts.is_empty() {
        return Ok(Vec::new());
    }
    let store = state
        .artifact_store()
        .ok_or_else(|| ArtifactCollectionError {
            collected: Vec::new(),
            // Not `Backend`: a deployment without artifact storage will not grow one
            // between attempts, and `is_retryable` would send every attempt to a fresh
            // machine to re-run a workload that already succeeded.
            error: CoreError::Unsupported(format!(
                "the run asked for {} artifact(s) but artifact storage is not configured",
                workload.artifacts.len()
            )),
        })?;
    let runtime = state
        .runtime_for(sandbox)
        .map_err(|error| ArtifactCollectionError {
            collected: Vec::new(),
            error,
        })?;
    let mut collected = Vec::new();
    let mut failure = None;
    for path in &workload.artifacts {
        match collect_one(state, &*runtime, &*store, sandbox, tenant, run.id, path).await {
            Ok(artifact) => collected.push(artifact),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    // Whatever did get collected is recorded before the failure is raised, and
    // handed back with it. The run is about to be marked failed, and a failed run
    // is exactly the one whose evidence somebody is going to open: dropping the
    // artifacts that were stored because a later path failed would lose the only
    // copy of them, and reporting them in the listing but not in the run document
    // would make the two disagree about what happened.
    state
        .repository()
        .put_run_artifacts(tenant, run.id, collected.clone())
        .await
        .map_err(|error| ArtifactCollectionError {
            collected: collected.clone(),
            error,
        })?;
    match failure {
        Some(error) => Err(ArtifactCollectionError { collected, error }),
        None => Ok(collected),
    }
}

/// A collection that stored some of what it was asked for and then failed.
///
/// The partial list travels with the error so the caller can put it in the run
/// document. A failed run is exactly the one whose evidence somebody opens, and
/// reporting the stored artifacts in the listing but not in the run would make the
/// two disagree about what happened.
struct ArtifactCollectionError {
    collected: Vec<RunArtifactRef>,
    error: CoreError,
}

/// The object key one collected artifact is stored under.
///
/// Derived from a digest of the artifact's name rather than from the name's path
/// components. An absolute name used verbatim produced
/// `tenants/{t}/runs/{r}//workspace/report.txt`, whose empty component the object
/// store rejects. A digest isolates the name; a UUID isolates each upload so
/// retries cannot overwrite evidence or resurrect a deletion tombstone.
pub(crate) fn run_artifact_key(tenant: TenantId, run: Uuid, name: &str) -> String {
    let digest = hex::encode(Sha256::digest(name.as_bytes()));
    format!(
        "tenants/{tenant}/runs/{run}/artifacts/{digest}/{}",
        new_id()
    )
}

/// Pulls binary chunks only when the object store is ready for another chunk.
/// Each read is independently fenced by the runtime/worker; a version token
/// prevents a changing sandbox file from becoming a mixed-version artifact.
async fn collect_one(
    state: &AppState,
    runtime: &dyn SandboxRuntime,
    store: &dyn ArtifactStore,
    sandbox: &Sandbox,
    tenant: TenantId,
    run: Uuid,
    name: &str,
) -> Result<RunArtifactRef, CoreError> {
    let _permit = state
        .upload_slots
        .acquire()
        .await
        .map_err(|_| CoreError::Unavailable("artifact uploads closed".into()))?;
    let mut source = RunArtifactSource {
        runtime,
        sandbox,
        name,
        offset: 0,
        size_bytes: None,
        version: None,
        pending: std::collections::VecDeque::new(),
        done: false,
        read_failed: false,
    };
    let object_key = run_artifact_key(tenant, run, name);
    let repository = state.repository();
    repository
        .reserve_artifact_upload(tenant, Some(run), &object_key)
        .await?;
    // What the store reports it wrote, not a second opinion computed here: the
    // size and digest that come back describe the bytes that are actually on the
    // object store, which is the only thing a later download can be checked
    // against.
    let stored = tokio::time::timeout(
        std::time::Duration::from_secs(crate::artifact_gc::MAX_ARTIFACT_UPLOAD_SECONDS),
        store.put_stream(&object_key, &mut source, aiec_core::MAX_FILE as u64),
    )
    .await
    .map_err(|_| CoreError::Unsupported(format!("artifact upload timed out for {name}")))?
    .map_err(|error| {
        if source.read_failed {
            error
        } else {
            // A storage refusal cannot be repaired by re-running this workload.
            CoreError::Unsupported(format!("artifact storage rejected {name}: {error}"))
        }
    })?;
    repository
        .complete_artifact_upload(tenant, Some(run), &object_key)
        .await?;
    Ok(RunArtifactRef {
        name: name.to_owned(),
        object_key,
        size_bytes: stored.size_bytes as i64,
        checksum_sha256: Some(stored.checksum_sha256),
        content_type: Some("application/octet-stream".to_owned()),
    })
}

struct RunArtifactSource<'a> {
    runtime: &'a dyn SandboxRuntime,
    sandbox: &'a Sandbox,
    name: &'a str,
    offset: u64,
    size_bytes: Option<u64>,
    version: Option<String>,
    /// Chunks already read and validated but not yet handed to the store. The
    /// store pulls one at a time, so a group is fetched once and drained here
    /// rather than re-requested per chunk.
    pending: std::collections::VecDeque<FileChunk>,
    done: bool,
    read_failed: bool,
}

#[async_trait::async_trait]
impl aiec_core::storage::ArtifactSource for RunArtifactSource<'_> {
    async fn next_chunk(&mut self) -> Result<Option<bytes::Bytes>, CoreError> {
        use aiec_core::runtime::{FILE_CHUNK_BURST, FILE_CHUNK_BYTES, FileChunkRequest};
        if self.done {
            return Ok(None);
        }
        // Drain what the last group already read before asking for more: the
        // store decides when the next chunk is wanted, and a group is only
        // worth fetching if the store still wants one.
        if let Some(chunk) = self.pending.pop_front() {
            return self.accept(chunk);
        }
        let request = FileChunkRequest {
            path: self.name.to_owned(),
            offset: self.offset,
            length: FILE_CHUNK_BYTES,
            expected_version: self.version.clone(),
        };
        let read = self
            .runtime
            .get_file_chunks(self.sandbox, request, FILE_CHUNK_BURST)
            .await;
        let chunks = match read {
            Ok(chunks) => chunks,
            Err(error) => {
                self.read_failed = true;
                return Err(match error {
                    CoreError::NotFound(message) => CoreError::NotFound(format!(
                        "could not read artifact {}: {message}",
                        self.name
                    )),
                    CoreError::LimitExceeded(message) => {
                        CoreError::LimitExceeded(format!("artifact {}: {message}", self.name))
                    }
                    error => error,
                });
            }
        };
        for chunk in chunks.into_iter().rev() {
            self.pending.push_front(chunk);
        }
        match self.pending.pop_front() {
            Some(chunk) => self.accept(chunk),
            None => Ok(None),
        }
    }
}

impl RunArtifactSource<'_> {
    /// Folds one validated chunk into the run's view of the file and returns
    /// the bytes the store asked for. Every consistency rule the single-chunk
    /// version enforced is here unchanged: the size must not move, the version
    /// must match, and the offset advances by exactly what was read.
    fn accept(&mut self, chunk: FileChunk) -> Result<Option<bytes::Bytes>, CoreError> {
        use aiec_core::runtime::{FILE_CHUNK_BYTES, FileChunkRequest};
        let step = FileChunkRequest {
            path: self.name.to_owned(),
            offset: self.offset,
            length: FILE_CHUNK_BYTES,
            expected_version: self.version.clone(),
        };
        if let Err(error) = step.validate_chunk(&chunk) {
            self.read_failed = true;
            return Err(match error {
                CoreError::LimitExceeded(message) => {
                    CoreError::LimitExceeded(format!("artifact {}: {message}", self.name))
                }
                CoreError::Conflict(message) => {
                    CoreError::Conflict(format!("artifact {}: {message}", self.name))
                }
                error => error,
            });
        }
        if self.size_bytes.is_some_and(|size| size != chunk.size_bytes) {
            self.read_failed = true;
            return Err(CoreError::Conflict(format!(
                "runtime returned inconsistent artifact chunks for {}",
                self.name
            )));
        }
        self.offset += chunk.bytes.len() as u64;
        self.size_bytes = Some(chunk.size_bytes);
        self.version = Some(chunk.version);
        self.done = chunk.eof;
        if chunk.bytes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(chunk.bytes))
        }
    }
}

/// Destroys the machine, or retains it under the policy when it failed.
///
/// A cleanup that fails is reported rather than logged and dropped: the caller
/// has to know a machine is still alive, or they will stop watching it and
/// assume its capacity is free.
/// Whether a failed destroy is worth another attempt.
///
/// Three things go wrong transiently here. A sandbox whose worker is resyncing
/// its lease refuses the first destroy and accepts the second - and that race
/// arrives as a `Conflict`, not a `Transient`, because the store is reporting a
/// fencing mismatch rather than a backend failure. The storage layer can also
/// deadlock or fail to serialise, which clears as soon as the other transaction
/// commits. Treating any of them as terminal is how a finished run ends up
/// outliving the machine it was supposed to release, and how a caller is told
/// their cleanup failed when the machine is already gone.
fn is_transient_destroy_error(error: &CoreError) -> bool {
    match error {
        CoreError::Transient(_) => true,
        CoreError::Conflict(message) if is_lease_resync(message) => true,
        // A runtime that cannot be reached at all. Every non-`Core` runtime
        // error is mapped to `Io`, so this is what a Docker socket hiccup, a
        // Firecracker process that vanished, or a TLS failure arrives as. It is
        // the one case the doc above names and the only one that was missing:
        // without it a single transport failure became a permanent
        // `cleanup_failed`, which is what keeps a queue row in `reclaiming` and
        // holds its slot, so a hiccup cost the run its machine for good.
        CoreError::Io(_) => true,
        _ => false,
    }
}

/// Whether a `Conflict` on destroy is the lease resync race rather than a
/// refusal. Matched against the exact sentences the store and the worker emit:
/// treating every conflict as fatal reports a cleanup failure for a machine
/// that is already gone, and treating every conflict as transient would retry
/// a genuine refusal forever.
fn is_lease_resync(message: &str) -> bool {
    matches!(
        message,
        "worker lease generation or status changed"
            | "sandbox lease generation does not match the control plane"
            | "stale sandbox lease generation"
    )
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
    let started = Instant::now();
    state.runtime_for(sandbox)?.destroy(sandbox).await?;
    let runtime_destroy_ms = started.elapsed().as_millis() as u64;
    let release_started = Instant::now();
    // Hosted capacity is never leased from a worker, so there is no lease to
    // release; asking the scheduler would fail for a lease that never existed.
    if state.is_production() && sandbox.runtime != RuntimeKind::Hosted {
        state.scheduler().release(tenant, sandbox_id).await?;
    }
    let lease_release_ms = release_started.elapsed().as_millis() as u64;
    let metadata_started = Instant::now();
    state
        .repository()
        .delete_sandbox(tenant, sandbox_id)
        .await?;
    tracing::info!(
        %sandbox_id,
        node_id = ?sandbox.node_id,
        runtime = sandbox.runtime.as_str(),
        runtime_destroy_ms,
        lease_release_ms,
        metadata_delete_ms = metadata_started.elapsed().as_millis() as u64,
        teardown_ms = started.elapsed().as_millis() as u64,
        "sandbox teardown completed"
    );
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

pub(crate) async fn destroy_with_retry(
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
            Ok(sandbox) if sandbox.state == aiec_core::SandboxState::Destroyed => return Ok(()),
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

/// Destroys everything a run still holds, without executing it again.
///
/// This is the recovery path, not the execution path. When an executor's lease
/// expires the run is already terminal in the database; all that is left is to
/// release the compute it was holding. Calling it for a run that is still
/// queued would destroy nothing, because no machine has been placed yet, and
/// it never touches the sandbox a caller asked to keep until its TTL expires.
pub(crate) async fn reclaim_run(state: &AppState, run: &Run) -> Result<Run, CoreError> {
    if !run.state.is_terminal() {
        return Ok(run.clone());
    }
    let store = state.repository();
    let links = store.list_run_sandboxes(run.tenant_id, run.id).await?;
    let ids: Vec<Uuid> = links
        .iter()
        .map(|link| link.sandbox_id)
        .filter(|id| run.retained_sandbox_id != Some(*id))
        .collect();
    let mut current = run.clone();
    let mut results = std::mem::take(&mut current.results);
    // The report of a *previous* failed teardown is not evidence about this one.
    // Carrying it forward means a run whose machines are all gone still answers
    // "cleanup failed" forever, so the dispatcher re-leases it on every
    // recovery tick, never finishes the queue row, and starves queued work -
    // three runs whose sandboxes were destroyed weeks apart wedged the queue
    // this way. The earlier failure stays in the event log and the attempt
    // record; only the teardown being attempted now may repopulate it.
    results.cleanup_failed = None;
    cleanup(state, run.tenant_id, &mut current, &ids, &mut results, None).await;
    store
        .record_run_results(run.tenant_id, run.id, results, current.state)
        .await
}

/// Reclaims one expired debugging machine; failure leaves ownership retryable.
pub(crate) async fn expire_retention(state: &AppState, run: &Run) -> Result<(), CoreError> {
    let Some(sandbox_id) = run.retained_sandbox_id else {
        return Ok(());
    };
    // Retention is recorded before the run settles, because `cleanup()` runs
    // first. A run that is still executing therefore carries an expiring
    // `retained_until` for a machine its executor is still using, and expiring
    // it would destroy that machine and clear the fields: the caller who asked
    // to keep a debugging machine would be told there is none. The store's own
    // query filters the same way; this is the second gate, so a caller holding a
    // stale read cannot reach the destroy either.
    if !run.state.is_terminal() {
        return Ok(());
    }
    if run.retained_until.is_none_or(|until| until > Utc::now()) {
        return Ok(());
    }
    if let Err(error) = destroy_with_retry(state, run.tenant_id, sandbox_id).await {
        let mut results = run.results.clone();
        results.cleanup_failed = Some(CleanupReport {
            sandbox_id,
            error: error.clone(),
        });
        state
            .repository()
            .record_run_results(run.tenant_id, run.id, results, run.state)
            .await?;
        return Err(CoreError::Unavailable(error));
    }
    state
        .repository()
        .clear_run_retention(run.tenant_id, run.id, sandbox_id)
        .await?;
    // A destroy that has now succeeded clears the earlier report of one that
    // did not. Leaving it would tell the caller their machine outlived the run
    // after the evidence says the opposite.
    if run.results.cleanup_failed.is_some() {
        let mut results = run.results.clone();
        results.cleanup_failed = None;
        state
            .repository()
            .record_run_results(run.tenant_id, run.id, results, run.state)
            .await?;
    }
    event(
        state,
        run,
        "sandbox.retention_expired",
        serde_json::json!({ "sandbox_id": sandbox_id }),
    )
    .await;
    Ok(())
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
    retention_seconds: Option<i64>,
) {
    if sandbox_ids.is_empty() {
        return;
    }
    let succeeded = run.failure_reason.is_none();
    let mut retained = None;
    if let Ok(current) = state.repository().get_run(tenant, run.id).await
        && current.state == RunState::Cancelled
    {
        run.state = RunState::Cancelled;
    }
    if let Some(retained_seconds) = retention_seconds
        && run.state != RunState::Cancelled
        && run.retention.should_retain(succeeded)
    {
        let until = Utc::now() + Duration::seconds(retained_seconds);
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
                    retained = Some(kept);
                    event(
                        state,
                        run,
                        "sandbox.retained",
                        serde_json::json!({ "sandbox_ids": [kept], "until": until }),
                    )
                    .await;
                }
                Err(error) => {
                    // Without durable retention ownership, reclaim this machine
                    // along with the other attempts rather than leaking it.
                    tracing::warn!(
                        run_id = %run.id,
                        sandbox_id = %kept,
                        error = %error,
                        "could not record retention; reclaiming the sandbox"
                    );
                    results.cleanup_failed = Some(CleanupReport {
                        sandbox_id: kept,
                        error: format!("could not record the retained sandbox: {error}"),
                    });
                }
            }
        }
    }

    for sandbox_id in sandbox_ids {
        if retained == Some(*sandbox_id) {
            continue;
        }
        // A machine that is already gone was not torn down by this pass.
        // `destroy_with_retry` reports that case as success, so without this
        // check a second cleanup - the outer per-attempt pass re-entering after
        // `execute` already released the machine - recorded a `sandbox.destroyed`
        // event for a teardown that never happened. The event log is the
        // evidence a caller reads to decide whether a run released its
        // machines, so it must not overstate what was released.
        // Absent counts too: `destroy_with_retry` answers success when the row
        // is gone as well as when it is already destroyed, and neither is a
        // teardown this pass performed.
        match state.repository().get_sandbox(tenant, *sandbox_id).await {
            Ok(sandbox) if sandbox.state == aiec_core::SandboxState::Destroyed => continue,
            Err(CoreError::NotFound(_)) => continue,
            _ => {}
        }
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
                if let Some(report) = &mut results.cleanup_failed {
                    use std::fmt::Write;
                    let _ = write!(
                        report.error,
                        "; sandbox {sandbox_id} teardown failed: {error}"
                    );
                } else {
                    results.cleanup_failed = Some(CleanupReport {
                        sandbox_id: *sandbox_id,
                        error,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod retry_policy {
    use super::{default_image_for, is_retryable, is_transient_destroy_error};
    use aiec_core::{CoreError, RuntimeKind};

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

    /// A worker rebuilding its lease races a teardown that is already under
    /// way. The store reports that as a `Conflict`, because it is fencing and
    /// not failing, and treating it as fatal made a run whose machine was
    /// already gone report a cleanup failure - twice, on a retention expiry and
    /// on an ordinary setup failure. The retry is what makes both honest.
    #[test]
    fn a_lease_resync_during_teardown_is_worth_retrying() {
        for message in [
            "worker lease generation or status changed",
            "sandbox lease generation does not match the control plane",
            "stale sandbox lease generation",
        ] {
            let resync = CoreError::Conflict(message.into());
            assert!(
                is_transient_destroy_error(&resync),
                "{message} must be retried"
            );
        }
    }

    /// A refusal that is not the resync race is still fatal, so widening the
    /// match cannot turn a real refusal into an endless retry.
    #[test]
    fn an_unrelated_conflict_stays_fatal_on_destroy() {
        for refusal in [
            CoreError::Conflict("sandbox is not running".into()),
            CoreError::Conflict("run is no longer active".into()),
            CoreError::Conflict("record already exists".into()),
        ] {
            assert!(
                !is_transient_destroy_error(&refusal),
                "{refusal} must not be retried"
            );
        }
    }

    /// An object store that will not take an artifact must not cost a machine.
    ///
    /// The workload has already succeeded by the time artifacts are collected,
    /// so classifying the store's refusal as `Backend` - which `is_retryable`
    /// sends to a fresh machine - re-ran finished work and re-collected the
    /// same bytes to arrive at the same refusal. Observed live: a run whose
    /// bucket did not exist recorded exactly one attempt, because that run
    /// used the default `max_attempts: 1`; with a higher bound the old
    /// classification would re-run finished work on a fresh machine for each
    /// remaining attempt. The run still fails; it just fails once.
    #[test]
    fn a_rejected_artifact_is_not_worth_another_machine() {
        let rejected = CoreError::Unsupported(
            "artifact storage rejected proof.txt: S3 request returned 404 Not Found".into(),
        );
        assert!(
            !is_retryable(&rejected),
            "a rejected artifact must not re-run a workload that already succeeded"
        );
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
            // `Io` is deliberately absent: it is the runtime-unreachable case
            // and it is retried. A genuine refusal from a runtime arrives as
            // `Backend`, `Conflict` or `NotFound`, all of which are here.
            assert!(
                !is_transient_destroy_error(&permanent),
                "{permanent} must not be retried"
            );
        }
    }

    /// A runtime that cannot be reached is the case this function exists for,
    /// and it is the one the original implementation forgot: every non-`Core`
    /// runtime error becomes `Io`, so a Docker socket hiccup during teardown
    /// arrived as `Io` and was treated as terminal. The run then settled with a
    /// permanent `cleanup_failed`, which is precisely what keeps its queue row
    /// out of `finished` and holds an active slot for the life of the deployment.
    /// The default image is a property of the runtime, not one name for all of
    /// them.
    ///
    /// Found by running a Run against a live Docker worker that named no image:
    /// the Run asked the registry for `aiec-coding:latest`, which is the
    /// Firecracker guest image and is not a container image, and failed with an
    /// opaque pull error long after admission. Every Run on that runtime that
    /// omitted an image did the same - 242 of them.
    #[test]
    fn a_run_that_names_no_image_gets_one_the_runtime_can_boot() {
        assert_eq!(
            default_image_for(RuntimeKind::Firecracker),
            "aiec-coding:latest",
            "the microVM guest image is the reference it is admitted under"
        );
        for runtime in [
            RuntimeKind::Docker,
            RuntimeKind::BwrapDev,
            RuntimeKind::Hosted,
        ] {
            assert_eq!(
                default_image_for(runtime),
                "debian:bookworm-slim",
                "{} boots a container image, and a guest image reference is \
                 not one",
                runtime.as_str()
            );
        }
        // The two must not collide, or the distinction is not doing anything.
        assert_ne!(
            default_image_for(RuntimeKind::Firecracker),
            default_image_for(RuntimeKind::Docker)
        );
    }

    #[test]
    fn a_runtime_that_cannot_be_reached_is_worth_another_try() {
        for transport in [
            CoreError::Io(std::io::Error::other("docker socket closed")),
            CoreError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        ] {
            assert!(
                is_transient_destroy_error(&transport),
                "{transport} must be retried: the machine may well be gone"
            );
        }
        // And the permanent cases stay permanent.
        for permanent in [
            CoreError::NotFound("no such sandbox".into()),
            CoreError::Conflict("sandbox is not running".into()),
            CoreError::Backend("guest agent refused the command".into()),
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

#[cfg(test)]
mod changed_paths {
    use super::porcelain_paths;

    /// `changed_files` is what a caller acts on: it copies a path back into a
    /// workspace, compares it against a diff, reports it as touched. Splitting
    /// porcelain the ordinary way and trimming the remainder turned a rename
    /// into `old -> new` and cut the tail off any path with a space in it, so
    /// the list named files that do not exist and missed ones that do.
    #[test]
    fn a_renamed_path_comes_back_as_the_path_that_exists_now() {
        let porcelain = "R  new name.txt\0old name.txt\0 M kept/unchanged.rs\0?? added file.rs\0";
        assert_eq!(
            porcelain_paths(porcelain),
            vec!["new name.txt", "kept/unchanged.rs", "added file.rs"]
        );
    }

    /// Without `-z` git C-quotes any path holding a backslash or a non-ASCII
    /// byte. The control plane asks for `-z`, so what arrives is the path
    /// itself - no unescaping, and no chance of reporting an escaped name as
    /// though the repository contained it.
    #[test]
    fn a_path_is_reported_exactly_as_it_exists() {
        let porcelain = " M src/caf\u{e9}/na\u{ef}ve.rs\0A  src/tab\there.rs\0";
        assert_eq!(
            porcelain_paths(porcelain),
            vec!["src/caf\u{e9}/na\u{ef}ve.rs", "src/tab\there.rs"]
        );
    }

    /// A record too short to be `XY <path>` is not a path, and guessing one out
    /// of it is how a caller ends up operating on a file the run never touched.
    #[test]
    fn a_record_that_is_not_a_path_yields_no_path() {
        assert!(porcelain_paths("\0\n\0").is_empty());
        assert!(porcelain_paths("").is_empty());
    }
}
