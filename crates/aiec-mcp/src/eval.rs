//! Provider-agnostic evaluation workflows.
//!
//! Legacy repository preparation/task tools still compose sandbox primitives.
//! OMP tools instead expand through the API's thin adapter into ordinary durable
//! Runs, using the generic client's bounded batch rather than owning machines.
//! Both paths isolate work and report cleanup failures; durable lifetime,
//! cancellation, timeout and retention belong to the control plane.
//!
//! 1. **Isolation.** Every run gets its own sandbox, so a comparison never
//!    measures a workspace a previous run dirtied.
//! 2. **Cleanup.** Legacy repository workflows release their [`SandboxGuard`];
//!    durable OMP workflows return the Run's authoritative cleanup evidence.
//! 3. **Refusal to judge.** [`compare_omp`] returns measurements. Which
//!    revision is better is a judgement the caller makes; this module does not
//!    encode one, and it never reads the host filesystem to get its numbers.
//!
//! Nothing here runs anything on the host. Repository URLs and revisions are
//! validated before they reach a shell string, and every command a caller
//! supplies is handed to the sandbox as an argument vector, so a payload such
//! as `"; rm -rf /"` is inert data rather than syntax.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

use aiec_api::omp::{OmpRunSpec, actual_omp_revision, to_run_request, wall_time_ms};
use aiec_client::CreateRunRequest;
use aiec_core::run::{
    CapabilityRequirements, CleanupReport, CommandOutcome, ResourceRequirements, RetentionPolicy,
    Run, RunState,
};
use serde::Serialize;
use uuid::Uuid;

use crate::error::{ErrorCode, McpError};
use crate::guard::LocalEndpoint;
use crate::sandbox::{ExecOutcome, LocalAiec, map_client_error};

/// The image used when a caller does not name one.
///
/// Matches the server's default image, so a request that omits the field gets
/// the same machine as `aiec_create_sandbox`.
pub const DEFAULT_IMAGE: &str = "python:3.13";
/// The local microVM runtime every evaluation runs on.
pub const DEFAULT_RUNTIME: &str = "firecracker";
/// How long a sandbox, and each command inside it, may take by default.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 900;

/// Where a cloned target repository lives inside the sandbox.
pub const REPO_PATH: &str = "/workspace/repository";

const SANDBOX_CPU: u32 = 2;
const SANDBOX_MEMORY_MB: u32 = 2048;
// The guest rootfs image on a stock deployment is 4 GiB, so asking for more
// than the image can grow to fails at create with a backend error. 2 GiB keeps a
// clean clone plus a build comfortably inside it.
const SANDBOX_DISK_MB: u32 = 2048;
const MAX_URL_LENGTH: usize = 2_048;
const MAX_REF_LENGTH: usize = 255;
const MAX_TASK_LENGTH: usize = 32_768;

/// Characters that must never appear in a repository URL.
///
/// The URL is single-quoted before it reaches a script, so this is belt and
/// braces: it also keeps shell metacharacters out of any log line that would
/// otherwise carry one. Legal-but-pointless URL characters (`?`, `&`, `#`) are
/// refused too, because a clone URL has no use for them.
const FORBIDDEN_URL_CHARS: &[char] = &[
    '\'', '"', '\\', '`', '$', ';', '|', '&', '<', '>', '(', ')', '{', '}', '[', ']', '*', '?',
    '#', '^', '!', ' ',
];

/// Characters git itself forbids in a revision, plus the shell metacharacters.
///
/// A revision reaches `git fetch` and `git checkout` inside a quoted script, so
/// this both matches `git check-ref-format` and refuses anything that could
/// break out of the quoting.
const FORBIDDEN_REF_CHARS: &[char] = &[
    '\'', '"', '\\', '`', '$', ';', '|', '&', '<', '>', '(', ')', '{', '}', '[', ']', '*', '?',
    '^', '~', ':', '!', ' ',
];

// ---------------------------------------------------------------------------
// Measurements
// ---------------------------------------------------------------------------

/// One command that ran inside a sandbox, reduced to what a comparison needs.
#[derive(Debug, Clone, Serialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    /// True only when the command exited zero without being cut off.
    pub ok: bool,
}

impl CommandResult {
    /// Reduces a sandbox execution to a measurement.
    pub fn from_outcome(outcome: &ExecOutcome) -> Self {
        Self {
            exit_code: outcome.exit_code,
            stdout: outcome.stdout.clone(),
            stderr: outcome.stderr.clone(),
            duration_ms: outcome.duration_ms,
            ok: outcome.exit_code == 0 && !outcome.timed_out,
        }
    }

    /// Builds a measurement from parts, for callers that already hold them.
    pub fn new(exit_code: i32, stdout: &str, stderr: &str, duration_ms: u64) -> Self {
        Self {
            exit_code,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            duration_ms,
            ok: exit_code == 0,
        }
    }
}

/// Whether every measurement in a set succeeded.
fn all_ok(results: &[CommandResult]) -> bool {
    results.iter().all(|result| result.ok)
}

/// Whether a sandbox execution counts as success.
///
/// A command that was cut off is not a success, whatever exit code it carried
/// back: a timeout that reports zero would otherwise pass a validation.
fn succeeded(outcome: &ExecOutcome) -> bool {
    outcome.exit_code == 0 && !outcome.timed_out
}

// ---------------------------------------------------------------------------
// prepare_repo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PrepareRepoRequest {
    /// An `https://`, `git@host:path` or `ssh://` git URL.
    pub repo_url: String,
    /// Runtime for the sandbox. Defaults to a local microVM.
    pub runtime: Option<String>,
    /// A branch, tag or commit. The remote default when absent.
    pub reference: Option<String>,
    /// Overrides [`DEFAULT_IMAGE`].
    pub image: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrepareRepoResult {
    /// The sandbox holding the clone. The caller owns it and must destroy it.
    pub sandbox_id: Uuid,
    pub repo_path: String,
    /// The commit that was actually checked out.
    pub head: String,
}

/// Creates a sandbox and clones a repository inside it.
///
/// The sandbox is left running on success: this is the primitive the other
/// workflows build on, and they need the machine afterwards. It is destroyed
/// again if the clone fails, so a failure cannot leak a sandbox either.
pub async fn prepare_repo(
    aiec: &LocalAiec,
    request: PrepareRepoRequest,
) -> Result<PrepareRepoResult, McpError> {
    let repo_url = validate_repo_url(&request.repo_url)?;
    let reference = validate_optional_reference(request.reference.as_deref())?;

    let image = request.image.as_deref().unwrap_or(DEFAULT_IMAGE);
    let timeout = DEFAULT_TIMEOUT_SECONDS;
    let (view, sandbox_id, _) = create_sandbox_with_repo(
        aiec,
        image,
        request.runtime.as_deref().unwrap_or(DEFAULT_RUNTIME),
        &repo_url,
        reference.as_deref(),
        timeout,
    )
    .await?;
    aiec.mark_tool_owned(sandbox_id);

    let mut guard = SandboxGuard::new(aiec, sandbox_id, false);
    // The workspace was cloned during create, so this confirms it is really
    // there and records the commit it is at.
    let ready = head_revision(aiec, sandbox_id, REPO_PATH, timeout).await;
    if ready.is_ok() {
        // Success hands the machine to the caller, so it must survive release.
        guard.keep();
    }
    // Release before propagating: a failed preparation must not leak a sandbox.
    guard.release().await;
    let head = ready?;
    let _ = view;

    Ok(PrepareRepoResult {
        sandbox_id,
        repo_path: REPO_PATH.to_owned(),
        head,
    })
}

// ---------------------------------------------------------------------------
// run_repo_task
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RunRepoTaskRequest {
    pub repo_url: String,
    /// Runtime for the sandbox. Defaults to a local microVM.
    pub runtime: Option<String>,
    pub reference: Option<String>,
    /// Commands run in order before the task, each as an argument vector.
    pub setup_commands: Vec<Vec<String>>,
    /// The command under test, as an argument vector.
    pub task_command: Vec<String>,
    /// Every validation runs, so one failure does not hide the others.
    pub validation_commands: Vec<Vec<String>>,
    pub timeout_seconds: Option<u64>,
    /// Leave the sandbox running so it can be inspected.
    pub keep_sandbox: bool,
    pub image: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunRepoTaskResult {
    /// The sandbox the run used, for correlation. It has already been
    /// destroyed unless the caller asked to keep it.
    pub sandbox_id: Option<Uuid>,
    /// The commit the task ran against.
    pub commit: String,
    pub task: CommandResult,
    pub validations: Vec<CommandResult>,
    pub git_status: String,
    pub git_diff: String,
    pub changed_files: Vec<String>,
    /// The task succeeded and every validation passed.
    pub overall_success: bool,
    /// Set when the sandbox outlived the run, so a caller is never left with a
    /// live machine it believes was released.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_failed: Option<CleanupFailure>,
}

/// Clones a repository, runs a task in it, and reports what changed.
///
/// A non-zero task exit is a measurement, not an error: the validations still
/// run, so the caller learns whether the task failed loudly or silently broke
/// the build. Only a failure of the sandbox itself aborts the run early, and
/// that path still destroys the sandbox.
pub async fn run_repo_task(
    aiec: &LocalAiec,
    request: RunRepoTaskRequest,
) -> Result<RunRepoTaskResult, McpError> {
    let repo_url = validate_repo_url(&request.repo_url)?;
    let reference = validate_optional_reference(request.reference.as_deref())?;
    for command in &request.setup_commands {
        validate_command(command, "setup command")?;
    }
    validate_command(&request.task_command, "task command")?;
    for command in &request.validation_commands {
        validate_command(command, "validation command")?;
    }

    let timeout = resolve_timeout(request.timeout_seconds);
    let image = request.image.as_deref().unwrap_or(DEFAULT_IMAGE);

    let (_, sandbox_id, _) = create_sandbox_with_repo(
        aiec,
        image,
        request.runtime.as_deref().unwrap_or(DEFAULT_RUNTIME),
        &repo_url,
        reference.as_deref(),
        timeout,
    )
    .await?;
    aiec.mark_tool_owned(sandbox_id);
    let guard = SandboxGuard::new(aiec, sandbox_id, request.keep_sandbox);

    let outcome = repo_task_workflow(
        aiec,
        sandbox_id,
        &guard,
        &repo_url,
        reference.as_deref(),
        &request,
        timeout,
    )
    .await;

    // The one exit point: the machine is released before the result is
    // propagated, so a `?` on the way out cannot skip the cleanup.
    let cleanup_failed = guard.release().await;
    match outcome {
        Ok(mut result) => {
            result.cleanup_failed = cleanup_failed;
            Ok(result)
        }
        // The error path still has to carry the cleanup report. Discarding it
        // here is what let a leaked machine go unreported: the run failed, the
        // destroy failed too, and the caller was told only about the first.
        Err(error) => Err(attach_cleanup_failure(error, cleanup_failed)),
    }
}

/// Everything that happens inside a task sandbox, after it exists.
async fn repo_task_workflow(
    aiec: &LocalAiec,
    sandbox_id: Uuid,
    guard: &SandboxGuard<'_>,
    repo_url: &str,
    reference: Option<&str>,
    request: &RunRepoTaskRequest,
    timeout: u64,
) -> Result<RunRepoTaskResult, McpError> {
    let started = Instant::now();
    // The repository is already in place, materialised during create.
    let commit = head_revision(aiec, sandbox_id, REPO_PATH, timeout).await?;
    let _ = (repo_url, reference);

    let environment = BTreeMap::new();
    for command in &request.setup_commands {
        let outcome = aiec
            .exec(
                sandbox_id,
                command,
                Some(REPO_PATH.to_owned()),
                environment.clone(),
                None,
                timeout,
            )
            .await?;
        if !succeeded(&outcome) {
            return Err(step_failure("a setup command", &outcome));
        }
    }

    let task = CommandResult::from_outcome(
        &aiec
            .exec(
                sandbox_id,
                &request.task_command,
                Some(REPO_PATH.to_owned()),
                environment.clone(),
                None,
                timeout,
            )
            .await?,
    );

    let validations = run_validations(
        aiec,
        sandbox_id,
        &request.validation_commands,
        &environment,
        timeout,
    )
    .await?;

    let evidence = aiec.git_evidence(sandbox_id, REPO_PATH).await?;
    let overall_success = task.ok && all_ok(&validations);
    tracing::debug!(
        sandbox_id = %sandbox_id,
        wall_time_ms = started.elapsed().as_millis(),
        overall_success,
        "repository task finished"
    );

    Ok(RunRepoTaskResult {
        sandbox_id: guard.sandbox_id(),
        commit,
        task,
        validations,
        git_status: evidence.git_status,
        git_diff: evidence.git_diff,
        changed_files: evidence.changed_files,
        overall_success,
        // Replaced by the caller, which owns the guard and its outcome.
        cleanup_failed: None,
    })
}

// ---------------------------------------------------------------------------
// run_omp_once
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OmpRunRequest {
    /// Runtime for the sandbox. Defaults to a local microVM.
    pub runtime: Option<String>,
    /// The OMP repository, cloned and checked out at `omp_ref`.
    pub omp_repo: String,
    /// The OMP revision under test: a branch, tag or commit.
    pub omp_ref: String,
    /// The repository OMP is pointed at.
    pub target_repo: String,
    pub target_ref: Option<String>,
    /// Natural-language task: positional argument by default, stdin for overrides.
    pub task: String,
    /// Run once before OMP, in the target repository.
    pub setup_command: Option<Vec<String>>,
    /// Builds OMP in its checkout; defaults to Bun install and build.
    pub build_command: Option<Vec<String>>,
    /// Override invocation. Task bytes arrive on stdin and in `OMP_TASK`.
    pub omp_command: Option<Vec<String>>,
    pub validation_commands: Vec<Vec<String>>,
    pub timeout_seconds: Option<u64>,
    pub keep_sandbox: bool,
    pub resources: Option<ResourceRequirements>,
    pub requirements: CapabilityRequirements,
    pub environment: BTreeMap<String, String>,
    pub secrets: Vec<String>,
    /// Must be 1: this function performs exactly one isolated run. Use
    /// [`compare_omp`] to repeat a measurement.
    pub repetitions: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct OmpRunResult {
    pub run_id: Uuid,
    pub state: RunState,
    pub failure_reason: Option<String>,
    pub omp_ref: String,
    pub target_ref: Option<String>,
    pub actual_omp_ref: Option<String>,
    pub actual_target_ref: Option<String>,
    /// Only set when the control plane retained the machine.
    pub sandbox_id: Option<Uuid>,
    pub runtime: Option<String>,
    pub wall_time_ms: Option<u64>,
    pub phase_ms: BTreeMap<String, u64>,
    /// Null means preparation failed or the task otherwise never ran.
    pub omp: Option<CommandOutcome>,
    pub setup: Vec<CommandOutcome>,
    pub validations: Vec<CommandOutcome>,
    pub git_status: String,
    pub git_diff: String,
    pub git_evidence_truncated: bool,
    pub changed_files: Vec<String>,
    pub cleanup_failed: Option<CleanupReport>,
    pub success: bool,
}

impl OmpRunResult {
    fn from_run(request: &OmpRunRequest, run: Run) -> Self {
        let actual_omp_ref = actual_omp_revision(&run);
        let wall_time_ms = wall_time_ms(&run);
        Self {
            run_id: run.id,
            state: run.state,
            failure_reason: run.failure_reason,
            omp_ref: request.omp_ref.clone(),
            target_ref: request.target_ref.clone(),
            actual_omp_ref,
            actual_target_ref: run.results.commit,
            sandbox_id: run.retained_sandbox_id,
            runtime: run.placement.runtime,
            wall_time_ms,
            phase_ms: run.results.phase_ms,
            omp: run.results.task,
            setup: run.results.setup,
            validations: run.results.validations,
            git_status: run.results.git_status,
            git_diff: run.results.git_diff,
            git_evidence_truncated: run.results.git_evidence_truncated,
            changed_files: run.results.changed_files,
            cleanup_failed: run.results.cleanup_failed,
            success: run.state == RunState::Succeeded,
        }
    }
}

/// The same pure adapter used by the API, submitted over the ordinary Run route.
fn durable_omp_request(
    aiec: &LocalAiec,
    request: &OmpRunRequest,
) -> Result<CreateRunRequest, McpError> {
    validate_omp_request(request)?;
    let runtime = request.runtime.as_deref().unwrap_or(DEFAULT_RUNTIME);
    LocalEndpoint::require_local_runtime(runtime)?;
    let spec = OmpRunSpec {
        omp_repo: validate_repo_url(&request.omp_repo)?,
        omp_ref: validate_reference(&request.omp_ref)?,
        task: request.task.clone(),
        target_repo: validate_repo_url(&request.target_repo)?,
        target_ref: validate_optional_reference(request.target_ref.as_deref())?,
        setup_command: request.setup_command.clone(),
        build_command: request.build_command.clone(),
        omp_command: request.omp_command.clone(),
        validations: request.validation_commands.clone(),
        timeout_seconds: Some(resolve_timeout(request.timeout_seconds)),
        runtime: Some(runtime.to_owned()),
        resources: request.resources.clone(),
        requirements: request.requirements.clone(),
        retention: Some(if request.keep_sandbox {
            RetentionPolicy::KeepAlways
        } else {
            RetentionPolicy::Destroy
        }),
        retained_seconds: Some(aiec.default_ttl_seconds() as i64),
        environment: request.environment.clone(),
        secrets: request.secrets.clone(),
    };
    let expanded = to_run_request(&spec).map_err(|error| McpError::invalid(error.to_string()))?;
    Ok(CreateRunRequest {
        workload: expanded.workload,
        resources: expanded.resources,
        requirements: expanded.requirements,
        retention: expanded.retention,
        requested_runtime: expanded.requested_runtime,
        retained_seconds: expanded.retained_seconds,
        idempotency_key: expanded.idempotency_key,
        parent_run_id: expanded.parent_run_id,
        matrix_id: expanded.matrix_id,
    })
}

/// Runs one OMP revision against one target repository, in its own sandbox.
///
/// Everything the run touches is inside that sandbox: the OMP checkout, the
/// target clone, whatever the setup command builds and the diff that comes
/// back out. A previous run cannot influence this one.
pub async fn run_omp_once(
    aiec: &LocalAiec,
    request: &OmpRunRequest,
) -> Result<OmpRunResult, McpError> {
    let durable = durable_omp_request(aiec, request)?;
    let run = aiec
        .client()
        .create_run(&durable)
        .await
        .map_err(|error| map_client_error(&error))?;
    Ok(OmpRunResult::from_run(request, run))
}

// ---------------------------------------------------------------------------
// compare_omp
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CompareOmpRequest {
    pub omp_repo: String,
    /// Runtime for every sandbox this comparison creates.
    pub runtime: Option<String>,
    /// The revision in use today.
    pub baseline_ref: String,
    /// The revision under evaluation.
    pub candidate_ref: String,
    pub target_repo: String,
    pub target_ref: Option<String>,
    pub task: String,
    /// Prepares the target repository after the OMP checkout is built.
    pub setup_command: Option<Vec<String>>,
    /// Builds OMP in its checkout; defaults to Bun install and build.
    pub build_command: Option<Vec<String>>,
    /// Override invocation, with task bytes on stdin and in `OMP_TASK`.
    pub omp_command: Option<Vec<String>>,
    pub validation_commands: Vec<Vec<String>>,
    /// Repetitions per side. One when absent.
    pub repetitions: Option<u32>,
    pub timeout_seconds: Option<u64>,
    /// How many sandboxes may exist at once. Defaults to, and is capped by,
    /// the server's own configured limit.
    pub max_parallel: Option<usize>,
    pub resources: Option<ResourceRequirements>,
    pub requirements: CapabilityRequirements,
    pub environment: BTreeMap<String, String>,
    pub secrets: Vec<String>,
}

/// The measurements for one side of a comparison.
///
/// There is deliberately no field saying which side did better. These numbers
/// are what a caller compares; the judgement is theirs.
#[derive(Debug, Clone, Serialize)]
pub struct SideSummary {
    /// `baseline` or `candidate`, exactly as the caller named the sides.
    pub label: String,
    /// The revision every run on this side used.
    pub revision: String,
    pub successful_runs: u32,
    pub failed_runs: u32,
    /// Validations that passed, across every run on this side.
    pub validation_passes: u32,
    /// Validations that ran, across every run on this side.
    pub validation_total: u32,
    /// Wall time summed over the runs on this side.
    pub wall_time_ms: Option<u64>,
    pub phase_ms: BTreeMap<String, u64>,
    /// One slot per durable run. Null means its task never executed.
    pub exit_codes: Vec<Option<i32>>,
    pub missing_task_runs: u32,
    pub setup_failures: u32,
    pub submission_failures: u32,
    pub actual_omp_revisions: Vec<Option<String>>,
    pub actual_target_revisions: Vec<Option<String>>,
    pub cleanup_failures: Vec<CleanupReport>,
    /// Distinct files changed by at least one run on this side.
    pub changed_file_count: usize,
    /// Runs with clipped git evidence; changed-file/diff totals are incomplete.
    pub git_evidence_truncations: usize,
    /// Commands whose stored output previews were clipped.
    pub output_preview_truncations: usize,
    /// The tail of the last run's output, from the agent and then the
    /// validations.
    ///
    /// Without this a side can only report that it failed and the exit code
    /// that says so, which leaves "why" as guesswork. It is clipped, because an
    /// agent that dumped a build log should not be able to blow up the report.
    #[serde(default)]
    pub last_output: String,
    /// Captured diff-preview bytes summed over this side, not full diff size.
    pub total_diff_bytes: usize,
}

impl SideSummary {
    /// Aggregates the runs of one side. Pure, so it can be tested directly.
    pub fn from_runs(label: &str, revision: &str, runs: &[OmpRunResult]) -> Self {
        let mut summary = Self {
            label: label.to_owned(),
            revision: revision.to_owned(),
            successful_runs: 0,
            failed_runs: 0,
            validation_passes: 0,
            validation_total: 0,
            wall_time_ms: if runs.is_empty() { None } else { Some(0) },
            phase_ms: BTreeMap::new(),
            exit_codes: Vec::with_capacity(runs.len()),
            missing_task_runs: 0,
            setup_failures: 0,
            submission_failures: 0,
            actual_omp_revisions: Vec::with_capacity(runs.len()),
            actual_target_revisions: Vec::with_capacity(runs.len()),
            cleanup_failures: Vec::new(),
            changed_file_count: 0,
            total_diff_bytes: 0,
            git_evidence_truncations: 0,
            output_preview_truncations: 0,
            last_output: String::new(),
        };

        // A file touched by three of four runs is still one file the candidate
        // touched, so the union is reported rather than a count per run.
        let mut changed: BTreeSet<&str> = BTreeSet::new();
        for run in runs {
            if run.success {
                summary.successful_runs += 1;
            } else {
                summary.failed_runs += 1;
            }
            summary.validation_total += run.validations.len() as u32;
            summary.validation_passes += run.validations.iter().filter(|v| v.ok).count() as u32;
            summary.wall_time_ms = summary
                .wall_time_ms
                .zip(run.wall_time_ms)
                .map(|(total, elapsed)| total.saturating_add(elapsed));
            summary
                .exit_codes
                .push(run.omp.as_ref().map(|task| task.exit_code));
            summary.missing_task_runs += u32::from(run.omp.is_none());
            summary.setup_failures += run.setup.iter().filter(|step| !step.ok).count() as u32;
            summary
                .actual_omp_revisions
                .push(run.actual_omp_ref.clone());
            summary
                .actual_target_revisions
                .push(run.actual_target_ref.clone());
            if let Some(cleanup) = &run.cleanup_failed {
                summary.cleanup_failures.push(cleanup.clone());
            }
            for (phase, elapsed) in &run.phase_ms {
                let total = summary.phase_ms.entry(phase.clone()).or_default();
                *total = total.saturating_add(*elapsed);
            }
            summary.total_diff_bytes = summary.total_diff_bytes.saturating_add(run.git_diff.len());
            summary.git_evidence_truncations += usize::from(run.git_evidence_truncated);
            summary.output_preview_truncations += run
                .setup
                .iter()
                .chain(run.omp.iter())
                .chain(run.validations.iter())
                .filter(|command| command.output_preview_truncated)
                .count();
            changed.extend(run.changed_files.iter().map(String::as_str));
            // Include successful output too: absence is not evidence that an
            // agent did nothing. Setup failures and validation diagnostics stay visible.
            summary.last_output.clear();
            for step in run
                .setup
                .iter()
                .chain(run.omp.iter())
                .chain(run.validations.iter())
            {
                append_output_tail(&mut summary.last_output, &step.stdout);
                append_output_tail(&mut summary.last_output, &step.stderr);
            }
            if let Some(reason) = &run.failure_reason {
                append_output_tail(&mut summary.last_output, reason);
            }
        }
        summary.changed_file_count = changed.len();
        summary
    }
}

/// Carries a cleanup failure out on the error path.
///
/// A machine that outlived its run is the more urgent fact than the workflow
/// error, so it is attached to the error's details rather than dropped.
fn attach_cleanup_failure(error: McpError, cleanup: Option<CleanupFailure>) -> McpError {
    let Some(cleanup) = cleanup else {
        return error;
    };
    let mut details = if error.details.is_object() {
        error.details
    } else {
        serde_json::json!({})
    };
    if let Some(object) = details.as_object_mut() {
        object.insert(
            "cleanup_failed".to_owned(),
            serde_json::json!({ "sandbox_id": cleanup.sandbox_id, "error": cleanup.error }),
        );
        object.insert("sandbox_still_running".to_owned(), serde_json::json!(true));
    }
    McpError { details, ..error }
}

/// A sandbox this server created and could not destroy.
///
/// Reported rather than swallowed: the run's measurements are still worth
/// having, but the caller has to know a machine is still alive.
#[derive(Debug, Clone, Serialize)]
pub struct CleanupFailure {
    pub sandbox_id: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OmpSubmissionFailure {
    pub side: String,
    pub repetition: u32,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompareOmpResult {
    /// Correlates every sandbox and log line of this comparison.
    pub evaluation_id: Uuid,
    pub baseline: SideSummary,
    pub candidate: SideSummary,
    /// Intentionally retained machines; cleanup failures are reported separately.
    pub sandbox_ids: Vec<Uuid>,
    pub baseline_runs: Vec<OmpRunResult>,
    pub candidate_runs: Vec<OmpRunResult>,
    pub submission_failures: Vec<OmpSubmissionFailure>,
    /// The concurrency actually used.
    pub max_parallel: usize,
}

/// The last few kilobytes of a run's output, so a failing comparison says why
/// without letting an agent's build log dominate the report.
fn append_output_tail(output: &mut String, text: &str) {
    const LIMIT: usize = 2048;
    if text.is_empty() {
        return;
    }
    let mut start = text.len().saturating_sub(LIMIT);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    if start > 0 {
        output.clear();
    } else if !output.is_empty() {
        output.push('\n');
    }
    output.push_str(&text[start..]);
    let mut trim = output.len().saturating_sub(LIMIT);
    while !output.is_char_boundary(trim) {
        trim += 1;
    }
    output.drain(..trim);
}

fn tail_of(text: &str) -> String {
    const LIMIT: usize = 2048;
    if text.len() <= LIMIT {
        return text.trim().to_owned();
    }
    let mut start = text.len() - LIMIT;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", text[start..].trim())
}

/// Runs two OMP revisions against the same target and returns measurements.
///
/// Every cell is an ordinary durable Run. The generic client's bounded sliding
/// window schedules the batch; there is no OMP-specific sandbox lifetime.
pub async fn compare_omp(
    aiec: &LocalAiec,
    request: CompareOmpRequest,
) -> Result<CompareOmpResult, McpError> {
    let repetitions = resolve_repetitions(request.repetitions)?;
    let max_parallel = resolve_max_parallel(aiec, request.max_parallel);
    let evaluation_id = Uuid::now_v7();
    let mut planned = Vec::with_capacity(repetitions as usize * 2);
    let mut requests = Vec::with_capacity(repetitions as usize * 2);
    for repetition in 0..repetitions {
        for (side, revision) in [
            ("baseline", &request.baseline_ref),
            ("candidate", &request.candidate_ref),
        ] {
            let run = OmpRunRequest {
                runtime: request.runtime.clone(),
                omp_repo: request.omp_repo.clone(),
                omp_ref: revision.clone(),
                target_repo: request.target_repo.clone(),
                target_ref: request.target_ref.clone(),
                task: request.task.clone(),
                setup_command: request.setup_command.clone(),
                build_command: request.build_command.clone(),
                omp_command: request.omp_command.clone(),
                validation_commands: request.validation_commands.clone(),
                timeout_seconds: request.timeout_seconds,
                keep_sandbox: false,
                repetitions: 1,
                resources: request.resources.clone(),
                requirements: request.requirements.clone(),
                environment: request.environment.clone(),
                secrets: request.secrets.clone(),
            };
            let mut durable = durable_omp_request(aiec, &run)?;
            durable.matrix_id = Some(evaluation_id);
            durable.idempotency_key = Some(format!("omp-{evaluation_id}-{side}-{repetition}"));
            requests.push(durable);
            planned.push((side, repetition, run));
        }
    }
    let cells = aiec
        .client()
        .run_cells(&requests, max_parallel)
        .await
        .map_err(|error| map_client_error(&error))?;
    let mut baseline_runs = Vec::with_capacity(repetitions as usize);
    let mut candidate_runs = Vec::with_capacity(repetitions as usize);
    let mut submission_failures = Vec::new();
    for cell in cells {
        let (side, repetition, requested) = &planned[cell.index];
        if let Some(run) = cell.run {
            let outcome = OmpRunResult::from_run(requested, run);
            if *side == "baseline" {
                baseline_runs.push(outcome);
            } else {
                candidate_runs.push(outcome);
            }
        } else {
            submission_failures.push(OmpSubmissionFailure {
                side: (*side).to_owned(),
                repetition: *repetition,
                error: cell
                    .error
                    .unwrap_or_else(|| "the control plane returned no Run".into()),
            });
        }
    }
    let mut baseline = SideSummary::from_runs("baseline", &request.baseline_ref, &baseline_runs);
    let mut candidate =
        SideSummary::from_runs("candidate", &request.candidate_ref, &candidate_runs);
    for failure in &submission_failures {
        let summary = if failure.side == "baseline" {
            &mut baseline
        } else {
            &mut candidate
        };
        summary.failed_runs += 1;
        summary.submission_failures += 1;
        summary.last_output = tail_of(&failure.error);
        summary.wall_time_ms = None;
    }
    let sandbox_ids = baseline_runs
        .iter()
        .chain(candidate_runs.iter())
        .filter_map(|run| run.sandbox_id)
        .collect();
    Ok(CompareOmpResult {
        evaluation_id,
        baseline,
        candidate,
        sandbox_ids,
        baseline_runs,
        candidate_runs,
        submission_failures,
        max_parallel,
    })
}

// ---------------------------------------------------------------------------
// Sandbox lifetime
// ---------------------------------------------------------------------------

/// Owns a sandbox for the length of a workflow.
///
/// The guard has no `Drop` implementation, because destruction is an await and
/// a destructor cannot await. Instead every workflow funnels through a single
/// exit point that calls [`SandboxGuard::release`] before it propagates a
/// result, so the `?` operator can never skip it. `release` consumes the
/// guard, so it cannot run twice either.
struct SandboxGuard<'a> {
    aiec: &'a LocalAiec,
    sandbox_id: Uuid,
    keep: bool,
}

impl<'a> SandboxGuard<'a> {
    fn new(aiec: &'a LocalAiec, sandbox_id: Uuid, keep: bool) -> Self {
        Self {
            aiec,
            sandbox_id,
            keep,
        }
    }

    /// Hands the sandbox to the caller instead of destroying it.
    fn keep(&mut self) {
        self.keep = true;
    }

    /// The id to report back, and only when the machine still exists.
    ///
    /// Returning the id of a sandbox that was just destroyed invites the caller
    /// to drive a machine that is already gone, so a run that cleaned up after
    /// itself reports nothing here.
    fn sandbox_id(&self) -> Option<Uuid> {
        self.keep.then_some(self.sandbox_id)
    }

    /// Destroys the sandbox unless the caller asked to keep it.
    ///
    /// A cleanup failure is logged, never propagated: the caller's result
    /// matters more than a machine that outlived its run, and the ownership
    /// record still lets shutdown collect it.
    async fn release(self) -> Option<CleanupFailure> {
        if self.keep {
            return None;
        }
        let sandbox_id = self.sandbox_id;
        match self.aiec.destroy_sandbox(sandbox_id).await {
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(
                    sandbox_id = %sandbox_id,
                    error = %error,
                    "could not destroy the evaluation sandbox"
                );
                // Surfaced in the tool result: a silent failure here leaves a
                // running machine holding capacity that the caller believes was
                // released.
                Some(CleanupFailure {
                    sandbox_id: sandbox_id.to_string(),
                    error: error.message,
                })
            }
        }
    }
}

/// Creates the sandbox a workflow runs in, with networking on.
/// Creates a sandbox whose repository workspace is fetched by the control plane.
///
/// AIec performs the clone inside the guest, so the sandbox is created with a
/// network. Everything after the clone runs in that same machine; the network is
/// only needed to fetch the repository.
async fn create_sandbox_with_repo(
    aiec: &LocalAiec,
    image: &str,
    runtime: &str,
    repo_url: &str,
    reference: Option<&str>,
    timeout_seconds: u64,
) -> Result<(crate::sandbox::SandboxView, Uuid, Uuid), McpError> {
    aiec.create_sandbox_with_workspace(
        image,
        runtime,
        aiec_core::WorkspaceSpec::Git {
            repo: repo_url.to_owned(),
            reference: reference.map(str::to_owned),
            shallow: false,
        },
        SANDBOX_CPU,
        SANDBOX_MEMORY_MB,
        SANDBOX_DISK_MB,
        timeout_seconds,
        // The clone runs inside the guest, so it needs egress to the remote.
        true,
    )
    .await
}

/// Reads the commit a prepared workspace is at, failing if the clone is absent.
async fn head_revision(
    aiec: &LocalAiec,
    sandbox_id: Uuid,
    repo_path: &str,
    timeout_seconds: u64,
) -> Result<String, McpError> {
    let outcome = aiec
        .exec_shell(
            sandbox_id,
            &format!("cd {repo_path} && git rev-parse HEAD"),
            timeout_seconds,
        )
        .await?;
    if outcome.exit_code != 0 {
        return Err(McpError::new(
            crate::error::ErrorCode::LocalRuntimeUnavailable,
            format!(
                "the repository workspace was not materialised at {repo_path}: {}",
                outcome.stderr.trim()
            ),
        )
        .with_sandbox(sandbox_id));
    }
    Ok(outcome.stdout.trim().to_owned())
}

// ---------------------------------------------------------------------------
// Running things inside a sandbox
// ---------------------------------------------------------------------------

/// Runs every validation, in order, and keeps the failures.
///
/// A validation that exits non-zero is a result, not an error, so all of them
/// run: stopping at the first would hide whether a later one also breaks. An
/// error the sandbox itself reports does abort, because it says nothing about
/// the code under test.
async fn run_validations(
    aiec: &LocalAiec,
    sandbox_id: Uuid,
    commands: &[Vec<String>],
    environment: &BTreeMap<String, String>,
    timeout_seconds: u64,
) -> Result<Vec<CommandResult>, McpError> {
    let mut results = Vec::with_capacity(commands.len());
    for command in commands {
        let outcome = aiec
            .exec(
                sandbox_id,
                command,
                Some(REPO_PATH.to_owned()),
                environment.clone(),
                None,
                timeout_seconds,
            )
            .await?;
        results.push(CommandResult::from_outcome(&outcome));
    }
    Ok(results)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A workflow step that failed for a reason outside the caller's arguments.
fn step_failure(what: &str, outcome: &ExecOutcome) -> McpError {
    let mut message = format!(
        "{what} failed inside the sandbox with exit code {}: {}",
        outcome.exit_code,
        first_lines(&outcome.stderr, 4)
    );
    if !outcome.stdout.trim().is_empty() {
        message.push_str(&format!(" (stdout: {})", first_lines(&outcome.stdout, 2)));
    }
    McpError::new(ErrorCode::UnsupportedOperation, message)
}

/// The first `count` non-blank lines of a stream, for an error message.
fn first_lines(text: &str, count: usize) -> String {
    let joined = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(count)
        .collect::<Vec<_>>()
        .join("; ");
    if joined.is_empty() {
        "<no output>".to_owned()
    } else {
        joined
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Checks a repository URL and returns it trimmed.
///
/// Only three forms are accepted: `https://`, `git@host:path` and `ssh://`.
/// Anything that would let a caller reach a local path, an unexpected protocol
/// or a host other than the one it appears to name is refused here rather than
/// discovered by git.
fn validate_repo_url(raw: &str) -> Result<String, McpError> {
    let url = raw.trim();
    if url.is_empty() {
        return Err(McpError::invalid("the repository URL is empty"));
    }
    if url.len() > MAX_URL_LENGTH {
        return Err(McpError::invalid(format!(
            "the repository URL is {} bytes, above the {MAX_URL_LENGTH} byte limit",
            url.len()
        )));
    }
    if let Some(bad) = forbidden_char(url, FORBIDDEN_URL_CHARS) {
        return Err(McpError::invalid(format!(
            "the repository URL contains `{bad}`, which is not valid in a URL"
        )));
    }

    if let Some(remainder) = url.strip_prefix("https://") {
        let authority = remainder.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(McpError::invalid("the repository URL has no host"));
        }
        if authority.contains('@') {
            return Err(McpError::invalid(
                "the repository URL may not carry credentials; use an ssh URL or a configured key",
            ));
        }
        return Ok(url.to_owned());
    }

    if let Some(remainder) = url.strip_prefix("git@") {
        let (host, path) = remainder.split_once(':').ok_or_else(|| {
            McpError::invalid(
                "an ssh repository URL looks like `git@host:owner/repo`, with no `://`",
            )
        })?;
        check_ssh_host(host)?;
        if path.is_empty() {
            return Err(McpError::invalid("the repository URL has no path"));
        }
        return Ok(url.to_owned());
    }

    if let Some(remainder) = url.strip_prefix("ssh://") {
        let authority = remainder.split('/').next().unwrap_or_default();
        let (userinfo, host) = match authority.rsplit_once('@') {
            Some((userinfo, host)) => (Some(userinfo), host),
            None => (None, authority),
        };
        if userinfo.is_some_and(|userinfo| userinfo.contains(':')) {
            return Err(McpError::invalid(
                "the repository URL may not carry a password",
            ));
        }
        check_ssh_host(host)?;
        return Ok(url.to_owned());
    }

    Err(McpError::invalid(format!(
        "`{url}` is not an accepted repository URL: use `https://host/owner/repo`, \
         `git@host:owner/repo` or `ssh://host/owner/repo`"
    )))
}

fn check_ssh_host(host: &str) -> Result<(), McpError> {
    if host.is_empty() {
        return Err(McpError::invalid("the repository URL has no host"));
    }
    if host.starts_with('-') {
        return Err(McpError::invalid(
            "the repository URL host may not start with `-`",
        ));
    }
    Ok(())
}

/// Checks a revision and returns it trimmed.
fn validate_reference(raw: &str) -> Result<String, McpError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(McpError::invalid("the revision is empty"));
    }
    if value.len() > MAX_REF_LENGTH {
        return Err(McpError::invalid(format!(
            "the revision is {} bytes, above the {MAX_REF_LENGTH} byte limit",
            value.len()
        )));
    }
    if let Some(bad) = forbidden_char(value, FORBIDDEN_REF_CHARS) {
        return Err(McpError::invalid(format!(
            "the revision contains `{bad}`, which git does not allow in a reference"
        )));
    }
    // `--upload-pack=...` is an option, not a revision.
    if value.starts_with('-') {
        return Err(McpError::invalid(
            "a revision may not start with `-`, which git would read as an option",
        ));
    }
    if value.contains("..") {
        return Err(McpError::invalid(
            "a revision may not contain `..`; name the path explicitly instead",
        ));
    }
    if value.contains("@{") {
        return Err(McpError::invalid(
            "a revision may not contain `@{`, which names a reflog position",
        ));
    }
    if value.starts_with('/') || value.ends_with('/') {
        return Err(McpError::invalid(
            "a revision may not start or end with `/`",
        ));
    }
    for component in value.split('/') {
        if component.is_empty() {
            return Err(McpError::invalid(
                "a revision may not contain an empty path component",
            ));
        }
        if component.starts_with('.') {
            return Err(McpError::invalid(
                "a revision may not contain a component starting with `.`",
            ));
        }
        if component.ends_with(".lock") {
            return Err(McpError::invalid(
                "a revision may not end a component with `.lock`",
            ));
        }
    }
    Ok(value.to_owned())
}

/// Validates an optional revision, treating a blank one as absent.
fn validate_optional_reference(raw: Option<&str>) -> Result<Option<String>, McpError> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => validate_reference(value).map(Some),
        None => Ok(None),
    }
}

/// The first character that is a control character, whitespace or forbidden.
fn forbidden_char(value: &str, forbidden: &[char]) -> Option<char> {
    value.chars().find(|character| {
        character.is_control() || character.is_whitespace() || forbidden.contains(character)
    })
}

/// Checks a command that will be run as an argument vector.
///
/// An argument vector is not a shell, so a metacharacter is inert here. What is
/// refused is the shape that indicates a confused caller: nothing to run, an
/// empty word that would vanish crossing the control plane, or a program name
/// that is really an option.
fn validate_command(command: &[String], what: &str) -> Result<(), McpError> {
    if command.is_empty() {
        return Err(McpError::invalid(format!("the {what} is empty")));
    }
    if command[0].starts_with('-') {
        return Err(McpError::invalid(format!(
            "the {what} starts with `{}`, which a program would read as an option",
            command[0]
        )));
    }
    // A caller that explicitly asks for a shell is asking for a script, and a
    // script has line breaks. That is a deliberate signal rather than an
    // accident, and it changes nothing about isolation: the script still runs
    // inside the sandbox. Any other argument, and any control character other
    // than a newline or tab, is still refused.
    let script_argument = explicit_shell_script(command).map(|index| index + 1);

    for (index, argument) in command.iter().enumerate() {
        let allow_newlines = script_argument == Some(index);
        if let Some(bad) = argument
            .chars()
            .find(|c| c.is_control() && !(allow_newlines && matches!(c, '\n' | '\t')))
        {
            return Err(McpError::invalid(format!(
                "the {what} contains the control character `{}`",
                bad.escape_debug()
            )));
        }
    }
    Ok(())
}

/// Returns the index of the script argument when `command` is an explicit
/// invocation of a shell with a `-c` flag, e.g. `["sh", "-lc", "<script>"]`.
///
/// The flag may carry bundling letters (`-lc`), which is how `sh -lc` and
/// `bash -c` are normally written.
fn explicit_shell_script(command: &[String]) -> Option<usize> {
    let program = Path::new(&command[0])
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !matches!(program, "sh" | "bash" | "zsh" | "dash" | "ksh") {
        return None;
    }
    let flag = command.get(1)?;
    if !flag.starts_with('-') || flag.starts_with("--") {
        return None;
    }
    // The flag must actually request a command string. Testing that every
    // letter is in {c,l,i} is not enough: `-l` alone would pass vacuously.
    let letters = flag.trim_start_matches('-');
    (letters.contains('c') && letters.chars().all(|c| matches!(c, 'c' | 'l' | 'i'))).then_some(1)
}

/// Checks the task handed to OMP.
fn validate_task(task: &str) -> Result<(), McpError> {
    if task.trim().is_empty() {
        return Err(McpError::invalid("the task is empty"));
    }
    if task.len() > MAX_TASK_LENGTH {
        return Err(McpError::invalid(format!(
            "the task is {} bytes, above the {MAX_TASK_LENGTH} byte limit",
            task.len()
        )));
    }
    Ok(())
}

/// Checks everything a single OMP run needs.
fn validate_omp_request(request: &OmpRunRequest) -> Result<(), McpError> {
    validate_repo_url(&request.omp_repo)?;
    validate_reference(&request.omp_ref)?;
    validate_repo_url(&request.target_repo)?;
    validate_optional_reference(request.target_ref.as_deref())?;
    validate_task(&request.task)?;
    if let Some(setup) = &request.setup_command {
        validate_command(setup, "setup command")?;
    }
    if let Some(build) = &request.build_command {
        validate_command(build, "build command")?;
    }
    if let Some(omp_command) = &request.omp_command {
        validate_command(omp_command, "omp command")?;
    }
    for command in &request.validation_commands {
        validate_command(command, "validation command")?;
    }
    if request.repetitions != 1 {
        return Err(McpError::invalid(format!(
            "this tool runs exactly one repetition, but {} were requested; use aiec_compare_omp \
             to repeat a measurement",
            request.repetitions
        )));
    }
    Ok(())
}

/// Resolves a repetition count, defaulting to a single run.
fn resolve_repetitions(repetitions: Option<u32>) -> Result<u32, McpError> {
    match repetitions {
        Some(0) => Err(McpError::invalid(
            "a comparison needs at least one repetition per side",
        )),
        Some(count) => Ok(count),
        None => Ok(1),
    }
}

/// Resolves the concurrency, never above the server's own configured limit.
///
/// A caller may ask for fewer sandboxes than the server allows, but not more:
/// the configured limit is what the local workers were sized for.
fn resolve_max_parallel(aiec: &LocalAiec, requested: Option<usize>) -> usize {
    let capacity = aiec.max_parallel().max(1);
    requested.map_or(capacity, |wanted| wanted.clamp(1, capacity))
}

/// Resolves a timeout, bounded by what a sandbox and the facade accept.
fn resolve_timeout(timeout_seconds: Option<u64>) -> u64 {
    timeout_seconds
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS)
        .clamp(1, 3_600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(exit_code: i32, timed_out: bool) -> ExecOutcome {
        ExecOutcome {
            exit_code,
            stdout: String::new(),
            stderr: String::new(),
            timed_out,
            duration_ms: 1,
            truncated: false,
        }
    }

    fn command(exit_code: i32) -> CommandOutcome {
        CommandOutcome {
            exit_code,
            stdout: "out".into(),
            stderr: "err".into(),
            duration_ms: 10,
            ok: exit_code == 0,
            ..Default::default()
        }
    }

    fn run(
        success: bool,
        exit_code: i32,
        validations: &[i32],
        diff: &str,
        files: &[&str],
    ) -> OmpRunResult {
        OmpRunResult {
            run_id: Uuid::nil(),
            state: if success {
                RunState::Succeeded
            } else {
                RunState::Failed
            },
            failure_reason: None,
            omp_ref: "refs/heads/main".to_owned(),
            target_ref: None,
            actual_omp_ref: None,
            actual_target_ref: None,
            sandbox_id: Some(Uuid::nil()),
            runtime: Some(DEFAULT_RUNTIME.to_owned()),
            wall_time_ms: Some(100),
            phase_ms: BTreeMap::new(),
            setup: Vec::new(),
            cleanup_failed: None,
            omp: Some(command(exit_code)),
            validations: validations.iter().map(|code| command(*code)).collect(),
            git_status: String::new(),
            git_diff: diff.to_owned(),
            git_evidence_truncated: false,
            changed_files: files.iter().map(|file| (*file).to_owned()).collect(),
            success,
        }
    }

    // -- repository URLs -----------------------------------------------------

    #[test]
    fn https_urls_are_accepted_and_trimmed() {
        for url in [
            "https://github.com/owner/repo",
            "https://github.com/owner/repo.git",
            "https://gitlab.example.com:8443/group/sub/repo",
        ] {
            let accepted = validate_repo_url(url);
            assert!(accepted.is_ok(), "{url} should be accepted: {accepted:?}");
        }
        assert_eq!(
            validate_repo_url("  https://github.com/owner/repo  ").expect("trimmed"),
            "https://github.com/owner/repo"
        );
    }

    #[test]
    fn ssh_urls_are_accepted() {
        for url in [
            "git@github.com:owner/repo.git",
            "ssh://git@github.com/owner/repo.git",
            "ssh://github.com/owner/repo.git",
            "ssh://git@github.com:2222/owner/repo.git",
        ] {
            let accepted = validate_repo_url(url);
            assert!(accepted.is_ok(), "{url} should be accepted: {accepted:?}");
        }
    }

    #[test]
    fn non_ssh_transports_are_refused() {
        for url in [
            "http://github.com/owner/repo",
            "git://github.com/owner/repo",
            "file:///etc/passwd",
            "ftp://example.com/repo",
            "/home/user/repo",
            "./relative/repo",
            "github.com/owner/repo",
        ] {
            let refused = validate_repo_url(url).expect_err(url);
            assert_eq!(refused.code, ErrorCode::InvalidArgument, "{url}");
        }
    }

    #[test]
    fn a_url_cannot_carry_a_payload_or_a_credential() {
        for url in [
            "https://github.com/o/r; touch /tmp/pwned",
            "https://github.com/o/r && curl evil.example",
            "https://github.com/o/r`id`",
            "https://github.com/o/r$(id)",
            "https://github.com/o/r | tee /tmp/x",
            "https://github.com/o/r\nrm -rf /",
            "https://github.com/o/r\trm -rf /",
            "https://user:pass@github.com/o/r",
            "ssh://user:pass@github.com/o/r",
        ] {
            let refused = validate_repo_url(url).expect_err(url);
            assert_eq!(refused.code, ErrorCode::InvalidArgument, "{url}");
        }
    }

    #[test]
    fn a_hostless_or_over_long_url_is_refused() {
        for url in ["", "   ", "https://", "git@", "git@:owner/repo", "ssh://"] {
            let refused = validate_repo_url(url).expect_err(url);
            assert_eq!(refused.code, ErrorCode::InvalidArgument, "{url}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_URL_LENGTH));
        let refused = validate_repo_url(&long).expect_err("too long");
        assert!(refused.message.contains("byte limit"));
    }

    // -- revisions -----------------------------------------------------------

    #[test]
    fn ordinary_revisions_are_accepted() {
        for reference in [
            "main",
            "release/1.0",
            "v1.2.3",
            "0123456789abcdef0123456789abcdef01234567",
            "refs/heads/feature/omp_speedup",
            "feature_x",
        ] {
            let accepted = validate_reference(reference);
            assert!(
                accepted.is_ok(),
                "{reference} should be accepted: {accepted:?}"
            );
        }
    }

    #[test]
    fn a_revision_cannot_inject_into_the_script() {
        for reference in [
            "main; touch /tmp/pwned",
            "main && id",
            "main`id`",
            "main$(id)",
            "main | tee /tmp/x",
            "main'quote",
            "main\\n id",
            "main\nrm -rf /",
            "main --upload-pack=touch /tmp/pwned",
            "-main",
            "main > /tmp/x",
            "main {id}",
        ] {
            let refused = validate_reference(reference).expect_err(reference);
            assert_eq!(refused.code, ErrorCode::InvalidArgument, "{reference}");
        }
    }

    #[test]
    fn revisions_git_itself_would_refuse_are_refused() {
        for reference in [
            "",
            "   ",
            "a..b",
            "main@{0}",
            "main~1",
            "main^",
            "a:b",
            "a?b",
            "a*b",
            "a[bc",
            "refs/",
            "/refs/heads/main",
            "refs/heads/main/",
            "refs/heads//main",
            ".hidden/main",
            "refs/heads/main.lock",
        ] {
            let refused = validate_reference(reference).expect_err(reference);
            assert_eq!(refused.code, ErrorCode::InvalidArgument, "{reference}");
        }
    }

    #[test]
    fn a_blank_reference_means_the_remote_default() {
        assert_eq!(validate_optional_reference(None).expect("absent"), None);
        assert_eq!(
            validate_optional_reference(Some("   ")).expect("blank is absent"),
            None
        );
        assert_eq!(
            validate_optional_reference(Some(" main ")).expect("trimmed"),
            Some("main".to_owned())
        );
        assert_eq!(
            validate_optional_reference(Some("main; id"))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    // -- commands ------------------------------------------------------------

    #[test]
    fn a_command_must_name_something_to_run() {
        let empty: Vec<String> = Vec::new();
        assert_eq!(
            validate_command(&empty, "task command").unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            validate_command(&["-rf".to_owned()], "task command")
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            validate_command(&["ls".to_owned(), "a\0b".to_owned()], "task command")
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            validate_command(&["ls\n-la".to_owned()], "task command")
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn a_command_with_shell_metacharacters_is_still_an_argument_vector() {
        // Not refused, and it must not be: `exec` never sees a shell, so this
        // python program and its argument are two literal words.
        let command = vec![
            "python".to_owned(),
            "-c".to_owned(),
            "print('; rm -rf /')".to_owned(),
        ];
        assert!(validate_command(&command, "task command").is_ok());
    }

    // -- measurements --------------------------------------------------------

    #[test]
    fn a_timed_out_command_never_counts_as_ok() {
        let cut_off = CommandResult::from_outcome(&outcome(0, true));
        assert!(!cut_off.ok, "a command that was cut off did not succeed");

        let clean = CommandResult::from_outcome(&outcome(0, false));
        assert!(clean.ok);

        let failed = CommandResult::from_outcome(&outcome(1, false));
        assert!(!failed.ok);
        assert!(all_ok(std::slice::from_ref(&clean)));
        assert!(!all_ok(&[clean, failed]));
        assert!(all_ok(&[]), "no validations means nothing failed");
    }

    #[test]
    fn a_summary_counts_runs_validations_time_and_files() {
        let runs = vec![
            run(true, 0, &[0, 0], "0123456789", &["a.rs", "b.rs"]),
            run(false, 1, &[1, 0], "01234", &["a.rs", "c.rs"]),
        ];
        let summary = SideSummary::from_runs("baseline", "main", &runs);

        assert_eq!(summary.label, "baseline");
        assert_eq!(summary.revision, "main");
        assert_eq!(summary.successful_runs, 1);
        assert_eq!(summary.failed_runs, 1);
        assert_eq!(summary.validation_passes, 3);
        assert_eq!(summary.validation_total, 4);
        assert_eq!(summary.wall_time_ms, Some(200));
        assert_eq!(summary.exit_codes, vec![Some(0), Some(1)]);
        // Distinct files across the runs, not a sum: `a.rs` was touched twice.
        assert_eq!(summary.changed_file_count, 3);
        assert_eq!(summary.total_diff_bytes, 15);
    }

    #[test]
    fn an_empty_side_summarises_to_zero_rather_than_panicking() {
        let summary = SideSummary::from_runs("candidate", "feature", &[]);
        assert_eq!(summary.successful_runs, 0);
        assert_eq!(summary.failed_runs, 0);
        assert_eq!(summary.validation_passes, 0);
        assert_eq!(summary.validation_total, 0);
        assert_eq!(summary.wall_time_ms, None);
        assert!(summary.exit_codes.is_empty());
        assert_eq!(summary.changed_file_count, 0);
        assert_eq!(summary.total_diff_bytes, 0);
    }

    #[test]
    fn preparation_failure_is_missing_task_not_a_synthetic_exit_or_duration() {
        let mut failed = run(false, 0, &[], "", &[]);
        failed.omp = None;
        failed.wall_time_ms = None;
        failed.setup = vec![command(23)];
        failed.failure_reason = Some("agent build failed".into());
        failed.cleanup_failed = Some(CleanupReport {
            sandbox_id: Uuid::nil(),
            error: "destroy refused".into(),
        });
        let summary = SideSummary::from_runs("baseline", "main", &[failed]);
        assert_eq!(summary.exit_codes, vec![None]);
        assert_eq!(summary.wall_time_ms, None);
        assert_eq!(summary.missing_task_runs, 1);
        assert_eq!(summary.setup_failures, 1);
        assert_eq!(summary.cleanup_failures[0].error, "destroy refused");
        assert!(summary.last_output.contains("agent build failed"));
    }

    #[test]
    fn successful_task_and_failed_validation_outputs_remain_visible() {
        let mut measured = run(false, 0, &[42], "", &[]);
        measured.omp.as_mut().unwrap().stdout = "TASK_REACHED".into();
        measured.omp.as_mut().unwrap().stderr.clear();
        measured.validations[0].stdout.clear();
        measured.validations[0].stderr = "CHECK_FAILED".into();
        let summary = SideSummary::from_runs("candidate", "next", &[measured]);
        assert_eq!(summary.exit_codes, vec![Some(0)]);
        assert_eq!(summary.validation_passes, 0);
        assert!(summary.last_output.contains("TASK_REACHED"));
        assert!(summary.last_output.contains("CHECK_FAILED"));
    }

    // -- command validation --------------------------------------------------

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_owned()).collect()
    }

    /// A caller that explicitly asks for a shell is asking for a script, and a
    /// script has line breaks. Refusing those made the high-level tools
    /// unusable, because installing a toolchain needs more than one line.
    #[test]
    fn an_explicit_shell_invocation_may_carry_a_multiline_script() {
        let command = argv(&["sh", "-lc", "set -e\necho one\necho two"]);
        assert!(validate_command(&command, "setup command").is_ok());

        for shell in ["bash", "zsh", "dash", "ksh"] {
            let command = argv(&[shell, "-c", "a\nb"]);
            assert!(
                validate_command(&command, "setup command").is_ok(),
                "{shell} -c should accept a script"
            );
        }
    }

    /// The relaxation is only for the script argument of an explicit shell. An
    /// ordinary argument, or a different program, is still refused.
    #[test]
    fn a_newline_outside_an_explicit_script_is_still_refused() {
        for command in [
            argv(&["python", "a\nb"]),
            argv(&["echo", "hello", "wor\nld"]),
            // A program that merely starts with "sh" is not a shell invocation.
            argv(&["shape-tool", "-c", "a\nb"]),
            // A flag without `c` is not a script request.
            argv(&["sh", "-l", "a\nb"]),
        ] {
            assert!(
                validate_command(&command, "task command").is_err(),
                "{command:?} must be refused"
            );
        }
    }

    #[test]
    fn other_control_characters_stay_refused_even_in_a_script() {
        let command = argv(&["sh", "-lc", "echo \u{0}done"]);
        assert!(validate_command(&command, "setup command").is_err());
    }

    #[test]
    fn an_option_like_program_is_still_refused() {
        assert!(validate_command(&argv(&["--version"]), "task command").is_err());
        assert!(validate_command(&argv(&[]), "task command").is_err());
    }

    // -- request validation --------------------------------------------------

    fn omp_request() -> OmpRunRequest {
        OmpRunRequest {
            runtime: None,
            omp_repo: "https://github.com/owner/omp".to_owned(),
            omp_ref: "main".to_owned(),
            target_repo: "https://github.com/owner/repo".to_owned(),
            target_ref: None,
            task: "fix the flaky test".to_owned(),
            setup_command: None,
            omp_command: None,
            build_command: None,
            validation_commands: Vec::new(),
            timeout_seconds: None,
            keep_sandbox: false,
            repetitions: 1,
            resources: None,
            requirements: Default::default(),
            environment: BTreeMap::new(),
            secrets: Vec::new(),
        }
    }

    #[test]
    fn a_well_formed_run_is_accepted() {
        assert!(validate_omp_request(&omp_request()).is_ok());
    }

    #[test]
    fn a_run_refuses_anything_that_would_reach_past_the_sandbox() {
        let repeated = OmpRunRequest {
            repetitions: 3,
            ..omp_request()
        };
        let refused = validate_omp_request(&repeated).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidArgument);
        assert!(refused.message.contains("aiec_compare_omp"));

        let none = OmpRunRequest {
            repetitions: 0,
            ..omp_request()
        };
        assert_eq!(
            validate_omp_request(&none).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let bad_ref = OmpRunRequest {
            omp_ref: "main; id".to_owned(),
            ..omp_request()
        };
        assert_eq!(
            validate_omp_request(&bad_ref).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let local_target = OmpRunRequest {
            target_repo: "/etc".to_owned(),
            ..omp_request()
        };
        assert_eq!(
            validate_omp_request(&local_target).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let empty_task = OmpRunRequest {
            task: "  ".to_owned(),
            ..omp_request()
        };
        assert_eq!(
            validate_omp_request(&empty_task).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repetitions_default_to_one_and_never_to_zero() {
        assert_eq!(resolve_repetitions(None).expect("default"), 1);
        assert_eq!(resolve_repetitions(Some(4)).expect("explicit"), 4);
        assert_eq!(
            resolve_repetitions(Some(0)).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn a_timeout_is_bounded_by_what_a_sandbox_accepts() {
        assert_eq!(resolve_timeout(None), DEFAULT_TIMEOUT_SECONDS);
        assert_eq!(resolve_timeout(Some(0)), 1);
        assert_eq!(resolve_timeout(Some(120)), 120);
        assert_eq!(resolve_timeout(Some(10_000)), 3_600);
    }

    // -- errors --------------------------------------------------------------

    #[test]
    fn a_failing_step_reports_both_streams_and_never_leaks_nothing() {
        let mut failed = outcome(2, false);
        failed.stderr = "error: cannot find package\n".to_owned();
        failed.stdout = "resolving\n".to_owned();
        let error = step_failure("a setup command", &failed);
        assert_eq!(error.code, ErrorCode::UnsupportedOperation);
        assert!(error.message.contains("exit code 2"));
        assert!(error.message.contains("cannot find package"));
        assert!(error.message.contains("resolving"));

        let silent = step_failure("a setup command", &outcome(2, false));
        assert!(silent.message.contains("<no output>"));
    }

    #[test]
    fn an_empty_error_stream_still_says_something() {
        assert_eq!(first_lines("", 4), "<no output>");
        assert_eq!(first_lines("\n \n", 4), "<no output>");
        assert_eq!(first_lines("a\nb\nc\nd\ne", 2), "a; b");
    }
}
