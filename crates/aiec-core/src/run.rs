//! The orchestration layer's vocabulary: a Run is work, a Sandbox is compute.
//!
//! A sandbox already exists and already works. What did not exist is the thing a
//! caller actually wants to ask for: "run this task, in a clean machine, and
//! tell me what changed". Everything here exists to make that a durable object
//! with its own identity, history and results, rather than a sequence of API
//! calls a caller has to orchestrate by hand and keep in its head.
//!
//! The types are deliberately boring: a Run is a row, a state machine, and a
//! document. It does not replace the sandbox API, and it does not own execution
//! — the runtime does that, unchanged.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::network::NetworkPolicy;

/// Most setup commands a workload may carry.
///
/// The step count is caller input, and every step is an exec whose output ends
/// up in the run's own row. Left unbounded, one request carrying five thousand
/// setup commands is five thousand machines' worth of work and five thousand
/// stored previews on a single frequently-read document: the size of the
/// request becomes the size of the answer to every later `GET`.
pub const MAX_SETUP_COMMANDS: usize = 32;

/// Most validation commands a workload may carry. Same reasoning as
/// [`MAX_SETUP_COMMANDS`]: validations all run even after one fails, so an
/// unbounded list is unbounded work *and* unbounded stored output.
pub const MAX_VALIDATION_COMMANDS: usize = 32;

/// Per-command cap for a setup step's stored preview, stdout and stderr
/// together. Setup output is the least interesting part of a run and the most
/// likely to be a long install log.
pub const MAX_SETUP_COMMAND_PREVIEW_BYTES: usize = 1024;

/// Same per-command cap for a validation step, for the same reason.
pub const MAX_VALIDATION_COMMAND_PREVIEW_BYTES: usize = 1024;

/// What one run's setup previews may carry in total. Equal to
/// `MAX_SETUP_COMMANDS * MAX_SETUP_COMMAND_PREVIEW_BYTES`, so the phase cap and
/// the per-command cap agree and neither can be raised alone.
pub const MAX_SETUP_PREVIEW_BYTES: usize = MAX_SETUP_COMMANDS * MAX_SETUP_COMMAND_PREVIEW_BYTES;

/// What one run's validation previews may carry in total.
pub const MAX_VALIDATION_PREVIEW_BYTES: usize =
    MAX_VALIDATION_COMMANDS * MAX_VALIDATION_COMMAND_PREVIEW_BYTES;

/// What one run's task preview may carry. The task is what the caller came for
/// and the only phase whose output they cannot recompute, so it gets the bulk of
/// the budget; setup and validation are usually a status line.
pub const MAX_TASK_PREVIEW_BYTES: usize = 128 * 1024;

/// What `git status`, the changed-file list and `git diff` may take together on
/// one run. A diff of a large repository is unbounded by nature, and it is the
/// largest thing stored on a row that every list and poll of runs has to read.
pub const MAX_GIT_EVIDENCE_BYTES: usize = 64 * 1024;

/// The ceiling on every byte of command output and git evidence one run stores.
///
/// `MAX_STDOUT`/`MAX_STDERR` bound what a *machine* returns - one megabyte each,
/// per command. They say nothing about the run document, which accumulates
/// every phase: 64 commands at a megabyte a stream is a hundred megabyte row
/// that every subsequent read pays for.
pub const MAX_RESULTS_PREVIEW_BYTES: usize = MAX_SETUP_PREVIEW_BYTES
    + MAX_VALIDATION_PREVIEW_BYTES
    + MAX_TASK_PREVIEW_BYTES
    + MAX_GIT_EVIDENCE_BYTES;

// The published ceiling has to be the sum of what is actually spent, or it is
// a number nobody can check.
const _: () = assert!(MAX_RESULTS_PREVIEW_BYTES == 256 * 1024);

/// Where a run is in its life.
///
/// Distinct from [`crate::SandboxState`] on purpose: a sandbox moves through
/// compute states, a run moves through work states, and conflating them is how
/// "the machine is running" comes to be mistaken for "the work succeeded".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Preparing,
    Running,
    Validating,
    Collecting,
    Succeeded,
    Failed,
    Cancelled,
}

impl RunState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::Validating => "validating",
            Self::Collecting => "collecting",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "queued" => Self::Queued,
            "preparing" => Self::Preparing,
            "running" => Self::Running,
            "validating" => Self::Validating,
            "collecting" => Self::Collecting,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    /// Whether a run in this state still holds compute that must be reclaimed.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Preparing | Self::Running | Self::Validating | Self::Collecting
        )
    }

    pub fn is_terminal(self) -> bool {
        !self.is_active()
    }

    /// The single place the run lifecycle is defined.
    ///
    /// A terminal state is final: there is no edge out of it, so a finished run
    /// cannot be talked back into running. Cancellation is allowed from anywhere
    /// active, because a caller must always be able to stop work it started.
    pub fn can_transition_to(self, next: Self) -> bool {
        use RunState::*;
        if next == Self::Cancelled {
            return self.is_active();
        }
        matches!(
            (self, next),
            (Queued, Preparing | Failed)
                | (Preparing, Running | Validating | Failed)
                | (Running, Preparing | Validating | Collecting | Failed)
                | (Validating, Preparing | Collecting | Failed)
                // A run with no validations still has to collect, so
                // `running -> collecting` is covered by the arm above.
                | (Collecting, Preparing | Succeeded | Failed)
        )
    }
}

/// What the run should execute.
///
/// One shape for every workflow: a single run, a repeated run, a comparison leg,
/// a matrix cell. Separate input formats per workflow is how a platform ends up
/// with four subtly different ideas of what a "command" is.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct WorkloadSpec {
    /// Image to boot. Ignored when a workspace repository is given and the image
    /// is left unset, in which case the default is used.
    #[serde(default)]
    pub image: Option<String>,
    /// Repository to start from, cloned inside the sandbox by the control plane.
    #[serde(default)]
    pub repo: Option<RepoSpec>,
    /// Commands run in order before the task, each an argument vector.
    #[serde(default)]
    pub setup: Vec<Vec<String>>,
    /// The work itself, as an argument vector. Never a shell string, so a task
    /// cannot be a command injection by construction.
    #[serde(default)]
    pub command: Vec<String>,
    /// Run after the task; all of them run even if one fails, so a caller can
    /// tell a loud failure from a silent one.
    #[serde(default)]
    pub validations: Vec<Vec<String>>,
    /// Paths to collect once the task is done.
    #[serde(default)]
    pub artifacts: Vec<String>,
    /// Non-secret environment for the task. Secrets come from the tenant's
    /// secret store by reference, never inline, so they are not in this document.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Names of tenant secrets to inject. Resolved at execution time.
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Collect `git status`, `git diff` and the changed-file list. Runs inside
    /// the sandbox; the control plane never shells out to git on the host.
    #[serde(default)]
    pub git_evidence: bool,
}

impl WorkloadSpec {
    /// A workload is only runnable once it says what to run, and only if what it
    /// says has a shape the control plane can carry.
    ///
    /// Step counts are refused here, before admission, rather than trimmed later
    /// or merely bounded while storing: a request for a thousand setup commands
    /// is a caller asking for work nobody can execute in one run, and quietly
    /// running the first 32 would report a success for a workload that was never
    /// run.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.setup.len() > MAX_SETUP_COMMANDS {
            return Err(crate::CoreError::LimitExceeded(format!(
                "a workload may carry at most {MAX_SETUP_COMMANDS} setup commands, not {}",
                self.setup.len()
            )));
        }
        if self.validations.len() > MAX_VALIDATION_COMMANDS {
            return Err(crate::CoreError::LimitExceeded(format!(
                "a workload may carry at most {MAX_VALIDATION_COMMANDS} validation commands, not {}",
                self.validations.len()
            )));
        }
        if self.command.is_empty() {
            return Err(crate::CoreError::InvalidRequest(
                "the workload has no command".into(),
            ));
        }
        if self.command.iter().any(|part| part.contains('\0')) {
            return Err(crate::CoreError::InvalidRequest(
                "the command contains a null byte".into(),
            ));
        }
        if let Some(repo) = &self.repo
            && let Err(error) = repo.validate()
        {
            return Err(error);
        }
        for command in self
            .setup
            .iter()
            .chain(std::iter::once(&self.command))
            .chain(self.validations.iter())
        {
            if command.is_empty() {
                return Err(crate::CoreError::InvalidRequest(
                    "a command in the workload is empty".into(),
                ));
            }
        }
        Ok(())
    }
}

/// A repository a run starts from.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RepoSpec {
    pub url: String,
    #[serde(default)]
    pub reference: Option<String>,
    /// Where it lands inside the sandbox. Fixed rather than caller-chosen so a
    /// workload cannot point a clone at a path that shadows the agent's tooling.
    #[serde(default = "default_repo_path")]
    pub path: String,
}

fn default_repo_path() -> String {
    "/workspace/repository".to_owned()
}

impl Default for RepoSpec {
    fn default() -> Self {
        Self {
            url: String::new(),
            reference: None,
            path: default_repo_path(),
        }
    }
}

impl RepoSpec {
    /// Only https and ssh git remotes, and never a URL carrying a credential.
    ///
    /// Refusing credentials matters more than it looks: a URL with a token in it
    /// would end up in the run document, in the event log, and in any error
    /// message that renders the request.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        let url = self.url.trim();
        if let Some(remote) = url.strip_prefix("git@") {
            if !remote.contains(':') || remote.chars().any(char::is_whitespace) {
                return Err(crate::CoreError::InvalidRequest(
                    "invalid SSH repository remote".into(),
                ));
            }
        } else {
            let remote = url::Url::parse(url)
                .map_err(|_| crate::CoreError::InvalidRequest("invalid repository URL".into()))?;
            if !matches!(remote.scheme(), "https" | "ssh") || remote.host_str().is_none() {
                return Err(crate::CoreError::InvalidRequest(
                    "a repository must be an https, git@ or ssh git remote".into(),
                ));
            }
            let credential = remote.password().is_some()
                || (remote.scheme() == "https" && !remote.username().is_empty())
                || (remote.scheme() == "ssh"
                    && !remote.username().bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    }));
            if credential {
                return Err(crate::CoreError::InvalidRequest(
                    "a repository URL must not carry credentials".into(),
                ));
            }
        }
        if let Some(reference) = &self.reference
            && !reference
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
        {
            return Err(crate::CoreError::InvalidRequest(
                "a git reference may only contain letters, digits, '.', '_', '-' and '/'".into(),
            ));
        }
        Ok(())
    }
}

/// What a run needs from its machine.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ResourceRequirements {
    #[serde(default = "default_cpu")]
    pub cpu: u32,
    #[serde(default = "default_run_memory")]
    pub memory_mb: u32,
    #[serde(default = "default_run_disk")]
    pub disk_mb: u32,
    #[serde(default)]
    pub network: NetworkPolicy,
    /// Out-of-guest governance for this run. Selected here because it answers
    /// the same question as `network`: what this machine may reach. A run with
    /// a Guard selection is governed by that policy alone - the ordinary
    /// network policy is not an alternative path to the same egress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<aiec_guard::policy::GuardConfig>,
}

impl ResourceRequirements {
    /// A run's resources must be a policy the runtime can actually enforce, not
    /// a document that only parses.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if let Some(guard) = &self.guard {
            guard
                .effective_policy()
                .map_err(|error| crate::CoreError::InvalidRequest(error.to_string()))?;
        }
        Ok(())
    }
}

fn default_cpu() -> u32 {
    1
}
fn default_run_memory() -> u32 {
    1024
}
fn default_run_disk() -> u32 {
    2048
}

/// What a run needs from its *runtime*.
///
/// A caller states requirements, not providers. Asking for
/// `full_kernel_isolation` and letting the scheduler choose is what stops every
/// caller from hardcoding `runtime="firecracker"` and what makes a mixed cluster
/// schedulable at all.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct CapabilityRequirements {
    #[serde(default)]
    pub full_kernel_isolation: bool,
    #[serde(default)]
    pub coding_guest: bool,
    #[serde(default)]
    pub network_policy: bool,
    #[serde(default)]
    pub workspace_snapshot: bool,
    #[serde(default)]
    pub portable_workspace: bool,
    #[serde(default)]
    pub memory_resume: bool,
    #[serde(default)]
    pub pty: bool,
    #[serde(default)]
    pub pause: bool,
}

impl CapabilityRequirements {
    /// Whether a worker advertising `capabilities` can satisfy these.
    pub fn satisfied_by(&self, capabilities: &crate::runtime::RuntimeCapabilities) -> bool {
        // Every requirement is a one-way demand: a worker either offers the
        // capability or it does not. A requirement that no worker satisfies must
        // fail placement rather than be quietly dropped.
        (!self.full_kernel_isolation || capabilities.full_kernel_isolation)
            && (!self.coding_guest || capabilities.coding_guest)
            && (!self.network_policy || capabilities.network_policy)
            && (!self.workspace_snapshot || capabilities.vm_snapshot)
            && (!self.portable_workspace || capabilities.portable_workspace)
            && (!self.memory_resume || capabilities.memory_resume)
            && (!self.pty || capabilities.pty)
            && (!self.pause || capabilities.pause)
    }

    /// Human-readable reasons, recorded with the placement so a refused run can
    /// be explained without re-running the scheduler by hand.
    pub fn reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.full_kernel_isolation {
            reasons.push("full kernel isolation required".to_owned());
        }
        if self.coding_guest {
            reasons.push("coding guest required".to_owned());
        }
        if self.network_policy {
            reasons.push("network policy required".to_owned());
        }
        if self.workspace_snapshot {
            reasons.push("workspace snapshots required".to_owned());
        }
        if self.portable_workspace {
            reasons.push("portable workspace required".to_owned());
        }
        if self.memory_resume {
            reasons.push("memory resume required".to_owned());
        }
        if self.pty {
            reasons.push("pty required".to_owned());
        }
        if self.pause {
            reasons.push("pause required".to_owned());
        }
        reasons
    }
}

/// What happens to the machine when the run ends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionPolicy {
    /// Always destroy. The default, because a machine nobody is looking at is
    /// just capacity nobody is using.
    #[default]
    Destroy,
    /// Keep the machine only when the run failed, so there is something to debug.
    KeepOnFailure,
    /// Keep the machine whatever the outcome.
    KeepAlways,
}

impl RetentionPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Destroy => "destroy",
            Self::KeepOnFailure => "keep_on_failure",
            Self::KeepAlways => "keep_always",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "destroy" => Self::Destroy,
            "keep_on_failure" => Self::KeepOnFailure,
            "keep_always" => Self::KeepAlways,
            _ => return None,
        })
    }

    /// Whether a machine should survive this outcome.
    ///
    /// "For debugging" is time-limited by construction: a retained machine still
    /// carries `retained_until`, and a run that failed is not a licence to hold
    /// compute forever.
    pub fn should_retain(self, succeeded: bool) -> bool {
        match self {
            Self::Destroy => false,
            Self::KeepOnFailure => !succeeded,
            Self::KeepAlways => true,
        }
    }
}

/// A durable piece of work.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Run {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub state: RunState,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub queued_at: Option<chrono::DateTime<chrono::Utc>>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub workload: WorkloadSpec,
    pub resources: ResourceRequirements,
    pub requirements: CapabilityRequirements,
    /// Why the run was placed where it was.
    pub placement: Placement,
    pub results: RunResults,
    pub failure_reason: Option<String>,
    pub retention: RetentionPolicy,
    pub retained_sandbox_id: Option<Uuid>,
    pub retained_until: Option<chrono::DateTime<chrono::Utc>>,
    pub idempotency_key: Option<String>,
    pub parent_run_id: Option<Uuid>,
    pub matrix_id: Option<Uuid>,
    /// Which cell of which matrix this run was submitted as, when it was one.
    ///
    /// Stored on the Run rather than beside it, because the label is part of
    /// what the caller asked for: a matrix recovered tomorrow has to pair each
    /// run with the axis it was submitted under, and nothing else in the store
    /// can reproduce that. `None` is a real answer for a run that was not a
    /// matrix cell.
    #[serde(default)]
    pub matrix_cell: Option<MatrixCellIdentity>,
}

/// A run's place in a submitted matrix, as the caller stated it.
///
/// The position and the axis together are the whole identity of a cell: the
/// position orders the experiment, the axis says which variables it was
/// testing. Both are written at admission, before any of the matrix runs, so a
/// cell that fails, or an API that restarts mid-matrix, still comes back
/// labelled.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatrixCellIdentity {
    /// Position in the submitted matrix.
    pub index: u32,
    /// Variable name and value, e.g. `{"model": "opus"}`.
    #[serde(default)]
    pub axis: BTreeMap<String, String>,
}

impl Run {
    /// Whether a run still holds compute that has to be reclaimed.
    ///
    /// This is the predicate a sweeper needs, and it is deliberately false for
    /// a run that retained its machine on purpose: that machine has an expiry of
    /// its own and destroying it early would take away the debugging the caller
    /// asked for.
    pub fn needs_cleanup(&self) -> bool {
        self.state.is_terminal() && self.retained_until.is_none()
    }

    /// Whether the run is a candidate for a timed sweep.
    pub fn retention_expired(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.retained_until.is_some_and(|until| until <= now)
    }
}

/// Where a run landed and why.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Placement {
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub worker: Option<String>,
    #[serde(default)]
    pub reasons: Vec<String>,
}

/// The outcome of one command.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct CommandOutcome {
    pub command: Vec<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    /// Set when the sandbox clipped the output, in which case the result is
    /// evidence of a truncated run rather than of the command.
    #[serde(default)]
    pub truncated: bool,
    /// Set when the *stored* preview dropped part of the output, so `stdout`
    /// and `stderr` are a bounded excerpt rather than the whole thing.
    ///
    /// Deliberately not `truncated`, and deliberately not `ok`. `truncated` is
    /// a fact about the machine losing bytes mid-stream; this is a fact about
    /// how much of an already-complete result the control plane chose to keep.
    /// A command that exited 0 and ran to completion is a pass whether or not
    /// its first megabyte of output fitted in a preview - folding the two
    /// together would report every successful build as a failed one the moment
    /// output grew, and would leave nothing to tell the two apart.
    #[serde(default)]
    pub output_preview_truncated: bool,
    #[serde(default)]
    pub ok: bool,
}

/// What a run produced.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RunResults {
    #[serde(default)]
    pub task: Option<CommandOutcome>,
    #[serde(default)]
    pub validations: Vec<CommandOutcome>,
    #[serde(default)]
    pub setup: Vec<CommandOutcome>,
    #[serde(default)]
    pub commit: Option<String>,
    #[serde(default)]
    pub git_status: String,
    #[serde(default)]
    pub git_diff: String,
    #[serde(default)]
    pub changed_files: Vec<String>,
    /// Set when `git_status`, `git_diff` or `changed_files` was clipped to keep
    /// the run's row bounded, so all three are an excerpt rather than the whole
    /// repository's state.
    ///
    /// A run that touched ten thousand files and a run that touched none both
    /// have to fit the same document; without this flag the only way to tell
    /// them apart is to guess from a suspiciously round list.
    #[serde(default)]
    pub git_evidence_truncated: bool,
    #[serde(default)]
    pub artifacts: Vec<RunArtifactRef>,
    /// Per-phase timings, so "the run took 42 seconds" can be followed by
    /// "31 of them were repository setup" instead of a guess.
    #[serde(default)]
    pub phase_ms: BTreeMap<String, u64>,
    /// Set when a machine outlived the run, so the caller is never left with a
    /// live sandbox it believes was released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_failed: Option<CleanupReport>,
}

/// The marker left where a stored preview dropped output.
///
/// Visible on purpose. A silently short `stdout` is indistinguishable from a
/// command that simply printed less, and a caller debugging a failure should
/// not have to cross-reference a flag to learn that the middle of their
/// compiler log is not there.
const PREVIEW_ELISION: &str = "\n[...]\n";

/// The largest character boundary at or below `index`.
fn floor_boundary(text: &str, mut index: usize) -> &str {
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    &text[..index]
}

/// The smallest character boundary at or above `index`.
fn ceil_boundary(text: &str, mut index: usize) -> usize {
    while !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// Clips one stream to `cap` bytes, keeping both ends.
///
/// A prefix alone throws away the half a caller reads for: builds, tests and
/// stack traces all announce their failure at the end, while the reason the
/// command started doing anything odd is at the beginning. Both ends are cut on
/// a character boundary, because a preview that ends mid-codepoint is not a
/// shorter string - it is a document the caller's own JSON decoder rejects.
fn clip_stream(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        return text.to_owned();
    }
    let room = cap.saturating_sub(PREVIEW_ELISION.len());
    // Too small for a marker and two ends to be worth anything: keep the head
    // and spend the whole budget on it rather than on a marker that would
    // describe nothing.
    if room < 8 {
        return floor_boundary(text, cap).to_owned();
    }
    let head = floor_boundary(text, room / 2);
    let tail_start = ceil_boundary(text, text.len() - (room - room / 2));
    if tail_start <= head.len() {
        return floor_boundary(text, cap).to_owned();
    }
    let tail = &text[tail_start..];
    let mut clipped = String::with_capacity(head.len() + PREVIEW_ELISION.len() + tail.len());
    clipped.push_str(head);
    clipped.push_str(PREVIEW_ELISION);
    clipped.push_str(tail);
    clipped
}

/// Clips one command's stdout and stderr to `budget` bytes between them.
///
/// Returns the two streams and whether anything was dropped.
pub fn clip_output(stdout: &str, stderr: &str, budget: usize) -> (String, String, bool) {
    if stdout.len() + stderr.len() <= budget {
        return (stdout.to_owned(), stderr.to_owned(), false);
    }
    // An even split first, then whatever one stream did not use goes to the
    // other. Most commands log everything to a single stream, and a rigid
    // half-and-half would clip the side holding the answer to make room for an
    // empty one.
    let mut stdout_cap = stdout.len().min(budget / 2);
    let mut stderr_cap = stderr.len().min(budget - stdout_cap);
    let spare = budget - stdout_cap - stderr_cap;
    if stdout.len() > stdout_cap {
        stdout_cap += spare.min(stdout.len() - stdout_cap);
    } else {
        stderr_cap += spare.min(stderr.len() - stderr_cap);
    }
    (
        clip_stream(stdout, stdout_cap),
        clip_stream(stderr, stderr_cap),
        true,
    )
}

/// The byte budget one phase's stored previews share.
///
/// A per-command limit alone does not bound a phase, and a total alone does not
/// stop one command from eating all of it. This is the total; the per-command
/// number is passed in per call.
#[derive(Clone, Copy, Debug)]
pub struct PreviewBudget {
    remaining: usize,
}

impl PreviewBudget {
    pub fn new(total: usize) -> Self {
        Self { remaining: total }
    }

    /// Clips one outcome's stored preview to the smaller of `per_command` and
    /// what is left of the phase, then charges it what it actually kept.
    ///
    /// Charging what was kept rather than what was allowed means a phase of
    /// thirty small commands still has budget left for the thirty-first, instead
    /// of the first one consuming the cap by existing.
    pub fn clip(&mut self, outcome: &mut CommandOutcome, per_command: usize) {
        let cap = per_command.min(self.remaining);
        let (stdout, stderr, truncated) = clip_output(&outcome.stdout, &outcome.stderr, cap);
        outcome.stdout = stdout;
        outcome.stderr = stderr;
        outcome.output_preview_truncated |= truncated;
        self.remaining = self
            .remaining
            .saturating_sub(outcome.stdout.len() + outcome.stderr.len());
    }
}

/// Git evidence, bounded to what one run's row can carry.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GitEvidencePreview {
    pub status: String,
    pub diff: String,
    pub changed_files: Vec<String>,
    /// Set when any of the three was clipped, never signalled by an invented
    /// entry standing in for what was dropped.
    pub truncated: bool,
}

/// Bounds the git evidence one run stores to [`MAX_GIT_EVIDENCE_BYTES`].
///
/// One shared budget, spent in a fixed order: status first, then the changed
/// paths, then the diff with whatever is left. Status and the path list answer
/// *whether* the run changed anything, and they are small; a diff only matters
/// once the caller already knows that, and it is the one that is unbounded by
/// nature. Spending the budget the other way round would starve the answer for
/// the detail.
///
/// Changed paths are kept whole or dropped. A half-stored path is not a path -
/// reporting the head of a long filename as though it were the filename is how
/// a caller comes to copy into existence a file the run never touched. Once one
/// path does not fit, the rest are dropped rather than skipped over: a list of
/// the short paths from the middle of a repository is a worse answer than a
/// prefix of it.
pub fn bound_git_evidence(
    status: &str,
    diff: &str,
    changed_files: &[String],
) -> GitEvidencePreview {
    let share = MAX_GIT_EVIDENCE_BYTES / 4;
    let (status, _, status_clipped) = clip_output(status, "", share);

    let mut kept = Vec::new();
    let mut used = 0usize;
    let mut paths_clipped = false;
    for path in changed_files {
        if used + path.len() > share {
            paths_clipped = true;
            break;
        }
        used += path.len();
        kept.push(path.clone());
    }

    let (diff, _, diff_clipped) = clip_output(
        diff,
        "",
        MAX_GIT_EVIDENCE_BYTES.saturating_sub(status.len() + used),
    );
    GitEvidencePreview {
        status,
        diff,
        changed_files: kept,
        truncated: status_clipped || paths_clipped || diff_clipped,
    }
}

/// A machine that outlived its run.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CleanupReport {
    pub sandbox_id: Uuid,
    pub error: String,
}

/// A collected artifact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RunArtifactRef {
    pub name: String,
    pub object_key: String,
    pub size_bytes: i64,
    pub checksum_sha256: Option<String>,
    pub content_type: Option<String>,
}

/// One attempt of a run. A retried run keeps the attempts that did not work.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RunAttempt {
    pub id: Uuid,
    pub run_id: Uuid,
    pub attempt_number: i32,
    pub sandbox_id: Option<Uuid>,
    pub state: RunState,
    pub failure_reason: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Attempt-specific evidence is retained even when a later attempt succeeds.
    #[serde(default)]
    pub placement: Placement,
    #[serde(default)]
    pub results: RunResults,
}

/// An event in a run's history.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RunEvent {
    pub id: Uuid,
    pub run_id: Uuid,
    pub sandbox_id: Option<Uuid>,
    /// `run.created`, `sandbox.assigned`, `task.started`, `artifact.collected`, ...
    pub event_type: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    /// Shapes and names only. Never a value that could be a credential.
    pub detail: serde_json::Value,
}

/// A machine a run used, and what for.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RunSandbox {
    pub run_id: Uuid,
    pub sandbox_id: Uuid,
    pub role: String,
}

/// How many machines a workflow may hold at once.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BatchOptions {
    /// Bounded on purpose: asking for 50 concurrent sandboxes must not be a way
    /// to take the whole cluster, so the scheduler's admission still applies
    /// and this only caps the client's own appetite.
    pub max_parallel: usize,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self { max_parallel: 2 }
    }
}

impl BatchOptions {
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.max_parallel == 0 || self.max_parallel > 64 {
            return Err(crate::CoreError::InvalidRequest(
                "max_parallel must be between 1 and 64".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_terminal_run_cannot_be_moved_back_into_progress() {
        for terminal in [RunState::Succeeded, RunState::Failed, RunState::Cancelled] {
            for next in [
                RunState::Queued,
                RunState::Preparing,
                RunState::Running,
                RunState::Validating,
                RunState::Collecting,
            ] {
                assert!(
                    !terminal.can_transition_to(next),
                    "{terminal:?} must not move to {next:?}"
                );
            }
        }
    }

    #[test]
    fn the_happy_path_is_legal_in_order_and_illegal_out_of_it() {
        let path = [
            RunState::Queued,
            RunState::Preparing,
            RunState::Running,
            RunState::Validating,
            RunState::Collecting,
            RunState::Succeeded,
        ];
        for pair in path.windows(2) {
            assert!(
                pair[0].can_transition_to(pair[1]),
                "{:?}->{:?}",
                pair[0],
                pair[1]
            );
        }
        assert!(!RunState::Queued.can_transition_to(RunState::Succeeded));
        assert!(!RunState::Running.can_transition_to(RunState::Succeeded));
    }

    #[test]
    fn any_active_run_can_be_cancelled() {
        for state in [
            RunState::Queued,
            RunState::Preparing,
            RunState::Running,
            RunState::Validating,
            RunState::Collecting,
        ] {
            assert!(state.can_transition_to(RunState::Cancelled), "{state:?}");
        }
        assert!(!RunState::Succeeded.can_transition_to(RunState::Cancelled));
    }

    #[test]
    fn a_workload_without_a_command_is_not_runnable() {
        let mut workload = WorkloadSpec::default();
        assert!(workload.validate().is_err());
        workload.command = vec!["true".to_owned()];
        assert!(workload.validate().is_ok());
    }

    #[test]
    fn a_repository_url_cannot_carry_a_credential() {
        let ok = RepoSpec {
            url: "https://github.com/o/r.git".into(),
            ..Default::default()
        };
        assert!(ok.validate().is_ok());

        let with_token = RepoSpec {
            url: "https://ghp_secret@github.com/o/r.git".into(),
            ..Default::default()
        };
        assert!(with_token.validate().is_err());

        let not_git = RepoSpec {
            url: "file:///etc/passwd".into(),
            ..Default::default()
        };
        assert!(not_git.validate().is_err());
    }

    #[test]
    fn a_git_reference_cannot_smuggle_shell_syntax() {
        for reference in ["main; rm -rf /", "$(whoami)", "a b", "a|b", "a`b`"] {
            let spec = RepoSpec {
                url: "https://github.com/o/r.git".into(),
                reference: Some(reference.to_owned()),
                ..Default::default()
            };
            assert!(spec.validate().is_err(), "{reference:?} must be refused");
        }
        for reference in ["main", "v1.2.3", "feature/x", "a_b-c"] {
            let spec = RepoSpec {
                url: "https://github.com/o/r.git".into(),
                reference: Some(reference.to_owned()),
                ..Default::default()
            };
            assert!(spec.validate().is_ok(), "{reference:?} must be allowed");
        }
    }

    #[test]
    fn a_capability_requirement_is_never_silently_dropped() {
        let need_microvm = CapabilityRequirements {
            full_kernel_isolation: true,
            ..Default::default()
        };
        let weak = crate::runtime::RuntimeCapabilities::default();
        assert!(
            !need_microvm.satisfied_by(&weak),
            "a process-isolated worker must not satisfy a microVM requirement"
        );
        let strong = crate::runtime::RuntimeCapabilities {
            full_kernel_isolation: true,
            ..Default::default()
        };
        assert!(need_microvm.satisfied_by(&strong));
        assert!(
            need_microvm
                .reasons()
                .contains(&"full kernel isolation required".to_owned())
        );
    }

    #[test]
    fn retention_keeps_failures_but_not_forever() {
        assert!(RetentionPolicy::KeepOnFailure.should_retain(false));
        assert!(!RetentionPolicy::KeepOnFailure.should_retain(true));
        assert!(!RetentionPolicy::Destroy.should_retain(false));
        assert!(RetentionPolicy::KeepAlways.should_retain(true));
    }

    #[test]
    fn parallelism_is_bounded() {
        assert!(BatchOptions { max_parallel: 0 }.validate().is_err());
        assert!(BatchOptions { max_parallel: 65 }.validate().is_err());
        assert!(BatchOptions { max_parallel: 1 }.validate().is_ok());
        assert!(BatchOptions { max_parallel: 64 }.validate().is_ok());
    }

    /// The step count is caller input, and every step's output lands on the run's
    /// own row. A workload asking for more steps than a run can hold used to be
    /// admitted and then persisted as an arbitrarily large document.
    #[test]
    fn a_workload_asking_for_more_steps_than_a_run_can_hold_is_refused() {
        let step = || vec!["true".to_owned()];
        let mut workload = WorkloadSpec {
            command: step(),
            ..Default::default()
        };

        workload.setup = (0..MAX_SETUP_COMMANDS).map(|_| step()).collect();
        assert!(workload.validate().is_ok(), "32 setup steps are allowed");
        workload.setup.push(step());
        assert!(
            matches!(workload.validate(), Err(crate::CoreError::LimitExceeded(_))),
            "33 setup steps must be refused, not trimmed"
        );

        workload.setup.clear();
        workload.validations = (0..MAX_VALIDATION_COMMANDS).map(|_| step()).collect();
        assert!(workload.validate().is_ok(), "32 validations are allowed");
        workload.validations.push(step());
        assert!(matches!(
            workload.validate(),
            Err(crate::CoreError::LimitExceeded(_))
        ));
    }

    /// A clipped preview that cuts a codepoint in half is not a shorter string,
    /// it is a document the caller's own decoder rejects - so both ends are cut
    /// on character boundaries and neither end is thrown away.
    #[test]
    fn a_clipped_preview_keeps_both_ends_and_splits_no_character() {
        let head = "the first thing the build said\n";
        let tail = "the last thing the build said";
        // Four-byte characters, so nearly every byte offset lands inside one and
        // a naive byte slice would produce invalid UTF-8 almost immediately.
        let filler: String = (0..4096)
            .map(|index| char::from_u32('🌍' as u32 + index % 64).expect("astral"))
            .collect();
        let mut full = head.to_owned();
        full.push_str(&filler);
        full.push_str(tail);

        let (stdout, stderr, truncated) = clip_output(&full, "", 1024);
        assert!(truncated);
        assert_eq!(stderr, "", "stderr was empty and stays empty");
        assert!(stdout.len() <= 1024, "stored {} bytes", stdout.len());
        assert!(
            stdout.starts_with(head),
            "the beginning is what went wrong first"
        );
        assert!(stdout.ends_with(tail), "the end is where the reason is");

        assert_eq!(stdout.matches(PREVIEW_ELISION).count(), 1);
        let (before, after) = stdout
            .split_once(PREVIEW_ELISION)
            .expect("exactly one elision");
        let kept_head = before.strip_prefix(head).expect("the head is kept whole");
        let kept_tail = after.strip_suffix(tail).expect("the tail is kept whole");
        assert!(
            kept_head.chars().all(|c| c.len_utf8() == 4) && !kept_head.is_empty(),
            "kept head must be whole four-byte characters"
        );
        assert!(
            kept_tail.chars().all(|c| c.len_utf8() == 4) && !kept_tail.is_empty(),
            "kept tail must be whole four-byte characters"
        );
    }

    /// The whole point of a separate flag. A command that exited 0 and ran to
    /// completion is a pass; folding "the stored preview was clipped" into the
    /// outcome would report every successful build as a failure the moment its
    /// log outgrew the budget.
    #[test]
    fn clipping_a_stored_preview_does_not_turn_a_passing_command_into_a_failure() {
        let mut outcome = CommandOutcome {
            command: vec!["make".to_owned()],
            exit_code: 0,
            stdout: "compiling\n".repeat(100_000),
            stderr: "warning: deprecated\n".repeat(4_000),
            duration_ms: 42_000,
            truncated: false,
            output_preview_truncated: false,
            ok: true,
        };
        PreviewBudget::new(MAX_TASK_PREVIEW_BYTES).clip(&mut outcome, MAX_TASK_PREVIEW_BYTES);

        assert!(outcome.output_preview_truncated);
        assert!(
            !outcome.truncated,
            "clipping what we stored says nothing about the machine"
        );
        assert!(outcome.ok, "a passing command stays passing");
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.len() + outcome.stderr.len() <= MAX_TASK_PREVIEW_BYTES);
    }

    /// The acceptance that matters: a run's stored evidence is bounded by
    /// construction, whatever the step count and whatever the machine printed.
    #[test]
    fn a_run_whose_every_phase_floods_still_fits_its_results_budget() {
        let flood = || "a line of build noise\n".repeat(crate::MAX_STDOUT / 21);
        let mut stored = 0usize;

        let mut setup_budget = PreviewBudget::new(MAX_SETUP_PREVIEW_BYTES);
        let setup: Vec<CommandOutcome> = (0..MAX_SETUP_COMMANDS)
            .map(|_| {
                let mut outcome = CommandOutcome {
                    stdout: flood(),
                    ok: true,
                    ..Default::default()
                };
                setup_budget.clip(&mut outcome, MAX_SETUP_COMMAND_PREVIEW_BYTES);
                stored += outcome.stdout.len() + outcome.stderr.len();
                outcome
            })
            .collect();
        assert!(
            setup.iter().all(|outcome| outcome.output_preview_truncated),
            "every flooding setup step must say it was clipped"
        );

        let mut validation_budget = PreviewBudget::new(MAX_VALIDATION_PREVIEW_BYTES);
        let validations: Vec<CommandOutcome> = (0..MAX_VALIDATION_COMMANDS)
            .map(|_| {
                let mut outcome = CommandOutcome {
                    stdout: flood(),
                    ok: true,
                    ..Default::default()
                };
                validation_budget.clip(&mut outcome, MAX_VALIDATION_COMMAND_PREVIEW_BYTES);
                stored += outcome.stdout.len() + outcome.stderr.len();
                outcome
            })
            .collect();

        let mut task = CommandOutcome {
            stdout: flood(),
            stderr: flood(),
            ok: true,
            ..Default::default()
        };
        PreviewBudget::new(MAX_TASK_PREVIEW_BYTES).clip(&mut task, MAX_TASK_PREVIEW_BYTES);
        assert!(task.output_preview_truncated);
        stored += task.stdout.len() + task.stderr.len();

        let changed: Vec<String> = (0..50_000)
            .map(|index| format!("src/module{index}/source_file.rs"))
            .collect();
        let evidence = bound_git_evidence(
            &changed
                .iter()
                .map(|path| format!(" M {path}\n"))
                .collect::<String>(),
            &"+ an added line\n".repeat(200_000),
            &changed,
        );
        assert!(evidence.truncated);
        stored += evidence.status.len()
            + evidence.diff.len()
            + evidence
                .changed_files
                .iter()
                .map(String::len)
                .sum::<usize>();

        assert!(
            stored <= MAX_RESULTS_PREVIEW_BYTES,
            "stored {stored} bytes of evidence, ceiling is {MAX_RESULTS_PREVIEW_BYTES}"
        );
        assert!(
            validations
                .iter()
                .all(|outcome| outcome.output_preview_truncated),
            "every flooding validation must say it was clipped"
        );
    }

    /// A path that was never reported is worse than a missing path: a caller
    /// reads the list and acts on it. So paths are kept whole or dropped, the
    /// drop is visible, and nothing stands in for it.
    #[test]
    fn clipped_git_evidence_is_visible_and_reports_no_path_it_did_not_see() {
        let changed: Vec<String> = (0..50_000)
            .map(|index| format!("src/module{index}/source_file.rs"))
            .collect();
        let status = changed
            .iter()
            .map(|path| format!(" M {path}\n"))
            .collect::<String>();
        let diff = "+ an added line\n".repeat(200_000);

        let bounded = bound_git_evidence(&status, &diff, &changed);

        assert!(bounded.truncated);
        assert!(
            bounded.status.len()
                + bounded.diff.len()
                + bounded.changed_files.iter().map(String::len).sum::<usize>()
                <= MAX_GIT_EVIDENCE_BYTES
        );
        assert!(!bounded.changed_files.is_empty());
        // A prefix of what git reported: every entry is one it actually printed,
        // byte for byte, and the cut stops rather than skipping.
        assert_eq!(
            bounded.changed_files,
            changed[..bounded.changed_files.len()]
        );
        assert!(bounded.changed_files.len() < changed.len());
    }
}
