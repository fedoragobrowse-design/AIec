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
                | (Running, Validating | Collecting | Failed)
                | (Validating, Collecting | Failed)
                // A run with no validations still has to collect, so
                // `running -> collecting` is covered by the arm above.
                | (Collecting, Succeeded | Failed)
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
    /// A workload is only runnable once it says what to run.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
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
        let acceptable =
            url.starts_with("https://") || url.starts_with("git@") || url.starts_with("ssh://");
        if !acceptable {
            return Err(crate::CoreError::InvalidRequest(
                "a repository must be an https, git@ or ssh git remote".into(),
            ));
        }
        if url.contains('@') && url.starts_with("https://") {
            return Err(crate::CoreError::InvalidRequest(
                "a repository URL must not carry credentials".into(),
            ));
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
}
