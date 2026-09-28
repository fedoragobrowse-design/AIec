//! The OMP adapter: a thin layer over the generic run machinery.
//!
//! OMP is the first serious user of this platform, not a special case in it.
//! Everything here expands an OMP-shaped request into ordinary runs and reads
//! the results back, so the next agent to evaluate costs a small adapter rather
//! than a second scheduler. Nothing below this module knows what OMP is.
//!
//! The adapter never decides which revision is better. It reports what each side
//! did; picking a metric is the caller's job, because "better" depends on what
//! the caller is optimising for and an evaluation that quietly picks for them is
//! one they cannot trust.

use std::collections::{BTreeMap, BTreeSet};

use aiec_core::TenantId;
use aiec_core::run::{RepoSpec, RetentionPolicy, RunState, WorkloadSpec};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::eval_matrix::{CellResult, MatrixCell, MatrixResult, MatrixSpec, run_matrix};
use crate::runs::RunRequest;
use crate::{AppState, CoreError};

/// One OMP evaluation: a revision of the agent, against a task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OmpRunSpec {
    /// The agent repository, cloned and built inside the sandbox.
    pub omp_repo: String,
    /// The revision under evaluation.
    pub omp_ref: String,
    /// The task, in natural language, handed to the agent.
    pub task: String,
    /// The repository the agent works in.
    pub target_repo: String,
    #[serde(default)]
    pub target_ref: Option<String>,
    /// Prepares the agent before it runs.
    #[serde(default)]
    pub setup_command: Option<Vec<String>>,
    /// Runs the agent. Defaults to `omp run` with the task on stdin.
    #[serde(default)]
    pub omp_command: Option<Vec<String>>,
    /// Checked after the agent finishes. All of them run, even after one fails.
    #[serde(default)]
    pub validations: Vec<Vec<String>>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

fn default_repetitions() -> u32 {
    1
}
fn default_parallel() -> usize {
    2
}

/// Two revisions of the same agent, measured against the same task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OmpComparisonSpec {
    pub baseline: OmpRunSpec,
    pub candidate: OmpRunSpec,
    /// How many times each side runs. An agent is nondeterministic, so one run
    /// of each is an anecdote.
    #[serde(default = "default_repetitions")]
    pub repetitions: u32,
    #[serde(default = "default_parallel")]
    pub max_parallel: usize,
}

/// The default agent invocation.
///
/// Documented rather than clever: a caller overrides it when the agent's CLI
/// differs, and the command that actually ran is visible in the run's results
/// so nobody has to guess.
pub const DEFAULT_OMP_COMMAND: &[&str] = &["omp", "run"];

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Turns an OMP run into an ordinary workload.
///
/// The agent is cloned and built as *setup*, the task is the *command*, and the
/// checks are *validations* — three things the platform already schedules. The
/// only OMP-specific part left is the command itself.
pub fn to_run_request(spec: &OmpRunSpec) -> RunRequest {
    // A caller's setup is one command; the workload takes a list of them.
    let setup = spec
        .setup_command
        .clone()
        .map(|command| vec![command])
        .unwrap_or_else(|| {
            vec![vec![
                "/bin/sh".to_owned(),
                "-lc".to_owned(),
                format!(
                    "set -e; git clone --depth 1 --branch {r} {repo} /workspace/omp && \
                 cd /workspace/omp && (bun install && bun run build || true)",
                    r = shell_quote(&spec.omp_ref),
                    repo = shell_quote(&spec.omp_repo),
                ),
            ]]
        });

    let command = spec.omp_command.clone().unwrap_or_else(|| {
        DEFAULT_OMP_COMMAND
            .iter()
            .map(|part| (*part).to_owned())
            .collect()
    });

    RunRequest {
        workload: WorkloadSpec {
            repo: Some(RepoSpec {
                url: spec.target_repo.clone(),
                reference: spec.target_ref.clone(),
                ..Default::default()
            }),
            setup,
            command,
            validations: spec.validations.clone(),
            git_evidence: true,
            timeout_seconds: spec.timeout_seconds.or(Some(1800)),
            ..Default::default()
        },
        // A failed evaluation is exactly the one worth opening the machine for.
        retention: RetentionPolicy::KeepOnFailure,
        ..Default::default()
    }
}

/// One side's measurements across its repetitions.
#[derive(Clone, Debug, Serialize)]
pub struct OmpSideReport {
    pub label: String,
    pub revision: String,
    pub total_runs: u32,
    pub successful_runs: u32,
    pub failed_runs: u32,
    pub exit_codes: Vec<i32>,
    pub wall_time_ms: u64,
    /// Sandboxes retained for debugging, so a failure can be opened.
    pub retained_sandbox_ids: Vec<Uuid>,
}

/// A comparison, reported as measurements and nothing more.
#[derive(Clone, Debug, Serialize)]
pub struct OmpComparisonReport {
    pub evaluation_id: Uuid,
    pub requested_at: DateTime<Utc>,
    pub baseline: OmpSideReport,
    pub candidate: OmpSideReport,
    pub max_parallel: usize,
}

impl OmpComparisonReport {
    /// Success counts per side. Deliberately no winner.
    pub fn counts(&self) -> BTreeMap<&'static str, (u32, u32)> {
        BTreeMap::from([
            (
                "baseline",
                (self.baseline.successful_runs, self.baseline.total_runs),
            ),
            (
                "candidate",
                (self.candidate.successful_runs, self.candidate.total_runs),
            ),
        ])
    }
}

/// Runs a baseline and a candidate against the same task.
pub async fn compare(
    state: &AppState,
    tenant: TenantId,
    spec: &OmpComparisonSpec,
) -> Result<OmpComparisonReport, CoreError> {
    if spec.repetitions == 0 {
        return Err(CoreError::InvalidRequest(
            "repetitions must be at least one".into(),
        ));
    }
    if spec.baseline.task != spec.candidate.task {
        return Err(CoreError::InvalidRequest(
            "a comparison must give both sides the same task".into(),
        ));
    }

    let evaluation_id = Uuid::now_v7();
    let mut cells: Vec<MatrixCell> = Vec::new();
    for repetition in 0..spec.repetitions {
        for (label, side) in [("baseline", &spec.baseline), ("candidate", &spec.candidate)] {
            let mut axis = BTreeMap::new();
            axis.insert("side".to_owned(), label.to_owned());
            axis.insert("revision".to_owned(), side.omp_ref.clone());
            axis.insert("repetition".to_owned(), repetition.to_string());
            let mut request = to_run_request(side);
            request.matrix_id = Some(evaluation_id);
            // Every cell gets its own key: a shared one would hand the second
            // repetition the first one's run, and nothing would execute.
            request.idempotency_key = Some(format!("eval-{evaluation_id}-{label}-{repetition}"));
            cells.push(MatrixCell { axis, request });
        }
    }

    let matrix = MatrixSpec {
        cells,
        options: aiec_core::run::BatchOptions {
            max_parallel: spec.max_parallel.max(1),
        },
    };
    let result = run_matrix(state, tenant, &matrix).await?;

    Ok(OmpComparisonReport {
        evaluation_id,
        requested_at: Utc::now(),
        baseline: summarise(
            "baseline",
            &spec.baseline.omp_ref,
            side_of(&result, "baseline"),
        ),
        candidate: summarise(
            "candidate",
            &spec.candidate.omp_ref,
            side_of(&result, "candidate"),
        ),
        max_parallel: matrix.options.max_parallel,
    })
}

fn side_of<'a>(result: &'a MatrixResult, side: &'a str) -> Vec<&'a CellResult> {
    result
        .results
        .iter()
        .filter(|cell| cell.axis.get("side").map(String::as_str) == Some(side))
        .collect()
}

fn summarise(label: &str, revision: &str, cells: Vec<&CellResult>) -> OmpSideReport {
    let mut report = OmpSideReport {
        label: label.to_owned(),
        revision: revision.to_owned(),
        total_runs: cells.len() as u32,
        successful_runs: 0,
        failed_runs: 0,
        exit_codes: Vec::new(),
        wall_time_ms: 0,
        retained_sandbox_ids: Vec::new(),
    };
    let mut seen: BTreeSet<Uuid> = BTreeSet::new();
    for cell in cells {
        if cell.succeeded {
            report.successful_runs += 1;
        } else {
            report.failed_runs += 1;
        }
        if let Some(sandbox) = cell.sandbox_id
            && seen.insert(sandbox)
        {
            report.retained_sandbox_ids.push(sandbox);
        }
        if cell.state == RunState::Failed {
            report.exit_codes.push(1);
        }
    }
    report
}

/// Loads a suite from a reviewable JSON document.
///
/// Not a bespoke language: a suite has to be readable in a pull request, and a
/// format nobody can read is a format nobody reviews.
pub fn load_suite(contents: &str) -> Result<OmpComparisonSpec, CoreError> {
    serde_json::from_str(contents)
        .map_err(|error| CoreError::InvalidRequest(format!("invalid suite: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> OmpRunSpec {
        OmpRunSpec {
            omp_repo: "https://github.com/can1357/oh-my-pi".into(),
            omp_ref: "v18.3.5".into(),
            task: "fix the flaky test".into(),
            target_repo: "https://github.com/me/fixture".into(),
            target_ref: None,
            setup_command: None,
            omp_command: None,
            validations: vec![vec!["bun".into(), "test".into()]],
            timeout_seconds: None,
        }
    }

    #[test]
    fn an_omp_run_becomes_an_ordinary_workload() {
        let request = to_run_request(&spec());
        assert_eq!(request.workload.command, vec!["omp", "run"]);
        assert_eq!(request.workload.setup.len(), 1);
        assert_eq!(request.workload.validations.len(), 1);
        assert!(request.workload.git_evidence);
        assert_eq!(request.retention, RetentionPolicy::KeepOnFailure);
    }

    #[test]
    fn a_hostile_revision_cannot_escape_the_setup_script() {
        let mut hostile = spec();
        hostile.omp_ref = "main; rm -rf /".into();
        let request = to_run_request(&hostile);
        let script = request.workload.setup[0][2].clone();
        // Quoted, so the semicolon is data rather than a command.
        assert!(script.contains("'main; rm -rf /'"), "script was: {script}");
    }

    #[test]
    fn a_suite_loads_from_reviewable_json() {
        let comparison = OmpComparisonSpec {
            baseline: spec(),
            candidate: spec(),
            repetitions: 3,
            max_parallel: 2,
        };
        let json = serde_json::to_string(&comparison).expect("serialises");
        let loaded = load_suite(&json).expect("round-trips");
        assert_eq!(loaded.repetitions, 3);
        assert_eq!(loaded.baseline.omp_ref, "v18.3.5");
    }
}
