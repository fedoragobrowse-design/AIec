//! The result document: what leaves the VM.
//!
//! An evaluator should never have to scrape terminal text. Everything it needs
//! to decide whether the task passed is here, including the git evidence.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Validation passed, or there was nothing to validate.
    Success,
    /// The harness ran correctly and the task did not get done.
    Failed,
    /// The harness itself could not proceed.
    Error,
}

/// One validation command's outcome. Run by the harness, after the agent claims
/// it is done, and never on the model's word alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationOutcome {
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub timed_out: bool,
    pub duration_ms: u64,
    /// Bounded, same as everything else the model would see.
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub ok: bool,
}

/// The repository state, captured before and after.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitEvidence {
    pub head_before: Option<String>,
    pub head_after: Option<String>,
    pub branch: Option<String>,
    /// What the session changed, EXCLUDING the harness's own bookkeeping.
    pub changed_files: Vec<String>,
    /// The harness's own artifacts, listed separately rather than mixed in.
    ///
    /// They are real files and hiding them entirely would be dishonest, but
    /// counting a result document as something the agent did would corrupt the
    /// one field an evaluator reads to judge the work.
    pub harness_artifacts: Vec<String>,
    pub diff: String,
    pub diff_truncated: bool,
    pub is_repository: bool,
}

/// The metrics the spec asks every session to expose.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metrics {
    pub wall_ms: u64,
    /// Time spent waiting on the provider. Almost always the bulk of wall_ms.
    pub model_latency_ms: u64,
    /// Time the harness itself spent: dispatch, context building, encoding.
    pub harness_cpu_ms: u64,
    pub peak_rss_bytes: Option<u64>,
    pub model_requests: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub tool_calls: BTreeMap<String, u64>,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub shell_commands: u64,
    pub compactions: u32,
    /// High-water mark of the context estimate, in tokens.
    pub context_peak_tokens: u64,
    pub tool_failures: u64,
}

/// Everything needed to reproduce or attribute a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub harness_version: String,
    pub protocol: u32,
    pub provider: String,
    pub model: String,
    pub task_digest: String,
    pub config_digest: String,
    pub repository_start_commit: Option<String>,
}

/// The document written to `--result`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    pub task_id: String,
    pub status: Status,
    pub stop_reason: String,
    pub validation: Vec<ValidationOutcome>,
    pub git: GitEvidence,
    pub metrics: Metrics,
    pub provenance: Provenance,
    /// Set only when the harness itself could not proceed.
    pub failure: Option<String>,
}

impl Result {
    /// The all-clear variant, for the paths that never touch a repository.
    pub fn for_error(task_id: &str, provenance: Provenance, message: impl Into<String>) -> Self {
        Self {
            task_id: task_id.to_owned(),
            status: Status::Error,
            stop_reason: "harness_error".to_owned(),
            validation: Vec::new(),
            git: GitEvidence::default(),
            metrics: Metrics::default(),
            provenance,
            failure: Some(message.into()),
        }
    }

    /// Writes atomically: a result half-written when the VM dies is worse than
    /// no result, because the collector cannot tell it apart from a valid one.
    pub fn write_to(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let temp = path.with_extension("json.partial");
        std::fs::write(&temp, &json)?;
        std::fs::rename(&temp, path)
    }

    /// The stdout summary. Deliberately short: the detail is in the JSON.
    pub fn summary_line(&self) -> String {
        let changed = self.git.changed_files.len();
        match self.status {
            Status::Success => format!(
                "[done] {} changed, {} tool calls, {} model requests, {} ms",
                changed,
                self.metrics.tool_calls.values().sum::<u64>(),
                self.metrics.model_requests,
                self.metrics.wall_ms
            ),
            Status::Failed => format!(
                "[incomplete] {} changed, stopped: {}",
                changed, self.stop_reason
            ),
            Status::Error => format!("[error] {}", self.failure.as_deref().unwrap_or("unknown")),
        }
    }
}
