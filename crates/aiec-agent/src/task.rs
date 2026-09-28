//! The task an agent is handed, and the result it hands back.
//!
//! Both are small JSON documents read from and written to fixed paths, because
//! the harness has no configuration surface worth the cost: a VM that is about
//! to be destroyed should not need a settings file to be useful.
//!
//! The result is the only thing the outside world gets, so it is designed to be
//! read by a program rather than by a person: a verdict, the evidence behind
//! it, and a diff.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The work to do.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    /// What the agent is being asked to accomplish, in the task author's words.
    pub instruction: String,
    /// Repository the agent works in. Defaults to the current directory.
    #[serde(default)]
    pub repo_path: Option<String>,
    /// Commands run after the agent finishes, to decide whether it worked.
    #[serde(default)]
    pub validations: Vec<Vec<String>>,
    /// A ceiling on agent turns, so a confused model cannot spend a VM's whole
    /// budget discovering that.
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
    /// A ceiling on model requests, separately from turns, so a turn that makes
    /// several calls is bounded too.
    #[serde(default = "default_max_requests")]
    pub max_requests: u32,
    /// Ceiling on one tool result, in bytes, before it is compressed.
    #[serde(default = "default_max_tool_output")]
    pub max_tool_output_bytes: usize,
    /// Which model to use. Overrides the ambient configuration when present,
    /// because a task that names a model should get that model.
    #[serde(default)]
    pub model: Option<ModelChoice>,
    /// Free-form hints kept out of the system prompt, injected once near the
    /// start so they survive context compaction intact.
    #[serde(default)]
    pub context_notes: Vec<String>,
}

fn default_max_turns() -> u32 {
    64
}
fn default_max_requests() -> u32 {
    256
}
fn default_max_tool_output() -> usize {
    64 * 1024
}
#[allow(dead_code, reason = "reached through serde")]
fn default_max_tool_output_bytes() -> usize {
    64 * 1024
}

impl Task {
    /// Reads a task document, refusing a file that is not a task.
    pub fn load(path: &Path) -> Result<Self, HarnessError> {
        let bytes = std::fs::read(path)
            .map_err(|error| HarnessError::Io(format!("reading {}: {error}", path.display())))?;
        if bytes.len() > 1024 * 1024 {
            return Err(HarnessError::Task(
                "the task document is larger than 1 MiB".to_owned(),
            ));
        }
        let task: Self = serde_json::from_slice(&bytes)
            .map_err(|error| HarnessError::Task(format!("invalid task document: {error}")))?;
        if task.instruction.trim().is_empty() {
            return Err(HarnessError::Task("the task has no instruction".to_owned()));
        }
        Ok(task)
    }

    /// The repository the agent works in.
    pub fn repo(&self) -> std::path::PathBuf {
        self.repo_path
            .as_deref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    }
}

/// Which model to talk to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelChoice {
    #[serde(default)]
    pub provider: Option<String>,
    pub model: String,
    /// Reasoning effort, for providers that have it. Passed through rather than
    /// interpreted: the harness does not know what "medium" means for a provider
    /// it has never heard of.
    #[serde(default)]
    pub reasoning: Option<String>,
}

/// What the agent produced.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Result_ {
    pub ok: bool,
    pub turns: u32,
    pub requests: u32,
    /// Why the agent stopped. This is the field an operator reads first.
    pub stop_reason: StopReason,
    #[serde(default)]
    pub summary: String,
    /// Per-validation outcome, keyed by the command as written.
    pub validations: Vec<ValidationOutcome>,
    #[serde(default)]
    pub git: GitEvidence,
    #[serde(default)]
    pub usage: Usage,
    /// Only the tail of the transcript: enough to reconstruct a decision,
    /// bounded so the result cannot grow with the run.
    #[serde(default)]
    pub events: Vec<Event>,
    /// Set when the run ended in a way the harness considers a failure of the
    /// harness rather than of the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Harness version, so a result can be matched to the code that made it.
    pub harness_version: String,
}

impl Default for Result_ {
    fn default() -> Self {
        Self {
            ok: false,
            turns: 0,
            requests: 0,
            stop_reason: StopReason::Error,
            summary: String::new(),
            validations: Vec::new(),
            git: GitEvidence::default(),
            usage: Usage::default(),
            events: Vec::new(),
            error: None,
            harness_version: crate::HARNESS_VERSION.to_owned(),
        }
    }
}

impl Result_ {
    /// Writes the result document.
    ///
    /// Written once, atomically, because a half-written result is worse than
    /// none: whatever reads it would believe the run finished.
    pub fn save(&self, path: &Path) -> Result<(), HarnessError> {
        let text = serde_json::to_vec_pretty(self)
            .map_err(|error| HarnessError::Io(format!("encoding result: {error}")))?;
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, &text)
            .map_err(|error| HarnessError::Io(format!("writing result: {error}")))?;
        std::fs::rename(&temporary, path)
            .map_err(|error| HarnessError::Io(format!("publishing result: {error}")))?;
        Ok(())
    }
}

/// Why the loop ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The model said it was finished.
    ModelFinished,
    /// Every validation passed and the model agreed.
    TaskComplete,
    /// Out of turns.
    TurnBudget,
    /// Out of model requests.
    RequestBudget,
    /// The model repeated itself, so continuing would only cost tokens.
    LoopDetected,
    /// Nothing changed for a while, so continuing would not help.
    NoProgress,
    /// A model request failed too many times.
    ModelUnavailable,
    /// The harness itself failed.
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationOutcome {
    pub command: Vec<String>,
    pub exit_code: i32,
    pub ok: bool,
    #[serde(default)]
    pub duration_ms: u64,
    /// Trimmed, because a validation's job is its exit code, not its log.
    #[serde(default)]
    pub output_tail: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GitEvidence {
    #[serde(default)]
    pub head_before: Option<String>,
    #[serde(default)]
    pub head_after: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub diff: String,
    #[serde(default)]
    pub changed_files: Vec<String>,
    #[serde(default)]
    pub diff_truncated: bool,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub requests: u32,
}

/// One thing that happened, as a program-readable record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub at: chrono::DateTime<chrono::Utc>,
    pub turn: u32,
    #[serde(rename = "type")]
    pub kind: EventKind,
    /// Short and never a secret. Credentials do not belong in a transcript that
    /// gets written to disk and shipped back to the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "name", rename_all = "snake_case")]
pub enum EventKind {
    Started { harness: String },
    Turn,
    Request { model: String },
    ToolCall { tool: String },
    ToolResult { tool: String, ok: bool },
    Validation { ok: bool },
    Compacted { from: u32, to: u32 },
    Stopped { reason: StopReason },
    Failed { message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("io: {0}")]
    Io(String),
    #[error("task: {0}")]
    Task(String),
    #[error("model: {0}")]
    Model(String),
    #[error("tool: {0}")]
    Tool(String),
    #[error("configuration: {0}")]
    Config(String),
    #[error("budget: {0}")]
    Budget(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_without_an_instruction_is_refused() {
        let task = Task {
            instruction: "   ".to_owned(),
            repo_path: None,
            validations: Vec::new(),
            max_turns: 4,
            max_requests: 4,
            max_tool_output_bytes: 16,
            model: None,
            context_notes: Vec::new(),
        };
        let path = std::env::temp_dir().join(format!("aiec-task-{}.json", uuid::Uuid::now_v7()));
        std::fs::write(&path, serde_json::to_vec(&task).unwrap()).unwrap();
        assert!(
            Task::load(&path).is_err(),
            "a blank instruction must be refused"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_task_round_trips_through_its_document() {
        let task = Task {
            instruction: "fix the failing test".to_owned(),
            repo_path: Some("/workspace/repository".to_owned()),
            validations: vec![vec!["cargo".to_owned(), "test".to_owned()]],
            max_turns: 8,
            max_requests: 16,
            max_tool_output_bytes: 1024,
            model: Some(ModelChoice {
                provider: None,
                model: "stub".to_owned(),
                reasoning: None,
            }),
            context_notes: vec!["the parser is hand written".to_owned()],
        };
        let path = std::env::temp_dir().join(format!("aiec-task-{}.json", uuid::Uuid::now_v7()));
        std::fs::write(&path, serde_json::to_vec(&task).unwrap()).unwrap();
        let loaded = Task::load(&path).expect("valid task");
        assert_eq!(loaded.instruction, task.instruction);
        assert_eq!(loaded.validations, task.validations);
        assert_eq!(
            loaded.repo(),
            std::path::PathBuf::from("/workspace/repository")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_result_is_written_atomically() {
        let path = std::env::temp_dir().join(format!("aiec-result-{}.json", uuid::Uuid::now_v7()));
        let result = Result_ {
            ok: true,
            stop_reason: StopReason::TaskComplete,
            summary: "done".to_owned(),
            ..Default::default()
        };
        result.save(&path).expect("saved");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("task_complete"));
        // The temporary file must not survive the publish.
        assert!(!path.with_extension("json.tmp").exists());
        let _ = std::fs::remove_file(path);
    }
}
