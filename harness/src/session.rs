//! Session state on disk, so a crashed run is resumable.
//!
//! What is persisted is deliberately not the transcript. A raw context is large,
//! mostly redundant with the repository it describes, and the one thing it
//! cannot be trusted for is recovering after a crash — the model's memory did
//! not survive either. What is worth keeping is the structured state, the usage
//! so far, and the identity of the task, because those are what make a second
//! attempt meaningfully better than the first.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::HarnessError;
use crate::context::TaskState;

/// Written incrementally as the session runs, so a VM that dies leaves a usable
/// file rather than a truncated one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub protocol: u32,
    pub task_id: String,
    pub task_digest: String,
    /// The instruction, so a resume knows what it is resuming. Not a secret.
    pub instruction: String,
    pub state: TaskState,
    pub usage: crate::model::Usage,
    pub turns_completed: u32,
    pub tool_calls: u64,
    pub model: String,
    pub provider: String,
    /// A short note of what the model was in the middle of. Never the model key.
    pub last_summary: Option<String>,
    pub completed: bool,
}

impl SessionState {
    pub fn new(task: &crate::task::Task, model: &str, provider: &str) -> Self {
        Self {
            protocol: crate::PROTOCOL_VERSION,
            task_id: task.task_id.clone(),
            task_digest: task.digest.clone(),
            instruction: task.instruction.clone(),
            state: TaskState::new(task.instruction.clone()),
            usage: crate::model::Usage::default(),
            turns_completed: 0,
            tool_calls: 0,
            model: model.to_owned(),
            provider: provider.to_owned(),
            last_summary: None,
            completed: false,
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut value = serde_json::to_value(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // A tool observation can contain anything the repository contained,
        // including a credential someone left in a file. Scrub before it lands.
        crate::redaction::scrub_value(&mut value);
        let json = serde_json::to_vec_pretty(&value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let temp = path.with_extension("json.partial");
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&temp, json)?;
        std::fs::rename(&temp, path)
    }

    /// Reads a previous session, if there is one worth resuming.
    ///
    /// A state file from a different task, a different protocol, or a run that
    /// already finished is not resumable, and pretending otherwise would
    /// silently continue the wrong work.
    pub fn load(path: &Path) -> Result<Option<Self>, HarnessError> {
        if !path.exists() {
            return Ok(None);
        }
        // Read bytes, not text. A file that is not valid UTF-8 is still just a
        // file, and it still must not be able to fail the run; going through
        // `read_to_string` turned a corrupt state file into an error, which is
        // precisely what this function promises never to do.
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(HarnessError::io(path.display().to_string(), error)),
        };
        let Ok(raw) = String::from_utf8(bytes) else {
            return Ok(None);
        };
        match serde_json::from_str::<Self>(&raw) {
            Ok(state) if state.protocol != crate::PROTOCOL_VERSION => Ok(None),
            Ok(state) if state.completed => Ok(None),
            Ok(state) => Ok(Some(state)),
            // A half-written or hand-edited state file is not a reason to fail
            // the run; it just means there is nothing to resume from.
            Err(_) => Ok(None),
        }
    }

    /// Whether this state belongs to the task being run now.
    pub fn matches(&self, task: &crate::task::Task) -> bool {
        self.task_digest == task.digest && self.task_id == task.task_id
    }
}
