//! The event stream: one JSON object per line, written as it happens.
//!
//! AIec collects this as an artifact. It is written incrementally so a VM that
//! dies mid-run still leaves behind everything up to that point.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;

/// Appends JSONL events. Cheap enough to hold a lock and write a line.
pub struct EventLog {
    sink: Mutex<Option<std::fs::File>>,
    verbose: bool,
}

impl EventLog {
    /// `path` may be `None`, in which case events are dropped and only the
    /// concise human summary reaches stdout.
    pub fn open(path: Option<&Path>) -> std::io::Result<Self> {
        let file = match path {
            Some(p) => {
                if let Some(parent) = p.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)?;
                }
                Some(std::fs::File::create(p)?)
            }
            None => None,
        };
        Ok(Self {
            sink: Mutex::new(file),
            verbose: std::env::var_os("AIEC_AGENT_VERBOSE").is_some(),
        })
    }

    pub fn emit<T: Serialize>(&self, event: T) {
        let Ok(mut guard) = self.sink.lock() else {
            // A poisoned lock means a previous write panicked. Dropping events
            // is strictly better than taking the session down over telemetry.
            return;
        };
        let Some(file) = guard.as_mut() else { return };
        // A failure to serialize one event must not end the run.
        let Ok(line) = serde_json::to_string(&event) else {
            return;
        };
        let _ = writeln!(file, "{line}");
        // Flushed per line: the whole point is surviving an abrupt exit.
        let _ = file.flush();
    }

    pub fn verbose(&self) -> bool {
        self.verbose
    }
}

/// The event shapes. Kept as one enum so the stream cannot drift into
/// undocumented shapes.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event<'a> {
    SessionStarted {
        task_id: &'a str,
        provider: &'a str,
        model: &'a str,
        protocol: u32,
    },
    RepositoryInspected {
        root: &'a str,
        is_repository: bool,
        branch: Option<&'a str>,
        head: Option<&'a str>,
        dirty: bool,
    },
    ModelRequestStarted {
        turn: u32,
        context_tokens: u64,
        message_count: usize,
    },
    ModelRequestFinished {
        turn: u32,
        latency_ms: u64,
        input_tokens: u64,
        output_tokens: u64,
        tool_calls: usize,
    },
    ToolStarted {
        turn: u32,
        name: &'a str,
    },
    ToolFinished {
        turn: u32,
        name: &'a str,
        ok: bool,
        bytes: u64,
        detail: Option<&'a str>,
    },
    ContextCompacted {
        turn: u32,
        before_tokens: u64,
        after_tokens: u64,
    },

    SteeringApplied {
        turn: u32,
        note: &'a str,
    },
    ValidationsStarted {
        count: usize,
    },
    ValidationFinished {
        index: usize,
        argv: &'a [String],
        ok: bool,
        exit_code: i32,
        duration_ms: u64,
    },
    SessionCompleted {
        status: &'a str,
        stop_reason: &'a str,
        wall_ms: u64,
    },
}

/// The concise line a human sees on stdout. Machine detail goes to JSONL.
pub struct Stderr {
    pub quiet: bool,
}

impl Stderr {
    pub fn from_env() -> Self {
        Self {
            quiet: std::env::var_os("AIEC_AGENT_QUIET").is_some(),
        }
    }

    pub fn say(&self, message: &str) {
        if !self.quiet {
            eprintln!("{message}");
        }
    }
}

/// Where the default artifacts land, inside the workspace, so a resumed session
/// finds what the previous one wrote.
pub fn default_event_path(workspace: &Path) -> PathBuf {
    workspace.join(".aiec-agent/events.jsonl")
}

pub fn default_state_path(workspace: &Path) -> PathBuf {
    workspace.join(".aiec-agent/session.json")
}

/// Where a caller drops steering notes mid-session.
///
/// A file rather than a socket or a signal: the harness already runs one
/// process with no daemon, and a control channel would contradict that. The
/// caller writes a line, the loop picks it up on its next turn, and the note is
/// gone once consumed.
pub fn default_steer_path(workspace: &Path) -> PathBuf {
    workspace.join(".aiec-agent/steer")
}

/// Takes any steering notes that have arrived, leaving the file empty.
///
/// Returns the notes concatenated, or `None` when there are none. Errors are
/// swallowed: a caller that cannot write the file has not broken the session,
/// and failing the run over a missing optional hint would be absurd.
///
/// Notes are capped at 8 KiB and scrubbed: the steering file is
/// operator-writable and model-adjacent, so a note bigger than the cap is a
/// caller mistake refused here, and any secret the caller pasted is redacted
/// before the model sees it. Cap lives in `MAX_STEERING_BYTES`.
pub const MAX_STEERING_BYTES: usize = 8 * 1024;
pub fn take_steering(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    // Truncate first, then use: a note is consumed once, and a caller that
    // appends while we read must not have its next hint silently eaten.
    let _ = std::fs::write(path, b"");
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() > MAX_STEERING_BYTES {
        return None;
    }
    Some(crate::redaction::scrub(trimmed))
}
