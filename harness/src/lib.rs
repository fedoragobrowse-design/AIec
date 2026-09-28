//! A very small coding-agent runtime for disposable AIec VMs.

pub mod bench;

pub mod agent;
pub mod budget;
pub mod context;
pub mod events;
pub mod loop_guard;
pub mod model;
pub mod prompt;
pub mod redaction;
pub mod result;
pub mod session;
pub mod task;
pub mod tools;

/// Bumped when the task, result, or event shapes change in a way a caller would
/// notice. AIec negotiates on this to decide whether a guest is usable.
pub const PROTOCOL_VERSION: u32 = 1;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One thing that went wrong, typed at the boundary it happens on.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid {what}: {reason}")]
    Invalid { what: String, reason: String },

    #[error("tool {name} failed: {reason}")]
    Tool { name: String, reason: String },

    #[error("model error: {0}")]
    Model(String),

    #[error("model request exhausted the retry budget: {0}")]
    RetriesExhausted(String),

    #[error("task budget exhausted: {0}")]
    BudgetExhausted(String),

    #[error("the session was stopped: {0}")]
    Stopped(String),

    #[error("a credential is missing: {0}")]
    MissingCredential(String),
}

impl HarnessError {
    pub fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn invalid(what: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid {
            what: what.into(),
            reason: reason.into(),
        }
    }

    pub fn tool(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Tool {
            name: name.into(),
            reason: reason.into(),
        }
    }
}

/// A tool failed. That is an observation for the model, not a harness fault, so
/// the loop keeps going and the result still gets written.
#[derive(Debug, Clone)]
pub struct ToolFailure {
    pub name: String,
    pub message: String,
}

pub type Result<T, E = anyhow::Error> = std::result::Result<T, E>;
