//! A very small coding-agent harness that runs inside an AIec sandbox.
//!
//! The shape of the thing is dictated by where it runs. Every VM is destroyed
//! moments after the work finishes, so anything that costs time at startup is
//! paid again on every single task: a package install, a dependency resolve, a
//! migration, a database. This harness therefore boots in one step, opens one
//! file, talks to one model endpoint, and exits.
//!
//! What it deliberately is not: a VM manager, a scheduler, a session store, or a
//! platform. AIec already does all of that. This is the model and tool loop,
//! and nothing else.
//!
//! The second constraint is token cost. A short-lived agent still pays for
//! every token on every turn, so the system prompt is deliberately small, the
//! tool set is small, the repository is discovered lazily rather than scanned,
//! and large tool output is compressed rather than forwarded.

pub mod agent;
pub mod budget;
pub mod context;
pub mod events;
pub mod loop_guard;
pub mod model;
pub mod session;
pub mod task;
pub mod tools;

/// Reported in every result, so a result can be matched to the code that made
/// it. A harness whose behaviour changes between versions is worse than
/// useless if the caller cannot tell which one ran.
pub const HARNESS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The agent contract, kept deliberately small.
///
/// Everything that could have been a manual is a tool description or part of the
/// task instead. A harness that sends a manual on every request charges the
/// user for it on every turn, and the model reads less of what it is sent.
pub const SYSTEM_CONTRACT: &str = concat!(
    "You are a coding agent working in a git repository.\n\n",
    "Read before you edit. Use the tools; do not describe code you have not read.\n",
    "Prefer edit over write: write replaces a whole file, edit changes a known span.\n",
    "Check the task's validations before you say you are done. If they fail, fix the cause, not the test.\n",
    "Stay inside the repository. Do not change configuration you were not asked to change.\n\n",
    "When the task is complete, reply with a short summary and no tool calls."
);

/// The most a single read will return, in bytes.
///
/// Not a safety limit so much as a cost one: a model asked to edit a 5,000 line
/// file does not need it resent to change three lines.
pub const DEFAULT_READ_BYTES: usize = 256 * 1024;

/// How much of a tool result survives into context before compression.
pub const DEFAULT_TOOL_OUTPUT_BYTES: usize = 32 * 1024;

/// The first `limit` bytes of `text`, cut on a character boundary.
///
/// A byte limit that lands inside a multi-byte character is not an edge case:
/// it happens for any non-ASCII output, and slicing there is a panic rather
/// than a shorter string. Every bound in this harness is a byte count, so
/// every one of them goes through here.
pub fn head_bytes(text: &str, limit: usize) -> &str {
    let mut end = limit.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The last `limit` bytes of `text`, cut on a character boundary.
pub fn tail_bytes(text: &str, limit: usize) -> &str {
    let mut start = text.len().saturating_sub(limit);
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// Trims `text` to at most `limit` characters, marking the cut.
///
/// One implementation on purpose. Four copies of this helper existed, three of
/// them character-safe and one not, which is how a bound that aborts the whole
/// harness survived in the one place that clips command output.
pub fn clip(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let kept: String = text.chars().take(limit).collect();
    format!("{kept}…")
}
