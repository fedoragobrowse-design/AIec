//! The system prompt.
//!
//! Small on purpose. Every token here is paid on every request for the whole
//! session, and a long prompt is the single easiest place to smuggle a manual
//! into a context window. What the model needs is a contract, not a textbook;
//! the detail belongs in the tool descriptions, which are read when relevant.

use crate::context::TaskState;

/// The contract. Stable for the whole session so it stays a cacheable prefix.
pub const CONTRACT: &str = "\
You are a coding agent working inside a disposable Linux VM. You have a repository, \
a shell, and a set of tools. You cannot see outside this VM and you cannot ask for a \
new one.

Work by looking before you leap: read the files that matter, then change them, then \
prove it. Prefer the narrowest edit that fixes the actual defect over rewriting a file \
you have not fully read.

Rules:
- Paths are relative to the workspace. Absolute paths and `..` are refused.
- The `edit` tool takes a 1-based line range. Read a file before editing it.
- Run the project's own tests with `bash` to check your work. A test you did not run \
is not a test that passed.
- Do not modify the harness, its configuration, or anything outside the repository.

When the task is done, say so plainly and stop. You are not scored on how much you \
did; you are scored on whether the task is actually done and the diff shows it.";

/// Assembles the full stable prefix: the contract, then the state.
pub fn system_prompt(state: &TaskState) -> String {
    crate::context::stable_prefix(CONTRACT, state)
}

/// The one-off user turn that opens the session.
///
/// The repository is deliberately not described here. Lazy discovery is the
/// point: the model asks for what it needs, and the harness searches, rather
/// than the harness walking a tree it may not even be working in.
pub fn opening_turn(instruction: &str) -> &str {
    instruction
}

/// Operator context: facts the caller hands the model that it cannot reliably
/// discover itself — target ids, API bases, scope, credentials already in env.
/// Rendered once into the opening turn, so it is present from turn 1 rather
/// than arriving as mid-session steering the model may never have needed.
pub fn context_turn(context: &str) -> String {
    format!("<operator-context>\n{context}\n</operator-context>")
}
/// A steering note injected mid-session, without restarting anything.
pub fn steering_turn(note: &str) -> String {
    format!("<steering>\n{note}\n</steering>")
}
/// Told to the model when it claims completion, so the session does not end on
/// an assertion the caller then has to check anyway.
pub const DONE_CONTRACT: &str = "\
If the task is complete, stop calling tools and reply with a short summary of what you \
changed and how you verified it. If you are not finished, say what is blocking you.";
