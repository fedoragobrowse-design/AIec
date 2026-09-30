//! Context budgeting and compaction.
//!
//! The rule this module exists to enforce: never find out the context is full
//! because the provider said so. Track it, know it before every request, and
//! compact on structure rather than by asking a model to summarise a transcript.

use std::collections::BTreeSet;

use crate::model::{Message, Response, ToolCall};

/// What a compaction must not lose. The whole point of structured state is that
/// the objective and the failing test survive a summary the model writes badly.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TaskState {
    pub objective: String,
    pub constraints: Vec<String>,
    pub decisions: Vec<String>,
    pub files_read: BTreeSet<String>,
    pub files_changed: BTreeSet<String>,
    pub commands_run: Vec<String>,
    pub test_results: Vec<String>,
    pub open_problems: Vec<String>,
}

impl TaskState {
    pub fn new(objective: impl Into<String>) -> Self {
        Self {
            objective: objective.into(),
            ..Default::default()
        }
    }

    /// Renders as compact markdown for the system slot. This text is stable
    /// across turns, which is what makes the provider's prefix cache useful.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("## Objective\n");
        out.push_str(&self.objective);
        out.push('\n');
        // Two plain functions rather than two closures over `out`: both would
        // need `&mut out` at once, which the borrow checker is right to refuse.
        fn section(out: &mut String, title: &str, items: &BTreeSet<String>) {
            if items.is_empty() {
                return;
            }
            out.push_str("\n## ");
            out.push_str(title);
            out.push('\n');
            for item in items {
                out.push_str("- ");
                out.push_str(item);
                out.push('\n');
            }
        }
        fn list(out: &mut String, title: &str, items: &[String]) {
            if items.is_empty() {
                return;
            }
            out.push_str("\n## ");
            out.push_str(title);
            out.push('\n');
            for item in items {
                out.push_str("- ");
                out.push_str(item);
                out.push('\n');
            }
        }
        list(&mut out, "Constraints", &self.constraints);
        list(&mut out, "Decisions", &self.decisions);
        section(&mut out, "Files changed", &self.files_changed);
        list(&mut out, "Tests", &self.test_results);
        list(&mut out, "Open problems", &self.open_problems);
        out
    }

    /// Folds a turn into the state. Called every turn, so the facts are
    /// recorded as they happen rather than reconstructed during a crisis.
    pub fn observe(&mut self, response: &Response, observations: &[(String, bool)]) {
        for call in &response.tool_calls {
            self.commands_run
                .push(format!("{} {}", call.name, call.arguments));
        }
        for (summary, ok) in observations {
            if !ok {
                self.open_problems.push(summary.clone());
            }
            self.test_results.push(summary.clone());
        }
        // The lists are append-only evidence; cap them so the state itself
        // cannot grow without bound across a long session.
        for list in [
            &mut self.decisions,
            &mut self.commands_run,
            &mut self.test_results,
            &mut self.open_problems,
            &mut self.constraints,
        ] {
            if list.len() > 40 {
                let overflow = list.len() - 40;
                list.drain(0..overflow);
            }
        }
    }
}

/// Absolute ceiling on the progress block, in bytes.
const PROGRESS_BYTE_CAP: u64 = 8_000;
const MIN_LAST_MESSAGE_TOKENS: u64 = 256;

/// Bounds a single message that is too large to keep whole.
///
/// The head and the tail survive, because for a tool observation those are the
/// first error and the last summary, which is what a model acts on. A tool call
/// keeps its name and arguments, because a truncated tool call is not a tool
/// call.
fn squeeze_message(message: &Message, limit: usize) -> Message {
    match message {
        Message::System { content } | Message::User { content } => Message::User {
            content: compress_output(content, limit),
        },
        Message::Assistant { text, tool_calls } => Message::Assistant {
            text: text.as_ref().map(|t| compress_output(t, limit)),
            tool_calls: tool_calls.clone(),
        },
        Message::Tool {
            call_id,
            name,
            content,
        } => Message::Tool {
            call_id: call_id.clone(),
            name: name.clone(),
            content: compress_output(content, limit),
        },
    }
}

/// What one tool produced, carried with the identity needed to answer the call
/// that asked for it.
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub call_id: String,
    pub name: String,
    pub content: String,
    pub ok: bool,
}

/// Roughly 4 characters per token. Deliberately an estimate: the only thing that
/// matters is that it is monotonic and never wildly optimistic, and a real
/// tokenizer would cost more than it saves here.
pub fn estimate_tokens(text: &str) -> u64 {
    ((text.len() as u64) / 4) + 1
}

/// What the loop knows about the context before it sends anything.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub limit: u64,
    /// Held back for the model's own reply, so a request never fills the window
    /// with the prompt and then has nowhere to put the answer.
    pub reserved_output: u64,
}

impl Budget {
    pub fn new(limit: u32, max_output_tokens: u32) -> Self {
        Self {
            limit: limit as u64,
            reserved_output: max_output_tokens as u64,
        }
    }

    pub fn available(&self) -> u64 {
        self.limit.saturating_sub(self.reserved_output)
    }

    /// Whether a request of this size still leaves room for the answer.
    pub fn fits(&self, tokens: u64) -> bool {
        tokens + self.reserved_output <= self.limit
    }
}

/// The conversation, plus the accounting that keeps it inside the window.
pub struct Context {
    pub state: TaskState,
    pub messages: Vec<Message>,
    budget: Budget,
    peak_tokens: u64,
    compactions: u32,
    /// Digests of file contents already shown to the model, so an unchanged
    /// file is not re-sent just because the model looked at it again.
    seen_digests: std::collections::HashMap<String, String>,
    total_tool_calls: u64,
    total_tool_output_bytes: u64,
}

impl Context {
    pub fn new(objective: impl Into<String>, budget: Budget) -> Self {
        Self {
            state: TaskState::new(objective),
            messages: Vec::new(),
            budget,
            peak_tokens: 0,
            compactions: 0,
            seen_digests: std::collections::HashMap::new(),
            total_tool_calls: 0,
            total_tool_output_bytes: 0,
        }
    }

    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    pub fn compactions(&self) -> u32 {
        self.compactions
    }

    pub fn peak_tokens(&self) -> u64 {
        self.peak_tokens
    }

    pub fn tool_bytes(&self) -> u64 {
        self.total_tool_output_bytes
    }

    /// The current size of everything that would be sent.
    ///
    /// The state block is measured in the same bounded form `compact` emits, so
    /// the number here and the bytes on the wire cannot disagree.
    pub fn tokens(&self) -> u64 {
        self.tokens_of(&self.messages)
    }

    /// Inserts or refreshes the progress message.
    ///
    /// Called after every turn. It is what keeps the structured state in the
    /// transcript at all times, and doing it unconditionally rather than only
    /// on compaction is what makes the accounting in `tokens` honest: there is
    /// one copy of the state, in one place, and it is measured where it lives.
    pub fn refresh_progress(&mut self) {
        let message = Message::User {
            content: format!("<progress>\n{}\n</progress>", self.progress_block()),
        };
        // Index 0, or just after a leading system prompt, which is never old.
        let at = match self.messages.first() {
            Some(Message::System { .. }) => 1,
            _ => 0,
        };
        let already_there = matches!(
            self.messages.get(at),
            Some(Message::User { content }) if content.starts_with("<progress>")
        );
        if already_there {
            self.messages[at] = message;
        } else {
            self.messages.insert(at, message);
        }
    }

    /// The structured state as the model actually sees it.
    ///
    /// Bounded to a share of the window rather than to a fixed size: a
    /// progress block that is small in a large window is free, and one that is
    /// large in a small window is the overflow it was supposed to prevent.
    /// Measured in bytes because `compress_output` is, at roughly four bytes
    /// to the token.
    fn progress_block(&self) -> String {
        let share = self.budget.available() / 2;
        let bytes = (share.saturating_mul(4)).min(PROGRESS_BYTE_CAP) as usize;
        compress_output(&self.state.render(), bytes)
    }

    /// Records what happened, then compacts if the next request would not fit.
    ///
    /// Returns true when a compaction happened, so the caller can log it.
    /// Records a whole turn: the assistant's reply, then the tool results that
    /// answer it.
    ///
    /// The order matters and is the reason this lives in one place. A `tool`
    /// message is a reply to a specific tool call and has to follow the
    /// assistant turn that made it; emitting them in any other order produces a
    /// conversation that a real provider rejects with a 400 and a fixture
    /// happily accepts.
    pub fn push_turn(&mut self, response: &Response, results: &[ToolResult]) -> bool {
        let observations: Vec<(String, bool)> =
            results.iter().map(|r| (r.content.clone(), r.ok)).collect();
        self.state.observe(response, &observations);

        if response.text.is_some() || !response.tool_calls.is_empty() {
            self.messages.push(Message::Assistant {
                text: response.text.clone(),
                tool_calls: response.tool_calls.clone(),
            });
        }
        for result in results {
            self.messages.push(Message::Tool {
                call_id: result.call_id.clone(),
                name: result.name.clone(),
                content: result.content.clone(),
            });
        }

        self.total_tool_calls += response.tool_calls.len() as u64;
        self.refresh_progress();
        self.peak_tokens = self.peak_tokens.max(self.tokens());

        if self.budget.fits(self.tokens()) {
            return false;
        }
        self.compact();
        true
    }

    /// Drops the oldest turns and rebuilds the transcript from the structured
    /// state, keeping the most recent exchanges verbatim.
    ///
    /// Nothing is summarised by a model here. That is the deliberate choice:
    /// a summary is a lossy thing produced under pressure, whereas the state
    /// above was accumulated as facts while they were still true.
    pub fn compact(&mut self) {
        // The system message is never dropped: it is the contract, and it is
        // the stable prefix the provider's cache is keyed on.
        let system = match self.messages.first() {
            Some(Message::System { content }) => Some(content.clone()),
            _ => None,
        };

        let mut rebuilt: Vec<Message> = Vec::new();
        if let Some(system) = system {
            rebuilt.push(Message::System { content: system });
        }

        // The progress message is already in the transcript and is carried over
        // with it. Re-adding one here would put two copies in the context and
        // make the token accounting disagree with the request.
        if let Some(progress) = self
            .messages
            .iter()
            .find(|m| matches!(m, Message::User { content } if content.starts_with("<progress>")))
        {
            rebuilt.push(progress.clone());
        }

        // Walk backwards and keep what fits, rather than keeping a fixed
        // NUMBER of messages. A count is the wrong unit: six small messages
        // are nothing, and six large ones are a window overflow. The budget is
        // the unit that matters.
        let target = self
            .budget
            .available()
            .saturating_sub(self.tokens_of(&rebuilt));
        let mut used = 0u64;
        for message in self.messages.iter().rev() {
            if matches!(message, Message::System { .. }) {
                continue;
            }
            let cost = message_tokens(message);
            if used + cost > target {
                break;
            }
            used += cost;
            rebuilt.push(message.clone());
        }
        rebuilt.reverse();

        // If nothing at all fit, the last exchange still has to be bounded or
        // the next request is unsendable. Squeezing it keeps the most recent
        // thing the model saw, which is the thing it is most likely to need.
        if used == 0
            && let Some(last) = self
                .messages
                .iter()
                .rev()
                .find(|m| !matches!(m, Message::System { .. }))
        {
            rebuilt.push(squeeze_message(
                last,
                (MIN_LAST_MESSAGE_TOKENS * 4) as usize,
            ));
        }

        // The wrapper text around the progress block, and the system prompt
        // itself, are not part of the target arithmetic above. Rather than
        // account for them exactly and be wrong when a provider's real
        // tokeniser disagrees with the estimate, squeeze the newest turn until
        // the whole thing genuinely fits. This is the step that makes the
        // budget a guarantee rather than an intention.
        let mut guard = 0;
        while self.tokens_of(&rebuilt) > self.budget.available() && guard < 8 {
            let Some(index) = rebuilt
                .iter()
                .rposition(|m| !matches!(m, Message::System { .. }))
            else {
                break;
            };
            let current = message_tokens(&rebuilt[index]);
            if current == 0 {
                break;
            }
            // How much too big, measured exactly the way the loop condition is.
            let overflow = self
                .tokens_of(&rebuilt)
                .saturating_sub(self.budget.available());
            let keep = current.saturating_sub(overflow).max(32);
            rebuilt[index] = squeeze_message(&rebuilt[index], (keep * 4) as usize);
            guard += 1;
        }

        self.messages = rebuilt;
        self.compactions += 1;
    }

    fn tokens_of(&self, messages: &[Message]) -> u64 {
        messages.iter().map(message_tokens).sum()
    }

    /// Whether a file with this digest has already been shown unchanged.
    pub fn already_seen(&self, path: &str, digest: &str) -> bool {
        self.seen_digests.get(path).is_some_and(|d| d == digest)
    }

    pub fn mark_seen(&mut self, path: &str, digest: &str) {
        // Bounded: a long session should not accumulate a digest per file for
        // ever, and the working set is small.
        if self.seen_digests.len() > 512 {
            self.seen_digests.clear();
        }
        self.seen_digests.insert(path.to_owned(), digest.to_owned());
    }

    pub fn note_tool_output(&mut self, bytes: u64) {
        self.total_tool_output_bytes += bytes;
    }
}

fn message_tokens(message: &Message) -> u64 {
    match message {
        Message::System { content } | Message::User { content } => estimate_tokens(content),
        Message::Assistant { text, tool_calls } => {
            text.as_deref().map_or(0, estimate_tokens)
                + tool_calls
                    .iter()
                    .map(|c| estimate_tokens(&c.signature()))
                    .sum::<u64>()
        }
        Message::Tool { content, name, .. } => estimate_tokens(content) + estimate_tokens(name),
    }
}

/// Keeps the head and tail of a large result, and says what went missing.
///
/// Compiler and test output is overwhelmingly head and tail: the first error
/// and the last summary are what a model acts on. The middle is repetition.
pub fn compress_output(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let head_budget = limit * 2 / 3;
    let tail_budget = limit - head_budget;
    // Work on char boundaries so a multi-byte character is never split.
    let safe_head = floor_boundary(text, head_budget);
    let safe_tail_start = ceil_boundary(text, text.len().saturating_sub(tail_budget));

    format!(
        "{}\n\n[... {} bytes elided by the harness; narrow the query or raise the \
         limit to see it ...]\n\n{}",
        &text[..safe_head],
        safe_tail_start.saturating_sub(safe_head),
        &text[safe_tail_start..]
    )
}

fn floor_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// The stable prefix, in a fixed order. Reordering this between turns would
/// throw away the provider's cache for nothing.
pub fn stable_prefix(system: &str, state: &TaskState) -> String {
    format!("{system}\n\n<progress>\n{}\n</progress>", state.render())
}

/// Compares two tool calls for the loop detector.
pub fn same_call(a: &ToolCall, b: &ToolCall) -> bool {
    a.name == b.name && a.arguments == b.arguments
}
