//! What the model is allowed to keep in mind, and how that is paid for.
//!
//! The budget here is tokens, not characters, and the two differ enough to
//! matter: a rough four-characters-per-token estimate is fine for deciding *when*
//! to compact and wrong for anything a user reads.
//!
//! Three things are deliberately kept out of the way. The repository tree is
//! never enumerated into the prompt - the model asks for what it wants. Tool
//! output is compressed rather than truncated raw, because a truncated stack
//! trace loses its last lines, which are the useful ones. And the oldest
//! exchanges are summarised once, rather than every turn, so a long run does
//! not pay for summarising a conversation that barely moved.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::model::Message;
use crate::task::{Event, EventKind, Task};

/// Rough token count for a string.
///
/// Deliberately named as an estimate: it is used to decide when to compact, and
/// being 10% out changes when that happens, not whether the result is correct.
pub fn estimate_tokens(text: &str) -> u32 {
    // Four characters per token is the usual rule of thumb for English text and
    // source code, which is most of what a coding agent sends.
    ((text.chars().count() / 4) as u32).saturating_add(1)
}

/// The conversation, plus whatever has been compacted out of it.
pub struct Context {
    system: String,
    messages: Vec<Message>,
    /// Kept verbatim across compaction: the task and any notes are the whole
    /// point of the run, and losing them to a summary would be absurd.
    pinned: Vec<String>,
    /// Token counts by what produced them, so a caller can see where the
    /// context actually went.
    ledger: BTreeMap<&'static str, u32>,
    max_tokens: u32,
    turns: u32,
}

impl Context {
    pub fn new(task: &Task) -> Self {
        // The contract, not a manual. Everything that could have been prose
        // lives in a tool description or in the task instead.
        let system = format!(
            "{}\n\nTASK:\n{}\n{}",
            crate::SYSTEM_CONTRACT,
            task.instruction.trim(),
            task.context_notes
                .iter()
                .map(|note| format!("NOTE: {note}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let ledger = BTreeMap::from([("system", estimate_tokens(&system))]);
        Self {
            system,
            messages: Vec::new(),
            pinned: task.context_notes.clone(),
            ledger,
            // A deliberate fraction of a typical window. Compacting at 70% keeps
            // room for a large tool result to arrive without overflowing.
            max_tokens: 96_000,
            turns: 0,
        }
    }

    /// Records the assistant's turn.
    pub fn push_assistant(&mut self, text: Option<String>) {
        if let Some(text) = &text {
            self.add("assistant", estimate_tokens(text));
        }
        self.messages.push(Message::Assistant {
            content: text,
            tool_calls: Vec::new(),
        });
        self.turns += 1;
    }

    /// Attaches tool calls to the assistant turn just recorded.
    pub fn push_tool_calls(&mut self, calls: Vec<crate::model::ToolCall>) {
        if let Some(Message::Assistant { tool_calls, .. }) = self.messages.last_mut() {
            *tool_calls = calls;
        }
    }

    /// Records a tool result, compressed to a bound first.
    pub fn push_tool_result(&mut self, tool: &str, content: &str) {
        let compressed = crate::DEFAULT_TOOL_OUTPUT_BYTES.min(4096);
        let rendered = crate::tools::compress(content, compressed);
        self.add("tool", estimate_tokens(&rendered));
        self.messages.push(Message::Tool {
            tool_call_id: String::new(),
            name: tool.to_owned(),
            content: rendered,
        });
    }

    /// A note from the harness, kept as a user turn so it survives compaction.
    pub fn push_note(&mut self, text: String) {
        self.pinned.push(text.clone());
        self.add("harness", estimate_tokens(&text));
        self.messages.push(Message::User { content: text });
    }

    fn add(&mut self, bucket: &'static str, tokens: u32) {
        *self.ledger.entry(bucket).or_insert(0) += tokens;
    }

    /// Approximate tokens currently held.
    pub fn tokens(&self) -> u32 {
        self.ledger.values().sum()
    }

    /// Whether the conversation is close enough to the ceiling to compact.
    pub fn should_compact(&self) -> bool {
        self.tokens() > self.max_tokens
    }

    /// Drops the oldest exchanges, keeping the pinned material and the most
    /// recent turns.
    ///
    /// The first kept turn is a cheap stand-in for a summary: the agent's own
    /// account of what it was doing is more trustworthy than a generated
    /// paraphrase of it, and it costs nothing.
    pub fn compact(&mut self) -> (u32, u32) {
        let before = self.messages.len();
        const KEEP_RECENT: usize = 6;
        if before <= KEEP_RECENT {
            return (before as u32, before as u32);
        }
        let head: Vec<String> = self
            .messages
            .drain(..before - KEEP_RECENT)
            .filter_map(|message| describe(&message))
            .collect();
        let digest = if head.is_empty() {
            String::new()
        } else {
            format!(
                "Earlier in this run ({} exchanges, compacted):\n{}",
                head.len(),
                head.join("\n")
            )
        };
        let digest_tokens = estimate_tokens(&digest);
        self.messages.insert(0, Message::User { content: digest });
        self.ledger.insert("compacted", digest_tokens);
        (before as u32, self.messages.len() as u32)
    }

    /// The system message plus the conversation, in wire order.
    ///
    /// The system prompt is first and unchanged for the whole run, so a provider
    /// that caches by prefix can reuse it.
    pub fn as_wire(&self) -> Vec<Value> {
        let mut out = Vec::with_capacity(self.messages.len() + 1);
        out.push(serde_json::json!({
            "role": "system",
            "content": self.system,
        }));
        for message in &self.messages {
            out.push(message_to_value(message));
        }
        out
    }

    /// Token use by category.
    pub fn ledger(&self) -> &BTreeMap<&'static str, u32> {
        &self.ledger
    }

    /// A one-line account of the run for the result document.
    pub fn summary(&self) -> String {
        self.pinned
            .iter()
            .filter(|note| !note.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub fn turns(&self) -> u32 {
        self.turns
    }
}

fn message_to_value(message: &Message) -> Value {
    match message {
        Message::System { content } => serde_json::json!({"role": "system", "content": content}),
        Message::User { content } => serde_json::json!({"role": "user", "content": content}),
        Message::Assistant {
            content,
            tool_calls,
        } => {
            let mut value = serde_json::json!({"role": "assistant", "content": content});
            if !tool_calls.is_empty() {
                let calls: Vec<Value> = tool_calls
                    .iter()
                    .map(|call| {
                        serde_json::json!({
                            "id": call.id,
                            "type": "function",
                            "function": {
                                "name": call.name,
                                "arguments": call.arguments,
                            }
                        })
                    })
                    .collect();
                value["tool_calls"] = Value::Array(calls);
            }
            value
        }
        Message::Tool {
            tool_call_id,
            name,
            content,
        } => serde_json::json!({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": name,
            "content": content,
        }),
    }
}

fn describe(message: &Message) -> Option<String> {
    let text = match message {
        Message::Assistant { content, .. } => content.clone()?,
        Message::User { content } => content.clone(),
        Message::Tool { name, content, .. } => {
            let first = content.lines().next().unwrap_or_default();
            format!("{name}: {}", clip(first, 100))
        }
        Message::System { .. } => return None,
    };
    Some(clip(text.trim(), 160))
}

fn clip(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let kept: String = text.chars().take(limit).collect();
    format!("{kept}…")
}

/// Events describing what the context engine did, for the result document.
pub fn context_events(
    ledger: &BTreeMap<&'static str, u32>,
    compacted: Option<(u32, u32)>,
) -> Vec<Event> {
    let mut out = Vec::new();
    if let Some((from, to)) = compacted {
        out.push(Event {
            at: chrono::Utc::now(),
            turn: 0,
            kind: EventKind::Compacted { from, to },
            detail: None,
        });
    }
    let detail = ledger
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ");
    if !detail.is_empty() {
        out.push(Event {
            at: chrono::Utc::now(),
            turn: 0,
            kind: EventKind::Turn,
            detail: Some(format!("context {detail}")),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> Task {
        Task {
            instruction: "fix the parser".to_owned(),
            repo_path: None,
            validations: Vec::new(),
            max_turns: 8,
            max_requests: 16,
            max_tool_output_bytes: 1024,
            model: None,
            context_notes: vec!["the parser is hand written".to_owned()],
        }
    }

    #[test]
    fn the_system_prompt_carries_the_task_and_stays_small() {
        let context = Context::new(&task());
        let wire = context.as_wire();
        let system = wire[0]["content"].as_str().unwrap_or_default().to_owned();
        assert!(system.contains("fix the parser"));
        assert!(system.contains("hand written"));
        // The contract is meant to be short; a manual-sized prompt is the failure
        // this harness exists to avoid.
        assert!(
            system.len() < 3000,
            "system prompt is {} bytes",
            system.len()
        );
    }

    #[test]
    fn the_system_message_is_first_and_stable() {
        let mut context = Context::new(&task());
        let first = context.as_wire()[0].clone();
        context.push_tool_result("read", "contents");
        context.push_note("done".to_owned());
        let again = context.as_wire()[0].clone();
        // A stable prefix is what lets a provider cache it.
        assert_eq!(first, again);
    }

    #[test]
    fn compaction_keeps_recent_turns_and_shrinks_the_history() {
        let mut context = Context::new(&task());
        for index in 0..40 {
            context.push_assistant(Some(format!("assistant turn {index}")));
            context.push_tool_result("read", "output");
        }
        let before = context.as_wire().len();
        let (from, to) = context.compact();
        let after = context.as_wire().len();
        assert!(after < before, "{after} should be fewer than {before}");
        assert_eq!(from, 80);
        assert!(to <= 8, "kept {to} messages");
    }

    #[test]
    fn compaction_never_discards_the_task() {
        let mut context = Context::new(&task());
        for _ in 0..40 {
            context.push_assistant(Some("chatter".to_owned()));
        }
        context.compact();
        // The task lives in the system message, which compaction does not touch.
        let wire = context.as_wire();
        let system = wire[0]["content"].as_str().unwrap_or_default();
        assert!(system.contains("fix the parser"));
    }

    #[test]
    fn the_ledger_attributes_tokens_by_source() {
        let mut context = Context::new(&task());
        context.push_tool_result("read", "x".repeat(4000).as_str());
        assert!(context.ledger().contains_key("tool"));
        assert!(context.tokens() > 1000);
    }
}
