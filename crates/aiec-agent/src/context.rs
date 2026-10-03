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

use crate::model::{Message, ToolCall};
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
    /// context actually went. This is an accounting record of the whole run:
    /// it does not shrink when the conversation does.
    ledger: BTreeMap<&'static str, u32>,
    /// What the conversation currently costs. The ceiling is measured against
    /// this and not against the ledger, because a ledger that forgets to shrink
    /// turns the ceiling into a number that only ever grows.
    live: u32,
    max_tokens: u32,
    /// Bound on one tool result, in bytes: the task's own
    /// `max_tool_output_bytes` and the harness cap, whichever is smaller.
    ///
    /// Computed once, here, because this is the only place a tool result is
    /// bounded. A ceiling the task declares but nothing reads is not a
    /// ceiling - a task asking for a kilobyte was being sent four.
    tool_output_limit: usize,
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
        let system_tokens = estimate_tokens(&system);
        Self {
            system,
            messages: Vec::new(),
            pinned: task.context_notes.clone(),
            ledger: BTreeMap::from([("system", system_tokens)]),
            live: system_tokens,
            // A deliberate fraction of a typical window. Compacting at 70% keeps
            // room for a large tool result to arrive without overflowing.
            max_tokens: 96_000,
            turns: 0,
            tool_output_limit: crate::DEFAULT_TOOL_OUTPUT_BYTES
                .min(4096)
                .min(task.max_tool_output_bytes),
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
    ///
    /// The calls are charged here rather than in [`Context::push_assistant`]
    /// because they are attached after the text was recorded, and they are the
    /// larger half: a `write` call carries a whole file in its arguments. A
    /// ledger that does not count them reports the conversation as well inside
    /// the window while the provider is rejecting it for being over, which is
    /// the one failure the ceiling exists to prevent.
    pub fn push_tool_calls(&mut self, calls: Vec<crate::model::ToolCall>) {
        if !calls.is_empty() {
            // Serialized the way `as_wire` serializes them, so what is charged
            // here is what the rebase inside `compact` measures later and the
            // two cannot drift apart.
            let rendered: Vec<Value> = calls
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
            let rendered = serde_json::to_string(&rendered).unwrap_or_default();
            self.add("tool_calls", estimate_tokens(&rendered));
        }
        if let Some(Message::Assistant { tool_calls, .. }) = self.messages.last_mut() {
            *tool_calls = calls;
        }
    }

    /// Records a tool result, compressed to a bound first, and tied to the call
    /// it answers.
    ///
    /// The id travels with the result because that is the only thing that says
    /// which question this is the answer to. A result with an empty id is not a
    /// shorter message, it is a message about nothing.
    pub fn push_tool_result(&mut self, call: &ToolCall, content: &str) {
        let rendered = crate::tools::compress(content, self.tool_output_limit);
        self.add("tool", estimate_tokens(&rendered));
        self.messages.push(Message::Tool {
            tool_call_id: call.id.clone(),
            name: call.name.clone(),
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
        self.live = self.live.saturating_add(tokens);
    }

    /// Approximate tokens the conversation currently costs.
    pub fn tokens(&self) -> u32 {
        self.live
    }

    /// Tokens the whole run produced, by source, whether or not they are still
    /// in the window. The result document reports this; the ceiling uses
    /// [`Context::tokens`].
    pub fn total_produced(&self) -> u32 {
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
        // The kept window must not start on a tool result. A `tool` message
        // answers the assistant message before it, so cutting there leaves one
        // whose `tool_calls` are in the dropped half - and every OpenAI-shaped
        // provider rejects that with a 400 on the *next* request. One turn that
        // asked for six tools is enough: the assistant goes, six orphans stay,
        // and the run cannot continue at all.
        let mut cut = before - KEEP_RECENT;
        while cut < before && matches!(self.messages[cut], Message::Tool { .. }) {
            cut += 1;
        }
        // Agents do batch more tools than the window holds, and then the whole
        // window is results. Widening it back to the assistant that asked for
        // them keeps the newest turn whole rather than discarding the turn the
        // model just paid for.
        if cut >= before {
            while cut > 0 && matches!(self.messages[cut - 1], Message::Tool { .. }) {
                cut -= 1;
            }
            cut = cut.saturating_sub(1);
        }
        let head: Vec<String> = self
            .messages
            .drain(..cut)
            .filter_map(|message| describe(&message))
            .collect();
        let digest = if head.is_empty() {
            // `describe` has nothing to say about a contentless assistant turn
            // or about a system message, so a run whose drained turns were all
            // of those leaves `head` empty even though exchanges were dropped.
            // An empty string is not an option: it goes on the wire as a
            // `user` message with empty content, and every provider that
            // validates it rejects the whole request over it. The count of
            // what was dropped says the same thing and is never empty.
            format!("Earlier in this run ({cut} exchanges, compacted)")
        } else {
            format!(
                "Earlier in this run ({} exchanges, compacted):\n{}",
                head.len(),
                head.join("\n")
            )
        };
        let digest_tokens = estimate_tokens(&digest);
        // The digest is the run's one leading user turn. If the kept window
        // already begins with a user message - a note the harness pushed, or a
        // digest an earlier compaction left at the front - inserting a fresh
        // one in front of it puts two consecutive `user` messages on the wire,
        // and a provider that requires alternating roles rejects the whole
        // request rather than the odd message. Folding the kept turn into the
        // digest keeps both texts and the invariant.
        match self.messages.first() {
            Some(Message::User { content }) => {
                let merged = format!("{digest}\n{content}");
                self.messages[0] = Message::User { content: merged };
            }
            _ => self.messages.insert(0, Message::User { content: digest }),
        }
        self.ledger.insert("compacted", digest_tokens);
        // Rebase what the conversation costs. Without this the ceiling keeps
        // measuring every message the run ever produced, so the first
        // compaction does not lower anything and every later turn compacts
        // again over a window that never grew smaller.
        self.live = estimate_tokens(&self.system)
            + digest_tokens
            + self
                .messages
                .iter()
                .skip(1)
                .map(|message| message_to_value(message).to_string().len() as u32 / 4)
                .sum::<u32>();
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
            format!("{name}: {}", crate::clip(first, 100))
        }
        Message::System { .. } => return None,
    };
    Some(crate::clip(text.trim(), 160))
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

    fn call(name: &str) -> crate::model::ToolCall {
        crate::model::ToolCall {
            id: format!("call_{name}"),
            name: name.to_owned(),
            arguments: "{}".to_owned(),
        }
    }

    fn task() -> Task {
        task_with_tool_output(4096)
    }

    /// The same task with the tool-result ceiling the tests here vary.
    ///
    /// The ceiling is live, so it is a fixture knob rather than a constant: a
    /// test that measures what one tool result costs has to say what it asked
    /// for. 4096 is the harness's own cap, so everything that does not care
    /// about the ceiling sees exactly what it always saw.
    fn task_with_tool_output(max_tool_output_bytes: usize) -> Task {
        Task {
            instruction: "fix the parser".to_owned(),
            repo_path: None,
            validations: Vec::new(),
            max_turns: 8,
            max_requests: 16,
            max_tool_output_bytes,
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

    /// A tool result has to be attached to the call it answers, or the
    /// conversation the model sees on the next request is not a conversation.
    ///
    /// The wire format pairs each tool message with the assistant message that
    /// requested it by id. An assistant turn whose `tool_calls` were dropped,
    /// followed by a tool message with an empty id, is a transcript no
    /// conforming endpoint will accept and no model can read: the result
    /// arrives with nothing saying which question it is the answer to.
    #[test]
    fn a_tool_result_is_paired_with_the_call_that_asked_for_it() {
        let mut context = Context::new(&task());
        let call = ToolCall {
            id: "call_abc123".to_owned(),
            name: "read".to_owned(),
            arguments: r#"{"path":"src/lib.rs"}"#.to_owned(),
        };
        context.push_assistant(Some("looking".to_owned()));
        context.push_tool_calls(vec![call.clone()]);
        context.push_tool_result(&call, "the file");
        let wire = context.as_wire();
        let assistant = wire
            .iter()
            .find(|m| m["role"] == "assistant")
            .expect("an assistant turn");
        assert_eq!(
            assistant["tool_calls"][0]["id"], "call_abc123",
            "the model's own call must survive into the next request: {assistant}"
        );
        assert_eq!(assistant["tool_calls"][0]["function"]["name"], "read");
        let tool = wire.iter().find(|m| m["role"] == "tool").expect("a result");
        assert_eq!(
            tool["tool_call_id"], "call_abc123",
            "the result must name the call it answers: {tool}"
        );
        assert_eq!(tool["name"], "read");
    }

    /// Every call in a batch gets its own answer, and no answer is invented for
    /// a call the model did not make.
    #[test]
    fn every_call_in_a_batch_is_answered_exactly_once() {
        let mut context = Context::new(&task());
        let calls: Vec<ToolCall> = ["read", "grep", "bash"]
            .iter()
            .enumerate()
            .map(|(index, name)| ToolCall {
                id: format!("call_{index}"),
                name: (*name).to_owned(),
                arguments: "{}".to_owned(),
            })
            .collect();
        context.push_assistant(Some("three things".to_owned()));
        context.push_tool_calls(calls.clone());
        for call in &calls {
            context.push_tool_result(call, "done");
        }
        let wire = context.as_wire();
        let answers: Vec<&Value> = wire.iter().filter(|m| m["role"] == "tool").collect();
        assert_eq!(answers.len(), calls.len());
        for call in &calls {
            let matched = answers
                .iter()
                .filter(|m| m["tool_call_id"] == call.id.as_str())
                .count();
            assert_eq!(matched, 1, "{} is answered {matched} times", call.id);
        }
    }

    /// Compaction must not leave a tool result whose call it dropped.
    ///
    /// A `tool` message is only meaningful next to the assistant turn that
    /// asked for it; a provider rejects the whole request when one arrives with
    /// no matching `tool_calls`. The kept window used to be a fixed six
    /// messages counted back from the end, so a turn that asked for more than a
    /// couple of tools put the cut inside the results and stranded the rest of
    /// them - after which the run cannot continue at all.
    #[test]
    fn compaction_leaves_no_tool_result_without_its_call() {
        let mut context = Context::new(&task());
        // An agent that batches its reads is ordinary, so the newest turn here
        // asks for six tools at once: more than the kept window holds.
        for turn in 0..8 {
            context.push_assistant(Some(format!("turn {turn}")));
            let calls: Vec<ToolCall> = (0..6)
                .map(|index| ToolCall {
                    id: format!("call_{turn}_{index}"),
                    name: "read".to_owned(),
                    arguments: "{}".to_owned(),
                })
                .collect();
            context.push_tool_calls(calls.clone());
            for call in &calls {
                context.push_tool_result(call, "output");
            }
        }
        context.compact();
        let wire = context.as_wire();
        let mut asked: Vec<String> = Vec::new();
        let mut answers = 0usize;
        for message in &wire {
            match message["role"].as_str() {
                Some("assistant") => {
                    if let Some(list) = message["tool_calls"].as_array() {
                        asked.extend(
                            list.iter()
                                .filter_map(|call| call["id"].as_str().map(str::to_owned)),
                        );
                    }
                }
                Some("tool") => {
                    let id = message["tool_call_id"].as_str().unwrap_or_default();
                    answers += 1;
                    assert!(
                        asked.iter().any(|seen| seen == id),
                        "compaction stranded the answer to {id}: {wire:?}"
                    );
                }
                _ => {}
            }
        }
        // Every turn the agent paid for is gone either way, but the newest one
        // has to survive: keeping nothing but a digest throws away the results
        // the model just asked for.
        assert!(
            answers > 0,
            "compaction dropped the whole conversation: {wire:?}"
        );
        assert!(
            wire.iter().any(|m| m["tool_call_id"] == "call_7_5"),
            "the newest turn did not survive: {wire:?}"
        );
    }
    #[test]
    fn the_system_message_is_first_and_stable() {
        let mut context = Context::new(&task());
        let first = context.as_wire()[0].clone();
        context.push_tool_result(&call("read"), "contents");
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
            context.push_tool_result(&call("read"), "output");
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

    /// Compaction has to lower what the conversation costs, or the ceiling it
    /// is compared against never moves.
    ///
    /// The ledger is a record of the whole run and deliberately does not shrink,
    /// so it cannot also be the number the ceiling reads: a context that had
    /// compacted every turn would still report itself over the limit and
    /// compact again, forever, over a window no bigger than before.
    #[test]
    fn compaction_lowers_what_the_conversation_costs() {
        let mut context = Context::new(&task());
        for index in 0..400 {
            context.push_assistant(Some(format!("turn {index}")));
            context.push_tool_result(&call("read"), &"x".repeat(2000));
        }
        let produced = context.total_produced();
        let before = context.tokens();
        assert!(before > 96_000, "the fixture has to exceed the ceiling");
        let (_, after_messages) = context.compact();
        let after = context.tokens();
        assert!(
            after < before / 2,
            "compaction took {before} to {after}; the ceiling did not move"
        );
        assert!(after_messages <= 8, "{after_messages} messages kept");
        // What the run produced is still reported, and compaction's own digest
        // is part of it: that is work the run did, not work it undid.
        let total = context.total_produced();
        assert!(
            total > produced && total - produced < 20_000,
            "the run produced {produced} and compaction added {}",
            total - produced
        );
        assert!(context.ledger().contains_key("compacted"));
        assert!(!context.should_compact(), "a compacted context is under it");
    }

    #[test]
    fn the_ledger_attributes_tokens_by_source() {
        let mut context = Context::new(&task());
        context.push_tool_result(&call("read"), "x".repeat(4000).as_str());
        assert!(context.ledger().contains_key("tool"));
        assert!(context.tokens() > 1000);
    }

    /// Compaction has to leave a conversation a provider will accept.
    ///
    /// Two things about the digest are load-bearing. It is never empty: a turn
    /// that only carried tool calls has no content to describe, so a run whose
    /// drained turns were all of those produced `Message::User { content: "" }`,
    /// and a provider that validates user content rejects the whole request
    /// over a turn that says nothing. And it is never a second one: a note the
    /// harness pushed can be the first message of the kept window, and a fresh
    /// digest inserted in front of it puts two `user` messages back to back,
    /// which a provider requiring alternating roles also refuses.
    #[test]
    fn compaction_never_emits_an_empty_user_turn_or_two_in_a_row() {
        let mut context = Context::new(&task());
        // Every drained turn describes as nothing: a contentless assistant turn
        // has no content, and a tool result would have described - so this is a
        // conversation with no text in it at all.
        for _ in 0..12 {
            context.push_assistant(None);
        }
        context.compact();
        let digest = context.as_wire()[1]["content"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            !digest.trim().is_empty(),
            "compaction wrote an empty user turn: {digest:?}"
        );
        assert!(
            digest.contains("compacted"),
            "the digest must say what it is: {digest:?}"
        );

        // Now the shape that produces a second user turn. Compaction cuts a
        // fixed number of messages back from the end, and a note the harness
        // pushed is not tied to a pair the way an assistant turn is - so a note
        // sitting six back from the end *is* the first message of the kept
        // window. Four exchanges, then the note at exactly that position.
        const NOTE: &str = "a note the harness pushed and wants kept";
        let mut context = Context::new(&task());
        for index in 0..2 {
            context.push_assistant(Some(format!("turn {index}")));
            context.push_tool_result(&call("read"), "output");
        }
        context.push_note(NOTE.to_owned());
        for index in 2..4 {
            context.push_assistant(Some(format!("turn {index}")));
            context.push_tool_result(&call("read"), "output");
        }
        context.push_assistant(Some("turn 4".to_owned()));
        assert_eq!(context.as_wire()[5]["content"].as_str(), Some(NOTE));

        context.compact();
        assert_single_leading_user(&context);
        let digest = context.as_wire()[1]["content"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            digest.contains(NOTE),
            "the note folded into the digest was dropped: {digest:?}"
        );

        // And again, driven twice in a row: the digest compaction leaves at
        // the front is itself the leading user turn, so a naive second digest
        // lands on top of it.
        for index in 5..7 {
            context.push_assistant(Some(format!("turn {index}")));
            context.push_tool_result(&call("read"), "output");
        }
        context.compact();
        assert_single_leading_user(&context);
    }

    /// The wire holds one leading user turn - the digest - and it says
    /// something, and it is not followed by a second user turn.
    fn assert_single_leading_user(context: &Context) {
        let wire = context.as_wire();
        assert_eq!(wire[1]["role"], "user", "no digest at the front: {wire:?}");
        let digest = wire[1]["content"].as_str().unwrap_or_default();
        assert!(
            !digest.trim().is_empty(),
            "compaction wrote an empty user turn: {wire:?}"
        );
        assert!(
            digest.contains("Earlier in this run"),
            "the front of the conversation is not a digest: {digest:?}"
        );
        for pair in wire.windows(2) {
            assert!(
                !(pair[0]["role"] == "user" && pair[1]["role"] == "user"),
                "two user turns in a row after compaction: {wire:?}"
            );
        }
    }

    /// A tool call's arguments are prompt bytes and have to be paid for.
    ///
    /// A `write` call carries a whole file. Charging only the assistant's text
    /// left the ceiling reading a conversation that was, in the provider's
    /// arithmetic, far over its window - so compaction never ran and the run
    /// died on a context-length error with nothing in the ledger to explain it.
    #[test]
    fn tool_calls_are_charged_to_the_context() {
        let mut context = Context::new(&task());
        // Forty kilobytes of file in one call: a large but ordinary edit.
        let write = |index: usize| ToolCall {
            id: format!("call_{index}"),
            name: "write".to_owned(),
            arguments: serde_json::json!({
                "path": "src/lib.rs",
                "content": "x".repeat(40_000),
            })
            .to_string(),
        };
        context.push_assistant(Some("rewriting the module".to_owned()));
        let before = context.tokens();
        context.push_tool_calls(vec![write(0)]);
        let charged = context.tokens() - before;
        assert!(
            charged > 8_000,
            "forty kilobytes of arguments were charged {charged} tokens"
        );
        assert!(
            context.ledger().contains_key("tool_calls"),
            "the charge is unattributed: {:?}",
            context.ledger()
        );
        // And it has to be enough to reach the ceiling, or charging it changes
        // nothing that matters.
        for index in 1..10 {
            context.push_assistant(Some(format!("turn {index}")));
            context.push_tool_calls(vec![write(index)]);
        }
        assert!(
            context.should_compact(),
            "ten forty-kilobyte writes cost {} tokens and the ceiling is 96_000",
            context.tokens()
        );
    }

    /// The ceiling the task asks for is the one that applies.
    ///
    /// `max_tool_output_bytes` was read by nothing at all: the bound came from
    /// the harness's own constant, so a task asking for a kilobyte was handed
    /// four, and a caller who tuned it for cost had no effect on anything.
    #[test]
    fn a_task_can_cap_one_tool_result() {
        let mut context = Context::new(&task_with_tool_output(1024));
        context.push_tool_result(&call("read"), &"x".repeat(200_000));
        let wire = context.as_wire();
        let rendered = wire
            .iter()
            .find(|m| m["role"] == "tool")
            .expect("a tool result")["content"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            rendered.len() <= 1024,
            "the task asked for 1024 bytes and got {}",
            rendered.len()
        );
        // A ceiling that clips without saying so is worse than no ceiling.
        assert!(
            rendered.contains("elided"),
            "the clip is invisible: {} bytes",
            rendered.len()
        );
    }
}
