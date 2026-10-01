//! The event stream, and what is deliberately kept out of it.
//!
//! This is a debugging aid first: when a harness run goes wrong, the question
//! is always "what did it think it was doing". It is bounded, because a run that
//! loops would otherwise produce a result larger than the work it was doing.

use std::sync::Mutex;

use crate::task::{Event, EventKind, StopReason};

/// How many events are kept. Enough to reconstruct the shape of a run, small
/// enough that the result document stays readable.
///
/// The **most recent** this many. The result document documents this field as
/// the tail of the transcript, and a tail that drops from the front is the only
/// kind that keeps the events worth having: a bound that refuses new events
/// once it is full loses the end of the run, which is where `stopped`,
/// `failed` and every late compaction live.
const MAX_EVENTS: usize = 400;

/// Collects events for the result document.
pub struct Sink {
    version: &'static str,
    events: Mutex<Vec<Event>>,
    turn: Mutex<u32>,
}

impl Sink {
    pub fn new(version: &'static str) -> Self {
        Self {
            version,
            events: Mutex::new(Vec::new()),
            turn: Mutex::new(0),
        }
    }

    fn push(&self, kind: EventKind, detail: Option<String>) {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        events.push(Event {
            at: chrono::Utc::now(),
            turn: *self.turn.lock().unwrap_or_else(|e| e.into_inner()),
            kind,
            detail: detail.map(|text| crate::clip(&text, 240)),
        });
        if events.len() > MAX_EVENTS {
            let excess = events.len() - MAX_EVENTS;
            events.drain(..excess);
        }
    }

    pub fn started(&self) {
        self.push(
            EventKind::Started {
                harness: self.version.to_owned(),
            },
            None,
        );
    }

    pub fn turn(&self, turn: u32) {
        if let Ok(mut current) = self.turn.lock() {
            *current = turn;
        }
        self.push(EventKind::Turn, None);
    }

    pub fn request(&self, model: &str) {
        self.push(
            EventKind::Request {
                model: model.to_owned(),
            },
            None,
        );
    }

    pub fn tool_call(&self, tool: &str) {
        self.push(
            EventKind::ToolCall {
                tool: tool.to_owned(),
            },
            None,
        );
    }

    pub fn tool_result(&self, tool: &str, ok: bool) {
        self.push(
            EventKind::ToolResult {
                tool: tool.to_owned(),
                ok,
            },
            None,
        );
    }

    pub fn validation(&self, ok: bool) {
        self.push(EventKind::Validation { ok }, None);
    }

    pub fn compacted(&self, from: u32, to: u32) {
        self.push(EventKind::Compacted { from, to }, None);
    }

    pub fn stopped(&self, reason: StopReason) {
        self.push(EventKind::Stopped { reason }, None);
    }

    pub fn failed(&self, message: &str) {
        self.push(
            EventKind::Failed {
                message: message.to_owned(),
            },
            None,
        );
    }

    /// Takes the collected events.
    pub fn drain(&self) -> Vec<Event> {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_is_bounded() {
        let sink = Sink::new("test");
        for _ in 0..MAX_EVENTS * 2 {
            sink.tool_call("read");
        }
        assert_eq!(sink.drain().len(), MAX_EVENTS);
    }

    #[test]
    fn details_are_clipped() {
        assert_eq!(crate::clip("short", 10), "short");
        let long = crate::clip(&"x".repeat(50), 10);
        assert_eq!(long.chars().count(), 11); // ten characters plus the ellipsis
    }

    /// The bound must not cost the end of the run.
    ///
    /// `stopped` is the field an operator reads first and it is written last,
    /// so a bound that stops accepting events once it is full deletes exactly
    /// the answer to "why did this stop" from every long run's result document.
    #[test]
    fn a_long_run_still_records_how_it_ended() {
        let sink = Sink::new("test");
        sink.started();
        for index in 0..MAX_EVENTS * 3 {
            sink.tool_call("read");
            sink.tool_result("read", index % 7 == 0);
        }
        sink.stopped(StopReason::TurnBudget);
        let events = sink.drain();
        assert_eq!(events.len(), MAX_EVENTS, "the bound still holds");
        assert!(
            events
                .last()
                .is_some_and(|event| matches!(event.kind, EventKind::Stopped { .. })),
            "the last event is not the one that says the run stopped: {:?}",
            events.last().map(|event| &event.kind)
        );
    }
}
