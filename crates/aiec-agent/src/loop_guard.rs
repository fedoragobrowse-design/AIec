//! Detecting a loop before it costs a VM's worth of tokens.
//!
//! Two independent signals, because they catch different failures. A *repeated
//! call* catches a model asking for the same thing over and over. A *no progress*
//! check catches a model doing plenty of work that changes nothing - reading
//! files, running searches, editing nothing - which looks busy and is not.

use std::collections::VecDeque;

/// How many recent calls are remembered for the repeat check.
const WINDOW: usize = 8;

/// The same call this many times in a row is a loop, not a strategy.
const REPEAT_LIMIT: u32 = 3;

/// Edits that change nothing, in a row, mean the agent has lost the thread.
const NO_PROGRESS_LIMIT: u32 = 6;

use crate::task::StopReason;

#[derive(Debug, Default)]
pub struct Guard {
    recent: VecDeque<String>,
    repeats: u32,
    unproductive: u32,
}

impl Guard {
    /// Records a call the agent is about to make.
    pub fn observe(&mut self, call: &crate::model::ToolCall) {
        let signature = call.signature();
        if self.recent.back() == Some(&signature) {
            self.repeats += 1;
        } else {
            self.repeats = 0;
            self.recent.push_back(signature);
            while self.recent.len() > WINDOW {
                self.recent.pop_front();
            }
        }
    }

    /// Records what a tool actually did.
    ///
    /// Only edits can make progress. A read that succeeds is progress in the
    /// sense that the model learned something, but the model repeating a read
    /// is caught above, so counting only edits here is enough to catch the
    /// "edits, then reverts, then edits" spiral.
    pub fn observe_effect(&mut self, changed_anything: bool) {
        if changed_anything {
            self.unproductive = 0;
        } else {
            self.unproductive = self.unproductive.saturating_add(1);
        }
    }

    /// Whether the run should stop, and why.
    pub fn stalled(&self) -> Option<StopReason> {
        if self.repeats >= REPEAT_LIMIT {
            return Some(StopReason::LoopDetected);
        }
        if self.unproductive >= NO_PROGRESS_LIMIT {
            return Some(StopReason::NoProgress);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ToolCall;

    fn call(name: &str, args: &str) -> ToolCall {
        ToolCall {
            id: "1".to_owned(),
            name: name.to_owned(),
            arguments: args.to_owned(),
        }
    }

    #[test]
    fn the_same_call_repeatedly_is_a_loop() {
        let mut guard = Guard::default();
        let read = call("read", "{\"path\":\"a.rs\"}");
        // The first call is not a repeat, so the limit is reached one call later.
        for _ in 0..=REPEAT_LIMIT {
            guard.observe(&read);
        }
        assert_eq!(guard.stalled(), Some(StopReason::LoopDetected));
    }

    #[test]
    fn varied_work_is_not_a_loop() {
        let mut guard = Guard::default();
        for index in 0..12 {
            guard.observe(&call("read", &format!("{{\"path\":\"file{index}.rs\"}}")));
        }
        assert_eq!(guard.stalled(), None);
    }

    #[test]
    fn work_that_changes_nothing_eventually_stops() {
        let mut guard = Guard::default();
        for _ in 0..NO_PROGRESS_LIMIT {
            guard.observe_effect(false);
        }
        assert_eq!(guard.stalled(), Some(StopReason::NoProgress));
    }

    #[test]
    fn real_progress_resets_the_stall_counter() {
        let mut guard = Guard::default();
        for _ in 0..NO_PROGRESS_LIMIT - 1 {
            guard.observe_effect(false);
        }
        guard.observe_effect(true);
        for _ in 0..NO_PROGRESS_LIMIT - 1 {
            guard.observe_effect(false);
        }
        assert_eq!(guard.stalled(), None);
    }
}
