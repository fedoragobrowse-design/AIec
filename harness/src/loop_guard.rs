//! Loop detection and the no-progress signal.
//!
//! A model stuck in a loop wastes the whole session's budget. A model legitimately
//! repeating a step does not. The difference is evidence: identical call,
//! identical arguments, and an identical observation, several times running.

use std::collections::VecDeque;

use crate::model::Response;

/// A progress marker. Deliberately not "tokens spent" — a model generating more
/// while changing nothing is the exact case this is meant to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// A file the model has not looked at before.
    NewFileInspected(String),
    /// A file's contents changed.
    FileChanged(String),
    /// A tool observation the model has not seen before.
    NewObservation(String),
    /// Something failed in a way the model has not seen before.
    NewError(String),
}

impl Progress {
    fn key(&self) -> String {
        match self {
            Self::NewFileInspected(p) => format!("read:{p}"),
            Self::FileChanged(p) => format!("write:{p}"),
            Self::NewObservation(o) => format!("obs:{o}"),
            Self::NewError(e) => format!("err:{e}"),
        }
    }
}

/// Watches for a provable no-progress loop.
pub struct LoopGuard {
    /// Signatures of recent turns, oldest first.
    recent: VecDeque<String>,
    /// How many of those recent turns were byte-identical to their neighbour.
    repeats: u32,
    seen_progress: std::collections::HashSet<String>,
    /// Repetition is normal up to a point. A model re-reading a file it just
    /// wrote, or retrying a failing test after a fix, is working.
    tolerance: u32,
}

impl LoopGuard {
    pub fn new(tolerance: u32) -> Self {
        Self {
            recent: VecDeque::new(),
            repeats: 0,
            seen_progress: std::collections::HashSet::new(),
            tolerance,
        }
    }

    /// Records the progress a turn made, if any. Returns true if it was new.
    pub fn record_progress(&mut self, progress: &[Progress]) -> bool {
        let mut any_new = false;
        for item in progress {
            if self.seen_progress.insert(item.key()) {
                any_new = true;
            }
        }
        if any_new {
            // New evidence breaks the streak: this is what stops a genuine fix
            // from being mistaken for a loop.
            self.repeats = 0;
        }
        any_new
    }

    /// Feeds one turn. Returns true when the session should stop.
    pub fn observe_turn(&mut self, response: &Response, observations: &[(String, bool)]) -> bool {
        // The whole turn's fingerprint: the calls and what came back.
        let mut fingerprint = String::new();
        for call in &response.tool_calls {
            fingerprint.push_str(&call.signature());
            fingerprint.push('\n');
        }
        for (text, _) in observations {
            fingerprint.push_str(text);
            fingerprint.push('\n');
        }

        if self.repeats_back() {
            self.repeats = self.repeats.saturating_add(1);
        } else {
            self.repeats = 0;
        }

        self.recent.push_back(fingerprint);
        // Only enough history to compare against the last turn.
        while self.recent.len() > 2 {
            self.recent.pop_front();
        }

        self.repeats >= self.tolerance
    }

    fn repeats_back(&self) -> bool {
        if self.recent.len() < 2 {
            return false;
        }
        let (Some(a), Some(b)) = (self.recent.front(), self.recent.back()) else {
            return false;
        };
        // Compared by reference: indexing a VecDeque would move the strings out.
        a == b
    }
}

/// Infers progress from a turn, so the caller does not have to classify it.
pub fn classify(response: &Response, observations: &[(String, bool)]) -> Vec<Progress> {
    let mut out = Vec::new();
    for call in &response.tool_calls {
        let path = serde_json::from_str::<serde_json::Value>(&call.arguments)
            .ok()
            .and_then(|v| v.get("path").and_then(|p| p.as_str()).map(str::to_owned));
        match (call.name.as_str(), path) {
            ("read", Some(p)) => out.push(Progress::NewFileInspected(p)),
            ("write" | "edit", Some(p)) => out.push(Progress::FileChanged(p)),
            _ => {}
        }
    }
    for (text, ok) in observations {
        if *ok {
            out.push(Progress::NewObservation(text.clone()));
        } else {
            out.push(Progress::NewError(text.clone()));
        }
    }
    out
}
