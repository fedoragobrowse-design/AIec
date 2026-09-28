//! Counting, and stopping when the count runs out.
//!
//! An agent inside a disposable VM has a natural budget: the VM's remaining
//! lifetime. Counting turns and model requests separately matters because a
//! single turn can make several requests, so a turn ceiling alone would not stop
//! a model that calls tools in a loop.

use crate::task::Usage;

/// The ceilings, and what has been spent against them.
#[derive(Debug)]
pub struct Budget {
    turns: u32,
    requests: u32,
    max_turns: u32,
    max_requests: u32,
    /// Space held back for the model's own reply, so a long turn is not cut off
    /// mid-sentence by the context ceiling.
    reserve_output: u32,
    pub usage: Usage,
}

impl Budget {
    pub fn new(max_turns: u32, max_requests: u32) -> Self {
        Self {
            turns: 0,
            requests: 0,
            max_turns: max_turns.max(1),
            max_requests: max_requests.max(1),
            reserve_output: 4096,
            usage: Usage::default(),
        }
    }

    pub fn next_turn(&mut self) {
        self.turns = self.turns.saturating_add(1);
    }

    pub fn charge_request(&mut self) {
        self.requests = self.requests.saturating_add(1);
    }

    pub fn turns(&self) -> u32 {
        self.turns
    }

    pub fn requests(&self) -> u32 {
        self.requests
    }

    pub fn turns_exhausted(&self) -> bool {
        self.turns >= self.max_turns
    }

    pub fn requests_exhausted(&self) -> bool {
        self.requests >= self.max_requests
    }

    /// Tokens to hold back for the reply.
    pub fn reserve_output(&self) -> u32 {
        self.reserve_output
    }

    /// Records what a request actually cost, from a provider's own report.
    ///
    /// Providers that do not report usage send none, and the ledger then simply
    /// stays short rather than being invented.
    pub fn absorb(&mut self, usage: crate::task::Usage) {
        self.usage.input_tokens = self.usage.input_tokens.saturating_add(usage.input_tokens);
        self.usage.output_tokens = self.usage.output_tokens.saturating_add(usage.output_tokens);
        self.usage.cached_input_tokens = self
            .usage
            .cached_input_tokens
            .saturating_add(usage.cached_input_tokens);
        self.usage.requests = self.requests;
    }

    /// Records what a request actually cost.
    pub fn absorb_usage(&mut self, input: u64, output: u64, cached: u64) {
        self.usage.input_tokens = self.usage.input_tokens.saturating_add(input);
        self.usage.output_tokens = self.usage.output_tokens.saturating_add(output);
        self.usage.cached_input_tokens = self.usage.cached_input_tokens.saturating_add(cached);
        self.usage.requests = self.requests;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_stop_rather_than_run_forever() {
        let mut budget = Budget::new(2, 3);
        assert!(!budget.turns_exhausted());
        budget.next_turn();
        assert!(!budget.turns_exhausted());
        budget.next_turn();
        assert!(budget.turns_exhausted());
    }

    #[test]
    fn a_zero_budget_still_allows_one_turn() {
        // Zero would be a run that cannot start, which is worse than one turn.
        let mut budget = Budget::new(0, 0);
        assert!(!budget.turns_exhausted());
        budget.next_turn();
        assert!(budget.turns_exhausted());
    }

    #[test]
    fn usage_accumulates_without_overflowing() {
        let mut budget = Budget::new(4, 4);
        budget.absorb_usage(u64::MAX, 10, 5);
        budget.absorb_usage(10, 10, 5);
        assert_eq!(
            budget.usage.input_tokens,
            u64::MAX,
            "saturating, not wrapped"
        );
        assert!(budget.usage.output_tokens == 20);
    }
}
