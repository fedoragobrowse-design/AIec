//! Out-of-guest control messages. Guest harness evidence is not accepted here.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Result, enforcement::CounterSnapshot, events::GuardEvent};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardIdentity {
    pub sandbox_id: Uuid,
    pub tenant_id: Uuid,
    pub policy_hash: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardFence {
    pub lease_id: Uuid,
    pub generation: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardBudgetState {
    pub identity: GuardIdentity,
    pub expires_at: DateTime<Utc>,
    pub max_model_requests: u64,
    pub max_bytes_in: u64,
    pub max_bytes_out: u64,
    pub model_requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub quarantined: bool,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BudgetDebit {
    pub model_requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Reservations must commit before upstream admission or forwarding bytes.
/// A lost authority connection refuses traffic; it cannot fall back to RAM.
#[async_trait]
pub trait BudgetAuthority: Send + Sync {
    async fn reserve(
        &self,
        identity: &GuardIdentity,
        fence: GuardFence,
        debit: BudgetDebit,
    ) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleTrigger {
    pub rule: String,
    pub first_event_sequence: Option<u64>,
    pub evidence_references: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardObservation {
    pub identity: GuardIdentity,
    pub fence: GuardFence,
    pub counters: CounterSnapshot,
    pub events: Vec<GuardEvent>,
    pub observed_at: DateTime<Utc>,
    pub event_start_sequence: u64,
    pub event_previous_hash: String,
    pub event_sequence: u64,
    pub event_head: String,
    pub network_cut: bool,
    pub paused: bool,
    pub budget: GuardBudgetState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRequest {
    pub fence: GuardFence,
    pub policy_hash: String,
    pub rules: Vec<RuleTrigger>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardIncident {
    pub id: Uuid,
    pub identity: GuardIdentity,
    pub fence: GuardFence,
    pub rules: Vec<RuleTrigger>,
    pub triggered_at: DateTime<Utc>,
    pub network_cut_at: Option<DateTime<Utc>>,
    pub paused_at: Option<DateTime<Utc>>,
    pub snapshot_id: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    pub events: Vec<GuardEvent>,
    pub event_start_sequence: u64,
    pub event_previous_hash: String,
    pub event_sequence: u64,
    pub event_head: String,
    pub errors: Vec<String>,
    pub notified_at: Option<DateTime<Utc>>,
    pub report: String,
}

/// Worker-side telemetry before control-plane lease and durable budget enrichment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardRuntimeObservation {
    pub identity: GuardIdentity,
    pub counters: CounterSnapshot,
    pub events: Vec<GuardEvent>,
    pub observed_at: DateTime<Utc>,
    pub event_start_sequence: u64,
    pub event_previous_hash: String,
    pub event_sequence: u64,
    pub event_head: String,
    pub network_cut: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuardControlCommand {
    /// Applies a policy a human approved, on the worker that owns the policy.
    ///
    /// The control plane records and checks the human approval; the worker owns
    /// the live policy cell and the kernel rules, so it re-checks that the
    /// proposal was written against the policy still in force, verifies the
    /// candidate against the operator boundary, installs the rules, swaps the
    /// policy and appends the audit record. A refusal at any step leaves the
    /// previous policy and its hash in force.
    ApplyProposal {
        /// The durable proposal the control plane reviewed and approved.
        proposal: crate::proposals::Proposal,
        approved_by: String,
    },
    /// Binds an attachment to the ownership worker dispatch just proved, before
    /// a guarded machine is created or started. The fence moves forward within
    /// one lease and never backward, and a different lease cannot take an
    /// attachment that is already live.
    SetFence {
        fence: GuardFence,
    },
    Observe {
        policy_hash: String,
        after: u64,
    },
    Heartbeat {
        policy_hash: String,
    },
    Cut {
        policy_hash: String,
    },
    AppendEvent {
        policy_hash: String,
        event: crate::events::EventInput,
    },
    CapturePaused {
        snapshot_id: String,
    },
    /// Reopens an attachment a human has released.
    ///
    /// The worker clears the latch and reinstalls the rules; the control plane
    /// only marks the sandbox released afterwards, so a released sandbox is one
    /// whose network actually carries traffic again.
    Release {
        policy_hash: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum GuardControlResponse {
    Unit,
    Observation(GuardRuntimeObservation),
    Event(GuardEvent),
    Forensics {
        snapshot_id: String,
        size_bytes: u64,
    },
    Released {
        policy_hash: String,
    },
    PolicyApplied {
        proposal_id: Uuid,
        previous_policy_hash: String,
        policy_hash: String,
    },
}
