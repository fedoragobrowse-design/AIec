use crate::{MemoryData, MemoryRepository, StoreError, owned, page};
use aiec_core::{
    GuardProposal, Sandbox, SandboxState,
    storage::{
        BudgetDebit, GuardBudgetState, GuardFence, GuardIdentity, GuardIncident, GuardProposalPage,
        MAX_GUARD_PAGE, PageCursor, WorkerLease,
    },
};
use aiec_guard::proposals::ProposalState;

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[cfg(test)]
mod tests;

pub(crate) fn initialize(
    existing: Option<&GuardBudgetState>,
    state: GuardBudgetState,
) -> Result<GuardBudgetState, StoreError> {
    if let Some(existing) = existing {
        if existing.identity.sandbox_id != state.identity.sandbox_id
            || existing.identity.tenant_id != state.identity.tenant_id
            || existing.expires_at != state.expires_at
            || existing.max_model_requests != state.max_model_requests
            || existing.max_bytes_in != state.max_bytes_in
            || existing.max_bytes_out != state.max_bytes_out
        {
            return Err(StoreError::Conflict(
                "Guard budget ownership, caps and expiration are immutable".into(),
            ));
        }
        let mut carried = existing.clone();
        // Usage already spent under the previous policy is still spent. A
        // human approval may change what the sandbox may reach; it may not buy
        // the sandbox a second allowance, so the counters move with the
        // policy identity and never reset to zero.
        carried.identity.policy_hash = state.identity.policy_hash;
        return Ok(carried);
    }
    if state.model_requests != 0 || state.bytes_in != 0 || state.bytes_out != 0 || state.quarantined
    {
        return Err(StoreError::Conflict(
            "Guard budget must initialize with zero usage and no quarantine".into(),
        ));
    }
    Ok(state)
}

pub(crate) fn validate_fence(
    lease: &WorkerLease,
    fence: GuardFence,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    if lease.id != fence.lease_id || lease.status != "active" || lease.expires_at <= now {
        return Err(StoreError::Conflict(
            "Guard fence has no current active unexpired lease".into(),
        ));
    }
    if fence.generation <= 0 || fence.generation > lease.generation {
        return Err(StoreError::Conflict(
            "Guard fence generation was never issued".into(),
        ));
    }
    Ok(())
}

pub(crate) fn reserve(
    state: &GuardBudgetState,
    sandbox: &Sandbox,
    identity: &GuardIdentity,
    debit: BudgetDebit,
    now: DateTime<Utc>,
) -> Result<GuardBudgetState, StoreError> {
    if &state.identity != identity {
        return Err(StoreError::Conflict(
            "Guard policy identity mismatch".into(),
        ));
    }
    // The durable latch is separate from the sandbox's state: a quarantined
    // budget stays latched whatever the machine is doing, and releasing it is
    // the operator's call, not a state transition's.
    if state.quarantined {
        return Err(StoreError::Conflict("Guard sandbox is quarantined".into()));
    }
    // `consumes` is the same predicate the durable reaper filters its window
    // with, so a machine that has stopped being watched also stops being
    // charged. Enumerating states here instead would drift from it: `paused`
    // was missing from an earlier hand-written list, leaving an operator-paused
    // machine able to charge a budget no reaper would ever enforce.
    if !sandbox.state.consumes() {
        return Err(StoreError::Conflict("Guard sandbox is not active".into()));
    }
    if state.expires_at <= now {
        return Err(StoreError::QuotaExceeded(
            "Guard sandbox lifetime expired".into(),
        ));
    }
    let add = |used: u64, amount: u64, cap: u64| {
        used.checked_add(amount)
            .filter(|next| *next <= cap)
            .ok_or_else(|| {
                StoreError::QuotaExceeded("Guard model budget exhausted or overflowed".into())
            })
    };
    let mut result = state.clone();
    result.model_requests = add(
        state.model_requests,
        debit.model_requests,
        state.max_model_requests,
    )?;
    result.bytes_in = add(state.bytes_in, debit.bytes_in, state.max_bytes_in)?;
    result.bytes_out = add(state.bytes_out, debit.bytes_out, state.max_bytes_out)?;
    Ok(result)
}

/// Whether this budget still needs the reaper's attention.
///
/// `quarantined` is deliberately not a reason. A quarantined budget has had
/// the work done, but the sandbox it belongs to is not destroyed until an
/// operator releases it, so the row stays in the collection for a long time.
/// Reporting it as expired is what let handled budgets crowd the reaper's
/// window.
pub(crate) fn expired(state: &GuardBudgetState, now: DateTime<Utc>) -> bool {
    !state.quarantined
        && (state.expires_at <= now
            || state.model_requests >= state.max_model_requests
            || state.bytes_in >= state.max_bytes_in
            || state.bytes_out >= state.max_bytes_out)
}

fn validate_incident_evidence(incident: &GuardIncident) -> Result<(), StoreError> {
    let invalid =
        || StoreError::Conflict("Guard incident evidence chain or anchor is invalid".into());
    let count = u64::try_from(incident.events.len()).map_err(|_| invalid())?;
    if incident.event_start_sequence == 0
        || incident
            .event_start_sequence
            .checked_add(count)
            .and_then(|n| n.checked_sub(1))
            != Some(incident.event_sequence)
    {
        return Err(invalid());
    }
    let mut previous = incident.event_previous_hash.as_str();
    if previous.len() != 64
        || !previous
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    for event in &incident.events {
        if event.sandbox_id != incident.identity.sandbox_id
            || event.tenant_id != incident.identity.tenant_id
            || event.policy_hash != incident.identity.policy_hash
            || event.previous_hash != previous
        {
            return Err(invalid());
        }
        event.verify_bounds().map_err(|_| invalid())?;
        event.verify_self_hash().map_err(|_| invalid())?;
        previous = &event.current_hash;
    }
    if incident.event_head != previous {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn merge_incident(
    existing: Option<&GuardIncident>,
    incoming: GuardIncident,
) -> Result<GuardIncident, StoreError> {
    validate_incident_evidence(&incoming)?;
    let mut result = match existing {
        None => incoming,
        Some(existing) => {
            if existing.identity != incoming.identity
                || existing.fence.lease_id != incoming.fence.lease_id
            {
                return Err(StoreError::Conflict(
                    "Guard incident identity and owning lease are immutable".into(),
                ));
            }
            let mut result = existing.clone();
            if existing.snapshot_id.is_some()
                && incoming.snapshot_id.is_some()
                && existing.snapshot_id != incoming.snapshot_id
            {
                return Err(StoreError::Conflict(
                    "Guard incident snapshot is immutable once recorded".into(),
                ));
            }
            // Earlier-stage retries retain the original incident id, evidence and applied actions.
            if !incoming.events.starts_with(&existing.events)
                && !existing.events.starts_with(&incoming.events)
            {
                return Err(StoreError::Conflict(
                    "Guard incident evidence cannot be rewritten".into(),
                ));
            }
            if existing.event_start_sequence != incoming.event_start_sequence
                || existing.event_previous_hash != incoming.event_previous_hash
                || (existing.events.len() == incoming.events.len()
                    && (existing.event_sequence != incoming.event_sequence
                        || existing.event_head != incoming.event_head))
            {
                return Err(StoreError::Conflict(
                    "Guard incident evidence anchors cannot be rewritten".into(),
                ));
            }
            if existing.completed_at.is_none() {
                result.network_cut_at = existing.network_cut_at.or(incoming.network_cut_at);
                result.paused_at = existing.paused_at.or(incoming.paused_at);
                result.snapshot_id = existing
                    .snapshot_id
                    .clone()
                    .or(incoming.snapshot_id.clone());
                result.completed_at = incoming.completed_at;
                if incoming.events.len() > existing.events.len() {
                    result.events = incoming.events.clone();
                    result.event_sequence = incoming.event_sequence;
                    result.event_head = incoming.event_head.clone();
                }
                for rule in &incoming.rules {
                    if !result.rules.contains(rule) {
                        result.rules.push(rule.clone());
                    }
                }
                if !incoming.report.is_empty() {
                    result.report = incoming.report.clone();
                }
            }
            result.notified_at = existing.notified_at.or(incoming.notified_at);
            for error in &incoming.errors {
                if !result.errors.contains(error) {
                    result.errors.push(error.clone());
                }
            }
            result
        }
    };
    if result.completed_at.is_some()
        && (result.network_cut_at.is_none()
            || result.paused_at.is_none()
            || result.snapshot_id.as_ref().is_none_or(|id| id.is_empty())
            || result.report.is_empty())
    {
        return Err(StoreError::Conflict(
            "Guard incident cannot complete before cut, pause, preservation and report".into(),
        ));
    }
    // Retain the first fence, including its issued generation, across renewals.
    if let Some(existing) = existing {
        result.fence = existing.fence;
    }
    Ok(result)
}

fn memory_lease(
    data: &MemoryData,
    tenant: Uuid,
    id: Uuid,
    fence: GuardFence,
) -> Result<(), StoreError> {
    let lease = data
        .leases
        .values()
        .find(|lease| {
            lease.tenant_id == tenant && lease.sandbox_id == id && lease.status == "active"
        })
        .ok_or_else(|| StoreError::Conflict("Guard sandbox has no active lease".into()))?;
    validate_fence(lease, fence, Utc::now())
}

impl MemoryRepository {
    pub(crate) async fn put_guard_budget(
        &self,
        state: GuardBudgetState,
    ) -> Result<GuardBudgetState, StoreError> {
        let mut data = self.data.write().await;
        let sandbox = owned(&data, state.identity.tenant_id, state.identity.sandbox_id)?;
        let mut state = initialize(data.guard_budgets.get(&sandbox.id), state)?;
        if sandbox.state == SandboxState::Quarantined {
            state.quarantined = true;
        }
        data.guard_budgets.insert(sandbox.id, state.clone());
        Ok(state)
    }
    pub(crate) async fn get_guard_budget(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<GuardBudgetState, StoreError> {
        let data = self.data.read().await;
        owned(&data, tenant, id)?;
        data.guard_budgets
            .get(&id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }
    pub(crate) async fn reserve_guard_budget(
        &self,
        identity: GuardIdentity,
        fence: GuardFence,
        debit: BudgetDebit,
    ) -> Result<GuardBudgetState, StoreError> {
        let mut data = self.data.write().await;
        let sandbox = owned(&data, identity.tenant_id, identity.sandbox_id)?;
        memory_lease(&data, identity.tenant_id, identity.sandbox_id, fence)?;
        let state = data
            .guard_budgets
            .get(&sandbox.id)
            .ok_or(StoreError::NotFound)?;
        let result = reserve(state, &sandbox, &identity, debit, Utc::now())?;
        data.guard_budgets.insert(sandbox.id, result.clone());
        Ok(result)
    }
    pub(crate) async fn put_guard_incident(
        &self,
        incident: GuardIncident,
    ) -> Result<GuardIncident, StoreError> {
        let mut data = self.data.write().await;
        let identity = &incident.identity;
        owned(&data, identity.tenant_id, identity.sandbox_id)?;
        memory_lease(
            &data,
            identity.tenant_id,
            identity.sandbox_id,
            incident.fence,
        )?;
        let budget = data
            .guard_budgets
            .get(&identity.sandbox_id)
            .ok_or(StoreError::NotFound)?;
        if budget.identity != *identity {
            return Err(StoreError::Conflict(
                "Guard policy identity mismatch".into(),
            ));
        }
        let id = identity.sandbox_id;
        let result = merge_incident(data.guard_incidents.get(&id), incident)?;
        data.guard_incidents.insert(id, result.clone());
        Ok(result)
    }
    pub(crate) async fn get_guard_incident(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<GuardIncident, StoreError> {
        let data = self.data.read().await;
        owned(&data, tenant, id)?;
        data.guard_incidents
            .get(&id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }
    pub(crate) async fn list_expired_guard_budgets(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<GuardBudgetState>, StoreError> {
        let data = self.data.read().await;
        let mut matching: Vec<GuardBudgetState> = data
            .guard_budgets
            .values()
            .filter(|state| expired(state, now))
            .filter(|state| {
                // The reaper can only quarantine a sandbox it can fence, and
                // only a consuming sandbox is work. Same two conditions the
                // database applies, so the window means the same thing in both
                // stores.
                let Some(sandbox) = data.sandboxes.get(&state.identity.sandbox_id) else {
                    return false;
                };
                if !sandbox.state.consumes() {
                    return false;
                }
                data.leases.values().any(|lease| {
                    lease.tenant_id == state.identity.tenant_id
                        && lease.sandbox_id == state.identity.sandbox_id
                        && lease.status == "active"
                        && lease.expires_at > now
                })
            })
            .cloned()
            .collect();
        // Ordered so the window the reaper takes is the same one the database
        // would return, and so consecutive ticks drain rather than repeat.
        matching.sort_by_key(|state| state.identity.sandbox_id);
        matching.truncate(limit);
        Ok(matching)
    }
    pub(crate) async fn mark_guard_quarantined(
        &self,
        tenant: Uuid,
        id: Uuid,
        fence: GuardFence,
    ) -> Result<Sandbox, StoreError> {
        let mut data = self.data.write().await;
        let mut sandbox = owned(&data, tenant, id)?;
        memory_lease(&data, tenant, id, fence)?;
        if sandbox.state != SandboxState::Quarantined
            && !sandbox.state.can_transition_to(SandboxState::Quarantined)
        {
            return Err(StoreError::Conflict("sandbox cannot be quarantined".into()));
        }
        data.guard_budgets
            .get_mut(&id)
            .ok_or(StoreError::NotFound)?
            .quarantined = true;
        if sandbox.state != SandboxState::Quarantined {
            sandbox.state = SandboxState::Quarantined;
            sandbox.updated_at = Utc::now();
            data.sandboxes.insert(id, sandbox.clone());
        }
        Ok(sandbox)
    }
}

impl MemoryRepository {
    pub(crate) async fn update_guard_policy(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        guard: &aiec_guard::policy::GuardConfig,
        policy_hash: &str,
    ) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        let row = data
            .sandboxes
            .get_mut(&sandbox)
            .filter(|row| row.tenant_id == tenant)
            .ok_or(StoreError::NotFound)?;
        row.environment.guard = Some(guard.clone());
        row.environment.guard_policy_hash = Some(policy_hash.to_owned());
        row.updated_at = Utc::now();
        Ok(())
    }

    pub(crate) async fn release_guard_quarantine(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        released_by: &str,
    ) -> Result<Sandbox, StoreError> {
        let mut data = self.data.write().await;
        {
            let row = data
                .sandboxes
                .get(&sandbox)
                .filter(|row| row.tenant_id == tenant)
                .ok_or(StoreError::NotFound)?;
            if row.state != SandboxState::Quarantined {
                return Err(StoreError::Conflict("sandbox is not quarantined".into()));
            }
        }
        let row = data.sandboxes.get_mut(&sandbox).expect("checked above");
        row.state = SandboxState::Paused;
        row.updated_at = Utc::now();
        let released = row.clone();
        if let Some(budget) = data.guard_budgets.get_mut(&sandbox) {
            budget.quarantined = false;
        }
        // The incident is deliberately left alone: it is the immutable record
        // of what happened, and a release is recorded as an audit event beside
        // it rather than by rewriting the history.
        let _ = released_by;
        Ok(released)
    }

    /// Records a proposal, and advances its state only forward.
    pub(crate) async fn put_guard_proposal(
        &self,
        proposal: GuardProposal,
    ) -> Result<GuardProposal, StoreError> {
        let mut data = self.data.write().await;
        owned(&data, proposal.tenant_id, proposal.sandbox_id)?;
        let stored = data
            .guard_proposals
            .entry(proposal.id)
            .or_insert(proposal.clone());
        if stored.sandbox_id != proposal.sandbox_id
            || stored.tenant_id != proposal.tenant_id
            || stored.agent_id != proposal.agent_id
            || stored.base_policy_hash != proposal.base_policy_hash
            || stored.request != proposal.request
            || stored.created_at != proposal.created_at
        {
            return Err(StoreError::Conflict(
                "a policy proposal cannot change what it asked for".into(),
            ));
        }
        // A decision is a decision. Terminal states never move again, so a
        // replayed request cannot reopen an approved or refused proposal.
        if !matches!(stored.state, ProposalState::Pending) {
            return Ok(stored.clone());
        }
        if !matches!(proposal.state, ProposalState::Pending)
            && (proposal.decided_by.is_none() || proposal.decided_at.is_none())
        {
            return Err(StoreError::Conflict(
                "a decided policy proposal requires an operator and a time".into(),
            ));
        }
        *stored = proposal.clone();
        Ok(stored.clone())
    }

    pub(crate) async fn list_guard_proposals(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        limit: u32,
        after: Option<PageCursor>,
    ) -> Result<GuardProposalPage, StoreError> {
        let limit = limit.clamp(1, MAX_GUARD_PAGE) as usize;
        let data = self.data.read().await;
        owned(&data, tenant, sandbox)?;
        let mut rows: Vec<GuardProposal> = data
            .guard_proposals
            .values()
            .filter(|row| row.tenant_id == tenant && row.sandbox_id == sandbox)
            .filter(|row| match after {
                None => true,
                Some(cursor) => (row.created_at, row.id) < (cursor.created_at, cursor.id),
            })
            .cloned()
            .collect();
        // Newest first, and the id breaks a tie in the same direction the
        // database's `id DESC` does, so both stores page identically.
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        let (proposals, next) = page(rows, limit, |row| (row.created_at, row.id));
        Ok(GuardProposalPage { proposals, next })
    }

    pub(crate) async fn get_guard_proposal(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        id: Uuid,
    ) -> Result<GuardProposal, StoreError> {
        let data = self.data.read().await;
        owned(&data, tenant, sandbox)?;
        data.guard_proposals
            .get(&id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }
}
