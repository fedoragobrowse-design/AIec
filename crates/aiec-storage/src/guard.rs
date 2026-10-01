use crate::{MemoryData, MemoryRepository, StoreError, owned};
use aiec_core::{
    Sandbox, SandboxState,
    storage::{
        BudgetDebit, GuardBudgetState, GuardFence, GuardIdentity, GuardIncident, WorkerLease,
    },
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[cfg(test)]
mod tests;

pub(crate) fn initialize(
    existing: Option<&GuardBudgetState>,
    state: GuardBudgetState,
) -> Result<GuardBudgetState, StoreError> {
    if let Some(existing) = existing {
        if existing.identity != state.identity
            || existing.expires_at != state.expires_at
            || existing.max_model_requests != state.max_model_requests
            || existing.max_bytes_in != state.max_bytes_in
            || existing.max_bytes_out != state.max_bytes_out
        {
            return Err(StoreError::Conflict(
                "Guard budget identity, caps and expiration are immutable".into(),
            ));
        }
        return Ok(existing.clone());
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
    if state.quarantined || sandbox.state == SandboxState::Quarantined {
        return Err(StoreError::Conflict("Guard sandbox is quarantined".into()));
    }
    if matches!(
        sandbox.state,
        SandboxState::Destroying
            | SandboxState::Destroyed
            | SandboxState::Failed
            | SandboxState::Stopped
            | SandboxState::Stopping
    ) {
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

pub(crate) fn expired(state: &GuardBudgetState, now: DateTime<Utc>) -> bool {
    state.quarantined
        || state.expires_at <= now
        || state.model_requests >= state.max_model_requests
        || state.bytes_in >= state.max_bytes_in
        || state.bytes_out >= state.max_bytes_out
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
    ) -> Result<Vec<GuardBudgetState>, StoreError> {
        Ok(self
            .data
            .read()
            .await
            .guard_budgets
            .values()
            .filter(|state| expired(state, now))
            .cloned()
            .collect())
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
