use super::{
    PostgresRepository, StoreError, database_error, insert_sandbox_event, lease_from_row,
    lock_sandbox, sandbox_from_row,
};
use crate::guard::{initialize, merge_incident, reserve, validate_fence};
use aiec_core::{
    Sandbox, SandboxState,
    storage::{BudgetDebit, GuardBudgetState, GuardFence, GuardIdentity, GuardIncident},
};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

// Match capacity release/recovery: lease -> sandbox -> budget -> incident. No
// Guard transaction holds a sandbox lock while waiting for its owning lease.
async fn lock_owned(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
    fence: GuardFence,
) -> Result<Sandbox, StoreError> {
    let row = sqlx::query("SELECT * FROM sandbox_leases WHERE tenant_id=$1 AND sandbox_id=$2 AND status='active' FOR UPDATE")
        .bind(tenant).bind(id).fetch_optional(&mut **tx).await.map_err(database_error)?;
    // Tenant mismatches are indistinguishable from absent sandboxes.
    let sandbox = sandbox_from_row(&lock_sandbox(tx, tenant, id).await?)?;
    let lease = row
        .as_ref()
        .map(lease_from_row)
        .transpose()?
        .ok_or_else(|| StoreError::Conflict("Guard sandbox has no active lease".into()))?;
    validate_fence(&lease, fence, Utc::now())?;
    Ok(sandbox)
}

async fn budget(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<GuardBudgetState, StoreError> {
    let payload: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM guard_budgets WHERE tenant_id=$1 AND sandbox_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    serde_json::from_value(payload.ok_or(StoreError::NotFound)?).map_err(StoreError::Json)
}

async fn save_budget(
    tx: &mut Transaction<'_, Postgres>,
    state: &GuardBudgetState,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE guard_budgets SET payload=$1, expires_at=$4, updated_at=now() WHERE tenant_id=$2 AND sandbox_id=$3")
        .bind(serde_json::to_value(state)?).bind(state.identity.tenant_id).bind(state.identity.sandbox_id).bind(state.expires_at)
        .execute(&mut **tx).await.map_err(database_error)?;
    Ok(())
}

impl PostgresRepository {
    pub(crate) async fn put_guard_budget(
        &self,
        state: GuardBudgetState,
    ) -> Result<GuardBudgetState, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let sandbox = sandbox_from_row(
            &lock_sandbox(&mut tx, state.identity.tenant_id, state.identity.sandbox_id).await?,
        )?;
        let existing: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM guard_budgets WHERE tenant_id=$1 AND sandbox_id=$2 FOR UPDATE",
        )
        .bind(state.identity.tenant_id)
        .bind(state.identity.sandbox_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        let existing = existing
            .map(serde_json::from_value::<GuardBudgetState>)
            .transpose()?;
        let mut result = initialize(existing.as_ref(), state)?;
        if sandbox.state == SandboxState::Quarantined {
            result.quarantined = true;
        }
        if existing.is_none() {
            sqlx::query(
                "INSERT INTO guard_budgets (sandbox_id,tenant_id,payload,expires_at) VALUES ($1,$2,$3,$4)",
            )
            .bind(result.identity.sandbox_id)
            .bind(result.identity.tenant_id)
            .bind(serde_json::to_value(&result)?)
            .bind(result.expires_at)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        } else {
            save_budget(&mut tx, &result).await?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }
    pub(crate) async fn get_guard_budget(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<GuardBudgetState, StoreError> {
        let payload: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM guard_budgets WHERE tenant_id=$1 AND sandbox_id=$2",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?;
        serde_json::from_value(payload.ok_or(StoreError::NotFound)?).map_err(StoreError::Json)
    }
    pub(crate) async fn reserve_guard_budget(
        &self,
        identity: GuardIdentity,
        fence: GuardFence,
        debit: BudgetDebit,
    ) -> Result<GuardBudgetState, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let sandbox = lock_owned(&mut tx, identity.tenant_id, identity.sandbox_id, fence).await?;
        let state = budget(&mut tx, identity.tenant_id, identity.sandbox_id).await?;
        let result = reserve(&state, &sandbox, &identity, debit, Utc::now())?;
        save_budget(&mut tx, &result).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }
    pub(crate) async fn put_guard_incident(
        &self,
        incident: GuardIncident,
    ) -> Result<GuardIncident, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let identity = &incident.identity;
        lock_owned(
            &mut tx,
            identity.tenant_id,
            identity.sandbox_id,
            incident.fence,
        )
        .await?;
        let state = budget(&mut tx, identity.tenant_id, identity.sandbox_id).await?;
        if state.identity != *identity {
            return Err(StoreError::Conflict(
                "Guard policy identity mismatch".into(),
            ));
        }
        let existing: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM guard_incidents WHERE tenant_id=$1 AND sandbox_id=$2 FOR UPDATE",
        )
        .bind(identity.tenant_id)
        .bind(identity.sandbox_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        let existing = existing
            .map(serde_json::from_value::<GuardIncident>)
            .transpose()?;
        let result = merge_incident(existing.as_ref(), incident)?;
        sqlx::query("INSERT INTO guard_incidents (sandbox_id,tenant_id,incident_id,payload) VALUES ($1,$2,$3,$4) ON CONFLICT (sandbox_id) DO UPDATE SET payload=EXCLUDED.payload, updated_at=now()")
            .bind(result.identity.sandbox_id).bind(result.identity.tenant_id).bind(result.id).bind(serde_json::to_value(&result)?)
            .execute(&mut *tx).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }
    pub(crate) async fn get_guard_incident(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<GuardIncident, StoreError> {
        let payload: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM guard_incidents WHERE tenant_id=$1 AND sandbox_id=$2",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?;
        serde_json::from_value(payload.ok_or(StoreError::NotFound)?).map_err(StoreError::Json)
    }
    pub(crate) async fn list_expired_guard_budgets(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<GuardBudgetState>, StoreError> {
        let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT b.payload FROM guard_budgets b JOIN sandboxes s ON s.id=b.sandbox_id AND s.tenant_id=b.tenant_id WHERE s.state NOT IN ('destroyed','destroying') AND (b.expires_at <= $1 OR (b.payload->>'quarantined')::boolean OR (b.payload->>'model_requests')::numeric >= (b.payload->>'max_model_requests')::numeric OR (b.payload->>'bytes_in')::numeric >= (b.payload->>'max_bytes_in')::numeric OR (b.payload->>'bytes_out')::numeric >= (b.payload->>'max_bytes_out')::numeric) ORDER BY b.sandbox_id")
            .bind(now).fetch_all(&self.pool).await.map_err(database_error)?;
        rows.into_iter()
            .map(|value| serde_json::from_value(value).map_err(StoreError::Json))
            .collect()
    }
    pub(crate) async fn mark_guard_quarantined(
        &self,
        tenant: Uuid,
        id: Uuid,
        fence: GuardFence,
    ) -> Result<Sandbox, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let mut sandbox = lock_owned(&mut tx, tenant, id, fence).await?;
        if sandbox.state != SandboxState::Quarantined
            && !sandbox.state.can_transition_to(SandboxState::Quarantined)
        {
            return Err(StoreError::Conflict("sandbox cannot be quarantined".into()));
        }
        let mut state = budget(&mut tx, tenant, id).await?;
        state.quarantined = true;
        save_budget(&mut tx, &state).await?;
        if sandbox.state != SandboxState::Quarantined {
            let previous = sandbox.state;
            let updated_at = Utc::now();
            sqlx::query("UPDATE sandboxes SET state='quarantined', updated_at=$1 WHERE tenant_id=$2 AND id=$3")
                .bind(updated_at).bind(tenant).bind(id).execute(&mut *tx).await.map_err(database_error)?;
            insert_sandbox_event(
                &mut tx,
                tenant,
                id,
                Some(previous),
                SandboxState::Quarantined,
                Some("Guard quarantine latched"),
            )
            .await?;
            sandbox.state = SandboxState::Quarantined;
            sandbox.updated_at = updated_at;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(sandbox)
    }
}
