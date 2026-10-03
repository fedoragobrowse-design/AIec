//! Durable policy proposals.
//!
//! A proposal records what an agent asked for and what a human decided. It has
//! to outlive the process that received it, so it lives in the control plane
//! and is only ever advanced, never rewritten.

use aiec_core::{CoreError, GuardProposal};
use aiec_guard::proposals::ProposalState;
use chrono::{DateTime, Utc};
use sqlx::Row;

use crate::{PostgresRepository, StoreError, core_error, database_error};

fn map(error: StoreError) -> CoreError {
    core_error(error)
}

impl PostgresRepository {
    pub(crate) async fn update_guard_policy(
        &self,
        tenant: uuid::Uuid,
        sandbox: uuid::Uuid,
        guard: &aiec_guard::policy::GuardConfig,
        policy_hash: &str,
    ) -> Result<(), CoreError> {
        let config = serde_json::to_value(guard).map_err(|error| {
            CoreError::Backend(format!("guard config did not serialize: {error}"))
        })?;
        let changed = sqlx::query(
            "UPDATE sandboxes SET environment =              jsonb_set(jsonb_set(environment, '{guard}', $3::jsonb), '{guard_policy_hash}',              to_jsonb($4::text)), updated_at = now() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(sandbox)
        .bind(tenant)
        .bind(config)
        .bind(policy_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| map(database_error(e)))?
        .rows_affected();
        if changed == 0 {
            return Err(CoreError::NotFound("no such sandbox".into()));
        }
        Ok(())
    }

    /// Clears a durable quarantine after the worker has reopened the network.
    ///
    /// The latch trigger on `sandboxes` refuses any update that leaves
    /// `quarantined`, so this is the one path that may: it is reached only from
    /// the release route, after a fenced dispatch that reopened the network, and
    /// it moves the sandbox to `paused` rather than to `running` - a released
    /// machine stays stopped until someone starts it deliberately.
    pub(crate) async fn release_guard_quarantine(
        &self,
        tenant: uuid::Uuid,
        sandbox: uuid::Uuid,
        released_by: &str,
    ) -> Result<aiec_core::Sandbox, CoreError> {
        if released_by.is_empty() || released_by.len() > 128 {
            return Err(CoreError::InvalidRequest(
                "releasing operator identity is empty or oversized".into(),
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(|e| core_error(e.into()))?;
        sqlx::query("SELECT state FROM sandboxes WHERE id = $1 AND tenant_id = $2 FOR UPDATE")
            .bind(sandbox)
            .bind(tenant)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|e| core_error(e.into()))?;
        // Both latches - the sandbox's and its budget's - recognise exactly one
        // exit, an operator release, and both require the marker to arrive in
        // the same statement as the state change. They are checked in that
        // order on purpose: the sandbox moves first, so the budget trigger can
        // see a released sandbox when it runs. Neither trigger is disabled;
        // disabling one is catalog-scoped and permanent, so it cannot be a
        // release mechanism.
        let result = sqlx::query(
            "UPDATE sandboxes
                SET state = 'paused', guard_released_at = now(), guard_released_by = $3, updated_at = now()
              WHERE id = $1 AND tenant_id = $2 AND state = 'quarantined'
              RETURNING id",
        )
        .bind(sandbox)
        .bind(tenant)
        .bind(released_by)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| core_error(database_error(e)))?;
        if result.is_none() {
            return Err(CoreError::Conflict("sandbox is not quarantined".into()));
        }
        // Scoped by tenant like every other statement here: the budget row is
        // keyed by sandbox alone, and a release must not be able to reach a
        // row belonging to another tenant that a sandbox id could collide with.
        sqlx::query(
            "UPDATE guard_budgets
                SET payload = jsonb_set(payload, '{quarantined}', 'false'::jsonb, true),
                    guard_released_at = now(), guard_released_by = $3, updated_at = now()
              WHERE sandbox_id = $1 AND tenant_id = $2",
        )
        .bind(sandbox)
        .bind(tenant)
        .bind(released_by)
        .execute(&mut *transaction)
        .await
        .map_err(|e| core_error(database_error(e)))?;
        transaction
            .commit()
            .await
            .map_err(|e| core_error(e.into()))?;
        let row = sqlx::query("SELECT * FROM sandboxes WHERE id = $1 AND tenant_id = $2")
            .bind(sandbox)
            .bind(tenant)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| core_error(e.into()))?;
        crate::postgres::sandbox_from_row(&row).map_err(core_error)
    }

    pub(crate) async fn put_guard_proposal(
        &self,
        proposal: GuardProposal,
    ) -> Result<GuardProposal, CoreError> {
        let mut transaction = self.pool.begin().await.map_err(|e| map(e.into()))?;
        let existing = sqlx::query(
            "SELECT agent_id, request, base_policy_hash, state, decided_by, decided_at, \
             created_at, tenant_id, sandbox_id \
             FROM guard_proposals WHERE id = $1 FOR UPDATE",
        )
        .bind(proposal.id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| map(e.into()))?;

        // The row is located by id alone, so the insert and the update cannot
        // race — which also means the row that comes back is not necessarily
        // this tenant's. The in-memory store refuses that outright and this one
        // has to as well, or the two backends disagree about who owns a
        // proposal. The database trigger cannot catch it either: `tenant_id` is
        // not in the SET clause, so a write aimed at someone else's row looks
        // like a same-tenant update to it.
        //
        // The immutability check below is a separate thing and does not cover
        // this: it fires on the fields a caller would otherwise have had to
        // change to get here. A caller presenting another tenant's row
        // unchanged and differing only in its own tenant id passes straight
        // through it.
        if let Some(row) = &existing {
            let owner: uuid::Uuid = row.try_get("tenant_id").map_err(|e| map(e.into()))?;
            let owner_sandbox: uuid::Uuid = row.try_get("sandbox_id").map_err(|e| map(e.into()))?;
            if owner != proposal.tenant_id || owner_sandbox != proposal.sandbox_id {
                // Indistinguishable from a proposal that does not exist.
                return Err(map(StoreError::NotFound));
            }
        }
        let Some(row) = existing else {
            sqlx::query(
                "INSERT INTO guard_proposals (id, tenant_id, sandbox_id, agent_id, request, \
                 base_policy_hash, state, decided_by, decided_at, created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            )
            .bind(proposal.id)
            .bind(proposal.tenant_id)
            .bind(proposal.sandbox_id)
            .bind(&proposal.agent_id)
            .bind(serde_json::to_value(&proposal.request).map_err(|e| map(StoreError::Json(e)))?)
            .bind(&proposal.base_policy_hash)
            .bind(serde_json::to_value(&proposal.state).map_err(|e| map(StoreError::Json(e)))?)
            .bind(&proposal.decided_by)
            .bind(proposal.decided_at)
            .bind(proposal.created_at)
            .execute(&mut *transaction)
            .await
            .map_err(|e| map(database_error(e)))?;
            transaction.commit().await.map_err(|e| map(e.into()))?;
            return Ok(proposal);
        };

        // What it asked for is fixed at write time; only the decision moves.
        if row
            .try_get::<String, _>("agent_id")
            .map_err(|e| map(e.into()))?
            != proposal.agent_id
            || row
                .try_get::<serde_json::Value, _>("request")
                .map_err(|e| map(e.into()))?
                != serde_json::to_value(&proposal.request).map_err(|e| map(StoreError::Json(e)))?
            || row
                .try_get::<String, _>("base_policy_hash")
                .map_err(|e| map(e.into()))?
                != proposal.base_policy_hash
            || row
                .try_get::<chrono::DateTime<Utc>, _>("created_at")
                .map_err(|e| map(e.into()))?
                != proposal.created_at
        {
            return Err(map(StoreError::Conflict(
                "a policy proposal cannot change what it asked for".into(),
            )));
        }
        let stored: ProposalState = serde_json::from_value(
            row.try_get("state").map_err(|e| map(e.into()))?,
        )
        .map_err(|_| {
            map(StoreError::Conflict(
                "stored proposal state is unreadable".into(),
            ))
        })?;
        let result = if matches!(stored, ProposalState::Pending) {
            sqlx::query(
                "UPDATE guard_proposals SET state = $2, decided_by = $3, decided_at = $4 \
                 WHERE id = $1 RETURNING state, decided_by, decided_at",
            )
            .bind(proposal.id)
            .bind(serde_json::to_value(&proposal.state).map_err(|e| map(StoreError::Json(e)))?)
            .bind(&proposal.decided_by)
            .bind(proposal.decided_at)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|e| map(database_error(e)))?
            .try_get::<serde_json::Value, _>("state")
            .map_err(|e| map(e.into()))?
        } else {
            row.try_get("state").map_err(|e| map(e.into()))?
        };
        let decided_by: Option<String> =
            sqlx::query("SELECT decided_by FROM guard_proposals WHERE id = $1")
                .bind(proposal.id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|e| map(e.into()))?
                .try_get("decided_by")
                .map_err(|e| map(e.into()))?;
        let decided_at: Option<DateTime<Utc>> =
            sqlx::query("SELECT decided_at FROM guard_proposals WHERE id = $1")
                .bind(proposal.id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|e| map(e.into()))?
                .try_get("decided_at")
                .map_err(|e| map(e.into()))?;
        transaction.commit().await.map_err(|e| map(e.into()))?;
        Ok(GuardProposal {
            state: serde_json::from_value(result).map_err(|_| {
                map(StoreError::Conflict(
                    "stored proposal state is unreadable".into(),
                ))
            })?,
            decided_by,
            decided_at,
            ..proposal
        })
    }

    pub(crate) async fn list_guard_proposals(
        &self,
        tenant: uuid::Uuid,
        sandbox: uuid::Uuid,
    ) -> Result<Vec<GuardProposal>, CoreError> {
        let rows = sqlx::query(
            "SELECT id, sandbox_id, tenant_id, agent_id, request, base_policy_hash, state, \
             decided_by, decided_at, created_at FROM guard_proposals \
             WHERE tenant_id = $1 AND sandbox_id = $2 ORDER BY created_at DESC, id",
        )
        .bind(tenant)
        .bind(sandbox)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map(e.into()))?;
        rows.into_iter().map(Self::proposal_row).collect()
    }

    pub(crate) async fn get_guard_proposal(
        &self,
        tenant: uuid::Uuid,
        sandbox: uuid::Uuid,
        id: uuid::Uuid,
    ) -> Result<GuardProposal, CoreError> {
        let row = sqlx::query(
            "SELECT id, sandbox_id, tenant_id, agent_id, request, base_policy_hash, state, \
             decided_by, decided_at, created_at FROM guard_proposals \
             WHERE id = $1 AND tenant_id = $2 AND sandbox_id = $3",
        )
        .bind(id)
        .bind(tenant)
        .bind(sandbox)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map(e.into()))?
        .ok_or(CoreError::NotFound("no such policy proposal".into()))?;
        Self::proposal_row(row)
    }

    fn proposal_row(row: sqlx::postgres::PgRow) -> Result<GuardProposal, CoreError> {
        let request: serde_json::Value = row.try_get("request").map_err(|e| map(e.into()))?;
        let state: serde_json::Value = row.try_get("state").map_err(|e| map(e.into()))?;
        Ok(GuardProposal {
            id: row.try_get("id").map_err(|e| map(e.into()))?,
            sandbox_id: row.try_get("sandbox_id").map_err(|e| map(e.into()))?,
            tenant_id: row.try_get("tenant_id").map_err(|e| map(e.into()))?,
            agent_id: row.try_get("agent_id").map_err(|e| map(e.into()))?,
            request: serde_json::from_value(request).map_err(|_| {
                map(StoreError::Conflict(
                    "stored proposal request is unreadable".into(),
                ))
            })?,
            base_policy_hash: row.try_get("base_policy_hash").map_err(|e| map(e.into()))?,
            state: serde_json::from_value(state).map_err(|_| {
                map(StoreError::Conflict(
                    "stored proposal state is unreadable".into(),
                ))
            })?,
            decided_by: row.try_get("decided_by").map_err(|e| map(e.into()))?,
            decided_at: row.try_get("decided_at").map_err(|e| map(e.into()))?,
            created_at: row.try_get("created_at").map_err(|e| map(e.into()))?,
        })
    }
}
