use crate::{
    NODE_HEARTBEAT_TTL_SECONDS, PostgresRepository, StoreError, core_error, database_error,
};
use agentforge_core::{
    ApiKeyRecord, CoreError, ImageRecord, Node, RuntimeKind, Sandbox, SandboxState, Scope,
    Snapshot, UsageEvent, UsageSummary,
    scheduler::{ScheduleRequest, ScheduledSandbox, Scheduler},
    storage::{
        ReconciliationAction, SandboxEvent, SandboxOperation, StoredSnapshot, TenantRecord,
        WorkerAssignment, WorkerHeartbeat, WorkerLease, WorkerRegistration, WorkerStatus,
        MetadataStore,
    },
    new_id,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
#[cfg(test)]
use std::sync::Arc;
use uuid::Uuid;

fn stored_u32(value: i32, field: &str) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|error| StoreError::Conflict(format!("invalid {field}: {error}")))
}

fn stored_u64(value: i64, field: &str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|error| StoreError::Conflict(format!("invalid {field}: {error}")))
}

fn invalid_state(value: &str) -> StoreError {
    StoreError::Conflict(format!("invalid persisted sandbox state: {value}"))
}

fn state_from_str(value: &str) -> Result<SandboxState, StoreError> {
    match value {
        "creating" => Ok(SandboxState::Creating),
        "starting" => Ok(SandboxState::Starting),
        "running" => Ok(SandboxState::Running),
        "stopping" => Ok(SandboxState::Stopping),
        "stopped" => Ok(SandboxState::Stopped),
        "snapshotting" => Ok(SandboxState::Snapshotting),
        "restoring" => Ok(SandboxState::Restoring),
        "failed" => Ok(SandboxState::Failed),
        "destroying" => Ok(SandboxState::Destroying),
        "destroyed" => Ok(SandboxState::Destroyed),
        value => Err(invalid_state(value)),
    }
}

fn runtime_from_str(value: &str) -> Result<RuntimeKind, StoreError> {
    match value {
        "firecracker" => Ok(RuntimeKind::Firecracker),
        "bwrap-dev" => Ok(RuntimeKind::BwrapDev),
        value => Err(StoreError::Conflict(format!(
            "invalid persisted runtime: {value}"
        ))),
    }
}

fn sandbox_from_row(row: &sqlx::postgres::PgRow) -> Result<Sandbox, StoreError> {
    let state: String = row.try_get("state")?;
    let runtime: String = row.try_get("runtime")?;
    Ok(Sandbox {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        node_id: row.try_get("node_id")?,
        image_id: row.try_get("image_id")?,
        state: state_from_str(&state)?,
        runtime: runtime_from_str(&runtime)?,
        cpu: stored_u32(row.try_get("cpu")?, "sandbox cpu")?,
        memory_mb: stored_u32(row.try_get("memory_mb")?, "sandbox memory_mb")?,
        disk_mb: stored_u32(row.try_get("disk_mb")?, "sandbox disk_mb")?,
        timeout_seconds: stored_u64(row.try_get("timeout_seconds")?, "sandbox timeout_seconds")?,
        network: serde_json::from_value(row.try_get("network")?)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        runtime_path: row.try_get("runtime_path")?,
    })
}

fn event_from_row(row: &sqlx::postgres::PgRow) -> Result<SandboxEvent, StoreError> {
    let from_state: Option<String> = row.try_get("from_state")?;
    let to_state: String = row.try_get("to_state")?;
    Ok(SandboxEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        sandbox_id: row.try_get("sandbox_id")?,
        from_state: from_state.as_deref().map(state_from_str).transpose()?,
        to_state: state_from_str(&to_state)?,
        reason: row.try_get("reason")?,
        occurred_at: row.try_get("occurred_at")?,
    })
}

fn snapshot_from_row(row: &sqlx::postgres::PgRow) -> Result<Snapshot, StoreError> {
    Ok(Snapshot {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        sandbox_id: row.try_get("sandbox_id")?,
        object_key: row.try_get("object_key")?,
        size_bytes: stored_u64(row.try_get("size_bytes")?, "snapshot size_bytes")?,
        image_id: row.try_get("image_id")?,
        created_at: row.try_get("created_at")?,
    })
}

fn stored_snapshot_from_row(row: &sqlx::postgres::PgRow) -> Result<StoredSnapshot, StoreError> {
    let checksum: Option<String> = row.try_get("checksum_sha256")?;
    Ok(StoredSnapshot {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        sandbox_id: row.try_get("sandbox_id")?,
        object_key: row.try_get("object_key")?,
        manifest_object_key: row.try_get("manifest_object_key")?,
        memory_object_key: row.try_get("memory_object_key")?,
        disk_object_key: row.try_get("disk_object_key")?,
        workspace_object_key: row.try_get("workspace_object_key")?,
        size_bytes: stored_u64(row.try_get("size_bytes")?, "snapshot size_bytes")?,
        image_id: row.try_get("image_id")?,
        checksum_sha256: checksum
            .ok_or_else(|| StoreError::Conflict("snapshot has no content checksum".into()))?,
        kind: row.try_get("kind")?,
        complete: row.try_get("complete")?,
        manifest: row.try_get("manifest")?,
        created_at: row.try_get("created_at")?,
    })
}

fn lease_from_row(row: &sqlx::postgres::PgRow) -> Result<WorkerLease, StoreError> {
    Ok(WorkerLease {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        sandbox_id: row.try_get("sandbox_id")?,
        node_id: row.try_get("node_id")?,
        generation: row.try_get("generation")?,
        status: row.try_get("status")?,
        reason: row.try_get("reason")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn operation_from_row(row: &sqlx::postgres::PgRow) -> Result<SandboxOperation, StoreError> {
    Ok(SandboxOperation {
        tenant_id: row.try_get("tenant_id")?,
        request_id: row.try_get("request_id")?,
        sandbox_id: row.try_get("sandbox_id")?,
        operation: row.try_get("operation")?,
        payload: row.try_get("payload")?,
        status: row.try_get("status")?,
        result: row.try_get("result")?,
        error: row.try_get("error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn worker_status_from_row(row: &sqlx::postgres::PgRow) -> Result<WorkerStatus, StoreError> {
    let runtime: String = row.try_get("runtime")?;
    Ok(WorkerStatus {
        registration: WorkerRegistration {
            node_id: row.try_get("id")?,
            name: row.try_get("name")?,
            runtime: runtime_from_str(&runtime)?,
            control_endpoint: row.try_get("control_endpoint")?,
            total_vcpus: stored_u32(row.try_get("total_vcpus")?, "worker total_vcpus")?,
            total_memory_bytes: stored_u64(
                row.try_get("total_memory_bytes")?,
                "worker total_memory_bytes",
            )?,
            total_disk_bytes: stored_u64(
                row.try_get("total_disk_bytes")?,
                "worker total_disk_bytes",
            )?,
            available_vcpus: stored_u32(row.try_get("available_vcpus")?, "worker available_vcpus")?,
            available_memory_bytes: stored_u64(
                row.try_get("available_memory_bytes")?,
                "worker available_memory_bytes",
            )?,
            available_disk_bytes: stored_u64(
                row.try_get("available_disk_bytes")?,
                "worker available_disk_bytes",
            )?,
            healthy: row.try_get("healthy")?,
            version: stored_u64(row.try_get("version")?, "worker version")?,
            metadata: row.try_get("metadata")?,
            started_at: row.try_get("started_at")?,
            last_heartbeat: row.try_get("last_heartbeat")?,
        },
        sandbox_count: stored_u32(row.try_get("sandbox_count")?, "worker sandbox_count")?,
        observed_sandbox_count: stored_u32(
            row.try_get("observed_sandbox_count")?,
            "worker observed_sandbox_count",
        )?,
        last_error: row.try_get("last_error")?,
    })
}

fn action_from_row(row: &sqlx::postgres::PgRow) -> Result<ReconciliationAction, StoreError> {
    Ok(ReconciliationAction {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        node_id: row.try_get("node_id")?,
        sandbox_id: row.try_get("sandbox_id")?,
        lease_id: row.try_get("lease_id")?,
        source_key: row.try_get("source_key")?,
        action: row.try_get("action")?,
        reason: row.try_get("reason")?,
        detected_at: row.try_get("detected_at")?,
        processed_at: row.try_get("processed_at")?,
    })
}

fn scope_values(scopes: &[Scope]) -> Result<Value, StoreError> {
    serde_json::to_value(scopes).map_err(StoreError::Json)
}

fn scopes_from_value(value: Value) -> Result<Vec<Scope>, StoreError> {
    let values = value
        .as_array()
        .ok_or_else(|| StoreError::Conflict("API key scopes are not an array".into()))?;
    values
        .iter()
        .map(|value| {
            serde_json::from_value::<Scope>(value.clone())
                .map_err(|error| StoreError::Conflict(format!("invalid API key scope: {error}")))
        })
        .collect()
}

async fn fetch_sandbox(
    executor: impl sqlx::Executor<'_, Database = Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<Sandbox, StoreError> {
    let row = sqlx::query("SELECT * FROM sandboxes WHERE tenant_id = $1 AND id = $2")
        .bind(tenant)
        .bind(id)
        .fetch_optional(executor)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
    sandbox_from_row(&row)
}

async fn insert_sandbox_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    sandbox: Uuid,
    from_state: Option<SandboxState>,
    to_state: SandboxState,
    reason: Option<&str>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO sandbox_events \
         (id, tenant_id, sandbox_id, from_state, to_state, reason) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(new_id())
    .bind(tenant)
    .bind(sandbox)
    .bind(from_state.map(SandboxState::as_str))
    .bind(to_state.as_str())
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn insert_sandbox(
    tx: &mut Transaction<'_, Postgres>,
    value: &Sandbox,
) -> Result<(), StoreError> {
    if value.tenant_id.is_nil() {
        return Err(StoreError::Conflict("sandbox tenant is required".into()));
    }
    sqlx::query(
        "INSERT INTO sandboxes \
         (id, tenant_id, node_id, image_id, state, runtime, cpu, memory_mb, disk_mb, \
          timeout_seconds, network, runtime_path, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(value.id)
    .bind(value.tenant_id)
    .bind(value.node_id)
    .bind(&value.image_id)
    .bind(value.state.as_str())
    .bind(value.runtime.as_str())
    .bind(i32::try_from(value.cpu).map_err(|error| StoreError::Conflict(error.to_string()))?)
    .bind(i32::try_from(value.memory_mb).map_err(|error| StoreError::Conflict(error.to_string()))?)
    .bind(i32::try_from(value.disk_mb).map_err(|error| StoreError::Conflict(error.to_string()))?)
    .bind(
        i64::try_from(value.timeout_seconds)
            .map_err(|error| StoreError::Conflict(error.to_string()))?,
    )
    .bind(
        serde_json::to_value(&value.network)
            .map_err(|error| StoreError::Database(sqlx::Error::Decode(Box::new(error))))?,
    )
    .bind(&value.runtime_path)
    .bind(value.created_at)
    .bind(value.updated_at)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    insert_sandbox_event(
        tx,
        value.tenant_id,
        value.id,
        None,
        value.state,
        Some("sandbox created"),
    )
    .await
}

async fn update_state_transaction(
    pool: &sqlx::PgPool,
    tenant: Uuid,
    id: Uuid,
    expected: SandboxState,
    next: SandboxState,
    runtime_path: Option<String>,
    reason: &str,
) -> Result<Sandbox, StoreError> {
    let mut tx = pool.begin().await.map_err(database_error)?;
    let row = sqlx::query("SELECT * FROM sandboxes WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
    let mut value = sandbox_from_row(&row)?;
    if value.state == next {
        tx.commit().await.map_err(database_error)?;
        return Ok(value);
    }
    if value.state != expected || !value.state.can_transition_to(next) {
        return Err(StoreError::Conflict("invalid state transition".into()));
    }
    let updated_at = Utc::now();
    sqlx::query(
        "UPDATE sandboxes SET state = $1, runtime_path = COALESCE($2, runtime_path), updated_at = $3 \
         WHERE tenant_id = $4 AND id = $5",
    )
    .bind(next.as_str())
    .bind(runtime_path.clone())
    .bind(updated_at)
    .bind(tenant)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;
    insert_sandbox_event(&mut tx, tenant, id, Some(value.state), next, Some(reason)).await?;
    value.state = next;
    value.updated_at = updated_at;
    if let Some(path) = runtime_path {
        value.runtime_path = Some(path);
    }
    tx.commit().await.map_err(database_error)?;
    Ok(value)
}

fn sandbox_fingerprint(value: &Sandbox) -> Result<Vec<u8>, StoreError> {
    let semantic = json!({
        "tenant_id": value.tenant_id,
        "image_id": value.image_id,
        "state": value.state,
        "runtime": value.runtime,
        "cpu": value.cpu,
        "memory_mb": value.memory_mb,
        "disk_mb": value.disk_mb,
        "timeout_seconds": value.timeout_seconds,
        "network": value.network,
    });
    Ok(Sha256::digest(serde_json::to_vec(&semantic)?).to_vec())
}

fn schedule_fingerprint(
    value: &Sandbox,
    preferred_node: Option<Uuid>,
    lease_ttl_seconds: u64,
) -> Result<Vec<u8>, StoreError> {
    let semantic = json!({
        "sandbox": sandbox_fingerprint(value)?,
        "preferred_node": preferred_node,
        "lease_ttl_seconds": lease_ttl_seconds,
    });
    Ok(Sha256::digest(serde_json::to_vec(&semantic)?).to_vec())
}

async fn advisory_lock(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    request_id: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("{tenant}:{request_id}"))
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    Ok(())
}

#[derive(Clone)]
pub struct PostgresScheduler {
    repository: PostgresRepository,
}

impl PostgresScheduler {
    pub fn new(repository: PostgresRepository) -> Self {
        Self { repository }
    }

    pub fn repository(&self) -> &PostgresRepository {
        &self.repository
    }
}

impl PostgresScheduler {
    async fn schedule_on_node(
        &self,
        tenant: Uuid,
        request_id: Uuid,
        mut sandbox: Sandbox,
        lease_ttl_seconds: u64,
        preferred_node: Option<Uuid>,
    ) -> Result<ScheduledSandbox, StoreError> {
        if !(1..=3_600).contains(&lease_ttl_seconds) {
            return Err(StoreError::Conflict(
                "lease TTL must be between 1 and 3600 seconds".into(),
            ));
        }
        if sandbox.tenant_id != tenant {
            return Err(StoreError::Conflict(
                "sandbox tenant does not match request".into(),
            ));
        }
        let mut tx = self.repository.pool.begin().await.map_err(database_error)?;
        advisory_lock(&mut tx, tenant, request_id).await?;
        let existing_request = sqlx::query(
            "SELECT fingerprint FROM sandbox_requests WHERE tenant_id = $1 AND request_id = $2",
        )
        .bind(tenant)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        let mut retry_assignment = false;
        let mut lease_generation = 1_i64;
        if let Some(row) = existing_request {
            let existing_fingerprint: Vec<u8> = row.try_get("fingerprint")?;
            if existing_fingerprint
                != schedule_fingerprint(&sandbox, preferred_node, lease_ttl_seconds)?
            {
                return Err(StoreError::Conflict(
                    "sandbox idempotency key was reused".into(),
                ));
            }
            let sandbox_id: Uuid = sqlx::query_scalar(
                "SELECT sandbox_id FROM sandbox_requests WHERE tenant_id = $1 AND request_id = $2",
            )
            .bind(tenant)
            .bind(request_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
            let existing_sandbox = fetch_sandbox(&mut *tx, tenant, sandbox_id).await?;
            let existing_lease = fetch_lease_for_sandbox(&mut tx, tenant, sandbox_id).await?;
            if existing_lease.status == "active" || existing_sandbox.node_id.is_some() {
                let worker_endpoint: String = sqlx::query_scalar(
                    "SELECT control_endpoint FROM nodes WHERE id = $1",
                )
                .bind(existing_lease.node_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database_error)?;
                tx.commit().await.map_err(database_error)?;
                return Ok(ScheduledSandbox {
                    sandbox: existing_sandbox,
                    worker_id: existing_lease.node_id,
                    worker_endpoint,
                    lease_id: existing_lease.id,
                    lease_generation: existing_lease.generation,
                });
            }
            if existing_sandbox.state == SandboxState::Destroyed {
                return Err(StoreError::Conflict(
                    "destroyed sandbox cannot be rescheduled".into(),
                ));
            }
            sandbox = existing_sandbox;
            retry_assignment = true;
            lease_generation = existing_lease
                .generation
                .checked_add(1)
                .ok_or_else(|| StoreError::Conflict("lease generation overflow".into()))?;
        } else {
            insert_sandbox(&mut tx, &sandbox).await?;
            sqlx::query(
                "INSERT INTO sandbox_requests (tenant_id, request_id, sandbox_id, fingerprint) \
                 VALUES ($1,$2,$3,$4)",
            )
            .bind(tenant)
            .bind(request_id)
            .bind(sandbox.id)
            .bind(schedule_fingerprint(
                &sandbox,
                preferred_node,
                lease_ttl_seconds,
            )?)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        }

        let memory_bytes = u64::from(sandbox.memory_mb)
            .checked_mul(1_048_576)
            .ok_or_else(|| StoreError::Conflict("sandbox memory size overflow".into()))?;
        let disk_bytes = u64::from(sandbox.disk_mb)
            .checked_mul(1_048_576)
            .ok_or_else(|| StoreError::Conflict("sandbox disk size overflow".into()))?;
        let node = sqlx::query(
            "SELECT * FROM nodes \
             WHERE healthy = true \
               AND last_heartbeat >= now() - ($1 * interval '1 second') \
               AND available_vcpus >= $2 \
               AND available_memory_bytes >= $3 \
               AND available_disk_bytes >= $4 AND runtime = $5 \
               AND ($6::uuid IS NULL OR id = $6) \
             ORDER BY \
               (1.0 / GREATEST(available_vcpus, 1)) + \
               (1.0 / GREATEST(available_memory_bytes::numeric / 1073741824, 0.25)) + \
               (sandbox_count::numeric * 0.0001), \
               last_heartbeat DESC \
             LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .bind(NODE_HEARTBEAT_TTL_SECONDS)
        .bind(i32::try_from(sandbox.cpu).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(i64::try_from(memory_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(i64::try_from(disk_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(sandbox.runtime.as_str())
        .bind(preferred_node)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?
        .ok_or_else(|| StoreError::Conflict("no healthy worker has capacity".into()))?;
        let worker_endpoint: String = node.try_get("control_endpoint")?;
        let node_id: Uuid = node.try_get("id")?;
        sqlx::query(
            "UPDATE nodes SET available_vcpus = available_vcpus - $1, \
               available_memory_bytes = available_memory_bytes - $2, \
               available_disk_bytes = available_disk_bytes - $3, sandbox_count = sandbox_count + 1 \
             WHERE id = $4",
        )
        .bind(i32::try_from(sandbox.cpu).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(i64::try_from(memory_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(i64::try_from(disk_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        let assigned = sqlx::query(
            "UPDATE sandboxes SET node_id = $1, updated_at = now() \
             WHERE tenant_id = $2 AND id = $3 AND node_id IS NULL",
        )
        .bind(node_id)
        .bind(tenant)
        .bind(sandbox.id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if assigned.rows_affected() != 1 {
            return Err(StoreError::Conflict("sandbox was already assigned".into()));
        }

        let lease_id = new_id();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(lease_ttl_seconds as i64);
        sqlx::query(
            "INSERT INTO sandbox_leases \
             (id, tenant_id, sandbox_id, node_id, generation, status, expires_at, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,'active',$6,$7,$7)",
        )
        .bind(lease_id)
        .bind(tenant)
        .bind(sandbox.id)
        .bind(node_id)
        .bind(lease_generation)
        .bind(expires_at)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if retry_assignment {
            sqlx::query(
                "UPDATE sandbox_assignments SET sandbox_id=$3, node_id=$4, lease_id=$5, \
                 status='reserved', updated_at=$6 WHERE tenant_id=$1 AND request_id=$2",
            )
            .bind(tenant)
            .bind(request_id)
            .bind(sandbox.id)
            .bind(node_id)
            .bind(lease_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        } else {
            sqlx::query(
                "INSERT INTO sandbox_assignments \
                 (tenant_id, request_id, sandbox_id, node_id, lease_id, status, created_at, updated_at) \
                 VALUES ($1,$2,$3,$4,$5,'reserved',$6,$6)",
            )
            .bind(tenant)
            .bind(request_id)
            .bind(sandbox.id)
            .bind(node_id)
            .bind(lease_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        }
        insert_sandbox_event(
            &mut tx,
            tenant,
            sandbox.id,
            Some(sandbox.state),
            sandbox.state,
            Some("sandbox reserved on worker"),
        )
        .await?;
        let mut assigned_sandbox = fetch_sandbox(&mut *tx, tenant, sandbox.id).await?;
        assigned_sandbox.node_id = Some(node_id);
        assigned_sandbox.updated_at = now;
        let lease_row = sqlx::query("SELECT * FROM sandbox_leases WHERE id = $1")
            .bind(lease_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
        let lease = lease_from_row(&lease_row)?;
        tx.commit().await.map_err(database_error)?;
        Ok(ScheduledSandbox {
            sandbox: assigned_sandbox,
            worker_id: node_id,
            worker_endpoint,
            lease_id,
            lease_generation: lease.generation,
        })
    }
}

#[async_trait]
impl Scheduler for PostgresScheduler {
    async fn schedule(&self, request: ScheduleRequest) -> Result<ScheduledSandbox, CoreError> {
        self.schedule_on_node(
            request.tenant_id,
            request.request_id,
            request.sandbox,
            request.lease_ttl.as_secs(),
            request.preferred_worker,
        )
        .await
        .map_err(core_error)
    }

    async fn worker_endpoint(
        &self,
        tenant_id: Uuid,
        sandbox_id: Uuid,
    ) -> Result<String, CoreError> {
        sqlx::query_scalar(
            "SELECT nodes.control_endpoint FROM sandbox_leases \
             JOIN nodes ON nodes.id = sandbox_leases.node_id \
             WHERE sandbox_leases.tenant_id = $1 AND sandbox_leases.sandbox_id = $2 \
             AND sandbox_leases.status = 'active'",
        )
        .bind(tenant_id)
        .bind(sandbox_id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|error| core_error(database_error(error)))?
        .ok_or_else(|| CoreError::NotFound("active sandbox lease not found".into()))
    }

    async fn release(&self, tenant_id: Uuid, sandbox_id: Uuid) -> Result<(), CoreError> {
        let lease = sqlx::query(
            "SELECT id, generation FROM sandbox_leases \
             WHERE tenant_id = $1 AND sandbox_id = $2 AND status = 'active' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(sandbox_id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|error| core_error(database_error(error)))?
        .ok_or_else(|| CoreError::NotFound("active sandbox lease not found".into()))?;
        let lease_id = lease
            .try_get("id")
            .map_err(|error| core_error(error.into()))?;
        let generation = lease
            .try_get("generation")
            .map_err(|error| core_error(error.into()))?;
        self.repository.release_worker_lease(
            tenant_id,
            lease_id,
            generation,
            "released through scheduler",
        )
        .await
        .map(|_| ())
        .map_err(core_error)
    }
}

async fn fetch_lease_for_sandbox(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    sandbox: Uuid,
) -> Result<WorkerLease, StoreError> {
    let row = sqlx::query(
        "SELECT * FROM sandbox_leases WHERE tenant_id = $1 AND sandbox_id = $2 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant)
    .bind(sandbox)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?
    .ok_or(StoreError::NotFound)?;
    lease_from_row(&row)
}

impl PostgresRepository {
    async fn create_sandbox(&self, value: Sandbox) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        insert_sandbox(&mut tx, &value).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn get_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<Sandbox, StoreError> {
        fetch_sandbox(&self.pool, tenant, id).await
    }

    async fn list_sandboxes(&self, tenant: Uuid) -> Result<Vec<Sandbox>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM sandboxes WHERE tenant_id = $1 ORDER BY created_at DESC, id",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(sandbox_from_row).collect()
    }

    async fn update_state(
        &self,
        tenant: Uuid,
        id: Uuid,
        expected: SandboxState,
        next: SandboxState,
        runtime_path: Option<String>,
    ) -> Result<Sandbox, StoreError> {
        update_state_transaction(
            &self.pool,
            tenant,
            id,
            expected,
            next,
            runtime_path,
            "sandbox state changed",
        )
        .await
    }

    async fn delete_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let row =
            sqlx::query("SELECT * FROM sandboxes WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
                .bind(tenant)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(database_error)?
                .ok_or(StoreError::NotFound)?;
        let sandbox = sandbox_from_row(&row)?;
        let lease_row = sqlx::query(
            "SELECT * FROM sandbox_leases WHERE tenant_id=$1 AND sandbox_id=$2 \
             AND status IN ('active', 'completed') ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        if let Some(row) = lease_row {
            let lease = lease_from_row(&row)?;
            release_capacity(&mut tx, &lease, "released", "sandbox deleted").await?;
        }
        if sandbox.state != SandboxState::Destroyed {
            sqlx::query(
                "UPDATE sandboxes SET state='destroyed', updated_at=now() \
                 WHERE tenant_id=$1 AND id=$2",
            )
            .bind(tenant)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
            insert_sandbox_event(
                &mut tx,
                tenant,
                id,
                Some(sandbox.state),
                SandboxState::Destroyed,
                Some("sandbox deleted"),
            )
            .await?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn put_key(&self, value: ApiKeyRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO api_keys \
             (id, tenant_id, digest, scopes, expires_at, revoked_at) VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(value.id)
        .bind(value.tenant_id)
        .bind(value.digest.as_slice())
        .bind(scope_values(&value.scopes)?)
        .bind(value.expires_at)
        .bind(value.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }

    async fn revoke_key(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, now()) \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, StoreError> {
        let row = sqlx::query("SELECT * FROM api_keys WHERE digest = $1")
            .bind(digest.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
        Ok(ApiKeyRecord {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            digest: row
                .try_get::<Vec<u8>, _>("digest")?
                .try_into()
                .map_err(|_| StoreError::Conflict("invalid API key digest".into()))?,
            scopes: scopes_from_value(row.try_get("scopes")?)?,
            expires_at: row.try_get("expires_at")?,
            revoked_at: row.try_get("revoked_at")?,
        })
    }

    async fn put_snapshot(&self, value: Snapshot) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO snapshots \
             (id, tenant_id, sandbox_id, object_key, manifest_object_key, size_bytes, image_id, \
              kind, complete, created_at) \
             VALUES ($1,$2,$3,$4,$4,$5,$6,'filesystem',false,$7)",
        )
        .bind(value.id)
        .bind(value.tenant_id)
        .bind(value.sandbox_id)
        .bind(&value.object_key)
        .bind(
            i64::try_from(value.size_bytes)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(&value.image_id)
        .bind(value.created_at)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }

    async fn get_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<Snapshot, StoreError> {
        let row = sqlx::query("SELECT * FROM snapshots WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
        snapshot_from_row(&row)
    }

    async fn list_snapshots(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<Vec<Snapshot>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM snapshots WHERE tenant_id = $1 AND sandbox_id = $2 \
             ORDER BY created_at DESC, id",
        )
        .bind(tenant)
        .bind(sandbox)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(snapshot_from_row).collect()
    }

    async fn delete_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM snapshots WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(database_error)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn append_usage(&self, value: UsageEvent) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO usage_events (id, tenant_id, sandbox_id, metric, quantity, occurred_at) \
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(value.id)
        .bind(value.tenant_id)
        .bind(value.sandbox_id)
        .bind(value.metric)
        .bind(value.quantity)
        .bind(value.occurred_at)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }

    async fn usage(&self, tenant: Uuid) -> Result<Vec<UsageSummary>, StoreError> {
        let rows = sqlx::query(
            "SELECT metric, COALESCE(SUM(quantity), 0)::bigint AS quantity \
             FROM usage_events WHERE tenant_id = $1 GROUP BY metric ORDER BY metric",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter()
            .map(|row| {
                Ok(UsageSummary {
                    metric: row.try_get("metric")?,
                    quantity: row.try_get("quantity")?,
                })
            })
            .collect()
    }

    async fn register_node(&self, value: Node) -> Result<(), StoreError> {
        self.register_worker(WorkerRegistration {
            node_id: value.id,
            name: value.name,
            runtime: RuntimeKind::BwrapDev,
            control_endpoint: String::new(),
            total_vcpus: value.available_vcpus,
            total_memory_bytes: value.available_memory_bytes,
            total_disk_bytes: value.available_disk_bytes,
            available_vcpus: value.available_vcpus,
            available_memory_bytes: value.available_memory_bytes,
            available_disk_bytes: value.available_disk_bytes,
            healthy: value.healthy,
            version: 1,
            metadata: Value::Object(Default::default()),
            started_at: value.last_heartbeat,
            last_heartbeat: value.last_heartbeat,
        })
        .await
    }

    async fn heartbeat(&self, id: Uuid) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE nodes SET healthy = true, last_heartbeat = now(), version = version + 1 \
             WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn list_nodes(&self) -> Result<Vec<Node>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM nodes WHERE healthy = true \
             AND last_heartbeat >= now() - ($1 * interval '1 second') ORDER BY name",
        )
        .bind(NODE_HEARTBEAT_TTL_SECONDS)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter()
            .map(|row| {
                let status = worker_status_from_row(row)?;
                Ok(Node {
                    id: status.registration.node_id,
                    name: status.registration.name,
                    available_vcpus: status.registration.available_vcpus,
                    available_memory_bytes: status.registration.available_memory_bytes,
                    available_disk_bytes: status.registration.available_disk_bytes,
                    sandbox_count: status.sandbox_count,
                    healthy: status.registration.healthy,
                    last_heartbeat: status.registration.last_heartbeat,
                })
            })
            .collect()
    }

    async fn put_tenant(&self, value: TenantRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO tenants (id, name, created_at) VALUES ($1,$2,$3) \
             ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name",
        )
        .bind(value.id)
        .bind(value.name)
        .bind(value.created_at)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }

    async fn get_tenant(&self, id: Uuid) -> Result<TenantRecord, StoreError> {
        let row = sqlx::query("SELECT * FROM tenants WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
        Ok(TenantRecord {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn list_sandbox_events(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        limit: u32,
    ) -> Result<Vec<SandboxEvent>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM sandbox_events WHERE tenant_id = $1 AND sandbox_id = $2 \
             ORDER BY occurred_at DESC, id LIMIT $3",
        )
        .bind(tenant)
        .bind(sandbox)
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(event_from_row).collect()
    }

    async fn put_stored_snapshot(&self, value: StoredSnapshot) -> Result<(), StoreError> {
        if value.checksum_sha256.len() != 64
            || !value
                .checksum_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(StoreError::Conflict(
                "stored snapshot requires a SHA-256 checksum".into(),
            ));
        }
        if value.complete
            && (value.memory_object_key.is_none()
                || value.disk_object_key.is_none()
                || value.workspace_object_key.is_none())
        {
            return Err(StoreError::Conflict(
                "complete VM snapshot requires memory, disk, and workspace objects".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO snapshots \
             (id, tenant_id, sandbox_id, object_key, manifest_object_key, memory_object_key, \
              disk_object_key, workspace_object_key, size_bytes, image_id, checksum_sha256, \
              kind, manifest, complete, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        )
        .bind(value.id)
        .bind(value.tenant_id)
        .bind(value.sandbox_id)
        .bind(&value.object_key)
        .bind(&value.manifest_object_key)
        .bind(&value.memory_object_key)
        .bind(&value.disk_object_key)
        .bind(&value.workspace_object_key)
        .bind(
            i64::try_from(value.size_bytes)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(&value.image_id)
        .bind(value.checksum_sha256.to_ascii_lowercase())
        .bind(&value.kind)
        .bind(&value.manifest)
        .bind(value.complete)
        .bind(value.created_at)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }

    async fn get_stored_snapshot(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<StoredSnapshot, StoreError> {
        let row = sqlx::query("SELECT * FROM snapshots WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
        stored_snapshot_from_row(&row)
    }

    async fn list_stored_snapshots(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<Vec<StoredSnapshot>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM snapshots WHERE tenant_id=$1 AND sandbox_id=$2 \
             AND checksum_sha256 IS NOT NULL ORDER BY created_at DESC, id",
        )
        .bind(tenant)
        .bind(sandbox)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(stored_snapshot_from_row).collect()
    }

    async fn create_sandbox_idempotent(
        &self,
        tenant: Uuid,
        request_id: Uuid,
        sandbox: Sandbox,
    ) -> Result<Sandbox, StoreError> {
        if sandbox.tenant_id != tenant {
            return Err(StoreError::Conflict(
                "sandbox tenant does not match request".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        advisory_lock(&mut tx, tenant, request_id).await?;
        let existing = sqlx::query(
            "SELECT sandbox_id, fingerprint FROM sandbox_requests \
             WHERE tenant_id = $1 AND request_id = $2",
        )
        .bind(tenant)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        if let Some(row) = existing {
            let existing_fingerprint: Vec<u8> = row.try_get("fingerprint")?;
            if existing_fingerprint != sandbox_fingerprint(&sandbox)? {
                return Err(StoreError::Conflict(
                    "sandbox idempotency key was reused".into(),
                ));
            }
            let sandbox_id: Uuid = row.try_get("sandbox_id")?;
            let result = fetch_sandbox(&mut *tx, tenant, sandbox_id).await?;
            tx.commit().await.map_err(database_error)?;
            return Ok(result);
        }
        insert_sandbox(&mut tx, &sandbox).await?;
        sqlx::query(
            "INSERT INTO sandbox_requests (tenant_id, request_id, sandbox_id, fingerprint) \
             VALUES ($1,$2,$3,$4)",
        )
        .bind(tenant)
        .bind(request_id)
        .bind(sandbox.id)
        .bind(sandbox_fingerprint(&sandbox)?)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(sandbox)
    }

    async fn register_worker(&self, value: WorkerRegistration) -> Result<(), StoreError> {
        if value.name.trim().is_empty() {
            return Err(StoreError::Conflict("worker name is required".into()));
        }
        if value.total_vcpus == 0 || value.version == 0 {
            return Err(StoreError::Conflict(
                "worker total vCPUs and registration version must be positive".into(),
            ));
        }
        if value.runtime == RuntimeKind::Firecracker
            && reqwest::Url::parse(&value.control_endpoint)
                .ok()
                .filter(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
                .is_none()
        {
            return Err(StoreError::Conflict(
                "Firecracker worker requires an HTTP(S) control endpoint".into(),
            ));
        }
        if value.available_vcpus > value.total_vcpus
            || value.available_memory_bytes > value.total_memory_bytes
            || value.available_disk_bytes > value.total_disk_bytes
        {
            return Err(StoreError::Conflict(
                "worker available capacity exceeds total capacity".into(),
            ));
        }
        let result = sqlx::query(
            "INSERT INTO nodes \
             (id, name, runtime, control_endpoint, total_vcpus, total_memory_bytes, \
              total_disk_bytes, available_vcpus, available_memory_bytes, available_disk_bytes, \
              sandbox_count, healthy, version, metadata, started_at, last_heartbeat) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,$11,$12,$13,$14,$15) \
             ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, runtime=EXCLUDED.runtime, \
             control_endpoint=EXCLUDED.control_endpoint, total_vcpus=EXCLUDED.total_vcpus, \
             total_memory_bytes=EXCLUDED.total_memory_bytes, total_disk_bytes=EXCLUDED.total_disk_bytes, \
             sandbox_count=nodes.sandbox_count, healthy=EXCLUDED.healthy, \
             version=EXCLUDED.version, metadata=EXCLUDED.metadata, started_at=EXCLUDED.started_at, \
             last_heartbeat=EXCLUDED.last_heartbeat WHERE nodes.version < EXCLUDED.version",
        )
        .bind(value.node_id)
        .bind(&value.name)
        .bind(value.runtime.as_str())
        .bind(&value.control_endpoint)
        .bind(i32::try_from(value.total_vcpus).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(i64::try_from(value.total_memory_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(i64::try_from(value.total_disk_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(i32::try_from(value.available_vcpus).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(i64::try_from(value.available_memory_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(i64::try_from(value.available_disk_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(value.healthy)
        .bind(i64::try_from(value.version).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(&value.metadata)
        .bind(value.started_at)
        .bind(value.last_heartbeat)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            let current = self.get_worker(value.node_id).await?;
            let same_registration = current.registration.name == value.name
                && current.registration.runtime == value.runtime
                && current.registration.control_endpoint == value.control_endpoint
                && current.registration.total_vcpus == value.total_vcpus
                && current.registration.total_memory_bytes == value.total_memory_bytes
                && current.registration.total_disk_bytes == value.total_disk_bytes
                && current.registration.healthy == value.healthy
                && current.registration.metadata == value.metadata;
            if current.registration.version != value.version || !same_registration {
                return Err(StoreError::Conflict(
                    "worker registration version is stale or was reused".into(),
                ));
            }
        }
        Ok(())
    }

    async fn heartbeat_worker(
        &self,
        heartbeat: WorkerHeartbeat,
    ) -> Result<WorkerStatus, StoreError> {
        let result = sqlx::query(
            "UPDATE nodes SET healthy=$1, version=$2, metadata=$3, last_error=$4, \
             observed_sandbox_count=$5, last_heartbeat=now() \
             WHERE id=$6 AND version <= $2",
        )
        .bind(heartbeat.healthy)
        .bind(
            i64::try_from(heartbeat.version)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(&heartbeat.metadata)
        .bind(&heartbeat.last_error)
        .bind(
            i32::try_from(heartbeat.sandbox_count)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(heartbeat.node_id)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            let current = self.get_worker(heartbeat.node_id).await?;
            if current.registration.version > heartbeat.version {
                return Err(StoreError::Conflict(
                    "worker heartbeat version is stale".into(),
                ));
            }
            return Err(StoreError::Conflict(
                "worker heartbeat version is stale".into(),
            ));
        }
        self.get_worker(heartbeat.node_id).await
    }

    async fn get_worker(&self, node_id: Uuid) -> Result<WorkerStatus, StoreError> {
        let row = sqlx::query("SELECT * FROM nodes WHERE id = $1")
            .bind(node_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
        worker_status_from_row(&row)
    }

    async fn list_workers(&self, include_unhealthy: bool) -> Result<Vec<WorkerStatus>, StoreError> {
        let rows = if include_unhealthy {
            sqlx::query("SELECT * FROM nodes ORDER BY name")
                .fetch_all(&self.pool)
                .await
        } else {
            sqlx::query(
                "SELECT * FROM nodes WHERE healthy = true \
                 AND last_heartbeat >= now() - ($1 * interval '1 second') ORDER BY name",
            )
            .bind(NODE_HEARTBEAT_TTL_SECONDS)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(database_error)?;
        rows.iter().map(worker_status_from_row).collect()
    }

    async fn claim_worker_assignments(
        &self,
        node_id: Uuid,
        limit: u32,
        lease_ttl_seconds: u64,
    ) -> Result<Vec<WorkerAssignment>, StoreError> {
        if !(1..=3_600).contains(&lease_ttl_seconds) {
            return Err(StoreError::Conflict(
                "lease TTL must be between 1 and 3600 seconds".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let rows = sqlx::query(
            "SELECT a.* FROM sandbox_assignments a \
             JOIN sandbox_leases l ON l.id = a.lease_id \
             WHERE a.node_id=$1 AND a.status='reserved' AND l.status='active' \
               AND l.expires_at > now() \
             ORDER BY a.created_at LIMIT $2 FOR UPDATE OF a SKIP LOCKED",
        )
        .bind(node_id)
        .bind(i64::from(limit.clamp(1, 100)))
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        let mut assignments = Vec::with_capacity(rows.len());
        for row in rows {
            let tenant_id: Uuid = row.try_get("tenant_id")?;
            let request_id: Uuid = row.try_get("request_id")?;
            let sandbox_id: Uuid = row.try_get("sandbox_id")?;
            let lease_id: Uuid = row.try_get("lease_id")?;
            sqlx::query(
                "UPDATE sandbox_assignments SET status='assigned', updated_at=now() \
                 WHERE tenant_id=$1 AND request_id=$2",
            )
            .bind(tenant_id)
            .bind(request_id)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
            sqlx::query(
                "UPDATE sandbox_leases SET expires_at=now()+($1 * interval '1 second'), \
                 generation=generation+1, updated_at=now() WHERE id=$2 AND status='active'",
            )
            .bind(
                i64::try_from(lease_ttl_seconds)
                    .map_err(|error| StoreError::Conflict(error.to_string()))?,
            )
            .bind(lease_id)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
            let sandbox = fetch_sandbox(&mut *tx, tenant_id, sandbox_id).await?;
            let lease_row = sqlx::query("SELECT * FROM sandbox_leases WHERE id=$1")
                .bind(lease_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database_error)?;
            assignments.push(WorkerAssignment {
                tenant_id,
                request_id,
                sandbox,
                lease: lease_from_row(&lease_row)?,
                status: "assigned".into(),
            });
        }
        tx.commit().await.map_err(database_error)?;
        Ok(assignments)
    }

    async fn list_worker_assignments(
        &self,
        tenant: Uuid,
        node_id: Uuid,
        status: Option<&str>,
        limit: u32,
    ) -> Result<Vec<WorkerAssignment>, StoreError> {
        if status.is_some_and(|value| {
            !matches!(
                value,
                "reserved" | "assigned" | "completed" | "released" | "expired"
            )
        }) {
            return Err(StoreError::Conflict("unknown assignment status".into()));
        }
        let rows = sqlx::query(
            "SELECT * FROM sandbox_assignments \
             WHERE tenant_id=$1 AND node_id=$2 AND ($3::text IS NULL OR status=$3) \
             ORDER BY created_at DESC LIMIT $4",
        )
        .bind(tenant)
        .bind(node_id)
        .bind(status)
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        let mut assignments = Vec::with_capacity(rows.len());
        for row in rows {
            let tenant_id: Uuid = row.try_get("tenant_id")?;
            let request_id: Uuid = row.try_get("request_id")?;
            let sandbox_id: Uuid = row.try_get("sandbox_id")?;
            let lease_id: Uuid = row.try_get("lease_id")?;
            assignments.push(WorkerAssignment {
                tenant_id,
                request_id,
                sandbox: fetch_sandbox(&self.pool, tenant_id, sandbox_id).await?,
                lease: self.get_worker_lease(tenant_id, lease_id).await?,
                status: row.try_get("status")?,
            });
        }
        Ok(assignments)
    }

    async fn list_worker_assignments_for_node(
        &self,
        node_id: Uuid,
        status: Option<&str>,
        limit: u32,
    ) -> Result<Vec<WorkerAssignment>, StoreError> {
        if status.is_some_and(|value| {
            !matches!(
                value,
                "reserved" | "assigned" | "completed" | "released" | "expired"
            )
        }) {
            return Err(StoreError::Conflict("unknown assignment status".into()));
        }
        let rows = sqlx::query(
            "SELECT * FROM sandbox_assignments \
             WHERE node_id=$1 AND ($2::text IS NULL OR status=$2) \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(node_id)
        .bind(status)
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        let mut assignments = Vec::with_capacity(rows.len());
        for row in rows {
            let tenant_id: Uuid = row.try_get("tenant_id")?;
            let request_id: Uuid = row.try_get("request_id")?;
            let sandbox_id: Uuid = row.try_get("sandbox_id")?;
            let lease_id: Uuid = row.try_get("lease_id")?;
            assignments.push(WorkerAssignment {
                tenant_id,
                request_id,
                sandbox: fetch_sandbox(&self.pool, tenant_id, sandbox_id).await?,
                lease: self.get_worker_lease(tenant_id, lease_id).await?,
                status: row.try_get("status")?,
            });
        }
        Ok(assignments)
    }

    async fn get_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
    ) -> Result<WorkerLease, StoreError> {
        let row = sqlx::query("SELECT * FROM sandbox_leases WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(lease_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
        lease_from_row(&row)
    }

    async fn get_active_worker_lease(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<WorkerLease, StoreError> {
        let row = sqlx::query(
            "SELECT * FROM sandbox_leases WHERE tenant_id=$1 AND sandbox_id=$2 \
             AND status='active' AND expires_at > now() \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant)
        .bind(sandbox)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
        lease_from_row(&row)
    }

    async fn renew_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
        generation: i64,
        ttl_seconds: u64,
    ) -> Result<WorkerLease, StoreError> {
        if !(1..=3_600).contains(&ttl_seconds) {
            return Err(StoreError::Conflict(
                "lease TTL must be between 1 and 3600 seconds".into(),
            ));
        }
        let result = sqlx::query(
            "UPDATE sandbox_leases SET expires_at = now() + ($1 * interval '1 second'), \
             generation=generation+1, updated_at = now() \
             WHERE tenant_id=$2 AND id=$3 AND generation=$4 \
             AND status='active' AND expires_at > now()",
        )
        .bind(i64::try_from(ttl_seconds).map_err(|error| StoreError::Conflict(error.to_string()))?)
        .bind(tenant)
        .bind(lease_id)
        .bind(generation)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            let lease = self.get_worker_lease(tenant, lease_id).await?;
            if lease.expires_at <= Utc::now() {
                return Err(StoreError::Conflict("worker lease has expired".into()));
            }
            return Err(StoreError::Conflict(
                "worker lease generation or status changed".into(),
            ));
        }
        self.get_worker_lease(tenant, lease_id).await
    }

    async fn complete_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
        generation: i64,
        result_value: Value,
    ) -> Result<WorkerLease, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let row =
            sqlx::query("SELECT * FROM sandbox_leases WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(tenant)
                .bind(lease_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(database_error)?
                .ok_or(StoreError::NotFound)?;
        let lease = lease_from_row(&row)?;
        if lease.status == "completed" {
            if lease.reason.as_deref() != Some(result_value.to_string().as_str()) {
                return Err(StoreError::Conflict(
                    "worker lease already has a different completion result".into(),
                ));
            }
            tx.commit().await.map_err(database_error)?;
            return Ok(lease);
        }
        if lease.expires_at <= Utc::now() {
            return Err(StoreError::Conflict("worker lease has expired".into()));
        }
        if lease.status != "active" || lease.generation != generation {
            return Err(StoreError::Conflict(
                "worker lease generation or status changed".into(),
            ));
        }
        sqlx::query(
            "UPDATE sandbox_leases SET status='completed', reason=$1, updated_at=now() \
             WHERE id=$2",
        )
        .bind(result_value.to_string())
        .bind(lease_id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        sqlx::query(
            "UPDATE sandbox_assignments SET status='completed', updated_at=now() \
             WHERE tenant_id=$1 AND lease_id=$2",
        )
        .bind(tenant)
        .bind(lease_id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        let row = sqlx::query("SELECT * FROM sandbox_leases WHERE id=$1")
            .bind(lease_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
        let lease = lease_from_row(&row)?;
        tx.commit().await.map_err(database_error)?;
        Ok(lease)
    }

    async fn release_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
        generation: i64,
        reason: &str,
    ) -> Result<WorkerLease, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let row =
            sqlx::query("SELECT * FROM sandbox_leases WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(tenant)
                .bind(lease_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(database_error)?
                .ok_or(StoreError::NotFound)?;
        let lease = lease_from_row(&row)?;
        if lease.status == "released" {
            if lease.reason.as_deref() != Some(reason) {
                return Err(StoreError::Conflict(
                    "worker lease already has a different release reason".into(),
                ));
            }
            tx.commit().await.map_err(database_error)?;
            return Ok(lease);
        }
        if !matches!(lease.status.as_str(), "active" | "completed")
            || lease.generation != generation
        {
            return Err(StoreError::Conflict(
                "worker lease generation or status changed".into(),
            ));
        }
        release_capacity(&mut tx, &lease, "released", reason).await?;
        let row = sqlx::query("SELECT * FROM sandbox_leases WHERE id=$1")
            .bind(lease_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
        let lease = lease_from_row(&row)?;
        tx.commit().await.map_err(database_error)?;
        Ok(lease)
    }

    async fn reconcile_expired_leases(
        &self,
        limit: u32,
    ) -> Result<Vec<ReconciliationAction>, StoreError> {
        let limit = i64::from(limit.clamp(1, 10_000));
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let rows = sqlx::query(
            "SELECT * FROM sandbox_leases WHERE status='active' AND expires_at <= now() \
             ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED",
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        let mut actions = Vec::with_capacity(rows.len());
        for row in &rows {
            let lease = lease_from_row(row)?;
            release_capacity(&mut tx, &lease, "expired", "lease expired").await?;
            let source_key = format!("lease:{}:{}:expired", lease.id, lease.generation);
            let action_id = new_id();
            sqlx::query(
                "INSERT INTO reconciliation_actions \
                 (id, tenant_id, node_id, sandbox_id, lease_id, source_key, action, reason) \
                 VALUES ($1,$2,$3,$4,$5,$6,'release_expired_lease',$7) ON CONFLICT (source_key) DO NOTHING",
            )
            .bind(action_id)
            .bind(lease.tenant_id)
            .bind(lease.node_id)
            .bind(lease.sandbox_id)
            .bind(lease.id)
            .bind(&source_key)
            .bind("lease expired")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
            let action_row =
                sqlx::query("SELECT * FROM reconciliation_actions WHERE source_key=$1")
                    .bind(&source_key)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(database_error)?;
            actions.push(action_from_row(&action_row)?);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(actions)
    }

    async fn list_reconciliation_actions(
        &self,
        tenant: Uuid,
        limit: u32,
    ) -> Result<Vec<ReconciliationAction>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM reconciliation_actions WHERE tenant_id=$1 \
             ORDER BY detected_at DESC, id LIMIT $2",
        )
        .bind(tenant)
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(action_from_row).collect()
    }

    async fn begin_sandbox_operation(
        &self,
        value: SandboxOperation,
    ) -> Result<SandboxOperation, StoreError> {
        if value.status != "pending" {
            return Err(StoreError::Conflict("new operation must be pending".into()));
        }
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        advisory_lock(&mut tx, value.tenant_id, value.request_id).await?;
        sqlx::query(
            "INSERT INTO operation_requests \
             (tenant_id, request_id, sandbox_id, operation, payload, status, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,'pending',$6,$6) ON CONFLICT (tenant_id, request_id) DO NOTHING",
        )
        .bind(value.tenant_id)
        .bind(value.request_id)
        .bind(value.sandbox_id)
        .bind(&value.operation)
        .bind(&value.payload)
        .bind(value.created_at)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        let row =
            sqlx::query("SELECT * FROM operation_requests WHERE tenant_id=$1 AND request_id=$2")
                .bind(value.tenant_id)
                .bind(value.request_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database_error)?;
        let existing = operation_from_row(&row)?;
        if existing.sandbox_id != value.sandbox_id
            || existing.operation != value.operation
            || existing.payload != value.payload
        {
            return Err(StoreError::Conflict(
                "operation idempotency key was reused".into(),
            ));
        }
        tx.commit().await.map_err(database_error)?;
        Ok(existing)
    }

    async fn complete_sandbox_operation(
        &self,
        tenant: Uuid,
        request_id: Uuid,
        result: Value,
    ) -> Result<SandboxOperation, StoreError> {
        update_operation(self, tenant, request_id, "succeeded", Some(result), None).await
    }

    async fn fail_sandbox_operation(
        &self,
        tenant: Uuid,
        request_id: Uuid,
        error: Value,
    ) -> Result<SandboxOperation, StoreError> {
        update_operation(self, tenant, request_id, "failed", None, Some(error)).await
    }

    async fn get_sandbox_operation(
        &self,
        tenant: Uuid,
        request_id: Uuid,
    ) -> Result<SandboxOperation, StoreError> {
        let row =
            sqlx::query("SELECT * FROM operation_requests WHERE tenant_id=$1 AND request_id=$2")
                .bind(tenant)
                .bind(request_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(database_error)?
                .ok_or(StoreError::NotFound)?;
        operation_from_row(&row)
    }

    async fn put_image(&self, value: ImageRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO images (id, reference, rootfs, size_bytes, created_at) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&value.id)
        .bind(&value.reference)
        .bind(&value.rootfs)
        .bind(
            i64::try_from(value.size_bytes)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(value.created_at)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }

    async fn get_image(&self, id: &str) -> Result<ImageRecord, StoreError> {
        let row = sqlx::query("SELECT * FROM images WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
        Ok(ImageRecord {
            id: row.try_get("id")?,
            reference: row.try_get("reference")?,
            rootfs: row.try_get("rootfs")?,
            size_bytes: stored_u64(row.try_get("size_bytes")?, "image size_bytes")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[async_trait]
impl MetadataStore for PostgresRepository {
    async fn create_sandbox(&self, value: Sandbox) -> Result<(), CoreError> {
        Self::create_sandbox(self, value).await.map_err(core_error)
    }
    async fn get_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<Sandbox, CoreError> {
        Self::get_sandbox(self, tenant, id).await.map_err(core_error)
    }
    async fn list_sandboxes(&self, tenant: Uuid) -> Result<Vec<Sandbox>, CoreError> {
        Self::list_sandboxes(self, tenant).await.map_err(core_error)
    }
    async fn update_state(&self, tenant: Uuid, id: Uuid, expected: SandboxState, next: SandboxState, runtime_path: Option<String>) -> Result<Sandbox, CoreError> {
        Self::update_state(self, tenant, id, expected, next, runtime_path).await.map_err(core_error)
    }
    async fn delete_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<(), CoreError> {
        Self::delete_sandbox(self, tenant, id).await.map_err(core_error)
    }
    async fn put_key(&self, value: ApiKeyRecord) -> Result<(), CoreError> {
        Self::put_key(self, value).await.map_err(core_error)
    }
    async fn revoke_key(&self, tenant: Uuid, id: Uuid) -> Result<(), CoreError> {
        Self::revoke_key(self, tenant, id).await.map_err(core_error)
    }
    async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, CoreError> {
        Self::find_key(self, digest).await.map_err(core_error)
    }
    async fn put_snapshot(&self, value: Snapshot) -> Result<(), CoreError> {
        Self::put_snapshot(self, value).await.map_err(core_error)
    }
    async fn get_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<Snapshot, CoreError> {
        Self::get_snapshot(self, tenant, id).await.map_err(core_error)
    }
    async fn list_snapshots(&self, tenant: Uuid, sandbox: Uuid) -> Result<Vec<Snapshot>, CoreError> {
        Self::list_snapshots(self, tenant, sandbox).await.map_err(core_error)
    }
    async fn delete_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<(), CoreError> {
        Self::delete_snapshot(self, tenant, id).await.map_err(core_error)
    }
    async fn append_usage(&self, value: UsageEvent) -> Result<(), CoreError> {
        Self::append_usage(self, value).await.map_err(core_error)
    }
    async fn usage(&self, tenant: Uuid) -> Result<Vec<UsageSummary>, CoreError> {
        Self::usage(self, tenant).await.map_err(core_error)
    }
    async fn register_node(&self, value: Node) -> Result<(), CoreError> {
        Self::register_node(self, value).await.map_err(core_error)
    }
    async fn heartbeat(&self, id: Uuid) -> Result<(), CoreError> {
        Self::heartbeat(self, id).await.map_err(core_error)
    }
    async fn list_nodes(&self) -> Result<Vec<Node>, CoreError> {
        Self::list_nodes(self).await.map_err(core_error)
    }
    async fn put_tenant(&self, value: TenantRecord) -> Result<(), CoreError> {
        Self::put_tenant(self, value).await.map_err(core_error)
    }
    async fn get_tenant(&self, id: Uuid) -> Result<TenantRecord, CoreError> {
        Self::get_tenant(self, id).await.map_err(core_error)
    }
    async fn list_sandbox_events(&self, tenant: Uuid, sandbox: Uuid, limit: u32) -> Result<Vec<SandboxEvent>, CoreError> {
        Self::list_sandbox_events(self, tenant, sandbox, limit).await.map_err(core_error)
    }
    async fn put_stored_snapshot(&self, value: StoredSnapshot) -> Result<(), CoreError> {
        Self::put_stored_snapshot(self, value).await.map_err(core_error)
    }
    async fn get_stored_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<StoredSnapshot, CoreError> {
        Self::get_stored_snapshot(self, tenant, id).await.map_err(core_error)
    }
    async fn list_stored_snapshots(&self, tenant: Uuid, sandbox: Uuid) -> Result<Vec<StoredSnapshot>, CoreError> {
        Self::list_stored_snapshots(self, tenant, sandbox).await.map_err(core_error)
    }
    async fn create_sandbox_idempotent(&self, tenant: Uuid, request_id: Uuid, sandbox: Sandbox) -> Result<Sandbox, CoreError> {
        Self::create_sandbox_idempotent(self, tenant, request_id, sandbox).await.map_err(core_error)
    }
    async fn register_worker(&self, value: WorkerRegistration) -> Result<(), CoreError> {
        Self::register_worker(self, value).await.map_err(core_error)
    }
    async fn heartbeat_worker(&self, heartbeat: WorkerHeartbeat) -> Result<WorkerStatus, CoreError> {
        Self::heartbeat_worker(self, heartbeat).await.map_err(core_error)
    }
    async fn get_worker(&self, node_id: Uuid) -> Result<WorkerStatus, CoreError> {
        Self::get_worker(self, node_id).await.map_err(core_error)
    }
    async fn list_workers(&self, include_unhealthy: bool) -> Result<Vec<WorkerStatus>, CoreError> {
        Self::list_workers(self, include_unhealthy).await.map_err(core_error)
    }
    async fn claim_worker_assignments(&self, node_id: Uuid, limit: u32, lease_ttl_seconds: u64) -> Result<Vec<WorkerAssignment>, CoreError> {
        Self::claim_worker_assignments(self, node_id, limit, lease_ttl_seconds).await.map_err(core_error)
    }
    async fn list_worker_assignments(&self, tenant: Uuid, node_id: Uuid, status: Option<&str>, limit: u32) -> Result<Vec<WorkerAssignment>, CoreError> {
        Self::list_worker_assignments(self, tenant, node_id, status, limit).await.map_err(core_error)
    }
    async fn list_worker_assignments_for_node(&self, node_id: Uuid, status: Option<&str>, limit: u32) -> Result<Vec<WorkerAssignment>, CoreError> {
        Self::list_worker_assignments_for_node(self, node_id, status, limit).await.map_err(core_error)
    }
    async fn get_worker_lease(&self, tenant: Uuid, lease_id: Uuid) -> Result<WorkerLease, CoreError> {
        Self::get_worker_lease(self, tenant, lease_id).await.map_err(core_error)
    }
    async fn get_active_worker_lease(&self, tenant: Uuid, sandbox: Uuid) -> Result<WorkerLease, CoreError> {
        Self::get_active_worker_lease(self, tenant, sandbox).await.map_err(core_error)
    }
    async fn renew_worker_lease(&self, tenant: Uuid, lease_id: Uuid, generation: i64, ttl_seconds: u64) -> Result<WorkerLease, CoreError> {
        Self::renew_worker_lease(self, tenant, lease_id, generation, ttl_seconds).await.map_err(core_error)
    }
    async fn complete_worker_lease(&self, tenant: Uuid, lease_id: Uuid, generation: i64, result: Value) -> Result<WorkerLease, CoreError> {
        Self::complete_worker_lease(self, tenant, lease_id, generation, result).await.map_err(core_error)
    }
    async fn release_worker_lease(&self, tenant: Uuid, lease_id: Uuid, generation: i64, reason: &str) -> Result<WorkerLease, CoreError> {
        Self::release_worker_lease(self, tenant, lease_id, generation, reason).await.map_err(core_error)
    }
    async fn reconcile_expired_leases(&self, limit: u32) -> Result<Vec<ReconciliationAction>, CoreError> {
        Self::reconcile_expired_leases(self, limit).await.map_err(core_error)
    }
    async fn list_reconciliation_actions(&self, tenant: Uuid, limit: u32) -> Result<Vec<ReconciliationAction>, CoreError> {
        Self::list_reconciliation_actions(self, tenant, limit).await.map_err(core_error)
    }
    async fn begin_sandbox_operation(&self, value: SandboxOperation) -> Result<SandboxOperation, CoreError> {
        Self::begin_sandbox_operation(self, value).await.map_err(core_error)
    }
    async fn complete_sandbox_operation(&self, tenant: Uuid, request_id: Uuid, result: Value) -> Result<SandboxOperation, CoreError> {
        Self::complete_sandbox_operation(self, tenant, request_id, result).await.map_err(core_error)
    }
    async fn fail_sandbox_operation(&self, tenant: Uuid, request_id: Uuid, error: Value) -> Result<SandboxOperation, CoreError> {
        Self::fail_sandbox_operation(self, tenant, request_id, error).await.map_err(core_error)
    }
    async fn get_sandbox_operation(&self, tenant: Uuid, request_id: Uuid) -> Result<SandboxOperation, CoreError> {
        Self::get_sandbox_operation(self, tenant, request_id).await.map_err(core_error)
    }
    async fn put_image(&self, value: ImageRecord) -> Result<(), CoreError> {
        Self::put_image(self, value).await.map_err(core_error)
    }
    async fn get_image(&self, id: &str) -> Result<ImageRecord, CoreError> {
        Self::get_image(self, id).await.map_err(core_error)
    }
}


async fn update_operation(
    repository: &PostgresRepository,
    tenant: Uuid,
    request_id: Uuid,
    status: &str,
    result: Option<Value>,
    error: Option<Value>,
) -> Result<SandboxOperation, StoreError> {
    let mut tx = repository.pool.begin().await.map_err(database_error)?;
    let row = sqlx::query(
        "SELECT * FROM operation_requests WHERE tenant_id=$1 AND request_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?
    .ok_or(StoreError::NotFound)?;
    let existing = operation_from_row(&row)?;
    if existing.status != "pending" {
        let matches =
            existing.status == status && existing.result == result && existing.error == error;
        if !matches {
            return Err(StoreError::Conflict(
                "operation already has a different terminal result".into(),
            ));
        }
        tx.commit().await.map_err(database_error)?;
        return Ok(existing);
    }
    sqlx::query(
        "UPDATE operation_requests SET status=$1, result=$2, error=$3, updated_at=now() \
         WHERE tenant_id=$4 AND request_id=$5",
    )
    .bind(status)
    .bind(result)
    .bind(error)
    .bind(tenant)
    .bind(request_id)
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;
    let row = sqlx::query("SELECT * FROM operation_requests WHERE tenant_id=$1 AND request_id=$2")
        .bind(tenant)
        .bind(request_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
    let operation = operation_from_row(&row)?;
    tx.commit().await.map_err(database_error)?;
    Ok(operation)
}

async fn release_capacity(
    tx: &mut Transaction<'_, Postgres>,
    lease: &WorkerLease,
    status: &str,
    reason: &str,
) -> Result<(), StoreError> {
    let changed = sqlx::query(
        "UPDATE sandbox_leases SET status=$1, reason=$2, updated_at=now() \
         WHERE id=$3 AND status IN ('active', 'completed') AND generation=$4",
    )
    .bind(status)
    .bind(reason)
    .bind(lease.id)
    .bind(lease.generation)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    if changed.rows_affected() == 0 {
        return Err(StoreError::Conflict(
            "worker lease was reconciled concurrently".into(),
        ));
    }
    let sandbox = fetch_sandbox(&mut **tx, lease.tenant_id, lease.sandbox_id).await?;
    let memory_bytes = u64::from(sandbox.memory_mb)
        .checked_mul(1_048_576)
        .ok_or_else(|| StoreError::Conflict("sandbox memory size overflow".into()))?;
    let disk_bytes = u64::from(sandbox.disk_mb)
        .checked_mul(1_048_576)
        .ok_or_else(|| StoreError::Conflict("sandbox disk size overflow".into()))?;
    sqlx::query(
        "UPDATE nodes SET available_vcpus=LEAST(total_vcpus, available_vcpus+$1), \
         available_memory_bytes=LEAST(total_memory_bytes, available_memory_bytes+$2), \
         available_disk_bytes=LEAST(total_disk_bytes, available_disk_bytes+$3), \
         sandbox_count=GREATEST(0, sandbox_count-1) WHERE id=$4",
    )
    .bind(i32::try_from(sandbox.cpu).map_err(|error| StoreError::Conflict(error.to_string()))?)
    .bind(i64::try_from(memory_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
    .bind(i64::try_from(disk_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?)
    .bind(lease.node_id)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    sqlx::query(
        "UPDATE sandboxes SET node_id=NULL, updated_at=now() \
         WHERE tenant_id=$1 AND id=$2 AND node_id=$3",
    )
    .bind(lease.tenant_id)
    .bind(lease.sandbox_id)
    .bind(lease.node_id)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    sqlx::query(
        "UPDATE sandbox_assignments SET status=$1, updated_at=now() \
         WHERE tenant_id=$2 AND lease_id=$3",
    )
    .bind(status)
    .bind(lease.tenant_id)
    .bind(lease.id)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    insert_sandbox_event(
        tx,
        lease.tenant_id,
        lease.sandbox_id,
        Some(sandbox.state),
        sandbox.state,
        Some(reason),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sandbox(tenant: Uuid) -> Sandbox {
        let now = Utc::now();
        Sandbox {
            id: new_id(),
            tenant_id: tenant,
            node_id: None,
            image_id: "afimg1_test".into(),
            state: SandboxState::Creating,
            runtime: RuntimeKind::Firecracker,
            cpu: 1,
            memory_mb: 64,
            disk_mb: 512,
            timeout_seconds: 60,
            network: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        }
    }

    async fn schedule_test_sandbox(
        repository: &PostgresRepository,
        tenant: Uuid,
        request_id: Uuid,
        sandbox: Sandbox,
    ) -> Result<ScheduledSandbox, CoreError> {
        PostgresScheduler::new(repository.clone())
            .schedule(ScheduleRequest {
                tenant_id: tenant,
                request_id,
                sandbox,
                preferred_worker: None,
                lease_ttl: Duration::from_secs(60),
            })
            .await
    }

    #[tokio::test]
    async fn concurrent_schedulers_reserve_capacity_once() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let repository = Arc::new(PostgresRepository::connect(&database_url).await.unwrap());
        repository.migrate().await.unwrap();
        let tenant = new_id();
        repository
            .put_tenant(TenantRecord {
                id: tenant,
                name: format!("lease-race-{}", tenant),
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        let node_id = new_id();
        repository
            .register_worker(WorkerRegistration {
                node_id,
                name: format!("node-{}", node_id),
                runtime: RuntimeKind::Firecracker,
                control_endpoint: "http://127.0.0.1:9000".into(),
                total_vcpus: 1,
                total_memory_bytes: 64 * 1_048_576,
                total_disk_bytes: 512 * 1_048_576,
                available_vcpus: 1,
                available_memory_bytes: 64 * 1_048_576,
                available_disk_bytes: 512 * 1_048_576,
                healthy: true,
                version: 1,
                metadata: json!({}),
                started_at: Utc::now(),
                last_heartbeat: Utc::now(),
            })
            .await
            .unwrap();
        let first = sandbox(tenant);
        let second = sandbox(tenant);
        let left = tokio::spawn({
            let repository = repository.clone();
            async move {
                schedule_test_sandbox(&repository, tenant, new_id(), first).await
            }
        });
        let right = tokio::spawn({
            let repository = repository.clone();
            async move {
                schedule_test_sandbox(&repository, tenant, new_id(), second).await
            }
        });
        let mut successes = 0;
        for result in [left.await.unwrap(), right.await.unwrap()] {
            if result.is_ok() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1);
        let workers = repository.get_worker(node_id).await.unwrap();
        assert_eq!(workers.registration.available_vcpus, 0);
        assert_eq!(workers.sandbox_count, 1);
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    async fn repository_and_tenant() -> Option<(Arc<PostgresRepository>, Uuid)> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let repository = Arc::new(PostgresRepository::connect(&database_url).await.unwrap());
        repository.migrate().await.unwrap();
        let tenant = new_id();
        repository
            .put_tenant(TenantRecord {
                id: tenant,
                name: format!("storage-invariant-{}", tenant),
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        Some((repository, tenant))
    }

    async fn register_test_worker(repository: &PostgresRepository, tenant: Uuid) -> Uuid {
        let node_id = new_id();
        repository
            .register_worker(WorkerRegistration {
                node_id,
                name: format!("node-{}-{node_id}", tenant),
                runtime: RuntimeKind::Firecracker,
                control_endpoint: "http://127.0.0.1:9000".into(),
                total_vcpus: 2,
                total_memory_bytes: 128 * 1_048_576,
                total_disk_bytes: 1024 * 1_048_576,
                available_vcpus: 2,
                available_memory_bytes: 128 * 1_048_576,
                available_disk_bytes: 1024 * 1_048_576,
                healthy: true,
                version: 1,
                metadata: json!({}),
                started_at: Utc::now(),
                last_heartbeat: Utc::now(),
            })
            .await
            .unwrap();
        node_id
    }

    #[tokio::test]
    async fn heartbeat_preserves_scheduler_capacity_and_refreshes_same_version() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let _scheduled = schedule_test_sandbox(&repository, tenant, new_id(), sandbox(tenant))
            .await
            .unwrap();
        let before = repository.get_worker(node_id).await.unwrap();
        sqlx::query("UPDATE nodes SET last_heartbeat=now()-interval '1 minute' WHERE id=$1")
            .bind(node_id)
            .execute(&repository.pool)
            .await
            .unwrap();
        let heartbeat = WorkerHeartbeat {
            node_id,
            available_vcpus: 2,
            available_memory_bytes: 128 * 1_048_576,
            available_disk_bytes: 1024 * 1_048_576,
            sandbox_count: 7,
            healthy: true,
            version: 1,
            metadata: json!({}),
            last_error: None,
        };
        let after = repository
            .heartbeat_worker(heartbeat.clone())
            .await
            .unwrap();
        assert_eq!(after.registration.available_vcpus, 1);
        assert_eq!(
            after.registration.available_memory_bytes,
            before.registration.available_memory_bytes
        );
        assert_eq!(after.sandbox_count, 1);
        assert_eq!(after.observed_sandbox_count, 7);
        assert!(after.registration.last_heartbeat > before.registration.last_heartbeat);

        sqlx::query("UPDATE nodes SET last_heartbeat=now()-interval '1 minute' WHERE id=$1")
            .bind(node_id)
            .execute(&repository.pool)
            .await
            .unwrap();
        let refreshed = repository.heartbeat_worker(heartbeat).await.unwrap();
        assert!(refreshed.registration.last_heartbeat > Utc::now() - chrono::Duration::seconds(5));
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    #[tokio::test]
    async fn active_lease_lookup_and_renewal_are_durable_but_expiry_blocks_completion() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let scheduled = schedule_test_sandbox(&repository, tenant, new_id(), sandbox(tenant))
            .await
            .unwrap();
        let claimed = repository
            .claim_worker_assignments(node_id, 1, 60)
            .await
            .unwrap();
        let current = repository
            .get_active_worker_lease(tenant, scheduled.sandbox.id)
            .await
            .unwrap();
        assert_eq!(current.id, scheduled.lease_id);
        assert_eq!(current.generation, claimed[0].lease.generation);
        let renewed = repository
            .renew_worker_lease(tenant, current.id, current.generation, 120)
            .await
            .unwrap();
        let reopened = PostgresRepository::connect(&database_url()).await.unwrap();
        assert_eq!(
            reopened
                .get_worker_lease(tenant, renewed.id)
                .await
                .unwrap()
                .generation,
            renewed.generation
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), reopened.pool.close()).await;
        sqlx::query("UPDATE sandbox_leases SET expires_at=now()-interval '1 second' WHERE id=$1")
            .bind(renewed.id)
            .execute(&repository.pool)
            .await
            .unwrap();
        assert!(
            repository
                .complete_worker_lease(tenant, renewed.id, renewed.generation, json!({"ok": true}))
                .await
                .is_err()
        );
        assert!(
            repository
                .get_active_worker_lease(tenant, scheduled.sandbox.id)
                .await
                .is_err()
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    fn database_url() -> String {
        std::env::var("DATABASE_URL").unwrap()
    }

    #[tokio::test]
    async fn usage_events_reject_truncate() {
        let Some((repository, _tenant)) = repository_and_tenant().await else {
            return;
        };
        assert!(
            sqlx::query("TRUNCATE usage_events")
                .execute(&repository.pool)
                .await
                .is_err()
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }
}
