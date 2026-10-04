use crate::{
    NODE_HEARTBEAT_TTL_SECONDS, PostgresRepository, StoreError, core_error, database_error,
};
mod guard;
use aiec_core::{
    ApiKeyRecord, ApprovalDecisionRequest, CoreError, GuardProposal, GuardToolApproval,
    ImageRecord, Node, RuntimeKind, Sandbox, SandboxState, Scope, Snapshot, UsageEvent,
    UsageSummary, new_id,
    run::{
        Placement, RetentionPolicy, Run, RunArtifactRef, RunAttempt, RunEvent, RunResults,
        RunSandbox, RunState, WorkloadSpec,
    },
    run_queue::{RunQueueClaim, RunQueueLimits},
    runtime::RuntimeCapabilities,
    scheduler::{ScheduleRequest, ScheduledSandbox, Scheduler, WorkerDispatch},
    storage::{
        AuditEvent, BudgetDebit, GuardBudgetState, GuardFence, GuardIdentity, GuardIncident,
        MetadataStore, Reassignment, ReconciliationAction, SandboxEvent, SandboxOperation,
        SandboxOwnership, StoredSnapshot, TenantRecord, WorkerAssignment, WorkerHeartbeat,
        WorkerLease, WorkerRegistration, WorkerStatus,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
#[cfg(test)]
use std::sync::Arc;
use uuid::Uuid;

/// Lease granted to a replacement owner during recovery, matching the scheduler default.
const RECOVERY_LEASE_TTL_SECONDS: i64 = 300;

/// Longest operator-supplied drain reason, matched by the `nodes_drain_reason_length`
/// constraint so a reason that somehow bypasses this check still cannot bloat the row.
const DRAIN_REASON_MAX_CHARS: usize = 512;

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
        "paused" => Ok(SandboxState::Paused),
        "quarantined" => Ok(SandboxState::Quarantined),
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
        "docker" => Ok(RuntimeKind::Docker),
        "bwrap-dev" => Ok(RuntimeKind::BwrapDev),
        "hosted" => Ok(RuntimeKind::Hosted),
        value => Err(StoreError::Conflict(format!(
            "invalid persisted runtime: {value}"
        ))),
    }
}

pub(crate) fn sandbox_from_row(row: &sqlx::postgres::PgRow) -> Result<Sandbox, StoreError> {
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
        environment: serde_json::from_value(row.try_get("environment")?)?,
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
            capabilities: serde_json::from_value(row.try_get("capabilities")?)
                .map_err(StoreError::Json)?,
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
        accepting_sandboxes: row.try_get("accepting_sandboxes")?,
        drain_reason: row.try_get("drain_reason")?,
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

fn audit_event_from_row(row: &sqlx::postgres::PgRow) -> Result<AuditEvent, StoreError> {
    Ok(AuditEvent {
        id: row.try_get("id")?,
        occurred_at: row.try_get("occurred_at")?,
        tenant_id: row.try_get("tenant_id")?,
        actor: row.try_get("actor")?,
        action: row.try_get("action")?,
        subject_type: row.try_get("subject_type")?,
        subject_id: row.try_get("subject_id")?,
        result: row.try_get("result")?,
        request_id: row.try_get("request_id")?,
        remote_addr: row.try_get("remote_addr")?,
        detail: row.try_get("detail")?,
    })
}

fn invalid_run_state(value: &str) -> StoreError {
    StoreError::Conflict(format!("invalid persisted run state: {value}"))
}

fn run_state_from_str(value: &str) -> Result<RunState, StoreError> {
    RunState::parse(value).ok_or_else(|| invalid_run_state(value))
}

/// The states a stored attempt may be in.
///
/// An attempt is one try at a run, so only a try that is under way or has
/// finished is a thing that can be recorded. A run in `queued` or `preparing`
/// has not made an attempt yet, and writing that here would be a claim about
/// work that never started.
fn attempt_state_as_str(value: RunState) -> Result<&'static str, StoreError> {
    match value {
        RunState::Running => Ok("running"),
        RunState::Succeeded => Ok("succeeded"),
        RunState::Failed => Ok("failed"),
        RunState::Cancelled => Ok("cancelled"),
        state => Err(StoreError::Conflict(format!(
            "an attempt cannot be recorded in the {} state",
            state.as_str()
        ))),
    }
}

pub(crate) fn run_from_row(row: &sqlx::postgres::PgRow) -> Result<Run, StoreError> {
    let state: String = row.try_get("state")?;
    let retention: String = row.try_get("retention")?;
    let environment: Value = row.try_get("environment")?;
    // A run's environment is written twice: inside the workload document, which
    // is what gets executed, and as its own column so a query can find a run by
    // an environment name without unnesting the whole workload. The column is
    // the one a query reads, so it is also the one that wins on the way back and
    // a round trip cannot hand back a workload that disagrees with the row.
    let mut workload: WorkloadSpec = serde_json::from_value(row.try_get("workload")?)?;
    workload.environment = serde_json::from_value(environment)?;
    Ok(Run {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        state: run_state_from_str(&state)?,
        requested_at: row.try_get("requested_at")?,
        queued_at: row.try_get("queued_at")?,
        started_at: row.try_get("started_at")?,
        completed_at: row.try_get("completed_at")?,
        workload,
        resources: serde_json::from_value(row.try_get("resources")?)?,
        requirements: serde_json::from_value(row.try_get("requirements")?)?,
        placement: serde_json::from_value(row.try_get("placement")?)?,
        results: serde_json::from_value(row.try_get("results")?)?,
        failure_reason: row.try_get("failure_reason")?,
        retention: RetentionPolicy::parse(&retention).ok_or_else(|| {
            StoreError::Conflict(format!("invalid persisted run retention: {retention}"))
        })?,
        retained_sandbox_id: row.try_get("retained_sandbox_id")?,
        retained_until: row.try_get("retained_until")?,
        idempotency_key: row.try_get("idempotency_key")?,
        parent_run_id: row.try_get("parent_run_id")?,
        matrix_id: row.try_get("matrix_id")?,
        // The cell this run was admitted as. A document that does not parse is
        // a corrupt ledger rather than an absent label, so it is reported
        // instead of being read as a run that was never a cell.
        matrix_cell: row
            .try_get::<Option<Value>, _>("matrix_cell")?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                StoreError::Conflict(format!("invalid persisted matrix cell: {error}"))
            })?,
    })
}

fn run_event_from_row(row: &sqlx::postgres::PgRow) -> Result<RunEvent, StoreError> {
    Ok(RunEvent {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        sandbox_id: row.try_get("sandbox_id")?,
        event_type: row.try_get("type")?,
        occurred_at: row.try_get("occurred_at")?,
        detail: row.try_get("detail")?,
    })
}

fn run_sandbox_from_row(row: &sqlx::postgres::PgRow) -> Result<RunSandbox, StoreError> {
    Ok(RunSandbox {
        run_id: row.try_get("run_id")?,
        sandbox_id: row.try_get("sandbox_id")?,
        role: row.try_get("role")?,
    })
}

/// Reads a non-negative `bigint` column as a count.
fn quota_count(row: &sqlx::postgres::PgRow, column: &str) -> Result<u32, StoreError> {
    let value: i64 = row.try_get(column)?;
    u32::try_from(value).map_err(|_| {
        StoreError::Conflict(format!(
            "persisted quota column {column} is not a count: {value}"
        ))
    })
}

/// Reads a non-negative `bigint` column as an amount.
fn quota_amount(row: &sqlx::postgres::PgRow, column: &str) -> Result<u64, StoreError> {
    let value: i64 = row.try_get(column)?;
    u64::try_from(value).map_err(|_| {
        StoreError::Conflict(format!(
            "persisted quota column {column} is negative: {value}"
        ))
    })
}

fn run_attempt_from_row(row: &sqlx::postgres::PgRow) -> Result<RunAttempt, StoreError> {
    let state: String = row.try_get("state")?;
    Ok(RunAttempt {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        attempt_number: row.try_get("attempt_number")?,
        sandbox_id: row.try_get("sandbox_id")?,
        state: run_state_from_str(&state)?,
        failure_reason: row.try_get("failure_reason")?,
        started_at: row.try_get("started_at")?,
        completed_at: row.try_get("completed_at")?,
        placement: serde_json::from_value(row.try_get("placement")?)?,
        results: serde_json::from_value(row.try_get("results")?)?,
    })
}

fn run_artifact_from_row(row: &sqlx::postgres::PgRow) -> Result<RunArtifactRef, StoreError> {
    Ok(RunArtifactRef {
        name: row.try_get("name")?,
        object_key: row.try_get("object_key")?,
        size_bytes: row.try_get("size_bytes")?,
        checksum_sha256: row.try_get("checksum_sha256")?,
        content_type: row.try_get("content_type")?,
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

/// Reads one run on behalf of a tenant.
///
/// Every run read goes through here, so a run belonging to another tenant is
/// indistinguishable from one that does not exist.
async fn fetch_run(
    executor: impl sqlx::Executor<'_, Database = Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<Run, StoreError> {
    let row = sqlx::query("SELECT * FROM runs WHERE tenant_id = $1 AND id = $2")
        .bind(tenant)
        .bind(id)
        .fetch_optional(executor)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
    run_from_row(&row)
}

pub(crate) async fn insert_run_tx(
    tx: &mut Transaction<'_, Postgres>,
    value: Run,
) -> Result<Run, StoreError> {
    if value.tenant_id.is_nil() {
        return Err(StoreError::Conflict("run tenant is required".into()));
    }
    let workload = serde_json::to_value(&value.workload)?;
    // The environment is stored twice on purpose: once inside the workload
    // document, which is what actually executes, and once in its own column
    // so a run can be found by an environment name without unnesting every
    // workload in the tenant. `run_from_row` reads the column back into the
    // document, so the two can never disagree.
    let environment = serde_json::to_value(&value.workload.environment)?;
    let requirements = serde_json::to_value(&value.requirements)?;
    let resources = serde_json::to_value(&value.resources)?;
    let placement = serde_json::to_value(&value.placement)?;
    let results = serde_json::to_value(&value.results)?;
    // The conflict target names the partial unique index, so a retry
    // carrying the same key collides here instead of inserting a second run.
    // `DO UPDATE` with a write that changes nothing is what brings the row
    // back in this same statement: `DO NOTHING` would return no row and cost
    // a second round trip to read a run the caller already knows exists, and
    // a read-then-insert pair would let two concurrent retries both insert.
    let row = sqlx::query(
        "INSERT INTO runs (id, tenant_id, state, requested_at, queued_at, started_at, \
             completed_at, workload, environment, requirements, resources, placement, results, \
             failure_reason, retention, retained_sandbox_id, retained_until, idempotency_key, \
             parent_run_id, matrix_id, matrix_cell) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) \
             ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL \
             DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key RETURNING *",
    )
    .bind(value.id)
    .bind(value.tenant_id)
    .bind(value.state.as_str())
    .bind(value.requested_at)
    .bind(value.queued_at)
    .bind(value.started_at)
    .bind(value.completed_at)
    .bind(&workload)
    .bind(&environment)
    .bind(&requirements)
    .bind(&resources)
    .bind(&placement)
    .bind(&results)
    .bind(&value.failure_reason)
    .bind(value.retention.as_str())
    .bind(value.retained_sandbox_id)
    .bind(value.retained_until)
    .bind(&value.idempotency_key)
    .bind(value.parent_run_id)
    .bind(value.matrix_id)
    // Written with the run itself: the cell's axis exists nowhere else, and a
    // matrix whose labels are attached after the fact loses every label whose
    // cell failed, or whose submission never came back.
    .bind(
        value
            .matrix_cell
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?,
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(database_error)?;
    run_from_row(&row)
}

/// Links compute before placement commits, so cancellation can always find it.
async fn link_attempt_sandbox(
    tx: &mut Transaction<'_, Postgres>,
    run_id: Uuid,
    attempt_id: Uuid,
    sandbox_id: Uuid,
) -> Result<(), StoreError> {
    let assigned = sqlx::query(
        "UPDATE run_attempts SET sandbox_id=$3 WHERE id=$1 AND run_id=$2 \
         AND state='running' AND completed_at IS NULL AND sandbox_id IS NULL",
    )
    .bind(attempt_id)
    .bind(run_id)
    .bind(sandbox_id)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    if assigned.rows_affected() != 1 {
        return Err(StoreError::Conflict(
            "attempt is not awaiting compute".into(),
        ));
    }
    sqlx::query("INSERT INTO run_sandboxes (run_id,sandbox_id,role) VALUES ($1,$2,'primary')")
        .bind(run_id)
        .bind(sandbox_id)
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    Ok(())
}

/// How far a write to a run's child tables is allowed to reach.
#[derive(Clone, Copy)]
enum ChildAssociation {
    /// The machine only has to belong to the tenant: this write is what
    /// associates it with the run.
    Owned,
    /// Retention, which additionally requires the run to have used the machine
    /// and may not displace the one the run is already keeping.
    Retained,
}

/// Says which guard refused a run-child write, in terms the caller can act on.
///
/// The write itself carries the predicates, so nothing inconsistent is ever
/// stored - this only runs after a statement matched no rows, and turns that
/// into [`StoreError::NotFound`] for a run that is not this tenant's and a
/// [`StoreError::Conflict`] for a machine that is, rather than the
/// foreign-key violation the caller has no way to interpret.
async fn run_child_refusal(
    executor: impl sqlx::Executor<'_, Database = Postgres>,
    tenant: Uuid,
    run: Uuid,
    machine: Option<Uuid>,
    require: ChildAssociation,
) -> StoreError {
    let row = match sqlx::query(
        "SELECT r.retained_sandbox_id, \
           EXISTS (SELECT 1 FROM sandboxes s WHERE s.id = $1 AND s.tenant_id = $2) \
             AS owns_machine, \
           EXISTS (SELECT 1 FROM run_sandboxes rs \
             WHERE rs.run_id = r.id AND rs.sandbox_id = $1) AS used_machine \
         FROM runs r WHERE r.id = $3 AND r.tenant_id = $2",
    )
    .bind(machine)
    .bind(tenant)
    .bind(run)
    .fetch_optional(executor)
    .await
    {
        Ok(row) => row,
        Err(error) => return database_error(error),
    };
    // Another tenant's run is not a run this caller may name, and saying which
    // guard refused would confirm that it exists at all.
    let Some(row) = row else {
        return StoreError::NotFound;
    };
    if machine.is_some() && !row.try_get::<bool, _>("owns_machine").unwrap_or(false) {
        return StoreError::Conflict(
            "a run may only name a machine belonging to its own tenant".into(),
        );
    }
    let used = row.try_get::<bool, _>("used_machine").unwrap_or(false);
    let kept: Option<Uuid> = row.try_get("retained_sandbox_id").unwrap_or(None);
    if matches!(require, ChildAssociation::Retained) {
        if let Some(kept) = kept
            && Some(kept) != machine
        {
            // Overwriting is the leak this refuses: the displaced machine has a
            // row the sweeper will never select, so nothing ever reclaims it.
            return StoreError::Conflict("run already retains a different machine".into());
        }
        if machine.is_some() && !used {
            return StoreError::Conflict("a run may only keep a machine it used".into());
        }
    }
    StoreError::Conflict("the run no longer accepts this write".into())
}

/// A hard delete of a run cascades into `run_events`, whose triggers reject any
/// mutation of the record of what happened.
///
/// The record outranks the request to erase it, so the caller is told the run is
/// kept rather than handed the raw `RAISE` from a trigger it has no way to act
/// on. The delete is still the thing that decides: a run with no recorded
/// history is removed normally, and this only rewrites the error.
fn run_history_is_append_only(error: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(database) = &error
        && database.code().as_deref() == Some("P0001")
    {
        return StoreError::Conflict(
            "a run's recorded history is append-only and cannot be deleted".into(),
        );
    }
    database_error(error)
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
    required: Option<&aiec_core::runtime::RuntimeCapabilities>,
) -> Result<(), StoreError> {
    if value.tenant_id.is_nil() {
        return Err(StoreError::Conflict("sandbox tenant is required".into()));
    }
    let predicate = match required {
        Some(required) => {
            let mut value = serde_json::to_value(required)?;
            if let Value::Object(fields) = &mut value {
                // Only what the workload actually demands: a false boolean is
                // "no requirement", and containment compares the rest exactly,
                // so demanding `false` would refuse a worker that has it true.
                fields.retain(|_, value| value == &Value::Bool(true));
                // Same reasoning for the isolation class. `Process` means the
                // caller did not ask for a class, so naming it would exclude
                // every microVM and container worker alike.
                if fields.get("isolation") == Some(&serde_json::json!("process")) {
                    fields.remove("isolation");
                }
            }
            value
        }
        None => json!({ "exec": true, "files": true }),
    };
    sqlx::query(
        "INSERT INTO sandboxes \
         (id, tenant_id, node_id, image_id, state, runtime, cpu, memory_mb, disk_mb, \
          timeout_seconds, network, environment, runtime_path, created_at, updated_at, \
          required_capabilities) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
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
    .bind(
        serde_json::to_value(&value.environment)
            .map_err(|error| StoreError::Database(sqlx::Error::Decode(Box::new(error))))?,
    )
    .bind(&value.runtime_path)
    .bind(value.created_at)
    .bind(value.updated_at)
    .bind(predicate)
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

async fn lock_sandbox(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<sqlx::postgres::PgRow, StoreError> {
    sqlx::query("SELECT * FROM sandboxes WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)
}

/// Applies the shared compare-and-set transition to an already locked sandbox row.
async fn apply_state_transition(
    tx: &mut Transaction<'_, Postgres>,
    row: sqlx::postgres::PgRow,
    expected: SandboxState,
    next: SandboxState,
    runtime_path: Option<String>,
    reason: &str,
) -> Result<Sandbox, StoreError> {
    let mut value = sandbox_from_row(&row)?;
    if next == SandboxState::Quarantined && value.state != SandboxState::Quarantined {
        return Err(StoreError::Conflict(
            "use the atomic Guard quarantine operation".into(),
        ));
    }
    if value.state == next {
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
    .bind(value.tenant_id)
    .bind(value.id)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    insert_sandbox_event(
        tx,
        value.tenant_id,
        value.id,
        Some(value.state),
        next,
        Some(reason),
    )
    .await?;
    value.state = next;
    value.updated_at = updated_at;
    if let Some(path) = runtime_path {
        value.runtime_path = Some(path);
    }
    Ok(value)
}

/// The active, unexpired lease that currently owns a sandbox, if any.
struct ActiveLease {
    id: Uuid,
    generation: i64,
}

/// Reads the sandbox's active, unexpired lease.
///
/// Expired leases are excluded deliberately. A lease past `expires_at` has already lost
/// the sandbox to recovery, so treating it as an owner would let the previous worker
/// commit state while its replacement is being placed.
async fn active_lease(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    sandbox: Uuid,
) -> Result<Option<ActiveLease>, StoreError> {
    let row = sqlx::query(
        "SELECT id, generation FROM sandbox_leases \
         WHERE tenant_id=$1 AND sandbox_id=$2 AND status='active' AND expires_at > now() \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant)
    .bind(sandbox)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    row.map(|row| {
        Ok(ActiveLease {
            id: row.try_get("id")?,
            generation: row.try_get("generation")?,
        })
    })
    .transpose()
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
    let row = lock_sandbox(&mut tx, tenant, id).await?;
    let value = apply_state_transition(&mut tx, row, expected, next, runtime_path, reason).await?;
    tx.commit().await.map_err(database_error)?;
    Ok(value)
}

/// Compare-and-set transition fenced by the sandbox's lease identity.
///
/// The sandbox row lock and the lease read share one transaction, so a reassignment
/// committed by another transaction is always observed here. The lease *id* is the
/// fence; the generation only orders writes on that one lease. `renew_worker_lease`
/// and assignment claims both increment the generation of the lease they extend, so a
/// caller that read ownership just before such a commit holds a lease that is still
/// its own at an older generation. Comparing generations for equality refused that
/// caller on a sandbox nobody had taken from it, which is the failure this fixes;
/// a newer generation from a *different* lease is still refused, because the ids
/// differ, and a generation ahead of the lease it names is refused because no such
/// state of that lease was ever issued.
///
/// Every refusal is logged with the supplied and current lease identity and
/// generation, so a refusal here is attributable to the store rather than being
/// indistinguishable from the worker's own fence.
async fn update_state_with_lease_transaction(
    pool: &sqlx::PgPool,
    tenant: Uuid,
    id: Uuid,
    expected: SandboxState,
    next: SandboxState,
    lease_id: Uuid,
    generation: i64,
) -> Result<(), StoreError> {
    let mut tx = pool.begin().await.map_err(database_error)?;
    // Lease before sandbox, matching reassignment and capacity release. Hold
    // the supplied identity stable through the state CAS.
    sqlx::query(
        "SELECT id FROM sandbox_leases WHERE tenant_id=$1 AND sandbox_id=$2 AND id=$3 FOR UPDATE",
    )
    .bind(tenant)
    .bind(id)
    .bind(lease_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;
    let row = lock_sandbox(&mut tx, tenant, id).await?;
    let current = active_lease(&mut tx, tenant, id).await?;
    match &current {
        None => {
            tracing::warn!(
                sandbox_id = %id,
                %lease_id,
                supplied_generation = generation,
                "fenced state change refused: the sandbox has no active unexpired lease"
            );
            return Err(StoreError::Transient(
                "sandbox has no active unexpired lease".into(),
            ));
        }
        Some(current) if current.id != lease_id => {
            tracing::warn!(
                sandbox_id = %id,
                %lease_id,
                supplied_generation = generation,
                current_lease_id = %current.id,
                current_generation = current.generation,
                "fenced state change refused: this sandbox was reassigned to another lease"
            );
            return Err(StoreError::Transient(
                "sandbox lease was reassigned to another owner".into(),
            ));
        }
        // Same lease, but the caller claims a generation this lease never reached.
        // Accepting it would let a caller act on a state the store cannot vouch for.
        Some(current) if current.generation < generation => {
            tracing::warn!(
                sandbox_id = %id,
                %lease_id,
                supplied_generation = generation,
                current_generation = current.generation,
                "fenced state change refused: the supplied generation is ahead of its own lease"
            );
            return Err(StoreError::Conflict(
                "sandbox lease generation is ahead of its lease".into(),
            ));
        }
        Some(current) if current.generation > generation => tracing::debug!(
            sandbox_id = %id,
            %lease_id,
            supplied_generation = generation,
            current_generation = current.generation,
            "the lease was renewed between the ownership read and this change; same lease, accepting"
        ),
        Some(_) => {}
    }
    apply_state_transition(
        &mut tx,
        row,
        expected,
        next,
        None,
        "sandbox state changed by lease owner",
    )
    .await?;
    tx.commit().await.map_err(database_error)?;
    Ok(())
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
        "environment": value.environment,
    });
    Ok(Sha256::digest(serde_json::to_vec(&semantic)?).to_vec())
}

fn schedule_fingerprint(
    value: &Sandbox,
    preferred_node: Option<Uuid>,
    lease_ttl_seconds: u64,
    required: &aiec_core::runtime::RuntimeCapabilities,
    run_id: Option<Uuid>,
) -> Result<Vec<u8>, StoreError> {
    let semantic = json!({
        "sandbox": sandbox_fingerprint(value)?,
        "preferred_node": preferred_node,
        "lease_ttl_seconds": lease_ttl_seconds,
        "required_capabilities": required,
        "run_id": run_id,
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

/// CPU, memory and disk bytes a placement debits from a worker.
fn sandbox_capacity_demand(sandbox: &Sandbox) -> Result<(i32, i64, i64), StoreError> {
    let memory_bytes = u64::from(sandbox.memory_mb)
        .checked_mul(1_048_576)
        .ok_or_else(|| StoreError::Conflict("sandbox memory size overflow".into()))?;
    let disk_bytes = u64::from(sandbox.disk_mb)
        .checked_mul(1_048_576)
        .ok_or_else(|| StoreError::Conflict("sandbox disk size overflow".into()))?;
    Ok((
        i32::try_from(sandbox.cpu).map_err(|error| StoreError::Conflict(error.to_string()))?,
        i64::try_from(memory_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?,
        i64::try_from(disk_bytes).map_err(|error| StoreError::Conflict(error.to_string()))?,
    ))
}

/// How long a placement waits for a sibling's host lock before it gives up on
/// that host. The wait is bounded because the lock holder is another request,
/// and the refusal that follows stays fail-closed: the host is excluded, the
/// remaining ones are still tried, and nothing is placed without headroom.
const HOST_LOCK_ATTEMPTS: u32 = 40;
const HOST_LOCK_BACKOFF: std::time::Duration = std::time::Duration::from_millis(5);

/// Picks the worker a placement runs on, locking the chosen row for the transaction.
///
/// Scheduling and lease recovery share this so recovery cannot drift from the scheduler
/// in health, runtime, capability or capacity requirements. `accepting_sandboxes` is part
/// of that set: a draining worker is healthy and still heartbeating, but it is being
/// emptied on purpose, so it must not be handed a sandbox that has not been placed yet.
/// Nothing here disturbs what the worker already holds.
async fn select_schedulable_node(
    tx: &mut Transaction<'_, Postgres>,
    sandbox: &Sandbox,
    preferred_node: Option<Uuid>,
) -> Result<Option<sqlx::postgres::PgRow>, StoreError> {
    let (vcpus, memory_bytes, disk_bytes) = sandbox_capacity_demand(sandbox)?;
    let mut excluded_hosts: Vec<String> = Vec::new();
    // Try-locks avoid both cross-host deadlocks and a busy host stalling others.
    for _ in 0..8 {
        let candidate = sqlx::query(
            "SELECT * FROM nodes n \
             WHERE n.healthy = true \
               AND n.last_heartbeat >= now() - ($1 * interval '1 second') \
               AND n.accepting_sandboxes = true \
               AND n.available_vcpus >= $2 \
               AND n.available_memory_bytes >= $3 \
               AND n.available_disk_bytes >= $4 AND n.runtime = $5 \
               AND n.capabilities @> (SELECT required_capabilities FROM sandboxes WHERE id=$6) \
               AND ($7::uuid IS NULL OR n.id = $7) \
               AND NOT (n.metadata #>> '{pressure,host_id}' = ANY($8::text[])) \
               AND aiec_host_has_headroom(n.metadata #>> '{pressure,host_id}', $2, $3, $4, $1) \
             ORDER BY \
               (1.0 / GREATEST(n.available_vcpus, 1)) + \
               (1.0 / GREATEST(n.available_memory_bytes::numeric / 1073741824, 0.25)) + \
               (n.sandbox_count::numeric * 0.0001), n.last_heartbeat DESC \
             LIMIT 1 FOR UPDATE OF n SKIP LOCKED",
        )
        .bind(NODE_HEARTBEAT_TTL_SECONDS)
        .bind(vcpus)
        .bind(memory_bytes)
        .bind(disk_bytes)
        .bind(sandbox.runtime.as_str())
        .bind(sandbox.id)
        .bind(preferred_node)
        .bind(&excluded_hosts)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?;
        let Some(candidate) = candidate else {
            return Ok(None);
        };
        let metadata: Value = candidate.try_get("metadata")?;
        let host = metadata["pressure"]["host_id"]
            .as_str()
            .ok_or_else(|| StoreError::Conflict("worker host identity is missing".into()))?;
        // Losing the race for this host's headroom lock is not evidence that the
        // host is full: whoever holds it is another placement, mid-flight, and
        // it commits in the time it takes to write a few rows. Treating that
        // collision as a full host refuses a placement against a host with
        // room in it, and reports it with the same `no schedulable worker has
        // capacity` a genuinely full host produces. Wait for the lock instead,
        // bounded, and keep the exclusion for when the wait is exhausted.
        let mut locked = false;
        for attempt in 0..HOST_LOCK_ATTEMPTS {
            locked = sqlx::query_scalar(
                "SELECT pg_try_advisory_xact_lock(hashtextextended('host:' || $1::text, 0))",
            )
            .bind(host)
            .fetch_one(&mut **tx)
            .await
            .map_err(database_error)?;
            if locked {
                break;
            }
            if attempt + 1 < HOST_LOCK_ATTEMPTS {
                tokio::time::sleep(HOST_LOCK_BACKOFF).await;
            }
        }
        if locked {
            // A new statement after the lock sees any reservation committed
            // since candidate selection, including debits on sibling workers.
            let fits: bool = sqlx::query_scalar("SELECT aiec_host_has_headroom($1,$2,$3,$4,$5)")
                .bind(host)
                .bind(vcpus)
                .bind(memory_bytes)
                .bind(disk_bytes)
                .bind(NODE_HEARTBEAT_TTL_SECONDS)
                .fetch_one(&mut **tx)
                .await
                .map_err(database_error)?;
            if fits {
                return Ok(Some(candidate));
            }
        }
        excluded_hosts.push(host.to_owned());
    }
    Ok(None)
}

/// Debits a placement from a worker's advertised capacity.
async fn debit_capacity(
    tx: &mut Transaction<'_, Postgres>,
    node_id: Uuid,
    demand: (i32, i64, i64),
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE nodes SET available_vcpus = available_vcpus - $1, \
           available_memory_bytes = available_memory_bytes - $2, \
           available_disk_bytes = available_disk_bytes - $3, sandbox_count = sandbox_count + 1 \
         WHERE id = $4",
    )
    .bind(demand.0)
    .bind(demand.1)
    .bind(demand.2)
    .bind(node_id)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    Ok(())
}

/// Points a sandbox's durable assignment at a replacement lease so the new worker claims it.
async fn retarget_assignment(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    sandbox: Uuid,
    expired_lease: Uuid,
    node_id: Uuid,
    replacement_lease: Uuid,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let retargeted = sqlx::query(
        "UPDATE sandbox_assignments SET node_id=$3, lease_id=$4, status='reserved', \
         updated_at=$5 WHERE tenant_id=$1 AND lease_id=$2",
    )
    .bind(tenant)
    .bind(expired_lease)
    .bind(node_id)
    .bind(replacement_lease)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    if retargeted.rows_affected() > 0 {
        return Ok(());
    }
    // The expired lease never had an assignment row; rebuild it from the scheduling request.
    let request_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT request_id FROM sandbox_requests WHERE tenant_id=$1 AND sandbox_id=$2",
    )
    .bind(tenant)
    .bind(sandbox)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    let Some(request_id) = request_id else {
        return Err(StoreError::Conflict(
            "reassigned sandbox has no scheduling request".into(),
        ));
    };
    sqlx::query(
        "INSERT INTO sandbox_assignments \
         (tenant_id, request_id, sandbox_id, node_id, lease_id, status, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,'reserved',$6,$6) \
         ON CONFLICT (tenant_id, request_id) DO UPDATE SET node_id=EXCLUDED.node_id, \
         lease_id=EXCLUDED.lease_id, status='reserved', updated_at=EXCLUDED.updated_at",
    )
    .bind(tenant)
    .bind(request_id)
    .bind(sandbox)
    .bind(node_id)
    .bind(replacement_lease)
    .bind(now)
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
        request: ScheduleRequest,
    ) -> Result<aiec_core::scheduler::ProvisionAdmission, StoreError> {
        let ScheduleRequest {
            tenant_id: tenant,
            request_id,
            mut sandbox,
            lease_ttl,
            preferred_worker: preferred_node,
            mut required_capabilities,
            run_id,
        } = request;
        let lease_ttl_seconds = lease_ttl.as_secs();
        required_capabilities.exec = true;
        required_capabilities.files = true;
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
        if let Some(run_id) = run_id {
            let state: String = sqlx::query_scalar(
                "SELECT state FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            )
            .bind(tenant)
            .bind(run_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
            if !run_state_from_str(&state)?.is_active() {
                return Err(StoreError::Conflict("run is no longer active".into()));
            }
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("tenant-quota:{tenant}"))
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
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
                != schedule_fingerprint(
                    &sandbox,
                    preferred_node,
                    lease_ttl_seconds,
                    &required_capabilities,
                    run_id,
                )?
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
            let existing_lease = fetch_lease_for_sandbox(&mut tx, tenant, sandbox_id).await?;
            let sandbox_row = lock_sandbox(&mut tx, tenant, sandbox_id).await?;
            let mut existing_sandbox = sandbox_from_row(&sandbox_row)?;
            if matches!(
                existing_sandbox.state,
                SandboxState::Destroying | SandboxState::Destroyed | SandboxState::Quarantined
            ) {
                return Err(StoreError::Conflict(
                    "sandbox is not available for provisioning admission".into(),
                ));
            }
            // Reuse only a lease that is still an owner. `expires_at` is part of
            // the predicate for the same reason `dispatch_target` includes it:
            // an expired-but-still-`active` row is not an owner, and handing
            // back its endpoint dispatches the sandbox to a machine recovery is
            // already reclaiming. The second term alone would let any assigned
            // sandbox through, which is every expired lease.
            let lease_is_live =
                existing_lease.status == "active" && existing_lease.expires_at > Utc::now();
            if lease_is_live {
                let worker_endpoint: String =
                    sqlx::query_scalar("SELECT control_endpoint FROM nodes WHERE id = $1")
                        .bind(existing_lease.node_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(database_error)?;
                tx.commit().await.map_err(database_error)?;
                return Ok(aiec_core::scheduler::ProvisionAdmission {
                    scheduled: ScheduledSandbox {
                        sandbox: existing_sandbox,
                        worker_id: existing_lease.node_id,
                        worker_endpoint,
                        lease_id: existing_lease.id,
                        lease_generation: existing_lease.generation,
                    },
                    acquired: false,
                });
            }
            if existing_lease.status == "active" {
                // An expired lease that recovery has not collected yet still
                // holds its worker's capacity debited. Settle it the way
                // `reassign_expired_lease` settles one it finds still `active`,
                // so the retry below places the sandbox on capacity that is
                // actually free instead of tripping "already assigned". The
                // debit rides on the lease, not on the sandbox's assignment, so
                // it is released even if the assignment is already gone.
                release_capacity(
                    &mut tx,
                    &existing_lease,
                    "expired",
                    "lease_expired_reschedule",
                )
                .await?;
                sqlx::query(
                    "UPDATE sandboxes SET node_id=NULL, updated_at=now() \
                     WHERE tenant_id=$1 AND id=$2 AND node_id=$3",
                )
                .bind(tenant)
                .bind(existing_sandbox.id)
                .bind(existing_lease.node_id)
                .execute(&mut *tx)
                .await
                .map_err(database_error)?;
                existing_sandbox.node_id = None;
            }
            sandbox = existing_sandbox;
            retry_assignment = true;
            lease_generation = existing_lease
                .generation
                .checked_add(1)
                .ok_or_else(|| StoreError::Conflict("lease generation overflow".into()))?;
        } else {
            let quota = sqlx::query(
                "SELECT max_active_sandboxes, max_vcpus, max_memory_mb, max_disk_mb \
                 FROM tenant_quotas WHERE tenant_id=$1 FOR UPDATE",
            )
            .bind(tenant)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
            let usage = sqlx::query(
                "SELECT count(*)::bigint AS active, COALESCE(sum(cpu),0)::bigint AS vcpus, \
                 COALESCE(sum(memory_mb),0)::bigint AS memory_mb, COALESCE(sum(disk_mb),0)::bigint AS disk_mb \
                 FROM sandboxes WHERE tenant_id=$1 AND state NOT IN ('destroyed','failed')",
            )
            .bind(tenant)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
            let current = aiec_core::QuotaUsage {
                active_sandboxes: u32::try_from(usage.try_get::<i64, _>("active")?)
                    .map_err(|_| StoreError::QuotaExceeded("invalid active usage".into()))?,
                vcpus: u32::try_from(usage.try_get::<i64, _>("vcpus")?)
                    .map_err(|_| StoreError::QuotaExceeded("invalid vCPU usage".into()))?,
                memory_mb: u64::try_from(usage.try_get::<i64, _>("memory_mb")?)
                    .map_err(|_| StoreError::QuotaExceeded("invalid memory usage".into()))?,
                disk_mb: u64::try_from(usage.try_get::<i64, _>("disk_mb")?)
                    .map_err(|_| StoreError::QuotaExceeded("invalid disk usage".into()))?,
            };
            let next = current
                .checked_add(&sandbox)
                .ok_or_else(|| StoreError::QuotaExceeded("quota usage overflow".into()))?;
            let limits = aiec_core::QuotaLimits {
                max_active_sandboxes: u32::try_from(
                    quota.try_get::<i32, _>("max_active_sandboxes")?,
                )
                .map_err(|_| StoreError::QuotaExceeded("invalid active quota".into()))?,
                max_vcpus: u32::try_from(quota.try_get::<i32, _>("max_vcpus")?)
                    .map_err(|_| StoreError::QuotaExceeded("invalid vCPU quota".into()))?,
                max_memory_mb: u64::try_from(quota.try_get::<i64, _>("max_memory_mb")?)
                    .map_err(|_| StoreError::QuotaExceeded("invalid memory quota".into()))?,
                max_disk_mb: u64::try_from(quota.try_get::<i64, _>("max_disk_mb")?)
                    .map_err(|_| StoreError::QuotaExceeded("invalid disk quota".into()))?,
            };
            if next.exceeds(limits) {
                return Err(StoreError::QuotaExceeded(
                    "tenant resource quota exceeded".into(),
                ));
            }
            insert_sandbox(&mut tx, &sandbox, Some(&required_capabilities)).await?;
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
                &required_capabilities,
                run_id,
            )?)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        }

        let demand = sandbox_capacity_demand(&sandbox)?;
        let node = select_schedulable_node(&mut tx, &sandbox, preferred_node)
            .await?
            // Every healthy, capacity-bearing worker can also be draining, so the old
            // "no healthy worker" wording sent operators looking for an outage.
            .ok_or_else(|| StoreError::Transient("no schedulable worker has capacity".into()))?;
        let worker_endpoint: String = node.try_get("control_endpoint")?;
        let node_id: Uuid = node.try_get("id")?;
        debit_capacity(&mut tx, node_id, demand).await?;
        let assigned = sqlx::query(
            "UPDATE sandboxes SET node_id = $1, \
             state=CASE WHEN $4 THEN 'creating' ELSE state END, \
             runtime_path=CASE WHEN $4 THEN NULL ELSE runtime_path END, updated_at = now() \
             WHERE tenant_id = $2 AND id = $3 AND node_id IS NULL",
        )
        .bind(node_id)
        .bind(tenant)
        .bind(sandbox.id)
        .bind(retry_assignment)
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
        if let Some(run_id) = run_id {
            link_attempt_sandbox(&mut tx, run_id, request_id, sandbox.id).await?;
        }
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
        Ok(aiec_core::scheduler::ProvisionAdmission {
            scheduled: ScheduledSandbox {
                sandbox: assigned_sandbox,
                worker_id: node_id,
                worker_endpoint,
                lease_id,
                lease_generation: lease.generation,
            },
            acquired: true,
        })
    }
}

#[async_trait]
impl Scheduler for PostgresScheduler {
    async fn schedule(&self, request: ScheduleRequest) -> Result<ScheduledSandbox, CoreError> {
        self.schedule_on_node(request)
            .await
            .map(|admission| admission.scheduled)
            .map_err(core_error)
    }

    async fn schedule_for_provision(
        &self,
        request: ScheduleRequest,
    ) -> Result<aiec_core::scheduler::ProvisionAdmission, CoreError> {
        self.schedule_on_node(request).await.map_err(core_error)
    }

    /// Resolves the dispatch authority for a sandbox in one snapshot.
    ///
    /// Endpoint and fencing identity are read from the same statement, so a caller
    /// cannot dispatch to a worker under a lease generation that belongs to a
    /// different one. `expires_at > now()` is part of the same predicate: an
    /// expired-but-still-`active` row is not an owner, and handing back its
    /// endpoint would dispatch work to a machine recovery is already reclaiming.
    async fn dispatch_target(
        &self,
        tenant_id: Uuid,
        sandbox_id: Uuid,
    ) -> Result<WorkerDispatch, CoreError> {
        let row = sqlx::query(
            "SELECT sandbox_leases.id AS lease_id, sandbox_leases.generation, \
             nodes.control_endpoint AS endpoint FROM sandbox_leases \
             JOIN nodes ON nodes.id = sandbox_leases.node_id \
             WHERE sandbox_leases.tenant_id = $1 AND sandbox_leases.sandbox_id = $2 \
             AND sandbox_leases.status = 'active' AND sandbox_leases.expires_at > now() \
             ORDER BY sandbox_leases.created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(sandbox_id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|error| core_error(database_error(error)))?
        .ok_or_else(|| CoreError::NotFound("active sandbox lease not found".into()))?;
        let endpoint = row
            .try_get("endpoint")
            .map_err(|error| core_error(error.into()))?;
        let lease_id = row
            .try_get("lease_id")
            .map_err(|error| core_error(error.into()))?;
        let generation = row
            .try_get("generation")
            .map_err(|error| core_error(error.into()))?;
        Ok(WorkerDispatch {
            endpoint,
            lease_id,
            generation,
        })
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
        self.repository
            .release_worker_lease(
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
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
    )
    .bind(tenant)
    .bind(sandbox)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?
    .ok_or(StoreError::NotFound)?;
    lease_from_row(&row)
}

/// The snapshot listing, as the database sees it.
///
/// Hoisted so the query plan can be asserted against the statement that
/// actually runs. A test carrying its own copy of this SQL proves that the copy
/// has a `LIMIT` in it, which is not the question: deleting the `LIMIT` from
/// the store leaves the copy untouched and the plan assertion still passes,
/// while the database goes on materialising every snapshot the sandbox ever
/// had. The paging tests cannot catch it either - the rows are trimmed in Rust
/// after the fetch.
pub(crate) const LIST_SNAPSHOTS_SQL: &str = "\
     SELECT * FROM snapshots WHERE tenant_id = $1 AND sandbox_id = $2 \
     AND ($3::timestamptz IS NULL OR (created_at, id) < ($3, $4)) \
     ORDER BY created_at DESC, id DESC LIMIT $5";

/// Re-exported for the same reason as [`LIST_SNAPSHOTS_SQL`]: the plan
/// assertion has to run against the statement that actually executes.
#[cfg(test)]
pub(crate) use guard::EXPIRED_GUARD_BUDGETS_SQL;

impl PostgresRepository {
    /// Creates a run, or returns the run this idempotency key already produced.
    async fn set_run_failure(
        &self,
        tenant: Uuid,
        id: Uuid,
        failure_reason: Option<String>,
        state: RunState,
    ) -> Result<Run, StoreError> {
        // Guarded against overwriting a state that is already final.
        //
        // Every other write in this file holds the run to its lifecycle, and
        // this one did not - so a run that reached `cancelled` or `succeeded`
        // was silently rewritten to `failed` afterwards. That is not a
        // theoretical race: cancelling a run destroys its machine, the
        // in-flight execution then fails against a machine that is gone, and
        // this statement is what turns the caller's "cancelled" into "failed".
        // The executor cannot be reached to stop, because the run *is* the
        // request.
        //
        // The reason is still recorded on a losing write, so the history of what
        // happened is not lost - only the terminal verdict is protected.
        let updated = sqlx::query(
            "UPDATE runs SET failure_reason = $1, \
               state = CASE WHEN state IN ('succeeded', 'cancelled') \
                 THEN state ELSE $2 END, \
               completed_at = COALESCE(completed_at, now()) \
             WHERE tenant_id = $3 AND id = $4 RETURNING *",
        )
        .bind(failure_reason.as_deref())
        .bind(state.as_str())
        .bind(tenant)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
        run_from_row(&updated)
    }

    /// Writes results, failure reason and terminal state in one statement.
    ///
    /// The terminal guard is the same one `set_run_failure` applies, and for
    /// the same reason: cancelling a run destroys its machine, the in-flight
    /// execution then fails against a machine that is gone, and this statement
    /// decides whether the caller keeps `cancelled` or is overwritten with
    /// `failed`. Results and the reason are still recorded on that losing
    /// write, so what happened is preserved even when the verdict is not
    /// changed - only the terminal outcome is protected.
    ///
    /// `completed_at` is written only when the resulting state is terminal, so
    /// this cannot stamp a run as finished on the one path where the guard
    /// above deliberately declines to settle it.
    async fn record_run_failure(
        &self,
        tenant: Uuid,
        id: Uuid,
        results: RunResults,
        reason: Option<String>,
    ) -> Result<Run, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        // Locks the row and answers `NotFound` for a run that does not exist;
        // the update below reads its own `state` under that same lock, so the
        // terminal guard cannot be decided twice concurrently.
        let _row = sqlx::query("SELECT * FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
        let updated = sqlx::query(
            "UPDATE runs SET \
               results = CASE WHEN state = 'failed' THEN results ELSE $1 END, \
               failure_reason = CASE WHEN state = 'failed' THEN failure_reason ELSE $2 END, \
               state = CASE WHEN state IN ('succeeded','cancelled') THEN state ELSE 'failed' END, \
               completed_at = CASE WHEN state IN ('succeeded','cancelled') \
                 THEN completed_at ELSE COALESCE(completed_at, now()) END \
             WHERE tenant_id = $3 AND id = $4 RETURNING *",
        )
        .bind(serde_json::to_value(&results)?)
        .bind(reason.as_deref())
        .bind(tenant)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
        let value = run_from_row(&updated)?;
        tx.commit().await.map_err(database_error)?;
        Ok(value)
    }

    async fn set_run_placement(
        &self,
        tenant: Uuid,
        id: Uuid,
        placement: Placement,
    ) -> Result<Run, StoreError> {
        let updated = sqlx::query(
            "UPDATE runs SET placement = $1 WHERE tenant_id = $2 AND id = $3 RETURNING *",
        )
        .bind(serde_json::to_value(&placement).map_err(StoreError::Json)?)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
        run_from_row(&updated)
    }
    async fn create_sandbox(&self, value: Sandbox) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        insert_sandbox(&mut tx, &value, None).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn create_attempt_sandbox(
        &self,
        run_id: Uuid,
        attempt_id: Uuid,
        sandbox: Sandbox,
        required: RuntimeCapabilities,
    ) -> Result<Sandbox, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let state: String =
            sqlx::query_scalar("SELECT state FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(sandbox.tenant_id)
                .bind(run_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(database_error)?
                .ok_or(StoreError::NotFound)?;
        if !run_state_from_str(&state)?.is_active() {
            return Err(StoreError::Conflict("run is no longer active".into()));
        }
        insert_sandbox(&mut tx, &sandbox, Some(&required)).await?;
        link_attempt_sandbox(&mut tx, run_id, attempt_id, sandbox.id).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(sandbox)
    }

    async fn get_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<Sandbox, StoreError> {
        fetch_sandbox(&self.pool, tenant, id).await
    }

    async fn list_sandboxes(
        &self,
        tenant: Uuid,
        limit: u32,
        after: Option<aiec_core::storage::PageCursor>,
    ) -> Result<aiec_core::storage::SandboxPage, StoreError> {
        let limit = limit.clamp(1, aiec_core::storage::MAX_SANDBOX_PAGE);
        let (at, before) = match after {
            Some(cursor) => (Some(cursor.created_at), Some(cursor.id)),
            None => (None, None),
        };
        // The bound and the cursor are both in the query. Sandbox rows are
        // never deleted, so a tenant's list is their whole history and reading
        // it to serve a bounded page would make the page size a fiction.
        // `(created_at, id) < ...` is the row-value form of the keyset, and it
        // is compared against the ordering the page is actually returned in, so
        // the two cannot disagree at a tie.
        let rows = sqlx::query(
            "SELECT * FROM sandboxes \
             WHERE tenant_id = $1 \
               AND ($2::timestamptz IS NULL OR (created_at, id) < ($2::timestamptz, $3::uuid)) \
             ORDER BY created_at DESC, id DESC LIMIT $4",
        )
        .bind(tenant)
        .bind(at)
        .bind(before)
        .bind(i64::from(limit) + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;

        let mut sandboxes = Vec::with_capacity(rows.len().min(limit as usize));
        for row in rows.iter().take(limit as usize) {
            sandboxes.push(sandbox_from_row(row)?);
        }
        // The cursor names the last sandbox this page returned, not the row
        // held back to prove another page exists: pointing at that row would
        // skip it, and a caller paging to the end would never be shown it.
        let next = match (rows.len() > limit as usize, sandboxes.last()) {
            (true, Some(last)) => Some(aiec_core::storage::PageCursor {
                created_at: last.created_at,
                id: last.id,
            }),
            _ => None,
        };
        Ok(aiec_core::storage::SandboxPage { sandboxes, next })
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
        // The lease is locked before the sandbox, and the order is not
        // incidental. Every path that releases capacity - the reconciler, a
        // worker handing a lease back, recovery - takes the lease row first and
        // then the sandbox row. Locking the sandbox first here made this the
        // other half of a textbook ABBA deadlock: one transaction holding the
        // sandbox and waiting for the lease, the other holding the lease and
        // waiting for the sandbox. It surfaced as a 40P01 that aborted whichever
        // side lost, which on the reconciler meant a whole batch of expiries
        // deferred, and on a destroy meant the machine was never released.
        let lease_row = sqlx::query(
            "SELECT * FROM sandbox_leases WHERE tenant_id=$1 AND sandbox_id=$2 \
             AND status IN ('active', 'completed') ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        let row =
            sqlx::query("SELECT * FROM sandboxes WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
                .bind(tenant)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(database_error)?
                .ok_or(StoreError::NotFound)?;
        let sandbox = sandbox_from_row(&row)?;
        if sandbox.state == SandboxState::Quarantined {
            return Err(StoreError::Conflict(
                "quarantined sandbox requires explicit human release".into(),
            ));
        }
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

    /// Reads an API key row, including its name and last-used stamp.
    fn api_key_from_row(row: &sqlx::postgres::PgRow) -> Result<ApiKeyRecord, StoreError> {
        let scopes: serde_json::Value = row.try_get("scopes")?;
        Ok(ApiKeyRecord {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            digest: {
                let raw: Vec<u8> = row.try_get("digest")?;
                let mut out = [0u8; 32];
                out.copy_from_slice(&raw);
                out
            },
            scopes: scopes_from_value(scopes)?,
            expires_at: row.try_get("expires_at")?,
            revoked_at: row.try_get("revoked_at")?,
            name: row
                .try_get::<Option<String>, _>("name")?
                .unwrap_or_default(),
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
        })
    }

    async fn put_key(&self, value: ApiKeyRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO api_keys \
             (id, tenant_id, digest, scopes, expires_at, revoked_at, name, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(value.id)
        .bind(value.tenant_id)
        .bind(value.digest.as_slice())
        .bind(scope_values(&value.scopes)?)
        .bind(value.expires_at)
        .bind(value.revoked_at)
        .bind(&value.name)
        .bind(value.created_at)
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

    /// Lists a tenant's API keys, newest first.
    async fn list_keys(&self, tenant: Uuid) -> Result<Vec<ApiKeyRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(Self::api_key_from_row).collect()
    }

    async fn get_key(&self, tenant: Uuid, id: Uuid) -> Result<Option<ApiKeyRecord>, StoreError> {
        // One row by primary key, scoped by tenant. The revocation path needs
        // to know what a key holds before it destroys it, and reading the
        // tenant's whole key list to find out would make every revocation cost
        // as much as the largest key set that tenant has ever had.
        let row = sqlx::query("SELECT * FROM api_keys WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?;
        row.map(|row| Self::api_key_from_row(&row)).transpose()
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
            name: row
                .try_get::<Option<String>, _>("name")?
                .unwrap_or_default(),
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
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
        limit: u32,
        after: Option<aiec_core::storage::PageCursor>,
    ) -> Result<aiec_core::storage::SnapshotPage, StoreError> {
        let limit = limit.clamp(1, aiec_core::storage::MAX_SNAPSHOT_PAGE);
        let (after_created_at, after_id) = after
            .map(|cursor| (Some(cursor.created_at), Some(cursor.id)))
            .unwrap_or((None, None));
        let rows = sqlx::query(LIST_SNAPSHOTS_SQL)
            .bind(tenant)
            .bind(sandbox)
            .bind(after_created_at)
            .bind(after_id)
            .bind(i64::from(limit) + 1)
            .fetch_all(&self.pool)
            .await
            .map_err(database_error)?;
        let mut snapshots: Vec<Snapshot> = rows
            .iter()
            .map(snapshot_from_row)
            .collect::<Result<_, _>>()?;
        // The extra row exists only to prove another page follows, so the
        // cursor names the last row *returned*: paging from the held-back row
        // would skip exactly one snapshot per page.
        let next = if snapshots.len() > limit as usize {
            let last = &snapshots[limit as usize - 1];
            Some(aiec_core::storage::PageCursor {
                created_at: last.created_at,
                id: last.id,
            })
        } else {
            None
        };
        snapshots.truncate(limit as usize);
        Ok(aiec_core::storage::SnapshotPage { snapshots, next })
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

    async fn register_node(&self, value: Node) -> Result<Uuid, StoreError> {
        self.register_worker(WorkerRegistration {
            node_id: value.id,
            name: value.name,
            runtime: RuntimeKind::BwrapDev,
            capabilities: aiec_core::runtime::RuntimeCapabilities::default(),
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

    async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(database_error)?;
        Ok(())
    }

    async fn node_capacity_totals(&self) -> Result<aiec_core::NodeCapacity, StoreError> {
        // Same predicate as `list_nodes`: healthy and inside the heartbeat
        // TTL. Aggregating without it would report capacity the fleet has
        // already given up, which is a different number than the one /metrics
        // has always reported.
        let row = sqlx::query(
            // Both sums are cast back to bigint: Postgres widens sum(int4) to
            // int8 but sum(int8) to numeric, and the caller wants a byte count,
            // not an arbitrary-precision decimal.
            "SELECT COALESCE(SUM(available_vcpus), 0)::bigint AS vcpus, \
             COALESCE(SUM(available_memory_bytes), 0)::bigint AS memory \
             FROM nodes WHERE healthy = true \
             AND last_heartbeat >= now() - ($1 * interval '1 second')",
        )
        .bind(NODE_HEARTBEAT_TTL_SECONDS)
        .fetch_one(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(aiec_core::NodeCapacity {
            // `sum(integer)` widens to bigint in Postgres, so this is an
            // int8 even though the column it sums is an int4.
            available_vcpus: row.try_get::<i64, _>("vcpus")?.max(0) as u32,
            available_memory_bytes: row.try_get::<i64, _>("memory")?.max(0) as u64,
        })
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
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        sqlx::query(
            "INSERT INTO tenants (id, name, created_at) VALUES ($1,$2,$3) \
             ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name",
        )
        .bind(value.id)
        .bind(&value.name)
        .bind(value.created_at)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        sqlx::query(
            "INSERT INTO tenant_quotas \
             (tenant_id, max_active_sandboxes, max_vcpus, max_memory_mb, max_disk_mb) \
             VALUES ($1, 8, 32, 65536, 1048576) ON CONFLICT (tenant_id) DO NOTHING",
        )
        .bind(value.id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
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

    /// Appends one audit event. There is deliberately no update or delete path:
    /// the table's triggers reject both, so a mistake has to be answered with a
    /// correcting event rather than an edit to the record of what happened.
    async fn append_audit_event(&self, value: AuditEvent) -> Result<(), StoreError> {
        if value.actor.trim().is_empty()
            || value.action.trim().is_empty()
            || value.subject_type.trim().is_empty()
        {
            return Err(StoreError::Conflict(
                "an audit event needs an actor, an action and a subject type".into(),
            ));
        }
        if !matches!(value.result.as_str(), "success" | "denied" | "failure") {
            return Err(StoreError::Conflict(
                "an audit event result must be success, denied or failure".into(),
            ));
        }
        if !value.detail.is_object() {
            return Err(StoreError::Conflict(
                "an audit event detail must be a JSON object".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO audit_log \
             (id, occurred_at, tenant_id, actor, action, subject_type, subject_id, result, \
              request_id, remote_addr, detail) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(value.id)
        .bind(value.occurred_at)
        .bind(value.tenant_id)
        .bind(value.actor)
        .bind(value.action)
        .bind(value.subject_type)
        .bind(&value.subject_id)
        .bind(&value.result)
        .bind(value.request_id)
        .bind(&value.remote_addr)
        .bind(&value.detail)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }

    /// Lists audit events newest first, optionally filtered by tenant and action.
    ///
    /// A `None` tenant matches system-level events too, which is how an operator
    /// reads the whole trail rather than one tenant's slice of it.
    async fn list_audit_events(
        &self,
        tenant: Option<Uuid>,
        action: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM audit_log \
             WHERE ($1::uuid IS NULL OR tenant_id = $1) \
               AND ($2::text IS NULL OR action = $2) \
             ORDER BY occurred_at DESC, id DESC LIMIT $3",
        )
        .bind(tenant)
        .bind(action)
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(audit_event_from_row).collect()
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
        // Completeness means "every object this kind promises is present". A
        // workspace snapshot carries no memory or disk object, so demanding them
        // made portable-workspace snapshots unstorable and blocked the recovery
        // path that restores them on a new owner.
        if value.complete {
            match value.kind.as_str() {
                "workspace" => {
                    if value.workspace_object_key.is_none() {
                        return Err(StoreError::Conflict(
                            "complete workspace snapshot requires a workspace object".into(),
                        ));
                    }
                }
                "virtual_machine" | "memory" => {
                    if value.memory_object_key.is_none()
                        || value.disk_object_key.is_none()
                        || value.workspace_object_key.is_none()
                    {
                        return Err(StoreError::Conflict(
                            "complete VM snapshot requires memory, disk, and workspace objects"
                                .into(),
                        ));
                    }
                }
                // An unrecognised kind cannot be validated against a known set of
                // objects, so it keeps the strictest requirement.
                _ => {
                    if value.memory_object_key.is_none()
                        || value.disk_object_key.is_none()
                        || value.workspace_object_key.is_none()
                    {
                        return Err(StoreError::Conflict(
                            "complete VM snapshot requires memory, disk, and workspace objects"
                                .into(),
                        ));
                    }
                }
            }
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

    async fn latest_stored_snapshot(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        kind: &str,
    ) -> Result<Option<StoredSnapshot>, StoreError> {
        // One row, newest first, chosen in the database. `complete` and the
        // checksum are both required because `stored_snapshot_from_row`
        // refuses a snapshot without one, and a partial capture that passed
        // here would fail the mapping rather than being skipped.
        let row = sqlx::query(
            "SELECT * FROM snapshots WHERE tenant_id=$1 AND sandbox_id=$2 \
             AND kind=$3 AND complete AND checksum_sha256 IS NOT NULL \
             ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(tenant)
        .bind(sandbox)
        .bind(kind)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?;
        row.as_ref().map(stored_snapshot_from_row).transpose()
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
        insert_sandbox(&mut tx, &sandbox, None).await?;
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

    async fn register_worker(&self, value: WorkerRegistration) -> Result<Uuid, StoreError> {
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
                .filter(|url| url.scheme() == "https" && url.host_str().is_some())
                .is_none()
        {
            return Err(StoreError::Conflict(
                "Firecracker worker requires an HTTPS control endpoint".into(),
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
        let capabilities = serde_json::to_value(&value.capabilities).map_err(StoreError::Json)?;
        // A re-registering worker restates its capacity, not its drain state. Adding
        // accepting_sandboxes to this upsert would silently put a deliberately
        // decommissioned worker back into the placement pool; clearing a drain is
        // `set_worker_draining`'s job alone.
        // A worker's name is unique. Re-registering after a restart must take
        // over the record that already holds the name: rejecting it wedges the
        // worker in a restart loop and strands the sandboxes it placed.
        let existing_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM nodes WHERE name = $1")
            .bind(&value.name)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?;
        let node_id = existing_id.unwrap_or(value.node_id);

        let result = sqlx::query(
            "INSERT INTO nodes \
             (id, name, runtime, capabilities, control_endpoint, total_vcpus, total_memory_bytes, \
              total_disk_bytes, available_vcpus, available_memory_bytes, available_disk_bytes, \
              sandbox_count, healthy, version, metadata, started_at, last_heartbeat) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,$12,$13,$14,$15,$16) \
             ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, runtime=EXCLUDED.runtime, \
             capabilities=EXCLUDED.capabilities, control_endpoint=EXCLUDED.control_endpoint, \
             total_vcpus=EXCLUDED.total_vcpus, total_memory_bytes=EXCLUDED.total_memory_bytes, \
             total_disk_bytes=EXCLUDED.total_disk_bytes, sandbox_count=nodes.sandbox_count, \
             available_vcpus=GREATEST(0, LEAST(EXCLUDED.total_vcpus, \
               EXCLUDED.total_vcpus - (nodes.total_vcpus - nodes.available_vcpus))), \
             available_memory_bytes=GREATEST(0, LEAST(EXCLUDED.total_memory_bytes, \
               EXCLUDED.total_memory_bytes - (nodes.total_memory_bytes - nodes.available_memory_bytes))), \
             available_disk_bytes=GREATEST(0, LEAST(EXCLUDED.total_disk_bytes, \
               EXCLUDED.total_disk_bytes - (nodes.total_disk_bytes - nodes.available_disk_bytes))), \
             healthy=EXCLUDED.healthy, version=EXCLUDED.version, metadata=EXCLUDED.metadata, \
             started_at=EXCLUDED.started_at, last_heartbeat=EXCLUDED.last_heartbeat \
             WHERE nodes.version < EXCLUDED.version",
        )
        .bind(node_id)
        .bind(&value.name)
        .bind(value.runtime.as_str())
        .bind(&capabilities)
        .bind(&value.control_endpoint)
        .bind(
            i32::try_from(value.total_vcpus)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(
            i64::try_from(value.total_memory_bytes)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(
            i64::try_from(value.total_disk_bytes)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(
            i32::try_from(value.available_vcpus)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(
            i64::try_from(value.available_memory_bytes)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(
            i64::try_from(value.available_disk_bytes)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(value.healthy)
        .bind(
            i64::try_from(value.version)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .bind(&value.metadata)
        .bind(value.started_at)
        .bind(value.last_heartbeat)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            // Look up the id this registration actually owns. On a re-registration
            // that is the id adopted from the name lookup above, not the fresh id
            // the caller proposed, so using `value.node_id` here reported NotFound
            // and turned every restart into a fatal error.
            let current = self.get_worker(node_id).await?;
            let same_registration = current.registration.name == value.name
                && current.registration.runtime == value.runtime
                && current.registration.capabilities == value.capabilities
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

        // Re-read the id in case another registration claimed the name between
        // the lookup and the write, so the caller always adopts the record that
        // actually exists.
        let authoritative: Uuid = sqlx::query_scalar("SELECT id FROM nodes WHERE name = $1")
            .bind(&value.name)
            .fetch_one(&self.pool)
            .await
            .map_err(database_error)?;
        Ok(authoritative)
    }

    async fn heartbeat_worker(
        &self,
        heartbeat: WorkerHeartbeat,
    ) -> Result<WorkerStatus, StoreError> {
        // Lock lease rows before the node, matching capacity release. Merely
        // counting under READ COMMITTED could observe an uncommitted revocation
        // as still active, then refresh the node after that revocation committed.
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        // A node whose leases have all been expired or released owns nothing, so
        // a heartbeat claiming to still be serving sandboxes reports ownership
        // the control plane has already taken back. Refuse it rather than record
        // it: a returning worker must re-register to become schedulable again.
        let owned: Vec<Uuid> = sqlx::query_scalar(
            // The expiry predicate matters: a lease that has lapsed on the clock
            // but has not been swept yet still reads as 'active', and that is
            // exactly the window in which a late heartbeat arrives.
            "SELECT id FROM sandbox_leases \
             WHERE node_id = $1 AND status = 'active' AND expires_at > now() \
             ORDER BY id FOR UPDATE",
        )
        .bind(heartbeat.node_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        if owned.is_empty() && heartbeat.healthy && heartbeat.sandbox_count > 0 {
            // Rolling back by dropping the transaction keeps the node row
            // exactly as it was: unhealthy is not what this worker is, and a
            // stale heartbeat is not what this worker sent.
            return Err(StoreError::Conflict(format!(
                "worker reports {} running sandboxes but holds no active lease",
                heartbeat.sandbox_count
            )));
        }
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
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            // A worker that never registered must not be reported as merely stale: the two
            // failures mean different things to the caller and to the operator.
            let current = match self.get_worker(heartbeat.node_id).await {
                Ok(current) => current,
                Err(StoreError::NotFound) => {
                    return Err(StoreError::Conflict("worker does not exist".into()));
                }
                Err(error) => return Err(error),
            };
            if current.registration.version > heartbeat.version {
                return Err(StoreError::Conflict(
                    "worker heartbeat version is stale".into(),
                ));
            }
            return Err(StoreError::Conflict(
                "worker heartbeat lost a concurrent update race".into(),
            ));
        }
        tx.commit().await.map_err(database_error)?;
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

    /// The tenant's quota policy and its current aggregate usage.
    ///
    /// The same two queries `schedule` runs under its transaction lock, read
    /// here without one: this exists so a caller sizing a batch has the
    /// scheduler's own numbers in front of it, and taking the lock would only
    /// make concurrent batch sizing queue up behind each other. It decides
    /// nothing - every cell still passes through `schedule`, which re-reads
    /// these rows and refuses anything that does not fit.
    async fn tenant_quota_usage(
        &self,
        tenant: Uuid,
    ) -> Result<(aiec_core::QuotaLimits, aiec_core::QuotaUsage), StoreError> {
        let limits = sqlx::query(
            "SELECT max_active_sandboxes::bigint AS max_active_sandboxes, \
             max_vcpus::bigint AS max_vcpus, max_memory_mb, max_disk_mb \
             FROM tenant_quotas WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or_else(|| StoreError::Conflict(format!("tenant {tenant} has no configured quota")))?;
        let usage = sqlx::query(
            "SELECT count(*)::bigint AS active, COALESCE(sum(cpu),0)::bigint AS vcpus, \
             COALESCE(sum(memory_mb),0)::bigint AS memory_mb, \
             COALESCE(sum(disk_mb),0)::bigint AS disk_mb \
             FROM sandboxes WHERE tenant_id = $1 AND state NOT IN ('destroyed','failed')",
        )
        .bind(tenant)
        .fetch_one(&self.pool)
        .await
        .map_err(database_error)?;
        Ok((
            aiec_core::QuotaLimits {
                max_active_sandboxes: quota_count(&limits, "max_active_sandboxes")?,
                max_vcpus: quota_count(&limits, "max_vcpus")?,
                max_memory_mb: quota_amount(&limits, "max_memory_mb")?,
                max_disk_mb: quota_amount(&limits, "max_disk_mb")?,
            },
            aiec_core::QuotaUsage {
                active_sandboxes: quota_count(&usage, "active")?,
                vcpus: quota_count(&usage, "vcpus")?,
                memory_mb: quota_amount(&usage, "memory_mb")?,
                disk_mb: quota_amount(&usage, "disk_mb")?,
            },
        ))
    }

    /// Starts or stops a worker draining without touching its health.
    ///
    /// `healthy` is left exactly as it is: a drained worker must keep reporting in,
    /// because the reconciler reads an unhealthy worker as a reason to expire its
    /// leases, and draining is a request to finish the work, not a report of failure.
    async fn set_worker_draining(
        &self,
        node_id: Uuid,
        draining: bool,
        reason: Option<&str>,
    ) -> Result<WorkerStatus, StoreError> {
        let trimmed = reason.map(str::trim).filter(|value| !value.is_empty());
        if let Some(value) = trimmed
            && value.chars().count() > DRAIN_REASON_MAX_CHARS
        {
            return Err(StoreError::Conflict(format!(
                "drain reason must be at most {DRAIN_REASON_MAX_CHARS} characters"
            )));
        }
        // Clearing the drain clears the reason with it, so a worker that comes back
        // never advertises a stale reason to the next operator.
        let stored_reason = if draining {
            trimmed.map(str::to_string)
        } else {
            None
        };
        // `accepting_sandboxes` is the inverse of the flag the caller passes: the
        // column is what the scheduler reads, the argument is what the operator
        // asks for, and binding one straight into the other would leave a drained
        // worker in the placement pool while reporting a drain in the reason column.
        let result = sqlx::query(
            "UPDATE nodes SET accepting_sandboxes = $2, drain_reason = $3 WHERE id = $1",
        )
        .bind(node_id)
        .bind(!draining)
        .bind(&stored_reason)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        self.get_worker(node_id).await
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
        // A draining worker is being emptied, so it must not be handed a reservation
        // that has not been started yet either. A reservation left behind here stays
        // `reserved`: its lease runs out and the reconciler recovers the sandbox on a
        // worker that is still accepting work, which is what draining wants anyway.
        // A node that does not exist has nothing to drain and yields nothing, exactly
        // as this method already did for an unknown worker.
        let accepting: Option<bool> =
            sqlx::query_scalar("SELECT accepting_sandboxes FROM nodes WHERE id = $1")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(database_error)?;
        if accepting != Some(true) {
            return Ok(Vec::new());
        }
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        // The lease row is locked first, and the assignment second, because
        // every path that gives capacity back (`release_capacity`, and through
        // it `delete_sandbox`, `release_worker_lease`, `reconcile_expired_leases`
        // and `release_orphaned_leases`) takes them in that order. Locking the
        // assignment first is the exact inverse, so a worker claiming a
        // reservation while the reconciler sweeps the same sandbox is a cycle:
        // PostgreSQL aborts one side with 40P01, and on the reconciler side that
        // is the whole `FOR UPDATE` page it was sweeping.
        let lease_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT l.id FROM sandbox_leases l \
             JOIN sandbox_assignments a ON a.lease_id = l.id \
             JOIN sandboxes s ON s.id=a.sandbox_id AND s.tenant_id=a.tenant_id \
             WHERE a.node_id=$1 AND a.status='reserved' AND l.status='active' \
               AND l.expires_at > now() AND s.state <> 'quarantined' \
             ORDER BY a.created_at LIMIT $2 FOR UPDATE OF l SKIP LOCKED",
        )
        .bind(node_id)
        .bind(i64::from(limit.clamp(1, 100)))
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        if lease_ids.is_empty() {
            tx.commit().await.map_err(database_error)?;
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT a.* FROM sandbox_assignments a \
             JOIN sandbox_leases l ON l.id = a.lease_id \
             JOIN sandboxes s ON s.id=a.sandbox_id AND s.tenant_id=a.tenant_id \
             WHERE a.node_id=$1 AND a.status='reserved' AND l.id = ANY($2) \
               AND l.status='active' AND l.expires_at > now() AND s.state <> 'quarantined' \
             ORDER BY a.created_at FOR UPDATE OF a SKIP LOCKED",
        )
        .bind(node_id)
        .bind(&lease_ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        let mut assignments = Vec::with_capacity(rows.len());
        for row in rows {
            let tenant_id: Uuid = row.try_get("tenant_id")?;
            let request_id: Uuid = row.try_get("request_id")?;
            let sandbox_id: Uuid = row.try_get("sandbox_id")?;
            let lease_id: Uuid = row.try_get("lease_id")?;
            // Fenced exactly like `renew_worker_lease`: the lease this claim is
            // about to hand the worker has to still be the one the control plane
            // owns, at the generation the claim read. Without the predicate the
            // update matched zero rows for a lease a reconciler had already
            // expired, the result was discarded, and the worker was handed a
            // reservation the control plane had taken back - a real machine
            // built against a lease whose fencing calls are then all refused.
            let renewed = sqlx::query(
                "UPDATE sandbox_leases SET expires_at=now()+($1 * interval '1 second'), \
                 generation=generation+1, updated_at=now() \
                 WHERE id=$2 AND status='active' AND expires_at > now()",
            )
            .bind(
                i64::try_from(lease_ttl_seconds)
                    .map_err(|error| StoreError::Conflict(error.to_string()))?,
            )
            .bind(lease_id)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
            if renewed.rows_affected() == 0 {
                // Left `reserved` for the scheduler to hand out again: this
                // request never owned it, so this request must not mark it.
                continue;
            }
            sqlx::query(
                "UPDATE sandbox_assignments SET status='assigned', updated_at=now() \
                 WHERE tenant_id=$1 AND request_id=$2 AND status='reserved'",
            )
            .bind(tenant_id)
            .bind(request_id)
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
            "SELECT l.* FROM sandbox_leases l JOIN sandboxes s ON s.id=l.sandbox_id \
             WHERE l.status='active' AND l.expires_at <= now() AND s.state <> 'quarantined' \
             ORDER BY l.expires_at LIMIT $1 FOR UPDATE OF l SKIP LOCKED",
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        let mut actions = Vec::with_capacity(rows.len());
        for row in &rows {
            let lease = lease_from_row(row)?;
            let sandbox_row = lock_sandbox(&mut tx, lease.tenant_id, lease.sandbox_id).await?;
            let sandbox = sandbox_from_row(&sandbox_row)?;
            if matches!(
                sandbox.state,
                SandboxState::Destroying | SandboxState::Quarantined
            ) {
                // Teardown owns this reservation until runtime stop is confirmed.
                continue;
            }
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

    async fn update_state_with_lease(
        &self,
        tenant: Uuid,
        id: Uuid,
        expected: SandboxState,
        next: SandboxState,
        lease_id: Uuid,
        generation: i64,
    ) -> Result<(), StoreError> {
        update_state_with_lease_transaction(
            &self.pool, tenant, id, expected, next, lease_id, generation,
        )
        .await
    }

    /// Reads the active lease that currently owns a sandbox, expired or not.
    async fn sandbox_ownership(
        &self,
        sandbox_id: Uuid,
    ) -> Result<Option<SandboxOwnership>, StoreError> {
        let Some(row) = sqlx::query(
            "SELECT node_id, id, generation, expires_at FROM sandbox_leases \
             WHERE sandbox_id=$1 AND status='active' ORDER BY created_at DESC LIMIT 1",
        )
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        else {
            return Ok(None);
        };
        Ok(Some(SandboxOwnership {
            node_id: row.try_get("node_id")?,
            lease_id: row.try_get("id")?,
            generation: row.try_get("generation")?,
            expires_at: row.try_get("expires_at")?,
        }))
    }

    /// Expires a dead worker's lease and places the sandbox on a healthy worker.
    ///
    /// Accepts a lease that this store still holds as `active` and one that
    /// [`reconcile_expired_leases`](Self::reconcile_expired_leases) already expired, so
    /// recovery works whether or not the reconciler ran first. Returns `None` when the
    /// lease is not expired, when the sandbox is already owned, or when no healthy worker
    /// has capacity.
    /// The sandbox is returned to the state a fresh placement uses, so the replacement
    /// worker recreates the machine; recovery is an authoritative reset rather than a
    /// lifecycle transition, because the previous owner's machine is already gone.
    async fn reassign_expired_lease(
        &self,
        lease_id: Uuid,
    ) -> Result<Option<Reassignment>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let row = sqlx::query("SELECT * FROM sandbox_leases WHERE id = $1 FOR UPDATE SKIP LOCKED")
            .bind(lease_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(database_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let lease = lease_from_row(&row)?;
        if lease.expires_at > Utc::now() {
            return Ok(None);
        }
        if !matches!(lease.status.as_str(), "active" | "expired") {
            return Ok(None);
        }
        // A sandbox another lease already owns is not recoverable: a repeated recovery pass
        // must never install a second owner or regress the fencing generation.
        let owned: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM sandbox_leases \
             WHERE tenant_id=$1 AND sandbox_id=$2 AND status='active' AND id <> $3 LIMIT 1",
        )
        .bind(lease.tenant_id)
        .bind(lease.sandbox_id)
        .bind(lease.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        if owned.is_some() {
            return Ok(None);
        }
        // The sandbox row is locked for the rest of this transaction, not just
        // read. This path held the expired lease's lock and nothing else, while
        // the ordinary stop path (`update_state` -> `lock_sandbox`) holds only
        // the sandbox row: a sandbox read as `running` here could be stopped by
        // a concurrent request a moment later, and this transaction would then
        // move it back to `creating` with a fresh live lease and debited
        // capacity, under a caller who had just been told it was going away.
        // Locking it makes the state check below and the write at the end
        // describe the same row.
        let sandbox_row = lock_sandbox(&mut tx, lease.tenant_id, lease.sandbox_id).await?;
        let sandbox: Sandbox = sandbox_from_row(&sandbox_row)?;
        // A run's attempt/cleanup executor owns its machines. Generic lease
        // recovery must not race that executor or resurrect a completed run.
        // Link installation takes the same sandbox lock, so eligibility and
        // association cannot change independently during this transaction.
        let run_owned: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM run_sandboxes WHERE sandbox_id=$1)")
                .bind(sandbox.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database_error)?;
        if run_owned {
            return Ok(None);
        }
        // Only a live sandbox is worth recovering: a sandbox that is being stopped,
        // snapshotted or torn down is left to those flows.
        if !matches!(
            sandbox.state,
            SandboxState::Creating
                | SandboxState::Starting
                | SandboxState::Running
                | SandboxState::Paused
                | SandboxState::Restoring
        ) {
            return Ok(None);
        }
        match lease.status.as_str() {
            // Still active: expiry, capacity release and node clearing happen here.
            "active" => {
                release_capacity(&mut tx, &lease, "expired", "lease_expired_recovery").await?;
            }
            // The reconciler already expired this lease and released its capacity, so the
            // release is skipped and only a leftover node pointer is cleared.
            _ => {
                sqlx::query(
                    "UPDATE sandboxes SET node_id=NULL, updated_at=now() \
                     WHERE tenant_id=$1 AND id=$2 AND node_id=$3",
                )
                .bind(lease.tenant_id)
                .bind(lease.sandbox_id)
                .bind(lease.node_id)
                .execute(&mut *tx)
                .await
                .map_err(database_error)?;
            }
        }
        // Ordering: the expiry and capacity release above are committed even when no worker
        // is available, because a dead owner must not keep a worker's capacity debited
        // while we wait for a replacement. The caller retries on `None`.
        let Some(node) = select_schedulable_node(&mut tx, &sandbox, None).await? else {
            tx.commit().await.map_err(database_error)?;
            return Ok(None);
        };
        let node_id: Uuid = node.try_get("id")?;
        debit_capacity(&mut tx, node_id, sandbox_capacity_demand(&sandbox)?).await?;
        let highest: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(generation), 0) FROM sandbox_leases \
             WHERE tenant_id=$1 AND sandbox_id=$2",
        )
        .bind(lease.tenant_id)
        .bind(lease.sandbox_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
        let generation = highest
            .max(lease.generation)
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("lease generation overflow".into()))?;
        let replacement_id = new_id();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO sandbox_leases \
             (id, tenant_id, sandbox_id, node_id, generation, status, expires_at, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,'active',$6,$7,$7)",
        )
        .bind(replacement_id)
        .bind(lease.tenant_id)
        .bind(lease.sandbox_id)
        .bind(node_id)
        .bind(generation)
        .bind(now + Duration::seconds(RECOVERY_LEASE_TTL_SECONDS))
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        retarget_assignment(
            &mut tx,
            lease.tenant_id,
            lease.sandbox_id,
            lease.id,
            node_id,
            replacement_id,
            now,
        )
        .await?;
        let reassigned = sqlx::query(
            "UPDATE sandboxes SET node_id=$1, state=$2, runtime_path=NULL, updated_at=$3 \
             WHERE tenant_id=$4 AND id=$5 AND state=$6",
        )
        .bind(node_id)
        .bind(SandboxState::Creating.as_str())
        .bind(now)
        .bind(lease.tenant_id)
        .bind(lease.sandbox_id)
        .bind(sandbox.state.as_str())
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if reassigned.rows_affected() == 0 {
            // The state this recovery validated against is gone. The new lease,
            // the debited node and the retargeted assignment all roll back with
            // it rather than stranding a machine against a sandbox somebody
            // else is tearing down.
            return Err(StoreError::Conflict(
                "sandbox left the recoverable states while its lease was being reassigned".into(),
            ));
        }
        insert_sandbox_event(
            &mut tx,
            lease.tenant_id,
            lease.sandbox_id,
            Some(sandbox.state),
            SandboxState::Creating,
            Some("sandbox reassigned after lease expiry"),
        )
        .await?;
        let sandbox = fetch_sandbox(&mut *tx, lease.tenant_id, lease.sandbox_id).await?;
        let lease_row = sqlx::query("SELECT * FROM sandbox_leases WHERE id = $1")
            .bind(replacement_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
        let lease = lease_from_row(&lease_row)?;
        tx.commit().await.map_err(database_error)?;
        Ok(Some(Reassignment { lease, sandbox }))
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

    async fn create_run(&self, value: Run) -> Result<Run, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let run = insert_run_tx(&mut tx, value).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(run)
    }

    async fn get_run(&self, tenant: Uuid, id: Uuid) -> Result<Run, StoreError> {
        fetch_run(&self.pool, tenant, id).await
    }

    async fn list_runs(
        &self,
        tenant: Uuid,
        state: Option<RunState>,
        limit: u32,
    ) -> Result<Vec<Run>, StoreError> {
        // The tenant leads so `runs_tenant_created_idx` drives the page, which
        // is the index that answers "this tenant's runs, newest first". The
        // state stays an `OR` on a nullable parameter so one statement serves
        // both the filtered and the unfiltered page, and a filter that matches
        // few rows of a tenant's own page costs less than a second scan shape.
        let rows = sqlx::query(
            "SELECT * FROM runs \
             WHERE tenant_id = $1 AND ($2::text IS NULL OR state = $2) \
             ORDER BY requested_at DESC, id DESC LIMIT $3",
        )
        .bind(tenant)
        .bind(state.map(RunState::as_str))
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(run_from_row).collect()
    }

    async fn update_run_state(
        &self,
        tenant: Uuid,
        id: Uuid,
        from: RunState,
        to: RunState,
    ) -> Result<Run, StoreError> {
        if !from.can_transition_to(to) {
            return Err(StoreError::Conflict("invalid run state transition".into()));
        }
        // The expected state is part of the write rather than a check made in
        // Rust before it: two callers racing the same transition both pass any
        // local check, and only one of them can still match `state = $4`. The
        // lifecycle edge above is the one thing checked here, because
        // `RunState::can_transition_to` is the only definition of the lifecycle
        // and a second copy of it in SQL would be a second thing to keep true.
        // The lifecycle timestamps move with the state, because a run that
        // succeeded with no completion time cannot be aged or reported on.
        let row = sqlx::query(
            "UPDATE runs SET state = $1, \
               queued_at = CASE WHEN $1 <> 'queued' THEN COALESCE(queued_at, now()) \
                 ELSE queued_at END, \
               started_at = CASE WHEN $1 IN ('running','validating','collecting') \
                 THEN COALESCE(started_at, now()) ELSE started_at END, \
               completed_at = CASE WHEN $1 IN ('succeeded','failed','cancelled') \
                 THEN now() ELSE completed_at END \
             WHERE tenant_id = $2 AND id = $3 AND state = $4 RETURNING *",
        )
        .bind(to.as_str())
        .bind(tenant)
        .bind(id)
        .bind(from.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?;
        if let Some(row) = row {
            return run_from_row(&row);
        }
        // No row updated is two different failures, and the caller acts on them
        // differently: a run this tenant cannot see is missing, while a run that
        // is visible but no longer in `from` was moved by someone else.
        if self.get_run(tenant, id).await.is_ok() {
            return Err(StoreError::Conflict("run state changed".into()));
        }
        Err(StoreError::NotFound)
    }

    async fn record_run_results(
        &self,
        tenant: Uuid,
        id: Uuid,
        results: RunResults,
        state: RunState,
    ) -> Result<Run, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let row = sqlx::query("SELECT * FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(database_error)?
            .ok_or(StoreError::NotFound)?;
        let current = run_from_row(&row)?;
        // Results arrive with the state they put the run in, and unlike
        // `update_run_state` that state is the caller's claim rather than a
        // compare-and-set. It is still held to the lifecycle here, so a late
        // write cannot talk a finished run back into running.
        if current.state != state && !current.state.can_transition_to(state) {
            return Err(StoreError::Conflict("invalid run state transition".into()));
        }
        let updated = sqlx::query(
            "UPDATE runs SET results = $1, state = $2, \
               completed_at = CASE WHEN $2 IN ('succeeded','failed','cancelled') \
                 THEN COALESCE(completed_at, now()) ELSE completed_at END \
             WHERE tenant_id = $3 AND id = $4 RETURNING *",
        )
        .bind(serde_json::to_value(&results)?)
        .bind(state.as_str())
        .bind(tenant)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
        let value = run_from_row(&updated)?;
        tx.commit().await.map_err(database_error)?;
        Ok(value)
    }

    async fn release_orphaned_leases(
        &self,
        limit: u32,
    ) -> Result<aiec_core::storage::OrphanedLeaseRelease, StoreError> {
        let limit = i64::from(limit.clamp(1, 10_000));
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let rows = sqlx::query(
            "SELECT l.* FROM sandbox_leases l JOIN sandboxes s ON s.id = l.sandbox_id \
             WHERE l.status = 'active' AND s.state IN ('destroyed', 'failed') \
             ORDER BY l.expires_at LIMIT $1 FOR UPDATE OF l SKIP LOCKED",
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        let mut released = 0u32;
        let mut already = 0u32;
        for row in &rows {
            let lease = lease_from_row(row)?;
            match release_capacity(
                &mut tx,
                &lease,
                "released",
                "sandbox reached a terminal state",
            )
            .await
            {
                Ok(()) => released += 1,
                // The fence, not the terminal-state check, is what makes this
                // safe to run on a timer. `release_capacity` updates the lease
                // only while it is still `active` with the same generation, so a
                // lease that a concurrent `delete_sandbox` already credited back
                // affects no rows and reports a conflict. Treating that as
                // "already released" is correct; treating it as an error would
                // make this pass look broken every time it did its job.
                Err(StoreError::Conflict(_)) => already += 1,
                // Anything else is a real failure and is raised rather than
                // counted as a success. Swallowing it would understate what is
                // still held while the sweeper reported the pass as healthy.
                // This layer does not log; it returns, and the caller decides.
                Err(error) => return Err(error),
            }
        }
        tx.commit().await.map_err(database_error)?;
        Ok(aiec_core::storage::OrphanedLeaseRelease {
            released,
            already_released: already,
        })
    }

    async fn list_stranded_sandboxes(
        &self,
        older_than: chrono::DateTime<chrono::Utc>,
        limit: u32,
    ) -> Result<Vec<Sandbox>, StoreError> {
        // Two conditions, both necessary.
        //
        // No live lease: something still holding a sandbox on a worker renews
        // its lease, so its absence means nobody is driving it.
        //
        // And no unfinished run: a sandbox being set up right now has a run in
        // `preparing` and briefly no lease, and tearing that down would kill
        // work in flight. Terminal or absent run means nobody is waiting for
        // this machine.
        let rows = sqlx::query(
            "SELECT s.* FROM sandboxes s \
             WHERE s.state NOT IN ('destroyed', 'failed', 'quarantined') \
               AND s.updated_at < $1 \
               AND NOT EXISTS (\
                 SELECT 1 FROM sandbox_leases l \
                 WHERE l.sandbox_id = s.id AND l.status = 'active' \
                   AND l.expires_at > now()) \
               AND NOT EXISTS (\
                 SELECT 1 FROM run_sandboxes rs JOIN runs r ON r.id = rs.run_id \
                 WHERE rs.sandbox_id = s.id \
                   AND r.state NOT IN ('succeeded', 'failed', 'cancelled')) \
             ORDER BY s.updated_at ASC LIMIT $2",
        )
        .bind(older_than)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(sandbox_from_row).collect()
    }

    async fn retain_run_sandbox(
        &self,
        tenant: Uuid,
        id: Uuid,
        sandbox_id: Uuid,
        until: chrono::DateTime<chrono::Utc>,
    ) -> Result<Run, StoreError> {
        // One statement decides all three guards. Written as a check followed by
        // an update, two concurrent retentions of different machines both pass
        // the check and the second overwrites the first: the displaced machine
        // is left with no `retained_until` anywhere, so the sweeper never
        // selects it and it holds its capacity until someone deletes the
        // database. Fenced on the current value instead, so the loser writes
        // nothing at all - and a retry of the *same* machine still succeeds,
        // because that is the same retention restated, not a second one.
        let row = sqlx::query(
            "UPDATE runs r SET retained_sandbox_id=$1, retained_until=$2 \
             WHERE r.tenant_id=$3 AND r.id=$4 \
               AND (r.retained_sandbox_id IS NULL OR r.retained_sandbox_id=$1) \
               AND EXISTS (SELECT 1 FROM sandboxes s \
                 WHERE s.id=$1 AND s.tenant_id=$3) \
               AND EXISTS (SELECT 1 FROM run_sandboxes rs \
                 WHERE rs.run_id=r.id AND rs.sandbox_id=$1) \
             RETURNING r.*",
        )
        .bind(sandbox_id)
        .bind(until)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?;
        match row {
            Some(row) => run_from_row(&row),
            None => Err(run_child_refusal(
                &self.pool,
                tenant,
                id,
                Some(sandbox_id),
                ChildAssociation::Retained,
            )
            .await),
        }
    }

    async fn record_retention_cleanup_failure(
        &self,
        tenant: Uuid,
        id: Uuid,
        sandbox_id: Uuid,
        error: String,
    ) -> Result<Run, StoreError> {
        // A targeted write into `results`, not a replacement of it: a concurrent
        // clear, or any other results write, must not be undone here. Fenced on
        // `retained_sandbox_id` so a sweeper holding a stale read whose machine
        // was already released matches nothing and writes nothing.
        let row = sqlx::query(
            "UPDATE runs SET results = jsonb_set( \
               COALESCE(results,'{}'::jsonb), '{cleanup_failed}', \
               jsonb_build_object('sandbox_id', $3::text, 'error', $4), true) \
             WHERE tenant_id=$1 AND id=$2 AND retained_sandbox_id=$3 RETURNING *",
        )
        .bind(tenant)
        .bind(id)
        .bind(sandbox_id)
        .bind(error)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
        run_from_row(&row)
    }

    async fn clear_run_retention(
        &self,
        tenant: Uuid,
        id: Uuid,
        sandbox_id: Uuid,
    ) -> Result<Run, StoreError> {
        // Retention and the report about that same machine clear together, under
        // one predicate. Splitting them let a sweeper already in flight
        // repopulate the report after the clear committed, leaving a permanently
        // failed teardown that the dispatcher re-leases forever. Narrowing by
        // sandbox id leaves a report about another machine alone; it is still true.
        let row = sqlx::query(
            "UPDATE runs SET retained_sandbox_id=NULL, retained_until=NULL, \
               results = CASE WHEN results->'cleanup_failed'->>'sandbox_id' = $3::text \
                 THEN results - 'cleanup_failed' ELSE results END \
             WHERE tenant_id=$1 AND id=$2 AND retained_sandbox_id=$3 RETURNING *",
        )
        .bind(tenant)
        .bind(id)
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
        run_from_row(&row)
    }

    async fn delete_run(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
        // A run that still holds a machine cannot be deleted, and the reason is
        // the same one keeps `retained_until` from being optional bookkeeping:
        // `runs_retained_until_idx` is how the sweeper finds the machine it owes
        // a reclaim, and `run_sandboxes` is how cleanup finds the machines a run
        // still owns. Deleting the row removes both indexes with nothing else
        // pointing at the machines, so a deleted run keeps its vCPUs debited for
        // the life of the database and its containers running with nothing left
        // to tear them down. One statement has to decide this, because a check
        // followed by the delete is the same window everything else here closed.
        let result = sqlx::query(
            "DELETE FROM runs r WHERE r.tenant_id = $1 AND r.id = $2 \
               AND r.retained_sandbox_id IS NULL \
               AND NOT EXISTS (SELECT 1 FROM run_sandboxes rs WHERE rs.run_id = r.id)",
        )
        .bind(tenant)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(run_history_is_append_only)?;
        if result.rows_affected() == 0 {
            // Refused and absent are different answers: a caller that already
            // deleted its run, and one whose run is still holding a machine.
            let held = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM runs WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?;
            return Err(if held.is_some() {
                StoreError::Conflict("run still owns a machine".into())
            } else {
                StoreError::NotFound
            });
        }
        Ok(())
    }

    /// Appends one run event. There is deliberately no update or delete path:
    /// the table's triggers reject both, so a mistake has to be answered with a
    /// correcting event rather than an edit to the record of what happened.
    async fn append_run_event(&self, tenant: Uuid, value: RunEvent) -> Result<(), StoreError> {
        if value.event_type.trim().is_empty() {
            return Err(StoreError::Conflict("a run event needs a type".into()));
        }
        if !value.detail.is_object() {
            return Err(StoreError::Conflict(
                "a run event detail must be a JSON object".into(),
            ));
        }
        // Selected from the tenant's own run rather than inserted against a run
        // id: `run_events` holds no tenant and no foreign key on the machine it
        // may name, so a statement that does not carry both predicates stores a
        // row another tenant's machine is readable through.
        let written = sqlx::query(
            "INSERT INTO run_events (id, run_id, sandbox_id, type, occurred_at, detail) \
             SELECT $1::uuid, r.id, $3::uuid, $4::text, $5::timestamptz, $6::jsonb \
             FROM runs r WHERE r.id = $2 AND r.tenant_id = $7 \
               AND ($3::uuid IS NULL OR EXISTS (SELECT 1 FROM sandboxes s \
                 WHERE s.id = $3 AND s.tenant_id = r.tenant_id))",
        )
        .bind(value.id)
        .bind(value.run_id)
        .bind(value.sandbox_id)
        .bind(value.event_type)
        .bind(value.occurred_at)
        .bind(value.detail)
        .bind(tenant)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if written.rows_affected() != 1 {
            return Err(run_child_refusal(
                &self.pool,
                tenant,
                value.run_id,
                value.sandbox_id,
                ChildAssociation::Owned,
            )
            .await);
        }
        Ok(())
    }

    async fn list_run_events(&self, tenant: Uuid, run: Uuid) -> Result<Vec<RunEvent>, StoreError> {
        // The child tables carry no tenant of their own, so the run is joined in
        // to keep a tenant from reading another tenant's history.
        let rows = sqlx::query(
            "SELECT e.* FROM run_events e JOIN runs r ON r.id = e.run_id \
             WHERE r.tenant_id = $1 AND e.run_id = $2 ORDER BY e.occurred_at, e.id",
        )
        .bind(tenant)
        .bind(run)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(run_event_from_row).collect()
    }

    async fn link_run_sandbox(&self, tenant: Uuid, value: RunSandbox) -> Result<(), StoreError> {
        if value.role.trim().is_empty() {
            return Err(StoreError::Conflict("a run sandbox needs a role".into()));
        }
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        match lock_sandbox(&mut tx, tenant, value.sandbox_id).await {
            Ok(_) => {}
            Err(StoreError::NotFound) => {
                return Err(run_child_refusal(
                    &mut *tx,
                    tenant,
                    value.run_id,
                    Some(value.sandbox_id),
                    ChildAssociation::Owned,
                )
                .await);
            }
            Err(error) => return Err(error),
        }
        // The run and the machine have to be the same tenant's, and that is
        // decided by the join rather than by a lookup a caller could race: the
        // pair either lands whole or does not land at all. Relinking the same
        // machine is a change of purpose -- a retry takes over the role its
        // first attempt had -- so the link is restated rather than duplicated,
        // and a retried link of the same machine and role is a no-op instead of
        // a unique violation.
        let written = sqlx::query(
            "INSERT INTO run_sandboxes (run_id, sandbox_id, role) \
             SELECT r.id, s.id, $3::text FROM runs r \
             JOIN sandboxes s ON s.id = $2 AND s.tenant_id = r.tenant_id \
             WHERE r.id = $1 AND r.tenant_id = $4 \
             ON CONFLICT (run_id, sandbox_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(value.run_id)
        .bind(value.sandbox_id)
        .bind(value.role)
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if written.rows_affected() != 1 {
            return Err(run_child_refusal(
                &mut *tx,
                tenant,
                value.run_id,
                Some(value.sandbox_id),
                ChildAssociation::Owned,
            )
            .await);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn list_run_sandboxes(
        &self,
        tenant: Uuid,
        run: Uuid,
    ) -> Result<Vec<RunSandbox>, StoreError> {
        let rows = sqlx::query(
            "SELECT s.run_id, s.sandbox_id, s.role FROM run_sandboxes s \
             JOIN runs r ON r.id = s.run_id \
             WHERE r.tenant_id = $1 AND s.run_id = $2 ORDER BY s.created_at, s.sandbox_id",
        )
        .bind(tenant)
        .bind(run)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(run_sandbox_from_row).collect()
    }

    /// Starts an attempt or imports already-completed historical evidence.
    /// Allocation assigns compute once; completion seals the attempt once.
    async fn record_run_attempt(&self, tenant: Uuid, value: RunAttempt) -> Result<(), StoreError> {
        if value.attempt_number <= 0 {
            return Err(StoreError::Conflict(
                "a run attempt number must be positive".into(),
            ));
        }
        let state = attempt_state_as_str(value.state)?;
        // Same shape as the other child writes: the run is selected under its
        // tenant, and a machine the attempt names has to be that tenant's.
        let written = sqlx::query(
            "INSERT INTO run_attempts \
             (id, run_id, attempt_number, sandbox_id, state, failure_reason, started_at, \
              completed_at, placement, results) \
             SELECT $1::uuid, r.id, $3::integer, $4::uuid, $5::text, $6::text, \
                    $7::timestamptz, $8::timestamptz, $9::jsonb, $10::jsonb \
             FROM runs r WHERE r.id = $2 AND r.tenant_id = $11 \
               AND ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM sandboxes s \
                 WHERE s.id = $4 AND s.tenant_id = r.tenant_id))",
        )
        .bind(value.id)
        .bind(value.run_id)
        .bind(value.attempt_number)
        .bind(value.sandbox_id)
        .bind(state)
        .bind(&value.failure_reason)
        .bind(value.started_at)
        .bind(value.completed_at)
        .bind(serde_json::to_value(&value.placement)?)
        .bind(serde_json::to_value(&value.results)?)
        .bind(tenant)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if written.rows_affected() != 1 {
            return Err(run_child_refusal(
                &self.pool,
                tenant,
                value.run_id,
                value.sandbox_id,
                ChildAssociation::Owned,
            )
            .await);
        }
        Ok(())
    }

    async fn complete_run_attempt(
        &self,
        tenant: Uuid,
        attempt: RunAttempt,
    ) -> Result<(), StoreError> {
        if !attempt.state.is_terminal() || attempt.completed_at.is_none() {
            return Err(StoreError::Conflict(
                "attempt completion must be terminal".into(),
            ));
        }
        let changed = sqlx::query(
            "UPDATE run_attempts a SET state=$4,failure_reason=$5,completed_at=$6, \
             placement=$7,results=$8 FROM runs r WHERE a.id=$2 AND a.run_id=$3 \
             AND r.id=a.run_id AND r.tenant_id=$1 AND a.state='running' \
             AND a.completed_at IS NULL",
        )
        .bind(tenant)
        .bind(attempt.id)
        .bind(attempt.run_id)
        .bind(attempt_state_as_str(attempt.state)?)
        .bind(&attempt.failure_reason)
        .bind(attempt.completed_at)
        .bind(serde_json::to_value(&attempt.placement)?)
        .bind(serde_json::to_value(&attempt.results)?)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if changed.rows_affected() != 1 {
            return Err(StoreError::Conflict(
                "attempt is already complete or unavailable".into(),
            ));
        }
        Ok(())
    }

    async fn list_run_attempts(
        &self,
        tenant: Uuid,
        run: Uuid,
    ) -> Result<Vec<RunAttempt>, StoreError> {
        let rows = sqlx::query(
            "SELECT a.* FROM run_attempts a JOIN runs r ON r.id = a.run_id \
             WHERE r.tenant_id = $1 AND a.run_id = $2 ORDER BY a.attempt_number",
        )
        .bind(tenant)
        .bind(run)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(run_attempt_from_row).collect()
    }

    async fn put_run_artifacts(
        &self,
        tenant: Uuid,
        run: Uuid,
        artifacts: Vec<RunArtifactRef>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let owner = sqlx::query(
            "SELECT artifacts_expired_at FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(run)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
        if owner
            .try_get::<Option<DateTime<Utc>>, _>("artifacts_expired_at")?
            .is_some()
        {
            return Err(StoreError::Conflict("Run artifacts have expired".into()));
        }
        let mut artifacts = artifacts;
        artifacts.sort_by(|a, b| a.object_key.cmp(&b.object_key));
        // Replacing rather than appending: a run's artifacts are what the
        // collection pass found, and a re-run that collects fewer files must not
        // leave the files it no longer produced listed against the run.
        sqlx::query("DELETE FROM run_artifacts WHERE run_id = $1")
            .bind(run)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        for artifact in artifacts {
            if artifact.name.trim().is_empty() || artifact.object_key.trim().is_empty() {
                return Err(StoreError::Conflict(
                    "a run artifact needs a name and an object key".into(),
                ));
            }
            if artifact.size_bytes < 0 {
                return Err(StoreError::Conflict(
                    "a run artifact cannot have a negative size".into(),
                ));
            }
            sqlx::query(
                "INSERT INTO run_artifacts \
                 (id, run_id, name, object_key, size_bytes, checksum_sha256, content_type) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(new_id())
            .bind(run)
            .bind(&artifact.name)
            .bind(&artifact.object_key)
            .bind(artifact.size_bytes)
            .bind(&artifact.checksum_sha256)
            .bind(&artifact.content_type)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn list_run_artifacts(
        &self,
        tenant: Uuid,
        run: Uuid,
    ) -> Result<Vec<RunArtifactRef>, StoreError> {
        let rows = sqlx::query(
            "SELECT f.name, f.object_key, f.size_bytes, f.checksum_sha256, f.content_type \
             FROM run_artifacts f JOIN runs r ON r.id = f.run_id \
             WHERE r.tenant_id = $1 AND f.run_id = $2 \
             AND r.artifacts_expired_at IS NULL ORDER BY f.name",
        )
        .bind(tenant)
        .bind(run)
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(run_artifact_from_row).collect()
    }

    /// Lists the runs whose retained machine has passed its expiry.
    ///
    /// This is the one run read with no tenant: expiry is a property of a
    /// machine, and a machine that was retained for debugging is still capacity
    /// the cluster is holding whether or not anybody is still asking. The
    /// predicate mirrors `Run::retention_expired` exactly, and it is written so
    /// `runs_retained_until_idx` can answer it: the partial index's predicate is
    /// restated here and nothing else narrows the scan, so the sweep is an index
    /// range rather than a full pass over every run ever recorded.
    async fn retained_runs_due(
        &self,
        now: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<Run>, StoreError> {
        // Terminal states only. `retain_run_sandbox` is called from `cleanup()`,
        // which runs BEFORE the run settles, so a row can carry `retained_until`
        // while the executor is still writing results against that machine. With
        // `retained_seconds` at its validated minimum the 15 s sweeper sees such
        // a row, destroys the machine under a live run, and clears the retention
        // fields - so the caller who asked to keep a debugging machine is told
        // there is none. The artifact GC query filters on the same thing for the
        // same reason.
        let rows = sqlx::query(
            "SELECT * FROM runs WHERE retained_until IS NOT NULL AND retained_until <= $1 \
             AND state IN ('succeeded','failed','cancelled') \
             ORDER BY retained_until LIMIT $2",
        )
        .bind(now)
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .map_err(database_error)?;
        rows.iter().map(run_from_row).collect()
    }
}

#[async_trait]
impl MetadataStore for PostgresRepository {
    async fn put_guard_budget(
        &self,
        state: GuardBudgetState,
    ) -> Result<GuardBudgetState, CoreError> {
        Self::put_guard_budget(self, state)
            .await
            .map_err(core_error)
    }
    async fn update_guard_policy(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        guard: &aiec_guard::policy::GuardConfig,
        policy_hash: &str,
    ) -> Result<(), CoreError> {
        Self::update_guard_policy(self, tenant, sandbox, guard, policy_hash).await
    }

    async fn release_guard_quarantine(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        released_by: &str,
    ) -> Result<Sandbox, CoreError> {
        Self::release_guard_quarantine(self, tenant, sandbox, released_by).await
    }

    async fn put_guard_proposal(
        &self,
        proposal: GuardProposal,
    ) -> Result<GuardProposal, CoreError> {
        Self::put_guard_proposal(self, proposal).await
    }

    async fn list_guard_proposals(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        limit: u32,
        after: Option<aiec_core::storage::PageCursor>,
    ) -> Result<aiec_core::storage::GuardProposalPage, CoreError> {
        Self::list_guard_proposals(self, tenant, sandbox, limit, after).await
    }

    async fn get_guard_proposal(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        id: Uuid,
    ) -> Result<GuardProposal, CoreError> {
        Self::get_guard_proposal(self, tenant, sandbox, id).await
    }

    async fn put_guard_tool_approval(
        &self,
        approval: GuardToolApproval,
    ) -> Result<GuardToolApproval, CoreError> {
        Self::put_guard_tool_approval(self, approval).await
    }

    async fn get_or_put_guard_tool_approval(
        &self,
        approval: GuardToolApproval,
    ) -> Result<GuardToolApproval, CoreError> {
        Self::get_or_put_guard_tool_approval(self, approval).await
    }

    async fn decide_guard_tool_approval(
        &self,
        request: ApprovalDecisionRequest<'_>,
    ) -> Result<Option<GuardToolApproval>, CoreError> {
        Self::decide_guard_tool_approval(self, request).await
    }

    async fn consume_guard_tool_approval(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        tool: &str,
        request_digest: &str,
        requested_by_key_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<GuardToolApproval>, CoreError> {
        Self::consume_guard_tool_approval(
            self,
            tenant,
            sandbox,
            tool,
            request_digest,
            requested_by_key_id,
            now,
        )
        .await
    }

    async fn list_guard_tool_approvals(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        limit: u32,
        after: Option<aiec_core::storage::PageCursor>,
    ) -> Result<aiec_core::storage::GuardToolApprovalPage, CoreError> {
        Self::list_guard_tool_approvals(self, tenant, sandbox, limit, after).await
    }

    async fn get_guard_budget(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<GuardBudgetState, CoreError> {
        Self::get_guard_budget(self, tenant, id)
            .await
            .map_err(core_error)
    }
    async fn reserve_guard_budget(
        &self,
        identity: GuardIdentity,
        fence: GuardFence,
        debit: BudgetDebit,
    ) -> Result<GuardBudgetState, CoreError> {
        Self::reserve_guard_budget(self, identity, fence, debit)
            .await
            .map_err(core_error)
    }
    async fn put_guard_incident(
        &self,
        incident: GuardIncident,
    ) -> Result<GuardIncident, CoreError> {
        Self::put_guard_incident(self, incident)
            .await
            .map_err(core_error)
    }
    async fn get_guard_incident(&self, tenant: Uuid, id: Uuid) -> Result<GuardIncident, CoreError> {
        Self::get_guard_incident(self, tenant, id)
            .await
            .map_err(core_error)
    }
    async fn list_expired_guard_budgets(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<GuardBudgetState>, CoreError> {
        Self::list_expired_guard_budgets(self, now, limit)
            .await
            .map_err(core_error)
    }
    async fn mark_guard_quarantined(
        &self,
        tenant: Uuid,
        id: Uuid,
        fence: GuardFence,
    ) -> Result<Sandbox, CoreError> {
        Self::mark_guard_quarantined(self, tenant, id, fence)
            .await
            .map_err(core_error)
    }
    async fn create_sandbox(&self, value: Sandbox) -> Result<(), CoreError> {
        Self::create_sandbox(self, value).await.map_err(core_error)
    }
    async fn create_attempt_sandbox(
        &self,
        run_id: Uuid,
        attempt_id: Uuid,
        sandbox: Sandbox,
        required: RuntimeCapabilities,
    ) -> Result<Sandbox, CoreError> {
        Self::create_attempt_sandbox(self, run_id, attempt_id, sandbox, required)
            .await
            .map_err(core_error)
    }
    async fn get_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<Sandbox, CoreError> {
        Self::get_sandbox(self, tenant, id)
            .await
            .map_err(core_error)
    }
    async fn list_sandboxes(
        &self,
        tenant: Uuid,
        limit: u32,
        after: Option<aiec_core::storage::PageCursor>,
    ) -> Result<aiec_core::storage::SandboxPage, CoreError> {
        Self::list_sandboxes(self, tenant, limit, after)
            .await
            .map_err(core_error)
    }
    async fn update_state(
        &self,
        tenant: Uuid,
        id: Uuid,
        expected: SandboxState,
        next: SandboxState,
        runtime_path: Option<String>,
    ) -> Result<Sandbox, CoreError> {
        Self::update_state(self, tenant, id, expected, next, runtime_path)
            .await
            .map_err(core_error)
    }
    async fn update_state_with_lease(
        &self,
        tenant: Uuid,
        id: Uuid,
        expected: SandboxState,
        next: SandboxState,
        lease_id: Uuid,
        generation: i64,
    ) -> Result<(), CoreError> {
        Self::update_state_with_lease(self, tenant, id, expected, next, lease_id, generation)
            .await
            .map_err(core_error)
    }
    async fn delete_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<(), CoreError> {
        Self::delete_sandbox(self, tenant, id)
            .await
            .map_err(core_error)
    }
    async fn put_key(&self, value: ApiKeyRecord) -> Result<(), CoreError> {
        Self::put_key(self, value).await.map_err(core_error)
    }
    async fn revoke_key(&self, tenant: Uuid, id: Uuid) -> Result<(), CoreError> {
        Self::revoke_key(self, tenant, id).await.map_err(core_error)
    }
    async fn list_keys(&self, tenant: Uuid) -> Result<Vec<ApiKeyRecord>, CoreError> {
        Self::list_keys(self, tenant).await.map_err(core_error)
    }

    async fn get_key(&self, tenant: Uuid, id: Uuid) -> Result<Option<ApiKeyRecord>, CoreError> {
        Self::get_key(self, tenant, id).await.map_err(core_error)
    }

    async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, CoreError> {
        Self::find_key(self, digest).await.map_err(core_error)
    }
    async fn put_snapshot(&self, value: Snapshot) -> Result<(), CoreError> {
        Self::put_snapshot(self, value).await.map_err(core_error)
    }
    async fn get_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<Snapshot, CoreError> {
        Self::get_snapshot(self, tenant, id)
            .await
            .map_err(core_error)
    }
    async fn list_snapshots(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        limit: u32,
        after: Option<aiec_core::storage::PageCursor>,
    ) -> Result<aiec_core::storage::SnapshotPage, CoreError> {
        Self::list_snapshots(self, tenant, sandbox, limit, after)
            .await
            .map_err(core_error)
    }
    async fn delete_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<(), CoreError> {
        Self::delete_snapshot(self, tenant, id)
            .await
            .map_err(core_error)
    }
    async fn append_usage(&self, value: UsageEvent) -> Result<(), CoreError> {
        Self::append_usage(self, value).await.map_err(core_error)
    }
    async fn usage(&self, tenant: Uuid) -> Result<Vec<UsageSummary>, CoreError> {
        Self::usage(self, tenant).await.map_err(core_error)
    }
    async fn register_node(&self, value: Node) -> Result<Uuid, CoreError> {
        Self::register_node(self, value).await.map_err(core_error)
    }
    async fn ping(&self) -> Result<(), CoreError> {
        Self::ping(self).await.map_err(core_error)
    }

    async fn node_capacity_totals(&self) -> Result<aiec_core::NodeCapacity, CoreError> {
        Self::node_capacity_totals(self).await.map_err(core_error)
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
    async fn list_sandbox_events(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        limit: u32,
    ) -> Result<Vec<SandboxEvent>, CoreError> {
        Self::list_sandbox_events(self, tenant, sandbox, limit)
            .await
            .map_err(core_error)
    }
    async fn append_audit_event(&self, event: AuditEvent) -> Result<(), CoreError> {
        Self::append_audit_event(self, event)
            .await
            .map_err(core_error)
    }
    async fn list_audit_events(
        &self,
        tenant: Option<Uuid>,
        action: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AuditEvent>, CoreError> {
        Self::list_audit_events(self, tenant, action, limit)
            .await
            .map_err(core_error)
    }
    async fn put_stored_snapshot(&self, value: StoredSnapshot) -> Result<(), CoreError> {
        Self::put_stored_snapshot(self, value)
            .await
            .map_err(core_error)
    }
    async fn get_stored_snapshot(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<StoredSnapshot, CoreError> {
        Self::get_stored_snapshot(self, tenant, id)
            .await
            .map_err(core_error)
    }
    async fn latest_stored_snapshot(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        kind: &str,
    ) -> Result<Option<StoredSnapshot>, CoreError> {
        Self::latest_stored_snapshot(self, tenant, sandbox, kind)
            .await
            .map_err(core_error)
    }
    async fn create_sandbox_idempotent(
        &self,
        tenant: Uuid,
        request_id: Uuid,
        sandbox: Sandbox,
    ) -> Result<Sandbox, CoreError> {
        Self::create_sandbox_idempotent(self, tenant, request_id, sandbox)
            .await
            .map_err(core_error)
    }
    async fn register_worker(&self, value: WorkerRegistration) -> Result<Uuid, CoreError> {
        Self::register_worker(self, value).await.map_err(core_error)
    }
    async fn heartbeat_worker(
        &self,
        heartbeat: WorkerHeartbeat,
    ) -> Result<WorkerStatus, CoreError> {
        Self::heartbeat_worker(self, heartbeat)
            .await
            .map_err(core_error)
    }
    async fn get_worker(&self, node_id: Uuid) -> Result<WorkerStatus, CoreError> {
        Self::get_worker(self, node_id).await.map_err(core_error)
    }
    async fn list_workers(&self, include_unhealthy: bool) -> Result<Vec<WorkerStatus>, CoreError> {
        Self::list_workers(self, include_unhealthy)
            .await
            .map_err(core_error)
    }
    async fn set_worker_draining(
        &self,
        node_id: Uuid,
        draining: bool,
        reason: Option<&str>,
    ) -> Result<WorkerStatus, CoreError> {
        Self::set_worker_draining(self, node_id, draining, reason)
            .await
            .map_err(core_error)
    }
    async fn claim_worker_assignments(
        &self,
        node_id: Uuid,
        limit: u32,
        lease_ttl_seconds: u64,
    ) -> Result<Vec<WorkerAssignment>, CoreError> {
        Self::claim_worker_assignments(self, node_id, limit, lease_ttl_seconds)
            .await
            .map_err(core_error)
    }
    async fn list_worker_assignments(
        &self,
        tenant: Uuid,
        node_id: Uuid,
        status: Option<&str>,
        limit: u32,
    ) -> Result<Vec<WorkerAssignment>, CoreError> {
        Self::list_worker_assignments(self, tenant, node_id, status, limit)
            .await
            .map_err(core_error)
    }
    async fn list_worker_assignments_for_node(
        &self,
        node_id: Uuid,
        status: Option<&str>,
        limit: u32,
    ) -> Result<Vec<WorkerAssignment>, CoreError> {
        Self::list_worker_assignments_for_node(self, node_id, status, limit)
            .await
            .map_err(core_error)
    }
    async fn get_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
    ) -> Result<WorkerLease, CoreError> {
        Self::get_worker_lease(self, tenant, lease_id)
            .await
            .map_err(core_error)
    }
    async fn get_active_worker_lease(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<WorkerLease, CoreError> {
        Self::get_active_worker_lease(self, tenant, sandbox)
            .await
            .map_err(core_error)
    }
    async fn renew_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
        generation: i64,
        ttl_seconds: u64,
    ) -> Result<WorkerLease, CoreError> {
        Self::renew_worker_lease(self, tenant, lease_id, generation, ttl_seconds)
            .await
            .map_err(core_error)
    }
    async fn complete_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
        generation: i64,
        result: Value,
    ) -> Result<WorkerLease, CoreError> {
        Self::complete_worker_lease(self, tenant, lease_id, generation, result)
            .await
            .map_err(core_error)
    }
    async fn release_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
        generation: i64,
        reason: &str,
    ) -> Result<WorkerLease, CoreError> {
        Self::release_worker_lease(self, tenant, lease_id, generation, reason)
            .await
            .map_err(core_error)
    }
    async fn reconcile_expired_leases(
        &self,
        limit: u32,
    ) -> Result<Vec<ReconciliationAction>, CoreError> {
        Self::reconcile_expired_leases(self, limit)
            .await
            .map_err(core_error)
    }
    async fn reassign_expired_lease(
        &self,
        lease_id: Uuid,
    ) -> Result<Option<Reassignment>, CoreError> {
        Self::reassign_expired_lease(self, lease_id)
            .await
            .map_err(core_error)
    }
    async fn sandbox_ownership(
        &self,
        sandbox_id: Uuid,
    ) -> Result<Option<SandboxOwnership>, CoreError> {
        Self::sandbox_ownership(self, sandbox_id)
            .await
            .map_err(core_error)
    }
    async fn list_reconciliation_actions(
        &self,
        tenant: Uuid,
        limit: u32,
    ) -> Result<Vec<ReconciliationAction>, CoreError> {
        Self::list_reconciliation_actions(self, tenant, limit)
            .await
            .map_err(core_error)
    }
    async fn begin_sandbox_operation(
        &self,
        value: SandboxOperation,
    ) -> Result<SandboxOperation, CoreError> {
        Self::begin_sandbox_operation(self, value)
            .await
            .map_err(core_error)
    }
    async fn complete_sandbox_operation(
        &self,
        tenant: Uuid,
        request_id: Uuid,
        result: Value,
    ) -> Result<SandboxOperation, CoreError> {
        Self::complete_sandbox_operation(self, tenant, request_id, result)
            .await
            .map_err(core_error)
    }
    async fn fail_sandbox_operation(
        &self,
        tenant: Uuid,
        request_id: Uuid,
        error: Value,
    ) -> Result<SandboxOperation, CoreError> {
        Self::fail_sandbox_operation(self, tenant, request_id, error)
            .await
            .map_err(core_error)
    }
    async fn get_sandbox_operation(
        &self,
        tenant: Uuid,
        request_id: Uuid,
    ) -> Result<SandboxOperation, CoreError> {
        Self::get_sandbox_operation(self, tenant, request_id)
            .await
            .map_err(core_error)
    }
    async fn put_image(&self, value: ImageRecord) -> Result<(), CoreError> {
        Self::put_image(self, value).await.map_err(core_error)
    }
    async fn get_image(&self, id: &str) -> Result<ImageRecord, CoreError> {
        Self::get_image(self, id).await.map_err(core_error)
    }
    async fn set_run_failure(
        &self,
        tenant: Uuid,
        id: Uuid,
        failure_reason: Option<String>,
        state: RunState,
    ) -> Result<Run, CoreError> {
        Self::set_run_failure(self, tenant, id, failure_reason, state)
            .await
            .map_err(core_error)
    }
    async fn record_run_failure(
        &self,
        tenant: Uuid,
        id: Uuid,
        results: RunResults,
        reason: Option<String>,
    ) -> Result<Run, CoreError> {
        Self::record_run_failure(self, tenant, id, results, reason)
            .await
            .map_err(core_error)
    }

    async fn set_run_placement(
        &self,
        tenant: Uuid,
        id: Uuid,
        placement: Placement,
    ) -> Result<Run, CoreError> {
        Self::set_run_placement(self, tenant, id, placement)
            .await
            .map_err(core_error)
    }
    async fn create_run(&self, run: Run) -> Result<Run, CoreError> {
        Self::create_run(self, run).await.map_err(core_error)
    }
    async fn get_run(&self, tenant: Uuid, id: Uuid) -> Result<Run, CoreError> {
        Self::get_run(self, tenant, id).await.map_err(core_error)
    }
    async fn list_runs(
        &self,
        tenant: Uuid,
        state: Option<RunState>,
        limit: u32,
    ) -> Result<Vec<Run>, CoreError> {
        Self::list_runs(self, tenant, state, limit)
            .await
            .map_err(core_error)
    }
    async fn update_run_state(
        &self,
        tenant: Uuid,
        id: Uuid,
        from: RunState,
        to: RunState,
    ) -> Result<Run, CoreError> {
        Self::update_run_state(self, tenant, id, from, to)
            .await
            .map_err(core_error)
    }
    async fn record_run_results(
        &self,
        tenant: Uuid,
        id: Uuid,
        results: RunResults,
        state: RunState,
    ) -> Result<Run, CoreError> {
        Self::record_run_results(self, tenant, id, results, state)
            .await
            .map_err(core_error)
    }
    async fn release_orphaned_leases(
        &self,
        limit: u32,
    ) -> Result<aiec_core::storage::OrphanedLeaseRelease, CoreError> {
        Self::release_orphaned_leases(self, limit)
            .await
            .map_err(core_error)
    }
    async fn list_stranded_sandboxes(
        &self,
        older_than: chrono::DateTime<chrono::Utc>,
        limit: u32,
    ) -> Result<Vec<Sandbox>, CoreError> {
        Self::list_stranded_sandboxes(self, older_than, limit)
            .await
            .map_err(core_error)
    }
    async fn retain_run_sandbox(
        &self,
        tenant: Uuid,
        id: Uuid,
        sandbox_id: Uuid,
        until: chrono::DateTime<chrono::Utc>,
    ) -> Result<Run, CoreError> {
        Self::retain_run_sandbox(self, tenant, id, sandbox_id, until)
            .await
            .map_err(core_error)
    }
    async fn record_retention_cleanup_failure(
        &self,
        tenant: Uuid,
        id: Uuid,
        sandbox_id: Uuid,
        error: String,
    ) -> Result<Run, CoreError> {
        Self::record_retention_cleanup_failure(self, tenant, id, sandbox_id, error)
            .await
            .map_err(core_error)
    }
    async fn clear_run_retention(
        &self,
        tenant: Uuid,
        id: Uuid,
        sandbox_id: Uuid,
    ) -> Result<Run, CoreError> {
        Self::clear_run_retention(self, tenant, id, sandbox_id)
            .await
            .map_err(core_error)
    }
    async fn delete_run(&self, tenant: Uuid, id: Uuid) -> Result<(), CoreError> {
        Self::delete_run(self, tenant, id).await.map_err(core_error)
    }
    async fn append_run_event(&self, tenant: Uuid, event: RunEvent) -> Result<(), CoreError> {
        Self::append_run_event(self, tenant, event)
            .await
            .map_err(core_error)
    }
    async fn list_run_events(&self, tenant: Uuid, run: Uuid) -> Result<Vec<RunEvent>, CoreError> {
        Self::list_run_events(self, tenant, run)
            .await
            .map_err(core_error)
    }
    async fn link_run_sandbox(&self, tenant: Uuid, link: RunSandbox) -> Result<(), CoreError> {
        Self::link_run_sandbox(self, tenant, link)
            .await
            .map_err(core_error)
    }
    async fn list_run_sandboxes(
        &self,
        tenant: Uuid,
        run: Uuid,
    ) -> Result<Vec<RunSandbox>, CoreError> {
        Self::list_run_sandboxes(self, tenant, run)
            .await
            .map_err(core_error)
    }
    async fn record_run_attempt(&self, tenant: Uuid, attempt: RunAttempt) -> Result<(), CoreError> {
        Self::record_run_attempt(self, tenant, attempt)
            .await
            .map_err(core_error)
    }
    async fn complete_run_attempt(
        &self,
        tenant: Uuid,
        attempt: RunAttempt,
    ) -> Result<(), CoreError> {
        Self::complete_run_attempt(self, tenant, attempt)
            .await
            .map_err(core_error)
    }
    async fn list_run_attempts(
        &self,
        tenant: Uuid,
        run: Uuid,
    ) -> Result<Vec<RunAttempt>, CoreError> {
        Self::list_run_attempts(self, tenant, run)
            .await
            .map_err(core_error)
    }
    async fn put_run_artifacts(
        &self,
        tenant: Uuid,
        run: Uuid,
        artifacts: Vec<RunArtifactRef>,
    ) -> Result<(), CoreError> {
        Self::put_run_artifacts(self, tenant, run, artifacts)
            .await
            .map_err(core_error)
    }
    async fn list_run_artifacts(
        &self,
        tenant: Uuid,
        run: Uuid,
    ) -> Result<Vec<RunArtifactRef>, CoreError> {
        Self::list_run_artifacts(self, tenant, run)
            .await
            .map_err(core_error)
    }
    async fn reserve_artifact_upload(
        &self,
        tenant: Uuid,
        run: Option<Uuid>,
        key: &str,
    ) -> Result<(), CoreError> {
        Self::reserve_artifact_upload(self, tenant, run, key)
            .await
            .map_err(core_error)
    }
    async fn complete_artifact_upload(
        &self,
        tenant: Uuid,
        run: Option<Uuid>,
        key: &str,
    ) -> Result<(), CoreError> {
        Self::complete_artifact_upload(self, tenant, run, key)
            .await
            .map_err(core_error)
    }
    async fn claim_artifact_deletions(
        &self,
        now: DateTime<Utc>,
        retention_seconds: i64,
        pending_grace_seconds: i64,
        limit: u32,
        lease_seconds: i64,
    ) -> Result<Vec<aiec_core::storage::ArtifactDeletion>, CoreError> {
        Self::claim_artifact_deletions(
            self,
            now,
            retention_seconds,
            pending_grace_seconds,
            limit,
            lease_seconds,
        )
        .await
        .map_err(core_error)
    }
    async fn finish_artifact_deletion(
        &self,
        key: &str,
        claim: Uuid,
        deleted: bool,
        retry_at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        Self::finish_artifact_deletion(self, key, claim, deleted, retry_at)
            .await
            .map_err(core_error)
    }
    async fn retained_runs_due(
        &self,
        now: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<Run>, CoreError> {
        Self::retained_runs_due(self, now, limit)
            .await
            .map_err(core_error)
    }
    async fn list_matrix_cells(
        &self,
        tenant: Uuid,
        matrix: Uuid,
        limit: u32,
        after: Option<aiec_core::storage::MatrixCursor>,
    ) -> Result<aiec_core::storage::MatrixCellPage, CoreError> {
        crate::matrix::list_matrix_cells(self, tenant, matrix, limit, after)
            .await
            .map_err(core_error)
    }
    async fn get_tenant_quota_usage(
        &self,
        tenant: Uuid,
    ) -> Result<(aiec_core::QuotaLimits, aiec_core::QuotaUsage), CoreError> {
        Self::tenant_quota_usage(self, tenant)
            .await
            .map_err(core_error)
    }
    fn supports_run_queue(&self) -> bool {
        true
    }
    async fn enqueue_run(
        &self,
        run: Run,
        request: Value,
        limits: RunQueueLimits,
    ) -> Result<Run, CoreError> {
        Self::enqueue_run(self, run, request, limits)
            .await
            .map_err(core_error)
    }
    async fn claim_run_queue(
        &self,
        owner: Uuid,
        limits: RunQueueLimits,
    ) -> Result<Option<RunQueueClaim>, CoreError> {
        Self::claim_run_queue(self, owner, limits)
            .await
            .map_err(core_error)
    }
    async fn recover_run_queue(
        &self,
        owner: Uuid,
        limits: RunQueueLimits,
    ) -> Result<Option<RunQueueClaim>, CoreError> {
        Self::recover_run_queue(self, owner, limits)
            .await
            .map_err(core_error)
    }
    async fn heartbeat_run_queue(
        &self,
        tenant: Uuid,
        run: Uuid,
        owner: Uuid,
        lease_seconds: u32,
    ) -> Result<bool, CoreError> {
        Self::heartbeat_run_queue(self, tenant, run, owner, lease_seconds)
            .await
            .map_err(core_error)
    }
    async fn fail_run_queue(
        &self,
        tenant: Uuid,
        run: Uuid,
        owner: Uuid,
        reason: String,
    ) -> Result<bool, CoreError> {
        Self::fail_run_queue(self, tenant, run, owner, reason)
            .await
            .map_err(core_error)
    }
    async fn finish_run_queue(
        &self,
        tenant: Uuid,
        run: Uuid,
        owner: Uuid,
    ) -> Result<bool, CoreError> {
        Self::finish_run_queue(self, tenant, run, owner)
            .await
            .map_err(core_error)
    }
    async fn run_queue_finished(&self, tenant: Uuid, run: Uuid) -> Result<bool, CoreError> {
        Self::run_queue_finished(self, tenant, run)
            .await
            .map_err(core_error)
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
pub(crate) mod tests {
    mod capacity;
    mod guard_durable;
    use sqlx::postgres::PgPoolOptions;

    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[test]
    fn runtime_parser_accepts_docker() {
        assert_eq!(runtime_from_str("docker").unwrap(), RuntimeKind::Docker);
    }

    #[test]
    fn runtime_parser_round_trips_every_persisted_runtime() {
        // A hosted sandbox is persisted with the same `runtime` column as any other.
        // Missing the arm makes it unreadable with "invalid persisted runtime", which
        // is indistinguishable from a corrupt row.
        for kind in [
            RuntimeKind::Firecracker,
            RuntimeKind::Docker,
            RuntimeKind::BwrapDev,
            RuntimeKind::Hosted,
        ] {
            assert_eq!(runtime_from_str(kind.as_str()).unwrap(), kind);
        }
        assert!(runtime_from_str("qemu").is_err());
    }

    #[test]
    fn capability_json_round_trips() {
        let capabilities = aiec_core::runtime::RuntimeCapabilities {
            isolation: aiec_core::runtime::RuntimeIsolation::Container,
            exec: true,
            files: true,
            streaming: false,
            ..Default::default()
        };
        let value = serde_json::to_value(capabilities.clone()).unwrap();
        let parsed: aiec_core::runtime::RuntimeCapabilities =
            serde_json::from_value(value).unwrap();
        assert_eq!(parsed, capabilities);
    }
    pub(crate) fn sandbox_record(tenant: Uuid) -> Sandbox {
        sandbox(tenant)
    }

    pub(super) fn sandbox(tenant: Uuid) -> Sandbox {
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
            environment: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        }
    }

    /// The sandbox page is a keyset read, so its correctness lives in the SQL:
    /// the predicate, the ordering, and the row held back to decide whether
    /// `next` exists. None of that is exercised by the in-memory store, whose
    /// filter-and-sort is a different implementation of the same idea.
    #[tokio::test]
    async fn the_sql_sandbox_page_walks_the_whole_history_without_repeating_or_skipping() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        if database_url.is_empty() {
            return;
        }
        let repository = Arc::new(PostgresRepository::connect(&database_url).await.unwrap());
        repository.migrate().await.unwrap();
        let tenant = new_id();
        repository
            .put_tenant(TenantRecord {
                id: tenant,
                name: format!("sandbox-page-{}", tenant),
                created_at: Utc::now(),
            })
            .await
            .unwrap();

        // Stated timestamps, so the expected order is known rather than read
        // back out of whatever the clock happened to do.
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("a valid instant");
        // The tie is placed where the walk rests on it: with a page of four the
        // first page ends on the pair's higher id, so the second page can only
        // contain the other half of the pair if the predicate compares the id
        // as well as the timestamp. A tie at either end of the history would
        // pass under a timestamp-only comparison by luck, because the cursor
        // would never come to rest on it.
        let stamps: Vec<DateTime<Utc>> = (0..8)
            .map(|index| base + chrono::Duration::seconds(index))
            .chain(std::iter::repeat_n(base + chrono::Duration::seconds(7), 2))
            .chain((8..11).map(|index| base + chrono::Duration::seconds(index)))
            .collect();
        let mut expected: Vec<(DateTime<Utc>, Uuid)> = Vec::with_capacity(stamps.len());
        for created_at in stamps {
            let mut value = sandbox(tenant);
            value.created_at = created_at;
            value.updated_at = created_at;
            repository.create_sandbox(value.clone()).await.unwrap();
            expected.push((created_at, value.id));
        }
        expected.sort_by(|a, b| b.cmp(a));
        let newest_first: Vec<Uuid> = expected.iter().map(|(_, id)| *id).collect();

        // Four does not divide twelve, so a cursor that dropped or repeated a
        // single row changes the walk rather than being rounded away.
        //
        // The page length is asserted below, but the query's own `LIMIT` is
        // not: the rows are trimmed in Rust as well, so deleting `LIMIT` from
        // the SQL leaves this test green while the database goes on
        // transferring every row the tenant owns. The statement-level bound is
        // therefore unproven here — it is there to keep the transfer small, and
        // the page bound the length assertion pins holds either way.
        let mut walked = Vec::new();
        let mut cursor: Option<aiec_core::storage::PageCursor> = None;
        let mut guard = 0;
        loop {
            let page = repository.list_sandboxes(tenant, 4, cursor).await.unwrap();
            assert!(
                page.sandboxes.len() <= 4,
                "the query returned more rows than the limit"
            );
            let more = page.next.is_some();
            if let Some(next) = page.next {
                let last = page
                    .sandboxes
                    .last()
                    .expect("a page with a next is not empty");
                assert_eq!(
                    (next.created_at, next.id),
                    (last.created_at, last.id),
                    "the cursor must name the last row returned, not the held-back row"
                );
                cursor = Some(next);
            }
            walked.extend(page.sandboxes.iter().map(|s| s.id));
            guard += 1;
            if !more {
                break;
            }
            assert!(guard <= newest_first.len(), "the cursor never ran out");
        }
        assert_eq!(
            walked, newest_first,
            "the SQL page must reproduce the tenant's sandboxes exactly once, newest first"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// The page is correct in isolation and slow in the worst case if the index
    /// does not carry the tie-breaker. Nothing about correctness detects that:
    /// `created_at DESC, id DESC` reads correctly from `(tenant_id,
    /// created_at DESC)` too, just by sorting everything the index returns
    /// before the `LIMIT` applies. Only the index definition can catch it, so
    /// the definition is asserted the way the guard migrations assert their
    /// own constraints.
    #[tokio::test]
    async fn the_sandbox_list_index_carries_the_keyset_tie_breaker() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        if database_url.is_empty() {
            return;
        }
        let repository = Arc::new(PostgresRepository::connect(&database_url).await.unwrap());
        repository.migrate().await.unwrap();

        let definition: Option<String> = sqlx::query_scalar(
            "SELECT pg_get_indexdef(to_regclass('sandboxes_tenant_created_idx'))",
        )
        .fetch_one(&repository.pool)
        .await
        .expect("the index lookup must run");
        // `to_regclass` rather than a `pg_class` name filter: the test suite
        // creates isolated schemas, and an unscoped name lookup finds whichever
        // of them answers first -- so this assertion could pass or fail
        // depending on which tests ran before it.
        let definition = definition.expect("the sandbox list index must exist in the search path");
        assert!(
            definition.ends_with("(tenant_id, created_at DESC, id DESC)"),
            "a keyset page on (created_at, id) needs both columns in that order; \
             without the tie-breaker the whole tie bucket is sorted before LIMIT \
             applies. Found: {definition}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// The same assertion for the two Guard history listings, whose indexes had
    /// the same missing tie-breaker. Nothing about correctness detects it: the
    /// page reads correctly from `(tenant_id, sandbox_id, created_at DESC)`
    /// too, just by sorting everything tied before the `LIMIT` applies, and
    /// neither table is ever pruned, so the tie bucket only grows.
    #[tokio::test]
    async fn the_guard_history_indexes_carry_the_keyset_tie_breaker() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        if database_url.is_empty() {
            return;
        }
        let repository = Arc::new(PostgresRepository::connect(&database_url).await.unwrap());
        repository.migrate().await.unwrap();

        for index in [
            "guard_proposals_by_sandbox",
            "guard_tool_approvals_by_sandbox",
        ] {
            let definition: Option<String> =
                sqlx::query_scalar("SELECT pg_get_indexdef(to_regclass($1))")
                    .bind(index)
                    .fetch_one(&repository.pool)
                    .await
                    .expect("the index lookup must run");
            let definition =
                definition.unwrap_or_else(|| panic!("{index} must exist in the search path"));
            assert!(
                definition.ends_with("(tenant_id, sandbox_id, created_at DESC, id DESC)"),
                "{index} pages on (created_at, id), so it needs both columns in \
                 that order; without the tie-breaker every row sharing a \
                 timestamp is sorted before LIMIT applies. Found: {definition}"
            );
        }
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// The snapshot listing is the third table that had the same missing
    /// tie-breaker, after the sandbox list and the two Guard histories. Its
    /// index stopped at `created_at`, and the query ordered `created_at DESC,
    /// id` - descending by one column and ascending by the other, which is a
    /// stable order but not the order a descending keyset walks.
    #[tokio::test]
    async fn the_snapshot_list_index_carries_the_keyset_tie_breaker() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        if database_url.is_empty() {
            return;
        }
        let repository = Arc::new(PostgresRepository::connect(&database_url).await.unwrap());
        repository.migrate().await.unwrap();

        let definition: Option<String> =
            sqlx::query_scalar("SELECT pg_get_indexdef(to_regclass($1))")
                .bind("snapshots_tenant_sandbox_idx")
                .fetch_one(&repository.pool)
                .await
                .expect("the index lookup must run");
        let definition = definition.expect("the snapshot list index must exist in the search path");
        assert!(
            definition.ends_with("(tenant_id, sandbox_id, created_at DESC, id DESC)"),
            "the snapshot page keys on (created_at, id) in descending order, so \
             the index needs both columns in that order. Found: {definition}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    async fn schedule_test_sandbox(
        repository: &PostgresRepository,
        tenant: Uuid,
        request_id: Uuid,
        sandbox: Sandbox,
        preferred_worker: Option<Uuid>,
    ) -> Result<ScheduledSandbox, CoreError> {
        PostgresScheduler::new(repository.clone())
            .schedule(ScheduleRequest {
                tenant_id: tenant,
                request_id,
                sandbox,
                preferred_worker,
                lease_ttl: Duration::from_secs(60),
                required_capabilities: Default::default(),
                run_id: None,
            })
            .await
    }

    #[tokio::test]
    async fn concurrent_schedulers_reserve_capacity_once() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        if database_url.is_empty() {
            return;
        }
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
                capabilities: aiec_core::runtime::RuntimeCapabilities {
                    exec: true,
                    files: true,
                    streaming: false,
                    ..Default::default()
                },
                control_endpoint: "https://127.0.0.1:9000".into(),
                total_vcpus: 1,
                total_memory_bytes: 64 * 1_048_576,
                total_disk_bytes: 512 * 1_048_576,
                available_vcpus: 1,
                available_memory_bytes: 64 * 1_048_576,
                available_disk_bytes: 512 * 1_048_576,
                healthy: true,
                version: 1,
                metadata: test_pressure_metadata(
                    tenant,
                    HOST_VCPUS,
                    HOST_MEMORY_BYTES,
                    HOST_DISK_BYTES,
                ),
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
                schedule_test_sandbox(&repository, tenant, new_id(), first, Some(node_id)).await
            }
        });
        let right = tokio::spawn({
            let repository = repository.clone();
            async move {
                schedule_test_sandbox(&repository, tenant, new_id(), second, Some(node_id)).await
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

    /// A placement is refused for capacity, not for having lost a race for the
    /// host's headroom lock. A sibling placement holds that lock for the few
    /// milliseconds its transaction takes, so losing it says nothing about how
    /// much room the host has - and treating it as a full host turned ordinary
    /// concurrency into `no schedulable worker has capacity`. The lock is held
    /// here from another connection, so the collision is the condition under
    /// test rather than something to hope for.
    #[tokio::test]
    async fn a_placement_waits_for_another_placements_host_lock() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_worker_with(
            &repository,
            tenant,
            MEMORY_WORKER.0,
            MEMORY_WORKER.1,
            16_384,
        )
        .await;
        let host = format!("test-host-{tenant}");
        let mut holder = repository.pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('host:' || $1::text, 0))")
            .bind(&host)
            .execute(&mut *holder)
            .await
            .unwrap();
        let placement = tokio::spawn({
            let repository = repository.clone();
            async move {
                schedule_test_sandbox(
                    &repository,
                    tenant,
                    new_id(),
                    sandbox(tenant),
                    Some(node_id),
                )
                .await
            }
        });
        // Held for a moment, then released inside the wait the fix allows.
        tokio::time::sleep(Duration::from_millis(60)).await;
        holder.commit().await.unwrap();
        placement
            .await
            .unwrap()
            .expect("a placement was refused for a lock its holder had already released");
        let worker = repository.get_worker(node_id).await.unwrap();
        assert_eq!(worker.registration.available_vcpus, MEMORY_WORKER.0 - 1);
        assert_eq!(worker.sandbox_count, 1);
    }

    #[tokio::test]
    async fn concurrent_quota_admission_is_serialized() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        sqlx::query(
            "UPDATE tenant_quotas SET max_active_sandboxes=1, max_vcpus=2, \
             max_memory_mb=128, max_disk_mb=1024 WHERE tenant_id=$1",
        )
        .bind(tenant)
        .execute(&repository.pool)
        .await
        .unwrap();
        let left = tokio::spawn({
            let repository = repository.clone();
            async move {
                schedule_test_sandbox(
                    &repository,
                    tenant,
                    new_id(),
                    sandbox(tenant),
                    Some(node_id),
                )
                .await
            }
        });
        let right = tokio::spawn({
            let repository = repository.clone();
            async move {
                schedule_test_sandbox(
                    &repository,
                    tenant,
                    new_id(),
                    sandbox(tenant),
                    Some(node_id),
                )
                .await
            }
        });
        let results = [left.await.unwrap(), right.await.unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(CoreError::QuotaExceeded(_))))
                .count(),
            1
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// A worker of a stated shape on a host of a stated ceiling: the shared
    /// fixtures all declare an implausibly large machine, and this is the one
    /// that has to place against a real number of logical CPUs.
    async fn register_worker_on_host(
        repository: &PostgresRepository,
        tenant: Uuid,
        vcpus: u32,
        host_vcpus: u32,
    ) -> Uuid {
        let node_id = new_id();
        repository
            .register_worker(WorkerRegistration {
                node_id,
                name: format!("cpu-node-{tenant}-{node_id}"),
                runtime: RuntimeKind::Firecracker,
                capabilities: aiec_core::runtime::RuntimeCapabilities {
                    exec: true,
                    files: true,
                    streaming: false,
                    ..Default::default()
                },
                control_endpoint: "https://127.0.0.1:9000".into(),
                total_vcpus: vcpus,
                total_memory_bytes: 128 * 1_048_576,
                total_disk_bytes: 1024 * 1_048_576,
                available_vcpus: vcpus,
                available_memory_bytes: 128 * 1_048_576,
                available_disk_bytes: 1024 * 1_048_576,
                healthy: true,
                version: 1,
                metadata: test_pressure_metadata(
                    tenant,
                    host_vcpus,
                    HOST_MEMORY_BYTES,
                    HOST_DISK_BYTES,
                ),
                started_at: Utc::now(),
                last_heartbeat: Utc::now(),
            })
            .await
            .unwrap();
        node_id
    }

    /// Two workers on one machine each read every vCPU free, and each is right
    /// about its own worker. The machine has eight, so a fourth vCPU on top of
    /// the five the first worker took does not exist: the second placement is
    /// refused even though the worker it names has eight free of its own.
    ///
    /// The vCPUs come back when the placement that spent them is released, and
    /// they come back once - the same request that was refused succeeds
    /// afterwards, against a worker holding exactly what it started with.
    #[tokio::test]
    async fn two_workers_on_one_host_cannot_both_spend_the_machines_vcpus() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        const CEILING: u32 = 8;
        let first = register_worker_on_host(&repository, tenant, CEILING, CEILING).await;
        let second = register_worker_on_host(&repository, tenant, CEILING, CEILING).await;

        let taken = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox_with(tenant, 5, 128, 1024),
            Some(first),
        )
        .await
        .expect("five vCPUs fit a machine that has eight");

        let refused = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox_with(tenant, 4, 128, 1024),
            Some(second),
        )
        .await;
        assert!(
            matches!(&refused, Err(CoreError::Transient(message)) if message.contains("no schedulable worker has capacity")),
            "two workers must not spend more vCPUs than the host has: {refused:?}"
        );
        let untouched = repository.get_worker(second).await.unwrap();
        assert_eq!(
            untouched.registration.available_vcpus, CEILING,
            "the refusal must leave the second worker's own ledger alone"
        );

        // Releasing the first placement hands its five vCPUs back exactly once.
        repository
            .delete_sandbox(tenant, taken.sandbox.id)
            .await
            .unwrap();
        let released = repository.get_worker(first).await.unwrap();
        assert_eq!(released.registration.available_vcpus, CEILING);
        assert_eq!(released.sandbox_count, 0);
        schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox_with(tenant, 4, 128, 1024),
            Some(second),
        )
        .await
        .expect("the vCPUs a released placement held are spendable again");

        // A host whose ceiling nobody could observe lends no CPU at all, however
        // perfectly it measured memory and disk: a missing measurement is not a
        // measurement of unlimited capacity.
        sqlx::query(
            "UPDATE nodes SET metadata = jsonb_set(metadata, '{pressure}', \
             (metadata #> '{pressure}') - 'total_vcpus' - 'available_vcpus') \
             WHERE id = ANY($1::uuid[])",
        )
        .bind(vec![first, second])
        .execute(&repository.pool)
        .await
        .unwrap();
        let unmeasured = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox_with(tenant, 1, 128, 1024),
            Some(first),
        )
        .await;
        assert!(
            matches!(&unmeasured, Err(CoreError::Transient(message)) if message.contains("no schedulable worker has capacity")),
            "a host whose ceiling was never observed must refuse: {unmeasured:?}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    async fn repository_and_tenant() -> Option<(Arc<PostgresRepository>, Uuid)> {
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())?;
        let repository = Arc::new(
            PostgresRepository::connect(database_url.trim())
                .await
                .unwrap(),
        );
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

    // Recovery and sweep queries cross tenants, so a fresh tenant alone cannot
    // isolate their inputs from other tests or rows left by previous runs.
    pub(crate) async fn isolated_repository_and_tenant()
    -> Option<(Arc<PostgresRepository>, Uuid, sqlx::PgPool, String)> {
        let url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("storage_test_{}", new_id().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let search_path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .after_connect(move |connection, _| {
                let search_path = search_path.clone();
                Box::pin(async move {
                    sqlx::query(&search_path).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        let repository = Arc::new(PostgresRepository::from_pool(pool));
        repository.migrate().await.unwrap();
        let tenant = new_id();
        repository
            .put_tenant(TenantRecord {
                id: tenant,
                name: format!("storage-invariant-{tenant}"),
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        Some((repository, tenant, admin, schema))
    }

    pub(crate) async fn drop_test_schema(
        repository: &PostgresRepository,
        admin: sqlx::PgPool,
        schema: String,
    ) {
        repository.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }

    async fn register_test_worker(repository: &PostgresRepository, tenant: Uuid) -> Uuid {
        let node_id = new_id();
        repository
            .register_worker(WorkerRegistration {
                node_id,
                name: format!("node-{}-{node_id}", tenant),
                runtime: RuntimeKind::Firecracker,
                capabilities: aiec_core::runtime::RuntimeCapabilities {
                    exec: true,
                    files: true,
                    streaming: false,
                    ..Default::default()
                },
                control_endpoint: "https://127.0.0.1:9000".into(),
                total_vcpus: 2,
                total_memory_bytes: 128 * 1_048_576,
                total_disk_bytes: 1024 * 1_048_576,
                available_vcpus: 2,
                available_memory_bytes: 128 * 1_048_576,
                available_disk_bytes: 1024 * 1_048_576,
                healthy: true,
                version: 1,
                metadata: test_pressure_metadata(
                    tenant,
                    HOST_VCPUS,
                    HOST_MEMORY_BYTES,
                    HOST_DISK_BYTES,
                ),
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
        let _scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
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

    /// A worker that holds no active lease is refused *and* left unrefreshed.
    ///
    /// The refusal is the easy half. The row is the point: the heartbeat used
    /// to update `nodes` first and check ownership afterwards, so a worker
    /// whose leases had all expired or been released - whose capacity had
    /// already been taken back - still had its `last_heartbeat` refreshed and
    /// stayed healthy in the placement pool, and the CLI keeps beating every
    /// five seconds after a 409. The node here is aged by an hour first, so
    /// the assertion distinguishes "the row was left alone" from "the row was
    /// written and the error was still produced".
    #[tokio::test]
    async fn a_heartbeat_claiming_sandboxes_without_a_lease_leaves_the_row_alone() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        let claimed = repository
            .claim_worker_assignments(node_id, 1, 60)
            .await
            .unwrap();
        expire_lease(&repository, claimed[0].lease.id).await;
        sqlx::query("UPDATE nodes SET last_heartbeat=now()-interval '1 hour' WHERE id=$1")
            .bind(node_id)
            .execute(&repository.pool)
            .await
            .unwrap();
        let aged = repository.get_worker(node_id).await.unwrap();

        let error = repository
            .heartbeat_worker(WorkerHeartbeat {
                node_id,
                sandbox_count: 1,
                healthy: true,
                version: 1,
                metadata: json!({}),
                last_error: None,
            })
            .await
            .expect_err("a worker with no active lease must not be recorded as serving");
        match error {
            StoreError::Conflict(message) => assert!(
                message.contains("no active lease"),
                "the refusal must say what the control plane found: {message}"
            ),
            other => panic!("expected a conflict, got {other:?}"),
        }

        let after = repository.get_worker(node_id).await.unwrap();
        assert_eq!(
            after.registration.last_heartbeat, aged.registration.last_heartbeat,
            "the refused heartbeat refreshed the row anyway, leaving a worker \
             that owns nothing in the placement pool"
        );
        assert_eq!(
            after.observed_sandbox_count, aged.observed_sandbox_count,
            "the refused heartbeat recorded a sandbox count it does not have"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    #[tokio::test]
    async fn lease_revocation_cannot_race_a_healthy_heartbeat() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        let mut revoke = repository.pool.begin().await.unwrap();
        sqlx::query("UPDATE sandbox_leases SET status='expired', expires_at=now()-interval '1 second' WHERE id=$1")
            .bind(scheduled.lease_id).execute(&mut *revoke).await.unwrap();
        sqlx::query(
            "UPDATE nodes SET healthy=false, last_heartbeat=now()-interval '1 hour' WHERE id=$1",
        )
        .bind(node_id)
        .execute(&mut *revoke)
        .await
        .unwrap();
        // The isolated pool has two connections: revoke holds one, and the
        // heartbeat uses this other backend. Wait for an actual database lock,
        // not a timing assumption about which task has reached its UPDATE.
        let mut connection = repository.pool.acquire().await.unwrap();
        let heartbeat_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        drop(connection);
        let heartbeats = repository.clone();
        let beat = tokio::spawn(async move {
            heartbeats
                .heartbeat_worker(WorkerHeartbeat {
                    node_id,
                    sandbox_count: 1,
                    healthy: true,
                    version: 1,
                    metadata: json!({}),
                    last_error: None,
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let blocked: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",
                ).bind(heartbeat_pid).fetch_one(&admin).await.unwrap();
                if blocked { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("heartbeat did not reach the held database lock");
        revoke.commit().await.unwrap();
        let result = beat.await.unwrap();
        let after = repository.get_worker(node_id).await.unwrap();
        drop_test_schema(&repository, admin, schema).await;
        assert!(
            matches!(result, Err(StoreError::Conflict(_))),
            "a revoked owner refreshed the node instead of refusing the heartbeat"
        );
        assert!(!after.registration.healthy);
        assert_eq!(after.observed_sandbox_count, 0);
    }

    #[tokio::test]
    async fn active_lease_lookup_and_renewal_are_durable_but_expiry_blocks_completion() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
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

    async fn expire_lease(repository: &PostgresRepository, lease_id: Uuid) {
        sqlx::query("UPDATE sandbox_leases SET expires_at=now()-interval '1 second' WHERE id=$1")
            .bind(lease_id)
            .execute(&repository.pool)
            .await
            .unwrap();
    }

    async fn mark_worker_dead(repository: &PostgresRepository, node_id: Uuid) {
        sqlx::query(
            "UPDATE nodes SET healthy=false, last_heartbeat=now()-interval '1 hour' WHERE id=$1",
        )
        .bind(node_id)
        .execute(&repository.pool)
        .await
        .unwrap();
    }

    /// Host-scale headroom, deliberately far larger than any node's own
    /// allocation. A node advertises what it was allocated; the host is a
    /// machine several nodes share, and admission is checked against the
    /// machine.
    const HOST_MEMORY_BYTES: u64 = 64 * 1_073_741_824;
    /// Larger than the biggest sandbox any fixture places (a ~976 GiB
    /// disk-shaped one), because admission is checked against the machine and
    /// every fixture worker shares one.
    const HOST_DISK_BYTES: u64 = 2 * 1_099_511_627_776;
    /// Logical CPUs of the machine those fixtures share. Deliberately far
    /// above every node's own allocation, because CPU is a ceiling the whole
    /// host is capped against rather than a store each worker fills: a fixture
    /// that declared a realistic ceiling would have every test placing against
    /// it, and the tests that are about placement are not about CPU. The one
    /// test that is states its own ceiling through `test_pressure_metadata`.
    const HOST_VCPUS: u32 = 256;

    /// The worker metadata a real worker publishes: a host pressure reading,
    /// which the scheduler requires before it will place anything.
    ///
    /// Scoped to the tenant so two tests running against one database do not
    /// aggregate their workers into one imaginary machine, while the several
    /// workers a single test registers still share a host as they would in a
    /// cluster. Absent figures are refused by design - a worker that never
    /// published a reading is one nobody asked about, and refusing to place on
    /// it is the point of the gate.
    fn test_pressure_metadata(
        tenant: Uuid,
        host_vcpus: u32,
        host_memory_bytes: u64,
        host_disk_bytes: u64,
    ) -> Value {
        json!({
            "pressure": aiec_core::host_pressure::HostPressure::from_measurements(
                format!("test-host-{tenant}"),
                chrono::Utc::now(),
                aiec_core::host_pressure::HostMeasurements {
                    total_vcpus: Some(host_vcpus),
                    available_vcpus: Some(host_vcpus),
                    total_memory_bytes: Some(host_memory_bytes),
                    memory_available_bytes: Some(host_memory_bytes),
                    total_disk_bytes: Some(host_disk_bytes),
                    disk_available_bytes: Some(host_disk_bytes),
                },
                aiec_core::host_pressure::HostReserves::from_mib(0, 0),
            )
            .to_metadata(),
        })
    }

    /// Registers a worker of an explicit shape so a recovery test can use a sandbox that
    /// only workers of that shape can hold.
    async fn register_worker_with(
        repository: &PostgresRepository,
        tenant: Uuid,
        vcpus: u32,
        memory_mb: u64,
        disk_mb: u64,
    ) -> Uuid {
        let node_id = new_id();
        let memory_bytes = memory_mb * 1_048_576;
        let disk_bytes = disk_mb * 1_048_576;
        repository
            .register_worker(WorkerRegistration {
                node_id,
                name: format!("recovery-node-{tenant}-{node_id}"),
                runtime: RuntimeKind::Firecracker,
                capabilities: aiec_core::runtime::RuntimeCapabilities {
                    exec: true,
                    files: true,
                    streaming: false,
                    ..Default::default()
                },
                control_endpoint: "https://127.0.0.1:9000".into(),
                total_vcpus: vcpus,
                total_memory_bytes: memory_bytes,
                total_disk_bytes: disk_bytes,
                available_vcpus: vcpus,
                available_memory_bytes: memory_bytes,
                available_disk_bytes: disk_bytes,
                healthy: true,
                version: 1,
                metadata: test_pressure_metadata(
                    tenant,
                    HOST_VCPUS,
                    HOST_MEMORY_BYTES,
                    HOST_DISK_BYTES,
                ),
                started_at: Utc::now(),
                last_heartbeat: Utc::now(),
            })
            .await
            .unwrap();
        node_id
    }

    fn sandbox_with(tenant: Uuid, vcpus: u32, memory_mb: u32, disk_mb: u32) -> Sandbox {
        let mut value = sandbox(tenant);
        value.cpu = vcpus;
        value.memory_mb = memory_mb;
        value.disk_mb = disk_mb;
        value
    }

    /// Snapshot of every worker's debited vCPUs and sandbox count, taken around a
    /// reassignment so the capacity it moves can be asserted whichever worker is chosen.
    async fn node_capacity(
        repository: &PostgresRepository,
    ) -> std::collections::HashMap<Uuid, (i32, i32)> {
        let rows = sqlx::query("SELECT id, available_vcpus, sandbox_count FROM nodes")
            .fetch_all(&repository.pool)
            .await
            .unwrap();
        rows.iter()
            .map(|row| {
                (
                    row.try_get::<Uuid, _>("id").unwrap(),
                    (
                        row.try_get::<i32, _>("available_vcpus").unwrap(),
                        row.try_get::<i32, _>("sandbox_count").unwrap(),
                    ),
                )
            })
            .collect()
    }

    /// Resource shapes exercise memory-heavy and disk-heavy recovery separately.
    const MEMORY_WORKER: (u32, u64, u64) = (32, 61_000, 4_096);
    const MEMORY_SANDBOX: (u32, u32, u32) = (31, 60_000, 3_072);
    const DISK_WORKER: (u32, u64, u64) = (32, 4_096, 1_010_000);
    const DISK_SANDBOX: (u32, u32, u32) = (31, 3_072, 1_000_000);

    /// A lease renewed between the ownership read and the state change is still ours.
    ///
    /// `renew_worker_lease` increments the generation of the lease it extends, and
    /// `claim_worker_assignments` does the same when a worker claims its assignment.
    /// A control plane that read ownership a moment before either of those commits
    /// holds a lease that is still its own at an older generation. Comparing the two
    /// generations for equality refused exactly that caller, on a sandbox nobody had
    /// taken from it, which is how a lifecycle change on a live machine came back as
    /// a stale generation and was indistinguishable from a genuine takeover.
    #[tokio::test]
    async fn a_lease_renewed_after_the_ownership_read_still_owns_the_change() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        let claimed = repository
            .claim_worker_assignments(node_id, 1, 60)
            .await
            .unwrap();
        let lease_id = claimed[0].lease.id;
        let read = claimed[0].lease.generation;
        let sandbox_id = scheduled.sandbox.id;

        // The renewal lands between this caller's ownership read and its change.
        let renewed = repository
            .renew_worker_lease(tenant, lease_id, read, 60)
            .await
            .unwrap();
        assert_eq!(renewed.generation, read + 1);
        assert_eq!(renewed.id, lease_id, "a renewal keeps the lease");

        repository
            .update_state_with_lease(
                tenant,
                sandbox_id,
                SandboxState::Creating,
                SandboxState::Starting,
                lease_id,
                read,
            )
            .await
            .expect("a renewal must not be read as a reassignment");
        assert_eq!(
            repository
                .get_sandbox(tenant, sandbox_id)
                .await
                .unwrap()
                .state,
            SandboxState::Starting
        );

        // The renewed generation is accepted too, so the caller that re-read
        // ownership after the renewal is not the only one that can commit.
        repository
            .update_state_with_lease(
                tenant,
                sandbox_id,
                SandboxState::Starting,
                SandboxState::Running,
                lease_id,
                renewed.generation,
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .get_sandbox(tenant, sandbox_id)
                .await
                .unwrap()
                .state,
            SandboxState::Running
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// A renewal racing the fenced change changes nothing about the outcome.
    ///
    /// The renewal and the state change are separate transactions, so either can commit
    /// first. Both orders describe the same owner: the lease is the same lease either
    /// way, and a fence that refused one of the two orders would be refusing a sandbox
    /// nobody had taken over. Run against a real database rather than a mock, because
    /// the interleaving is what the fence has to be correct about.
    #[tokio::test]
    async fn a_renewal_concurrent_with_a_fenced_change_never_refuses_the_owner() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        let claimed = repository
            .claim_worker_assignments(node_id, 1, 60)
            .await
            .unwrap();
        let lease = claimed[0].lease.clone();
        let sandbox_id = scheduled.sandbox.id;
        // Renewals only ever move forward, so each round reads the generation this
        // owner currently holds rather than reusing the one it started with.
        let mut owned = lease.clone();
        for _ in 0..8 {
            let (renewed, changed) = tokio::join!(
                repository.renew_worker_lease(tenant, lease.id, owned.generation, 60),
                repository.update_state_with_lease(
                    tenant,
                    sandbox_id,
                    SandboxState::Creating,
                    SandboxState::Starting,
                    lease.id,
                    owned.generation,
                ),
            );
            assert!(
                changed.is_ok(),
                "the owner was refused while its own lease was being renewed: {changed:?}"
            );
            assert!(renewed.is_ok(), "the renewal itself must succeed");
            owned = repository.get_worker_lease(tenant, lease.id).await.unwrap();
            assert_eq!(owned.status, "active", "the lease stays the owner's");
        }
        assert_eq!(
            repository
                .get_sandbox(tenant, sandbox_id)
                .await
                .unwrap()
                .state,
            SandboxState::Starting
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// A lease that no longer owns the sandbox is refused at any generation, including
    /// the replacement's own higher one.
    ///
    /// A fence that reasoned about the number rather than the lease would have to take
    /// this caller's side here, because the generation it presents is the higher one.
    /// That is precisely the direction that lets a dead owner keep committing after
    /// recovery handed the sandbox to a replacement.
    #[tokio::test]
    async fn a_previous_owner_is_refused_even_at_its_replacements_generation() {
        // Isolated: reassignment deliberately picks any healthy worker, so on
        // the shared schema this test would take another test's node - and a
        // test running beside it would then find its own worker already full.
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let (vcpus, memory_mb, disk_mb) = MEMORY_WORKER;
        let dead_node = register_worker_with(&repository, tenant, vcpus, memory_mb, disk_mb).await;
        let _replacement_worker =
            register_worker_with(&repository, tenant, vcpus, memory_mb, disk_mb).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox_with(tenant, MEMORY_SANDBOX.0, MEMORY_SANDBOX.1, MEMORY_SANDBOX.2),
            Some(dead_node),
        )
        .await
        .unwrap();
        let claimed = repository
            .claim_worker_assignments(dead_node, 1, 60)
            .await
            .unwrap();
        let dead_lease = claimed[0].lease.id;
        let sandbox_id = scheduled.sandbox.id;
        mark_worker_dead(&repository, dead_node).await;
        expire_lease(&repository, dead_lease).await;
        let recovery = repository
            .reassign_expired_lease(dead_lease)
            .await
            .unwrap()
            .expect("an expired lease of a dead worker is reassigned");
        assert_ne!(recovery.lease.id, dead_lease, "recovery issues a new lease");

        // The generation recovery published, and one further ahead of it.
        for supplied_generation in [recovery.lease.generation, recovery.lease.generation + 1] {
            let error = repository
                .update_state_with_lease(
                    tenant,
                    sandbox_id,
                    SandboxState::Creating,
                    SandboxState::Starting,
                    dead_lease,
                    supplied_generation,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(
                    &error,
                    StoreError::Transient(message)
                        if message == "sandbox lease was reassigned to another owner"
                ),
                "the previous owner must be refused whatever it presents: {error}"
            );
            assert_eq!(
                repository
                    .get_sandbox(tenant, sandbox_id)
                    .await
                    .unwrap()
                    .state,
                SandboxState::Creating
            );
        }
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            drop_test_schema(&repository, admin, schema),
        )
        .await;
    }

    /// An expired lease is not an owner, and the fence fails closed on it.
    ///
    /// The row is still `active`: expiry is a timestamp, and recovery is what turns it
    /// into a replacement. Until then the sandbox has no unexpired owner, so the honest
    /// answer is that nobody may commit on this lease's behalf - which is a different
    /// refusal from a reassignment, and says so.
    #[tokio::test]
    async fn an_expired_or_absent_lease_cannot_commit_and_says_which_it_was() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        let claimed = repository
            .claim_worker_assignments(node_id, 1, 60)
            .await
            .unwrap();
        let lease = claimed[0].lease.clone();
        let sandbox_id = scheduled.sandbox.id;
        expire_lease(&repository, lease.id).await;
        let error = repository
            .update_state_with_lease(
                tenant,
                sandbox_id,
                SandboxState::Creating,
                SandboxState::Starting,
                lease.id,
                lease.generation,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                StoreError::Transient(message)
                    if message == "sandbox has no active unexpired lease"
            ),
            "expiry must fail closed, and be distinguishable from a takeover: {error}"
        );
        assert_eq!(
            repository
                .get_sandbox(tenant, sandbox_id)
                .await
                .unwrap()
                .state,
            SandboxState::Creating
        );

        // Another sandbox's lease is not an owner of this one either, so a live lease
        // somewhere cannot stand in for a missing fence here.
        let unleased = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        assert!(
            matches!(
                repository
                    .update_state_with_lease(
                        tenant,
                        unleased.sandbox.id,
                        SandboxState::Creating,
                        SandboxState::Starting,
                        lease.id,
                        lease.generation,
                    )
                    .await,
                Err(StoreError::Transient(message))
                    if message == "sandbox lease was reassigned to another owner"
            ),
            "another sandbox's lease must not fence this one"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// A generation ahead of the lease it names belongs to no issued state.
    ///
    /// Generations only move forward on a lease, so a caller holding a number above the
    /// stored one is not describing this lease. It is refused as a conflict rather than
    /// as a retryable race, because retrying cannot make the number become true.
    #[tokio::test]
    async fn a_generation_ahead_of_its_own_lease_is_refused() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        let claimed = repository
            .claim_worker_assignments(node_id, 1, 60)
            .await
            .unwrap();
        let lease = claimed[0].lease.clone();
        let sandbox_id = scheduled.sandbox.id;
        let error = repository
            .update_state_with_lease(
                tenant,
                sandbox_id,
                SandboxState::Creating,
                SandboxState::Starting,
                lease.id,
                lease.generation + 1,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                StoreError::Conflict(message)
                    if message == "sandbox lease generation is ahead of its lease"
            ),
            "an unissued generation must be refused: {error}"
        );
        assert_eq!(
            repository
                .get_sandbox(tenant, sandbox_id)
                .await
                .unwrap()
                .state,
            SandboxState::Creating
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// Endpoint and fencing identity come from one lease, so a dispatch can never pair
    /// a worker's address with another lease's generation.
    #[tokio::test]
    async fn dispatch_target_reports_the_endpoint_and_identity_of_one_lease() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        let scheduler = PostgresScheduler::new(repository.as_ref().clone());
        let dispatch = scheduler
            .dispatch_target(tenant, scheduled.sandbox.id)
            .await
            .unwrap();
        assert_eq!(dispatch.lease_id, scheduled.lease_id);
        assert_eq!(dispatch.generation, scheduled.lease_generation);
        assert_eq!(
            dispatch.endpoint,
            sqlx::query_scalar::<_, String>("SELECT control_endpoint FROM nodes WHERE id = $1")
                .bind(node_id)
                .fetch_one(&repository.pool)
                .await
                .unwrap()
        );

        // A renewal moves the generation the next dispatch carries, under the same lease.
        let renewed = repository
            .renew_worker_lease(tenant, scheduled.lease_id, scheduled.lease_generation, 60)
            .await
            .unwrap();
        let after = scheduler
            .dispatch_target(tenant, scheduled.sandbox.id)
            .await
            .unwrap();
        assert_eq!(after.lease_id, scheduled.lease_id);
        assert_eq!(after.generation, renewed.generation);

        // An expired lease is not an owner, so it is not a dispatch target either:
        // handing back its endpoint would send work to a machine that has lost it.
        expire_lease(&repository, scheduled.lease_id).await;
        assert!(
            matches!(
                scheduler
                    .dispatch_target(tenant, scheduled.sandbox.id)
                    .await,
                Err(CoreError::NotFound(_))
            ),
            "an expired lease must not remain a dispatch target"
        );
        assert!(matches!(
            scheduler.dispatch_target(tenant, new_id()).await,
            Err(CoreError::NotFound(_))
        ));
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    #[tokio::test]
    async fn a_workspace_snapshot_is_storable_and_restorable() {
        // Regression: completeness used to require memory and disk objects for
        // every snapshot kind, and the capture path inserted the same row twice,
        // so a workspace snapshot could never be stored. Recovery restores
        // exactly this row, so it has to round-trip.
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let (vcpus, memory_mb, disk_mb) = MEMORY_WORKER;
        let node = register_worker_with(&repository, tenant, vcpus, memory_mb, disk_mb).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox_with(tenant, MEMORY_SANDBOX.0, MEMORY_SANDBOX.1, MEMORY_SANDBOX.2),
            Some(node),
        )
        .await
        .unwrap();
        let snapshot_id = new_id();
        let object_key = format!("{}-{}", scheduled.sandbox.id, new_id());
        repository
            .put_stored_snapshot(StoredSnapshot {
                id: snapshot_id,
                tenant_id: tenant,
                sandbox_id: scheduled.sandbox.id,
                object_key: object_key.clone(),
                manifest_object_key: format!("{object_key}.manifest.json"),
                memory_object_key: None,
                disk_object_key: None,
                workspace_object_key: Some(object_key.clone()),
                size_bytes: 128,
                image_id: scheduled.sandbox.image_id.clone(),
                checksum_sha256: "a".repeat(64),
                kind: "workspace".to_string(),
                manifest: serde_json::json!({"kind": "workspace"}),
                complete: true,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let stored = repository
            .get_stored_snapshot(tenant, snapshot_id)
            .await
            .unwrap();
        assert_eq!(stored.kind, "workspace");
        assert!(stored.complete);
        assert_eq!(stored.workspace_object_key.as_deref(), Some(&*object_key));
        let recoverable = repository
            .latest_stored_snapshot(tenant, scheduled.sandbox.id, "workspace")
            .await
            .unwrap();
        assert_eq!(
            recoverable.map(|entry| entry.id),
            Some(snapshot_id),
            "recovery would not find the workspace archive"
        );
    }

    #[tokio::test]
    async fn reassignment_moves_the_sandbox_and_fences_the_dead_owner() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let (vcpus, memory_mb, disk_mb) = MEMORY_WORKER;
        let dead_node = register_worker_with(&repository, tenant, vcpus, memory_mb, disk_mb).await;
        let second_worker =
            register_worker_with(&repository, tenant, vcpus, memory_mb, disk_mb).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox_with(tenant, MEMORY_SANDBOX.0, MEMORY_SANDBOX.1, MEMORY_SANDBOX.2),
            Some(dead_node),
        )
        .await
        .unwrap();
        let claimed = repository
            .claim_worker_assignments(dead_node, 1, 60)
            .await
            .unwrap();
        let dead_lease = claimed[0].lease.id;
        let dead_generation = claimed[0].lease.generation;
        let sandbox_id = scheduled.sandbox.id;
        for (expected, next) in [
            (SandboxState::Creating, SandboxState::Starting),
            (SandboxState::Starting, SandboxState::Running),
        ] {
            repository
                .update_state_with_lease(
                    tenant,
                    sandbox_id,
                    expected,
                    next,
                    dead_lease,
                    dead_generation,
                )
                .await
                .unwrap();
        }
        let before = node_capacity(&repository).await;
        mark_worker_dead(&repository, dead_node).await;
        expire_lease(&repository, scheduled.lease_id).await;
        let recovery = repository
            .reassign_expired_lease(scheduled.lease_id)
            .await
            .unwrap()
            .expect("an expired lease of a dead worker is reassigned");
        let replacement = recovery.lease.node_id;
        assert_eq!(replacement, second_worker);
        assert_eq!(recovery.lease.generation, dead_generation + 1);
        assert_eq!(recovery.lease.status, "active");
        assert!(recovery.lease.expires_at > Utc::now());
        assert_eq!(recovery.sandbox.id, sandbox_id);
        assert_eq!(recovery.sandbox.node_id, Some(replacement));
        assert_eq!(recovery.sandbox.state, SandboxState::Creating);
        assert_eq!(
            repository
                .get_sandbox(tenant, sandbox_id)
                .await
                .unwrap()
                .node_id,
            Some(replacement)
        );
        let after = node_capacity(&repository).await;
        let (dead_vcpus, dead_count) = before[&dead_node];
        assert_eq!(after[&dead_node], (dead_vcpus + 31, dead_count - 1));
        let (replacement_vcpus, replacement_count) = before[&replacement];
        assert_eq!(
            after[&replacement],
            (replacement_vcpus - 31, replacement_count + 1)
        );
        let reclaimed = repository
            .claim_worker_assignments(replacement, 1, 60)
            .await
            .unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].lease.id, recovery.lease.id);
        let ownership = repository
            .sandbox_ownership(sandbox_id)
            .await
            .unwrap()
            .expect("the reassigned sandbox has an owner");
        assert_eq!(ownership.lease_id, recovery.lease.id);
        assert_eq!(ownership.node_id, replacement);
        assert_eq!(ownership.generation, reclaimed[0].lease.generation);
        let expired = repository
            .get_worker_lease(tenant, scheduled.lease_id)
            .await
            .unwrap();
        assert_eq!(expired.status, "expired");
        assert_eq!(expired.reason.as_deref(), Some("lease_expired_recovery"));
        assert!(
            repository
                .complete_worker_lease(
                    tenant,
                    scheduled.lease_id,
                    dead_generation,
                    json!({ "ok": true }),
                )
                .await
                .is_err()
        );
        let late = repository
            .update_state_with_lease(
                tenant,
                sandbox_id,
                SandboxState::Creating,
                SandboxState::Starting,
                dead_lease,
                dead_generation,
            )
            .await;
        assert!(
            matches!(
                late,
                Err(StoreError::Transient(message))
                    if message == "sandbox lease was reassigned to another owner"
            ),
            "the previous owner must be refused after recovery moved the sandbox"
        );
        assert_eq!(
            repository
                .get_sandbox(tenant, sandbox_id)
                .await
                .unwrap()
                .state,
            SandboxState::Creating
        );
        repository
            .update_state_with_lease(
                tenant,
                sandbox_id,
                SandboxState::Creating,
                SandboxState::Starting,
                ownership.lease_id,
                ownership.generation,
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .get_sandbox(tenant, sandbox_id)
                .await
                .unwrap()
                .state,
            SandboxState::Starting
        );
        assert!(
            repository
                .reassign_expired_lease(scheduled.lease_id)
                .await
                .unwrap()
                .is_none()
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    #[tokio::test]
    async fn reassignment_refuses_a_live_lease_and_an_unknown_lease() {
        // Isolated: this test reassigns, and reassignment may pick any healthy
        // worker. On the shared schema that is another test's node.
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let node_id = register_test_worker(&repository, tenant).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        assert!(
            repository
                .reassign_expired_lease(scheduled.lease_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .reassign_expired_lease(new_id())
                .await
                .unwrap()
                .is_none()
        );
        let lease = repository
            .get_worker_lease(tenant, scheduled.lease_id)
            .await
            .unwrap();
        assert_eq!(lease.status, "active");
        assert_eq!(
            repository
                .get_sandbox(tenant, scheduled.sandbox.id)
                .await
                .unwrap()
                .node_id,
            Some(node_id)
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    #[tokio::test]
    async fn reassignment_recovers_a_lease_the_reconciler_already_expired() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let (vcpus, memory_mb, disk_mb) = DISK_WORKER;
        let dead_node = register_worker_with(&repository, tenant, vcpus, memory_mb, disk_mb).await;
        let second_worker =
            register_worker_with(&repository, tenant, vcpus, memory_mb, disk_mb).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox_with(tenant, DISK_SANDBOX.0, DISK_SANDBOX.1, DISK_SANDBOX.2),
            Some(dead_node),
        )
        .await
        .unwrap();
        let before = node_capacity(&repository).await;
        mark_worker_dead(&repository, dead_node).await;
        expire_lease(&repository, scheduled.lease_id).await;
        // The reconciler works in bounded batches, so drain until this lease is expired.
        let mut reconciled_here = false;
        for _ in 0..10 {
            let actions = repository.reconcile_expired_leases(100).await.unwrap();
            if actions
                .iter()
                .any(|action| action.lease_id == Some(scheduled.lease_id))
            {
                reconciled_here = true;
                break;
            }
        }
        assert!(
            reconciled_here,
            "the reconciler expired the dead owner's lease"
        );
        let reconciled = node_capacity(&repository).await;
        let (dead_vcpus, dead_count) = before[&dead_node];
        assert_eq!(reconciled[&dead_node], (dead_vcpus + 31, dead_count - 1));
        // The capacity release already happened, so recovery must not release it again.
        let recovery = repository
            .reassign_expired_lease(scheduled.lease_id)
            .await
            .unwrap()
            .expect("a lease the reconciler expired is still recoverable");
        assert_eq!(recovery.lease.generation, scheduled.lease_generation + 1);
        assert_eq!(recovery.lease.node_id, second_worker);
        assert_eq!(recovery.sandbox.node_id, Some(recovery.lease.node_id));
        assert_eq!(recovery.sandbox.state, SandboxState::Creating);
        let after = node_capacity(&repository).await;
        assert_eq!(after[&dead_node], reconciled[&dead_node]);
        let (replacement_vcpus, replacement_count) = before[&recovery.lease.node_id];
        assert_eq!(
            after[&recovery.lease.node_id],
            (replacement_vcpus - 31, replacement_count + 1)
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    fn audit_event(
        tenant: Option<Uuid>,
        action: &str,
        result: &str,
        occurred_at: DateTime<Utc>,
    ) -> AuditEvent {
        AuditEvent {
            id: new_id(),
            occurred_at,
            tenant_id: tenant,
            actor: "user:operator".into(),
            action: action.into(),
            subject_type: "sandbox".into(),
            subject_id: Some(new_id().to_string()),
            result: result.into(),
            request_id: Some(new_id()),
            remote_addr: Some("203.0.113.7".into()),
            detail: json!({"cpu": 1, "runtime": "firecracker"}),
        }
    }

    /// A timestamp a Postgres `timestamptz` round-trips exactly, so a read-back
    /// audit event can be compared field by field instead of by proximity.
    fn whole_microsecond_ago(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_micros(Utc::now().timestamp_micros() - seconds * 1_000_000)
            .expect("a timestamp a minute ago is representable")
    }

    #[tokio::test]
    async fn audit_events_are_durable_filterable_and_append_only() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let other_tenant = new_id();
        let first = audit_event(
            Some(tenant),
            "sandbox.create",
            "success",
            whole_microsecond_ago(30),
        );
        let second = audit_event(
            Some(tenant),
            "sandbox.destroy",
            "denied",
            whole_microsecond_ago(20),
        );
        let system = audit_event(None, "worker.drain", "success", whole_microsecond_ago(10));
        for event in [&first, &second, &system] {
            repository.append_audit_event(event.clone()).await.unwrap();
        }
        // A second connection proves the trail is durable rather than an artifact of
        // the session that wrote it.
        let reopened = PostgresRepository::connect(&database_url()).await.unwrap();
        let everything = reopened.list_audit_events(None, None, 100).await.unwrap();
        assert!(
            [first.id, second.id, system.id]
                .iter()
                .all(|id| everything.iter().any(|event| event.id == *id)),
            "every appended event survives a reconnect, read back {:?}",
            everything
                .iter()
                .map(|event| (event.id, event.action.clone()))
                .collect::<Vec<_>>()
        );
        let round_tripped = everything
            .iter()
            .find(|event| event.id == first.id)
            .expect("the first event is readable");
        assert_eq!(
            *round_tripped, first,
            "an audit event round-trips unchanged"
        );
        // Newest first, and the system event has no tenant to group it.
        let positions: Vec<usize> = [first.id, second.id, system.id]
            .iter()
            .map(|id| {
                everything
                    .iter()
                    .position(|event| event.id == *id)
                    .expect("an appended event is in the page")
            })
            .collect();
        assert!(
            positions[2] < positions[1] && positions[1] < positions[0],
            "events are listed newest first, got {positions:?}"
        );
        assert_eq!(system.tenant_id, None);

        let scoped = reopened
            .list_audit_events(Some(tenant), None, 100)
            .await
            .unwrap();
        assert!(
            scoped.iter().all(|event| event.tenant_id == Some(tenant)),
            "a tenant filter never leaks another tenant's events"
        );
        assert!(
            !scoped.iter().any(|event| event.id == system.id),
            "a system event belongs to no tenant"
        );
        let unrelated = reopened
            .list_audit_events(Some(other_tenant), None, 100)
            .await
            .unwrap();
        assert!(
            unrelated
                .iter()
                .all(|event| event.id != first.id && event.id != second.id),
            "another tenant never sees these events"
        );
        let by_action = reopened
            .list_audit_events(None, Some("sandbox.create"), 100)
            .await
            .unwrap();
        assert!(
            by_action
                .iter()
                .all(|event| event.action == "sandbox.create"),
            "an action filter only returns that action"
        );
        let both = reopened
            .list_audit_events(Some(tenant), Some("sandbox.destroy"), 100)
            .await
            .unwrap();
        assert!(
            both.iter().any(|event| event.id == second.id)
                && !both.iter().any(|event| event.id == first.id),
            "tenant and action filters intersect"
        );
        // The limit is a page size, not a threshold: asking for more than the clamp
        // returns the newest page, and zero still returns the oldest of the clamp.
        let capped = reopened.list_audit_events(None, None, 5_000).await.unwrap();
        assert!(
            capped.len() <= 1_000,
            "an oversized limit is clamped instead of honoured"
        );
        let one = reopened.list_audit_events(None, None, 0).await.unwrap();
        assert_eq!(one.len(), 1, "a zero limit still returns the minimum page");
        assert_eq!(one[0].id, system.id);

        // An audit trail that can be rewritten is not an audit trail.
        for statement in [
            "UPDATE audit_log SET result='failure'",
            "UPDATE audit_log SET detail='{}'",
            "DELETE FROM audit_log",
        ] {
            assert!(
                sqlx::query(statement)
                    .execute(&reopened.pool)
                    .await
                    .is_err(),
                "`{statement}` must be rejected"
            );
        }
        assert!(
            sqlx::query("TRUNCATE audit_log")
                .execute(&reopened.pool)
                .await
                .is_err(),
            "TRUNCATE must be rejected too"
        );
        let survived = reopened
            .list_audit_events(Some(tenant), None, 100)
            .await
            .unwrap();
        assert!(
            survived
                .iter()
                .any(|event| event.id == first.id && event.result == "success"),
            "a rejected mutation leaves the record exactly as it was"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), reopened.pool.close()).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    #[tokio::test]
    async fn a_draining_worker_takes_no_new_work_and_keeps_the_work_it_holds() {
        // Isolated: the reassignment below may land on any healthy worker, which
        // on the shared schema is a node a test running beside this one owns.
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let node_id = register_worker_with(&repository, tenant, 4, 256, 4_096).await;
        let scheduled = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        let claimed = repository
            .claim_worker_assignments(node_id, 1, 60)
            .await
            .unwrap();
        let generation = claimed[0].lease.generation;

        let draining = repository
            .set_worker_draining(node_id, true, Some("host maintenance"))
            .await
            .unwrap();
        assert!(!draining.accepting_sandboxes);
        assert_eq!(draining.drain_reason.as_deref(), Some("host maintenance"));
        assert!(
            draining.registration.healthy,
            "draining is a request to finish the work, not a report of failure"
        );
        let listed = repository.list_workers(false).await.unwrap();
        let entry = listed
            .iter()
            .find(|worker| worker.registration.node_id == node_id)
            .expect("a draining worker is still a live worker and stays listed");
        assert!(!entry.accepting_sandboxes);
        assert_eq!(entry.drain_reason.as_deref(), Some("host maintenance"));

        let refused = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await;
        let refusal = match &refused {
            Err(CoreError::Transient(message)) => message.as_str(),
            other => {
                panic!("a draining worker must not be offered to the scheduler, got {other:?}")
            }
        };
        assert_eq!(refusal, "no schedulable worker has capacity");

        // Nothing about the sandbox it is already running changed: the lease is
        // live, the reconciler has no reason to sweep it, and recovery will not
        // move it. A drained worker that was treated as a dead one would fail all
        // three, which is exactly the confusion draining has to avoid.
        let held = repository
            .get_active_worker_lease(tenant, scheduled.sandbox.id)
            .await
            .unwrap();
        assert_eq!(held.id, scheduled.lease_id);
        assert_eq!(held.node_id, node_id);
        assert_eq!(held.generation, generation);
        // The reconciler sweeps leases that ran out, not workers that stopped taking
        // work, so running it over a drained worker has to leave the lease alone.
        let actions = repository.reconcile_expired_leases(1_000).await.unwrap();
        assert!(
            actions
                .iter()
                .all(|action| action.lease_id != Some(scheduled.lease_id)),
            "draining does not expire a lease that has not run out"
        );
        let after_sweep = repository
            .get_worker_lease(tenant, scheduled.lease_id)
            .await
            .unwrap();
        assert_eq!(after_sweep.status, "active");
        assert_eq!(after_sweep.generation, generation);
        assert_eq!(
            repository.get_worker(node_id).await.unwrap().sandbox_count,
            1,
            "the drained worker still owns the capacity its sandbox holds"
        );
        assert!(
            repository
                .reassign_expired_lease(scheduled.lease_id)
                .await
                .unwrap()
                .is_none(),
            "a draining worker's live lease is not eligible for reassignment"
        );
        let renewed = repository
            .renew_worker_lease(tenant, scheduled.lease_id, generation, 120)
            .await
            .unwrap();
        assert_eq!(renewed.generation, generation + 1);
        assert_eq!(
            repository
                .get_sandbox(tenant, scheduled.sandbox.id)
                .await
                .unwrap()
                .node_id,
            Some(node_id)
        );

        // Draining withholds new placements; it must not become a shield. Once the
        // lease genuinely runs out the reconciler still has to reclaim it, or a
        // forgotten drain would leak a worker's capacity forever.
        expire_lease(&repository, scheduled.lease_id).await;
        let mut reclaimed = false;
        for _ in 0..10 {
            let actions = repository.reconcile_expired_leases(1_000).await.unwrap();
            if actions
                .iter()
                .any(|action| action.lease_id == Some(scheduled.lease_id))
            {
                reclaimed = true;
                break;
            }
        }
        assert!(
            reclaimed,
            "a lease that ran out is reclaimed even while its worker is draining"
        );
        let drained = repository.get_worker(node_id).await.unwrap();
        assert!(!drained.accepting_sandboxes);
        assert_eq!(
            drained.sandbox_count, 0,
            "the reclaimed lease released the drained worker's capacity"
        );

        assert!(
            repository
                .set_worker_draining(new_id(), true, Some("no such worker"))
                .await
                .is_err(),
            "draining an unknown worker is not a silent success"
        );
        assert!(
            repository
                .set_worker_draining(node_id, true, Some(&"x".repeat(513)))
                .await
                .is_err(),
            "an unbounded drain reason is refused"
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    #[tokio::test]
    async fn a_drain_survives_the_worker_heartbeating_and_re_registering() {
        // Both paths restate the worker's own view of itself. If either one carried
        // accepting_sandboxes, an ordinary heartbeat would quietly undo an operator's
        // decision and put a decommissioned machine back into the placement pool.
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_worker_with(&repository, tenant, 4, 256, 4_096).await;
        repository
            .set_worker_draining(node_id, true, Some("kernel upgrade"))
            .await
            .unwrap();
        let beat = repository
            .heartbeat_worker(WorkerHeartbeat {
                node_id,
                sandbox_count: 0,
                healthy: true,
                version: 2,
                metadata: json!({}),
                last_error: None,
            })
            .await
            .unwrap();
        assert!(
            !beat.accepting_sandboxes,
            "a heartbeat must not end a drain"
        );
        assert_eq!(beat.drain_reason.as_deref(), Some("kernel upgrade"));
        assert!(beat.registration.healthy);

        let reregistered = repository
            .register_worker(WorkerRegistration {
                node_id,
                name: format!("recovery-node-{tenant}-{node_id}"),
                runtime: RuntimeKind::Firecracker,
                capabilities: aiec_core::runtime::RuntimeCapabilities {
                    exec: true,
                    files: true,
                    streaming: false,
                    ..Default::default()
                },
                control_endpoint: "https://127.0.0.1:9000".into(),
                total_vcpus: 4,
                total_memory_bytes: 256 * 1_048_576,
                total_disk_bytes: 4_096 * 1_048_576,
                available_vcpus: 4,
                available_memory_bytes: 256 * 1_048_576,
                available_disk_bytes: 4_096 * 1_048_576,
                healthy: true,
                version: 3,
                metadata: json!({}),
                started_at: Utc::now(),
                last_heartbeat: Utc::now(),
            })
            .await;
        assert!(
            reregistered.is_ok(),
            "re-registering a drained worker is a normal event, got {reregistered:?}"
        );
        let after = repository.get_worker(node_id).await.unwrap();
        assert!(
            !after.accepting_sandboxes,
            "re-registering must not put a drained worker back into placement"
        );
        assert_eq!(after.drain_reason.as_deref(), Some("kernel upgrade"));
        let refused = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await;
        assert!(refused.is_err(), "the drain is still in force after both");
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    #[tokio::test]
    async fn clearing_a_drain_gives_the_worker_its_work_and_capacity_back() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let node_id = register_worker_with(&repository, tenant, 4, 256, 4_096).await;
        for _ in 0..2 {
            schedule_test_sandbox(
                &repository,
                tenant,
                new_id(),
                sandbox(tenant),
                Some(node_id),
            )
            .await
            .unwrap();
        }
        let running = repository
            .claim_worker_assignments(node_id, 1, 60)
            .await
            .unwrap();
        assert_eq!(running.len(), 1);
        let waiting = repository
            .list_worker_assignments_for_node(node_id, Some("reserved"), 10)
            .await
            .unwrap();
        assert_eq!(waiting.len(), 1, "the second sandbox is still unclaimed");
        let reserved_id = waiting[0].sandbox.id;

        repository
            .set_worker_draining(node_id, true, Some("kernel upgrade"))
            .await
            .unwrap();
        assert!(
            repository
                .claim_worker_assignments(node_id, 10, 60)
                .await
                .unwrap()
                .is_empty(),
            "a draining worker is handed no new work"
        );
        let still_reserved = repository
            .list_worker_assignments_for_node(node_id, Some("reserved"), 10)
            .await
            .unwrap();
        assert_eq!(still_reserved.len(), 1);
        assert_eq!(still_reserved[0].sandbox.id, reserved_id);

        let restored = repository
            .set_worker_draining(node_id, false, None)
            .await
            .unwrap();
        assert!(restored.accepting_sandboxes);
        assert!(
            restored.drain_reason.is_none(),
            "clearing the drain clears the reason with it, got {:?}",
            restored.drain_reason
        );
        let claimed = repository
            .claim_worker_assignments(node_id, 10, 60)
            .await
            .unwrap();
        assert_eq!(
            claimed.len(),
            1,
            "the work withheld during the drain is handed over once it ends"
        );
        assert_eq!(claimed[0].sandbox.id, reserved_id);
        let placed = schedule_test_sandbox(
            &repository,
            tenant,
            new_id(),
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        assert_eq!(placed.worker_id, node_id);
        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// A worker that restarts with a fresh id must take over the record that
    /// already owns its name. Rejecting it wedged the worker in a restart loop
    /// and stranded every sandbox it had placed.
    #[tokio::test]
    async fn a_worker_restarting_with_a_fresh_id_adopts_its_existing_record() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        repository.migrate().await.unwrap();
        let (vcpus, memory_mb, disk_mb) = MEMORY_WORKER;
        let now = Utc::now();
        let name = format!("restarting-node-{tenant}");

        let registration = |node_id: Uuid, version: u64| WorkerRegistration {
            node_id,
            name: name.clone(),
            runtime: RuntimeKind::Firecracker,
            capabilities: Default::default(),
            control_endpoint: "https://127.0.0.1:19443".to_string(),
            total_vcpus: vcpus,
            total_memory_bytes: memory_mb * 1_048_576,
            total_disk_bytes: disk_mb * 1_048_576,
            available_vcpus: vcpus,
            available_memory_bytes: memory_mb * 1_048_576,
            available_disk_bytes: disk_mb * 1_048_576,
            healthy: true,
            version,
            metadata: Value::Object(Default::default()),
            started_at: now,
            last_heartbeat: now,
        };

        // The first process registers, then "restarts" with a brand new id.
        let first = repository
            .register_worker(registration(new_id(), 1))
            .await
            .unwrap();
        let second = repository
            .register_worker(registration(new_id(), 1))
            .await
            .expect("re-registering under an existing name must be accepted");

        assert_eq!(
            first, second,
            "a restarting worker must be told the id it was actually given"
        );
        // The database is shared across tests, so scope the check to this name.
        let matching = repository
            .list_workers(true)
            .await
            .unwrap()
            .into_iter()
            .filter(|worker| worker.registration.name == name)
            .count();
        assert_eq!(
            matching, 1,
            "a restarting worker must not accumulate duplicate node records"
        );
    }

    /// Scheduling is idempotent on its request id, so a retry after a timeout
    /// hands back the placement it already made. That is only correct while the
    /// lease is still an owner: handing back an expired one sends the caller to
    /// a machine recovery is already reclaiming, and the sandbox ends up with
    /// two writers who both believe they hold the node.
    #[tokio::test]
    async fn a_rescheduled_sandbox_never_reuses_an_expired_lease() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        repository.migrate().await.unwrap();
        let node_id = register_test_worker(&repository, tenant).await;
        let request_id = new_id();

        // Pinned to one worker throughout: the preferred node is part of the
        // idempotency fingerprint, so a retry may not change it, and the
        // capacity assertions below are about this sandbox rather than about
        // which free worker the retry happened to choose.
        let first = schedule_test_sandbox(
            &repository,
            tenant,
            request_id,
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();

        // A retry while the lease is live is the idempotent case: same node,
        // same lease, no second debit.
        let retried = schedule_test_sandbox(
            &repository,
            tenant,
            request_id,
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        assert_eq!(retried.lease_id, first.lease_id);
        assert_eq!(retried.worker_id, first.worker_id);
        assert_eq!(retried.lease_generation, first.lease_generation);

        // Now the lease expires without recovery collecting it. The row is still
        // `active` and the sandbox is still assigned, which is exactly the state
        // that used to be mistaken for ownership.
        sqlx::query(
            "UPDATE sandbox_leases SET expires_at = now() - interval '1 second' WHERE id = $1",
        )
        .bind(first.lease_id)
        .execute(&repository.pool)
        .await
        .unwrap();

        // Pinned to the same worker so the capacity assertions below are about
        // this sandbox rather than about which free worker the retry chose.
        let after_expiry = schedule_test_sandbox(
            &repository,
            tenant,
            request_id,
            sandbox(tenant),
            Some(node_id),
        )
        .await
        .unwrap();
        assert_eq!(after_expiry.worker_id, node_id);
        assert_ne!(
            after_expiry.lease_id, first.lease_id,
            "an expired lease is not an owner; the retry must not hand it back"
        );
        assert!(
            after_expiry.lease_generation > first.lease_generation,
            "the replacement fences the generation the expired lease held"
        );
        let dispatched = PostgresScheduler::new((*repository).clone())
            .dispatch_target(tenant, after_expiry.sandbox.id)
            .await
            .unwrap();
        assert_eq!(
            dispatched.lease_id, after_expiry.lease_id,
            "the placement the caller was handed is the one it can dispatch to"
        );

        // And the worker is not charged twice for the same sandbox: the expired
        // lease's debit was released before the replacement took it.
        let worker = repository.get_worker(node_id).await.unwrap();
        assert_eq!(
            worker.registration.available_vcpus, 1,
            "one sandbox on one worker costs one debit, not two"
        );
        assert_eq!(
            worker.registration.available_memory_bytes,
            (128 - 64) * 1_048_576,
            "the expired lease's debit is released before the replacement takes it"
        );
        assert_eq!(
            worker.registration.available_disk_bytes,
            (1024 - 512) * 1_048_576,
            "the expired lease's debit is released before the replacement takes it"
        );
        assert_eq!(worker.sandbox_count, 1);

        let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
    }

    /// A worker that comes back on a different machine reports different
    /// capacity. Its record is updated in place, so the number of units already
    /// promised to sandboxes has to survive that resize - it is the one thing
    /// the new registration knows nothing about.
    #[tokio::test]
    async fn a_worker_resizing_carries_the_units_already_committed() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        repository.migrate().await.unwrap();
        let now = Utc::now();
        let node_id = new_id();
        let name = format!("resizing-node-{tenant}");

        let registration =
            |total_vcpus: u32, available_vcpus: u32, version: u64| WorkerRegistration {
                node_id,
                name: name.clone(),
                runtime: RuntimeKind::Firecracker,
                capabilities: Default::default(),
                control_endpoint: "https://127.0.0.1:19443".to_string(),
                total_vcpus,
                total_memory_bytes: u64::from(total_vcpus) * 1_048_576,
                total_disk_bytes: u64::from(total_vcpus) * 1_048_576,
                available_vcpus,
                available_memory_bytes: u64::from(available_vcpus) * 1_048_576,
                available_disk_bytes: u64::from(available_vcpus) * 1_048_576,
                healthy: true,
                version,
                metadata: Value::Object(Default::default()),
                started_at: now,
                last_heartbeat: now,
            };
        async fn worker(
            repository: &PostgresRepository,
            node_id: Uuid,
        ) -> aiec_core::storage::WorkerStatus {
            repository
                .list_workers(true)
                .await
                .unwrap()
                .into_iter()
                .find(|worker| worker.registration.node_id == node_id)
                .expect("the worker keeps its record across a resize")
        }

        // Eight vCPUs with five already committed to sandboxes.
        repository
            .register_worker(registration(8, 3, 1))
            .await
            .unwrap();
        repository
            .set_worker_draining(node_id, true, Some("maintenance"))
            .await
            .unwrap();

        // Growing: the committed five stay committed, the three that were free
        // stay free, and the five new vCPUs are all advertised.
        repository
            .register_worker(registration(16, 3, 2))
            .await
            .unwrap();
        let grown = worker(&repository, node_id).await;
        assert_eq!(grown.registration.total_vcpus, 16);
        assert_eq!(
            grown.registration.available_vcpus, 11,
            "growing a worker must advertise the capacity it gained"
        );

        // Shrinking below what is committed: the five committed units cannot
        // fit, but they are real sandboxes that are still running. The worker
        // reports no headroom rather than refusing to register - refusing would
        // wedge a worker that is healthy and holding work.
        repository
            .register_worker(registration(4, 3, 3))
            .await
            .unwrap();
        let shrunk = worker(&repository, node_id).await;
        assert_eq!(shrunk.registration.total_vcpus, 4);
        assert_eq!(
            shrunk.registration.available_vcpus, 0,
            "a worker smaller than its committed units reports no headroom, \
             not negative headroom"
        );
        assert!(
            shrunk.registration.available_vcpus <= shrunk.registration.total_vcpus,
            "a resize must never advertise more than the worker has"
        );
        // The resize is about capacity only. What the worker is running, and
        // whether it is taking new work, are not the registration's to change.
        assert_eq!(shrunk.sandbox_count, grown.sandbox_count);
        assert!(!shrunk.accepting_sandboxes);
        assert_eq!(shrunk.drain_reason.as_deref(), Some("maintenance"));

        // An idle worker that shrinks simply gives up the difference.
        let idle = new_id();
        let idle_name = format!("idle-resizing-node-{tenant}");
        repository
            .register_worker(WorkerRegistration {
                node_id: idle,
                name: idle_name,
                runtime: RuntimeKind::Firecracker,
                capabilities: Default::default(),
                control_endpoint: "https://127.0.0.1:19443".to_string(),
                total_vcpus: 8,
                total_memory_bytes: 8 * 1_048_576,
                total_disk_bytes: 8 * 1_048_576,
                available_vcpus: 8,
                available_memory_bytes: 8 * 1_048_576,
                available_disk_bytes: 8 * 1_048_576,
                healthy: true,
                version: 1,
                metadata: Value::Object(Default::default()),
                started_at: now,
                last_heartbeat: now,
            })
            .await
            .unwrap();
        repository
            .register_worker(WorkerRegistration {
                node_id: idle,
                name: format!("idle-resizing-node-{tenant}"),
                runtime: RuntimeKind::Firecracker,
                capabilities: Default::default(),
                control_endpoint: "https://127.0.0.1:19443".to_string(),
                total_vcpus: 4,
                total_memory_bytes: 4 * 1_048_576,
                total_disk_bytes: 4 * 1_048_576,
                available_vcpus: 4,
                available_memory_bytes: 4 * 1_048_576,
                available_disk_bytes: 4 * 1_048_576,
                healthy: true,
                version: 2,
                metadata: Value::Object(Default::default()),
                started_at: now,
                last_heartbeat: now,
            })
            .await
            .unwrap();
        let idle_worker = repository
            .list_workers(true)
            .await
            .unwrap()
            .into_iter()
            .find(|worker| worker.registration.node_id == idle)
            .unwrap();
        assert_eq!(
            idle_worker.registration.available_vcpus, 4,
            "a worker that gave up capacity it was not using keeps what it has left"
        );
    }

    /// A queued run, with everything else left at its defaults so a test can say
    /// exactly which field it is exercising.
    fn run(tenant: Uuid) -> Run {
        Run {
            id: new_id(),
            tenant_id: tenant,
            state: RunState::Queued,
            // Postgres keeps microseconds, so a fixture carrying nanoseconds
            // could never compare equal to the run that comes back out.
            requested_at: whole_microsecond_ago(0),
            queued_at: None,
            started_at: None,
            completed_at: None,
            workload: WorkloadSpec {
                command: vec!["echo".into(), "hello".into()],
                ..Default::default()
            },
            resources: Default::default(),
            requirements: Default::default(),
            placement: Default::default(),
            results: Default::default(),
            failure_reason: None,
            retention: RetentionPolicy::Destroy,
            retained_sandbox_id: None,
            retained_until: None,
            idempotency_key: None,
            parent_run_id: None,
            matrix_id: None,
            matrix_cell: None,
        }
    }

    /// A machine that exists as a row and is linked to the run, which is what
    /// a retention now requires of the machine it keeps: an id nobody ever
    /// handed the run is not a machine the run held.
    async fn linked_machine(repository: &PostgresRepository, tenant: Uuid, run: Uuid) -> Uuid {
        let machine = sandbox(tenant);
        let id = machine.id;
        repository.create_sandbox(machine).await.unwrap();
        repository
            .link_run_sandbox(
                tenant,
                RunSandbox {
                    run_id: run,
                    sandbox_id: id,
                    role: "primary".into(),
                },
            )
            .await
            .unwrap();
        id
    }

    fn run_event(run: Uuid, event_type: &str, offset_seconds: i64) -> RunEvent {
        RunEvent {
            id: new_id(),
            run_id: run,
            sandbox_id: None,
            event_type: event_type.into(),
            occurred_at: Utc::now() + chrono::Duration::seconds(offset_seconds),
            detail: json!({ "step": offset_seconds }),
        }
    }

    fn run_artifact(name: &str) -> RunArtifactRef {
        RunArtifactRef {
            name: name.into(),
            object_key: format!("runs/artifacts/{name}"),
            size_bytes: 4_096,
            checksum_sha256: None,
            content_type: Some("application/json".into()),
        }
    }

    /// The repository as a caller reaches it.
    ///
    /// The run methods exist twice on `PostgresRepository` -- once returning the
    /// store's own error, once as the trait -- and a bare call resolves to the
    /// inherent one. These tests assert on the `CoreError` an API handler
    /// receives, so the error paths go through the trait.
    fn store(repository: &PostgresRepository) -> &dyn MetadataStore {
        repository
    }

    /// A second tenant, for the isolation checks. `repository_and_tenant` only
    /// ever hands back one tenant, and every run read is tenant-scoped, so an
    /// outsider has to exist before "the wrong tenant cannot see it" means
    /// anything.
    async fn other_tenant(repository: &PostgresRepository) -> Uuid {
        let tenant = new_id();
        repository
            .put_tenant(TenantRecord {
                id: tenant,
                name: format!("run-outsider-{tenant}"),
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        tenant
    }

    #[tokio::test]
    async fn a_run_round_trips_with_every_field_intact() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let parent = repository.create_run(run(tenant)).await.unwrap();
        let moment = DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
            .expect("the current time is representable");
        let mut value = run(tenant);
        value.state = RunState::Failed;
        value.queued_at = Some(moment);
        value.started_at = Some(moment + chrono::Duration::seconds(1));
        value.completed_at = Some(moment + chrono::Duration::seconds(9));
        value.workload = WorkloadSpec {
            image: Some("afimg1_base".into()),
            repo: Some(aiec_core::run::RepoSpec {
                url: "https://example.invalid/repo.git".into(),
                reference: Some("main".into()),
                path: "/workspace/repository".into(),
            }),
            setup: vec![vec!["apt-get".into(), "update".into()]],
            command: vec!["cargo".into(), "test".into()],
            validations: vec![vec!["cargo".into(), "clippy".into()]],
            artifacts: vec!["target/report.json".into()],
            environment: BTreeMap::from([("CI".to_owned(), "true".to_owned())]),
            secrets: vec!["NPM_TOKEN".into()],
            timeout_seconds: Some(900),
            git_evidence: true,
        };
        value.resources = aiec_core::run::ResourceRequirements {
            cpu: 4,
            memory_mb: 2_048,
            disk_mb: 8_192,
            network: aiec_core::network::NetworkPolicy::Internet,
            guard: None,
        };
        value.requirements = aiec_core::run::CapabilityRequirements {
            full_kernel_isolation: true,
            coding_guest: true,
            ..Default::default()
        };
        value.placement = aiec_core::run::Placement {
            runtime: Some("firecracker".into()),
            worker: Some("node-1".into()),
            reasons: vec!["the only worker offering a pty".into()],
        };
        value.results = RunResults {
            task: Some(aiec_core::run::CommandOutcome {
                command: vec!["cargo".into(), "test".into()],
                exit_code: 1,
                stdout: "running 3 tests".into(),
                stderr: "one test failed".into(),
                duration_ms: 1_200,
                truncated: false,
                output_preview_truncated: false,
                ok: false,
            }),
            validations: vec![aiec_core::run::CommandOutcome {
                command: vec!["cargo".into(), "fmt".into()],
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: 40,
                truncated: false,
                output_preview_truncated: false,
                ok: true,
            }],
            setup: Vec::new(),
            commit: Some("0f1e2d3".into()),
            git_status: " M src/main.rs".into(),
            git_diff: "+ println!();".into(),
            git_evidence_truncated: false,
            changed_files: vec!["src/main.rs".into()],
            artifacts: vec![run_artifact("report.json")],
            phase_ms: BTreeMap::from([("collect".to_owned(), 90)]),
            cleanup_failed: None,
        };
        value.failure_reason = Some("the task exited 1".into());
        value.retention = RetentionPolicy::KeepOnFailure;
        value.retained_sandbox_id = Some(new_id());
        value.retained_until = Some(moment + chrono::Duration::hours(2));
        value.idempotency_key = Some(format!("round-trip-{tenant}"));
        value.parent_run_id = Some(parent.id);
        value.matrix_id = Some(new_id());

        let created = repository.create_run(value.clone()).await.unwrap();
        assert_eq!(
            created, value,
            "a created run reads back exactly as it was written"
        );
        assert_eq!(repository.get_run(tenant, value.id).await.unwrap(), value);

        let listed = repository.list_runs(tenant, None, 50).await.unwrap();
        assert!(listed.contains(&value));
        let queued = repository
            .list_runs(tenant, Some(RunState::Queued), 50)
            .await
            .unwrap();
        assert!(queued.contains(&parent));
        assert!(
            !queued.contains(&value),
            "a state filter must not hand back runs in another state"
        );
    }

    #[tokio::test]
    async fn a_repeated_create_with_the_same_key_returns_the_first_run() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let outsider = other_tenant(&repository).await;
        let key = format!("retry-{tenant}");
        let mut first = run(tenant);
        first.idempotency_key = Some(key.clone());
        let created = repository.create_run(first.clone()).await.unwrap();

        let mut retry = run(tenant);
        retry.idempotency_key = Some(key.clone());
        retry.workload.command = vec!["rm".into(), "-rf".into(), "/".into()];
        let again = repository.create_run(retry).await.unwrap();
        assert_eq!(
            again, created,
            "a retried request is handed the run it already created, not a second one"
        );
        assert_eq!(
            repository.list_runs(tenant, None, 50).await.unwrap().len(),
            1
        );

        // The key is the tenant's, not the cluster's: another tenant asking for
        // the same key is a different run, not a collision.
        let mut elsewhere = run(outsider);
        elsewhere.idempotency_key = Some(key);
        let theirs = repository.create_run(elsewhere).await.unwrap();
        assert_ne!(theirs.id, created.id);
        assert_eq!(
            repository
                .list_runs(outsider, None, 50)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// The property every other run read depends on: a run is unreachable
    /// without the tenant that owns it, and every path that takes a tenant says
    /// so rather than falling back to the owner's view.
    #[tokio::test]
    async fn a_run_belonging_to_another_tenant_is_not_found() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let outsider = other_tenant(&repository).await;
        let value = repository.create_run(run(tenant)).await.unwrap();
        repository
            .append_run_event(tenant, run_event(value.id, "run.created", 0))
            .await
            .unwrap();
        repository
            .put_run_artifacts(tenant, value.id, vec![run_artifact("report.json")])
            .await
            .unwrap();

        assert!(matches!(
            store(&repository).get_run(outsider, value.id).await,
            Err(CoreError::NotFound(_))
        ));
        assert!(matches!(
            store(&repository)
                .update_run_state(outsider, value.id, RunState::Queued, RunState::Preparing)
                .await,
            Err(CoreError::NotFound(_))
        ));
        assert!(matches!(
            store(&repository)
                .record_run_results(outsider, value.id, RunResults::default(), RunState::Failed,)
                .await,
            Err(CoreError::NotFound(_))
        ));
        assert!(matches!(
            store(&repository).delete_run(outsider, value.id).await,
            Err(CoreError::NotFound(_))
        ));
        assert!(matches!(
            store(&repository)
                .put_run_artifacts(outsider, value.id, vec![run_artifact("stolen.json")])
                .await,
            Err(CoreError::NotFound(_))
        ));
        assert!(
            repository
                .list_run_events(outsider, value.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            repository
                .list_run_artifacts(outsider, value.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            repository
                .list_run_attempts(outsider, value.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            repository
                .list_run_sandboxes(outsider, value.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            repository
                .list_runs(outsider, None, 50)
                .await
                .unwrap()
                .is_empty()
        );

        // None of that cost the owner access to their own run.
        assert_eq!(repository.get_run(tenant, value.id).await.unwrap(), value);
    }

    #[tokio::test]
    async fn a_stale_state_transition_is_refused() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let value = repository.create_run(run(tenant)).await.unwrap();
        let preparing = repository
            .update_run_state(tenant, value.id, RunState::Queued, RunState::Preparing)
            .await
            .unwrap();
        assert_eq!(preparing.state, RunState::Preparing);
        assert!(
            preparing.started_at.is_none(),
            "a preparing run has not started executing yet"
        );

        // The winner of a race is the only one that moves the run; the loser is
        // told the state moved rather than being allowed to overwrite it.
        assert!(matches!(
            store(&repository)
                .update_run_state(tenant, value.id, RunState::Queued, RunState::Running)
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert_eq!(
            store(&repository)
                .get_run(tenant, value.id)
                .await
                .unwrap()
                .state,
            RunState::Preparing,
            "a refused transition must leave the run where the winner put it"
        );

        // An edge the lifecycle does not have is refused before the write is
        // issued at all, the same way a sandbox transition is: the caller hears
        // about an impossible move rather than about a row that did not change.
        assert!(matches!(
            store(&repository)
                .update_run_state(tenant, value.id, RunState::Preparing, RunState::Collecting,)
                .await,
            Err(CoreError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn recording_results_settles_the_run_and_will_not_restart_it() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let mut value = run(tenant);
        value.state = RunState::Collecting;
        value.queued_at = Some(whole_microsecond_ago(9));
        value.started_at = Some(whole_microsecond_ago(3));
        let created = repository.create_run(value).await.unwrap();
        let results = RunResults {
            task: Some(aiec_core::run::CommandOutcome {
                command: vec!["cargo".into(), "test".into()],
                exit_code: 0,
                stdout: "ok".into(),
                stderr: String::new(),
                duration_ms: 900,
                truncated: false,
                output_preview_truncated: false,
                ok: true,
            }),
            commit: Some("0f1e2d3".into()),
            ..Default::default()
        };

        let settled = repository
            .record_run_results(tenant, created.id, results.clone(), RunState::Succeeded)
            .await
            .unwrap();
        assert_eq!(settled.state, RunState::Succeeded);
        assert_eq!(settled.results, results);
        assert!(
            settled.completed_at.is_some(),
            "a run that finished without a completion time cannot be aged"
        );

        // Results carry the state they put the run in rather than a
        // compare-and-set, so a late write must not be able to restart a run
        // that has already finished.
        assert!(matches!(
            store(&repository)
                .record_run_results(tenant, created.id, RunResults::default(), RunState::Running,)
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert_eq!(
            repository.get_run(tenant, created.id).await.unwrap(),
            settled
        );
    }

    #[tokio::test]
    async fn run_events_append_in_order_and_cannot_be_deleted() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let value = repository.create_run(run(tenant)).await.unwrap();
        for (offset, kind) in ["run.created", "sandbox.assigned", "task.started"]
            .iter()
            .enumerate()
        {
            repository
                .append_run_event(tenant, run_event(value.id, kind, offset as i64))
                .await
                .unwrap();
        }

        let events = repository.list_run_events(tenant, value.id).await.unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            vec!["run.created", "sandbox.assigned", "task.started"],
            "a run's history reads back in the order it happened"
        );
        assert_eq!(events[2].detail, json!({ "step": 2 }));

        // An event naming a run that is not there is a naming mistake, not a
        // database failure the caller cannot act on.
        assert!(matches!(
            store(&repository)
                .append_run_event(tenant, run_event(new_id(), "run.created", 0))
                .await,
            Err(CoreError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn run_artifacts_round_trip_within_their_tenant() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let outsider = other_tenant(&repository).await;
        let value = repository.create_run(run(tenant)).await.unwrap();
        let mut large = run_artifact("target.tar");
        large.size_bytes = 1_073_741_824;
        let artifacts = vec![run_artifact("report.json"), large];
        repository
            .put_run_artifacts(tenant, value.id, artifacts.clone())
            .await
            .unwrap();

        let listed = repository
            .list_run_artifacts(tenant, value.id)
            .await
            .unwrap();
        let mut expected = artifacts;
        expected.sort_by(|left, right| left.name.cmp(&right.name));
        assert_eq!(listed, expected);
        assert!(
            repository
                .list_run_artifacts(outsider, value.id)
                .await
                .unwrap()
                .is_empty()
        );

        // A collection pass that finds fewer files must not leave the files it
        // no longer produced listed against the run.
        repository
            .put_run_artifacts(tenant, value.id, vec![run_artifact("report.json")])
            .await
            .unwrap();
        assert_eq!(
            repository
                .list_run_artifacts(tenant, value.id)
                .await
                .unwrap(),
            vec![run_artifact("report.json")]
        );
    }

    #[tokio::test]
    async fn a_run_records_the_machines_it_used_and_every_attempt() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let outsider = other_tenant(&repository).await;
        let machine = sandbox(tenant);
        let sandbox_id = machine.id;
        repository.create_sandbox(machine).await.unwrap();
        let value = repository.create_run(run(tenant)).await.unwrap();
        repository
            .link_run_sandbox(
                tenant,
                RunSandbox {
                    run_id: value.id,
                    sandbox_id,
                    role: "primary".into(),
                },
            )
            .await
            .unwrap();

        for (number, state, reason) in [
            (1, RunState::Failed, Some("the machine died")),
            (2, RunState::Succeeded, None),
        ] {
            repository
                .record_run_attempt(
                    tenant,
                    RunAttempt {
                        id: new_id(),
                        run_id: value.id,
                        attempt_number: number,
                        sandbox_id: Some(sandbox_id),
                        state,
                        failure_reason: reason.map(str::to_owned),
                        started_at: Utc::now(),
                        completed_at: Some(Utc::now()),
                        placement: Default::default(),
                        results: Default::default(),
                    },
                )
                .await
                .unwrap();
        }

        let attempts = repository
            .list_run_attempts(tenant, value.id)
            .await
            .unwrap();
        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.attempt_number)
                .collect::<Vec<_>>(),
            vec![1, 2],
            "a retried run keeps the attempt that did not work"
        );
        assert_eq!(attempts[0].state, RunState::Failed);
        assert_eq!(
            attempts[0].failure_reason.as_deref(),
            Some("the machine died")
        );
        let linked = repository
            .list_run_sandboxes(tenant, value.id)
            .await
            .unwrap();
        assert_eq!(
            linked,
            vec![RunSandbox {
                run_id: value.id,
                sandbox_id,
                role: "primary".into(),
            }]
        );
        assert!(
            repository
                .list_run_attempts(outsider, value.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            repository
                .list_run_sandboxes(outsider, value.id)
                .await
                .unwrap()
                .is_empty()
        );

        // An attempt is evidence of a try, so it cannot be recorded for a state
        // that is not a try, and a second attempt cannot rewrite the first.
        assert!(matches!(
            store(&repository)
                .record_run_attempt(
                    tenant,
                    RunAttempt {
                        id: new_id(),
                        run_id: value.id,
                        attempt_number: 3,
                        sandbox_id: None,
                        state: RunState::Queued,
                        failure_reason: None,
                        started_at: Utc::now(),
                        completed_at: None,
                        placement: Default::default(),
                        results: Default::default(),
                    },
                )
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert!(matches!(
            store(&repository)
                .record_run_attempt(
                    tenant,
                    RunAttempt {
                        id: new_id(),
                        run_id: value.id,
                        attempt_number: 1,
                        sandbox_id: None,
                        state: RunState::Succeeded,
                        failure_reason: None,
                        started_at: Utc::now(),
                        completed_at: None,
                        placement: Default::default(),
                        results: Default::default(),
                    },
                )
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert_eq!(
            repository
                .list_run_attempts(tenant, value.id)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn a_run_that_still_holds_a_machine_cannot_be_deleted_out_from_under_it() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let machine = sandbox(tenant);
        let sandbox_id = machine.id;
        repository.create_sandbox(machine).await.unwrap();

        // A linked machine is cleanup's only index onto it.
        let linked = repository.create_run(run(tenant)).await.unwrap();
        repository
            .link_run_sandbox(
                tenant,
                RunSandbox {
                    run_id: linked.id,
                    sandbox_id,
                    role: "primary".into(),
                },
            )
            .await
            .unwrap();
        assert!(
            matches!(
                store(&repository).delete_run(tenant, linked.id).await,
                Err(CoreError::Conflict(_))
            ),
            "a run that still names a machine was deleted, stranding it"
        );
        assert!(repository.get_run(tenant, linked.id).await.is_ok());

        // A retained machine is the sweeper's only index onto it, and retention
        // is only ever recorded for a machine the run used.
        let retained = repository.create_run(run(tenant)).await.unwrap();
        repository
            .link_run_sandbox(
                tenant,
                RunSandbox {
                    run_id: retained.id,
                    sandbox_id,
                    role: "primary".into(),
                },
            )
            .await
            .unwrap();
        repository
            .retain_run_sandbox(
                tenant,
                retained.id,
                sandbox_id,
                Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .map(|_| ())
            .map_err(|error| panic!("retention of a linked machine: {error:?}"));
        assert!(
            matches!(
                store(&repository).delete_run(tenant, retained.id).await,
                Err(CoreError::Conflict(_))
            ),
            "a run that still retains a machine was deleted before it was reclaimed"
        );

        // A run row can carry a retention whose link is not there — a fixture,
        // a row written before the link existed, or any writer that sets the
        // column directly. Retention is the sweeper's only index onto that
        // machine, so the guard reads the column itself rather than trusting
        // the link to be present whenever the column is.
        let mut unlinked = run(tenant);
        unlinked.retained_sandbox_id = Some(sandbox_id);
        unlinked.retained_until = Some(Utc::now() + chrono::Duration::hours(1));
        repository.create_run(unlinked.clone()).await.unwrap();
        assert!(
            matches!(
                store(&repository).delete_run(tenant, unlinked.id).await,
                Err(CoreError::Conflict(_))
            ),
            "a run still retaining a machine was deleted, with no link to find it by"
        );

        // Refused is not the same answer as absent.
        assert!(matches!(
            store(&repository).delete_run(tenant, new_id()).await,
            Err(CoreError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn a_run_with_recorded_history_is_kept_and_one_without_it_is_removed() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let with_history = repository.create_run(run(tenant)).await.unwrap();
        repository
            .append_run_event(tenant, run_event(with_history.id, "run.created", 0))
            .await
            .unwrap();
        assert!(
            matches!(
                store(&repository).delete_run(tenant, with_history.id).await,
                Err(CoreError::Conflict(_))
            ),
            "a run whose history has been recorded is not erasable"
        );
        assert!(repository.get_run(tenant, with_history.id).await.is_ok());

        let bare = repository.create_run(run(tenant)).await.unwrap();
        repository.delete_run(tenant, bare.id).await.unwrap();
        assert!(matches!(
            store(&repository).get_run(tenant, bare.id).await,
            Err(CoreError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn retained_runs_due_returns_only_runs_whose_retention_expired() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let now = whole_microsecond_ago(0);
        // A retained machine belongs to a run that has settled, which is the
        // only state in which expiring one is safe.
        let mut expired = run(tenant);
        expired.state = RunState::Failed;
        expired.retained_sandbox_id = Some(new_id());
        expired.retained_until = Some(now - chrono::Duration::hours(1));
        let mut held = run(tenant);
        held.state = RunState::Failed;
        held.retained_sandbox_id = Some(new_id());
        held.retained_until = Some(now + chrono::Duration::hours(1));
        let mut released = run(tenant);
        released.state = RunState::Succeeded;
        // Retention is recorded before the run settles, so a run that is still
        // executing can already carry an expiring `retained_until`. Sweeping it
        // would destroy a machine the executor is still writing results against
        // and clear the fields, telling the caller who asked to keep a debugging
        // machine that there is none.
        let mut settling = run(tenant);
        settling.state = RunState::Collecting;
        settling.retained_sandbox_id = Some(new_id());
        settling.retained_until = Some(now - chrono::Duration::hours(1));
        for value in [&expired, &held, &released, &settling] {
            repository.create_run(value.clone()).await.unwrap();
        }

        let due = repository.retained_runs_due(now, 100).await.unwrap();
        assert!(due.contains(&expired));
        assert!(
            !due.contains(&held),
            "a machine kept for debugging is not due before its own expiry"
        );
        assert!(
            !due.contains(&released),
            "a run that retained nothing has nothing to sweep"
        );
        assert!(
            !due.contains(&settling),
            "a run that has not settled is not swept, however long ago its \
             retention was recorded"
        );
        assert!(expired.retention_expired(now));
        assert!(!held.retention_expired(now));
        assert!(!released.retention_expired(now));
        drop_test_schema(&repository, admin, schema).await;
    }

    /// Two sweeper passes can overlap on one run's retained machine. The pass
    /// that destroys it and the pass that reports the teardown failed are both
    /// correct in isolation; the order they happen in decides whether the run
    /// is left claiming a machine nobody owns. Both orders are exercised here
    /// because both were wrong.
    #[tokio::test]
    async fn a_released_machine_leaves_no_cleanup_report_and_cannot_be_reported_afterwards() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let now = whole_microsecond_ago(0);

        // Failure first, then a successful release: the release disproves the
        // report, so the report must go with it in the same statement.
        let mut reported = run(tenant);
        reported.state = RunState::Failed;
        repository.create_run(reported.clone()).await.unwrap();
        let machine = linked_machine(&repository, tenant, reported.id).await;
        let held = repository
            .retain_run_sandbox(
                tenant,
                reported.id,
                machine,
                now + chrono::Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(held.retained_sandbox_id, Some(machine));
        let failed = repository
            .record_retention_cleanup_failure(
                tenant,
                reported.id,
                machine,
                "runtime unavailable".into(),
            )
            .await
            .unwrap();
        let report = failed
            .results
            .cleanup_failed
            .expect("the failed teardown is reported");
        assert_eq!(report.sandbox_id, machine);
        assert_eq!(report.error, "runtime unavailable");

        let cleared = repository
            .clear_run_retention(tenant, reported.id, machine)
            .await
            .unwrap();
        assert_eq!(cleared.retained_sandbox_id, None);
        assert_eq!(cleared.retained_until, None);
        assert!(
            cleared.results.cleanup_failed.is_none(),
            "a machine that was released has no teardown left to have failed"
        );

        // The sweeper that is still in flight with a stale read now tries to
        // report its failure. It must write nothing, or the run is back to
        // claiming a machine the winner already destroyed.
        assert!(matches!(
            repository
                .record_retention_cleanup_failure(
                    tenant,
                    reported.id,
                    machine,
                    "runtime unavailable".into()
                )
                .await,
            Err(StoreError::NotFound)
        ));
        assert!(
            repository
                .get_run(tenant, reported.id)
                .await
                .unwrap()
                .results
                .cleanup_failed
                .is_none()
        );
        // And a second release of the same machine is not a silent success
        // either: there is no longer anything of its retention to clear.
        assert!(matches!(
            repository
                .clear_run_retention(tenant, reported.id, machine)
                .await,
            Err(StoreError::NotFound)
        ));

        // A run already keeping a machine cannot be made to keep a different
        // one. Overwriting is how the first machine ends up with a row nothing
        // selects: the sweeper acts on `retained_until`, so the displaced
        // machine is never reclaimed and holds its capacity forever.
        let mut other = run(tenant);
        other.state = RunState::Failed;
        repository.create_run(other.clone()).await.unwrap();
        let kept = linked_machine(&repository, tenant, other.id).await;
        let second = linked_machine(&repository, tenant, other.id).await;
        repository
            .retain_run_sandbox(tenant, other.id, kept, now + chrono::Duration::hours(1))
            .await
            .unwrap();
        repository
            .record_retention_cleanup_failure(tenant, other.id, kept, "still broken".into())
            .await
            .unwrap();
        assert!(
            matches!(
                repository
                    .retain_run_sandbox(tenant, other.id, second, now + chrono::Duration::hours(1))
                    .await,
                Err(StoreError::Conflict(_))
            ),
            "a second machine may not displace the one the run is already keeping"
        );
        assert_eq!(
            repository
                .get_run(tenant, other.id)
                .await
                .unwrap()
                .retained_sandbox_id,
            Some(kept),
            "the refused retention left the machine that was already kept in place"
        );
        let swept = repository
            .clear_run_retention(tenant, other.id, kept)
            .await
            .unwrap();
        assert_eq!(swept.retained_sandbox_id, None);
        assert!(
            swept.results.cleanup_failed.is_none(),
            "the machine that was released takes its own failed teardown with it"
        );

        // A report for a machine this run is not retaining is refused outright
        // rather than filed against whoever currently holds the machine.
        let mut stranger = run(tenant);
        stranger.state = RunState::Failed;
        repository.create_run(stranger.clone()).await.unwrap();
        assert!(matches!(
            repository
                .record_retention_cleanup_failure(tenant, stranger.id, kept, "not mine".into())
                .await,
            Err(StoreError::NotFound)
        ));

        drop_test_schema(&repository, admin, schema).await;
    }

    /// The tables hanging off a run carry no tenant of their own, so the tenant
    /// has to arrive with the write. Without it the link list - the exact ids
    /// cleanup reads to tear machines down - accepts any machine id in the
    /// database: cleanup then fails closed on a machine it can never destroy,
    /// reports the failure against a run that never held it, and the foreign
    /// tenant's machine is destroyed instead once the report is acted on.
    #[tokio::test]
    async fn a_run_only_links_keeps_and_records_machines_from_its_own_tenant() {
        let Some((repository, tenant)) = repository_and_tenant().await else {
            return;
        };
        let outsider = other_tenant(&repository).await;
        let until = whole_microsecond_ago(0) + chrono::Duration::hours(1);
        let value = repository.create_run(run(tenant)).await.unwrap();

        let theirs = sandbox(outsider);
        let theirs_id = theirs.id;
        repository.create_sandbox(theirs).await.unwrap();

        assert!(matches!(
            repository
                .link_run_sandbox(
                    tenant,
                    RunSandbox {
                        run_id: value.id,
                        sandbox_id: theirs_id,
                        role: "primary".into(),
                    },
                )
                .await,
            Err(StoreError::Conflict(_))
        ));
        assert!(
            repository
                .list_run_sandboxes(tenant, value.id)
                .await
                .unwrap()
                .is_empty(),
            "a refused link leaves nothing behind for cleanup to find"
        );

        let mut named = run_event(value.id, "sandbox.assigned", 0);
        named.sandbox_id = Some(theirs_id);
        assert!(matches!(
            repository.append_run_event(tenant, named).await,
            Err(StoreError::Conflict(_))
        ));
        assert!(
            repository
                .list_run_events(tenant, value.id)
                .await
                .unwrap()
                .is_empty(),
            "history is append-only, so a refused event must leave no row either"
        );
        assert!(matches!(
            repository
                .record_run_attempt(
                    tenant,
                    RunAttempt {
                        id: new_id(),
                        run_id: value.id,
                        attempt_number: 1,
                        sandbox_id: Some(theirs_id),
                        state: RunState::Running,
                        failure_reason: None,
                        started_at: Utc::now(),
                        completed_at: None,
                        placement: Default::default(),
                        results: Default::default(),
                    },
                )
                .await,
            Err(StoreError::Conflict(_))
        ));
        assert!(
            repository
                .list_run_attempts(tenant, value.id)
                .await
                .unwrap()
                .is_empty()
        );

        assert!(matches!(
            repository
                .retain_run_sandbox(tenant, value.id, theirs_id, until)
                .await,
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(
            repository
                .get_run(tenant, value.id)
                .await
                .unwrap()
                .retained_sandbox_id,
            None
        );

        // A machine of this tenant's own that the run never used is refused for
        // the neighbouring reason: retention and the link list have to agree,
        // or cleanup tears down the machine the run asked to keep.
        let unlinked = sandbox(tenant);
        let unlinked_id = unlinked.id;
        repository.create_sandbox(unlinked).await.unwrap();
        assert!(matches!(
            repository
                .retain_run_sandbox(tenant, value.id, unlinked_id, until)
                .await,
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(
            repository
                .get_run(tenant, value.id)
                .await
                .unwrap()
                .retained_sandbox_id,
            None
        );

        let kept = linked_machine(&repository, tenant, value.id).await;
        let second = linked_machine(&repository, tenant, value.id).await;
        let retained = repository
            .retain_run_sandbox(tenant, value.id, kept, until)
            .await
            .unwrap();
        assert_eq!(retained.retained_sandbox_id, Some(kept));

        // Restating the same retention is a retry of one decision, not a second
        // one, so it succeeds and takes the later expiry.
        let later = whole_microsecond_ago(0) + chrono::Duration::hours(2);
        let retried = repository
            .retain_run_sandbox(tenant, value.id, kept, later)
            .await
            .unwrap();
        assert_eq!(retried.retained_until, Some(later));

        assert!(matches!(
            repository
                .retain_run_sandbox(tenant, value.id, second, until)
                .await,
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(
            repository.get_run(tenant, value.id).await.unwrap(),
            retried,
            "the refused second machine left the first one's retention untouched"
        );

        // Another tenant naming this run gets no answer at all: whether the run
        // exists is not theirs to learn.
        assert!(matches!(
            repository
                .retain_run_sandbox(outsider, value.id, kept, until)
                .await,
            Err(StoreError::NotFound)
        ));
    }

    /// A failure is one fact about a run: what it produced, why it stopped, and
    /// that it stopped. Written as two statements it can be half-applied, and
    /// the half that lands is the misleading one - results describing an outcome
    /// the run has not reached, or a `run.failed` event with a run that never
    /// became terminal.
    #[tokio::test]
    async fn a_failure_settles_results_reason_and_completion_in_one_write() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };

        let mut failing = run(tenant);
        failing.state = RunState::Running;
        repository.create_run(failing.clone()).await.unwrap();
        let settled = repository
            .record_run_failure(
                tenant,
                failing.id,
                RunResults {
                    phase_ms: BTreeMap::from([("collect".to_owned(), 90)]),
                    git_status: " M README".into(),
                    ..Default::default()
                },
                Some("the task exited 1".into()),
            )
            .await
            .unwrap();
        assert_eq!(settled.state, RunState::Failed);
        assert_eq!(settled.failure_reason.as_deref(), Some("the task exited 1"));
        assert_eq!(settled.results.phase_ms.get("collect"), Some(&90));
        assert_eq!(settled.results.git_status, " M README");
        assert!(
            settled.completed_at.is_some(),
            "a failed run is terminal and carries the moment it became so"
        );
        let reread = repository.get_run(tenant, failing.id).await.unwrap();
        assert_eq!(reread.state, RunState::Failed);
        assert_eq!(reread.failure_reason.as_deref(), Some("the task exited 1"));
        assert_eq!(reread.results.phase_ms.get("collect"), Some(&90));

        // Writing the same failure again must not move the run or its evidence:
        // a retried settlement is the same fact, not a second event, and the
        // retry that carries a default results document must not erase the
        // measurements the first one took.
        let again = repository
            .record_run_failure(tenant, failing.id, RunResults::default(), None)
            .await
            .unwrap();
        assert_eq!(again.state, RunState::Failed);
        assert_eq!(again.completed_at, settled.completed_at);
        assert_eq!(again.failure_reason.as_deref(), Some("the task exited 1"));
        assert_eq!(again.results.phase_ms.get("collect"), Some(&90));
        assert_eq!(again.results.git_status, " M README");

        // A cancelled run whose in-flight execution then fails keeps the verdict
        // its caller was already told, while still recording what the execution
        // produced and why it stopped. Not an error: cancelling is not undone by
        // a machine that is already gone failing once more.
        let mut cancelled = run(tenant);
        cancelled.state = RunState::Cancelled;
        cancelled.completed_at = Some(whole_microsecond_ago(30));
        repository.create_run(cancelled.clone()).await.unwrap();
        let kept = repository
            .record_run_failure(
                tenant,
                cancelled.id,
                RunResults {
                    git_status: "clean".into(),
                    ..Default::default()
                },
                Some("runtime vanished".into()),
            )
            .await
            .unwrap();
        assert_eq!(kept.state, RunState::Cancelled);
        assert_eq!(kept.failure_reason.as_deref(), Some("runtime vanished"));
        assert_eq!(kept.results.git_status, "clean");
        assert_eq!(kept.completed_at, cancelled.completed_at);

        // A run that is not this tenant's is not found rather than failed.
        assert!(matches!(
            repository
                .record_run_failure(
                    new_id(),
                    failing.id,
                    RunResults::default(),
                    Some("not mine".into())
                )
                .await,
            Err(StoreError::NotFound)
        ));

        drop_test_schema(&repository, admin, schema).await;
    }

    #[tokio::test]
    async fn run_owned_machines_are_not_rebuilt_by_generic_lease_recovery() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let old_worker = register_worker_with(&repository, tenant, 4, 256, 4096).await;
        let new_worker = register_worker_with(&repository, tenant, 4, 256, 4096).await;
        for state in [RunState::Running, RunState::Succeeded] {
            let mut owner = run(tenant);
            owner.state = state;
            repository.create_run(owner.clone()).await.unwrap();
            let scheduled = schedule_test_sandbox(
                &repository,
                tenant,
                new_id(),
                sandbox(tenant),
                Some(old_worker),
            )
            .await
            .unwrap();
            repository
                .link_run_sandbox(
                    tenant,
                    RunSandbox {
                        run_id: owner.id,
                        sandbox_id: scheduled.sandbox.id,
                        role: "primary".into(),
                    },
                )
                .await
                .unwrap();
            expire_lease(&repository, scheduled.lease_id).await;
            let before = repository.get_worker(new_worker).await.unwrap();
            let recovered = repository
                .reassign_expired_lease(scheduled.lease_id)
                .await
                .unwrap();
            let after = repository.get_worker(new_worker).await.unwrap();
            assert!(
                recovered.is_none(),
                "generic recovery must not rebuild a run attempt in {state:?}"
            );
            assert_eq!(
                after.registration.available_vcpus,
                before.registration.available_vcpus
            );
            assert_eq!(
                after.registration.available_memory_bytes,
                before.registration.available_memory_bytes
            );
            assert_eq!(
                after.registration.available_disk_bytes,
                before.registration.available_disk_bytes
            );
            assert!(
                repository
                    .get_active_worker_lease(tenant, scheduled.sandbox.id)
                    .await
                    .is_err()
            );
        }
        drop_test_schema(&repository, admin, schema).await;
    }
}
