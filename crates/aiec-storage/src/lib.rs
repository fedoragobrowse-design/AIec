mod artifact_gc;
mod guard;
mod images;
mod matrix;
mod memory_artifact_gc;
mod object_store;
mod postgres;
mod run_queue;
mod snapshots;

use aiec_core::{
    ApiKeyRecord, ApprovalDecisionRequest, ApprovalState, CoreError, GuardProposal,
    GuardToolApproval, ImageRecord, Node, Sandbox, SandboxState, Snapshot, UsageEvent,
    UsageSummary,
    storage::{
        AuditEvent, BudgetDebit, GuardBudgetState, GuardFence, GuardIdentity, GuardIncident,
        MetadataStore, Reassignment, ReconciliationAction, SandboxEvent, SandboxOperation,
        SandboxOwnership, StoredSnapshot, TenantRecord, WorkerAssignment, WorkerHeartbeat,
        WorkerLease, WorkerRegistration, WorkerStatus,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
pub use images::{SignedImageResolver, StandardImageResolver};
pub use object_store::{FilesystemObjectStore, S3Config, S3ObjectStore};
pub use postgres::PostgresScheduler;
pub use snapshots::{snapshot_capabilities, snapshot_kind, snapshot_metadata};
use sqlx::PgPool;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

pub const NODE_HEARTBEAT_TTL_SECONDS: i64 = 30;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("core: {0}")]
    Core(#[from] CoreError),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    /// A database failure that clears on its own: a deadlock, or a transaction
    /// that lost a serialisation race. Classified here, from the SQLSTATE,
    /// rather than by callers guessing from the message.
    #[error("transient database failure: {0}")]
    Transient(String),
    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("migration: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid object key: {0}")]
    InvalidObjectKey(String),
    #[error("object store: {0}")]
    ObjectStore(String),
    #[error("unsupported repository operation: {0}")]
    Unsupported(&'static str),
}

pub(crate) fn core_error(error: StoreError) -> CoreError {
    match error {
        StoreError::Core(error) => error,
        StoreError::NotFound => CoreError::NotFound("record not found".into()),
        StoreError::Conflict(message) => CoreError::Conflict(message),
        StoreError::QuotaExceeded(message) => CoreError::QuotaExceeded(message),
        StoreError::Database(error) => {
            if matches!(
                &error,
                sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
            ) {
                CoreError::Unavailable(error.to_string())
            } else {
                CoreError::Backend(error.to_string())
            }
        }
        StoreError::Migration(error) => CoreError::Backend(error.to_string()),
        StoreError::Transient(message) => CoreError::Transient(message),
        StoreError::Io(error) => CoreError::Io(error),
        StoreError::Json(error) => CoreError::Backend(error.to_string()),
        StoreError::InvalidObjectKey(message) => CoreError::InvalidRequest(message),
        StoreError::ObjectStore(message) => CoreError::Backend(message),
        StoreError::Unsupported(operation) => {
            CoreError::Unsupported(format!("metadata operation `{operation}`"))
        }
    }
}

pub(crate) fn database_error(error: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(database) = &error {
        if database.is_unique_violation() {
            return StoreError::Conflict("record already exists".into());
        }
        if database.is_check_violation() {
            return StoreError::Conflict("record violates a storage invariant".into());
        }
        // SQLSTATE, not prose: 40P01 is a deadlock and 40001 is a
        // serialisation failure. Both clear once the other transaction
        // commits, which is exactly what "try again" means.
        if let Some(code) = database.code()
            && matches!(code.as_ref(), "40P01" | "40001")
        {
            return StoreError::Transient(error.to_string());
        }
    }
    StoreError::Database(error)
}

#[derive(Default)]
struct MemoryData {
    sandboxes: HashMap<Uuid, Sandbox>,
    keys: HashMap<Uuid, ApiKeyRecord>,
    snapshots: HashMap<Uuid, Snapshot>,
    usage: Vec<UsageEvent>,
    stored_snapshots: HashMap<Uuid, StoredSnapshot>,
    nodes: HashMap<Uuid, Node>,
    tenants: HashMap<Uuid, TenantRecord>,
    artifact_objects: BTreeMap<String, memory_artifact_gc::MemoryArtifact>,
    artifact_scan: Option<String>,
    guard_budgets: HashMap<Uuid, GuardBudgetState>,
    guard_incidents: HashMap<Uuid, GuardIncident>,
    guard_proposals: HashMap<Uuid, GuardProposal>,
    leases: HashMap<Uuid, WorkerLease>,
    guard_tool_approvals: HashMap<Uuid, GuardToolApproval>,
}

#[derive(Default)]
pub struct MemoryRepository {
    data: RwLock<MemoryData>,
}

impl MemoryRepository {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

fn owned(data: &MemoryData, tenant: Uuid, id: Uuid) -> Result<Sandbox, StoreError> {
    data.sandboxes
        .get(&id)
        .filter(|value| value.tenant_id == tenant)
        .cloned()
        .ok_or(StoreError::NotFound)
}

impl MemoryRepository {
    async fn create_sandbox(&self, value: Sandbox) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        if data.sandboxes.contains_key(&value.id) {
            return Err(StoreError::Conflict("sandbox exists".into()));
        }
        data.sandboxes.insert(value.id, value);
        Ok(())
    }

    async fn get_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<Sandbox, StoreError> {
        let data = self.data.read().await;
        owned(&data, tenant, id)
    }

    async fn list_sandboxes(&self, tenant: Uuid) -> Result<Vec<Sandbox>, StoreError> {
        Ok(self
            .data
            .read()
            .await
            .sandboxes
            .values()
            .filter(|value| value.tenant_id == tenant)
            .cloned()
            .collect())
    }

    async fn update_state(
        &self,
        tenant: Uuid,
        id: Uuid,
        expected: SandboxState,
        next: SandboxState,
        runtime_path: Option<String>,
    ) -> Result<Sandbox, StoreError> {
        let mut data = self.data.write().await;
        let mut value = owned(&data, tenant, id)?;
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
        value.state = next;
        value.updated_at = Utc::now();
        if runtime_path.is_some() {
            value.runtime_path = runtime_path;
        }
        data.sandboxes.insert(id, value.clone());
        Ok(value)
    }

    async fn delete_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        let mut value = owned(&data, tenant, id)?;
        if value.state == SandboxState::Quarantined {
            return Err(StoreError::Conflict(
                "quarantined sandbox requires explicit human release".into(),
            ));
        }
        value.state = SandboxState::Destroyed;
        value.updated_at = Utc::now();
        data.sandboxes.insert(id, value);
        Ok(())
    }

    async fn put_key(&self, value: ApiKeyRecord) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        if data.keys.contains_key(&value.id) {
            return Err(StoreError::Conflict("API key exists".into()));
        }
        data.keys.insert(value.id, value);
        Ok(())
    }

    async fn revoke_key(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        let value = data
            .keys
            .get_mut(&id)
            .filter(|value| value.tenant_id == tenant)
            .ok_or(StoreError::NotFound)?;
        value.revoked_at = Some(Utc::now());
        Ok(())
    }

    /// Lists a tenant's keys, newest first. The development store keeps the
    /// same shape as production so the dashboard behaves identically.
    async fn list_keys(&self, tenant: Uuid) -> Result<Vec<ApiKeyRecord>, StoreError> {
        let data = self.data.read().await;
        let mut keys: Vec<ApiKeyRecord> = data
            .keys
            .values()
            .filter(|value| value.tenant_id == tenant)
            .cloned()
            .collect();
        keys.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        Ok(keys)
    }

    async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, StoreError> {
        self.data
            .read()
            .await
            .keys
            .values()
            .find(|value| value.digest == *digest)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn put_snapshot(&self, value: Snapshot) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        // PostgreSQL keeps one `snapshots` row per snapshot: a basic insert and
        // a stored insert are the same primary key, not two records.
        if data.snapshots.contains_key(&value.id) || data.stored_snapshots.contains_key(&value.id) {
            return Err(StoreError::Conflict("snapshot exists".into()));
        }
        memory_artifact_gc::link_keys(&mut data, value.tenant_id, &[Some(&value.object_key)])?;
        data.snapshots.insert(value.id, value);
        Ok(())
    }

    async fn get_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<Snapshot, StoreError> {
        self.data
            .read()
            .await
            .snapshots
            .get(&id)
            .filter(|value| value.tenant_id == tenant)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn list_snapshots(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<Vec<Snapshot>, StoreError> {
        Ok(self
            .data
            .read()
            .await
            .snapshots
            .values()
            .filter(|value| value.tenant_id == tenant && value.sandbox_id == sandbox)
            .cloned()
            .collect())
    }

    async fn delete_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        // The stored and basic views are written together and share one owning
        // tenant, so either authorises the delete and a foreign tenant sees
        // nothing to delete.
        let owned = data
            .stored_snapshots
            .get(&id)
            .is_some_and(|value| value.tenant_id == tenant)
            || data
                .snapshots
                .get(&id)
                .is_some_and(|value| value.tenant_id == tenant);
        if !owned {
            return Err(StoreError::NotFound);
        }
        let basic_key = data
            .snapshots
            .get(&id)
            .map(|value| value.object_key.clone());
        data.snapshots.remove(&id);
        // One stored row carries every object role, so its keys are unlinked
        // once each; a basic-only snapshot references its primary key alone.
        match data.stored_snapshots.remove(&id) {
            Some(stored) => {
                memory_artifact_gc::unlink_keys(
                    &mut data,
                    &memory_artifact_gc::stored_keys(&stored),
                );
            }
            None => memory_artifact_gc::unlink_keys(&mut data, &[basic_key.as_deref()]),
        }
        Ok(())
    }

    async fn append_usage(&self, value: UsageEvent) -> Result<(), StoreError> {
        self.data.write().await.usage.push(value);
        Ok(())
    }

    async fn usage(&self, tenant: Uuid) -> Result<Vec<UsageSummary>, StoreError> {
        let mut grouped: HashMap<String, i64> = HashMap::new();
        for value in self
            .data
            .read()
            .await
            .usage
            .iter()
            .filter(|value| value.tenant_id == tenant)
        {
            *grouped.entry(value.metric.clone()).or_default() += value.quantity;
        }
        Ok(grouped
            .into_iter()
            .map(|(metric, quantity)| UsageSummary { metric, quantity })
            .collect())
    }

    async fn register_node(&self, value: Node) -> Result<Uuid, StoreError> {
        let mut nodes = self.data.write().await;
        // The name is unique, so re-registering adopts the record that already
        // holds it and reports its id back to the caller.
        let existing = nodes
            .nodes
            .iter()
            .find(|(_, node)| node.name == value.name)
            .map(|(id, _)| *id);
        let id = existing.unwrap_or(value.id);
        let mut node = value;
        node.id = id;
        nodes.nodes.insert(id, node);
        Ok(id)
    }

    async fn heartbeat(&self, id: Uuid) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        let node = data.nodes.get_mut(&id).ok_or(StoreError::NotFound)?;
        node.last_heartbeat = Utc::now();
        node.healthy = true;
        Ok(())
    }

    async fn list_nodes(&self) -> Result<Vec<Node>, StoreError> {
        Ok(self
            .data
            .read()
            .await
            .nodes
            .values()
            .filter(|node| {
                node.healthy && node.last_heartbeat > Utc::now() - chrono::Duration::seconds(30)
            })
            .cloned()
            .collect())
    }
    /// PostgreSQL records a stored snapshot as that same `snapshots` row, so the
    /// basic view is written with it under one lock: a stored-only insert is
    /// listable, gettable and deletable, and each object key is referenced once.
    async fn put_stored_snapshot(&self, value: StoredSnapshot) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        if data.snapshots.contains_key(&value.id) || data.stored_snapshots.contains_key(&value.id) {
            return Err(StoreError::Conflict("snapshot exists".into()));
        }
        memory_artifact_gc::link_keys(
            &mut data,
            value.tenant_id,
            &memory_artifact_gc::stored_keys(&value),
        )?;
        data.snapshots.insert(
            value.id,
            Snapshot {
                id: value.id,
                tenant_id: value.tenant_id,
                sandbox_id: value.sandbox_id,
                object_key: value.object_key.clone(),
                size_bytes: value.size_bytes,
                image_id: value.image_id.clone(),
                created_at: value.created_at,
            },
        );
        data.stored_snapshots.insert(value.id, value);
        Ok(())
    }

    async fn get_stored_snapshot(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<StoredSnapshot, StoreError> {
        self.data
            .read()
            .await
            .stored_snapshots
            .get(&id)
            .filter(|value| value.tenant_id == tenant)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn list_stored_snapshots(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<Vec<StoredSnapshot>, StoreError> {
        Ok(self
            .data
            .read()
            .await
            .stored_snapshots
            .values()
            .filter(|value| value.tenant_id == tenant && value.sandbox_id == sandbox)
            .cloned()
            .collect())
    }

    /// Records a request for one high-risk call.
    ///
    /// What is asked is fixed once written, matching the trigger on the
    /// Postgres table. An in-memory store that let a request be rewritten
    /// would make the API tests pass against a guarantee production does not
    /// have.
    pub async fn put_guard_tool_approval(
        &self,
        approval: GuardToolApproval,
    ) -> Result<GuardToolApproval, StoreError> {
        if approval.request_digest.len() != 64
            || !approval
                .request_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(StoreError::Conflict(
                "approval digest must be 64 lowercase hex characters".into(),
            ));
        }
        if approval.expires_at <= approval.created_at {
            return Err(StoreError::Conflict(
                "an approval must expire after it was made".into(),
            ));
        }
        let mut data = self.data.write().await;
        if data.guard_tool_approvals.contains_key(&approval.id) {
            return Err(StoreError::Conflict(
                "approval request already exists".into(),
            ));
        }
        data.guard_tool_approvals
            .insert(approval.id, approval.clone());
        Ok(approval)
    }

    /// Applies an operator's decision, refusing the cases that must never
    /// succeed: a decision by the requester, a decision on something already
    /// decided, and a decision naming an unknown request.
    ///
    /// Each refusal is `Ok(None)` rather than an error, because the caller
    /// answers all three the same way and an error would invite a retry of a
    /// request that is never going to be allowed.
    pub async fn decide_guard_tool_approval(
        &self,
        request: ApprovalDecisionRequest<'_>,
    ) -> Result<Option<GuardToolApproval>, StoreError> {
        if request.decision == ApprovalState::Pending {
            return Ok(None);
        }
        let mut data = self.data.write().await;
        let Some(approval) = data.guard_tool_approvals.get_mut(&request.request_id) else {
            return Ok(None);
        };
        if approval.tenant_id != request.tenant
            || approval.sandbox_id != request.sandbox
            || approval.state != ApprovalState::Pending
            || approval.requested_by_key_id == request.decided_by_key_id
            || request.at < approval.created_at
        {
            return Ok(None);
        }
        approval.state = request.decision;
        approval.decided_by_key_id = Some(request.decided_by_key_id);
        approval.decided_by_label = Some(request.decided_by_label.to_string());
        approval.decided_at = Some(request.at);
        Ok(Some(approval.clone()))
    }

    /// Spends a grant, once, for exactly the call it was made for.
    ///
    /// The whole check and the write happen under one write lock, which is
    /// what makes it single-use rather than merely "checked then set". A
    /// requester that does not match spends nothing: an approval belongs to
    /// the call that asked for it, not to whoever repeats it.
    pub async fn consume_guard_tool_approval(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        tool: &str,
        request_digest: &str,
        requested_by_key_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<GuardToolApproval>, StoreError> {
        let mut data = self.data.write().await;
        let candidate = data
            .guard_tool_approvals
            .values()
            .filter(|approval| {
                approval.tenant_id == tenant
                    && approval.sandbox_id == sandbox
                    && approval.tool == tool
                    && approval.request_digest == request_digest
                    && approval.requested_by_key_id == requested_by_key_id
                    && approval.state == ApprovalState::Granted
                    && approval.consumed_at.is_none()
                    && approval.expires_at > now
                    && approval.decided_at.is_some_and(|decided| decided <= now)
            })
            .max_by_key(|approval| (approval.decided_at, approval.id))
            .map(|approval| approval.id);
        let Some(id) = candidate else {
            return Ok(None);
        };
        let approval = data
            .guard_tool_approvals
            .get_mut(&id)
            .expect("the candidate was just found under the same lock");
        approval.consumed_at = Some(now);
        Ok(Some(approval.clone()))
    }

    pub async fn list_guard_tool_approvals(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<Vec<GuardToolApproval>, StoreError> {
        let data = self.data.read().await;
        let mut listed: Vec<GuardToolApproval> = data
            .guard_tool_approvals
            .values()
            .filter(|approval| approval.tenant_id == tenant && approval.sandbox_id == sandbox)
            .cloned()
            .collect();
        listed.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        Ok(listed)
    }
}

#[async_trait]
impl MetadataStore for MemoryRepository {
    async fn put_guard_budget(
        &self,
        state: GuardBudgetState,
    ) -> Result<GuardBudgetState, CoreError> {
        Self::put_guard_budget(self, state)
            .await
            .map_err(core_error)
    }
    async fn update_guard_policy_hash(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        policy_hash: &str,
    ) -> Result<(), CoreError> {
        Self::update_guard_policy_hash(self, tenant, sandbox, policy_hash)
            .await
            .map_err(core_error)
    }

    async fn release_guard_quarantine(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        released_by: &str,
    ) -> Result<Sandbox, CoreError> {
        Self::release_guard_quarantine(self, tenant, sandbox, released_by)
            .await
            .map_err(core_error)
    }

    async fn put_guard_proposal(
        &self,
        proposal: GuardProposal,
    ) -> Result<GuardProposal, CoreError> {
        Self::put_guard_proposal(self, proposal)
            .await
            .map_err(core_error)
    }

    async fn list_guard_proposals(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<Vec<GuardProposal>, CoreError> {
        Self::list_guard_proposals(self, tenant, sandbox)
            .await
            .map_err(core_error)
    }

    async fn get_guard_proposal(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
        id: Uuid,
    ) -> Result<GuardProposal, CoreError> {
        Self::get_guard_proposal(self, tenant, sandbox, id)
            .await
            .map_err(core_error)
    }

    async fn put_guard_tool_approval(
        &self,
        approval: GuardToolApproval,
    ) -> Result<GuardToolApproval, CoreError> {
        Self::put_guard_tool_approval(self, approval)
            .await
            .map_err(core_error)
    }

    async fn decide_guard_tool_approval(
        &self,
        request: ApprovalDecisionRequest<'_>,
    ) -> Result<Option<GuardToolApproval>, CoreError> {
        Self::decide_guard_tool_approval(self, request)
            .await
            .map_err(core_error)
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
        .map_err(core_error)
    }

    async fn list_guard_tool_approvals(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<Vec<GuardToolApproval>, CoreError> {
        Self::list_guard_tool_approvals(self, tenant, sandbox)
            .await
            .map_err(core_error)
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
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<GuardBudgetState>, CoreError> {
        Self::list_expired_guard_budgets(self, now)
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

    async fn get_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<Sandbox, CoreError> {
        Self::get_sandbox(self, tenant, id)
            .await
            .map_err(core_error)
    }

    async fn list_sandboxes(&self, tenant: Uuid) -> Result<Vec<Sandbox>, CoreError> {
        Self::list_sandboxes(self, tenant).await.map_err(core_error)
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
        _tenant: Uuid,
        _id: Uuid,
        _expected: SandboxState,
        _next: SandboxState,
        _lease_id: Uuid,
        _generation: i64,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
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

    async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, CoreError> {
        Self::find_key(self, digest).await.map_err(core_error)
    }

    async fn list_keys(&self, tenant: Uuid) -> Result<Vec<ApiKeyRecord>, CoreError> {
        Self::list_keys(self, tenant).await.map_err(core_error)
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
    ) -> Result<Vec<Snapshot>, CoreError> {
        Self::list_snapshots(self, tenant, sandbox)
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

    async fn heartbeat(&self, id: Uuid) -> Result<(), CoreError> {
        Self::heartbeat(self, id).await.map_err(core_error)
    }

    async fn list_nodes(&self) -> Result<Vec<Node>, CoreError> {
        Self::list_nodes(self).await.map_err(core_error)
    }

    async fn put_tenant(&self, value: TenantRecord) -> Result<(), CoreError> {
        // Tenants are real here, not stubbed: the public signup flow and the
        // dashboard must behave identically in development and production.
        let mut data = self.data.write().await;
        if data.tenants.contains_key(&value.id) {
            return Err(CoreError::Conflict("tenant already exists".into()));
        }
        data.tenants.insert(value.id, value);
        Ok(())
    }
    async fn get_tenant(&self, id: Uuid) -> Result<TenantRecord, CoreError> {
        let data = self.data.read().await;
        data.tenants
            .get(&id)
            .cloned()
            .ok_or_else(|| CoreError::NotFound("tenant not found".into()))
    }
    async fn list_sandbox_events(
        &self,
        _tenant: Uuid,
        _sandbox: Uuid,
        _limit: u32,
    ) -> Result<Vec<SandboxEvent>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
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
    async fn list_stored_snapshots(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<Vec<StoredSnapshot>, CoreError> {
        Self::list_stored_snapshots(self, tenant, sandbox)
            .await
            .map_err(core_error)
    }
    async fn create_sandbox_idempotent(
        &self,
        _tenant: Uuid,
        _request_id: Uuid,
        _sandbox: Sandbox,
    ) -> Result<Sandbox, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn register_worker(&self, _value: WorkerRegistration) -> Result<Uuid, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn heartbeat_worker(
        &self,
        _heartbeat: WorkerHeartbeat,
    ) -> Result<WorkerStatus, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn get_worker(&self, _node_id: Uuid) -> Result<WorkerStatus, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn list_workers(&self, _include_unhealthy: bool) -> Result<Vec<WorkerStatus>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn set_worker_draining(
        &self,
        _node_id: Uuid,
        _draining: bool,
        _reason: Option<&str>,
    ) -> Result<WorkerStatus, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn claim_worker_assignments(
        &self,
        _node_id: Uuid,
        _limit: u32,
        _lease_ttl_seconds: u64,
    ) -> Result<Vec<WorkerAssignment>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn list_worker_assignments(
        &self,
        _tenant: Uuid,
        _node_id: Uuid,
        _status: Option<&str>,
        _limit: u32,
    ) -> Result<Vec<WorkerAssignment>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn list_worker_assignments_for_node(
        &self,
        _node_id: Uuid,
        _status: Option<&str>,
        _limit: u32,
    ) -> Result<Vec<WorkerAssignment>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn get_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
    ) -> Result<WorkerLease, CoreError> {
        self.data
            .read()
            .await
            .leases
            .get(&lease_id)
            .filter(|lease| lease.tenant_id == tenant)
            .cloned()
            .ok_or_else(|| CoreError::NotFound("lease not found".into()))
    }
    async fn get_active_worker_lease(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<WorkerLease, CoreError> {
        self.data
            .read()
            .await
            .leases
            .values()
            .find(|lease| {
                lease.tenant_id == tenant
                    && lease.sandbox_id == sandbox
                    && lease.status == "active"
                    && lease.expires_at > Utc::now()
            })
            .cloned()
            .ok_or_else(|| CoreError::NotFound("active lease not found".into()))
    }
    async fn renew_worker_lease(
        &self,
        tenant: Uuid,
        lease_id: Uuid,
        generation: i64,
        ttl_seconds: u64,
    ) -> Result<WorkerLease, CoreError> {
        if !(1..=3600).contains(&ttl_seconds) {
            return Err(CoreError::InvalidRequest(
                "lease TTL must be between 1 and 3600 seconds".into(),
            ));
        }
        let mut data = self.data.write().await;
        let lease = data
            .leases
            .get_mut(&lease_id)
            .filter(|lease| lease.tenant_id == tenant)
            .ok_or_else(|| CoreError::NotFound("lease not found".into()))?;
        if lease.generation != generation
            || lease.status != "active"
            || lease.expires_at <= Utc::now()
        {
            return Err(CoreError::Conflict("lease is no longer current".into()));
        }
        lease.generation = lease
            .generation
            .checked_add(1)
            .ok_or_else(|| CoreError::Conflict("lease generation overflow".into()))?;
        lease.updated_at = Utc::now();
        lease.expires_at = lease.updated_at + chrono::Duration::seconds(ttl_seconds as i64);
        Ok(lease.clone())
    }
    async fn complete_worker_lease(
        &self,
        _tenant: Uuid,
        _lease_id: Uuid,
        _generation: i64,
        _result: serde_json::Value,
    ) -> Result<WorkerLease, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn release_worker_lease(
        &self,
        _tenant: Uuid,
        _lease_id: Uuid,
        _generation: i64,
        _reason: &str,
    ) -> Result<WorkerLease, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn reconcile_expired_leases(
        &self,
        _limit: u32,
    ) -> Result<Vec<ReconciliationAction>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn reassign_expired_lease(
        &self,
        _lease_id: Uuid,
    ) -> Result<Option<Reassignment>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn sandbox_ownership(
        &self,
        _sandbox_id: Uuid,
    ) -> Result<Option<SandboxOwnership>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn list_reconciliation_actions(
        &self,
        _tenant: Uuid,
        _limit: u32,
    ) -> Result<Vec<ReconciliationAction>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn begin_sandbox_operation(
        &self,
        _value: SandboxOperation,
    ) -> Result<SandboxOperation, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn complete_sandbox_operation(
        &self,
        _tenant: Uuid,
        _request_id: Uuid,
        _result: serde_json::Value,
    ) -> Result<SandboxOperation, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn fail_sandbox_operation(
        &self,
        _tenant: Uuid,
        _request_id: Uuid,
        _error: serde_json::Value,
    ) -> Result<SandboxOperation, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn get_sandbox_operation(
        &self,
        _tenant: Uuid,
        _request_id: Uuid,
    ) -> Result<SandboxOperation, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn put_image(&self, _value: ImageRecord) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn get_image(&self, _id: &str) -> Result<ImageRecord, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn append_audit_event(&self, _event: AuditEvent) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }
    async fn list_audit_events(
        &self,
        _tenant: Option<Uuid>,
        _action: Option<&str>,
        _limit: u32,
    ) -> Result<Vec<AuditEvent>, CoreError> {
        Err(CoreError::Unsupported("memory metadata store".into()))
    }

    async fn reserve_artifact_upload(
        &self,
        tenant: Uuid,
        run: Option<Uuid>,
        key: &str,
    ) -> Result<(), CoreError> {
        Self::reserve_artifact_upload(self, tenant, run, key).await
    }
    async fn complete_artifact_upload(
        &self,
        tenant: Uuid,
        run: Option<Uuid>,
        key: &str,
    ) -> Result<(), CoreError> {
        Self::complete_artifact_upload(self, tenant, run, key).await
    }
    async fn claim_artifact_deletions(
        &self,
        now: chrono::DateTime<Utc>,
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
    }
    async fn finish_artifact_deletion(
        &self,
        key: &str,
        claim: Uuid,
        deleted: bool,
        retry_at: chrono::DateTime<Utc>,
    ) -> Result<(), CoreError> {
        Self::finish_artifact_deletion(self, key, claim, deleted, retry_at).await
    }
}

#[derive(Clone)]
pub struct PostgresRepository {
    pub pool: PgPool,
}

impl PostgresRepository {
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        Ok(Self {
            pool: sqlx::postgres::PgPoolOptions::new()
                .max_connections(20)
                .connect(url)
                .await
                .map_err(database_error)?,
        })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        Ok(())
    }
}
