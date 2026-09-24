mod images;
mod object_store;
mod postgres;
mod snapshots;

pub use images::StandardImageResolver;
pub use object_store::{
    FilesystemObjectStore, S3Config, S3ObjectStore,
};
pub use postgres::PostgresScheduler;
pub use snapshots::{snapshot_capabilities, snapshot_kind, snapshot_metadata};

use agentforge_core::{
    ApiKeyRecord, ImageRecord, Node, Sandbox, SandboxState, Snapshot, UsageEvent, UsageSummary,
    CoreError,
    storage::{
        MetadataStore, ReconciliationAction, SandboxEvent, SandboxOperation, StoredSnapshot,
        TenantRecord, WorkerAssignment, WorkerHeartbeat, WorkerLease, WorkerRegistration,
        WorkerStatus,
    },
};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc};
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
        if data.snapshots.contains_key(&value.id) {
            return Err(StoreError::Conflict("snapshot exists".into()));
        }
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
        if data
            .snapshots
            .remove(&id)
            .filter(|value| value.tenant_id == tenant)
            .is_none()
        {
            return Err(StoreError::NotFound);
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

    async fn register_node(&self, value: Node) -> Result<(), StoreError> {
        self.data.write().await.nodes.insert(value.id, value);
        Ok(())
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
    async fn put_stored_snapshot(&self, value: StoredSnapshot) -> Result<(), StoreError> {
        let mut data = self.data.write().await;
        if data.stored_snapshots.contains_key(&value.id) {
            return Err(StoreError::Conflict("snapshot exists".into()));
        }
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

}

#[async_trait]
impl MetadataStore for MemoryRepository {
    async fn create_sandbox(&self, value: Sandbox) -> Result<(), CoreError> {
        Self::create_sandbox(self, value).await.map_err(core_error)
    }

    async fn get_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<Sandbox, CoreError> {
        Self::get_sandbox(self, tenant, id).await.map_err(core_error)
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

    async fn register_node(&self, value: Node) -> Result<(), CoreError> {
        Self::register_node(self, value).await.map_err(core_error)
    }

    async fn heartbeat(&self, id: Uuid) -> Result<(), CoreError> {
        Self::heartbeat(self, id).await.map_err(core_error)
    }

    async fn list_nodes(&self) -> Result<Vec<Node>, CoreError> {
        Self::list_nodes(self).await.map_err(core_error)
    }


    async fn put_tenant(&self, _value: TenantRecord) -> Result<(), CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn get_tenant(&self, _id: Uuid) -> Result<TenantRecord, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn list_sandbox_events(&self, _tenant: Uuid, _sandbox: Uuid, _limit: u32) -> Result<Vec<SandboxEvent>, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn put_stored_snapshot(&self, value: StoredSnapshot) -> Result<(), CoreError> {
        Self::put_stored_snapshot(self, value).await.map_err(core_error)
    }
    async fn get_stored_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<StoredSnapshot, CoreError> {
        Self::get_stored_snapshot(self, tenant, id).await.map_err(core_error)
    }
    async fn list_stored_snapshots(&self, tenant: Uuid, sandbox: Uuid) -> Result<Vec<StoredSnapshot>, CoreError> {
        Self::list_stored_snapshots(self, tenant, sandbox).await.map_err(core_error)
    }
    async fn create_sandbox_idempotent(&self, _tenant: Uuid, _request_id: Uuid, _sandbox: Sandbox) -> Result<Sandbox, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn register_worker(&self, _value: WorkerRegistration) -> Result<(), CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn heartbeat_worker(&self, _heartbeat: WorkerHeartbeat) -> Result<WorkerStatus, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn get_worker(&self, _node_id: Uuid) -> Result<WorkerStatus, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn list_workers(&self, _include_unhealthy: bool) -> Result<Vec<WorkerStatus>, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn claim_worker_assignments(&self, _node_id: Uuid, _limit: u32, _lease_ttl_seconds: u64) -> Result<Vec<WorkerAssignment>, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn list_worker_assignments(&self, _tenant: Uuid, _node_id: Uuid, _status: Option<&str>, _limit: u32) -> Result<Vec<WorkerAssignment>, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn list_worker_assignments_for_node(&self, _node_id: Uuid, _status: Option<&str>, _limit: u32) -> Result<Vec<WorkerAssignment>, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn get_worker_lease(&self, _tenant: Uuid, _lease_id: Uuid) -> Result<WorkerLease, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn get_active_worker_lease(&self, _tenant: Uuid, _sandbox: Uuid) -> Result<WorkerLease, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn renew_worker_lease(&self, _tenant: Uuid, _lease_id: Uuid, _generation: i64, _ttl_seconds: u64) -> Result<WorkerLease, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn complete_worker_lease(&self, _tenant: Uuid, _lease_id: Uuid, _generation: i64, _result: serde_json::Value) -> Result<WorkerLease, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn release_worker_lease(&self, _tenant: Uuid, _lease_id: Uuid, _generation: i64, _reason: &str) -> Result<WorkerLease, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn reconcile_expired_leases(&self, _limit: u32) -> Result<Vec<ReconciliationAction>, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn list_reconciliation_actions(&self, _tenant: Uuid, _limit: u32) -> Result<Vec<ReconciliationAction>, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn begin_sandbox_operation(&self, _value: SandboxOperation) -> Result<SandboxOperation, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn complete_sandbox_operation(&self, _tenant: Uuid, _request_id: Uuid, _result: serde_json::Value) -> Result<SandboxOperation, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn fail_sandbox_operation(&self, _tenant: Uuid, _request_id: Uuid, _error: serde_json::Value) -> Result<SandboxOperation, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn get_sandbox_operation(&self, _tenant: Uuid, _request_id: Uuid) -> Result<SandboxOperation, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn put_image(&self, _value: ImageRecord) -> Result<(), CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
    async fn get_image(&self, _id: &str) -> Result<ImageRecord, CoreError> { Err(CoreError::Unsupported("memory metadata store".into())) }
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
