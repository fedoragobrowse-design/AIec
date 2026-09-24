mod object_store;
mod postgres;

pub use object_store::{
    FilesystemObjectStore, GetObjectOptions, ObjectMetadata, ObjectStore, S3Config, S3ObjectStore,
};
pub use postgres::PostgresScheduler;

use agentforge_core::*;
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantRecord {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxEvent {
    pub id: Uuid,
    pub sandbox_id: Uuid,
    pub tenant_id: Uuid,
    pub from_state: Option<SandboxState>,
    pub to_state: SandboxState,
    pub reason: Option<String>,
    pub occurred_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSnapshot {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub sandbox_id: Uuid,
    pub object_key: String,
    pub manifest_object_key: String,
    pub memory_object_key: Option<String>,
    pub disk_object_key: Option<String>,
    pub workspace_object_key: Option<String>,
    pub size_bytes: u64,
    pub image_id: String,
    pub checksum_sha256: String,
    pub kind: String,
    pub complete: bool,
    pub manifest: Value,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerRegistration {
    pub node_id: Uuid,
    pub name: String,
    pub runtime: RuntimeKind,
    pub control_endpoint: String,
    pub total_vcpus: u32,
    pub total_memory_bytes: u64,
    pub total_disk_bytes: u64,
    pub available_vcpus: u32,
    pub available_memory_bytes: u64,
    pub available_disk_bytes: u64,
    pub healthy: bool,
    pub version: u64,
    pub metadata: Value,
    pub started_at: chrono::DateTime<Utc>,
    pub last_heartbeat: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerHeartbeat {
    pub node_id: Uuid,
    pub available_vcpus: u32,
    pub available_memory_bytes: u64,
    pub available_disk_bytes: u64,
    pub sandbox_count: u32,
    pub healthy: bool,
    pub version: u64,
    pub metadata: Value,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub registration: WorkerRegistration,
    pub sandbox_count: u32,
    pub observed_sandbox_count: u32,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerLease {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub sandbox_id: Uuid,
    pub node_id: Uuid,
    pub generation: i64,
    pub status: String,
    pub reason: Option<String>,
    pub expires_at: chrono::DateTime<Utc>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScheduledSandbox {
    pub sandbox: Sandbox,
    pub lease: WorkerLease,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerAssignment {
    pub tenant_id: Uuid,
    pub request_id: Uuid,
    pub sandbox: Sandbox,
    pub lease: WorkerLease,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconciliationAction {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub node_id: Uuid,
    pub sandbox_id: Option<Uuid>,
    pub lease_id: Option<Uuid>,
    pub source_key: String,
    pub action: String,
    pub reason: String,
    pub detected_at: chrono::DateTime<Utc>,
    pub processed_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxOperation {
    pub tenant_id: Uuid,
    pub request_id: Uuid,
    pub sandbox_id: Uuid,
    pub operation: String,
    pub payload: Value,
    pub status: String,
    pub result: Option<Value>,
    pub error: Option<Value>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[async_trait]
pub trait Repository: Send + Sync {
    async fn create_sandbox(&self, value: Sandbox) -> Result<(), StoreError>;
    async fn get_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<Sandbox, StoreError>;
    async fn list_sandboxes(&self, tenant: Uuid) -> Result<Vec<Sandbox>, StoreError>;
    async fn update_state(
        &self,
        tenant: Uuid,
        id: Uuid,
        expected: SandboxState,
        next: SandboxState,
        runtime_path: Option<String>,
    ) -> Result<Sandbox, StoreError>;
    async fn delete_sandbox(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError>;
    async fn put_key(&self, value: ApiKeyRecord) -> Result<(), StoreError>;
    async fn revoke_key(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError>;
    async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, StoreError>;
    async fn put_snapshot(&self, value: Snapshot) -> Result<(), StoreError>;
    async fn get_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<Snapshot, StoreError>;
    async fn list_snapshots(
        &self,
        tenant: Uuid,
        sandbox: Uuid,
    ) -> Result<Vec<Snapshot>, StoreError>;
    async fn delete_snapshot(&self, tenant: Uuid, id: Uuid) -> Result<(), StoreError>;
    async fn append_usage(&self, value: UsageEvent) -> Result<(), StoreError>;
    async fn usage(&self, tenant: Uuid) -> Result<Vec<UsageSummary>, StoreError>;
    async fn register_node(&self, value: Node) -> Result<(), StoreError>;
    async fn heartbeat(&self, id: Uuid) -> Result<(), StoreError>;
    async fn list_nodes(&self) -> Result<Vec<Node>, StoreError>;

    async fn put_tenant(&self, value: TenantRecord) -> Result<(), StoreError> {
        let _ = value;
        Err(StoreError::Unsupported("put_tenant"))
    }
    async fn get_tenant(&self, _id: Uuid) -> Result<TenantRecord, StoreError> {
        Err(StoreError::Unsupported("get_tenant"))
    }
    async fn list_sandbox_events(
        &self,
        _tenant: Uuid,
        _sandbox: Uuid,
        _limit: u32,
    ) -> Result<Vec<SandboxEvent>, StoreError> {
        Err(StoreError::Unsupported("list_sandbox_events"))
    }
    async fn put_stored_snapshot(&self, value: StoredSnapshot) -> Result<(), StoreError> {
        let _ = value;
        Err(StoreError::Unsupported("put_stored_snapshot"))
    }
    async fn get_stored_snapshot(
        &self,
        _tenant: Uuid,
        _id: Uuid,
    ) -> Result<StoredSnapshot, StoreError> {
        Err(StoreError::Unsupported("get_stored_snapshot"))
    }
    async fn list_stored_snapshots(
        &self,
        _tenant: Uuid,
        _sandbox: Uuid,
    ) -> Result<Vec<StoredSnapshot>, StoreError> {
        Err(StoreError::Unsupported("list_stored_snapshots"))
    }
    async fn create_sandbox_idempotent(
        &self,
        _tenant: Uuid,
        _request_id: Uuid,
        _sandbox: Sandbox,
    ) -> Result<Sandbox, StoreError> {
        Err(StoreError::Unsupported("create_sandbox_idempotent"))
    }
    async fn register_worker(&self, _value: WorkerRegistration) -> Result<(), StoreError> {
        Err(StoreError::Unsupported("register_worker"))
    }
    async fn heartbeat_worker(
        &self,
        _heartbeat: WorkerHeartbeat,
    ) -> Result<WorkerStatus, StoreError> {
        Err(StoreError::Unsupported("heartbeat_worker"))
    }
    async fn get_worker(&self, _node_id: Uuid) -> Result<WorkerStatus, StoreError> {
        Err(StoreError::Unsupported("get_worker"))
    }
    async fn list_workers(
        &self,
        _include_unhealthy: bool,
    ) -> Result<Vec<WorkerStatus>, StoreError> {
        Err(StoreError::Unsupported("list_workers"))
    }
    async fn claim_worker_assignments(
        &self,
        _node_id: Uuid,
        _limit: u32,
        _lease_ttl_seconds: u64,
    ) -> Result<Vec<WorkerAssignment>, StoreError> {
        Err(StoreError::Unsupported("claim_worker_assignments"))
    }
    async fn list_worker_assignments(
        &self,
        _tenant: Uuid,
        _node_id: Uuid,
        _status: Option<&str>,
        _limit: u32,
    ) -> Result<Vec<WorkerAssignment>, StoreError> {
        Err(StoreError::Unsupported("list_worker_assignments"))
    }
    async fn list_worker_assignments_for_node(
        &self,
        _node_id: Uuid,
        _status: Option<&str>,
        _limit: u32,
    ) -> Result<Vec<WorkerAssignment>, StoreError> {
        Err(StoreError::Unsupported("list_worker_assignments_for_node"))
    }
    async fn get_worker_lease(
        &self,
        _tenant: Uuid,
        _lease_id: Uuid,
    ) -> Result<WorkerLease, StoreError> {
        Err(StoreError::Unsupported("get_worker_lease"))
    }

    async fn get_active_worker_lease(
        &self,
        _tenant: Uuid,
        _sandbox: Uuid,
    ) -> Result<WorkerLease, StoreError> {
        Err(StoreError::Unsupported("get_active_worker_lease"))
    }
    async fn renew_worker_lease(
        &self,
        _tenant: Uuid,
        _lease_id: Uuid,
        _generation: i64,
        _ttl_seconds: u64,
    ) -> Result<WorkerLease, StoreError> {
        Err(StoreError::Unsupported("renew_worker_lease"))
    }
    async fn complete_worker_lease(
        &self,
        _tenant: Uuid,
        _lease_id: Uuid,
        _generation: i64,
        _result: Value,
    ) -> Result<WorkerLease, StoreError> {
        Err(StoreError::Unsupported("complete_worker_lease"))
    }
    async fn release_worker_lease(
        &self,
        _tenant: Uuid,
        _lease_id: Uuid,
        _generation: i64,
        _reason: &str,
    ) -> Result<WorkerLease, StoreError> {
        Err(StoreError::Unsupported("release_worker_lease"))
    }
    async fn reconcile_expired_leases(
        &self,
        _limit: u32,
    ) -> Result<Vec<ReconciliationAction>, StoreError> {
        Err(StoreError::Unsupported("reconcile_expired_leases"))
    }
    async fn list_reconciliation_actions(
        &self,
        _tenant: Uuid,
        _limit: u32,
    ) -> Result<Vec<ReconciliationAction>, StoreError> {
        Err(StoreError::Unsupported("list_reconciliation_actions"))
    }
    async fn begin_sandbox_operation(
        &self,
        value: SandboxOperation,
    ) -> Result<SandboxOperation, StoreError> {
        let _ = value;
        Err(StoreError::Unsupported("begin_sandbox_operation"))
    }
    async fn complete_sandbox_operation(
        &self,
        _tenant: Uuid,
        _request_id: Uuid,
        _result: Value,
    ) -> Result<SandboxOperation, StoreError> {
        Err(StoreError::Unsupported("complete_sandbox_operation"))
    }
    async fn fail_sandbox_operation(
        &self,
        _tenant: Uuid,
        _request_id: Uuid,
        _error: Value,
    ) -> Result<SandboxOperation, StoreError> {
        Err(StoreError::Unsupported("fail_sandbox_operation"))
    }
    async fn get_sandbox_operation(
        &self,
        _tenant: Uuid,
        _request_id: Uuid,
    ) -> Result<SandboxOperation, StoreError> {
        Err(StoreError::Unsupported("get_sandbox_operation"))
    }
    async fn put_image(&self, _value: ImageRecord) -> Result<(), StoreError> {
        Err(StoreError::Unsupported("put_image"))
    }
    async fn get_image(&self, _id: &str) -> Result<ImageRecord, StoreError> {
        Err(StoreError::Unsupported("get_image"))
    }
}

#[async_trait]
pub trait Scheduler: Send + Sync {
    async fn schedule_sandbox(
        &self,
        tenant: Uuid,
        request_id: Uuid,
        sandbox: Sandbox,
        lease_ttl_seconds: u64,
    ) -> Result<ScheduledSandbox, StoreError> {
        self.schedule_sandbox_on_node(tenant, request_id, sandbox, lease_ttl_seconds, None)
            .await
    }

    async fn schedule_sandbox_on_node(
        &self,
        tenant: Uuid,
        request_id: Uuid,
        sandbox: Sandbox,
        lease_ttl_seconds: u64,
        preferred_node: Option<Uuid>,
    ) -> Result<ScheduledSandbox, StoreError>;
}

#[derive(Default)]
struct MemoryData {
    sandboxes: HashMap<Uuid, Sandbox>,
    keys: HashMap<Uuid, ApiKeyRecord>,
    snapshots: HashMap<Uuid, Snapshot>,
    usage: Vec<UsageEvent>,
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

#[async_trait]
impl Repository for MemoryRepository {
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
