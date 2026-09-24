//! Metadata persistence and large artifact storage boundaries.

use crate::{
    ApiKeyRecord, CoreError, ImageRecord, Node, RuntimeKind, Sandbox, SandboxState, Snapshot,
    UsageEvent, UsageSummary,
};
use uuid::Uuid;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::{LeaseId, RequestId, SandboxId, SnapshotId, TenantId, WorkerId};

/// Metadata returned after writing an artifact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectMetadata {
    /// Stable object key.
    pub key: String,
    /// Encoded object size in bytes.
    pub size_bytes: u64,
    /// Lowercase hexadecimal SHA-256 checksum.
    pub checksum_sha256: String,
    /// Optional backend version tag.
    pub etag: Option<String>,
}

/// Integrity preconditions for reading an artifact.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetObjectOptions {
    /// Require a particular backend version tag.
    pub if_match: Option<String>,
    /// Require a particular SHA-256 checksum.
    pub expected_checksum_sha256: Option<String>,
}

/// Stores large opaque artifacts independently from relational metadata.
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    /// Writes bytes at `key`; existing-key behavior is defined by the backend.
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata, CoreError>;
    /// Reads an artifact without integrity preconditions.
    async fn get(&self, key: &str) -> Result<Vec<u8>, CoreError>;
    /// Reads an artifact only when all supplied preconditions match.
    async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, CoreError>;
    /// Deletes an artifact.
    async fn delete(&self, key: &str) -> Result<(), CoreError>;
    /// Deletes an artifact only when its version tag matches.
    async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), CoreError>;
}

/// A tenant record persisted by the metadata store.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantRecord {
    /// Tenant identifier.
    pub id: TenantId,
    /// Display name.
    pub name: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// An immutable state transition in a sandbox lifecycle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxEvent {
    /// Event identifier.
    pub id: Uuid,
    /// Sandbox whose state changed.
    pub sandbox_id: SandboxId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Previous state, if the sandbox already existed.
    pub from_state: Option<SandboxState>,
    /// New state.
    pub to_state: SandboxState,
    /// Optional reason for the transition.
    pub reason: Option<String>,
    /// Transition timestamp.
    pub occurred_at: DateTime<Utc>,
}

/// Durable snapshot metadata, including references to artifact objects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredSnapshot {
    /// Snapshot identifier.
    pub id: SnapshotId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Source sandbox.
    pub sandbox_id: SandboxId,
    /// Primary snapshot object key.
    pub object_key: String,
    /// Snapshot manifest object key.
    pub manifest_object_key: String,
    /// Optional VM memory object key.
    pub memory_object_key: Option<String>,
    /// Optional VM disk object key.
    pub disk_object_key: Option<String>,
    /// Optional workspace object key.
    pub workspace_object_key: Option<String>,
    /// Total stored byte count.
    pub size_bytes: u64,
    /// Source image identifier.
    pub image_id: String,
    /// SHA-256 checksum of the primary object.
    pub checksum_sha256: String,
    /// Backend-specific snapshot kind.
    pub kind: String,
    /// Whether every required object is durable.
    pub complete: bool,
    /// Backend-specific manifest.
    pub manifest: Value,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Capabilities and capacity advertised when a worker registers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WorkerRegistration {
    /// Stable worker identifier.
    pub node_id: WorkerId,
    /// Human-readable worker name.
    pub name: String,
    /// Runtime selected by the worker.
    pub runtime: RuntimeKind,
    /// Dispatch endpoint.
    pub control_endpoint: String,
    /// Total vCPU capacity.
    pub total_vcpus: u32,
    /// Total memory capacity in bytes.
    pub total_memory_bytes: u64,
    /// Total disk capacity in bytes.
    pub total_disk_bytes: u64,
    /// Currently allocatable vCPUs.
    pub available_vcpus: u32,
    /// Currently allocatable memory in bytes.
    pub available_memory_bytes: u64,
    /// Currently allocatable disk in bytes.
    pub available_disk_bytes: u64,
    /// Whether the worker is accepting work.
    pub healthy: bool,
    /// Worker protocol version.
    pub version: u64,
    /// Backend-specific labels and capabilities.
    pub metadata: Value,
    /// Worker process start time.
    pub started_at: DateTime<Utc>,
    /// Most recent heartbeat time.
    pub last_heartbeat: DateTime<Utc>,
}

/// Resource update sent with a worker heartbeat.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WorkerHeartbeat {
    /// Worker identifier.
    pub node_id: WorkerId,
    /// Currently allocatable vCPUs.
    pub available_vcpus: u32,
    /// Currently allocatable memory in bytes.
    pub available_memory_bytes: u64,
    /// Currently allocatable disk in bytes.
    pub available_disk_bytes: u64,
    /// Number of assigned sandboxes.
    pub sandbox_count: u32,
    /// Whether the worker remains healthy.
    pub healthy: bool,
    /// Worker protocol version.
    pub version: u64,
    /// Backend-specific metadata.
    pub metadata: Value,
    /// Most recent failure, if any.
    pub last_error: Option<String>,
}

/// Current persisted view of a worker.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WorkerStatus {
    /// Registration and capacity.
    pub registration: WorkerRegistration,
    /// Expected assignment count.
    pub sandbox_count: u32,
    /// Assignment count reported by the worker.
    pub observed_sandbox_count: u32,
    /// Most recent failure, if any.
    pub last_error: Option<String>,
}

/// Fencing lease for one sandbox assigned to one worker.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerLease {
    /// Lease identifier.
    pub id: LeaseId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Leased sandbox.
    pub sandbox_id: SandboxId,
    /// Worker holding the lease.
    pub node_id: WorkerId,
    /// Monotonic fencing generation.
    pub generation: i64,
    /// Backend-defined lease status.
    pub status: String,
    /// Completion or release reason.
    pub reason: Option<String>,
    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last mutation timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable work assignment consumed by a worker.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WorkerAssignment {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Idempotency request identifier.
    pub request_id: RequestId,
    /// Sandbox to execute.
    pub sandbox: Sandbox,
    /// Fencing lease.
    pub lease: WorkerLease,
    /// Backend-defined assignment status.
    pub status: String,
}

/// Durable repair action for inconsistent scheduler state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconciliationAction {
    /// Action identifier.
    pub id: Uuid,
    /// Affected tenant.
    pub tenant_id: TenantId,
    /// Affected worker.
    pub node_id: WorkerId,
    /// Affected sandbox, if any.
    pub sandbox_id: Option<SandboxId>,
    /// Affected lease, if any.
    pub lease_id: Option<LeaseId>,
    /// Source state key.
    pub source_key: String,
    /// Requested repair action.
    pub action: String,
    /// Detection reason.
    pub reason: String,
    /// Detection timestamp.
    pub detected_at: DateTime<Utc>,
    /// Processing timestamp.
    pub processed_at: DateTime<Utc>,
}

/// Durable, idempotent sandbox operation record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SandboxOperation {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Idempotency request identifier.
    pub request_id: RequestId,
    /// Target sandbox.
    pub sandbox_id: SandboxId,
    /// Operation name.
    pub operation: String,
    /// Operation input.
    pub payload: Value,
    /// Operation status.
    pub status: String,
    /// Successful result, if complete.
    pub result: Option<Value>,
    /// Failure details, if failed.
    pub error: Option<Value>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last mutation timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Persists AgentForge domain metadata with tenant-scoped access semantics.
#[async_trait]
pub trait MetadataStore: Send + Sync {
    /// Creates a sandbox.
    async fn create_sandbox(&self, value: Sandbox) -> Result<(), CoreError>;
    /// Gets a tenant-owned sandbox.
    async fn get_sandbox(&self, tenant: TenantId, id: SandboxId) -> Result<Sandbox, CoreError>;
    /// Lists all sandboxes owned by a tenant.
    async fn list_sandboxes(&self, tenant: TenantId) -> Result<Vec<Sandbox>, CoreError>;
    /// Performs a compare-and-set state transition.
    async fn update_state(
        &self,
        tenant: TenantId,
        id: SandboxId,
        expected: SandboxState,
        next: SandboxState,
        runtime_path: Option<String>,
    ) -> Result<Sandbox, CoreError>;
    /// Deletes a tenant-owned sandbox.
    async fn delete_sandbox(&self, tenant: TenantId, id: SandboxId) -> Result<(), CoreError>;
    /// Creates an API key record and returns conflict if its ID already exists.
    async fn put_key(&self, value: ApiKeyRecord) -> Result<(), CoreError>;
    /// Revokes a tenant-owned API key.
    async fn revoke_key(&self, tenant: TenantId, id: Uuid) -> Result<(), CoreError>;
    /// Finds an API key by digest.
    async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, CoreError>;
    /// Stores snapshot metadata.
    async fn put_snapshot(&self, value: Snapshot) -> Result<(), CoreError>;
    /// Gets tenant-owned snapshot metadata.
    async fn get_snapshot(&self, tenant: TenantId, id: SnapshotId) -> Result<Snapshot, CoreError>;
    /// Lists snapshots for a tenant-owned sandbox.
    async fn list_snapshots(
        &self,
        tenant: TenantId,
        sandbox: SandboxId,
    ) -> Result<Vec<Snapshot>, CoreError>;
    /// Deletes tenant-owned snapshot metadata.
    async fn delete_snapshot(&self, tenant: TenantId, id: SnapshotId) -> Result<(), CoreError>;
    /// Appends a usage event.
    async fn append_usage(&self, value: UsageEvent) -> Result<(), CoreError>;
    /// Aggregates usage for a tenant.
    async fn usage(&self, tenant: TenantId) -> Result<Vec<UsageSummary>, CoreError>;
    /// Registers a legacy node resource record.
    async fn register_node(&self, value: Node) -> Result<(), CoreError>;
    /// Updates a legacy node heartbeat.
    async fn heartbeat(&self, id: Uuid) -> Result<(), CoreError>;
    /// Lists registered legacy nodes.
    async fn list_nodes(&self) -> Result<Vec<Node>, CoreError>;
    /// Stores a tenant.
    async fn put_tenant(&self, value: TenantRecord) -> Result<(), CoreError>;
    /// Gets a tenant.
    async fn get_tenant(&self, id: TenantId) -> Result<TenantRecord, CoreError>;
    /// Lists recent lifecycle events for a sandbox.
    async fn list_sandbox_events(
        &self,
        tenant: TenantId,
        sandbox: SandboxId,
        limit: u32,
    ) -> Result<Vec<SandboxEvent>, CoreError>;
    /// Stores detailed snapshot metadata.
    async fn put_stored_snapshot(&self, value: StoredSnapshot) -> Result<(), CoreError>;
    /// Gets detailed snapshot metadata.
    async fn get_stored_snapshot(
        &self,
        tenant: TenantId,
        id: SnapshotId,
    ) -> Result<StoredSnapshot, CoreError>;
    /// Lists detailed snapshot metadata for a sandbox.
    async fn list_stored_snapshots(
        &self,
        tenant: TenantId,
        sandbox: SandboxId,
    ) -> Result<Vec<StoredSnapshot>, CoreError>;
    /// Idempotently creates a sandbox for a request.
    async fn create_sandbox_idempotent(
        &self,
        tenant: TenantId,
        request_id: RequestId,
        sandbox: Sandbox,
    ) -> Result<Sandbox, CoreError>;
    /// Registers a worker and its capacity.
    async fn register_worker(&self, value: WorkerRegistration) -> Result<(), CoreError>;
    /// Applies a worker heartbeat atomically.
    async fn heartbeat_worker(&self, heartbeat: WorkerHeartbeat) -> Result<WorkerStatus, CoreError>;
    /// Gets current worker state.
    async fn get_worker(&self, node_id: WorkerId) -> Result<WorkerStatus, CoreError>;
    /// Lists workers, optionally including unhealthy workers.
    async fn list_workers(&self, include_unhealthy: bool) -> Result<Vec<WorkerStatus>, CoreError>;
    /// Claims pending assignments for a worker.
    async fn claim_worker_assignments(
        &self,
        node_id: WorkerId,
        limit: u32,
        lease_ttl_seconds: u64,
    ) -> Result<Vec<WorkerAssignment>, CoreError>;
    /// Lists assignments for a tenant and worker, optionally filtered by status.
    async fn list_worker_assignments(
        &self,
        tenant: TenantId,
        node_id: WorkerId,
        status: Option<&str>,
        limit: u32,
    ) -> Result<Vec<WorkerAssignment>, CoreError>;
    /// Lists assignments for a worker, optionally filtered by status.
    async fn list_worker_assignments_for_node(
        &self,
        node_id: WorkerId,
        status: Option<&str>,
        limit: u32,
    ) -> Result<Vec<WorkerAssignment>, CoreError>;
    /// Gets a tenant-owned lease.
    async fn get_worker_lease(&self, tenant: TenantId, lease_id: LeaseId)
        -> Result<WorkerLease, CoreError>;
    /// Gets the active lease for a sandbox.
    async fn get_active_worker_lease(
        &self,
        tenant: TenantId,
        sandbox: SandboxId,
    ) -> Result<WorkerLease, CoreError>;
    /// Renews a lease only when its fencing generation remains current.
    async fn renew_worker_lease(
        &self,
        tenant: TenantId,
        lease_id: LeaseId,
        generation: i64,
        ttl_seconds: u64,
    ) -> Result<WorkerLease, CoreError>;
    /// Completes a lease only when its fencing generation remains current.
    async fn complete_worker_lease(
        &self,
        tenant: TenantId,
        lease_id: LeaseId,
        generation: i64,
        result: Value,
    ) -> Result<WorkerLease, CoreError>;
    /// Releases a fenced lease.
    async fn release_worker_lease(
        &self,
        tenant: TenantId,
        lease_id: LeaseId,
        generation: i64,
        reason: &str,
    ) -> Result<WorkerLease, CoreError>;
    /// Detects and durably records expired leases.
    async fn reconcile_expired_leases(
        &self,
        limit: u32,
    ) -> Result<Vec<ReconciliationAction>, CoreError>;
    /// Lists pending repair actions for a tenant.
    async fn list_reconciliation_actions(
        &self,
        tenant: TenantId,
        limit: u32,
    ) -> Result<Vec<ReconciliationAction>, CoreError>;
    /// Begins an idempotent sandbox operation.
    async fn begin_sandbox_operation(
        &self,
        value: SandboxOperation,
    ) -> Result<SandboxOperation, CoreError>;
    /// Completes an idempotent sandbox operation.
    async fn complete_sandbox_operation(
        &self,
        tenant: TenantId,
        request_id: RequestId,
        result: Value,
    ) -> Result<SandboxOperation, CoreError>;
    /// Fails an idempotent sandbox operation.
    async fn fail_sandbox_operation(
        &self,
        tenant: TenantId,
        request_id: RequestId,
        error: Value,
    ) -> Result<SandboxOperation, CoreError>;
    /// Gets an idempotent sandbox operation.
    async fn get_sandbox_operation(
        &self,
        tenant: TenantId,
        request_id: RequestId,
    ) -> Result<SandboxOperation, CoreError>;
    /// Stores image metadata.
    async fn put_image(&self, value: ImageRecord) -> Result<(), CoreError>;
    /// Gets image metadata by identifier.
    async fn get_image(&self, id: &str) -> Result<ImageRecord, CoreError>;
}
