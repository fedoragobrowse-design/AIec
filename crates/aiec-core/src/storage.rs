//! Metadata persistence and large artifact storage boundaries.

use crate::{
    ApiKeyRecord, ApprovalState, CoreError, GuardToolApproval, ImageRecord, Node, QuotaLimits,
    QuotaUsage, RuntimeKind, Sandbox, SandboxState, Snapshot, UsageEvent, UsageSummary,
    run::{Placement, Run, RunArtifactRef, RunAttempt, RunEvent, RunResults, RunSandbox, RunState},
    run_queue::{RunQueueClaim, RunQueueLimits},
    runtime::RuntimeCapabilities,
};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::GuardProposal;
pub use crate::{LeaseId, RequestId, SandboxId, SnapshotId, TenantId, WorkerId};
pub use aiec_guard::control::{
    BudgetDebit, GuardBudgetState, GuardFence, GuardIdentity, GuardIncident,
};

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

/// A durable, fenced claim to delete an unreferenced object.
#[derive(Clone, Debug)]
pub struct ArtifactDeletion {
    pub key: String,
    pub tenant_id: TenantId,
    pub claim: Uuid,
}

/// A bounded, pull-based artifact body. Producers yield at most 64 KiB per chunk.
#[async_trait]
pub trait ArtifactSource: Send {
    /// Returns the next chunk, or `None` after the body is exhausted.
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, CoreError>;
}

/// An artifact whose entire body has been verified before it becomes readable.
pub struct ArtifactDownload {
    /// Metadata computed from the verified bytes and accepted backend version.
    pub metadata: ObjectMetadata,
    /// Bounded spool reader; dropping it releases all staging storage.
    pub body: Box<dyn ArtifactSource>,
}

/// Stores large opaque artifacts independently from relational metadata.
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    /// Takes ownership of the body, allowing HTTP backends to send it without copying.
    async fn put(&self, key: &str, bytes: Bytes) -> Result<ObjectMetadata, CoreError>;
    /// Writes bounded chunks, refusing a body larger than `max_bytes`.
    async fn put_stream(
        &self,
        key: &str,
        source: &mut dyn ArtifactSource,
        max_bytes: u64,
    ) -> Result<ObjectMetadata, CoreError>;
    /// Spools and verifies the complete body before returning a bounded reader.
    async fn get_verified(
        &self,
        key: &str,
        options: &GetObjectOptions,
        max_bytes: u64,
    ) -> Result<ArtifactDownload, CoreError>;
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
    /// Lists metadata for objects beneath a key prefix.
    ///
    /// Implementations must return deterministic, key-sorted metadata and must not
    /// expose objects outside the prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMetadata>, CoreError>;
    /// Deletes an artifact only when its version tag matches.
    async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), CoreError>;
    /// Reclaims abandoned, backend-owned upload files, inspecting at most `limit` entries.
    /// Backends without local staging files have nothing to reclaim.
    async fn cleanup_temporary_uploads(
        &self,
        _older_than: DateTime<Utc>,
        _limit: u32,
    ) -> Result<u32, CoreError> {
        Ok(0)
    }
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

/// One immutable record in the security audit trail.
///
/// `sandbox_events` answers "what happened to this sandbox"; an [`AuditEvent`]
/// answers "who asked, for what, and was it allowed", which is a different
/// question with different retention rules. Rows are append-only in storage:
/// nothing in the system may rewrite or delete one.
///
/// # `detail` carries no secrets
///
/// `detail` is free-form context for a human reading the trail. It must never
/// contain API keys, key digests, bearer tokens, sandbox payloads, environment
/// values or any other credential: the audit trail is readable by operators and
/// is retained far longer than the data it describes. Storage cannot check this,
/// so the producer owns the contract — redact before you append.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Event identifier.
    pub id: Uuid,
    /// Time the audited action was decided, not the time it was recorded.
    pub occurred_at: DateTime<Utc>,
    /// Tenant the action belongs to, or `None` for system-level events.
    pub tenant_id: Option<TenantId>,
    /// Who acted: `user:<id>`, `worker:<node id>`, or `system`.
    pub actor: String,
    /// What was attempted, e.g. `sandbox.create` or `worker.drain`.
    pub action: String,
    /// Kind of thing acted on, e.g. `sandbox`, `api_key`, `worker`.
    pub subject_type: String,
    /// Identifier of the thing acted on, rendered as text.
    pub subject_id: Option<String>,
    /// Outcome: `success`, `denied` or `failure`.
    pub result: String,
    /// Correlates the trail with the request that caused it.
    pub request_id: Option<Uuid>,
    /// Remote address the request arrived from, if any.
    pub remote_addr: Option<String>,
    /// Redacted structured context. Never credentials.
    pub detail: Value,
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
    /// Capabilities advertised by the selected runtime.
    pub capabilities: RuntimeCapabilities,
    /// Dispatch endpoint.
    pub control_endpoint: String,
    /// Total vCPU capacity.
    pub total_vcpus: u32,
    /// Total memory capacity in bytes.
    pub total_memory_bytes: u64,
    /// Total disk capacity in bytes.
    pub total_disk_bytes: u64,
    /// vCPUs the worker declares it can allocate.
    ///
    /// Seeded into `nodes.available_*` on a *first* registration, and only then.
    /// The re-registration path deliberately omits them: a worker that restarts
    /// has no business restoring capacity the scheduler has already handed out,
    /// and a node that did would resurrect the debits of sandboxes it is not
    /// currently running.
    ///
    /// This is the only place a worker writes capacity, and it is a declaration
    /// rather than a report. A heartbeat carries none, because a periodic
    /// second writer would race `debit_capacity` and `release_capacity` and
    /// leave the ledger disagreeing with itself.
    pub available_vcpus: u32,
    /// See [`WorkerRegistration::available_vcpus`].
    pub available_memory_bytes: u64,
    /// See [`WorkerRegistration::available_vcpus`].
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
    /// Whether the worker is eligible for new sandbox placements.
    ///
    /// A worker is drained when it is otherwise perfectly healthy: it has been
    /// asked to stop taking new work, not reported a fault. A drained worker
    /// keeps running the sandboxes it already holds and keeps heartbeating, and
    /// only placement is withheld from it.
    pub accepting_sandboxes: bool,
    /// Why the worker was drained, if it is.
    pub drain_reason: Option<String>,
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

/// Result of recovering a sandbox whose owning worker died.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Reassignment {
    /// Replacement lease with a generation one higher than the expired lease.
    pub lease: WorkerLease,
    /// Sandbox as persisted after reassignment.
    pub sandbox: Sandbox,
}

/// Current active lease ownership for a sandbox, regardless of expiry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxOwnership {
    /// Worker holding the active lease.
    pub node_id: WorkerId,
    /// Active lease identifier.
    pub lease_id: LeaseId,
    /// Fencing generation of the active lease.
    pub generation: i64,
    /// Expiration timestamp of the active lease.
    pub expires_at: DateTime<Utc>,
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

/// Where the next page of a matrix starts.
///
/// The two fields together are the cell's own position in the ordering, so a
/// page boundary is a value that already exists rather than an offset a reader
/// has to keep consistent with rows that moved.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatrixCursor {
    /// `requested_at` of the last cell of the previous page.
    pub requested_at: DateTime<Utc>,
    /// Identifier of that cell, which breaks a `requested_at` tie.
    pub id: Uuid,
}

/// One cell of a matrix: the run it became, and how it was labelled.
///
/// The label is read from the run rather than from a record beside it, because
/// the run is where it was written: a cell whose submission failed, or an API
/// that restarted before the last cell finished, still comes back labelled.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixCell {
    /// The run this cell ran as.
    pub run: Run,
    /// Position in the submitted matrix, when the run was admitted as a cell.
    pub index: Option<u32>,
    /// The cell's axis values, or `None` when the run carries none.
    ///
    /// Absent is a real answer: the run is here and its labels are not, which
    /// is a different thing from a cell that had no axis to begin with.
    pub axis: Option<BTreeMap<String, String>>,
}

/// One bounded page of a matrix.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixCellPage {
    /// Cells in submission order, at most the requested limit.
    pub cells: Vec<MatrixCell>,
    /// Where the next page starts, or `None` when this page is the last.
    pub next: Option<MatrixCursor>,
}

/// Ceiling on one page of any tenant-scoped history listing.
///
/// Declared once, here, because the route clamps to it and the store clamps to
/// it: two copies of this number would drift, and the drift would show up as a
/// caller inside the process asking the database for more rows than the route
/// would ever have returned.
pub const MAX_HISTORY_PAGE: u32 = 200;

/// Ceiling on one page of a tenant's sandboxes.
pub const MAX_SANDBOX_PAGE: u32 = MAX_HISTORY_PAGE;

/// Ceiling on one page of a sandbox's Guard history.
pub const MAX_GUARD_PAGE: u32 = MAX_HISTORY_PAGE;

/// Ceiling on one page of a sandbox's snapshots.
pub const MAX_SNAPSHOT_PAGE: u32 = MAX_HISTORY_PAGE;

/// How many expired Guard budgets one tick of the durable budget reaper takes.
///
/// This is a window, not a cap on the backlog: a tick that leaves work behind
/// picks it up on the next one. That is only true while the window is filled
/// with budgets the reaper can act on, which is why the store excludes the ones
/// it cannot — an already-quarantined sandbox is not destroyed until an
/// operator releases it, so those rows accumulate, and they used to sort to
/// the front and consume the window.
pub const REAPER_GUARD_WINDOW: usize = 64;

/// Where the next page of a tenant-scoped history listing starts.
///
/// The two fields together are the row's own position in the ordering, so a
/// page boundary is a value that already exists rather than an offset a reader
/// would have to keep consistent against rows created or destroyed meanwhile.
///
/// One type for every listing that pages, because each of them orders on the
/// same `(created_at DESC, id DESC)` tuple. A separate copy per table would be
/// a shape that could drift rather than a value that is shared.
/// Sandboxes, Guard proposals and Guard tool approvals all order on that same
/// tuple and so share this one shape. `MatrixCursor` is deliberately separate:
/// it keys on `requested_at`, which is a different column and a different
/// order.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PageCursor {
    /// `created_at` of the last row of the previous page.
    pub created_at: DateTime<Utc>,
    /// Identifier of that row, which breaks a `created_at` tie.
    pub id: Uuid,
}

/// One bounded page of a tenant's sandboxes.
///
/// The page carries its successor because a bounded read that does not say
/// whether it truncated is indistinguishable from a complete one. A caller
/// that stops here has stopped where the page ended and can say so.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxPage {
    /// Sandboxes newest first, at most the requested limit.
    pub sandboxes: Vec<Sandbox>,
    /// Where the next page starts, or `None` when this page is the last.
    pub next: Option<PageCursor>,
}

/// One bounded page of a sandbox's Guard proposals, newest first.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardProposalPage {
    /// Proposals newest first, at most the requested limit.
    pub proposals: Vec<GuardProposal>,
    /// Where the next page starts, or `None` when this page is the last.
    pub next: Option<PageCursor>,
}

/// One bounded page of a sandbox's Guard tool approvals, newest first.
///
/// Decided rows are deliberately retained as history, so this table only ever
/// grows for the life of the sandbox. That is why it is paged rather than read
/// whole.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardToolApprovalPage {
    /// Approvals newest first, at most the requested limit.
    pub approvals: Vec<GuardToolApproval>,
    /// Where the next page starts, or `None` when this page is the last.
    pub next: Option<PageCursor>,
}

/// One bounded page of a sandbox's snapshots, newest first.
///
/// A snapshot is retained until somebody deletes it and nothing prunes them
/// automatically, so a sandbox that is snapshotted repeatedly grows this table
/// for as long as it lives. Paged rather than read whole for the same reason
/// the Guard histories are.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotPage {
    /// Snapshots newest first, at most the requested limit.
    pub snapshots: Vec<Snapshot>,
    /// Where the next page starts, or `None` when this page is the last.
    pub next: Option<PageCursor>,
}

/// What one pass of the orphaned-lease reclaim did.
///
/// Two counts rather than one, because "released a lease" and "found a lease
/// another path had already released" are both success and mean different things
/// to whoever is reading the sweeper. Collapsing them would make a pass that did
/// nothing look identical to one that reclaimed a hundred slots.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrphanedLeaseRelease {
    /// Leases this pass released.
    pub released: u32,
    /// Leases another path had already credited back before we reached them.
    pub already_released: u32,
}

/// One operator's decision about one pending high-risk call.
///
/// Grouped because the fields are not independent inputs: a decision without a
/// decider is anonymous, and one without a timestamp has no audit value. As
/// separate parameters it was possible to assemble a decision and leave the
/// identity unbound, which is the one thing §44 must not allow.
#[derive(Debug, Clone)]
pub struct ApprovalDecisionRequest<'a> {
    pub tenant: TenantId,
    pub sandbox: SandboxId,
    /// The request being decided, as recorded by the asker.
    pub request_id: Uuid,
    /// `Granted` or `Denied`. `Pending` is refused rather than treated as a
    /// decision.
    pub decision: ApprovalState,
    /// From the authenticated principal, never from the request body.
    pub decided_by_key_id: Uuid,
    /// Audit-only label for the deciding key.
    pub decided_by_label: &'a str,
    pub at: DateTime<Utc>,
}

/// Persists AIec domain metadata with tenant-scoped access semantics.
#[async_trait]
pub trait MetadataStore: Send + Sync {
    /// Initializes immutable Guard identity, expiration and caps without resetting usage.
    async fn put_guard_budget(
        &self,
        _state: GuardBudgetState,
    ) -> Result<GuardBudgetState, CoreError> {
        Err(CoreError::Unsupported("put_guard_budget".into()))
    }
    async fn get_guard_budget(
        &self,
        _tenant: TenantId,
        _id: SandboxId,
    ) -> Result<GuardBudgetState, CoreError> {
        Err(CoreError::Unsupported("get_guard_budget".into()))
    }
    /// Commits the debit before traffic forwards, under the current lease fence.
    async fn reserve_guard_budget(
        &self,
        _identity: GuardIdentity,
        _fence: GuardFence,
        _debit: BudgetDebit,
    ) -> Result<GuardBudgetState, CoreError> {
        Err(CoreError::Unsupported("reserve_guard_budget".into()))
    }
    /// Persists monotone quarantine progress; pending incidents survive restart.
    async fn put_guard_incident(
        &self,
        _incident: GuardIncident,
    ) -> Result<GuardIncident, CoreError> {
        Err(CoreError::Unsupported("put_guard_incident".into()))
    }
    async fn get_guard_incident(
        &self,
        _tenant: TenantId,
        _id: SandboxId,
    ) -> Result<GuardIncident, CoreError> {
        Err(CoreError::Unsupported("get_guard_incident".into()))
    }
    /// Budgets that still need quarantine: expired or exhausted, and not
    /// already quarantined.
    ///
    /// The store bounds the result to `limit` rows and orders it, because the
    /// caller is a periodic reaper that works through a fixed window per tick.
    /// Both halves of that contract matter. Rows that are already quarantined
    /// are excluded rather than returned-and-skipped: the caller has no work to
    /// do for them, and returning them lets enough of them fill the window and
    /// starve the budgets that do need enforcement.
    ///
    /// The reaper's window is [`REAPER_GUARD_WINDOW`]. It lives beside the
    /// contract so the caller and the stores cannot drift apart on it.
    async fn list_expired_guard_budgets(
        &self,
        _now: DateTime<Utc>,
        _limit: usize,
    ) -> Result<Vec<GuardBudgetState>, CoreError> {
        Err(CoreError::Unsupported("list_expired_guard_budgets".into()))
    }
    /// Clears a durable quarantine after an authorized release.
    ///
    /// The caller has already reopened the network; this makes the stored state
    /// agree with it. The record of the incident and who released it is kept:
    /// a released machine is still an audited one.
    async fn release_guard_quarantine(
        &self,
        _tenant: TenantId,
        _sandbox: SandboxId,
        _released_by: &str,
    ) -> Result<Sandbox, CoreError> {
        Err(CoreError::Unsupported("release_guard_quarantine".into()))
    }
    /// Atomically latches sandbox and budget quarantine; ordinary transitions cannot release it.
    async fn mark_guard_quarantined(
        &self,
        _tenant: TenantId,
        _id: SandboxId,
        _fence: GuardFence,
    ) -> Result<Sandbox, CoreError> {
        Err(CoreError::Unsupported("mark_guard_quarantined".into()))
    }
    /// Records the Guard configuration a sandbox now runs under.
    ///
    /// An approved proposal changes the enforcement identity without changing
    /// the sandbox's lifecycle, so this writes the configuration and its hash
    /// alone rather than pretending the machine was started again. The policy
    /// itself has to be written with the hash: every later observation is
    /// authorized against the policy the record carries, and a record holding
    /// the superseded policy would refuse every read of a correctly enforced
    /// sandbox.
    async fn update_guard_policy(
        &self,
        _tenant: TenantId,
        _sandbox: SandboxId,
        _guard: &aiec_guard::policy::GuardConfig,
        _policy_hash: &str,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("update_guard_policy".into()))
    }
    /// Records a policy proposal and its state.
    ///
    /// A proposal is a record of what an agent asked for and what a human
    /// decided. It has to outlive the process that received it: a pending
    /// proposal that vanished on restart would silently drop a decision an
    /// operator still has to make.
    async fn put_guard_proposal(
        &self,
        proposal: GuardProposal,
    ) -> Result<GuardProposal, CoreError> {
        let _ = proposal;
        Err(CoreError::Unsupported("put_guard_proposal".into()))
    }
    /// One bounded page of a sandbox's proposals, newest first.
    ///
    /// Paged because no proposal row is ever reclaimed and `guard:propose` is
    /// unbounded, so a sandbox's history grows for as long as the sandbox lives.
    /// Implementations must apply the bound in the query rather than
    /// materializing the history and truncating it.
    async fn list_guard_proposals(
        &self,
        _tenant: TenantId,
        _sandbox: SandboxId,
        _limit: u32,
        _after: Option<PageCursor>,
    ) -> Result<GuardProposalPage, CoreError> {
        Err(CoreError::Unsupported("list_guard_proposals".into()))
    }
    /// One proposal.
    async fn get_guard_proposal(
        &self,
        _tenant: TenantId,
        _sandbox: SandboxId,
        _id: Uuid,
    ) -> Result<GuardProposal, CoreError> {
        Err(CoreError::Unsupported("get_guard_proposal".into()))
    }
    /// Records the asker's request for one high-risk tool call.
    ///
    /// Implementations must store the row `pending` and take `requested_by_key_id`
    /// from the caller — which the route fills from the authenticated principal.
    /// A store that accepted an asker-chosen identity could be used to approve
    /// one's own call by nominating a second key.
    async fn put_guard_tool_approval(
        &self,
        _approval: GuardToolApproval,
    ) -> Result<GuardToolApproval, CoreError> {
        Err(CoreError::Unsupported("put_guard_tool_approval".into()))
    }
    /// Records the asker's request, or returns the one already open for the
    /// same sandbox, requester, tool and argument digest.
    ///
    /// A refused call is retried, and each retry is the same question. Without
    /// this, every retry adds another `pending` row: the operator queue fills
    /// with copies of one decision and the table grows with the retry rate.
    /// Implementations must match on the undecided request only, so asking
    /// again after a `denied` decision is a genuinely new ask.
    async fn get_or_put_guard_tool_approval(
        &self,
        _approval: GuardToolApproval,
    ) -> Result<GuardToolApproval, CoreError> {
        Err(CoreError::Unsupported(
            "get_or_put_guard_tool_approval".into(),
        ))
    }
    /// Applies an operator's decision to one pending request.
    ///
    /// Returns `None` when there was nothing to decide: unknown, already
    /// decided, or asked by the deciding key. Implementations must refuse all
    /// three rather than telling the caller which occurred.
    async fn decide_guard_tool_approval(
        &self,
        _request: ApprovalDecisionRequest<'_>,
    ) -> Result<Option<GuardToolApproval>, CoreError> {
        Err(CoreError::Unsupported("decide_guard_tool_approval".into()))
    }
    /// Spends a granted, unspent, unexpired approval for exactly this call by
    /// exactly this requester. `None` is a refusal.
    ///
    /// Implementations must make the spend atomic and single-use: two callers
    /// racing for one approval must produce one grant and one refusal, or a
    /// single human decision silently authorises two calls.
    async fn consume_guard_tool_approval(
        &self,
        _tenant: TenantId,
        _sandbox: SandboxId,
        _tool: &str,
        _request_digest: &str,
        _requested_by_key_id: Uuid,
        _now: DateTime<Utc>,
    ) -> Result<Option<GuardToolApproval>, CoreError> {
        Err(CoreError::Unsupported("consume_guard_tool_approval".into()))
    }
    /// One bounded page of the requests recorded against a sandbox, newest first.
    ///
    /// Paged because a decided row is retained as history and the sandbox
    /// itself can ask for one with nothing but `sandboxes:write`, so the rows
    /// grow from inside the sandbox rather than from operator action.
    async fn list_guard_tool_approvals(
        &self,
        _tenant: TenantId,
        _sandbox: SandboxId,
        _limit: u32,
        _after: Option<PageCursor>,
    ) -> Result<GuardToolApprovalPage, CoreError> {
        Err(CoreError::Unsupported("list_guard_tool_approvals".into()))
    }
    /// Creates a sandbox.
    async fn create_sandbox(&self, value: Sandbox) -> Result<(), CoreError>;
    /// Gets a tenant-owned sandbox.
    async fn get_sandbox(&self, tenant: TenantId, id: SandboxId) -> Result<Sandbox, CoreError>;
    /// Reads one bounded page of a tenant's sandboxes, newest first.
    ///
    /// The page is bounded because sandbox rows are never deleted: destroying a
    /// sandbox is a state transition, not a removal, and nothing reclaims them.
    /// A tenant's list is therefore their whole history and only grows.
    /// Implementations must apply the bound in the query rather than
    /// materializing the tenant's history and truncating it.
    async fn list_sandboxes(
        &self,
        tenant: TenantId,
        limit: u32,
        after: Option<PageCursor>,
    ) -> Result<SandboxPage, CoreError>;

    /// Performs a compare-and-set state transition.
    async fn update_state(
        &self,
        tenant: TenantId,
        id: SandboxId,
        expected: SandboxState,
        next: SandboxState,
        runtime_path: Option<String>,
    ) -> Result<Sandbox, CoreError>;
    /// Performs a compare-and-set state transition fenced by the sandbox's lease identity.
    ///
    /// The fence is the lease, not its generation counter. `lease_id` and `generation`
    /// are one ownership read, so the transition is rejected unless the sandbox's
    /// current active, unexpired lease *is* `lease_id`: a worker that lost its lease
    /// can never commit state, whatever generation it presents.
    ///
    /// On that same lease a `generation` at or behind the stored one is accepted. Both
    /// [`renew_worker_lease`](Self::renew_worker_lease) and assignment claims advance
    /// the generation of the lease they are extending, so a caller that read ownership
    /// a moment before such a commit is *behind* a fence it still legitimately holds.
    /// Comparing generations alone turned that renewal race into a refusal on a sandbox
    /// nobody had taken away. A generation *ahead* of the stored one is refused: it
    /// belongs to no issued state of this lease.
    ///
    /// Refusals are distinguishable, so a store refusal is never read as a worker
    /// refusal: a different lease is a reassignment, no unexpired lease is expiry or
    /// an unfinished placement, and a generation ahead of its lease is a caller the
    /// store cannot vouch for.
    async fn update_state_with_lease(
        &self,
        tenant: TenantId,
        id: SandboxId,
        expected: SandboxState,
        next: SandboxState,
        lease_id: LeaseId,
        generation: i64,
    ) -> Result<(), CoreError>;
    /// Deletes a tenant-owned sandbox.
    async fn delete_sandbox(&self, tenant: TenantId, id: SandboxId) -> Result<(), CoreError>;
    /// Creates an API key record and returns conflict if its ID already exists.
    async fn put_key(&self, value: ApiKeyRecord) -> Result<(), CoreError>;
    /// Revokes a tenant-owned API key.
    async fn revoke_key(&self, tenant: TenantId, id: Uuid) -> Result<(), CoreError>;
    /// Reads one tenant-owned API key by id, or `None` when the tenant has no
    /// such key. Exists so a revocation can inspect what it is about to revoke
    /// without listing the tenant's whole key set to do it.
    async fn get_key(&self, tenant: TenantId, id: Uuid) -> Result<Option<ApiKeyRecord>, CoreError>;
    /// Finds an API key by digest.
    async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, CoreError>;
    /// Lists a tenant's API keys as metadata. Secrets are never returned:
    /// only a digest is stored.
    async fn list_keys(&self, tenant: TenantId) -> Result<Vec<ApiKeyRecord>, CoreError>;
    /// Stores snapshot metadata.
    async fn put_snapshot(&self, value: Snapshot) -> Result<(), CoreError>;
    /// Gets tenant-owned snapshot metadata.
    async fn get_snapshot(&self, tenant: TenantId, id: SnapshotId) -> Result<Snapshot, CoreError>;
    /// Lists one bounded, newest-first page of a tenant-owned sandbox's
    /// snapshots. Snapshots are retained until they are deleted and nothing
    /// prunes them, so this is one page rather than the whole history.
    async fn list_snapshots(
        &self,
        tenant: TenantId,
        sandbox: SandboxId,
        limit: u32,
        after: Option<PageCursor>,
    ) -> Result<SnapshotPage, CoreError>;
    /// Deletes tenant-owned snapshot metadata.
    async fn delete_snapshot(&self, tenant: TenantId, id: SnapshotId) -> Result<(), CoreError>;
    /// Appends a usage event.
    async fn append_usage(&self, value: UsageEvent) -> Result<(), CoreError>;
    /// Aggregates usage for a tenant.
    async fn usage(&self, tenant: TenantId) -> Result<Vec<UsageSummary>, CoreError>;
    /// Registers a node resource record, returning the id the control plane
    /// actually holds for it.
    ///
    /// A node name is unique, so a worker that restarts with a fresh id must
    /// take over the existing record rather than be rejected. Returning the
    /// authoritative id lets the caller adopt the identity it was given.
    async fn register_node(&self, value: Node) -> Result<Uuid, CoreError>;
    /// Lists registered legacy nodes.
    async fn list_nodes(&self) -> Result<Vec<Node>, CoreError>;
    /// Proves the metadata store answers, without reading a collection.
    ///
    /// Readiness is served on an unauthenticated, unthrottled route because a
    /// load balancer has no credential to present, so its cost is paid by
    /// whoever happens to send the request. It previously proved the database
    /// was reachable by listing every worker and discarding the result, which
    /// made an anonymous probe a full-table read — the cheaper way to ask the
    /// same question is to ask it directly.
    async fn ping(&self) -> Result<(), CoreError>;
    /// Sums the fleet's free capacity without materialising the fleet.
    ///
    /// `/metrics` is likewise public, and Prometheus is only one of its
    /// callers: anyone can ask. It reports two totals, so shipping every node
    /// row to the process to add them up in Rust made an anonymous scrape
    /// proportional to the size of the fleet.
    async fn node_capacity_totals(&self) -> Result<crate::NodeCapacity, CoreError>;
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
    /// Reads the newest complete capture of one kind for a sandbox, or `None`
    /// when it has none.
    ///
    /// The only caller wants a single row - the archive to recover a workspace
    /// from - and every snapshot the sandbox ever took is retained, so listing
    /// the history to pick the newest one made recovery cost a function of the
    /// sandbox's lifetime. Naming the kind also keeps the filter in the query
    /// rather than in a scan that discards almost everything it read.
    async fn latest_stored_snapshot(
        &self,
        tenant: TenantId,
        sandbox: SandboxId,
        kind: &str,
    ) -> Result<Option<StoredSnapshot>, CoreError>;
    /// Idempotently creates a sandbox for a request.
    async fn create_sandbox_idempotent(
        &self,
        tenant: TenantId,
        request_id: RequestId,
        sandbox: Sandbox,
    ) -> Result<Sandbox, CoreError>;
    /// Registers a worker and its capacity.
    /// Registers a worker, returning the id the control plane holds for it.
    ///
    /// Worker names are unique, so a worker that restarts with a fresh id takes
    /// over the existing record instead of colliding with it.
    async fn register_worker(&self, value: WorkerRegistration) -> Result<Uuid, CoreError>;
    /// Applies a worker heartbeat atomically.
    async fn heartbeat_worker(&self, heartbeat: WorkerHeartbeat)
    -> Result<WorkerStatus, CoreError>;
    /// Gets current worker state.
    async fn get_worker(&self, node_id: WorkerId) -> Result<WorkerStatus, CoreError>;
    /// Lists workers, optionally including unhealthy workers.
    async fn list_workers(&self, include_unhealthy: bool) -> Result<Vec<WorkerStatus>, CoreError>;
    /// Starts or stops a worker draining, and returns its resulting state.
    ///
    /// Draining is an operator action on a healthy worker, not a health signal:
    /// it never changes `registration.healthy`, and a drained worker's existing
    /// leases are neither expired nor made eligible for reassignment. While
    /// draining, the scheduler places no new sandboxes on the worker and
    /// [`claim_worker_assignments`](Self::claim_worker_assignments) hands it
    /// nothing new. Re-registering or heartbeating the worker does not clear the
    /// flag; only calling this with `draining = false` does.
    ///
    /// `reason` is recorded only while draining and must be at most 512 bytes;
    /// clearing the drain always clears the reason. An unknown worker is
    /// [`CoreError::NotFound`].
    async fn set_worker_draining(
        &self,
        node_id: WorkerId,
        draining: bool,
        reason: Option<&str>,
    ) -> Result<WorkerStatus, CoreError>;
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
    async fn get_worker_lease(
        &self,
        tenant: TenantId,
        lease_id: LeaseId,
    ) -> Result<WorkerLease, CoreError>;
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
    /// Expires a dead worker's lease and reassigns the sandbox to a healthy worker.
    ///
    /// Returns `None` when the lease is not an expired active lease, or when no healthy
    /// worker currently has capacity for the sandbox.
    async fn reassign_expired_lease(
        &self,
        lease_id: LeaseId,
    ) -> Result<Option<Reassignment>, CoreError>;
    /// Reads the current active lease ownership of a sandbox, regardless of expiry.
    async fn sandbox_ownership(
        &self,
        sandbox_id: SandboxId,
    ) -> Result<Option<SandboxOwnership>, CoreError>;
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
    /// Appends one record to the security audit trail.
    ///
    /// Storage never rewrites or deletes an appended event, so a mistake is
    /// answered by appending a correcting event rather than editing history.
    /// `event.detail` must already be redacted; see [`AuditEvent`].
    async fn append_audit_event(&self, event: AuditEvent) -> Result<(), CoreError>;
    /// Lists audit events newest first, optionally filtered by tenant and action.
    ///
    /// A `None` tenant matches every event, including system-level events that
    /// have no tenant. `limit` is clamped by the store to a sane range; passing
    /// `0` returns the same page as the minimum rather than nothing.
    async fn list_audit_events(
        &self,
        tenant: Option<TenantId>,
        action: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AuditEvent>, CoreError>;

    // Run storage. A Run is durable work rather than compute, so it has its own
    // records, but it lives in the same store and behind the same tenant
    // scoping: nothing here is readable without the owning tenant.
    //
    // The methods below have no default implementation on purpose -- a store
    // that cannot keep runs must not pretend to -- except that they are declared
    // with bodies so that a store which only persists sandboxes still
    // implements the trait, answering `Unsupported` rather than failing to
    // compile. `PostgresRepository` implements every one of them.

    /// Creates a run, or returns the run this idempotency key already produced.
    ///
    /// Two requests carrying the same `(tenant, idempotency_key)` are one run:
    /// a retried request must not double-execute or double-bill. The stored run
    /// is returned unchanged, so a caller that retries after a timeout learns
    /// what actually happened instead of creating a second run.
    async fn create_run(&self, _run: Run) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Gets a tenant-owned run.
    async fn get_run(&self, _tenant: TenantId, _id: Uuid) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Lists a tenant's runs newest first, optionally filtered by state.
    ///
    /// `after` names the last returned row; the next page is strictly older in
    /// `(requested_at DESC, id DESC)` order. `MatrixCursor` carries this key.
    /// PostgreSQL supports run storage; the memory repository does not.
    async fn list_runs(
        &self,
        _tenant: TenantId,
        _state: Option<RunState>,
        _limit: u32,
        _after: Option<MatrixCursor>,
    ) -> Result<Vec<Run>, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Moves a run from one state to another, only if it is still in `from`.
    ///
    /// The expected state is part of the write, so two callers racing the same
    /// transition cannot both win: the loser is told the state moved rather
    /// than silently overwriting it. A terminal run never moves again.
    async fn update_run_state(
        &self,
        _tenant: TenantId,
        _id: Uuid,
        _from: RunState,
        _to: RunState,
    ) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Records what a run produced and the state that outcome put it in.
    async fn record_run_results(
        &self,
        _tenant: TenantId,
        _id: Uuid,
        _results: RunResults,
        _state: RunState,
    ) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Releases leases whose sandbox has already reached a terminal state.
    ///
    /// The gap between the two sweepers. One reclaims capacity from leases that
    /// have expired; the other releases sandboxes that nothing holds. Neither
    /// sees a lease that is still valid but belongs to a sandbox already
    /// `destroyed` or `failed` - the lease is alive, so the first skips it, and
    /// the sandbox is terminal, so the second never selects it. That is exactly
    /// how a parallel soak left two vCPUs debited and flat: the ledger was
    /// internally consistent and still wrong, because an active lease is only
    /// evidence of a live machine if the machine can still be terminal.
    async fn release_orphaned_leases(
        &self,
        _limit: u32,
    ) -> Result<OrphanedLeaseRelease, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Sandboxes stuck in a non-terminal state that no live lease and no
    /// unfinished run accounts for.
    ///
    /// A sandbox whose lease expired is not this: that is the reconciler's job,
    /// and the sandbox may be recoverable. These are the ones nothing can reach
    /// - the run that owned them finished or vanished, and the lease is gone -
    /// so nothing will ever select them again and they keep counting against
    /// the tenant's active-sandbox quota for as long as the database exists.
    async fn list_stranded_sandboxes(
        &self,
        _older_than: chrono::DateTime<chrono::Utc>,
        _limit: u32,
    ) -> Result<Vec<Sandbox>, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Persists which machine a run kept, and until when.
    ///
    /// Separate from `record_run_results` because it is the only thing that
    /// makes a retained machine findable. It used to be set on the in-memory
    /// run and never written, so the sweeper - which selects on
    /// `retained_until` - never saw the run, the machine was never reclaimed,
    /// and the caller was handed a `null` sandbox id and told nothing.
    ///
    /// Three things have to hold at once, and one write has to decide all of
    /// them, because the alternative is a check followed by a write and a run
    /// whose machine is already being kept arrives in between: the machine
    /// belongs to this run's tenant, this run is one that used it, and a
    /// machine already kept is never displaced. That last one is why a retry of
    /// the same machine succeeds - it is the same retention, restated - while
    /// a second machine is refused: overwriting leaves the first machine with
    /// no `retained_until` anywhere, so the sweeper never reclaims it and it
    /// holds capacity for the life of the database.
    async fn retain_run_sandbox(
        &self,
        _tenant: TenantId,
        _id: Uuid,
        _sandbox_id: Uuid,
        _until: chrono::DateTime<chrono::Utc>,
    ) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Records that the teardown of a retained machine failed.
    ///
    /// Conditional on `sandbox_id` still being the retained machine, for the
    /// same reason `clear_run_retention` is: two sweeper passes can overlap on
    /// the same run, and the loser must not leave a report about a machine the
    /// winner already released. Reading the run, mutating a copy of its results
    /// and writing the whole document back is what makes that impossible to
    /// guarantee - the read-modify-write window drops or resurrects whatever
    /// else changed `results` meanwhile - so the report has to be written by the
    /// database under the same predicate that selects the row.
    async fn record_retention_cleanup_failure(
        &self,
        _tenant: TenantId,
        _id: Uuid,
        _sandbox_id: Uuid,
        _error: String,
    ) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Clears a reclaimed retention marker without clearing a different machine.
    ///
    /// Clears the matching cleanup report in the same statement. A caller that
    /// released the machine has just disproved any report about it, and doing
    /// that in a separate read-modify-write is exactly the race
    /// `record_retention_cleanup_failure` exists to close: a late failing
    /// sweeper's write would otherwise land after the clear and the run would
    /// answer "cleanup failed" forever. A report about a *different* machine is
    /// left alone; it is still true.
    async fn clear_run_retention(
        &self,
        _tenant: TenantId,
        _id: Uuid,
        _sandbox_id: Uuid,
    ) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Deletes a tenant-owned run.
    ///
    /// A run whose history has been recorded is retained: the record of what
    /// happened is not deletable, and deleting the run would take it with it.
    ///
    /// A run that still holds a machine is refused for the same reason the
    /// sweeper needs `retained_until` to be true: the run row and its links are
    /// the only indexes that lead to those machines, so deleting it strands
    /// capacity and containers with nothing left to reclaim them.
    async fn delete_run(&self, _tenant: TenantId, _id: Uuid) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Appends one event to a run's history.
    ///
    /// Events are append-only in storage: there is no update or delete path, so
    /// a mistake is answered by appending a correcting event.
    ///
    /// `run_events` carries no tenant of its own, so the tenant is a parameter
    /// rather than something read back off the event: a write is refused unless
    /// it names this tenant's run, and a machine it names belongs to that same
    /// tenant. Naming another tenant's machine here makes it readable through
    /// this tenant's history and sends cleanup after a machine the run never
    /// held.
    async fn append_run_event(&self, _tenant: TenantId, _event: RunEvent) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Lists a run's history in the order it happened.
    async fn list_run_events(
        &self,
        _tenant: TenantId,
        _run: Uuid,
    ) -> Result<Vec<RunEvent>, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Records that a run used a machine, and what for.
    ///
    /// The machine has to belong to the run's tenant. `run_sandboxes` has no
    /// tenant column and its sandbox reference is a bare id, so without this
    /// the row accepts any pair - and the run's cleanup reads exactly these
    /// ids to tear machines down.
    async fn link_run_sandbox(
        &self,
        _tenant: TenantId,
        _link: RunSandbox,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Lists the machines a run used.
    async fn list_run_sandboxes(
        &self,
        _tenant: TenantId,
        _run: Uuid,
    ) -> Result<Vec<RunSandbox>, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Records one attempt of a run.
    ///
    /// Tenant-scoped for the same reason [`MetadataStore::append_run_event`]
    /// is: `run_attempts` carries none of its own, and the machine an attempt
    /// names has to be the tenant's.
    async fn record_run_attempt(
        &self,
        _tenant: TenantId,
        _attempt: RunAttempt,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Completes an in-progress attempt once, retaining its own outcomes.
    async fn complete_run_attempt(
        &self,
        _tenant: TenantId,
        _attempt: RunAttempt,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Atomically creates and assigns an attempt's unleased compute.
    async fn create_attempt_sandbox(
        &self,
        _run_id: Uuid,
        _attempt_id: Uuid,
        _sandbox: Sandbox,
        _required: crate::runtime::RuntimeCapabilities,
    ) -> Result<Sandbox, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Lists every attempt of a run, including the ones that did not work.
    async fn list_run_attempts(
        &self,
        _tenant: TenantId,
        _run: Uuid,
    ) -> Result<Vec<RunAttempt>, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Replaces the artifacts collected for a run.
    async fn put_run_artifacts(
        &self,
        _tenant: TenantId,
        _run: Uuid,
        _artifacts: Vec<RunArtifactRef>,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    /// Records upload ownership before external I/O. Keys cannot be reused after deletion.
    async fn reserve_artifact_upload(
        &self,
        _tenant: TenantId,
        _run: Option<Uuid>,
        _key: &str,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("artifact lifecycle storage".into()))
    }
    /// Records a successful upload even if collecting the Run metadata later fails.
    async fn complete_artifact_upload(
        &self,
        _tenant: TenantId,
        _run: Option<Uuid>,
        _key: &str,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("artifact lifecycle storage".into()))
    }
    /// Records an explicit user delete after the bytes are removed. Unlike
    /// the GC claim path, which only touches expired rows, a user delete of a
    /// live row would otherwise leave it `available` after the bytes are
    /// gone: the row keeps the name reserved forever (keys cannot be reused
    /// after deletion) while pointing at nothing. Marking it `deleted` after
    /// the bytes go keeps the reservation the row implies. Bytes go first
    /// because the tombstone is not reversible: `deleted` rows are invisible
    /// to the GC claim windows, so a tombstone committed before a transient
    /// byte-delete failure would orphan the bytes permanently.
    async fn delete_artifact_upload(
        &self,
        _tenant: TenantId,
        _run: Option<Uuid>,
        _key: &str,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("artifact lifecycle storage".into()))
    }
    /// Expires at most `limit` terminal Runs and leases at most `limit` safe deletions.
    /// All reference checks and ownership changes happen atomically; no object I/O occurs here.
    async fn claim_artifact_deletions(
        &self,
        _now: DateTime<Utc>,
        _retention_seconds: i64,
        _pending_grace_seconds: i64,
        _limit: u32,
        _lease_seconds: i64,
    ) -> Result<Vec<ArtifactDeletion>, CoreError> {
        Err(CoreError::Unsupported("artifact lifecycle storage".into()))
    }
    /// Acknowledges success or schedules a failed deletion for another attempt.
    /// Stale claim acknowledgements cannot change a newer worker's intent.
    async fn finish_artifact_deletion(
        &self,
        _key: &str,
        _claim: Uuid,
        _deleted: bool,
        _retry_at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("artifact lifecycle storage".into()))
    }
    /// Lists the artifacts collected for a run, by name.
    async fn list_run_artifacts(
        &self,
        _tenant: TenantId,
        _run: Uuid,
    ) -> Result<Vec<RunArtifactRef>, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }
    // Matrix results. A matrix is a set of runs that were submitted together,
    // and each run carries the cell it was admitted as. There is deliberately
    // no write here: a second copy of that membership could disagree with the
    // Run it describes, and the Run is the thing that exists.

    /// One bounded page of a matrix's cells, oldest first.
    ///
    /// Tenant-scoped and paged rather than complete on purpose: a matrix is
    /// only as large as its caller made it, and a reader that cannot ask for
    /// the rest of a large one has no way to see any of it. `after` is the last
    /// cell of the previous page, so the next page starts where that one
    /// stopped without re-reading what came before it.
    async fn list_matrix_cells(
        &self,
        _tenant: TenantId,
        _matrix: Uuid,
        _limit: u32,
        _after: Option<MatrixCursor>,
    ) -> Result<MatrixCellPage, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }

    /// A tenant's durable quota policy beside its current aggregate usage.
    ///
    /// The rows the scheduler itself enforces against, read without locking: a
    /// caller that sizes a batch from this still has the scheduler decide
    /// whether each cell is admitted, so a lock here would only serialise
    /// concurrent readers behind each other. A store that cannot answer says
    /// `Unsupported` rather than zero, because no ledger must not read as no
    /// capacity.
    async fn get_tenant_quota_usage(
        &self,
        _tenant: TenantId,
    ) -> Result<(QuotaLimits, QuotaUsage), CoreError> {
        Err(CoreError::Unsupported("tenant quota storage".into()))
    }

    /// Lists runs whose retained machine has passed its expiry.
    ///
    /// This is the sweeper's read, and it crosses tenants on purpose: expiry is
    /// a property of a machine, not of a tenant, so no tenant is passed.
    /// Records why a run failed and settles it.
    ///
    /// Separate from `record_run_results` because the reason is its own column:
    /// a caller reading a failed run should not have to know that it also landed
    /// in the results document to find it.
    /// Records where a run was placed and why.
    ///
    /// Kept out of `record_run_results` deliberately: placement is decided once,
    /// before any work runs, and a results document written later should not be
    /// able to rewrite where the run went.
    async fn set_run_placement(
        &self,
        _tenant: TenantId,
        _id: Uuid,
        _placement: Placement,
    ) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }

    async fn set_run_failure(
        &self,
        _tenant: TenantId,
        _id: Uuid,
        _failure_reason: Option<String>,
        _state: RunState,
    ) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }

    /// Records what a run produced, why it failed, and its terminal state, in
    /// one statement.
    ///
    /// This exists because doing it as `record_run_results` followed by
    /// `set_run_failure` is two round trips that can disagree. The first carries
    /// the caller's pre-settlement state, so between them the run holds results
    /// for an outcome it has not reached yet; if either write fails, the run is
    /// left non-terminal with a terminal `run.failed` event already appended and
    /// its evidence only ever in the failed write. One `UPDATE` leaves no such
    /// window: results, `failure_reason`, `state` and `completed_at` either all
    /// land or none do.
    ///
    /// A run that already reached a terminal state is not rewritten - the same
    /// protection `set_run_failure` gives - because a cancelled run whose
    /// execution then fails against the machine it no longer owns would
    /// otherwise be reported to the caller as failed.
    async fn record_run_failure(
        &self,
        _tenant: TenantId,
        _id: Uuid,
        _results: crate::run::RunResults,
        _reason: Option<String>,
    ) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }

    async fn retained_runs_due(
        &self,
        _now: DateTime<Utc>,
        _limit: u32,
    ) -> Result<Vec<Run>, CoreError> {
        Err(CoreError::Unsupported("run storage".into()))
    }

    // Durable Run queue. Execution ownership is separate from admission: an
    // accepted Run sits in a bounded queue until a dispatcher claims it, and a
    // dispatcher that dies mid-execution is recovered by lease expiry rather
    // than by the HTTP request that asked for the work.
    //
    // A store without a queue answers `Unsupported` for all of these, which is
    // how the in-memory development store keeps its direct-execution path.

    /// Whether this store can durably queue Runs at all.
    ///
    /// The composition root asks once so an executor is only spawned against a
    /// store that can actually feed it.
    fn supports_run_queue(&self) -> bool {
        false
    }
    /// Admits a queued Run and the request that will execute it, atomically.
    ///
    /// The Run row and its queue row commit together, so a refused admission
    /// never leaves an orphan Run behind, and an idempotency key is resolved
    /// before the capacity check so a retry joins its original run even when
    /// the queue is full.
    async fn enqueue_run(
        &self,
        _run: Run,
        _request: Value,
        _limits: RunQueueLimits,
    ) -> Result<Run, CoreError> {
        Err(CoreError::Unsupported("run queue".into()))
    }
    /// Claims the next queued Run for `owner`, or `None` when nothing is due.
    ///
    /// Fair across tenants: selection prefers the tenant with the fewest
    /// in-flight runs, then whichever tenant has waited longest. One Run
    /// cannot be claimed twice, and a slow executor does not hold the queue.
    async fn claim_run_queue(
        &self,
        _owner: Uuid,
        _limits: RunQueueLimits,
    ) -> Result<Option<RunQueueClaim>, CoreError> {
        Err(CoreError::Unsupported("run queue".into()))
    }
    /// Claims abandoned work whose owner lease expired, for teardown only.
    ///
    /// A recovered grant authorizes destroying whatever the lost owner left
    /// behind. It never authorizes executing the request a second time.
    async fn recover_run_queue(
        &self,
        _owner: Uuid,
        _limits: RunQueueLimits,
    ) -> Result<Option<RunQueueClaim>, CoreError> {
        Err(CoreError::Unsupported("run queue".into()))
    }
    /// Extends `owner`'s lease, never past the run's fixed execution deadline.
    ///
    /// Returns false once the lease has expired: a lapsed owner cannot be
    /// revived, because another dispatcher has already been handed the work.
    async fn heartbeat_run_queue(
        &self,
        _tenant: TenantId,
        _run: Uuid,
        _owner: Uuid,
        _lease_seconds: u32,
    ) -> Result<bool, CoreError> {
        Err(CoreError::Unsupported("run queue".into()))
    }
    /// Relinquishes execution ownership while keeping teardown owed.
    async fn fail_run_queue(
        &self,
        _tenant: TenantId,
        _run: Uuid,
        _owner: Uuid,
        _reason: String,
    ) -> Result<bool, CoreError> {
        Err(CoreError::Unsupported("run queue".into()))
    }
    /// Marks the queue entry done once the run is terminal and clean.
    async fn finish_run_queue(
        &self,
        _tenant: TenantId,
        _run: Uuid,
        _owner: Uuid,
    ) -> Result<bool, CoreError> {
        Err(CoreError::Unsupported("run queue".into()))
    }
    /// Whether this Run's queue entry is finished, or was never queued.
    async fn run_queue_finished(&self, _tenant: TenantId, _run: Uuid) -> Result<bool, CoreError> {
        Err(CoreError::Unsupported("run queue".into()))
    }
}
