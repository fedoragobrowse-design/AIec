use aiec_core::*;
use aiec_core::{
    runtime::{FileChunk, FileChunkRequest, RuntimeCapabilities, RuntimeHealth, SandboxRuntime},
    snapshots::{SnapshotCapabilities, SnapshotMetadata, SnapshotProvider, SnapshotRequest},
};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

pub const WORKER_TOKEN_HEADER: &str = "authorization";
/// Largest worker request or response body.
///
/// A capture returns its workspace archive to the control plane, and a
/// recovery posts one back to the worker that adopts the sandbox, so the wire
/// has to carry a base64-encoded archive. The bound is derived from the archive
/// limit rather than picked by hand, and stays finite so a worker cannot be
/// made to buffer an unbounded body.
const MAX_WORKER_TRANSFER: usize =
    aiec_core::snapshots::MAX_WORKSPACE_ARCHIVE_BYTES.div_ceil(3) * 4 + 64 * 1024;
const MAX_WORKER_RESPONSE_CACHE_ENTRIES: usize = 4_096;
const MAX_WORKER_RESPONSE_CACHE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
struct ResponseEntry {
    response: Arc<Mutex<Option<WorkerResponse>>>,
    encoded_size: usize,
    complete: bool,
}

#[derive(Default)]
struct ResponseCache {
    entries: HashMap<Uuid, ResponseEntry>,
    insertion_order: VecDeque<Uuid>,
    encoded_bytes: usize,
}

impl ResponseCache {
    fn get(&self, request_id: Uuid) -> Option<WorkerResponse> {
        self.entries
            .get(&request_id)
            .and_then(|entry| entry.response.try_lock().ok())
            .and_then(|response| response.clone())
    }

    fn entry(&mut self, request_id: Uuid) -> Arc<Mutex<Option<WorkerResponse>>> {
        if let Some(entry) = self.entries.get(&request_id) {
            return entry.response.clone();
        }
        let response = Arc::new(Mutex::new(None));
        self.entries.insert(
            request_id,
            ResponseEntry {
                response: response.clone(),
                encoded_size: 0,
                complete: false,
            },
        );
        // Enrolled as it is claimed, not only once it has a response. The
        // eviction pass walks this list, so an entry that only appeared here
        // when it was finished could never be a candidate: a request whose
        // client disconnected is dropped before it reaches `complete`, and its
        // entry would sit in the map for the lifetime of the process with
        // nothing the byte or entry bound could reclaim. `complete` repositions
        // the id it is given, so claiming one here does not duplicate it.
        self.insertion_order.push_back(request_id);
        response
    }

    async fn complete(&mut self, request_id: Uuid, response: WorkerResponse) {
        let encoded_size = serde_json::to_vec(&response).map_or(0, |bytes| bytes.len());
        if encoded_size > MAX_WORKER_RESPONSE_CACHE_BYTES {
            if let Some(entry) = self.entries.get_mut(&request_id) {
                *entry.response.lock().await = Some(response);
                entry.complete = true;
            }
            self.remove(request_id);
            return;
        }
        if let Some(entry) = self.entries.get_mut(&request_id) {
            self.encoded_bytes = self.encoded_bytes.saturating_sub(entry.encoded_size);
            entry.encoded_size = encoded_size;
            entry.complete = true;
            *entry.response.lock().await = Some(response);
        } else {
            let response_slot = Arc::new(Mutex::new(Some(response)));
            self.entries.insert(
                request_id,
                ResponseEntry {
                    response: response_slot,
                    encoded_size,
                    complete: true,
                },
            );
        }
        self.insertion_order
            .retain(|entry_id| *entry_id != request_id);
        let mut examined = 0;
        while (self.entries.len() > MAX_WORKER_RESPONSE_CACHE_ENTRIES
            || self.encoded_bytes.saturating_add(encoded_size) > MAX_WORKER_RESPONSE_CACHE_BYTES)
            && examined < self.insertion_order.len()
        {
            let Some(candidate) = self.insertion_order.pop_front() else {
                break;
            };
            let Some(entry) = self.entries.get(&candidate) else {
                continue;
            };
            // Finished slots are reclaimable. Empty slots require both an
            // unlocked mutex and no handler-owned Arc: an active handler may
            // have obtained the slot but not yet locked it.
            let abandoned = !entry.complete
                && Arc::strong_count(&entry.response) == 1
                && entry
                    .response
                    .try_lock()
                    .is_ok_and(|response| response.is_none());
            if entry.complete || abandoned {
                if let Some(evicted) = self.entries.remove(&candidate) {
                    self.encoded_bytes = self.encoded_bytes.saturating_sub(evicted.encoded_size);
                }
            } else {
                self.insertion_order.push_back(candidate);
            }
            examined += 1;
        }
        self.encoded_bytes = self.encoded_bytes.saturating_add(encoded_size);
        if self.insertion_order.back() != Some(&request_id) {
            self.insertion_order.push_back(request_id);
        }
    }

    /// Drops an entry and its place in the eviction order together.
    ///
    /// Both, because the order list is what the eviction pass walks: an id left
    /// behind here is a candidate that can never be reclaimed, so an entry
    /// removed this way would otherwise leak a slot in a list that is supposed
    /// to be bounded by the same number of entries.
    fn remove(&mut self, request_id: Uuid) {
        self.insertion_order
            .retain(|entry_id| *entry_id != request_id);
        if let Some(entry) = self.entries.remove(&request_id) {
            self.encoded_bytes = self.encoded_bytes.saturating_sub(entry.encoded_size);
        }
    }

    /// Cached entries, for the bound a test asserts.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum WorkerOperation {
    Create {
        sandbox: Sandbox,
    },
    Start {
        sandbox: Sandbox,
    },
    Stop {
        sandbox: Sandbox,
    },
    Pause {
        sandbox: Sandbox,
    },
    Resume {
        sandbox: Sandbox,
    },
    Destroy {
        sandbox: Sandbox,
    },
    Exec {
        sandbox: Sandbox,
        request: ExecRequest,
    },
    PutFile {
        sandbox: Sandbox,
        request: PutFileRequest,
    },
    GetFile {
        sandbox: Sandbox,
        path: String,
    },
    ListFiles {
        sandbox: Sandbox,
        path: String,
    },
    DeleteFile {
        sandbox: Sandbox,
        path: String,
    },
    MakeDirectory {
        sandbox: Sandbox,
        path: String,
    },
    Snapshot {
        sandbox: Sandbox,
        request: SnapshotRequest,
    },
    Restore {
        sandbox: Sandbox,
        snapshot: SnapshotMetadata,
    },
    ImportWorkspaceArchive {
        sandbox: Sandbox,
        /// Base64 portable workspace archive, bounded by
        /// `MAX_WORKSPACE_ARCHIVE_BYTES` once decoded.
        archive_base64: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum WorkerValue {
    Unit,
    Exec(ExecResult),
    File(FileContent),
    Files(Vec<FileEntry>),
    Snapshot(aiec_core::snapshots::CapturedSnapshot),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerError {
    pub code: String,
    pub message: String,
}

impl WorkerError {
    fn from_runtime(error: CoreError) -> Self {
        let (code, message) = match error {
            CoreError::InvalidRequest(message) => ("invalid_request", message),
            CoreError::Forbidden(message) => ("forbidden", message),
            CoreError::NotFound(message) => ("not_found", message),
            CoreError::Conflict(message) => ("conflict", message),
            CoreError::LimitExceeded(message) => ("limit_exceeded", message),
            CoreError::QuotaExceeded(message) => ("quota_exceeded", message),
            CoreError::Unavailable(message) => ("runtime_unavailable", message),
            // Distinct from "conflict": the caller did nothing wrong, and the
            // same request may well succeed a moment later.
            CoreError::Transient(message) => ("transient", message),
            CoreError::Unsupported(message) => ("unsupported", message),
            CoreError::Backend(message) => ("internal", message),
            CoreError::Io(error) => ("internal", error.to_string()),
        };
        Self {
            code: code.into(),
            message,
        }
    }
}

impl From<CoreError> for WorkerError {
    fn from(error: CoreError) -> Self {
        Self::from_runtime(error)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub request_id: Uuid,
    pub lease_id: Uuid,
    pub lease_generation: i64,
    pub operation: WorkerOperation,
}

#[derive(Serialize, Deserialize)]
struct WorkerChunkRequest {
    authorization: WorkerRequest,
    request: FileChunkRequest,
    /// How many consecutive chunks to serve under the one authorization.
    #[serde(default = "one_chunk")]
    chunks: usize,
}

fn one_chunk() -> usize {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub request_id: Uuid,
    pub result: Result<WorkerValue, WorkerError>,
}

/// Durable lease ownership of one sandbox as reported by the control plane.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnershipRecord {
    /// Worker holding the active lease.
    pub node_id: Uuid,
    /// Active lease identifier.
    pub lease_id: Uuid,
    /// Fencing generation of the active lease.
    pub generation: i64,
    /// Expiration timestamp of the active lease.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Outcome of asking the control plane who owns a sandbox right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipCheck {
    /// The calling worker holds the active lease at this generation.
    ///
    /// The lease id travels with the generation on purpose. A renewal keeps the
    /// same lease while advancing the generation, so generation alone cannot
    /// tell "the same lease, renewed" from "a different lease, reassigned" -
    /// and refusing the first is what made artifact reads fail on a machine the
    /// run still owned, while refusing the second is the whole point of the
    /// fence.
    Owned { generation: i64, lease_id: Uuid },
    /// The sandbox is durably owned by someone else, or has no active lease.
    Rejected(String),
}

/// Authoritative source of durable sandbox ownership for a worker.
///
/// The in-memory generation map dies with the process, so a restarted worker
/// must be able to re-ask the control plane before it touches a sandbox again.
#[async_trait]
pub trait OwnershipVerifier: Send + Sync {
    /// Resolves the current owner and generation of a sandbox.
    ///
    /// Returning an error means ownership could not be established; callers
    /// must then fail closed and never execute the operation.
    async fn verify(&self, sandbox_id: Uuid) -> Result<OwnershipCheck, CoreError>;
}

#[derive(Clone)]
pub struct HttpOwnershipVerifier {
    client: reqwest::Client,
    control_endpoint: Arc<str>,
    token: Arc<str>,
    node_id: Uuid,
}

impl HttpOwnershipVerifier {
    pub fn new(
        control_endpoint: impl Into<String>,
        token: impl Into<String>,
        node_id: Uuid,
    ) -> Result<Self, WorkerClientError> {
        Ok(Self {
            client: control_plane_http_client(Duration::from_secs(10))?,
            control_endpoint: Arc::from(control_endpoint.into().as_str()),
            token: Arc::from(token.into().as_str()),
            node_id,
        })
    }
}

/// Builds an HTTP client for control-plane calls, trusting the deployment CA
/// when one is configured.
///
/// Every control-plane client goes through this so a private CA configured in
/// `AIEC_TLS_CA_CERT` is honoured everywhere; a client that skipped it
/// would fail the TLS handshake against a private-CA control plane and, on a
/// fail-closed path, block every sandbox operation.
pub(crate) fn control_plane_http_client(
    timeout: Duration,
) -> Result<reqwest::Client, WorkerClientError> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(timeout);
    if let Ok(path) = std::env::var("AIEC_TLS_CA_CERT") {
        let pem = std::fs::read(path).map_err(|error| {
            WorkerClientError::Transport(format!("read AIEC_TLS_CA_CERT: {error}"))
        })?;
        let certificate = reqwest::Certificate::from_pem(&pem).map_err(|error| {
            WorkerClientError::Transport(format!("parse AIEC_TLS_CA_CERT: {error}"))
        })?;
        builder = builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|error| WorkerClientError::Transport(error.to_string()))
}

#[async_trait]
impl OwnershipVerifier for HttpOwnershipVerifier {
    async fn verify(&self, sandbox_id: Uuid) -> Result<OwnershipCheck, CoreError> {
        let url = format!(
            "{}/v1/workers/{}/ownership/{}",
            self.control_endpoint.trim_end_matches('/'),
            self.node_id,
            sandbox_id
        );
        let response = self
            .client
            .get(url)
            .bearer_auth(self.token.as_ref())
            .send()
            .await
            .map_err(|error| {
                CoreError::Unavailable(format!("ownership verification failed: {error}"))
            })?;
        let status = response.status();
        match status {
            StatusCode::OK => {
                let record: OwnershipRecord = response.json().await.map_err(|error| {
                    CoreError::Unavailable(format!("ownership response is invalid: {error}"))
                })?;
                if record.node_id != self.node_id {
                    return Ok(OwnershipCheck::Rejected(format!(
                        "sandbox {sandbox_id} is owned by another worker"
                    )));
                }
                Ok(OwnershipCheck::Owned {
                    generation: record.generation,
                    lease_id: record.lease_id,
                })
            }
            StatusCode::NOT_FOUND => Ok(OwnershipCheck::Rejected(format!(
                "sandbox {sandbox_id} has no active lease"
            ))),
            StatusCode::CONFLICT => Ok(OwnershipCheck::Rejected(format!(
                "sandbox {sandbox_id} is owned by another worker"
            ))),
            other => Err(CoreError::Unavailable(format!(
                "ownership verification returned {other}"
            ))),
        }
    }
}

/// Fencing generation learned from the control plane for one sandbox.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct LearnedGeneration {
    sandbox_id: Uuid,
    node_id: Uuid,
    generation: i64,
    /// Absent on ledgers written before this field existed, which is why it is
    /// optional rather than required: a worker upgrading must still load them.
    #[serde(default)]
    lease_id: Option<Uuid>,
}

/// Durable per-sandbox generation floor, persisted in the worker state dir.
#[derive(Debug, Default)]
struct GenerationLedger {
    path: Option<PathBuf>,
    records: HashMap<Uuid, LearnedGeneration>,
}

impl GenerationLedger {
    const FILE_NAME: &'static str = "lease-generations.json";

    fn in_memory() -> Self {
        Self::default()
    }

    /// Reloads the durable ledger, keeping only records for this node.
    fn load(dir: &Path, node_id: Uuid) -> Self {
        let path = dir.join(Self::FILE_NAME);
        let records = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<LearnedGeneration>>(&bytes).ok())
            .unwrap_or_default()
            .into_iter()
            .filter(|record| record.node_id == node_id)
            .map(|record| (record.sandbox_id, record))
            .collect();
        Self {
            path: Some(path),
            records,
        }
    }

    fn generation(&self, sandbox_id: Uuid) -> Option<i64> {
        self.records
            .get(&sandbox_id)
            .map(|record| record.generation)
    }

    /// The lease the learned floor belongs to, when it is known.
    #[cfg(test)]
    fn lease(&self, sandbox_id: Uuid) -> Option<Uuid> {
        self.records
            .get(&sandbox_id)
            .and_then(|record| record.lease_id)
    }

    /// Raises the durable generation floor for a sandbox and persists it.
    ///
    /// The floor never moves backwards: a control-plane answer below what this
    /// worker already learned is ignored, so no reordered or restarted view can
    /// re-admit a generation that was already superseded.
    fn record(
        &mut self,
        sandbox_id: Uuid,
        node_id: Uuid,
        generation: i64,
        lease_id: Uuid,
    ) -> Result<(), std::io::Error> {
        if let Some(existing) = self.records.get(&sandbox_id) {
            if existing.generation > generation {
                return Ok(());
            }
            // An entry written before this field existed loads with no lease, and
            // a sandbox whose floor is already correct would otherwise keep the
            // old over-strict refusal forever: the renewal that could tell us its
            // lease arrives at exactly the generation already on record, so an
            // unconditional `>=` would skip it and the entry would never be
            // upgraded. Re-learning at the same generation fills the lease in.
            if existing.generation == generation && existing.lease_id.is_some() {
                return Ok(());
            }
        }
        self.records.insert(
            sandbox_id,
            LearnedGeneration {
                sandbox_id,
                node_id,
                generation,
                lease_id: Some(lease_id),
            },
        );
        self.persist()
    }

    fn forget(&mut self, sandbox_id: Uuid) -> Result<(), std::io::Error> {
        if self.records.remove(&sandbox_id).is_some() {
            self.persist()?;
        }
        Ok(())
    }

    /// Rewrites the ledger atomically; a torn write must never be read back.
    fn persist(&self) -> Result<(), std::io::Error> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let mut records: Vec<LearnedGeneration> = self.records.values().copied().collect();
        records.sort_by_key(|record| record.sandbox_id);
        let encoded = serde_json::to_vec(&records)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, encoded)?;
        std::fs::rename(&temporary, path)
    }
}

/// Image capability profile of the guest this worker executes sandboxes on.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerGuestProfile {
    pub artifact_version: String,
    pub base: String,
    pub profile: String,
    pub capabilities: Vec<String>,
    pub git_version: Option<String>,
    pub guest_agent_version: String,
    /// Wire revision the baked guest agent implements.
    pub guest_protocol_version: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub node_id: Uuid,
    pub healthy: bool,
    pub runtime: RuntimeKind,
    pub capabilities: RuntimeCapabilities,
    pub in_flight: usize,
    pub capacity: u32,
    pub sandbox_count: usize,
    #[serde(default)]
    pub guest_profile: Option<WorkerGuestProfile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerRegistration {
    pub node_id: Uuid,
    pub name: String,
    pub runtime: RuntimeKind,
    pub capabilities: RuntimeCapabilities,
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
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
}

/// The heartbeat a worker posts.
///
/// Re-exported rather than redefined. There were two structurally identical
/// types - this one and `aiec_core::storage::WorkerHeartbeat` - and they drifted
/// once, which is how a change could be made "everywhere" and still not compile:
/// the worker imports this copy, the API handler uses the other, and only one of
/// them is what a reader of `WorkerHeartbeat` finds first.
pub use aiec_core::storage::WorkerHeartbeat;

#[derive(Clone)]
pub struct WorkerRuntime {
    client: Arc<dyn WorkerClient>,
    scheduler: Arc<dyn aiec_core::scheduler::Scheduler>,
    capabilities: RuntimeCapabilities,
}

impl WorkerRuntime {
    pub fn new(
        client: Arc<dyn WorkerClient>,
        scheduler: Arc<dyn aiec_core::scheduler::Scheduler>,
        capabilities: RuntimeCapabilities,
    ) -> Self {
        Self {
            client,
            scheduler,
            capabilities,
        }
    }
    pub fn with_capabilities(&self, capabilities: RuntimeCapabilities) -> Self {
        Self {
            client: self.client.clone(),
            scheduler: self.scheduler.clone(),
            capabilities,
        }
    }

    async fn call(
        &self,
        sandbox: &Sandbox,
        operation: WorkerOperation,
    ) -> Result<WorkerValue, CoreError> {
        let dispatch = self
            .scheduler
            .dispatch_target(sandbox.tenant_id, sandbox.id)
            .await?;
        let response = self
            .client
            .invoke(
                &dispatch.endpoint,
                WorkerRequest {
                    request_id: new_id(),
                    lease_id: dispatch.lease_id,
                    lease_generation: dispatch.generation,
                    operation,
                },
            )
            .await
            .map_err(runtime_client_error)?;
        response.result.map_err(runtime_worker_error)
    }
}

#[async_trait]
impl SandboxRuntime for WorkerRuntime {
    async fn create(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::Create {
                sandbox: sandbox.clone(),
            },
        )
        .await
        .map(|_| ())
    }

    async fn start(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::Start {
                sandbox: sandbox.clone(),
            },
        )
        .await
        .map(|_| ())
    }

    async fn stop(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::Stop {
                sandbox: sandbox.clone(),
            },
        )
        .await
        .map(|_| ())
    }
    async fn pause(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::Pause {
                sandbox: sandbox.clone(),
            },
        )
        .await
        .map(|_| ())
    }
    async fn resume(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::Resume {
                sandbox: sandbox.clone(),
            },
        )
        .await
        .map(|_| ())
    }

    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::Destroy {
                sandbox: sandbox.clone(),
            },
        )
        .await
        .map(|_| ())
    }

    async fn exec(&self, sandbox: &Sandbox, request: ExecRequest) -> Result<ExecResult, CoreError> {
        match self
            .call(
                sandbox,
                WorkerOperation::Exec {
                    sandbox: sandbox.clone(),
                    request,
                },
            )
            .await?
        {
            WorkerValue::Exec(result) => Ok(result),
            _ => Err(CoreError::Conflict("invalid worker exec response".into())),
        }
    }

    async fn put_file(&self, sandbox: &Sandbox, request: PutFileRequest) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::PutFile {
                sandbox: sandbox.clone(),
                request,
            },
        )
        .await
        .map(|_| ())
    }

    async fn get_file(&self, sandbox: &Sandbox, path: &str) -> Result<FileContent, CoreError> {
        match self
            .call(
                sandbox,
                WorkerOperation::GetFile {
                    sandbox: sandbox.clone(),
                    path: path.into(),
                },
            )
            .await?
        {
            WorkerValue::File(result) => Ok(result),
            _ => Err(CoreError::Conflict("invalid worker file response".into())),
        }
    }

    async fn get_file_chunk(
        &self,
        sandbox: &Sandbox,
        request: FileChunkRequest,
    ) -> Result<FileChunk, CoreError> {
        request.validate()?;
        let dispatch = self
            .scheduler
            .dispatch_target(sandbox.tenant_id, sandbox.id)
            .await?;
        let authorization = WorkerRequest {
            request_id: new_id(),
            lease_id: dispatch.lease_id,
            lease_generation: dispatch.generation,
            operation: WorkerOperation::GetFile {
                sandbox: sandbox.clone(),
                path: request.path.clone(),
            },
        };
        let chunk = self
            .client
            .get_file_chunk(&dispatch.endpoint, authorization, request.clone())
            .await?;
        request.validate_chunk(&chunk)?;
        Ok(chunk)
    }
    /// One dispatch and one authorized worker read for the whole group. This
    /// is the only runtime that overrides it, because it is the only one whose
    /// single read costs a network round trip plus two ownership checks.
    async fn get_file_chunks(
        &self,
        sandbox: &Sandbox,
        request: FileChunkRequest,
        count: usize,
    ) -> Result<Vec<FileChunk>, CoreError> {
        request.validate()?;
        let count = count.clamp(1, aiec_core::runtime::FILE_CHUNK_BURST);
        let dispatch = self
            .scheduler
            .dispatch_target(sandbox.tenant_id, sandbox.id)
            .await?;
        let authorization = WorkerRequest {
            request_id: new_id(),
            lease_id: dispatch.lease_id,
            lease_generation: dispatch.generation,
            operation: WorkerOperation::GetFile {
                sandbox: sandbox.clone(),
                path: request.path.clone(),
            },
        };
        self.client
            .get_file_chunks(&dispatch.endpoint, authorization, request, count)
            .await
    }

    async fn list_files(&self, sandbox: &Sandbox, path: &str) -> Result<Vec<FileEntry>, CoreError> {
        match self
            .call(
                sandbox,
                WorkerOperation::ListFiles {
                    sandbox: sandbox.clone(),
                    path: path.into(),
                },
            )
            .await?
        {
            WorkerValue::Files(result) => Ok(result),
            _ => Err(CoreError::Conflict(
                "invalid worker listing response".into(),
            )),
        }
    }

    async fn delete_file(
        &self,
        sandbox: &Sandbox,
        request: DeleteFileRequest,
    ) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::DeleteFile {
                sandbox: sandbox.clone(),
                path: request.path,
            },
        )
        .await
        .map(|_| ())
    }

    async fn make_directory(
        &self,
        sandbox: &Sandbox,
        request: MakeDirectoryRequest,
    ) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::MakeDirectory {
                sandbox: sandbox.clone(),
                path: request.path,
            },
        )
        .await
        .map(|_| ())
    }

    async fn import_workspace_archive(
        &self,
        sandbox: &Sandbox,
        archive: &[u8],
    ) -> Result<(), CoreError> {
        if archive.len() > aiec_core::snapshots::MAX_WORKSPACE_ARCHIVE_BYTES {
            return Err(CoreError::LimitExceeded(
                "workspace archive exceeds 64 MiB".into(),
            ));
        }
        // The archive is the only thing this worker needs from the previous
        // owner, so it travels with the request rather than being fetched from
        // shared storage on the worker's behalf.
        use base64::Engine;
        self.call(
            sandbox,
            WorkerOperation::ImportWorkspaceArchive {
                sandbox: sandbox.clone(),
                archive_base64: base64::engine::general_purpose::STANDARD.encode(archive),
            },
        )
        .await
        .map(|_| ())
    }

    async fn health(&self) -> RuntimeHealth {
        RuntimeHealth::healthy()
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        self.capabilities.clone()
    }
}

#[async_trait]
impl SnapshotProvider for WorkerRuntime {
    fn capabilities(&self) -> SnapshotCapabilities {
        SnapshotCapabilities {
            virtual_machine: true,
            memory: true,
            workspace: true,
            cross_instance_restore: true,
        }
    }

    async fn capture(
        &self,
        sandbox: &Sandbox,
        request: &SnapshotRequest,
    ) -> Result<aiec_core::snapshots::CapturedSnapshot, CoreError> {
        match self
            .call(
                sandbox,
                WorkerOperation::Snapshot {
                    sandbox: sandbox.clone(),
                    request: request.clone(),
                },
            )
            .await?
        {
            WorkerValue::Snapshot(captured) => Ok(captured),
            _ => Err(CoreError::Conflict(
                "invalid worker snapshot response".into(),
            )),
        }
    }

    async fn restore(
        &self,
        sandbox: &Sandbox,
        snapshot: &SnapshotMetadata,
    ) -> Result<(), CoreError> {
        self.call(
            sandbox,
            WorkerOperation::Restore {
                sandbox: sandbox.clone(),
                snapshot: snapshot.clone(),
            },
        )
        .await
        .map(|_| ())
    }
}

fn runtime_worker_error(error: WorkerError) -> CoreError {
    match error.code.as_str() {
        "invalid_request" => CoreError::InvalidRequest(error.message),
        "forbidden" => CoreError::Forbidden(error.message),
        "not_found" => CoreError::NotFound(error.message),
        "limit_exceeded" => CoreError::LimitExceeded(error.message),
        "quota_exceeded" => CoreError::QuotaExceeded(error.message),
        "runtime_unavailable" => CoreError::Unavailable(error.message),
        "unsupported" => CoreError::Unsupported(error.message),
        "snapshot_failed" | "conflict" => CoreError::Conflict(error.message),
        "guest_protocol" | "firecracker_api" | "internal" => CoreError::Backend(error.message),
        _ => CoreError::Backend(error.message),
    }
}

fn runtime_client_error(error: WorkerClientError) -> CoreError {
    match error {
        WorkerClientError::Unavailable(message) => CoreError::Unavailable(message),
        WorkerClientError::Transport(message) => {
            CoreError::Backend(format!("worker transport: {message}"))
        }
        WorkerClientError::Response(message) => {
            CoreError::Backend(format!("worker protocol: {message}"))
        }
    }
}

#[derive(Debug, Error)]
pub enum WorkerClientError {
    #[error("worker transport: {0}")]
    Transport(String),
    #[error("worker response: {0}")]
    Response(String),
    #[error("worker unavailable: {0}")]
    Unavailable(String),
}

fn operation_belongs_to_worker(operation: &WorkerOperation, node_id: Uuid) -> bool {
    let sandbox = match operation {
        WorkerOperation::Create { sandbox }
        | WorkerOperation::Start { sandbox }
        | WorkerOperation::Stop { sandbox }
        | WorkerOperation::Pause { sandbox }
        | WorkerOperation::Resume { sandbox }
        | WorkerOperation::Destroy { sandbox }
        | WorkerOperation::Exec { sandbox, .. }
        | WorkerOperation::PutFile { sandbox, .. }
        | WorkerOperation::GetFile { sandbox, .. }
        | WorkerOperation::ListFiles { sandbox, .. }
        | WorkerOperation::DeleteFile { sandbox, .. }
        | WorkerOperation::MakeDirectory { sandbox, .. }
        | WorkerOperation::Snapshot { sandbox, .. }
        | WorkerOperation::Restore { sandbox, .. }
        | WorkerOperation::ImportWorkspaceArchive { sandbox, .. } => sandbox,
    };
    // An unowned sandbox is never acceptable: without a durable owner there is
    // nothing to fence against, so any worker could act on it.
    sandbox.node_id == Some(node_id)
}
fn operation_sandbox_id(operation: &WorkerOperation) -> Uuid {
    match operation {
        WorkerOperation::Create { sandbox }
        | WorkerOperation::Start { sandbox }
        | WorkerOperation::Stop { sandbox }
        | WorkerOperation::Pause { sandbox }
        | WorkerOperation::Resume { sandbox }
        | WorkerOperation::Destroy { sandbox }
        | WorkerOperation::Exec { sandbox, .. }
        | WorkerOperation::PutFile { sandbox, .. }
        | WorkerOperation::GetFile { sandbox, .. }
        | WorkerOperation::ListFiles { sandbox, .. }
        | WorkerOperation::DeleteFile { sandbox, .. }
        | WorkerOperation::MakeDirectory { sandbox, .. }
        | WorkerOperation::Snapshot { sandbox, .. }
        | WorkerOperation::Restore { sandbox, .. }
        | WorkerOperation::ImportWorkspaceArchive { sandbox, .. } => sandbox.id,
    }
}

#[async_trait]
pub trait WorkerClient: Send + Sync {
    async fn invoke(
        &self,
        endpoint: &str,
        request: WorkerRequest,
    ) -> Result<WorkerResponse, WorkerClientError>;
    async fn get_file_chunk(
        &self,
        endpoint: &str,
        authorization: WorkerRequest,
        request: FileChunkRequest,
    ) -> Result<FileChunk, CoreError>;
    /// Reads a bounded group under one authorization. The default repeats
    /// single reads, so a client without the group endpoint still works.
    async fn get_file_chunks(
        &self,
        endpoint: &str,
        authorization: WorkerRequest,
        request: FileChunkRequest,
        count: usize,
    ) -> Result<Vec<FileChunk>, CoreError> {
        let mut chunks = Vec::new();
        for index in 0..count {
            let step = aiec_core::runtime::burst_request(&request, index);
            chunks.push(
                self.get_file_chunk(endpoint, authorization.clone(), step)
                    .await?,
            );
        }
        Ok(chunks)
    }
}

#[derive(Clone)]
pub struct HttpWorkerClient {
    client: reqwest::Client,
    token: Arc<str>,
    require_https: bool,
}

impl HttpWorkerClient {
    pub fn new_secure(token: impl Into<String>) -> Result<Self, WorkerClientError> {
        Ok(Self {
            client: control_plane_http_client(Duration::from_secs(120))?,
            token: Arc::from(token.into().as_str()),
            require_https: true,
        })
    }
    pub fn new(token: impl Into<String>) -> Result<Self, WorkerClientError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|error| WorkerClientError::Transport(error.to_string()))?;
        Ok(Self {
            client,
            token: Arc::from(token.into().as_str()),
            require_https: false,
        })
    }

    pub fn from_env() -> Result<Self, WorkerClientError> {
        let token = std::env::var("AIEC_WORKER_TOKEN")
            .map_err(|_| WorkerClientError::Unavailable("AIEC_WORKER_TOKEN is required".into()))?;
        Self::new_secure(token)
    }
}

#[async_trait]
impl WorkerClient for HttpWorkerClient {
    async fn get_file_chunk(
        &self,
        endpoint: &str,
        authorization: WorkerRequest,
        request: FileChunkRequest,
    ) -> Result<FileChunk, CoreError> {
        self.get_file_chunks(endpoint, authorization, request, 1)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| CoreError::Backend("worker returned no chunk".into()))
    }
    async fn get_file_chunks(
        &self,
        endpoint: &str,
        authorization: WorkerRequest,
        request: FileChunkRequest,
        count: usize,
    ) -> Result<Vec<FileChunk>, CoreError> {
        request.validate()?;
        let count = count.clamp(1, aiec_core::runtime::FILE_CHUNK_BURST);
        if self.require_https
            && reqwest::Url::parse(endpoint)
                .map_err(|error| CoreError::InvalidRequest(error.to_string()))?
                .scheme()
                != "https"
        {
            return Err(CoreError::Unavailable(
                "production worker endpoint must use HTTPS".into(),
            ));
        }
        let request_id = authorization.request_id;
        let mut response = self
            .client
            .post(format!("{}/v1/files/chunk", endpoint.trim_end_matches('/')))
            .bearer_auth(self.token.as_ref())
            .json(&WorkerChunkRequest {
                authorization,
                request: request.clone(),
                chunks: count,
            })
            .send()
            .await
            .map_err(|error| CoreError::Unavailable(error.to_string()))?;
        let binary = response.status().is_success()
            && response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                == Some("application/octet-stream");
        if !binary {
            let body = bounded_worker_body(&mut response, 16 * 1024).await?;
            let response: WorkerResponse = serde_json::from_slice(&body).map_err(|error| {
                CoreError::Backend(format!("invalid worker chunk error: {error}"))
            })?;
            if response.request_id != request_id {
                return Err(CoreError::Backend("worker request id mismatch".into()));
            }
            return Err(response
                .result
                .err()
                .map(runtime_worker_error)
                .unwrap_or_else(|| CoreError::Backend("invalid worker chunk response".into())));
        }
        let header = |name: &str| -> Result<&str, CoreError> {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| CoreError::Backend(format!("missing worker chunk header {name}")))
        };
        if header("x-aiec-request-id")? != request_id.to_string() {
            return Err(CoreError::Backend("worker request id mismatch".into()));
        }
        let size_bytes = header("x-aiec-file-size")?
            .parse::<u64>()
            .map_err(|_| CoreError::Backend("invalid worker file size".into()))?;
        let version = header("x-aiec-file-version")?.to_owned();
        let eof = header("x-aiec-file-eof")?
            .parse::<bool>()
            .map_err(|_| CoreError::Backend("invalid worker eof".into()))?;
        let frames = header("x-aiec-chunk-count")?
            .parse::<usize>()
            .map_err(|_| CoreError::Backend("invalid worker chunk count".into()))?;
        if frames == 0 || frames > count {
            return Err(CoreError::Backend("invalid worker chunk count".into()));
        }
        // The bound has to cover the frame headers as well as the payload, or a
        // full group of maximum-size chunks is refused for being 128 bytes
        // larger than the bytes it carries.
        let limit = count.saturating_mul(request.length.saturating_add(4));
        let body = bounded_worker_body(&mut response, limit).await?;
        let mut chunks = Vec::with_capacity(frames);
        let mut rest = body.as_ref();
        for index in 0..frames {
            if rest.len() < 4 {
                return Err(CoreError::Backend("truncated worker chunk frame".into()));
            }
            let length = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            rest = &rest[4..];
            if length > request.length || length > rest.len() {
                return Err(CoreError::Backend("invalid worker chunk frame".into()));
            }
            let step = aiec_core::runtime::burst_request(&request, index);
            let chunk = FileChunk {
                bytes: bytes::Bytes::copy_from_slice(&rest[..length]),
                size_bytes,
                version: version.clone(),
                // Only the last frame of a group can end the file, and only if
                // its own offset plus length reaches the recorded size.
                eof: eof && index + 1 == frames,
            };
            step.validate_chunk(&chunk)?;
            rest = &rest[length..];
            chunks.push(chunk);
        }
        if !rest.is_empty() {
            return Err(CoreError::Backend("trailing worker chunk bytes".into()));
        }
        Ok(chunks)
    }
    async fn invoke(
        &self,
        endpoint: &str,
        request: WorkerRequest,
    ) -> Result<WorkerResponse, WorkerClientError> {
        if self.require_https {
            let endpoint_url = reqwest::Url::parse(endpoint).map_err(|error| {
                WorkerClientError::Transport(format!("invalid worker endpoint: {error}"))
            })?;
            if endpoint_url.scheme() != "https" {
                return Err(WorkerClientError::Unavailable(
                    "production worker endpoint must use HTTPS".into(),
                ));
            }
        }
        let expected_id = request.request_id;
        let response = self
            .client
            .post(format!("{}/v1/operations", endpoint.trim_end_matches('/')))
            .bearer_auth(self.token.as_ref())
            .json(&request)
            .send()
            .await
            .map_err(|error| WorkerClientError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(WorkerClientError::Unavailable(format!(
                "worker returned {status}: {body}"
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_WORKER_TRANSFER as u64)
        {
            return Err(WorkerClientError::Response(format!(
                "worker response exceeds {} bytes",
                MAX_WORKER_TRANSFER
            )));
        }
        let response: WorkerResponse = response
            .json()
            .await
            .map_err(|error| WorkerClientError::Response(error.to_string()))?;
        if response.request_id != expected_id {
            return Err(WorkerClientError::Response(
                "worker request id mismatch".into(),
            ));
        }
        Ok(response)
    }
}

async fn bounded_worker_body(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<bytes::Bytes, CoreError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(CoreError::LimitExceeded("worker chunk response".into()));
    }
    let mut body = bytes::BytesMut::with_capacity(limit);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| CoreError::Backend(error.to_string()))?
    {
        if chunk.len() > limit - body.len() {
            return Err(CoreError::LimitExceeded("worker chunk response".into()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

#[derive(Clone)]
pub struct WorkerService {
    runtime: Arc<dyn SandboxRuntime>,
    snapshots: Option<Arc<dyn SnapshotProvider>>,
    generations: Arc<Mutex<GenerationLedger>>,
    verifier: Option<Arc<dyn OwnershipVerifier>>,
    guest_profile: Option<WorkerGuestProfile>,
    runtime_kind: RuntimeKind,
    capabilities: RuntimeCapabilities,
    node_id: Uuid,
    capacity: u32,
    token: Arc<str>,
    cache: Arc<Mutex<ResponseCache>>,
    in_flight: Arc<AtomicUsize>,
    sandboxes: Arc<Mutex<std::collections::HashSet<Uuid>>>,
    /// One gate per sandbox for the operations that change whether it exists.
    ///
    /// Separate from the runtime's own gate on purpose: this one is also where
    /// a request is re-authorized after it waits, which is a worker concern, and
    /// it holds for every backend the worker can be given, not only the ones
    /// that serialize themselves.
    lifecycle: Arc<aiec_runtime::SandboxLifecycle>,
    boot_slots: Arc<Semaphore>,
    snapshot_slots: Arc<Semaphore>,
}

impl WorkerService {
    pub fn new(
        runtime: Arc<dyn SandboxRuntime>,
        runtime_kind: RuntimeKind,
        capabilities: RuntimeCapabilities,
        snapshots: Option<Arc<dyn SnapshotProvider>>,
        token: impl Into<String>,
        node_id: Uuid,
        capacity: u32,
    ) -> Self {
        Self {
            runtime,
            snapshots,
            capabilities,
            generations: Arc::new(Mutex::new(GenerationLedger::in_memory())),
            verifier: None,
            guest_profile: None,
            runtime_kind,
            node_id,
            capacity,
            token: Arc::from(token.into().as_str()),
            cache: Arc::new(Mutex::new(ResponseCache::default())),
            in_flight: Arc::new(AtomicUsize::new(0)),
            sandboxes: Arc::new(Mutex::new(std::collections::HashSet::new())),
            lifecycle: Arc::new(aiec_runtime::SandboxLifecycle::new()),
            boot_slots: Arc::new(Semaphore::new((capacity as usize).clamp(1, 2))),
            snapshot_slots: Arc::new(Semaphore::new((capacity as usize).clamp(1, 2))),
        }
    }

    /// Persists learned lease generations under the worker state directory and
    /// reloads the previous ones, so a restart cannot forget a newer
    /// generation that a superseded request would otherwise slip past.
    pub fn with_state_dir(mut self, dir: &Path) -> Self {
        self.generations = Arc::new(Mutex::new(GenerationLedger::load(dir, self.node_id)));
        self
    }

    /// Sets the authoritative ownership source consulted before every
    /// operation reaches the runtime.
    pub fn with_ownership_verifier(mut self, verifier: Arc<dyn OwnershipVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    pub fn with_guest_profile(mut self, profile: WorkerGuestProfile) -> Self {
        self.guest_profile = Some(profile);
        self
    }

    #[cfg(test)]
    fn with_generation(self, sandbox_id: Uuid, generation: i64) -> Self {
        let mut ledger = GenerationLedger::in_memory();
        // A different lease from the one `stable_lease_id()` reports: a floor
        // that outlives a restart exists to stop this worker acting on a lease
        // that has since been replaced, and "replaced" means a different id.
        let _ = ledger.record(
            sandbox_id,
            self.node_id,
            generation,
            Uuid::from_u128(0xdead_beef_dead_beef_dead_beef_dead_beef),
        );
        Self {
            generations: Arc::new(Mutex::new(ledger)),
            ..self
        }
    }

    pub fn node_id(&self) -> Uuid {
        self.node_id
    }
    pub fn runtime(&self) -> Arc<dyn SandboxRuntime> {
        self.runtime.clone()
    }

    pub fn router(self) -> Router {
        let state = self.clone();
        Router::new()
            .route("/health", get(status))
            .route("/v1/operations", post(operation))
            .route(
                "/v1/files/chunk",
                post(file_chunk).layer(axum::extract::DefaultBodyLimit::max(32 * 1024)),
            )
            .layer(axum::extract::DefaultBodyLimit::max(MAX_WORKER_TRANSFER))
            .layer(axum::middleware::from_fn_with_state(state, authenticate))
            .with_state(self)
    }

    /// Establishes durable ownership for a sandbox, failing closed when the
    /// control plane cannot answer.
    async fn verify_ownership(&self, sandbox_id: Uuid) -> Result<OwnershipCheck, CoreError> {
        match self.verifier.as_ref() {
            Some(verifier) => verifier.verify(sandbox_id).await,
            None => Err(CoreError::Unavailable(
                "worker ownership verification is not configured".into(),
            )),
        }
    }

    /// Persists the generation the control plane just confirmed, keeping the
    /// in-memory map as a cache of the durable ledger.
    async fn learn_generation(&self, sandbox_id: Uuid, generation: i64, lease_id: Uuid) {
        if let Err(error) =
            self.generations
                .lock()
                .await
                .record(sandbox_id, self.node_id, generation, lease_id)
        {
            tracing::warn!(
                %sandbox_id,
                %generation,
                %error,
                "failed to persist learned lease generation"
            );
        }
    }

    async fn forget_generation(&self, sandbox_id: Uuid) {
        if let Err(error) = self.generations.lock().await.forget(sandbox_id) {
            tracing::warn!(
                %sandbox_id,
                %error,
                "failed to persist lease generation removal"
            );
        }
    }

    async fn execute(&self, operation: WorkerOperation) -> Result<WorkerValue, WorkerError> {
        let result = match operation {
            WorkerOperation::Create { sandbox } => self
                .runtime
                .create(&sandbox)
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::Start { sandbox } => self
                .runtime
                .start(&sandbox)
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::Stop { sandbox } => {
                self.runtime.stop(&sandbox).await.map(|_| WorkerValue::Unit)
            }
            WorkerOperation::Pause { sandbox } => self
                .runtime
                .pause(&sandbox)
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::Resume { sandbox } => self
                .runtime
                .resume(&sandbox)
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::Destroy { sandbox } => self
                .runtime
                .destroy(&sandbox)
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::Exec { sandbox, request } => self
                .runtime
                .exec(&sandbox, request)
                .await
                .map(WorkerValue::Exec),
            WorkerOperation::PutFile { sandbox, request } => self
                .runtime
                .put_file(&sandbox, request)
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::GetFile { sandbox, path } => self
                .runtime
                .get_file(&sandbox, &path)
                .await
                .map(WorkerValue::File),
            WorkerOperation::ListFiles { sandbox, path } => self
                .runtime
                .list_files(&sandbox, &path)
                .await
                .map(WorkerValue::Files),
            WorkerOperation::DeleteFile { sandbox, path } => self
                .runtime
                .delete_file(&sandbox, DeleteFileRequest { path })
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::MakeDirectory { sandbox, path } => self
                .runtime
                .make_directory(&sandbox, MakeDirectoryRequest { path })
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::Snapshot { sandbox, request } => {
                let provider = self.snapshots.as_ref().ok_or_else(|| {
                    CoreError::Conflict("worker runtime does not support snapshots".into())
                })?;
                provider
                    .capture(&sandbox, &request)
                    .await
                    .map(WorkerValue::Snapshot)
            }
            WorkerOperation::Restore { sandbox, snapshot } => {
                let provider = self.snapshots.as_ref().ok_or_else(|| {
                    CoreError::Conflict("worker runtime does not support snapshots".into())
                })?;
                provider
                    .restore(&sandbox, &snapshot)
                    .await
                    .map(|_| WorkerValue::Unit)
            }
            WorkerOperation::ImportWorkspaceArchive {
                sandbox,
                archive_base64,
            } => {
                let archive = decode_workspace_archive(&archive_base64)?;
                self.runtime
                    .import_workspace_archive(&sandbox, &archive)
                    .await
                    .map(|_| WorkerValue::Unit)
            }
        };
        result.map_err(WorkerError::from_runtime)
    }
}

/// Decodes a portable workspace archive received over the worker wire.
///
/// The encoded length is checked before decoding so an oversized or malformed
/// payload is rejected without letting a worker's string drive an allocation.
fn decode_workspace_archive(archive_base64: &str) -> Result<Vec<u8>, CoreError> {
    use base64::Engine;
    if archive_base64.len() > MAX_WORKER_TRANSFER {
        return Err(CoreError::LimitExceeded(format!(
            "workspace archive exceeds {} bytes",
            MAX_WORKER_TRANSFER
        )));
    }
    base64::engine::general_purpose::STANDARD
        .decode(archive_base64)
        .map_err(|_| CoreError::InvalidRequest("invalid workspace archive encoding".into()))
}

async fn authenticate(
    State(state): State<WorkerService>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, StatusCode> {
    let supplied = headers
        .get(WORKER_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !supplied.is_some_and(|value| constant_time_eq(value, state.token.as_ref())) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    left.iter()
        .zip(right.iter())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

async fn status(State(state): State<WorkerService>) -> Json<WorkerStatus> {
    Json(WorkerStatus {
        node_id: state.node_id,
        healthy: state.runtime.health().await.healthy,
        runtime: state.runtime_kind,
        capabilities: state.capabilities.clone(),
        sandbox_count: state.sandboxes.lock().await.len(),
        in_flight: state.in_flight.load(Ordering::Relaxed),
        capacity: state.capacity,
        guest_profile: state.guest_profile.clone(),
    })
}

fn rejected(request_id: Uuid, code: &str, message: impl Into<String>) -> Response {
    (
        StatusCode::OK,
        Json(WorkerResponse {
            request_id,
            result: Err(WorkerError {
                code: code.into(),
                message: message.into(),
            }),
        }),
    )
        .into_response()
}

/// Fences a worker request against durable ownership before the runtime runs.
///
/// Rejects foreign or superseded leases and generations the authority has not
/// issued. Renewals preserve lease identity and may advance after dispatch.
/// Unavailable ownership verification always fails closed.
async fn authorize(state: &WorkerService, request: &WorkerRequest) -> Result<(), Box<Response>> {
    let request_id = request.request_id;
    if !operation_belongs_to_worker(&request.operation, state.node_id) {
        return Err(Box::new(rejected(
            request_id,
            "conflict",
            "sandbox is not owned by this worker",
        )));
    }
    let sandbox_id = operation_sandbox_id(&request.operation);
    // Ownership is asked *before* the floor is judged. `renew_worker_lease`
    // increments the generation on every renewal, so a renewal that commits
    // between the control plane reading the generation and dispatching this
    // operation leaves the dispatched value one behind what this worker has
    // already served - observed live as `sent=2 learned=3`, refusing artifact
    // reads on a machine the run still owned. Judging that floor without asking
    // first meant the benign case was rejected and the real one never ran.
    let learned = state.generations.lock().await.generation(sandbox_id);
    // When ownership cannot be verified there is nothing to compare a lease id
    // against, so the local floor has to stand on its own and refuse. That is
    // the fail-closed case these tests pin: a worker that cannot ask who owns
    // the sandbox must not act on its own cached belief.
    let verified = match state.verify_ownership(sandbox_id).await {
        Ok(verified) => verified,
        Err(error) => {
            if learned.is_some_and(|learned| request.lease_generation < learned) {
                tracing::warn!(
                    sandbox_id = %sandbox_id,
                    sent = request.lease_generation,
                    learned = learned,
                    "ownership could not be verified and this dispatch is behind the floor; refusing"
                );
                return Err(Box::new(rejected(
                    request_id,
                    "conflict",
                    "stale sandbox lease generation",
                )));
            }
            return Err(Box::new(rejected(
                request_id,
                runtime_worker_code(&error),
                error_message(&error),
            )));
        }
    };
    match verified {
        OwnershipCheck::Rejected(message) => {
            tracing::warn!(
                sandbox_id = %sandbox_id,
                sent = request.lease_generation,
                %message,
                "the control plane refused ownership for this sandbox"
            );
            Err(Box::new(rejected(request_id, "conflict", message)))
        }
        OwnershipCheck::Owned {
            generation,
            lease_id,
        } => {
            // Compare the dispatched identity, not the learned identity: an old
            // dispatch may arrive after recovery placed a new lease on this
            // same worker and the ledger has already learned the replacement.
            if request.lease_id != lease_id || learned.is_some_and(|floor| generation < floor) {
                tracing::warn!(
                    %sandbox_id,
                    sent_lease = %request.lease_id,
                    current_lease = %lease_id,
                    sent = request.lease_generation,
                    verified = generation,
                    "worker refused a superseded lease or regressed ownership generation"
                );
                return Err(Box::new(rejected(
                    request_id,
                    "conflict",
                    "stale sandbox lease generation",
                )));
            }
            if generation < request.lease_generation {
                tracing::warn!(
                    sandbox_id = %sandbox_id,
                    sent = request.lease_generation,
                    verified = generation,
                    "the control plane is behind the dispatched generation; this worker may be acting on a stale lease"
                );
                return Err(Box::new(rejected(
                    request_id,
                    "conflict",
                    "sandbox lease generation does not match the control plane",
                )));
            }
            if generation > request.lease_generation {
                tracing::debug!(
                    sandbox_id = %sandbox_id,
                    sent = request.lease_generation,
                    verified = generation,
                    "lease was renewed between dispatch and authorization; adopting the newer generation"
                );
            }
            // Debug, not warn: this runs on every authorized operation, and it is
            // the evidence that the durable floor actually moved - without it,
            // a floor that never advances and a floor that advances twice look
            // identical from the outside.
            tracing::debug!(
                sandbox_id = %sandbox_id,
                generation,
                "authorized; advancing this worker's generation floor"
            );
            state
                .learn_generation(sandbox_id, generation, lease_id)
                .await;
            Ok(())
        }
    }
}

fn runtime_worker_code(error: &CoreError) -> &'static str {
    match error {
        CoreError::NotFound(_) => "not_found",
        CoreError::Conflict(_) => "conflict",
        CoreError::Forbidden(_) => "forbidden",
        _ => "runtime_unavailable",
    }
}

fn error_message(error: &CoreError) -> String {
    match error {
        CoreError::NotFound(message)
        | CoreError::Conflict(message)
        | CoreError::Forbidden(message)
        | CoreError::Unavailable(message)
        | CoreError::Transient(message)
        | CoreError::Backend(message)
        | CoreError::InvalidRequest(message)
        | CoreError::LimitExceeded(message)
        | CoreError::QuotaExceeded(message)
        | CoreError::Unsupported(message) => message.clone(),
        CoreError::Io(error) => error.to_string(),
    }
}

/// The sandbox whose lifecycle an operation changes, if it changes one.
///
/// Exec and the file operations are deliberately absent. They act on a running
/// sandbox's contents rather than on whether that sandbox exists, and queueing
/// them would make a destroy wait for the command it exists to interrupt.
fn lifecycle_sandbox(operation: &WorkerOperation) -> Option<Uuid> {
    match operation {
        WorkerOperation::Create { sandbox }
        | WorkerOperation::Start { sandbox }
        | WorkerOperation::Stop { sandbox }
        | WorkerOperation::Pause { sandbox }
        | WorkerOperation::Resume { sandbox }
        | WorkerOperation::Destroy { sandbox }
        | WorkerOperation::Snapshot { sandbox, .. }
        | WorkerOperation::Restore { sandbox, .. } => Some(sandbox.id),
        WorkerOperation::Exec { .. }
        | WorkerOperation::PutFile { .. }
        | WorkerOperation::GetFile { .. }
        | WorkerOperation::ListFiles { .. }
        | WorkerOperation::DeleteFile { .. }
        | WorkerOperation::MakeDirectory { .. }
        | WorkerOperation::ImportWorkspaceArchive { .. } => None,
    }
}

struct InFlight<'a>(&'a AtomicUsize);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn file_chunk(
    State(state): State<WorkerService>,
    Json(request): Json<WorkerChunkRequest>,
) -> Response {
    let authorization = &request.authorization;
    let WorkerOperation::GetFile { sandbox, path } = &authorization.operation else {
        return rejected(
            authorization.request_id,
            "invalid_request",
            "file authorization required",
        );
    };
    if path != &request.request.path {
        return rejected(
            authorization.request_id,
            "invalid_request",
            "chunk path mismatch",
        );
    }
    if let Err(error) = request.request.validate() {
        let error = WorkerError::from_runtime(error);
        return rejected(authorization.request_id, &error.code, error.message);
    }
    if let Err(response) = authorize(&state, authorization).await {
        return *response;
    }
    state.in_flight.fetch_add(1, Ordering::Relaxed);
    let _in_flight = InFlight(&state.in_flight);
    // The whole group is read between the two checks and buffered, so a lease
    // replaced while it is being read still stops the bytes before any of them
    // is written. Grouping removes the per-chunk round trip; it does not
    // remove the check that gates publication.
    let read = state
        .runtime
        .get_file_chunks(sandbox, request.request.clone(), request.chunks)
        .await;
    // A lease replacement during the read must never publish bytes.
    if let Err(response) = authorize(&state, authorization).await {
        return *response;
    }
    let chunks = match read {
        Ok(chunks) => chunks,
        Err(error) => {
            let error = WorkerError::from_runtime(error);
            return rejected(authorization.request_id, &error.code, error.message);
        }
    };
    if chunks.is_empty() || chunks.len() > request.chunks {
        return rejected(
            authorization.request_id,
            "internal",
            "invalid worker chunk group",
        );
    }
    // The group describes one file, so its shared metadata has to be true
    // before a single frame is encoded. The response carries one version and
    // one size for the whole group and the client stamps them onto every
    // chunk it reconstructs, so a group whose chunks disagree - from a
    // runtime that serves its own group, or from a file replaced between two
    // reads - would be published as one consistent artifact under a checksum
    // that authenticates the splice. Each chunk is validated against its own
    // request, and every chunk against the first one's version and size.
    let first = &chunks[0];
    for (index, chunk) in chunks.iter().enumerate() {
        let step = aiec_core::runtime::burst_request(&request.request, index);
        if chunk.size_bytes != first.size_bytes || chunk.version != first.version {
            return rejected(
                authorization.request_id,
                "conflict",
                "file changed during chunk group",
            );
        }
        if let Err(error) = step.validate_chunk(chunk) {
            let error = WorkerError::from_runtime(error);
            return rejected(authorization.request_id, &error.code, error.message);
        }
    }
    let mut body = Vec::with_capacity(chunks.iter().map(|c| c.bytes.len() + 4).sum());
    for chunk in &chunks {
        body.extend_from_slice(&(chunk.bytes.len() as u32).to_le_bytes());
        body.extend_from_slice(&chunk.bytes);
    }
    let last = chunks.last().expect("checked non-empty above");
    let mut response = axum::body::Body::from(body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    for (name, value) in [
        ("x-aiec-request-id", authorization.request_id.to_string()),
        ("x-aiec-file-size", first.size_bytes.to_string()),
        ("x-aiec-file-version", first.version.clone()),
        ("x-aiec-file-eof", last.eof.to_string()),
        ("x-aiec-chunk-count", chunks.len().to_string()),
    ] {
        match axum::http::HeaderValue::from_str(&value) {
            Ok(value) => {
                headers.insert(name, value);
            }
            Err(_) => {
                return rejected(
                    authorization.request_id,
                    "internal",
                    "invalid chunk metadata",
                );
            }
        }
    }
    response
}

async fn operation(
    State(state): State<WorkerService>,
    Json(request): Json<WorkerRequest>,
) -> Response {
    if let Err(response) = authorize(&state, &request).await {
        return *response;
    }
    if let Some(response) = state.cache.lock().await.get(request.request_id) {
        return (StatusCode::OK, Json(response)).into_response();
    }
    let slots = match &request.operation {
        WorkerOperation::Create { .. }
        | WorkerOperation::Start { .. }
        | WorkerOperation::Resume { .. }
        | WorkerOperation::Restore { .. } => Some(&state.boot_slots),
        WorkerOperation::Snapshot { .. } | WorkerOperation::ImportWorkspaceArchive { .. } => {
            Some(&state.snapshot_slots)
        }
        _ => None,
    };
    let _permit = match slots {
        Some(slots) => match slots.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return rejected(
                    request.request_id,
                    "runtime_unavailable",
                    "worker heavy-operation capacity exhausted",
                );
            }
        },
        None => None,
    };
    // One lifecycle operation per sandbox at a time. Without this a destroy
    // and a create for the same sandbox run together, and the answer each gets
    // is wrong: the destroy reports a machine that is gone while the create is
    // still copying into the directory it removed, and the create's copy is
    // what survives. The response cache above only collapses one request id;
    // these are two different ones.
    //
    // Both this and the re-authorization below run before this request claims a
    // response slot. A refusal at either of them is final for this attempt and
    // has no response to store, so it must not leave a cache entry behind: an
    // entry with no response is one the eviction pass will not reclaim, and a
    // caller that keeps sending superseded generations would otherwise grow the
    // cache for the lifetime of the process.
    // Counted from here rather than from just before the runtime runs: a
    // request queued behind another request for the same sandbox is work this
    // worker has accepted and not finished, and `/health` should say so.
    state.in_flight.fetch_add(1, Ordering::Relaxed);
    let _in_flight = InFlight(&state.in_flight);
    let lifecycle = match lifecycle_sandbox(&request.operation) {
        Some(sandbox_id) => match state.lifecycle.clone().enter(sandbox_id).await {
            Ok(guard) => Some(guard),
            Err(busy) => {
                return rejected(request.request_id, "runtime_unavailable", busy.to_string());
            }
        },
        None => None,
    };
    // Ownership was established before the wait, and a wait is a window in
    // which the control plane can move the sandbox to another worker or fence
    // this request's generation. It is established again here, so what runs is
    // authorized as of the moment it runs rather than as of the moment it
    // arrived. The guard is held until this handler returns its response, which
    // is what keeps a destroy behind a create that is still materializing.
    if lifecycle.is_some()
        && let Err(response) = authorize(&state, &request).await
    {
        return *response;
    }
    let response_slot = state.cache.lock().await.entry(request.request_id);
    let mut response_slot = response_slot.lock().await;
    if let Some(response) = response_slot.clone() {
        // A concurrent duplicate of this request id already ran it. Counted
        // above, so it is released here.
        return (StatusCode::OK, Json(response)).into_response();
    }
    let sandbox_event = match &request.operation {
        WorkerOperation::Create { sandbox } => Some((sandbox.id, true)),
        WorkerOperation::Destroy { sandbox } => Some((sandbox.id, false)),
        _ => None,
    };
    let result = state.execute(request.operation).await;
    if result.is_ok()
        && let Some((sandbox_id, create)) = sandbox_event
    {
        let mut sandboxes = state.sandboxes.lock().await;
        if create {
            sandboxes.insert(sandbox_id);
        } else {
            sandboxes.remove(&sandbox_id);
            // A destroyed sandbox is never rescheduled, so its fencing
            // generation must not outlive it in the durable ledger.
            drop(sandboxes);
            state.forget_generation(sandbox_id).await;
        }
    }
    let response = WorkerResponse {
        request_id: request.request_id,
        result,
    };
    *response_slot = Some(response.clone());
    drop(response_slot);
    state
        .cache
        .lock()
        .await
        .complete(request.request_id, response.clone())
        .await;
    (StatusCode::OK, Json(response)).into_response()
}

impl From<WorkerClientError> for crate::ApiFailure {
    fn from(error: WorkerClientError) -> Self {
        match error {
            WorkerClientError::Unavailable(message) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "worker_unavailable",
                message,
            ),
            WorkerClientError::Transport(message) => {
                Self::new(StatusCode::BAD_GATEWAY, "worker_transport", message)
            }
            WorkerClientError::Response(message) => {
                Self::new(StatusCode::BAD_GATEWAY, "worker_protocol", message)
            }
        }
    }
}

impl From<WorkerError> for crate::ApiFailure {
    fn from(error: WorkerError) -> Self {
        let status = match error.code.as_str() {
            "invalid_request" => StatusCode::BAD_REQUEST,
            "forbidden" => StatusCode::FORBIDDEN,
            "not_found" => StatusCode::NOT_FOUND,
            "conflict" => StatusCode::CONFLICT,
            "limit_exceeded" => StatusCode::PAYLOAD_TOO_LARGE,
            "runtime_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self::new(status, leaked_code(&error.code), error.message)
    }
}
fn leaked_code(code: &str) -> &'static str {
    match code {
        "invalid_request" => "invalid_request",
        "forbidden" => "forbidden",
        "not_found" => "not_found",
        "conflict" => "conflict",
        "limit_exceeded" => "limit_exceeded",
        "runtime_unavailable" => "runtime_unavailable",
        _ => "internal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiec_core::runtime::FILE_CHUNK_BYTES;
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicBool;
    use tower::util::ServiceExt;

    fn sandbox(node_id: Option<Uuid>) -> Sandbox {
        let now = chrono::Utc::now();
        Sandbox {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            node_id,
            image_id: "test".into(),
            state: SandboxState::Running,
            runtime: RuntimeKind::Firecracker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: NetworkPolicy::default(),
            environment: EnvironmentSpec::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        }
    }

    #[tokio::test]
    async fn worker_status_reports_configured_capabilities() {
        struct TestRuntime;
        #[async_trait]
        impl SandboxRuntime for TestRuntime {
            async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
                Ok(ExecResult {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms: 0,
                    timed_out: false,
                })
            }
            async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
                Ok(())
            }
            async fn get_file(&self, _: &Sandbox, path: &str) -> Result<FileContent, CoreError> {
                Ok(FileContent {
                    path: path.into(),
                    content_base64: String::new(),
                })
            }
            async fn get_file_chunk(
                &self,
                _: &Sandbox,
                _: FileChunkRequest,
            ) -> Result<FileChunk, CoreError> {
                Err(CoreError::Backend("unused".into()))
            }
            async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
                Ok(Vec::new())
            }
            async fn delete_file(
                &self,
                _: &Sandbox,
                _: DeleteFileRequest,
            ) -> Result<(), CoreError> {
                Ok(())
            }
            async fn make_directory(
                &self,
                _: &Sandbox,
                _: MakeDirectoryRequest,
            ) -> Result<(), CoreError> {
                Ok(())
            }
            async fn import_workspace_archive(
                &self,
                _: &Sandbox,
                _: &[u8],
            ) -> Result<(), CoreError> {
                Ok(())
            }
            async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn health(&self) -> RuntimeHealth {
                RuntimeHealth::healthy()
            }
            fn capabilities(&self) -> RuntimeCapabilities {
                RuntimeCapabilities {
                    isolation: aiec_core::runtime::RuntimeIsolation::Container,
                    exec: true,
                    files: true,
                    streaming: false,
                    ..RuntimeCapabilities::default()
                }
            }
        }
        let capabilities = RuntimeCapabilities {
            isolation: aiec_core::runtime::RuntimeIsolation::Container,
            exec: true,
            files: true,
            streaming: false,
            ..RuntimeCapabilities::default()
        };
        let service = WorkerService::new(
            Arc::new(TestRuntime),
            RuntimeKind::Docker,
            capabilities,
            None,
            "token",
            Uuid::now_v7(),
            1,
        );
        let response = service
            .router()
            .oneshot(
                axum::http::Request::get("/health")
                    .header("authorization", "Bearer token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let status: WorkerStatus = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status.runtime, RuntimeKind::Docker);
        assert!(
            status.capabilities.exec && status.capabilities.files && !status.capabilities.streaming
        );
    }

    #[test]
    fn rejects_operations_for_another_worker() {
        let owner = Uuid::now_v7();
        let other = Uuid::now_v7();
        let operation = WorkerOperation::Exec {
            sandbox: sandbox(Some(owner)),
            request: ExecRequest {
                command: vec!["true".into()],
                working_directory: None,
                environment: BTreeMap::new(),
                timeout_seconds: 1,
                stdin: None,
            },
        };
        assert!(!operation_belongs_to_worker(&operation, other));
        assert!(operation_belongs_to_worker(&operation, owner));
    }

    #[test]
    fn rejects_unowned_sandbox_operations() {
        let operation = WorkerOperation::Stop {
            sandbox: sandbox(None),
        };
        assert!(!operation_belongs_to_worker(&operation, Uuid::now_v7()));
    }
    #[tokio::test]
    async fn worker_service_rejects_foreign_sandbox_before_runtime_call() {
        struct FailingRuntime;
        #[async_trait]
        impl SandboxRuntime for FailingRuntime {
            async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn get_file_chunk(
                &self,
                _: &Sandbox,
                _: FileChunkRequest,
            ) -> Result<FileChunk, CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn delete_file(
                &self,
                _: &Sandbox,
                _: DeleteFileRequest,
            ) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn make_directory(
                &self,
                _: &Sandbox,
                _: MakeDirectoryRequest,
            ) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn import_workspace_archive(
                &self,
                _: &Sandbox,
                _: &[u8],
            ) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn health(&self) -> RuntimeHealth {
                RuntimeHealth::healthy()
            }
            fn capabilities(&self) -> RuntimeCapabilities {
                RuntimeCapabilities::default()
            }
        }
        let owner = Uuid::now_v7();
        let service = WorkerService::new(
            Arc::new(FailingRuntime),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        );
        let response = service
            .router()
            .oneshot(
                axum::http::Request::post("/v1/operations")
                    .header("authorization", "Bearer token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_string(&WorkerRequest {
                            request_id: Uuid::now_v7(),
                            lease_id: stable_lease_id(),
                            lease_generation: 1,
                            operation: WorkerOperation::Stop {
                                sandbox: sandbox(Some(Uuid::now_v7())),
                            },
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["result"]["Err"]["code"], "conflict");
    }
    #[tokio::test]
    async fn worker_service_rejects_stale_generation_before_runtime_call() {
        struct FailingRuntime;
        #[async_trait]
        impl SandboxRuntime for FailingRuntime {
            async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn get_file_chunk(
                &self,
                _: &Sandbox,
                _: FileChunkRequest,
            ) -> Result<FileChunk, CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn delete_file(
                &self,
                _: &Sandbox,
                _: DeleteFileRequest,
            ) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn make_directory(
                &self,
                _: &Sandbox,
                _: MakeDirectoryRequest,
            ) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn import_workspace_archive(
                &self,
                _: &Sandbox,
                _: &[u8],
            ) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
                Err(CoreError::Backend("unexpected".into()))
            }
            async fn health(&self) -> RuntimeHealth {
                RuntimeHealth::healthy()
            }
            fn capabilities(&self) -> RuntimeCapabilities {
                RuntimeCapabilities::default()
            }
        }
        let owner = Uuid::now_v7();
        let sandbox = sandbox(Some(owner));
        let service = WorkerService::new(
            Arc::new(FailingRuntime),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_generation(sandbox.id, 2);
        let response = service
            .router()
            .oneshot(
                axum::http::Request::post("/v1/operations")
                    .header("authorization", "Bearer token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_string(&WorkerRequest {
                            request_id: Uuid::now_v7(),
                            lease_id: stable_lease_id(),
                            lease_generation: 1,
                            operation: WorkerOperation::Stop { sandbox },
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["result"]["Err"]["code"], "conflict");
    }

    /// Runtime double that fails loudly, so any rejection path that still
    /// reached the runtime is visible in the response code.
    struct ForbiddenRuntime;
    #[async_trait]
    impl SandboxRuntime for ForbiddenRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            _: FileChunkRequest,
        ) -> Result<FileChunk, CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn import_workspace_archive(&self, _: &Sandbox, _: &[u8]) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
            Err(CoreError::Backend("runtime must not run".into()))
        }
        async fn health(&self) -> RuntimeHealth {
            RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::default()
        }
    }

    /// Runtime double that counts the exec calls that survived fencing.
    struct CountingRuntime {
        execs: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl SandboxRuntime for CountingRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
            self.execs.fetch_add(1, Ordering::Relaxed);
            Ok(ExecResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: 0,
                timed_out: false,
            })
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
            Ok(())
        }
        async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
            Ok(FileContent {
                path: "/workspace".into(),
                content_base64: String::new(),
            })
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            request: FileChunkRequest,
        ) -> Result<FileChunk, CoreError> {
            self.execs.fetch_add(1, Ordering::Relaxed);
            request.validate()?;
            let chunk = FileChunk {
                bytes: bytes::Bytes::from_static(b"chunk"),
                size_bytes: 5,
                version: "fixture".into(),
                eof: true,
            };
            request.validate_chunk(&chunk)?;
            Ok(chunk)
        }
        async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
            Ok(Vec::new())
        }
        async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
            Ok(())
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), CoreError> {
            Ok(())
        }
        async fn import_workspace_archive(&self, _: &Sandbox, _: &[u8]) -> Result<(), CoreError> {
            Ok(())
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn health(&self) -> RuntimeHealth {
            RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::default()
        }
    }

    /// One lease id for every "same lease" case in these tests, so the
    /// difference under test is the generation and not the lease.
    fn stable_lease_id() -> Uuid {
        Uuid::from_u128(0x5eed_5eed_5eed_5eed_5eed_5eed_5eed_5eed)
    }

    enum FakeOwnership {
        /// `Owned(generation)` uses a stable lease id, so two calls model the
        /// same lease renewed. `Reassigned(generation)` models a different
        /// lease issued for the same sandbox, which must be refused.
        Owned(i64),
        Reassigned(i64),
        Rejected(&'static str),
        Unavailable,
    }

    struct FakeOwnershipVerifier {
        answer: FakeOwnership,
    }

    #[async_trait]
    impl OwnershipVerifier for FakeOwnershipVerifier {
        async fn verify(&self, _: Uuid) -> Result<OwnershipCheck, CoreError> {
            match self.answer {
                FakeOwnership::Owned(generation) => Ok(OwnershipCheck::Owned {
                    generation,
                    lease_id: stable_lease_id(),
                }),
                FakeOwnership::Reassigned(generation) => Ok(OwnershipCheck::Owned {
                    generation,
                    lease_id: Uuid::now_v7(),
                }),
                FakeOwnership::Rejected(message) => Ok(OwnershipCheck::Rejected(message.into())),
                FakeOwnership::Unavailable => {
                    Err(CoreError::Unavailable("control plane unreachable".into()))
                }
            }
        }
    }

    fn exec_request(generation: i64, target: &Sandbox) -> WorkerRequest {
        WorkerRequest {
            request_id: Uuid::now_v7(),
            lease_id: stable_lease_id(),
            lease_generation: generation,
            operation: WorkerOperation::Exec {
                sandbox: target.clone(),
                request: ExecRequest {
                    command: vec!["true".into()],
                    working_directory: None,
                    environment: BTreeMap::new(),
                    timeout_seconds: 1,
                    stdin: None,
                },
            },
        }
    }

    async fn post_operation(service: WorkerService, request: WorkerRequest) -> serde_json::Value {
        let response = service
            .router()
            .oneshot(
                axum::http::Request::post("/v1/operations")
                    .header("authorization", "Bearer token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_string(&request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    struct ChunkOwnership {
        runtime_reads: Arc<AtomicUsize>,
        revoke_after_read: bool,
    }
    #[async_trait]
    impl OwnershipVerifier for ChunkOwnership {
        async fn verify(&self, _: Uuid) -> Result<OwnershipCheck, CoreError> {
            if self.revoke_after_read && self.runtime_reads.load(Ordering::SeqCst) > 0 {
                Ok(OwnershipCheck::Rejected(
                    "lease replaced during file read".into(),
                ))
            } else {
                Ok(OwnershipCheck::Owned {
                    generation: 2,
                    lease_id: stable_lease_id(),
                })
            }
        }
    }
    /// Revokes once the runtime has produced `revoke_after` reads, so the
    /// revocation lands between two chunks of one group rather than at its
    /// edges.
    struct GroupOwnership {
        runtime_reads: Arc<AtomicUsize>,
        revoke_after: usize,
    }
    #[async_trait]
    impl OwnershipVerifier for GroupOwnership {
        async fn verify(&self, _: Uuid) -> Result<OwnershipCheck, CoreError> {
            if self.runtime_reads.load(Ordering::SeqCst) >= self.revoke_after {
                Ok(OwnershipCheck::Rejected(
                    "lease replaced during file read".into(),
                ))
            } else {
                Ok(OwnershipCheck::Owned {
                    generation: 2,
                    lease_id: stable_lease_id(),
                })
            }
        }
    }

    #[tokio::test]
    async fn binary_chunks_are_refenced_after_read_without_caching_bytes() {
        for revoke_after_read in [false, true] {
            let owner = Uuid::now_v7();
            let target = sandbox(Some(owner));
            let reads = Arc::new(AtomicUsize::new(0));
            let service = WorkerService::new(
                Arc::new(CountingRuntime {
                    execs: reads.clone(),
                }),
                RuntimeKind::Firecracker,
                RuntimeCapabilities::default(),
                None,
                "token",
                owner,
                1,
            )
            .with_ownership_verifier(Arc::new(ChunkOwnership {
                runtime_reads: reads.clone(),
                revoke_after_read,
            }));
            let request = WorkerChunkRequest {
                authorization: WorkerRequest {
                    request_id: Uuid::now_v7(),
                    lease_id: stable_lease_id(),
                    lease_generation: 1,
                    operation: WorkerOperation::GetFile {
                        sandbox: target,
                        path: "/workspace/file".into(),
                    },
                },
                request: FileChunkRequest {
                    path: "/workspace/file".into(),
                    offset: 0,
                    length: FILE_CHUNK_BYTES,
                    expected_version: None,
                },
                chunks: 1,
            };
            let response = service
                .clone()
                .router()
                .oneshot(
                    axum::http::Request::post("/v1/files/chunk")
                        .header("authorization", "Bearer token")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            serde_json::to_vec(&request).unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(reads.load(Ordering::SeqCst), 1);
            assert_eq!(service.cache.lock().await.len(), 0);
            if revoke_after_read {
                let response: WorkerResponse = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(response.result.unwrap_err().code, "conflict");
            } else {
                assert_eq!(
                    response.headers()["content-type"],
                    "application/octet-stream"
                );
                assert_eq!(response.headers()["x-aiec-file-size"], "5");
                assert_eq!(
                    axum::body::to_bytes(response.into_body(), 64)
                        .await
                        .unwrap()
                        .as_ref(),
                    b"\x05\x00\x00\x00chunk"
                );
            }
        }
    }
    /// A group is read between the two authorization checks, so the trailing
    /// one is what publishes. This is the case a group makes possible that a
    /// single chunk could not: a lease replaced *between* the chunks of one
    /// request must still stop every byte of it.
    #[tokio::test]
    async fn a_chunk_group_is_published_only_if_the_lease_survived_the_whole_read() {
        for revoke_mid_group in [false, true] {
            let owner = Uuid::now_v7();
            let target = sandbox(Some(owner));
            let reads = Arc::new(AtomicUsize::new(0));
            let service = WorkerService::new(
                Arc::new(GroupRuntime {
                    reads: reads.clone(),
                }),
                RuntimeKind::Firecracker,
                RuntimeCapabilities::default(),
                None,
                "token",
                owner,
                1,
            )
            .with_ownership_verifier(Arc::new(GroupOwnership {
                runtime_reads: reads.clone(),
                revoke_after: if revoke_mid_group { 1 } else { usize::MAX },
            }));
            let request = WorkerChunkRequest {
                authorization: WorkerRequest {
                    request_id: Uuid::now_v7(),
                    lease_id: stable_lease_id(),
                    lease_generation: 1,
                    operation: WorkerOperation::GetFile {
                        sandbox: target,
                        path: "/workspace/file".into(),
                    },
                },
                request: FileChunkRequest {
                    path: "/workspace/file".into(),
                    offset: 0,
                    length: FILE_CHUNK_BYTES,
                    expected_version: None,
                },
                chunks: 8,
            };
            let response = service
                .router()
                .oneshot(
                    axum::http::Request::post("/v1/files/chunk")
                        .header("authorization", "Bearer token")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            serde_json::to_vec(&request).unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            if revoke_mid_group {
                let body: WorkerResponse = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(body.result.unwrap_err().code, "conflict");
            } else {
                assert_eq!(response.headers()["x-aiec-chunk-count"], "3");
                let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap();
                // three length-prefixed frames of 64 KiB each
                assert_eq!(body.len(), 3 * (4 + FILE_CHUNK_BYTES));
            }
        }
    }
    /// Serves a file of exactly three chunks and counts its reads, so a group
    /// request really does read more than once and a revocation can land
    /// between two of them.
    struct GroupRuntime {
        reads: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl SandboxRuntime for GroupRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
            Ok(())
        }
        async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            request: FileChunkRequest,
        ) -> Result<FileChunk, CoreError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let size = (FILE_CHUNK_BYTES * 3) as u64;
            let remaining = (size - request.offset).min(request.length as u64) as usize;
            let chunk = FileChunk {
                bytes: bytes::Bytes::from(vec![b'x'; remaining]),
                size_bytes: size,
                version: "group".into(),
                eof: request.offset + remaining as u64 == size,
            };
            request.validate_chunk(&chunk)?;
            Ok(chunk)
        }
        async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
            Ok(Vec::new())
        }
        async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
            Ok(())
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), CoreError> {
            Ok(())
        }
        async fn import_workspace_archive(&self, _: &Sandbox, _: &[u8]) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn health(&self) -> RuntimeHealth {
            RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::default()
        }
    }

    #[tokio::test]
    async fn worker_chunk_client_bounds_body_without_content_length() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().route(
            "/v1/files/chunk",
            post(|Json(request): Json<WorkerChunkRequest>| async move {
                // One frame of 6 bytes for a request that asked for 5: the
                // client must bound the body, not trust the length in a frame.
                let mut body = Vec::new();
                body.extend_from_slice(&6u32.to_le_bytes());
                body.extend_from_slice(b"123456");
                let stream =
                    futures::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from(body))]);
                (
                    [
                        ("content-type", "application/octet-stream".to_owned()),
                        (
                            "x-aiec-request-id",
                            request.authorization.request_id.to_string(),
                        ),
                        ("x-aiec-file-size", "5".to_owned()),
                        ("x-aiec-file-version", "fixture".to_owned()),
                        ("x-aiec-file-eof", "true".to_owned()),
                        ("x-aiec-chunk-count", "1".to_owned()),
                    ],
                    axum::body::Body::from_stream(stream),
                )
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = sandbox(Some(Uuid::now_v7()));
        let authorization = WorkerRequest {
            request_id: Uuid::now_v7(),
            lease_id: stable_lease_id(),
            lease_generation: 1,
            operation: WorkerOperation::GetFile {
                sandbox: target,
                path: "/workspace/file".into(),
            },
        };
        let result = HttpWorkerClient::new("token")
            .unwrap()
            .get_file_chunk(
                &endpoint,
                authorization,
                FileChunkRequest {
                    path: "/workspace/file".into(),
                    offset: 0,
                    length: 5,
                    expected_version: None,
                },
            )
            .await;
        server.abort();
        assert!(matches!(result, Err(CoreError::LimitExceeded(_))));
    }
    /// A full group of maximum-size chunks is the bound plus its frame headers.
    /// Getting that wrong refuses the largest legitimate artifact, and it was
    /// wrong once: the bound counted payload bytes only, so every 16 MiB
    /// artifact failed collection with "limit exceeded".
    #[tokio::test]
    async fn a_full_group_of_maximum_chunks_is_not_refused_as_oversize() {
        let count = aiec_core::runtime::FILE_CHUNK_BURST;
        let size = (FILE_CHUNK_BYTES * count) as u64;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let file_size = size.to_string();
        let frame_count = count;
        let app = Router::new().route(
            "/v1/files/chunk",
            post(move |Json(request): Json<WorkerChunkRequest>| async move {
                let (count, size) = (frame_count, file_size.clone());
                let mut body = Vec::with_capacity(count * (FILE_CHUNK_BYTES + 4));
                for _ in 0..request.chunks {
                    body.extend_from_slice(&(FILE_CHUNK_BYTES as u32).to_le_bytes());
                    body.extend_from_slice(&[b'x'; FILE_CHUNK_BYTES]);
                }
                (
                    [
                        ("content-type", "application/octet-stream".to_owned()),
                        (
                            "x-aiec-request-id",
                            request.authorization.request_id.to_string(),
                        ),
                        ("x-aiec-file-size", size),
                        ("x-aiec-file-version", "fixture".to_owned()),
                        ("x-aiec-file-eof", "true".to_owned()),
                        ("x-aiec-chunk-count", count.to_string()),
                    ],
                    axum::body::Body::from(body),
                )
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let target = sandbox(Some(Uuid::now_v7()));
        let authorization = WorkerRequest {
            request_id: Uuid::now_v7(),
            lease_id: stable_lease_id(),
            lease_generation: 1,
            operation: WorkerOperation::GetFile {
                sandbox: target,
                path: "/workspace/file".into(),
            },
        };
        let result = HttpWorkerClient::new("token")
            .unwrap()
            .get_file_chunks(
                &endpoint,
                authorization,
                FileChunkRequest {
                    path: "/workspace/file".into(),
                    offset: 0,
                    length: FILE_CHUNK_BYTES,
                    expected_version: None,
                },
                count,
            )
            .await;
        server.abort();
        let chunks = result.expect("a full group must not be refused for its size");
        assert_eq!(chunks.len(), count);
        assert_eq!(
            chunks.iter().map(|c| c.bytes.len()).sum::<usize>(),
            size as usize
        );
    }

    #[tokio::test]
    async fn binary_chunk_superseded_lease_never_reaches_runtime() {
        let owner = Uuid::now_v7();
        let target = sandbox(Some(owner));
        let reads = Arc::new(AtomicUsize::new(0));
        let service = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: reads.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Reassigned(2),
        }));
        let request = WorkerChunkRequest {
            authorization: WorkerRequest {
                request_id: Uuid::now_v7(),
                lease_id: stable_lease_id(),
                lease_generation: 1,
                operation: WorkerOperation::GetFile {
                    sandbox: target,
                    path: "/workspace/file".into(),
                },
            },
            request: FileChunkRequest {
                path: "/workspace/file".into(),
                offset: 0,
                length: FILE_CHUNK_BYTES,
                expected_version: None,
            },
            chunks: 1,
        };
        let response = service
            .router()
            .oneshot(
                axum::http::Request::post("/v1/files/chunk")
                    .header("authorization", "Bearer token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let response: WorkerResponse = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.result.unwrap_err().code, "conflict");
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn worker_service_rejects_unowned_sandbox_before_runtime_call() {
        let owner = Uuid::now_v7();
        let service = WorkerService::new(
            Arc::new(ForbiddenRuntime),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        );
        let value = post_operation(
            service,
            WorkerRequest {
                request_id: Uuid::now_v7(),
                lease_id: stable_lease_id(),
                lease_generation: 1,
                operation: WorkerOperation::Stop {
                    sandbox: sandbox(None),
                },
            },
        )
        .await;
        assert_eq!(value["result"]["Err"]["code"], "conflict");
        assert_eq!(
            value["result"]["Err"]["message"],
            "sandbox is not owned by this worker"
        );
    }

    #[tokio::test]
    async fn worker_service_fails_closed_when_ownership_cannot_be_verified() {
        let owner = Uuid::now_v7();
        let execs = Arc::new(AtomicUsize::new(0));
        let service = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        );
        let target = sandbox(Some(owner));
        let unreachable = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Unavailable,
        }));
        let value = post_operation(unreachable, exec_request(1, &target)).await;
        assert_eq!(value["result"]["Err"]["code"], "runtime_unavailable");
        assert_eq!(execs.load(Ordering::Relaxed), 0);

        // A worker without a verifier must not execute either.
        let unconfigured = post_operation(service, exec_request(1, &target)).await;
        assert_eq!(unconfigured["result"]["Err"]["code"], "runtime_unavailable");
        assert_eq!(execs.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn worker_service_rejects_foreign_ownership_before_runtime_call() {
        let owner = Uuid::now_v7();
        let execs = Arc::new(AtomicUsize::new(0));
        let service = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Rejected("sandbox is owned by another worker"),
        }));
        let value = post_operation(service, exec_request(1, &sandbox(Some(owner)))).await;
        assert_eq!(value["result"]["Err"]["code"], "conflict");
        assert_eq!(
            value["result"]["Err"]["message"],
            "sandbox is owned by another worker"
        );
        assert_eq!(execs.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn worker_service_rejects_generation_ahead_of_the_control_plane() {
        let owner = Uuid::now_v7();
        let execs = Arc::new(AtomicUsize::new(0));
        let service = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(3),
        }));
        let value = post_operation(service, exec_request(4, &sandbox(Some(owner)))).await;
        assert_eq!(value["result"]["Err"]["code"], "conflict");
        assert_eq!(execs.load(Ordering::Relaxed), 0);
    }

    /// A lease renewed between dispatch and authorization is still ours.
    ///
    /// `renew_worker_lease` increments the generation on every renewal, so the
    /// control plane can read generation N, have a renewal commit, and then
    /// answer an ownership check with N+1. The worker is not behind and the lease
    /// was not reassigned - the fence simply compared two reads of a counter
    /// that legitimately moves. Observed on a live artifact read as
    /// `sent=1 verified=2`, then `sent=2 verified=3`, refusing work on a machine
    /// the run still owned.
    ///
    /// Ownership is what makes this safe to accept: `verify_ownership` only
    /// answers `Owned` once it has confirmed *this* worker holds the sandbox, so
    /// a reassignment arrives as a rejection rather than as a higher number.
    #[tokio::test]
    async fn worker_service_accepts_a_lease_renewed_after_it_was_dispatched() {
        let owner = Uuid::now_v7();
        let execs = Arc::new(AtomicUsize::new(0));
        let service = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(2),
        }));
        // Dispatched against generation 1; the lease renewed to 2 in flight.
        let value = post_operation(service, exec_request(1, &sandbox(Some(owner)))).await;
        assert!(
            value["result"]["Ok"].is_object(),
            "a renewed lease must not be refused: {value}"
        );
        assert_eq!(execs.load(Ordering::Relaxed), 1, "the command must run");
    }

    #[tokio::test]
    async fn worker_service_keeps_learned_generation_across_restart() {
        let state_dir = std::env::temp_dir().join(format!("aiec-worker-fence-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&state_dir).unwrap();
        let owner = Uuid::now_v7();
        let execs = Arc::new(AtomicUsize::new(0));
        let target = sandbox(Some(owner));
        let first = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_state_dir(&state_dir)
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(7),
        }));
        let accepted = post_operation(first, exec_request(7, &target)).await;
        assert!(accepted["result"]["Ok"].is_object());
        assert_eq!(execs.load(Ordering::Relaxed), 1);

        // A restart reloads the persisted floor from the state directory. The
        // control plane has since moved the sandbox to generation 9 on another
        // worker, so a late request carrying the superseded generation 5 must
        // be refused before the runtime is touched.
        let restarted = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_state_dir(&state_dir)
        // `Reassigned`, not `Owned`: the comment above says the sandbox moved to
        // another worker, and that is a *different lease*, not the same lease at
        // a higher generation. A renewal keeps its lease id and is legitimate;
        // only a changed lease must be refused, and the distinction is the point
        // of carrying the id at all.
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Reassigned(9),
        }));
        let stale = post_operation(restarted, exec_request(5, &target)).await;
        assert_eq!(stale["result"]["Err"]["code"], "conflict");
        assert_eq!(
            stale["result"]["Err"]["message"],
            "stale sandbox lease generation"
        );
        assert_eq!(execs.load(Ordering::Relaxed), 1);
        std::fs::remove_dir_all(&state_dir).unwrap();
    }

    /// A floor written before this worker knew about lease ids must not be stuck.
    ///
    /// Those records load from `lease-generations.json` with no lease, so a
    /// below-floor dispatch would find nothing to compare against and be refused
    /// forever - the old behaviour, persisting across restarts. The renewal that
    /// carries the lease arrives at exactly the generation already recorded, so
    /// an unconditional "generation >= recorded, skip" would leave it stale
    /// indefinitely.
    #[test]
    fn a_legacy_floor_entry_is_upgraded_when_its_lease_is_relearned() {
        let dir = std::env::temp_dir().join(format!("aiec-legacy-floor-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("state dir");
        let sandbox_id = Uuid::now_v7();
        let node_id = Uuid::now_v7();
        let lease_id = Uuid::now_v7();
        // Exactly what an older worker wrote: no lease field at all.
        std::fs::write(
            dir.join(GenerationLedger::FILE_NAME),
            serde_json::to_vec(&[serde_json::json!({
                "sandbox_id": sandbox_id,
                "node_id": node_id,
                "generation": 4,
            })])
            .expect("encode"),
        )
        .expect("write legacy ledger");

        let mut ledger = GenerationLedger::load(&dir, node_id);
        assert_eq!(ledger.generation(sandbox_id), Some(4), "legacy entry loads");
        assert_eq!(
            ledger.lease(sandbox_id),
            None,
            "a legacy entry has no lease to compare"
        );
        // Re-learning at the same generation fills the lease in.
        ledger
            .record(sandbox_id, node_id, 4, lease_id)
            .expect("record");
        assert_eq!(
            ledger.lease(sandbox_id),
            Some(lease_id),
            "the legacy entry must be upgraded, not skipped"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The other half of the distinction: a dispatch behind this worker's floor
    /// on the *same* lease is a renewal, and must be allowed.
    ///
    /// `renew_worker_lease` increments the generation on every renewal, so a
    /// renewal that commits between the control plane reading the generation and
    /// dispatching the operation leaves the dispatched value behind what the
    /// worker already served. Refusing that - which the bare floor did - is what
    /// made artifact reads fail on a machine the run still owned.
    #[tokio::test]
    async fn worker_service_accepts_a_dispatch_behind_its_floor_on_the_same_lease() {
        let owner = Uuid::now_v7();
        let execs = Arc::new(AtomicUsize::new(0));
        // One service for both calls, so the second genuinely runs against a
        // floor the first one installed. Two services would each start with an
        // empty ledger and the test would pass whether or not the floor exists.
        let service = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(9),
        }));
        // The same sandbox both times: `sandbox()` mints a fresh id per call, so
        // two calls would land on different sandboxes and never consult the floor
        // this test exists to exercise.
        let target = sandbox(Some(owner));
        // A first call teaches this worker generation 9 on the stable lease...
        let first = post_operation(service.clone(), exec_request(9, &target)).await;
        assert!(first["result"]["Ok"].is_object(), "first call: {first}");
        // ...and a later dispatch carrying 7, on that same lease, is a renewal.
        let behind = post_operation(service, exec_request(7, &target)).await;
        assert!(
            behind["result"]["Ok"].is_object(),
            "a renewal behind the floor must be accepted: {behind}"
        );
        assert_eq!(execs.load(Ordering::Relaxed), 2, "both commands must run");
    }

    #[tokio::test]
    async fn a_superseded_dispatch_is_refused_after_reassignment_to_the_same_worker() {
        let owner = Uuid::now_v7();
        let execs = Arc::new(AtomicUsize::new(0));
        let service = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            2,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(6),
        }));
        let target = sandbox(Some(owner));
        let current = post_operation(service.clone(), exec_request(6, &target)).await;
        assert!(current["result"]["Ok"].is_object());
        // Recovery has already taught this worker the replacement lease. The
        // delayed request belongs to a different lease, not a benign renewal.
        let mut delayed = exec_request(5, &target);
        delayed.lease_id = Uuid::now_v7();
        let refused = post_operation(service, delayed).await;
        assert_eq!(refused["result"]["Err"]["code"], "conflict");
        assert_eq!(execs.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn worker_health_reports_the_guest_image_profile() {
        struct TestRuntime;
        #[async_trait]
        impl SandboxRuntime for TestRuntime {
            async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
                Err(CoreError::Backend("unused".into()))
            }
            async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
                Ok(())
            }
            async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
                Err(CoreError::Backend("unused".into()))
            }
            async fn get_file_chunk(
                &self,
                _: &Sandbox,
                _: FileChunkRequest,
            ) -> Result<FileChunk, CoreError> {
                Err(CoreError::Backend("unused".into()))
            }
            async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
                Ok(Vec::new())
            }
            async fn delete_file(
                &self,
                _: &Sandbox,
                _: DeleteFileRequest,
            ) -> Result<(), CoreError> {
                Ok(())
            }
            async fn make_directory(
                &self,
                _: &Sandbox,
                _: MakeDirectoryRequest,
            ) -> Result<(), CoreError> {
                Ok(())
            }
            async fn import_workspace_archive(
                &self,
                _: &Sandbox,
                _: &[u8],
            ) -> Result<(), CoreError> {
                Ok(())
            }
            async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
                Ok(())
            }
            async fn health(&self) -> RuntimeHealth {
                RuntimeHealth::healthy()
            }
            fn capabilities(&self) -> RuntimeCapabilities {
                RuntimeCapabilities::default()
            }
        }
        let service = WorkerService::new(
            Arc::new(TestRuntime),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            Uuid::now_v7(),
            1,
        )
        .with_guest_profile(WorkerGuestProfile {
            artifact_version: "1".into(),
            base: "debian-13".into(),
            profile: "coding".into(),
            capabilities: vec!["git".into()],
            git_version: Some("2.47.0".into()),
            guest_agent_version: "0.1.0".into(),
            guest_protocol_version: aiec_core::protocol::PROTOCOL_VERSION,
        });
        let response = service
            .router()
            .oneshot(
                axum::http::Request::get("/health")
                    .header("authorization", "Bearer token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status: WorkerStatus = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let profile = status.guest_profile.expect("guest profile is reported");
        assert_eq!(profile.profile, "coding");
        assert_eq!(profile.capabilities, vec!["git".to_owned()]);
        assert_eq!(profile.git_version.as_deref(), Some("2.47.0"));
    }

    #[tokio::test]
    async fn secure_client_rejects_plaintext_worker_endpoint() {
        let client = HttpWorkerClient::new_secure("token").unwrap();
        let result = client
            .invoke(
                "http://worker.invalid",
                WorkerRequest {
                    request_id: Uuid::now_v7(),
                    lease_id: stable_lease_id(),
                    lease_generation: 1,
                    operation: WorkerOperation::Stop {
                        sandbox: sandbox(None),
                    },
                },
            )
            .await;
        assert!(
            matches!(result, Err(WorkerClientError::Unavailable(message)) if message.contains("HTTPS"))
        );
    }

    /// Worker that records whatever a recovery imports, so a capture and the
    /// import that adopts it can be driven over the real worker wire.
    struct ArchiveRuntime {
        imported: Arc<parking_lot::Mutex<Vec<Vec<u8>>>>,
    }

    #[async_trait]
    impl SandboxRuntime for ArchiveRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
            Ok(())
        }
        async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            _: FileChunkRequest,
        ) -> Result<FileChunk, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
            Ok(Vec::new())
        }
        async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
            Ok(())
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), CoreError> {
            Ok(())
        }
        async fn import_workspace_archive(
            &self,
            _: &Sandbox,
            archive: &[u8],
        ) -> Result<(), CoreError> {
            self.imported.lock().push(archive.to_vec());
            Ok(())
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn health(&self) -> RuntimeHealth {
            RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::default()
        }
    }

    async fn worker_post(service: WorkerService, request: WorkerRequest) -> serde_json::Value {
        let response = service
            .router()
            .oneshot(
                axum::http::Request::post("/v1/operations")
                    .header("authorization", "Bearer token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_string(&request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    /// An import rewrites a sandbox's whole workspace, so it is fenced like any
    /// other state-changing operation: a superseded generation must not be able
    /// to overwrite the workspace of the worker that owns the sandbox now.
    #[tokio::test]
    async fn a_stale_generation_cannot_import_a_workspace() {
        use base64::Engine;
        let owner = Uuid::now_v7();
        let sandbox = sandbox(Some(owner));
        let imported = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let service = WorkerService::new(
            Arc::new(ArchiveRuntime {
                imported: imported.clone(),
            }),
            RuntimeKind::Docker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(5),
        }))
        // The worker already adopted this sandbox at generation 5, which is
        // what a completed recovery leaves behind in the durable ledger.
        .with_generation(sandbox.id, 5);

        let response = worker_post(
            service,
            WorkerRequest {
                request_id: Uuid::now_v7(),
                lease_id: Uuid::now_v7(),
                lease_generation: 4,
                operation: WorkerOperation::ImportWorkspaceArchive {
                    sandbox,
                    archive_base64: base64::engine::general_purpose::STANDARD.encode(b"stale"),
                },
            },
        )
        .await;
        assert_eq!(response["result"]["Err"]["code"], "conflict");
        assert!(imported.lock().is_empty());
    }

    #[test]
    fn an_oversized_workspace_import_is_rejected_before_decoding() {
        let oversized = "A".repeat(MAX_WORKER_TRANSFER + 1);
        assert!(matches!(
            decode_workspace_archive(&oversized),
            Err(CoreError::LimitExceeded(_))
        ));
        assert!(decode_workspace_archive("not base64!").is_err());
    }

    /// Runtime double that holds a create open until the test releases it, and
    /// records whether a second lifecycle operation reached it in the meantime.
    ///
    /// The overlap flag is the assertion, not the ordering: a destroy that ran
    /// while the create was in flight is recorded from inside the destroy
    /// itself, so the test cannot pass by the destroy never having been
    /// scheduled.
    struct LifecycleRuntime {
        creating: AtomicBool,
        overlapped: AtomicBool,
        entered_create: tokio::sync::Notify,
        release_create: tokio::sync::Semaphore,
        order: parking_lot::Mutex<Vec<&'static str>>,
        creates: Arc<AtomicUsize>,
        destroys: Arc<AtomicUsize>,
    }

    impl LifecycleRuntime {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                creating: AtomicBool::new(false),
                overlapped: AtomicBool::new(false),
                entered_create: tokio::sync::Notify::new(),
                release_create: tokio::sync::Semaphore::new(0),
                order: parking_lot::Mutex::new(Vec::new()),
                creates: Arc::new(AtomicUsize::new(0)),
                destroys: Arc::new(AtomicUsize::new(0)),
            })
        }

        /// Lets a held create finish.
        fn release(&self) {
            self.release_create.add_permits(1);
        }
    }

    #[async_trait]
    impl SandboxRuntime for LifecycleRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
            self.creates.fetch_add(1, Ordering::Relaxed);
            self.creating.store(true, Ordering::SeqCst);
            self.entered_create.notify_one();
            let _ = self.release_create.acquire().await;
            self.creating.store(false, Ordering::SeqCst);
            self.order.lock().push("create");
            Ok(())
        }
        async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
            self.destroys.fetch_add(1, Ordering::SeqCst);
            if self.creating.load(Ordering::SeqCst) {
                self.overlapped.store(true, Ordering::SeqCst);
            }
            self.order.lock().push("destroy");
            Ok(())
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
            Ok(ExecResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: 0,
                timed_out: false,
            })
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
            Ok(())
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            _: FileChunkRequest,
        ) -> Result<FileChunk, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
            Ok(FileContent {
                path: "/workspace".into(),
                content_base64: String::new(),
            })
        }
        async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
            Ok(Vec::new())
        }
        async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
            Ok(())
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), CoreError> {
            Ok(())
        }
        async fn import_workspace_archive(&self, _: &Sandbox, _: &[u8]) -> Result<(), CoreError> {
            Ok(())
        }
        async fn health(&self) -> RuntimeHealth {
            RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::default()
        }
    }

    fn lifecycle_service(runtime: Arc<LifecycleRuntime>, owner: Uuid) -> WorkerService {
        WorkerService::new(
            runtime,
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(1),
        }))
    }

    fn lifecycle_request(operation: WorkerOperation) -> WorkerRequest {
        WorkerRequest {
            request_id: Uuid::now_v7(),
            lease_id: stable_lease_id(),
            lease_generation: 1,
            operation,
        }
    }

    /// The race a completed destroy used to lose: it reported the sandbox gone
    /// while a create for the same sandbox was still materializing into the
    /// directory it had just removed, and the create's copy was what survived.
    #[tokio::test]
    async fn a_destroy_does_not_reach_the_runtime_while_a_create_of_that_sandbox_is_in_flight() {
        let owner = Uuid::now_v7();
        let target = sandbox(Some(owner));
        let runtime = LifecycleRuntime::new();
        let service = lifecycle_service(runtime.clone(), owner);

        let create = tokio::spawn(post_operation(
            service.clone(),
            lifecycle_request(WorkerOperation::Create {
                sandbox: target.clone(),
            }),
        ));
        // The create is inside the runtime now, holding the sandbox.
        runtime.entered_create.notified().await;
        let destroy = tokio::spawn(post_operation(
            service.clone(),
            lifecycle_request(WorkerOperation::Destroy {
                sandbox: target.clone(),
            }),
        ));
        // The create is still held, so anything the double records before it is
        // released is an operation that ran inside a create it should have been
        // behind. Yielding rather than sleeping: the destroy either makes
        // progress on one of these turns or it is queued, and it is queued.
        for _ in 0..256 {
            if runtime.destroys.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            runtime.destroys.load(Ordering::SeqCst),
            0,
            "the destroy reached the runtime while a create was still in flight"
        );

        runtime.release();
        let created = create.await.unwrap();
        let destroyed = destroy.await.unwrap();
        assert!(created["result"]["Ok"].is_object(), "{created}");
        assert!(destroyed["result"]["Ok"].is_object(), "{destroyed}");
        // Both ran, and in the only order that leaves nothing behind.
        assert!(!runtime.overlapped.load(Ordering::SeqCst));
        assert_eq!(*runtime.order.lock(), ["create", "destroy"]);
        assert_eq!(runtime.creates.load(Ordering::Relaxed), 1);
    }

    /// Exec takes no lifecycle gate, so a destroy is never queued behind the
    /// command it exists to interrupt. The gate is held here by the test itself
    /// rather than by a concurrent request, so there is nothing to schedule.
    #[tokio::test]
    async fn exec_runs_while_a_lifecycle_operation_holds_the_same_sandbox() {
        let owner = Uuid::now_v7();
        let target = sandbox(Some(owner));
        let execs = Arc::new(AtomicUsize::new(0));
        let service = WorkerService::new(
            Arc::new(CountingRuntime {
                execs: execs.clone(),
            }),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(1),
        }));
        let held = service.lifecycle.clone().enter(target.id).await.unwrap();
        let response = post_operation(service.clone(), exec_request(1, &target)).await;
        assert!(response["result"]["Ok"].is_object(), "{response}");
        assert_eq!(execs.load(Ordering::Relaxed), 1);
        drop(held);
    }

    /// Ownership the worker verifier is the only authority, so an answer the
    /// test can change.
    struct SwappableOwnership {
        answer: parking_lot::Mutex<FakeOwnership>,
        verified: Arc<AtomicUsize>,
        first: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl OwnershipVerifier for SwappableOwnership {
        async fn verify(&self, _: Uuid) -> Result<OwnershipCheck, CoreError> {
            let answer = self.answer.lock();
            if self.verified.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first.notify_one();
            }
            match &*answer {
                FakeOwnership::Owned(generation) => Ok(OwnershipCheck::Owned {
                    generation: *generation,
                    lease_id: Uuid::from_u128(0x5eed_5eed_5eed_5eed_5eed_5eed_5eed_5eed),
                }),
                FakeOwnership::Reassigned(generation) => Ok(OwnershipCheck::Owned {
                    generation: *generation,
                    lease_id: Uuid::now_v7(),
                }),
                FakeOwnership::Rejected(message) => Ok(OwnershipCheck::Rejected((*message).into())),
                FakeOwnership::Unavailable => {
                    Err(CoreError::Unavailable("control plane unreachable".into()))
                }
            }
        }
    }

    /// A request that waited for the sandbox is authorized again, because the
    /// wait is a window in which the control plane can hand the sandbox to
    /// somebody else. The create that is queued here is refused on the strength
    /// of the second answer, not the first.
    #[tokio::test]
    async fn a_queued_lifecycle_operation_is_authorized_again_before_it_runs() {
        let owner = Uuid::now_v7();
        let target = sandbox(Some(owner));
        let runtime = LifecycleRuntime::new();
        let verified = Arc::new(AtomicUsize::new(0));
        let first = Arc::new(tokio::sync::Notify::new());
        let verifier = Arc::new(SwappableOwnership {
            answer: parking_lot::Mutex::new(FakeOwnership::Owned(1)),
            verified: verified.clone(),
            first: first.clone(),
        });
        let service = WorkerService::new(
            runtime.clone(),
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(verifier.clone());
        let held = service.lifecycle.clone().enter(target.id).await.unwrap();
        let request = tokio::spawn(post_operation(
            service,
            lifecycle_request(WorkerOperation::Create {
                sandbox: target.clone(),
            }),
        ));
        // The request is authorized once and is now queued on the gate this
        // test holds.
        first.notified().await;
        *verifier.answer.lock() = FakeOwnership::Rejected("sandbox is owned by another worker");
        drop(held);

        let response = request.await.unwrap();
        assert_eq!(response["result"]["Err"]["code"], "conflict");
        assert_eq!(
            response["result"]["Err"]["message"],
            "sandbox is owned by another worker"
        );
        assert_eq!(runtime.creates.load(Ordering::Relaxed), 0);
        // Twice: once on arrival, once after the wait. Once would mean the
        // answer it queued behind was the one it ran on.
        assert_eq!(verified.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn boot_backpressure_releases_capacity_when_its_request_is_cancelled() {
        let owner = Uuid::now_v7();
        let runtime = LifecycleRuntime::new();
        let service = lifecycle_service(runtime.clone(), owner);
        let first = tokio::spawn(post_operation(
            service.clone(),
            lifecycle_request(WorkerOperation::Create {
                sandbox: sandbox(Some(owner)),
            }),
        ));
        runtime.entered_create.notified().await;
        let refused = post_operation(
            service.clone(),
            lifecycle_request(WorkerOperation::Create {
                sandbox: sandbox(Some(owner)),
            }),
        )
        .await;
        assert_eq!(refused["result"]["Err"]["code"], "runtime_unavailable");
        assert_eq!(runtime.creates.load(Ordering::SeqCst), 1);
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert_eq!(service.in_flight.load(Ordering::Relaxed), 0);

        let replacement = tokio::spawn(post_operation(
            service.clone(),
            lifecycle_request(WorkerOperation::Create {
                sandbox: sandbox(Some(owner)),
            }),
        ));
        runtime.entered_create.notified().await;
        runtime.release();
        let result = replacement.await.unwrap();
        assert!(result["result"]["Ok"].is_object());
        assert_eq!(runtime.creates.load(Ordering::SeqCst), 2);
        assert_eq!(service.in_flight.load(Ordering::Relaxed), 0);
    }

    /// A request whose client disconnected is dropped between claiming its
    /// response slot and storing anything in it, so its entry holds an empty
    /// slot forever. The entry and byte bounds are only real if the eviction
    /// pass can give that entry back, and it can only be a candidate if it was
    /// enrolled when it was claimed rather than when it was finished.
    #[tokio::test]
    async fn abandoned_response_entries_are_reclaimable_and_stay_within_the_bound() {
        let mut cache = ResponseCache::default();
        for _ in 0..MAX_WORKER_RESPONSE_CACHE_ENTRIES + 16 {
            // Claimed, then abandoned: the slot exists and nothing ever fills
            // it, which is exactly the state a dropped request leaves behind.
            drop(cache.entry(Uuid::now_v7()));
        }
        // One completed response tips the cache over its entry bound, which is
        // what starts the eviction pass over the abandoned entries.
        cache
            .complete(
                Uuid::now_v7(),
                WorkerResponse {
                    request_id: Uuid::now_v7(),
                    result: Ok(WorkerValue::Unit),
                },
            )
            .await;
        assert!(
            cache.len() <= MAX_WORKER_RESPONSE_CACHE_ENTRIES,
            "an abandoned entry is not reclaimable: {} entries against a bound of {}",
            cache.len(),
            MAX_WORKER_RESPONSE_CACHE_ENTRIES
        );
    }

    /// Serves a worker chunk read out of a real workspace file, so the group a
    /// worker publishes is made of the same bytes a backend would return and a
    /// file that changes mid-group is a real change, not a reported one.
    ///
    /// `replacement`, when set, replaces the file's inode with same-length
    /// different bytes before the first read that starts past offset zero:
    /// the window a guest writer has between two completed chunk reads.
    struct WorkspaceFileRuntime {
        root: PathBuf,
        replacement: Option<Vec<u8>>,
        swapped: AtomicBool,
    }
    impl WorkspaceFileRuntime {
        fn new(root: &std::path::Path, replacement: Option<Vec<u8>>) -> Self {
            Self {
                root: root.to_path_buf(),
                replacement,
                swapped: AtomicBool::new(false),
            }
        }
    }
    #[async_trait]
    impl SandboxRuntime for WorkspaceFileRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            request: FileChunkRequest,
        ) -> Result<FileChunk, CoreError> {
            if request.offset > 0
                && !self.swapped.load(Ordering::SeqCst)
                && let Some(replacement) = &self.replacement
            {
                self.swapped.store(true, Ordering::SeqCst);
                let staged = self.root.join("staged");
                std::fs::write(&staged, replacement).unwrap();
                std::fs::rename(&staged, self.root.join("file")).unwrap();
            }
            request.read_workspace(&self.root)
        }
        async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn import_workspace_archive(&self, _: &Sandbox, _: &[u8]) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn health(&self) -> RuntimeHealth {
            RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::default()
        }
    }

    /// A runtime that overrides the group read, which is exactly the case the
    /// worker cannot delegate: it bypasses the default implementation's
    /// pinning, so the worker's own check of the group's shared metadata is the
    /// only thing between two files' worth of chunks and one published
    /// artifact. Both groups below pass each chunk's own validation - the
    /// caller's `expected_version` is `None` on a first burst - and disagree
    /// with each other in the one field the worker publishes as group-wide.
    #[derive(Clone, Copy)]
    enum MixedGroup {
        Versions,
        Sizes,
    }
    struct MixedGroupRuntime {
        mixed: MixedGroup,
    }
    #[async_trait]
    impl SandboxRuntime for MixedGroupRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn start(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            _: FileChunkRequest,
        ) -> Result<FileChunk, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn get_file_chunks(
            &self,
            _: &Sandbox,
            request: FileChunkRequest,
            _: usize,
        ) -> Result<Vec<FileChunk>, CoreError> {
            let total = (FILE_CHUNK_BYTES * 2) as u64;
            let first = FileChunk {
                bytes: bytes::Bytes::from(vec![b'a'; FILE_CHUNK_BYTES]),
                size_bytes: total,
                version: "first".into(),
                eof: false,
            };
            let second = match self.mixed {
                MixedGroup::Versions => FileChunk {
                    bytes: bytes::Bytes::from(vec![b'b'; FILE_CHUNK_BYTES]),
                    size_bytes: total,
                    version: "second".into(),
                    eof: true,
                },
                MixedGroup::Sizes => FileChunk {
                    bytes: bytes::Bytes::from(vec![b'b'; FILE_CHUNK_BYTES]),
                    size_bytes: FILE_CHUNK_BYTES as u64,
                    version: "first".into(),
                    eof: true,
                },
            };
            request.validate()?;
            Ok(vec![first, second])
        }
        async fn list_files(&self, _: &Sandbox, _: &str) -> Result<Vec<FileEntry>, CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn delete_file(&self, _: &Sandbox, _: DeleteFileRequest) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn import_workspace_archive(&self, _: &Sandbox, _: &[u8]) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
            Ok(())
        }
        async fn health(&self) -> RuntimeHealth {
            RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::default()
        }
    }

    fn chunk_authorization(target: &Sandbox) -> WorkerRequest {
        WorkerRequest {
            request_id: Uuid::now_v7(),
            lease_id: stable_lease_id(),
            lease_generation: 2,
            operation: WorkerOperation::GetFile {
                sandbox: target.clone(),
                path: "/workspace/file".into(),
            },
        }
    }

    fn chunk_request(expected_version: Option<String>) -> FileChunkRequest {
        FileChunkRequest {
            path: "/workspace/file".into(),
            offset: 0,
            length: FILE_CHUNK_BYTES,
            expected_version,
        }
    }

    /// Serves a worker over loopback and reads one group through the HTTP
    /// client, so what the control plane would receive is what is asserted.
    async fn group_over_http(
        runtime: Arc<dyn SandboxRuntime>,
        owner: Uuid,
        target: &Sandbox,
        request: FileChunkRequest,
        count: usize,
    ) -> Result<Vec<FileChunk>, CoreError> {
        let service = WorkerService::new(
            runtime,
            RuntimeKind::Firecracker,
            RuntimeCapabilities::default(),
            None,
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(2),
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, service.router()).await.unwrap();
        });
        let read = HttpWorkerClient::new("token")
            .unwrap()
            .get_file_chunks(&endpoint, chunk_authorization(target), request, count)
            .await;
        server.abort();
        read
    }

    /// The first burst of an artifact read arrives with no version to check
    /// against, so a worker that publishes a group it never checked can hand
    /// the collector the first half of one file and the second half of another
    /// under a checksum that authenticates the splice. A same-size replacement
    /// between two completed chunks is enough.
    #[tokio::test]
    async fn a_worker_group_read_across_a_replacement_is_refused() {
        let root = std::env::temp_dir().join(format!("aiec-worker-chunks-{}", Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let total = FILE_CHUNK_BYTES * 2;
        std::fs::write(root.join("file"), vec![b'a'; total]).unwrap();
        let owner = Uuid::now_v7();
        let target = sandbox(Some(owner));
        let read = group_over_http(
            Arc::new(WorkspaceFileRuntime::new(&root, Some(vec![b'b'; total]))),
            owner,
            &target,
            chunk_request(None),
            4,
        )
        .await;
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            matches!(&read, Err(CoreError::Conflict(_))),
            "a worker must not publish a group that spans a replacement: {read:?}"
        );
    }

    /// A runtime that serves a group itself skips the default implementation
    /// that pins the first chunk, so the worker has to reject a group whose
    /// chunks disagree about which file they came from on its own.
    #[tokio::test]
    async fn a_worker_refuses_a_group_whose_chunks_disagree() {
        for mixed in [MixedGroup::Versions, MixedGroup::Sizes] {
            let owner = Uuid::now_v7();
            let target = sandbox(Some(owner));
            let response = WorkerService::new(
                Arc::new(MixedGroupRuntime { mixed }),
                RuntimeKind::Firecracker,
                RuntimeCapabilities::default(),
                None,
                "token",
                owner,
                1,
            )
            .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
                answer: FakeOwnership::Owned(2),
            }))
            .router()
            .oneshot(
                axum::http::Request::post("/v1/files/chunk")
                    .header("authorization", "Bearer token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&WorkerChunkRequest {
                            authorization: chunk_authorization(&target),
                            request: chunk_request(None),
                            chunks: 2,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
            assert_ne!(
                response.headers()["content-type"],
                "application/octet-stream",
                "a group that disagrees with itself must not be encoded"
            );
            let body: WorkerResponse = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body.result.unwrap_err().code, "conflict");
        }
    }

    /// The refusals above must cost a real group nothing: an unchanged file of
    /// several chunks is served whole, under one version, with the bytes the
    /// file holds.
    #[tokio::test]
    async fn a_worker_group_read_of_an_unchanged_file_is_served_whole() {
        let root = std::env::temp_dir().join(format!("aiec-worker-chunks-{}", Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let total = FILE_CHUNK_BYTES * 3;
        std::fs::write(root.join("file"), vec![b'x'; total]).unwrap();
        let owner = Uuid::now_v7();
        let target = sandbox(Some(owner));
        let read = group_over_http(
            Arc::new(WorkspaceFileRuntime::new(&root, None)),
            owner,
            &target,
            chunk_request(None),
            8,
        )
        .await
        .expect("an unchanged file must be served");
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(read.len(), 3);
        assert!(read.last().unwrap().eof);
        assert!(read[..2].iter().all(|chunk| !chunk.eof));
        assert!(
            read.iter()
                .all(|chunk| chunk.size_bytes == total as u64 && chunk.version == read[0].version)
        );
        let served: Vec<u8> = read.iter().flat_map(|chunk| chunk.bytes.to_vec()).collect();
        assert_eq!(served, vec![b'x'; total]);
    }
}
