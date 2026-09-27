use agentforge_core::*;
use agentforge_core::{
    runtime::{RuntimeCapabilities, RuntimeHealth, SandboxRuntime},
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
use tokio::sync::Mutex;
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
    agentforge_core::snapshots::MAX_WORKSPACE_ARCHIVE_BYTES.div_ceil(3) * 4 + 64 * 1024;
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
            if self
                .entries
                .get(&candidate)
                .is_some_and(|entry| entry.complete)
            {
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

    fn remove(&mut self, request_id: Uuid) {
        if let Some(entry) = self.entries.remove(&request_id) {
            self.encoded_bytes = self.encoded_bytes.saturating_sub(entry.encoded_size);
        }
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
    Snapshot(agentforge_core::snapshots::CapturedSnapshot),
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
    #[serde(default)]
    pub lease_generation: i64,
    pub operation: WorkerOperation,
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
    Owned { generation: i64 },
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
/// `AGENTFORGE_TLS_CA_CERT` is honoured everywhere; a client that skipped it
/// would fail the TLS handshake against a private-CA control plane and, on a
/// fail-closed path, block every sandbox operation.
pub(crate) fn control_plane_http_client(
    timeout: Duration,
) -> Result<reqwest::Client, WorkerClientError> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(timeout);
    if let Ok(path) = std::env::var("AGENTFORGE_TLS_CA_CERT") {
        let pem = std::fs::read(path).map_err(|error| {
            WorkerClientError::Transport(format!("read AGENTFORGE_TLS_CA_CERT: {error}"))
        })?;
        let certificate = reqwest::Certificate::from_pem(&pem).map_err(|error| {
            WorkerClientError::Transport(format!("parse AGENTFORGE_TLS_CA_CERT: {error}"))
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
    ) -> Result<(), std::io::Error> {
        if self
            .records
            .get(&sandbox_id)
            .is_some_and(|record| record.generation >= generation)
        {
            return Ok(());
        }
        self.records.insert(
            sandbox_id,
            LearnedGeneration {
                sandbox_id,
                node_id,
                generation,
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

#[derive(Clone)]
pub struct WorkerRuntime {
    client: Arc<dyn WorkerClient>,
    scheduler: Arc<dyn agentforge_core::scheduler::Scheduler>,
    capabilities: RuntimeCapabilities,
}

impl WorkerRuntime {
    pub fn new(
        client: Arc<dyn WorkerClient>,
        scheduler: Arc<dyn agentforge_core::scheduler::Scheduler>,
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
        let lease_generation = self
            .scheduler
            .lease_generation(sandbox.tenant_id, sandbox.id)
            .await?;
        let endpoint = self
            .scheduler
            .worker_endpoint(sandbox.tenant_id, sandbox.id)
            .await?;
        let response = self
            .client
            .invoke(
                &endpoint,
                WorkerRequest {
                    request_id: new_id(),
                    lease_generation,
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
        if archive.len() > agentforge_core::snapshots::MAX_WORKSPACE_ARCHIVE_BYTES {
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
    ) -> Result<agentforge_core::snapshots::CapturedSnapshot, CoreError> {
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
        let token = std::env::var("AGENTFORGE_WORKER_TOKEN").map_err(|_| {
            WorkerClientError::Unavailable("AGENTFORGE_WORKER_TOKEN is required".into())
        })?;
        Self::new_secure(token)
    }
}

#[async_trait]
impl WorkerClient for HttpWorkerClient {
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
        let _ = ledger.record(sandbox_id, self.node_id, generation);
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
    async fn learn_generation(&self, sandbox_id: Uuid, generation: i64) {
        if let Err(error) =
            self.generations
                .lock()
                .await
                .record(sandbox_id, self.node_id, generation)
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
/// Rejects a sandbox this worker does not own, a request whose generation is
/// below the durable floor learned from the control plane, and a request whose
/// generation the control plane has never issued. Verification failures are
/// retryable: nothing executes until ownership is established.
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
    let learned = state.generations.lock().await.generation(sandbox_id);
    if learned.is_some_and(|learned| request.lease_generation < learned) {
        return Err(Box::new(rejected(
            request_id,
            "conflict",
            "stale sandbox lease generation",
        )));
    }
    match state.verify_ownership(sandbox_id).await {
        Ok(OwnershipCheck::Rejected(message)) => {
            Err(Box::new(rejected(request_id, "conflict", message)))
        }
        Ok(OwnershipCheck::Owned { generation }) => {
            if request.lease_generation > generation {
                return Err(Box::new(rejected(
                    request_id,
                    "conflict",
                    "sandbox lease generation is ahead of the control plane",
                )));
            }
            state.learn_generation(sandbox_id, generation).await;
            Ok(())
        }
        Err(error) => Err(Box::new(rejected(
            request_id,
            runtime_worker_code(&error),
            error_message(&error),
        ))),
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
        | CoreError::Backend(message)
        | CoreError::InvalidRequest(message)
        | CoreError::LimitExceeded(message)
        | CoreError::QuotaExceeded(message)
        | CoreError::Unsupported(message) => message.clone(),
        CoreError::Io(error) => error.to_string(),
    }
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
    let response_slot = state.cache.lock().await.entry(request.request_id);
    let mut response_slot = response_slot.lock().await;
    if let Some(response) = response_slot.clone() {
        return (StatusCode::OK, Json(response)).into_response();
    }
    state.in_flight.fetch_add(1, Ordering::Relaxed);
    let sandbox_event = match &request.operation {
        WorkerOperation::Create { sandbox } => Some((sandbox.id, true)),
        WorkerOperation::Destroy { sandbox } => Some((sandbox.id, false)),
        _ => None,
    };
    let result = state.execute(request.operation).await;
    state.in_flight.fetch_sub(1, Ordering::Relaxed);
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
    use std::collections::BTreeMap;
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
                    isolation: agentforge_core::runtime::RuntimeIsolation::Container,
                    exec: true,
                    files: true,
                    streaming: false,
                    ..RuntimeCapabilities::default()
                }
            }
        }
        let capabilities = RuntimeCapabilities {
            isolation: agentforge_core::runtime::RuntimeIsolation::Container,
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

    enum FakeOwnership {
        Owned(i64),
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
                FakeOwnership::Owned(generation) => Ok(OwnershipCheck::Owned { generation }),
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

    #[tokio::test]
    async fn worker_service_keeps_learned_generation_across_restart() {
        let state_dir =
            std::env::temp_dir().join(format!("agentforge-worker-fence-{}", Uuid::now_v7()));
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
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(9),
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

    struct ArchiveSnapshots {
        archive: Vec<u8>,
    }

    #[async_trait]
    impl SnapshotProvider for ArchiveSnapshots {
        fn capabilities(&self) -> SnapshotCapabilities {
            SnapshotCapabilities {
                workspace: true,
                ..Default::default()
            }
        }
        async fn capture(
            &self,
            _: &Sandbox,
            request: &SnapshotRequest,
        ) -> Result<agentforge_core::snapshots::CapturedSnapshot, CoreError> {
            Ok(agentforge_core::snapshots::CapturedSnapshot::from_archive(
                Uuid::now_v7(),
                request.kind,
                request.object_key.clone(),
                self.archive.clone(),
            ))
        }
        async fn restore(&self, _: &Sandbox, _: &SnapshotMetadata) -> Result<(), CoreError> {
            Err(CoreError::Backend("unused".into()))
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

    /// The whole production handoff over the worker wire: the control plane
    /// captures a workspace, the bytes come back with the capture, and a later
    /// import delivers those exact bytes to the adopting worker's runtime.
    #[tokio::test]
    async fn a_workspace_capture_crosses_the_wire_and_is_imported_back() {
        use base64::Engine;
        let archive = vec![7_u8; 4096];
        let owner = Uuid::now_v7();
        let sandbox = sandbox(Some(owner));
        let imported = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let service = WorkerService::new(
            Arc::new(ArchiveRuntime {
                imported: imported.clone(),
            }),
            RuntimeKind::Docker,
            RuntimeCapabilities::default(),
            Some(Arc::new(ArchiveSnapshots {
                archive: archive.clone(),
            })),
            "token",
            owner,
            1,
        )
        .with_ownership_verifier(Arc::new(FakeOwnershipVerifier {
            answer: FakeOwnership::Owned(4),
        }));

        let captured = worker_post(
            service.clone(),
            WorkerRequest {
                request_id: Uuid::now_v7(),
                lease_generation: 4,
                operation: WorkerOperation::Snapshot {
                    sandbox: sandbox.clone(),
                    request: SnapshotRequest {
                        kind: agentforge_core::snapshots::SnapshotKind::Workspace,
                        object_key: "wire-1".into(),
                    },
                },
            },
        )
        .await;
        let value: agentforge_core::snapshots::CapturedSnapshot =
            serde_json::from_value(captured["result"]["Ok"]["value"].clone()).unwrap();
        assert_eq!(value.archive, archive);

        let imported_response = worker_post(
            service.clone(),
            WorkerRequest {
                request_id: Uuid::now_v7(),
                lease_generation: 4,
                operation: WorkerOperation::ImportWorkspaceArchive {
                    sandbox,
                    archive_base64: base64::engine::general_purpose::STANDARD
                        .encode(&value.archive),
                },
            },
        )
        .await;
        assert_eq!(imported_response["result"]["Ok"]["kind"], "unit");
        assert_eq!(imported.lock().as_slice(), &[archive]);
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
}
