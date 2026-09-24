use agentforge_core::{
    runtime::{RuntimeCapabilities, RuntimeHealth, SandboxRuntime},
    snapshots::{SnapshotCapabilities, SnapshotMetadata, SnapshotProvider, SnapshotRequest},
};
use agentforge_core::*;
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
const MAX_WORKER_RESPONSE: usize = 2 * 1024 * 1024;
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
    pub operation: WorkerOperation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub request_id: Uuid,
    pub result: Result<WorkerValue, WorkerError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub node_id: Uuid,
    pub healthy: bool,
    pub runtime: RuntimeKind,
    pub in_flight: usize,
    pub capacity: u32,
    pub sandbox_count: usize,
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
}

impl WorkerRuntime {
    pub fn new(
        client: Arc<dyn WorkerClient>,
        scheduler: Arc<dyn agentforge_core::scheduler::Scheduler>,
    ) -> Self {
        Self { client, scheduler }
    }

    async fn call(
        &self,
        sandbox: &Sandbox,
        operation: WorkerOperation,
    ) -> Result<WorkerValue, CoreError> {
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

    async fn exec(
        &self,
        sandbox: &Sandbox,
        request: ExecRequest,
    ) -> Result<ExecResult, CoreError> {
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

    async fn put_file(
        &self,
        sandbox: &Sandbox,
        request: PutFileRequest,
    ) -> Result<(), CoreError> {
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

    async fn list_files(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<Vec<FileEntry>, CoreError> {
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
            _ => Err(CoreError::Conflict("invalid worker listing response".into())),
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

    async fn health(&self) -> RuntimeHealth {
        RuntimeHealth::healthy()
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            vm_snapshot: true,
            memory_resume: true,
            network_policy: true,
            pause: true,
            workspace_snapshot: true,
            vsock: true,
            ..RuntimeCapabilities::default()
        }
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
            _ => Err(CoreError::Conflict("invalid worker snapshot response".into())),
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
        "runtime_unavailable" => CoreError::Unavailable(error.message),
        "unsupported" => CoreError::Unsupported(error.message),
        "snapshot_failed" | "conflict" => CoreError::Conflict(error.message),
        "guest_protocol" | "firecracker_api" | "internal" => {
            CoreError::Backend(error.message)
        }
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
}

impl HttpWorkerClient {
    pub fn new(token: impl Into<String>) -> Result<Self, WorkerClientError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|error| WorkerClientError::Transport(error.to_string()))?;
        Ok(Self {
            client,
            token: Arc::from(token.into().as_str()),
        })
    }

    pub fn from_env() -> Result<Self, WorkerClientError> {
        let token = std::env::var("AGENTFORGE_WORKER_TOKEN").map_err(|_| {
            WorkerClientError::Unavailable("AGENTFORGE_WORKER_TOKEN is required".into())
        })?;
        Self::new(token)
    }
}

#[async_trait]
impl WorkerClient for HttpWorkerClient {
    async fn invoke(
        &self,
        endpoint: &str,
        request: WorkerRequest,
    ) -> Result<WorkerResponse, WorkerClientError> {
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
            .is_some_and(|length| length > MAX_WORKER_RESPONSE as u64)
        {
            return Err(WorkerClientError::Response(
                "worker response exceeds 2 MiB".into(),
            ));
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
    runtime_kind: RuntimeKind,
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
        snapshots: Option<Arc<dyn SnapshotProvider>>,
        token: impl Into<String>,
        node_id: Uuid,
        capacity: u32,
    ) -> Self {
        Self {
            runtime,
            snapshots,
            runtime_kind,
            node_id,
            capacity,
            token: Arc::from(token.into().as_str()),
            cache: Arc::new(Mutex::new(ResponseCache::default())),
            in_flight: Arc::new(AtomicUsize::new(0)),
            sandboxes: Arc::new(Mutex::new(std::collections::HashSet::new())),
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
            .layer(axum::middleware::from_fn_with_state(state, authenticate))
            .with_state(self)
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
        };
        result.map_err(WorkerError::from_runtime)
    }
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
        sandbox_count: state.sandboxes.lock().await.len(),
        in_flight: state.in_flight.load(Ordering::Relaxed),
        capacity: state.capacity,
    })
}

async fn operation(
    State(state): State<WorkerService>,
    Json(request): Json<WorkerRequest>,
) -> Response {
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
