use agentforge_core::*;
use agentforge_runtime::{RuntimeError, SandboxRuntime};
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
use std::{collections::HashMap, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

pub const WORKER_TOKEN_HEADER: &str = "authorization";
const MAX_WORKER_RESPONSE: usize = 2 * 1024 * 1024;

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
        object_key: String,
    },
    Restore {
        sandbox: Sandbox,
        object_key: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum WorkerValue {
    Unit,
    Exec(ExecResult),
    File(FileContent),
    Files(Vec<FileEntry>),
    Size(u64),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerError {
    pub code: String,
    pub message: String,
}

impl WorkerError {
    fn from_runtime(error: RuntimeError) -> Self {
        let (code, message) = match error {
            RuntimeError::Core(CoreError::InvalidRequest(message)) => ("invalid_request", message),
            RuntimeError::Core(CoreError::Forbidden(message)) => ("forbidden", message),
            RuntimeError::Core(CoreError::NotFound(message)) => ("not_found", message),
            RuntimeError::Core(CoreError::Conflict(message)) => ("conflict", message),
            RuntimeError::Core(CoreError::LimitExceeded(message)) => ("limit_exceeded", message),
            RuntimeError::Unavailable(message) => ("runtime_unavailable", message),
            RuntimeError::Archive(message) => ("snapshot_failed", message),
            RuntimeError::Io(error) => ("internal", error.to_string()),
            RuntimeError::Protocol(error) => ("guest_protocol", error.to_string()),
            RuntimeError::FirecrackerApi(message) => ("firecracker_api", message),
            RuntimeError::Json(error) => ("internal", error.to_string()),
            RuntimeError::Core(CoreError::Io(error)) => ("internal", error.to_string()),
        };
        Self {
            code: code.into(),
            message,
        }
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

#[derive(Clone, Debug)]
pub struct ScheduledSandbox {
    pub sandbox: Sandbox,
    pub worker_endpoint: String,
    pub lease_id: Uuid,
}

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("scheduler unavailable: {0}")]
    Unavailable(String),
    #[error("scheduler rejected request: {0}")]
    Rejected(String),
}

#[async_trait]
pub trait Scheduler: Send + Sync {
    async fn schedule(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        sandbox: Sandbox,
    ) -> Result<ScheduledSandbox, SchedulerError>;
    async fn worker_endpoint(
        &self,
        tenant_id: Uuid,
        sandbox_id: Uuid,
    ) -> Result<String, SchedulerError>;
    async fn release(&self, tenant_id: Uuid, sandbox_id: Uuid) -> Result<(), SchedulerError>;
}

type LeaseCacheKey = (Uuid, Uuid);
type LeaseCacheValue = (Uuid, Uuid, i64);

pub struct StorageScheduler {
    repository: Arc<dyn agentforge_storage::Repository>,
    scheduler: Arc<dyn agentforge_storage::Scheduler>,
    lease_ttl_seconds: u64,
    leases: Arc<Mutex<HashMap<LeaseCacheKey, LeaseCacheValue>>>,
}

impl StorageScheduler {
    pub fn new(
        repository: Arc<dyn agentforge_storage::Repository>,
        scheduler: Arc<dyn agentforge_storage::Scheduler>,
        lease_ttl_seconds: u64,
    ) -> Self {
        Self {
            repository,
            scheduler,
            lease_ttl_seconds,
            leases: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Scheduler for StorageScheduler {
    async fn schedule(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        sandbox: Sandbox,
    ) -> Result<ScheduledSandbox, SchedulerError> {
        let scheduled = self
            .scheduler
            .schedule_sandbox(
                tenant_id,
                request_id,
                sandbox.clone(),
                self.lease_ttl_seconds,
            )
            .await
            .map_err(|error| SchedulerError::Rejected(error.to_string()))?;
        let worker = self
            .repository
            .get_worker(scheduled.lease.node_id)
            .await
            .map_err(|error| SchedulerError::Unavailable(error.to_string()))?;
        self.leases.lock().await.insert(
            (tenant_id, scheduled.sandbox.id),
            (
                scheduled.lease.id,
                scheduled.lease.node_id,
                scheduled.lease.generation,
            ),
        );
        Ok(ScheduledSandbox {
            sandbox: scheduled.sandbox,
            worker_endpoint: worker.registration.control_endpoint,
            lease_id: scheduled.lease.id,
        })
    }

    async fn worker_endpoint(
        &self,
        tenant_id: Uuid,
        sandbox_id: Uuid,
    ) -> Result<String, SchedulerError> {
        let lease = self
            .leases
            .lock()
            .await
            .get(&(tenant_id, sandbox_id))
            .copied();
        let node_id = if let Some((lease_id, node_id, generation)) = lease {
            let renewed = self
                .repository
                .renew_worker_lease(tenant_id, lease_id, generation, self.lease_ttl_seconds)
                .await
                .map_err(|error| SchedulerError::Unavailable(error.to_string()))?;
            if let Some((_, _, current_generation)) =
                self.leases.lock().await.get_mut(&(tenant_id, sandbox_id))
            {
                *current_generation = renewed.generation;
            }
            node_id
        } else {
            self.repository
                .list_sandboxes(tenant_id)
                .await
                .map_err(|error| SchedulerError::Unavailable(error.to_string()))?
                .into_iter()
                .find(|sandbox| sandbox.id == sandbox_id)
                .and_then(|sandbox| sandbox.node_id)
                .ok_or_else(|| {
                    SchedulerError::Rejected("sandbox has no worker assignment".into())
                })?
        };
        self.repository
            .get_worker(node_id)
            .await
            .map(|worker| worker.registration.control_endpoint)
            .map_err(|error| SchedulerError::Unavailable(error.to_string()))
    }

    async fn release(&self, tenant_id: Uuid, sandbox_id: Uuid) -> Result<(), SchedulerError> {
        let Some((lease_id, _node_id, generation)) =
            self.leases.lock().await.remove(&(tenant_id, sandbox_id))
        else {
            return Ok(());
        };
        self.repository
            .release_worker_lease(tenant_id, lease_id, generation, "sandbox deleted")
            .await
            .map(|_| ())
            .map_err(|error| SchedulerError::Rejected(error.to_string()))
    }
}

#[derive(Clone)]
pub struct WorkerRuntime {
    client: Arc<dyn WorkerClient>,
    scheduler: Arc<dyn Scheduler>,
    create_request_ids: Arc<Mutex<HashMap<Uuid, Uuid>>>,
    operation_request_ids: Arc<Mutex<HashMap<String, Uuid>>>,
}

impl WorkerRuntime {
    pub fn new(client: Arc<dyn WorkerClient>, scheduler: Arc<dyn Scheduler>) -> Self {
        Self {
            client,
            scheduler,
            create_request_ids: Arc::new(Mutex::new(HashMap::new())),
            operation_request_ids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn prepare_create(&self, sandbox_id: Uuid, request_id: Uuid) {
        self.create_request_ids
            .lock()
            .await
            .insert(sandbox_id, request_id);
    }

    async fn call(
        &self,
        sandbox: &Sandbox,
        operation: WorkerOperation,
    ) -> Result<WorkerValue, RuntimeError> {
        let endpoint = self
            .scheduler
            .worker_endpoint(sandbox.tenant_id, sandbox.id)
            .await
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        let request_id = {
            let key =
                serde_json::to_string(&operation).unwrap_or_else(|_| format!("{operation:?}"));
            let mut ids = self.operation_request_ids.lock().await;
            *ids.entry(key).or_insert_with(new_id)
        };
        let response = self
            .client
            .invoke(
                &endpoint,
                WorkerRequest {
                    request_id,
                    operation,
                },
            )
            .await
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        response.result.map_err(runtime_worker_error)
    }
}

#[async_trait]
impl SandboxRuntime for WorkerRuntime {
    async fn create(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        let request_id = {
            let mut ids = self.create_request_ids.lock().await;
            *ids.entry(sandbox.id).or_insert_with(new_id)
        };
        let endpoint = self
            .scheduler
            .worker_endpoint(sandbox.tenant_id, sandbox.id)
            .await
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        let response = self
            .client
            .invoke(
                &endpoint,
                WorkerRequest {
                    request_id,
                    operation: WorkerOperation::Create {
                        sandbox: sandbox.clone(),
                    },
                },
            )
            .await
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        response.result.map_err(runtime_worker_error)?;
        Ok(())
    }
    async fn start(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        self.call(
            sandbox,
            WorkerOperation::Start {
                sandbox: sandbox.clone(),
            },
        )
        .await
        .map(|_| ())
    }
    async fn stop(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        self.call(
            sandbox,
            WorkerOperation::Stop {
                sandbox: sandbox.clone(),
            },
        )
        .await
        .map(|_| ())
    }
    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
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
    ) -> Result<ExecResult, RuntimeError> {
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
            _ => Err(RuntimeError::Unavailable(
                "invalid worker exec response".into(),
            )),
        }
    }
    async fn put_file(
        &self,
        sandbox: &Sandbox,
        request: PutFileRequest,
    ) -> Result<(), RuntimeError> {
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
    async fn get_file(&self, sandbox: &Sandbox, path: &str) -> Result<FileContent, RuntimeError> {
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
            _ => Err(RuntimeError::Unavailable(
                "invalid worker file response".into(),
            )),
        }
    }
    async fn list_files(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<Vec<FileEntry>, RuntimeError> {
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
            _ => Err(RuntimeError::Unavailable(
                "invalid worker listing response".into(),
            )),
        }
    }
    async fn delete_file(&self, sandbox: &Sandbox, path: &str) -> Result<(), RuntimeError> {
        self.call(
            sandbox,
            WorkerOperation::DeleteFile {
                sandbox: sandbox.clone(),
                path: path.into(),
            },
        )
        .await
        .map(|_| ())
    }
    async fn make_directory(&self, sandbox: &Sandbox, path: &str) -> Result<(), RuntimeError> {
        self.call(
            sandbox,
            WorkerOperation::MakeDirectory {
                sandbox: sandbox.clone(),
                path: path.into(),
            },
        )
        .await
        .map(|_| ())
    }
    async fn snapshot(&self, sandbox: &Sandbox, object_key: &str) -> Result<u64, RuntimeError> {
        match self
            .call(
                sandbox,
                WorkerOperation::Snapshot {
                    sandbox: sandbox.clone(),
                    object_key: object_key.into(),
                },
            )
            .await?
        {
            WorkerValue::Size(size) => Ok(size),
            _ => Err(RuntimeError::Unavailable(
                "invalid worker snapshot response".into(),
            )),
        }
    }
    async fn restore(&self, sandbox: &Sandbox, object_key: &str) -> Result<(), RuntimeError> {
        self.call(
            sandbox,
            WorkerOperation::Restore {
                sandbox: sandbox.clone(),
                object_key: object_key.into(),
            },
        )
        .await
        .map(|_| ())
    }
    fn health(&self) -> bool {
        true
    }
}

fn runtime_worker_error(error: WorkerError) -> RuntimeError {
    match error.code.as_str() {
        "invalid_request" => RuntimeError::Core(CoreError::InvalidRequest(error.message)),
        "forbidden" => RuntimeError::Core(CoreError::Forbidden(error.message)),
        "not_found" => RuntimeError::Core(CoreError::NotFound(error.message)),
        "conflict" => RuntimeError::Core(CoreError::Conflict(error.message)),
        "limit_exceeded" => RuntimeError::Core(CoreError::LimitExceeded(error.message)),
        "runtime_unavailable" => RuntimeError::Unavailable(error.message),
        "snapshot_failed" => RuntimeError::Archive(error.message),
        _ => RuntimeError::Unavailable(error.message),
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
    runtime_kind: RuntimeKind,
    node_id: Uuid,
    capacity: u32,
    token: Arc<str>,
    cache: Arc<Mutex<HashMap<Uuid, WorkerResponse>>>,
    in_flight: Arc<Mutex<usize>>,
    sandboxes: Arc<Mutex<std::collections::HashSet<Uuid>>>,
}

impl WorkerService {
    pub fn new(
        runtime: Arc<dyn SandboxRuntime>,
        runtime_kind: RuntimeKind,
        token: impl Into<String>,
        node_id: Uuid,
        capacity: u32,
    ) -> Self {
        Self {
            runtime,
            runtime_kind,
            node_id,
            capacity,
            token: Arc::from(token.into().as_str()),
            cache: Arc::new(Mutex::new(HashMap::new())),
            in_flight: Arc::new(Mutex::new(0)),
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
                .delete_file(&sandbox, &path)
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::MakeDirectory { sandbox, path } => self
                .runtime
                .make_directory(&sandbox, &path)
                .await
                .map(|_| WorkerValue::Unit),
            WorkerOperation::Snapshot {
                sandbox,
                object_key,
            } => self
                .runtime
                .snapshot(&sandbox, &object_key)
                .await
                .map(WorkerValue::Size),
            WorkerOperation::Restore {
                sandbox,
                object_key,
            } => self
                .runtime
                .restore(&sandbox, &object_key)
                .await
                .map(|_| WorkerValue::Unit),
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
        healthy: state.runtime.health(),
        runtime: state.runtime_kind,
        sandbox_count: state.sandboxes.lock().await.len(),
        in_flight: 0,
        capacity: state.capacity,
    })
}

async fn operation(
    State(state): State<WorkerService>,
    Json(request): Json<WorkerRequest>,
) -> Response {
    if let Some(response) = state.cache.lock().await.get(&request.request_id).cloned() {
        return (StatusCode::OK, Json(response)).into_response();
    }
    let mut in_flight = state.in_flight.lock().await;
    *in_flight = in_flight.saturating_add(1);
    drop(in_flight);
    let sandbox_event = match &request.operation {
        WorkerOperation::Create { sandbox } => Some((sandbox.id, true)),
        WorkerOperation::Destroy { sandbox } => Some((sandbox.id, false)),
        _ => None,
    };
    let result = state.execute(request.operation).await;
    let mut flight = state.in_flight.lock().await;
    *flight = flight.saturating_sub(1);
    drop(flight);
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
    state
        .cache
        .lock()
        .await
        .insert(request.request_id, response.clone());
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
