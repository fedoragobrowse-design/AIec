use agentforge_core::*;
use agentforge_runtime::{RuntimeError, SandboxRuntime};
use agentforge_storage::{MemoryRepository, ObjectStore, Repository};
mod worker;
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use uuid::Uuid;
pub use worker::{
    HttpWorkerClient, ScheduledSandbox, Scheduler, SchedulerError, StorageScheduler, WorkerClient,
    WorkerClientError, WorkerError, WorkerHeartbeat, WorkerOperation, WorkerRegistration,
    WorkerRequest, WorkerResponse, WorkerRuntime, WorkerService, WorkerStatus, WorkerValue,
};

#[derive(Clone)]
pub struct AppState {
    pub runtime: Arc<dyn SandboxRuntime>,
    pub repository: Arc<dyn Repository>,
    requests: Arc<AtomicU64>,
    scheduler: Option<Arc<dyn Scheduler>>,
    worker_token: Option<Arc<str>>,
    object_store: Option<Arc<dyn ObjectStore>>,
}
impl AppState {
    pub fn new(repository: Arc<dyn Repository>, runtime: Arc<dyn SandboxRuntime>) -> Self {
        Self {
            worker_token: None,
            runtime,
            repository,
            scheduler: None,
            requests: Arc::new(AtomicU64::new(0)),
            object_store: None,
        }
    }
    pub fn with_worker_token(mut self, token: impl Into<String>) -> Self {
        self.worker_token = Some(Arc::from(token.into().as_str()));
        self
    }
    pub fn in_memory(runtime: Arc<dyn SandboxRuntime>) -> Self {
        Self::new(MemoryRepository::new(), runtime)
    }
    pub fn with_scheduler(mut self, scheduler: Arc<dyn Scheduler>) -> Self {
        self.scheduler = Some(scheduler);
        self
    }
    pub fn scheduler(&self) -> Option<Arc<dyn Scheduler>> {
        self.scheduler.clone()
    }
    pub fn with_object_store(mut self, object_store: Arc<dyn ObjectStore>) -> Self {
        self.object_store = Some(object_store);
        self
    }
}
#[derive(Debug)]
struct ApiFailure {
    status: StatusCode,
    code: &'static str,
    message: String,
    request_id: Uuid,
}
impl ApiFailure {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            request_id: new_id(),
        }
    }
}
impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorEnvelope {
                error: ApiErrorBody {
                    code: self.code.into(),
                    message: self.message,
                    request_id: self.request_id,
                },
            }),
        )
            .into_response()
    }
}
impl From<CoreError> for ApiFailure {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::InvalidRequest(m) => {
                Self::new(StatusCode::BAD_REQUEST, "invalid_request", m)
            }
            CoreError::Forbidden(m) => Self::new(StatusCode::FORBIDDEN, "forbidden", m),
            CoreError::NotFound(m) => Self::new(StatusCode::NOT_FOUND, "not_found", m),
            CoreError::Conflict(m) => Self::new(StatusCode::CONFLICT, "conflict", m),
            CoreError::LimitExceeded(m) => {
                Self::new(StatusCode::PAYLOAD_TOO_LARGE, "limit_exceeded", m)
            }
            CoreError::Io(e) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string())
            }
        }
    }
}
impl From<RuntimeError> for ApiFailure {
    fn from(e: RuntimeError) -> Self {
        match e {
            RuntimeError::Core(e) => e.into(),
            RuntimeError::Unavailable(m) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable", m)
            }
            RuntimeError::Io(e) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string())
            }
            RuntimeError::Json(e) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string())
            }
            RuntimeError::Archive(m) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "snapshot_failed", m)
            }
            RuntimeError::Protocol(error) => {
                Self::new(StatusCode::BAD_GATEWAY, "guest_protocol", error.to_string())
            }
            RuntimeError::FirecrackerApi(message) => {
                Self::new(StatusCode::BAD_GATEWAY, "firecracker_api", message)
            }
        }
    }
}
type ApiResult<T> = Result<Json<T>, ApiFailure>;
fn store(e: agentforge_storage::StoreError) -> ApiFailure {
    ApiFailure::new(StatusCode::NOT_FOUND, "not_found", e.to_string())
}
pub fn router(state: AppState) -> Router {
    let protected = protected_routes().layer(middleware::from_fn_with_state(state.clone(), auth));
    let workers = worker_routes().layer(middleware::from_fn_with_state(state.clone(), worker_auth));
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .nest("/v1", protected)
        .nest("/v1/workers", workers)
        .with_state(state)
}
fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/sandboxes", post(create_sandbox).get(list_sandboxes))
        .route("/sandboxes/{id}", get(get_sandbox).delete(delete_sandbox))
        .route("/sandboxes/{id}/start", post(start_sandbox))
        .route("/sandboxes/{id}/stop", post(stop_sandbox))
        .route("/sandboxes/{id}/resume", post(resume_sandbox))
        .route("/sandboxes/{id}/exec", post(exec_sandbox))
        .route(
            "/sandboxes/{id}/files",
            put(put_file).get(list_files).delete(delete_file),
        )
        .route("/sandboxes/{id}/files/content", get(get_file))
        .route("/sandboxes/{id}/files/list", get(list_files))
        .route("/sandboxes/{id}/files/mkdir", post(make_directory))
        .route(
            "/sandboxes/{id}/snapshots",
            post(create_snapshot).get(list_snapshots),
        )
        .route("/snapshots/{id}/restore", post(restore_snapshot))
        .route("/snapshots/{id}", delete(delete_snapshot))
        .route("/usage", get(usage))
}
pub fn app(state: AppState) -> Router {
    router(state)
}

fn worker_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_worker))
        .route("/reconcile", post(reconcile_workers))
        .route("/{id}/heartbeat", post(heartbeat_worker))
        .route("/{id}/status", get(worker_status))
        .route("/{id}/assignments/claim", post(claim_worker_assignments))
}

#[derive(Deserialize)]
struct WorkerClaimQuery {
    #[serde(default = "default_claim_limit")]
    limit: u32,
    #[serde(default = "default_lease_ttl")]
    lease_ttl_seconds: u64,
}
fn default_claim_limit() -> u32 {
    32
}
fn default_lease_ttl() -> u64 {
    300
}

async fn claim_worker_assignments(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<WorkerClaimQuery>,
) -> ApiResult<Vec<agentforge_storage::WorkerAssignment>> {
    match state
        .repository
        .claim_worker_assignments(
            id,
            query.limit.min(128),
            query.lease_ttl_seconds.clamp(1, 3600),
        )
        .await
    {
        Ok(assignments) => Ok(Json(assignments)),
        Err(agentforge_storage::StoreError::Unsupported(_)) => Ok(Json(Vec::new())),
        Err(error) => Err(store(error)),
    }
}

async fn worker_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiFailure> {
    let Some(expected) = state.worker_token.as_deref() else {
        return Err(ApiFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "worker_control_disabled",
            "worker control token is not configured",
        ));
    };
    let supplied = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !supplied.is_some_and(|value| worker::constant_time_eq(value, expected)) {
        return Err(ApiFailure::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid worker token",
        ));
    }
    Ok(next.run(request).await)
}

async fn register_worker(
    State(state): State<AppState>,
    Json(registration): Json<WorkerRegistration>,
) -> ApiResult<agentforge_storage::WorkerRegistration> {
    let record = agentforge_storage::WorkerRegistration {
        node_id: registration.node_id,
        name: registration.name,
        runtime: registration.runtime,
        control_endpoint: registration.control_endpoint,
        total_vcpus: registration.total_vcpus,
        total_memory_bytes: registration.total_memory_bytes,
        total_disk_bytes: registration.total_disk_bytes,
        available_vcpus: registration.available_vcpus,
        available_memory_bytes: registration.available_memory_bytes,
        available_disk_bytes: registration.available_disk_bytes,
        healthy: registration.healthy,
        version: registration.version,
        metadata: registration.metadata,
        started_at: Utc::now(),
        last_heartbeat: Utc::now(),
    };
    match state.repository.register_worker(record.clone()).await {
        Ok(()) => Ok(Json(record)),
        Err(agentforge_storage::StoreError::Unsupported(_)) => {
            state
                .repository
                .register_node(Node {
                    id: record.node_id,
                    name: record.name.clone(),
                    available_vcpus: record.available_vcpus,
                    available_memory_bytes: record.available_memory_bytes,
                    available_disk_bytes: record.available_disk_bytes,
                    sandbox_count: 0,
                    healthy: record.healthy,
                    last_heartbeat: record.last_heartbeat,
                })
                .await
                .map_err(store)?;
            Ok(Json(record))
        }
        Err(error) => Err(store(error)),
    }
}

async fn heartbeat_worker(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(heartbeat): Json<WorkerHeartbeat>,
) -> ApiResult<Value> {
    if heartbeat.node_id != id {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "worker heartbeat id mismatch",
        ));
    }
    let value = agentforge_storage::WorkerHeartbeat {
        node_id: heartbeat.node_id,
        available_vcpus: heartbeat.available_vcpus,
        available_memory_bytes: heartbeat.available_memory_bytes,
        available_disk_bytes: heartbeat.available_disk_bytes,
        sandbox_count: heartbeat.sandbox_count,
        healthy: heartbeat.healthy,
        version: heartbeat.version,
        metadata: heartbeat.metadata,
        last_error: heartbeat.last_error,
    };
    match state.repository.heartbeat_worker(value).await {
        Ok(status) => Ok(Json(json!(status))),
        Err(agentforge_storage::StoreError::Unsupported(_)) => {
            let Some(mut node) = state
                .repository
                .list_nodes()
                .await
                .map_err(store)?
                .into_iter()
                .find(|node| node.id == id)
            else {
                return Err(ApiFailure::new(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "worker is not registered",
                ));
            };
            node.available_vcpus = heartbeat.available_vcpus;
            node.available_memory_bytes = heartbeat.available_memory_bytes;
            node.available_disk_bytes = heartbeat.available_disk_bytes;
            node.sandbox_count = heartbeat.sandbox_count;
            node.healthy = heartbeat.healthy;
            node.last_heartbeat = Utc::now();
            state
                .repository
                .register_node(node.clone())
                .await
                .map_err(store)?;
            state.repository.heartbeat(id).await.map_err(store)?;
            Ok(Json(json!(node)))
        }
        Err(error) => Err(store(error)),
    }
}

async fn worker_status(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    match state.repository.get_worker(id).await {
        Ok(status) => Ok(Json(json!(status))),
        Err(agentforge_storage::StoreError::Unsupported(_)) => state
            .repository
            .list_nodes()
            .await
            .map_err(store)?
            .into_iter()
            .find(|node| node.id == id)
            .map(|node| Json(json!(node)))
            .ok_or_else(|| {
                ApiFailure::new(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "worker is not registered",
                )
            }),
        Err(error) => Err(store(error)),
    }
}

async fn reconcile_workers(State(state): State<AppState>) -> ApiResult<Value> {
    let actions = match state.repository.reconcile_expired_leases(100).await {
        Ok(actions) => actions,
        Err(agentforge_storage::StoreError::Unsupported(_)) => Vec::new(),
        Err(error) => return Err(store(error)),
    };
    let workers = match state.repository.list_workers(true).await {
        Ok(workers) => workers,
        Err(agentforge_storage::StoreError::Unsupported(_)) => state
            .repository
            .list_nodes()
            .await
            .map_err(store)?
            .into_iter()
            .map(|node| agentforge_storage::WorkerStatus {
                registration: agentforge_storage::WorkerRegistration {
                    node_id: node.id,
                    name: node.name,
                    runtime: RuntimeKind::BwrapDev,
                    control_endpoint: String::new(),
                    total_vcpus: node.available_vcpus,
                    total_memory_bytes: node.available_memory_bytes,
                    total_disk_bytes: node.available_disk_bytes,
                    available_vcpus: node.available_vcpus,
                    available_memory_bytes: node.available_memory_bytes,
                    available_disk_bytes: node.available_disk_bytes,
                    healthy: node.healthy,
                    version: 0,
                    metadata: json!({}),
                    started_at: node.last_heartbeat,
                    last_heartbeat: node.last_heartbeat,
                },
                sandbox_count: node.sandbox_count,
                last_error: None,
            })
            .collect(),
        Err(error) => return Err(store(error)),
    };
    Ok(Json(json!({"actions": actions, "workers": workers})))
}
async fn auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiFailure> {
    let raw = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiFailure::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing bearer API key",
            )
        })?;
    validate_api_key(raw).map_err(|_| {
        ApiFailure::new(StatusCode::UNAUTHORIZED, "unauthorized", "invalid API key")
    })?;
    let key = state
        .repository
        .find_key(&key_digest(raw))
        .await
        .map_err(|_| {
            ApiFailure::new(StatusCode::UNAUTHORIZED, "unauthorized", "invalid API key")
        })?;
    let now = Utc::now();
    if key.revoked_at.is_some() || key.expires_at.is_some_and(|x| x <= now) {
        return Err(ApiFailure::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "expired or revoked API key",
        ));
    }
    request.extensions_mut().insert(Principal {
        tenant_id: key.tenant_id,
        key_id: key.id,
        scopes: key.scopes,
    });
    Ok(next.run(request).await)
}
async fn health() -> Json<Value> {
    Json(json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}))
}
async fn ready() -> Json<Value> {
    Json(json!({"status":"ready"}))
}
async fn metrics(State(state): State<AppState>) -> Response {
    let count = state
        .repository
        .list_nodes()
        .await
        .map(|nodes| nodes.len())
        .unwrap_or_default();
    ([(axum::http::header::CONTENT_TYPE,"text/plain; version=0.0.4")],format!("# TYPE agentforge_api_requests_total counter\nagentforge_api_requests_total {}\n# TYPE agentforge_sandboxes_total gauge\nagentforge_sandboxes_total 0\n# TYPE agentforge_node_available_vcpus gauge\nagentforge_node_available_vcpus {}\n",state.requests.load(Ordering::Relaxed),count)).into_response()
}

#[derive(Deserialize)]
struct CreateSandboxBody {
    #[serde(flatten)]
    request: CreateSandboxRequest,
    runtime: Option<String>,
}
async fn create_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<CreateSandboxBody>,
) -> ApiResult<Sandbox> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let requested_runtime = match body.runtime.as_deref() {
        Some("firecracker") => Some(RuntimeKind::Firecracker),
        Some("bwrap-dev" | "bwrap_dev") => Some(RuntimeKind::BwrapDev),
        Some(other) => {
            return Err(ApiFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("unsupported runtime {other}"),
            ));
        }
        None => None,
    };
    if requested_runtime == Some(RuntimeKind::Firecracker) && s.scheduler().is_none() {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "firecracker requests require the production server",
        ));
    }
    if requested_runtime == Some(RuntimeKind::BwrapDev) && s.scheduler().is_some() {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "bwrap-dev is not available in production",
        ));
    }
    let r = body.request;
    validate_create(&r, 86400).map_err(ApiFailure::from)?;
    let request_id = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or_else(new_id);
    let now = if headers.get("idempotency-key").is_some() {
        chrono::DateTime::<Utc>::from_timestamp(0, 0).expect("epoch timestamp is valid")
    } else {
        Utc::now()
    };
    let mut x = Sandbox {
        id: request_id,
        tenant_id: p.tenant_id,
        node_id: None,
        runtime: if s.scheduler().is_some() {
            RuntimeKind::Firecracker
        } else {
            RuntimeKind::BwrapDev
        },
        image_id: image_id(&r.image),
        state: SandboxState::Creating,
        cpu: r.cpu,
        memory_mb: r.memory_mb,
        disk_mb: r.disk_mb,
        timeout_seconds: r.timeout_seconds,
        network: r.network,
        created_at: now,
        updated_at: now,
        runtime_path: None,
    };
    if let Some(scheduler) = s.scheduler() {
        x = scheduler
            .schedule(p.tenant_id, request_id, x)
            .await
            .map_err(|error| {
                ApiFailure::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "scheduler_unavailable",
                    error.to_string(),
                )
            })?
            .sandbox;
    } else {
        s.repository
            .create_sandbox(x.clone())
            .await
            .map_err(store)?;
    }
    if x.state != SandboxState::Creating {
        return Ok(Json(x));
    }
    s.runtime.create(&x).await.map_err(ApiFailure::from)?;
    x.state = SandboxState::Starting;
    s.repository
        .update_state(
            p.tenant_id,
            x.id,
            SandboxState::Creating,
            SandboxState::Starting,
            None,
        )
        .await
        .map_err(store)?;
    s.runtime.start(&x).await.map_err(ApiFailure::from)?;
    x.state = SandboxState::Running;
    s.repository
        .update_state(
            p.tenant_id,
            x.id,
            SandboxState::Starting,
            SandboxState::Running,
            None,
        )
        .await
        .map_err(store)?;
    Ok(Json(x))
}
async fn list_sandboxes(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Vec<Sandbox>> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    Ok(Json(
        s.repository
            .list_sandboxes(p.tenant_id)
            .await
            .map_err(store)?,
    ))
}
async fn get_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Sandbox> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    Ok(Json(
        s.repository
            .get_sandbox(p.tenant_id, id)
            .await
            .map_err(store)?,
    ))
}
async fn delete_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    s.runtime.destroy(&x).await.map_err(ApiFailure::from)?;
    if let Some(scheduler) = s.scheduler() {
        scheduler.release(p.tenant_id, id).await.map_err(|error| {
            ApiFailure::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "scheduler_unavailable",
                error.to_string(),
            )
        })?;
    }
    s.repository
        .delete_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    Ok(Json(json!({"status":"destroyed"})))
}
async fn start_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Sandbox> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let mut x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    let old = x.state;
    x.state = SandboxState::Starting;
    s.runtime.start(&x).await.map_err(ApiFailure::from)?;
    s.repository
        .update_state(p.tenant_id, id, old, SandboxState::Starting, None)
        .await
        .map_err(store)?;
    x.state = SandboxState::Running;
    s.repository
        .update_state(
            p.tenant_id,
            id,
            SandboxState::Starting,
            SandboxState::Running,
            None,
        )
        .await
        .map_err(store)?;
    Ok(Json(x))
}
async fn stop_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Sandbox> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let mut x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    let old = x.state;
    x.state = SandboxState::Stopping;
    s.runtime.stop(&x).await.map_err(ApiFailure::from)?;
    s.repository
        .update_state(p.tenant_id, id, old, SandboxState::Stopping, None)
        .await
        .map_err(store)?;
    x.state = SandboxState::Stopped;
    s.repository
        .update_state(
            p.tenant_id,
            id,
            SandboxState::Stopping,
            SandboxState::Stopped,
            None,
        )
        .await
        .map_err(store)?;
    Ok(Json(x))
}
async fn resume_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Sandbox> {
    start_sandbox(State(s), Extension(p), Path(id)).await
}
async fn exec_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(b): Json<ExecBody>,
) -> ApiResult<ExecResult> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    if x.state != SandboxState::Running {
        return Err(ApiFailure::from(CoreError::Conflict(
            "sandbox is not running".into(),
        )));
    }
    let r = b.into_request()?;
    validate_exec(&r).map_err(ApiFailure::from)?;
    Ok(Json(s.runtime.exec(&x, r).await.map_err(ApiFailure::from)?))
}
#[derive(Deserialize)]
struct ExecBody {
    command: Value,
    #[serde(default)]
    working_directory: Option<String>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    stdin: Option<String>,
}
impl ExecBody {
    fn into_request(self) -> Result<ExecRequest, ApiFailure> {
        let command = match self.command {
            Value::String(v) => v.split_whitespace().map(str::to_owned).collect(),
            Value::Array(a) => a
                .into_iter()
                .map(|v| {
                    v.as_str().map(str::to_owned).ok_or_else(|| {
                        ApiFailure::new(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            "command array must contain strings",
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(ApiFailure::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "command must be string or argv array",
                ));
            }
        };
        Ok(ExecRequest {
            command,
            working_directory: self.working_directory,
            environment: self.environment,
            timeout_seconds: self.timeout_seconds.unwrap_or(60),
            stdin: self.stdin,
        })
    }
}
async fn put_file(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(r): Json<PutFileRequest>,
) -> ApiResult<Value> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    s.runtime.put_file(&x, r).await.map_err(ApiFailure::from)?;
    Ok(Json(json!({"status":"written"})))
}
async fn get_file(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    Query(q): Query<ListFilesQuery>,
) -> ApiResult<FileContent> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    let x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    Ok(Json(
        s.runtime
            .get_file(&x, &q.path)
            .await
            .map_err(ApiFailure::from)?,
    ))
}
async fn list_files(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    Query(q): Query<ListFilesQuery>,
) -> ApiResult<Vec<FileEntry>> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    let x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    Ok(Json(
        s.runtime
            .list_files(&x, &q.path)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

async fn delete_file(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    Query(q): Query<ListFilesQuery>,
) -> ApiResult<Value> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    s.runtime
        .delete_file(&x, &q.path)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(json!({"status":"deleted"})))
}
async fn make_directory(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(r): Json<MakeDirectoryRequest>,
) -> ApiResult<Value> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    s.runtime
        .make_directory(&x, &r.path)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(json!({"status":"created"})))
}
async fn create_snapshot(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Snapshot> {
    p.authorize(Scope::SnapshotsWrite)
        .map_err(ApiFailure::from)?;
    let mut x = s
        .repository
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(store)?;
    let old = x.state;
    x.state = SandboxState::Snapshotting;
    s.repository
        .update_state(p.tenant_id, id, old, SandboxState::Snapshotting, None)
        .await
        .map_err(store)?;
    let key = format!("{id}/{}", new_id());
    let size = s
        .runtime
        .snapshot(&x, &key)
        .await
        .map_err(ApiFailure::from)?;
    let snap = Snapshot {
        id: new_id(),
        tenant_id: p.tenant_id,
        sandbox_id: id,
        object_key: key,
        size_bytes: size,
        image_id: x.image_id.clone(),
        created_at: Utc::now(),
    };
    s.repository
        .put_snapshot(snap.clone())
        .await
        .map_err(store)?;
    s.repository
        .update_state(
            p.tenant_id,
            id,
            SandboxState::Snapshotting,
            SandboxState::Running,
            None,
        )
        .await
        .map_err(store)?;
    Ok(Json(snap))
}
async fn list_snapshots(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Vec<Snapshot>> {
    p.authorize(Scope::SnapshotsRead)
        .map_err(ApiFailure::from)?;
    Ok(Json(
        s.repository
            .list_snapshots(p.tenant_id, id)
            .await
            .map_err(store)?,
    ))
}
async fn restore_snapshot(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(r): Json<RestoreSnapshotRequest>,
) -> ApiResult<Sandbox> {
    p.authorize(Scope::SnapshotsWrite)
        .map_err(ApiFailure::from)?;
    let snap = s
        .repository
        .get_snapshot(p.tenant_id, id)
        .await
        .map_err(store)?;
    let now = Utc::now();
    let mut x = Sandbox {
        id: new_id(),
        tenant_id: p.tenant_id,
        node_id: None,
        image_id: r.image.unwrap_or(snap.image_id),
        state: SandboxState::Restoring,
        runtime: if s.scheduler().is_some() {
            RuntimeKind::Firecracker
        } else {
            RuntimeKind::BwrapDev
        },
        cpu: r.cpu.unwrap_or(1),
        memory_mb: r.memory_mb.unwrap_or(512),
        disk_mb: r.disk_mb.unwrap_or(2048),
        timeout_seconds: 900,
        network: NetworkPolicy::default(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    };
    if let Some(scheduler) = s.scheduler() {
        x = scheduler
            .schedule(p.tenant_id, new_id(), x)
            .await
            .map_err(|error| {
                ApiFailure::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "scheduler_unavailable",
                    error.to_string(),
                )
            })?
            .sandbox;
    } else {
        s.repository
            .create_sandbox(x.clone())
            .await
            .map_err(store)?;
    }
    s.runtime.create(&x).await.map_err(ApiFailure::from)?;
    s.runtime
        .restore(&x, &snap.object_key)
        .await
        .map_err(ApiFailure::from)?;
    s.repository
        .update_state(
            p.tenant_id,
            x.id,
            SandboxState::Restoring,
            SandboxState::Running,
            None,
        )
        .await
        .map_err(store)?;
    x.state = SandboxState::Running;
    Ok(Json(x))
}
async fn delete_snapshot(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    p.authorize(Scope::SnapshotsWrite)
        .map_err(ApiFailure::from)?;
    let snapshot = s
        .repository
        .get_snapshot(p.tenant_id, id)
        .await
        .map_err(store)?;
    if let Some(object_store) = &s.object_store {
        object_store
            .delete(&snapshot.object_key)
            .await
            .map_err(|error| {
                ApiFailure::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "object_store",
                    error.to_string(),
                )
            })?;
    }
    s.repository
        .delete_snapshot(p.tenant_id, id)
        .await
        .map_err(store)?;
    Ok(Json(json!({"status":"deleted"})))
}
async fn usage(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Vec<UsageSummary>> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    let events = s.repository.usage(p.tenant_id).await.map_err(store)?;
    let mut out = std::collections::HashMap::<String, i64>::new();
    for e in events {
        *out.entry(e.metric).or_default() += e.quantity
    }
    Ok(Json(
        out.into_iter()
            .map(|(metric, quantity)| UsageSummary { metric, quantity })
            .collect(),
    ))
}
pub async fn serve(state: AppState, addr: std::net::SocketAddr) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app(state)).await
}

pub async fn serve_worker(
    service: WorkerService,
    addr: std::net::SocketAddr,
) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, service.router()).await
}
