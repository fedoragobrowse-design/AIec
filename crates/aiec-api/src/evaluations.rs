//! The generic evaluation surface, over HTTP.
//!
//! [`crate::eval_matrix`] already knows how to run a batch, a set of
//! repetitions and a matrix. This module is the wire in front of it: the three
//! routes a caller needs to ask for those, and nothing else. Keeping them in
//! one place is the point - every evaluation is authenticated, tenant-scoped
//! and scope-checked by the same code, rather than each shape remembering to.
//!
//! There is deliberately no agent-specific route in here. A new agent is a new
//! adapter over these three routes, not a new scheduler and not a new set of
//! guarantees to re-earn.

use aiec_core::Scope;
use aiec_core::run::{BatchOptions, Run};
use aiec_core::storage::MatrixCursor;
use axum::{
    Json, Router,
    extract::{Extension, FromRequestParts, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::eval_matrix::{
    MatrixPage, MatrixResult, MatrixSpec, read_matrix, run_batch, run_matrix, run_repetitions,
};
use crate::runs::RunRequest;
use crate::{ApiFailure, ApiResult, AppState, CoreError, Principal};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BatchRequest {
    #[serde(default)]
    pub requests: Vec<RunRequest>,
    #[serde(default)]
    pub options: BatchOptions,
}

/// The same workload, run several times.
///
/// Each repetition is its own machine and its own run, so a caller can tell an
/// agent that passes from an agent that passes reliably.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RepetitionRequest {
    pub request: RunRequest,
    /// One is the default: asking for none is almost always an arithmetic
    /// mistake, and it is rejected below rather than reported as an evaluation
    /// of nothing that happened.
    #[serde(default = "one_repetition")]
    pub repetitions: u32,
    #[serde(default)]
    pub options: BatchOptions,
}

fn one_repetition() -> u32 {
    1
}

/// A principal that has already been shown to hold a scope.
///
/// The check is an extractor rather than a line at the top of each handler
/// because axum extracts the whole request before the handler body runs: a
/// scope checked inside the body is checked *after* `Json` has already
/// validated and rejected the payload. That ordering answers a key with no
/// rights "your repetitions field is invalid" instead of "forbidden", which
/// tells an unauthorized caller about the shape of an endpoint they may not
/// use. This way every evaluation route refuses an unauthorized key before it
/// looks at the body at all.
pub(crate) struct WriteScope(Principal);

/// A principal that has already been shown to be allowed to read.
pub(crate) struct ReadScope(Principal);

/// Extracts the authenticated principal and checks one scope against it.
async fn principal_for<S: Send + Sync>(
    parts: &mut axum::http::request::Parts,
    state: &S,
    scope: Scope,
) -> Result<Principal, ApiFailure> {
    let Extension(principal) = Extension::<Principal>::from_request_parts(parts, state)
        .await
        .map_err(|_| {
            ApiFailure::new(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "this route requires authentication",
            )
        })?;
    principal.authorize(scope).map_err(ApiFailure::from)?;
    Ok(principal)
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for WriteScope {
    type Rejection = ApiFailure;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Writing scope, because an evaluation starts machines. A read-only key
        // can look at what a batch produced and cannot ask for one.
        Ok(Self(
            principal_for(parts, state, Scope::SandboxesWrite).await?,
        ))
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ReadScope {
    type Rejection = ApiFailure;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            principal_for(parts, state, Scope::SandboxesRead).await?,
        ))
    }
}

/// Runs a list of workloads, at most `max_parallel` machines at a time.
///
/// The runs, and nothing else. A summary laid over them would be a second
/// account of the same batch for a caller to decide which one to believe, and
/// the runs are already the record.
pub(crate) async fn create_batch(
    State(state): State<AppState>,
    WriteScope(principal): WriteScope,
    Json(body): Json<BatchRequest>,
) -> ApiResult<Vec<Run>> {
    Ok(Json(
        run_batch(&state, principal.tenant_id, body.requests, &body.options)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

/// Runs one workload several times, each repetition on its own machine.
pub(crate) async fn create_repetitions(
    State(state): State<AppState>,
    WriteScope(principal): WriteScope,
    Json(body): Json<RepetitionRequest>,
) -> ApiResult<Vec<Run>> {
    if body.repetitions == 0 {
        return Err(ApiFailure::from(CoreError::InvalidRequest(
            "repetitions must be at least 1".into(),
        )));
    }
    Ok(Json(
        run_repetitions(
            &state,
            principal.tenant_id,
            body.request,
            body.repetitions,
            &body.options,
        )
        .await
        .map_err(ApiFailure::from)?,
    ))
}

/// Expands and runs a matrix, reporting every cell.
pub(crate) async fn create_matrix(
    State(state): State<AppState>,
    WriteScope(principal): WriteScope,
    Json(spec): Json<MatrixSpec>,
) -> ApiResult<MatrixResult> {
    Ok(Json(
        run_matrix(&state, principal.tenant_id, &spec)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

/// How much of a matrix one read returns.
#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct MatrixPageQuery {
    /// Cells to return. The store clamps this to its own ceiling, so a caller
    /// cannot ask for a response the control plane has no bound on.
    #[serde(default)]
    pub limit: Option<u32>,
    /// The previous page's last cell: when it was requested, and which one.
    ///
    /// Both halves or neither. A cursor with only a timestamp has no cell to
    /// start after, and one with only an id cannot order a page that has not
    /// been read; guessing either would silently return the wrong page.
    #[serde(default)]
    pub after_requested_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub after_id: Option<Uuid>,
}

/// Cells returned when a caller does not say how many.
const DEFAULT_MATRIX_PAGE: u32 = 50;

/// Reads one bounded page of a matrix's cells.
pub(crate) async fn get_matrix(
    State(state): State<AppState>,
    ReadScope(principal): ReadScope,
    Path(matrix_id): Path<Uuid>,
    Query(query): Query<MatrixPageQuery>,
) -> ApiResult<MatrixPage> {
    let after = match (query.after_requested_at, query.after_id) {
        (None, None) => None,
        (Some(requested_at), Some(id)) => Some(MatrixCursor { requested_at, id }),
        _ => {
            return Err(ApiFailure::from(CoreError::InvalidRequest(
                "after_requested_at and after_id must be given together".into(),
            )));
        }
    };
    let limit = query.limit.unwrap_or(DEFAULT_MATRIX_PAGE);
    Ok(Json(
        read_matrix(&state, principal.tenant_id, matrix_id, limit, after)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

/// The routes this module owns.
///
/// Returned rather than built into the root router so the composition root
/// stays a list of merges: this module decides what an evaluation is, and the
/// root decides what is authenticated. Merge it into the protected routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/eval/batch", post(create_batch))
        .route("/eval/repetitions", post(create_repetitions))
        .route("/eval/matrix", post(create_matrix))
        .route("/eval/matrix/{matrix_id}", get(get_matrix))
}

#[cfg(test)]
mod tests {
    use super::*;

    use aiec_core::new_id;
    use aiec_core::platform::Platform;
    use aiec_core::run::{Run, RunState};
    use aiec_core::run_queue::RunQueueLimits;
    use aiec_core::runtime::{
        RuntimeCapabilities, RuntimeHealth, RuntimeIsolation, RuntimeRegistry, SandboxRuntime,
    };
    use aiec_core::storage::*;
    use aiec_core::storage::{WorkerHeartbeat, WorkerRegistration, WorkerStatus};
    use aiec_core::*;
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::{Method, StatusCode};
    use axum::middleware::{self, Next};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tower::util::ServiceExt;

    /// A runtime that does nothing, because none of these tests execute a
    /// workload: they are about who is allowed to ask, and about what the
    /// response says, neither of which reaches a machine.
    struct UnusedRuntime;

    #[async_trait::async_trait]
    impl SandboxRuntime for UnusedRuntime {
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
            _: aiec_core::runtime::FileChunkRequest,
        ) -> Result<aiec_core::runtime::FileChunk, CoreError> {
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
            // Exec and files, because these batches are sized against the
            // cluster's real capacity: a runtime that advertised neither could
            // not be selected, and a batch sized against an unselectable
            // runtime reads as "capacity unknown" - which is how a cluster with
            // nothing free came back claiming the width the caller asked for.
            RuntimeCapabilities {
                isolation: RuntimeIsolation::Container,
                exec: true,
                files: true,
                ..Default::default()
            }
        }
    }

    fn state_over(store: Arc<dyn MetadataStore>) -> AppState {
        let runtime: Arc<dyn SandboxRuntime> = Arc::new(UnusedRuntime);
        let platform = Platform::builder()
            .runtime(runtime.clone())
            .runtime_registry(Arc::new(RuntimeRegistry::with_runtime(
                RuntimeKind::Docker,
                runtime,
            )))
            .metadata_store(store)
            .scheduler(Arc::new(crate::DevelopmentScheduler))
            .policy(Arc::new(crate::DefaultPolicy))
            .build()
            .expect("a platform");
        AppState::development(platform)
    }

    /// These routes stand in for the authenticated ones, with a principal
    /// injected the way the auth middleware would inject it.
    fn eval_app(scopes: Vec<Scope>) -> Router {
        eval_app_for(new_id(), aiec_storage::MemoryRepository::new(), scopes)
    }

    fn eval_app_for(tenant: Uuid, store: Arc<dyn MetadataStore>, scopes: Vec<Scope>) -> Router {
        let principal = Principal {
            tenant_id: tenant,
            key_id: new_id(),
            scopes,
        };
        routes()
            .layer(middleware::from_fn(
                move |mut request: Request, next: Next| {
                    let principal = principal.clone();
                    async move {
                        request.extensions_mut().insert(principal);
                        next.run(request).await
                    }
                },
            ))
            .with_state(state_over(store))
    }

    async fn post_json(app: Router, path: &str, body: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("a request");
        let response = app.oneshot(request).await.expect("a response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn get_json(app: Router, path: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Body::empty())
            .expect("a request");
        let response = app.oneshot(request).await.expect("a response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// An evaluation starts machines, so a key that can only read cannot ask
    /// for one. Each shape is checked: the scope is enforced on the route, not
    /// on a code path some of them happen to share.
    #[tokio::test]
    async fn an_evaluation_needs_the_write_scope_on_every_route() {
        let reader = eval_app(vec![Scope::SandboxesRead]);
        for path in ["/eval/batch", "/eval/repetitions", "/eval/matrix"] {
            let (status, body) = post_json(reader.clone(), path, json!({})).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{path} accepted a read-only key: {body}"
            );
            assert_eq!(body["error"]["code"], "forbidden");
        }
    }

    /// The bound is enforced here, not only in the SDKs that happen to check
    /// it. A client asking for fifty machines at once is refused rather than
    /// quietly run at whatever the control plane felt like, and the refusal is
    /// about the bound rather than about the batch being empty.
    #[tokio::test]
    async fn a_batch_bound_the_control_plane_refuses_is_refused_here_too() {
        for max_parallel in [0, 65] {
            let writer = eval_app(vec![Scope::SandboxesWrite]);
            let (status, body) = post_json(
                writer,
                "/eval/batch",
                json!({"requests": [], "options": {"max_parallel": max_parallel}}),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a bound of {max_parallel} was accepted: {body}"
            );
            assert_eq!(body["error"]["code"], "invalid_request");
        }
    }

    /// Zero repetitions is an arithmetic mistake, and answering it as a
    /// successful evaluation of nothing would hide it.
    #[tokio::test]
    async fn repetitions_must_ask_for_at_least_one() {
        let writer = eval_app(vec![Scope::SandboxesWrite]);
        let (status, body) = post_json(
            writer,
            "/eval/repetitions",
            json!({
                "request": {"workload": {"command": ["true"]}},
                "repetitions": 0,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "invalid_request");
    }

    /// A store that admits a run and settles it immediately, so a test can see
    /// how many cells a batch had in flight rather than what a machine did.
    ///
    /// The delays are deliberately uneven: a batch that returned cells in
    /// completion order would pass every assertion about parallelism and still
    /// hand a caller the wrong answer about which cell was which.
    struct QueueStore {
        inner: Arc<aiec_storage::MemoryRepository>,
        nodes: Vec<Node>,
        inflight: AtomicUsize,
        peak: AtomicUsize,
        executions: AtomicUsize,
        cells: std::sync::Mutex<Vec<(TenantId, MatrixCell)>>,
    }

    impl QueueStore {
        fn new(nodes: Vec<Node>) -> Arc<Self> {
            Arc::new(Self {
                inner: aiec_storage::MemoryRepository::new(),
                nodes,
                inflight: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                executions: AtomicUsize::new(0),
                cells: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl MetadataStore for QueueStore {
        async fn create_sandbox(&self, value: Sandbox) -> Result<(), CoreError> {
            self.inner.create_sandbox(value).await
        }
        async fn get_sandbox(&self, tenant: TenantId, id: SandboxId) -> Result<Sandbox, CoreError> {
            self.inner.get_sandbox(tenant, id).await
        }
        async fn list_sandboxes(&self, tenant: TenantId) -> Result<Vec<Sandbox>, CoreError> {
            self.inner.list_sandboxes(tenant).await
        }
        async fn update_state(
            &self,
            tenant: TenantId,
            id: SandboxId,
            expected: SandboxState,
            next: SandboxState,
            runtime_path: Option<String>,
        ) -> Result<Sandbox, CoreError> {
            self.inner
                .update_state(tenant, id, expected, next, runtime_path)
                .await
        }
        async fn update_state_with_lease(
            &self,
            tenant: TenantId,
            id: SandboxId,
            expected: SandboxState,
            next: SandboxState,
            lease_id: LeaseId,
            generation: i64,
        ) -> Result<(), CoreError> {
            self.inner
                .update_state_with_lease(tenant, id, expected, next, lease_id, generation)
                .await
        }
        async fn delete_sandbox(&self, tenant: TenantId, id: SandboxId) -> Result<(), CoreError> {
            self.inner.delete_sandbox(tenant, id).await
        }
        async fn put_key(&self, value: ApiKeyRecord) -> Result<(), CoreError> {
            self.inner.put_key(value).await
        }
        async fn revoke_key(&self, tenant: TenantId, id: Uuid) -> Result<(), CoreError> {
            self.inner.revoke_key(tenant, id).await
        }
        async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, CoreError> {
            self.inner.find_key(digest).await
        }
        async fn list_keys(&self, tenant: TenantId) -> Result<Vec<ApiKeyRecord>, CoreError> {
            self.inner.list_keys(tenant).await
        }
        async fn put_snapshot(&self, value: Snapshot) -> Result<(), CoreError> {
            self.inner.put_snapshot(value).await
        }
        async fn get_snapshot(
            &self,
            tenant: TenantId,
            id: SnapshotId,
        ) -> Result<Snapshot, CoreError> {
            self.inner.get_snapshot(tenant, id).await
        }
        async fn list_snapshots(
            &self,
            tenant: TenantId,
            sandbox: SandboxId,
        ) -> Result<Vec<Snapshot>, CoreError> {
            self.inner.list_snapshots(tenant, sandbox).await
        }
        async fn delete_snapshot(&self, tenant: TenantId, id: SnapshotId) -> Result<(), CoreError> {
            self.inner.delete_snapshot(tenant, id).await
        }
        async fn append_usage(&self, value: UsageEvent) -> Result<(), CoreError> {
            self.inner.append_usage(value).await
        }
        async fn usage(&self, tenant: TenantId) -> Result<Vec<UsageSummary>, CoreError> {
            self.inner.usage(tenant).await
        }
        async fn register_node(&self, value: Node) -> Result<Uuid, CoreError> {
            self.inner.register_node(value).await
        }
        async fn put_tenant(&self, value: TenantRecord) -> Result<(), CoreError> {
            self.inner.put_tenant(value).await
        }
        async fn get_tenant(&self, id: TenantId) -> Result<TenantRecord, CoreError> {
            self.inner.get_tenant(id).await
        }
        async fn list_sandbox_events(
            &self,
            tenant: TenantId,
            sandbox: SandboxId,
            limit: u32,
        ) -> Result<Vec<SandboxEvent>, CoreError> {
            self.inner.list_sandbox_events(tenant, sandbox, limit).await
        }
        async fn put_stored_snapshot(&self, value: StoredSnapshot) -> Result<(), CoreError> {
            self.inner.put_stored_snapshot(value).await
        }
        async fn get_stored_snapshot(
            &self,
            tenant: TenantId,
            id: SnapshotId,
        ) -> Result<StoredSnapshot, CoreError> {
            self.inner.get_stored_snapshot(tenant, id).await
        }
        async fn list_stored_snapshots(
            &self,
            tenant: TenantId,
            sandbox: SandboxId,
        ) -> Result<Vec<StoredSnapshot>, CoreError> {
            self.inner.list_stored_snapshots(tenant, sandbox).await
        }
        async fn create_sandbox_idempotent(
            &self,
            tenant: TenantId,
            request_id: RequestId,
            sandbox: Sandbox,
        ) -> Result<Sandbox, CoreError> {
            self.inner
                .create_sandbox_idempotent(tenant, request_id, sandbox)
                .await
        }
        async fn register_worker(&self, value: WorkerRegistration) -> Result<Uuid, CoreError> {
            self.inner.register_worker(value).await
        }
        async fn heartbeat_worker(
            &self,
            heartbeat: WorkerHeartbeat,
        ) -> Result<WorkerStatus, CoreError> {
            self.inner.heartbeat_worker(heartbeat).await
        }
        async fn get_worker(&self, node_id: WorkerId) -> Result<WorkerStatus, CoreError> {
            self.inner.get_worker(node_id).await
        }
        async fn list_workers(
            &self,
            _include_unhealthy: bool,
        ) -> Result<Vec<WorkerStatus>, CoreError> {
            Ok(self
                .nodes
                .iter()
                .flat_map(|node| {
                    [RuntimeKind::Docker, RuntimeKind::Firecracker].map(|runtime| {
                        let full_kernel = runtime == RuntimeKind::Firecracker;
                        WorkerStatus {
                            registration: WorkerRegistration {
                                node_id: node.id,
                                name: node.name.clone(),
                                runtime,
                                capabilities: RuntimeCapabilities {
                                    isolation: if full_kernel {
                                        RuntimeIsolation::MicroVm
                                    } else {
                                        RuntimeIsolation::Container
                                    },
                                    exec: true,
                                    files: true,
                                    full_kernel_isolation: full_kernel,
                                    ..Default::default()
                                },
                                control_endpoint: "http://unused".into(),
                                total_vcpus: node.available_vcpus,
                                total_memory_bytes: node.available_memory_bytes,
                                total_disk_bytes: node.available_disk_bytes,
                                available_vcpus: node.available_vcpus,
                                available_memory_bytes: node.available_memory_bytes,
                                available_disk_bytes: node.available_disk_bytes,
                                healthy: node.healthy,
                                version: 1,
                                metadata: json!({}),
                                started_at: node.last_heartbeat,
                                last_heartbeat: node.last_heartbeat,
                            },
                            sandbox_count: 0,
                            observed_sandbox_count: 0,
                            last_error: None,
                            accepting_sandboxes: true,
                            drain_reason: None,
                        }
                    })
                })
                .collect())
        }
        async fn set_worker_draining(
            &self,
            node_id: WorkerId,
            draining: bool,
            reason: Option<&str>,
        ) -> Result<WorkerStatus, CoreError> {
            self.inner
                .set_worker_draining(node_id, draining, reason)
                .await
        }
        async fn claim_worker_assignments(
            &self,
            node_id: WorkerId,
            limit: u32,
            lease_ttl_seconds: u64,
        ) -> Result<Vec<WorkerAssignment>, CoreError> {
            self.inner
                .claim_worker_assignments(node_id, limit, lease_ttl_seconds)
                .await
        }
        async fn list_worker_assignments(
            &self,
            tenant: TenantId,
            node_id: WorkerId,
            status: Option<&str>,
            limit: u32,
        ) -> Result<Vec<WorkerAssignment>, CoreError> {
            self.inner
                .list_worker_assignments(tenant, node_id, status, limit)
                .await
        }
        async fn list_worker_assignments_for_node(
            &self,
            node_id: WorkerId,
            status: Option<&str>,
            limit: u32,
        ) -> Result<Vec<WorkerAssignment>, CoreError> {
            self.inner
                .list_worker_assignments_for_node(node_id, status, limit)
                .await
        }
        async fn get_worker_lease(
            &self,
            tenant: TenantId,
            lease_id: LeaseId,
        ) -> Result<WorkerLease, CoreError> {
            self.inner.get_worker_lease(tenant, lease_id).await
        }
        async fn get_active_worker_lease(
            &self,
            tenant: TenantId,
            sandbox: SandboxId,
        ) -> Result<WorkerLease, CoreError> {
            self.inner.get_active_worker_lease(tenant, sandbox).await
        }
        async fn renew_worker_lease(
            &self,
            tenant: TenantId,
            lease_id: LeaseId,
            generation: i64,
            ttl_seconds: u64,
        ) -> Result<WorkerLease, CoreError> {
            self.inner
                .renew_worker_lease(tenant, lease_id, generation, ttl_seconds)
                .await
        }
        async fn complete_worker_lease(
            &self,
            tenant: TenantId,
            lease_id: LeaseId,
            generation: i64,
            result: Value,
        ) -> Result<WorkerLease, CoreError> {
            self.inner
                .complete_worker_lease(tenant, lease_id, generation, result)
                .await
        }
        async fn release_worker_lease(
            &self,
            tenant: TenantId,
            lease_id: LeaseId,
            generation: i64,
            reason: &str,
        ) -> Result<WorkerLease, CoreError> {
            self.inner
                .release_worker_lease(tenant, lease_id, generation, reason)
                .await
        }
        async fn reconcile_expired_leases(
            &self,
            limit: u32,
        ) -> Result<Vec<ReconciliationAction>, CoreError> {
            self.inner.reconcile_expired_leases(limit).await
        }
        async fn reassign_expired_lease(
            &self,
            lease_id: LeaseId,
        ) -> Result<Option<Reassignment>, CoreError> {
            self.inner.reassign_expired_lease(lease_id).await
        }
        async fn sandbox_ownership(
            &self,
            sandbox_id: SandboxId,
        ) -> Result<Option<SandboxOwnership>, CoreError> {
            self.inner.sandbox_ownership(sandbox_id).await
        }
        async fn list_reconciliation_actions(
            &self,
            tenant: TenantId,
            limit: u32,
        ) -> Result<Vec<ReconciliationAction>, CoreError> {
            self.inner.list_reconciliation_actions(tenant, limit).await
        }
        async fn begin_sandbox_operation(
            &self,
            value: SandboxOperation,
        ) -> Result<SandboxOperation, CoreError> {
            self.inner.begin_sandbox_operation(value).await
        }
        async fn complete_sandbox_operation(
            &self,
            tenant: TenantId,
            request_id: RequestId,
            result: Value,
        ) -> Result<SandboxOperation, CoreError> {
            self.inner
                .complete_sandbox_operation(tenant, request_id, result)
                .await
        }
        async fn fail_sandbox_operation(
            &self,
            tenant: TenantId,
            request_id: RequestId,
            error: Value,
        ) -> Result<SandboxOperation, CoreError> {
            self.inner
                .fail_sandbox_operation(tenant, request_id, error)
                .await
        }
        async fn get_sandbox_operation(
            &self,
            tenant: TenantId,
            request_id: RequestId,
        ) -> Result<SandboxOperation, CoreError> {
            self.inner.get_sandbox_operation(tenant, request_id).await
        }
        async fn put_image(&self, value: ImageRecord) -> Result<(), CoreError> {
            self.inner.put_image(value).await
        }
        async fn get_image(&self, id: &str) -> Result<ImageRecord, CoreError> {
            self.inner.get_image(id).await
        }
        async fn append_audit_event(&self, event: AuditEvent) -> Result<(), CoreError> {
            self.inner.append_audit_event(event).await
        }
        async fn list_audit_events(
            &self,
            tenant: Option<TenantId>,
            action: Option<&str>,
            limit: u32,
        ) -> Result<Vec<AuditEvent>, CoreError> {
            self.inner.list_audit_events(tenant, action, limit).await
        }
        fn supports_run_queue(&self) -> bool {
            true
        }

        async fn list_nodes(&self) -> Result<Vec<Node>, CoreError> {
            Ok(self.nodes.clone())
        }

        async fn get_run(&self, tenant: TenantId, id: Uuid) -> Result<Run, CoreError> {
            self.cells
                .lock()
                .expect("cells")
                .iter()
                .find(|(owner, cell)| *owner == tenant && cell.run.id == id)
                .map(|(_, cell)| cell.run.clone())
                .ok_or_else(|| CoreError::NotFound("run".into()))
        }

        async fn run_queue_finished(&self, tenant: TenantId, id: Uuid) -> Result<bool, CoreError> {
            Ok(self.get_run(tenant, id).await?.state.is_terminal())
        }

        async fn enqueue_run(
            &self,
            mut run: Run,
            _request: Value,
            _limits: RunQueueLimits,
        ) -> Result<Run, CoreError> {
            {
                let mut cells = self.cells.lock().expect("cells");
                if let Some(key) = &run.idempotency_key
                    && let Some((_, stored)) = cells.iter().find(|(owner, cell)| {
                        *owner == run.tenant_id && cell.run.idempotency_key.as_ref() == Some(key)
                    })
                {
                    return Ok(stored.run.clone());
                }
                let identity = run.matrix_cell.as_ref();
                cells.push((
                    run.tenant_id,
                    MatrixCell {
                        index: identity.map(|cell| cell.index),
                        axis: identity.map(|cell| cell.axis.clone()),
                        run: run.clone(),
                    },
                ));
            }
            self.executions.fetch_add(1, Ordering::SeqCst);
            let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            let uneven = run.id.as_u128().is_multiple_of(2);
            tokio::time::sleep(Duration::from_millis(if uneven { 2 } else { 12 })).await;
            self.inflight.fetch_sub(1, Ordering::SeqCst);
            run.state = RunState::Succeeded;
            run.started_at = Some(run.requested_at);
            run.completed_at = Some(run.requested_at);
            let mut cells = self.cells.lock().expect("cells");
            let (_, stored) = cells
                .iter_mut()
                .find(|(_, cell)| cell.run.id == run.id)
                .expect("admitted run");
            stored.run = run.clone();
            Ok(run)
        }

        async fn list_matrix_cells(
            &self,
            tenant: TenantId,
            matrix: Uuid,
            limit: u32,
            after: Option<MatrixCursor>,
        ) -> Result<MatrixCellPage, CoreError> {
            let held = self.cells.lock().expect("cells");
            let mut owned: Vec<MatrixCell> = held
                .iter()
                .filter(|(owner, cell)| *owner == tenant && cell.run.matrix_id == Some(matrix))
                .map(|(_, cell)| cell.clone())
                .collect();
            owned.sort_by(|a, b| {
                a.run
                    .requested_at
                    .cmp(&b.run.requested_at)
                    .then(a.run.id.cmp(&b.run.id))
            });
            if let Some(after) = after {
                owned.retain(|cell| {
                    (cell.run.requested_at, cell.run.id) > (after.requested_at, after.id)
                });
            }
            let limit = limit.clamp(1, 256) as usize;
            let more = owned.len() > limit;
            owned.truncate(limit);
            let next = match (more, owned.last()) {
                (true, Some(last)) => Some(MatrixCursor {
                    requested_at: last.run.requested_at,
                    id: last.run.id,
                }),
                _ => None,
            };
            Ok(MatrixCellPage { cells: owned, next })
        }
    }

    /// One node with room for a stated number of default-sized cells.
    fn node_with(vcpus: u32, gigabytes: u64, healthy: bool) -> Node {
        Node {
            id: new_id(),
            name: "node".to_owned(),
            available_vcpus: vcpus,
            available_memory_bytes: gigabytes * 1024 * 1024 * 1024,
            available_disk_bytes: 64 * 1024 * 1024 * 1024,
            sandbox_count: 0,
            healthy,
            last_heartbeat: chrono::Utc::now(),
        }
    }

    fn matrix_body(cells: usize, max_parallel: usize) -> Value {
        let cells: Vec<Value> = (0..cells)
            .map(|index| {
                json!({
                    "axis": {"task": format!("cell-{index}")},
                    "request": {"workload": {"command": ["true"]}},
                })
            })
            .collect();
        json!({"cells": cells, "options": {"max_parallel": max_parallel}})
    }

    /// A batch is bounded by what the cluster can actually take, not by what the
    /// caller asked for, and it says which bound it used.
    ///
    /// The cluster here has room for far more cells than the queue executes at
    /// once, so the binding ceiling is the queue's own `max_active`: twelve
    /// cells were admitted and twelve came back, four at a time.
    #[tokio::test]
    async fn a_matrix_runs_no_more_cells_at_once_than_the_cluster_executes() {
        let store = QueueStore::new(vec![node_with(16, 64, true)]);
        let app = eval_app_for(new_id(), store.clone(), vec![Scope::SandboxesWrite]);
        let (status, body) = post_json(app, "/eval/matrix", matrix_body(12, 12)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["max_parallel"], 12, "the ask is reported as asked");
        assert_eq!(
            body["effective_parallel"], 4,
            "a twelve-cell batch must run no wider than the queue executes: {body}"
        );
        assert_eq!(body["results"].as_array().expect("cells").len(), 12);
        assert_eq!(
            store.peak(),
            4,
            "the queue saw more cells at once than it executes"
        );
    }

    /// A matrix that is keyed for some cells and not for others is refused, and
    /// refused before anything runs.
    ///
    /// Keyed cells keep their keys, so a retry resolves them to the first
    /// submission's runs under a different matrix id; unkeyed cells are keyed
    /// against a freshly minted id and execute again. The clash is only
    /// detectable once the batch is spent, so the request is turned away at the
    /// door with a count of what to fix and not one cell executed.
    #[tokio::test]
    async fn a_partly_keyed_matrix_is_refused_without_executing_a_cell() {
        let store = QueueStore::new(vec![node_with(16, 64, true)]);
        let app = eval_app_for(new_id(), store.clone(), vec![Scope::SandboxesWrite]);
        let mut body = matrix_body(4, 4);
        let cells = body["cells"].as_array_mut().unwrap();
        cells[0]["request"]["idempotency_key"] = json!("caller-keyed-0");
        cells[3]["request"]["idempotency_key"] = json!("caller-keyed-3");
        let (status, rejected) = post_json(app.clone(), "/eval/matrix", body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
        let message = rejected["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("every cell") && message.contains("no cell"),
            "{rejected}"
        );
        assert_eq!(
            store.executions.load(Ordering::SeqCst),
            0,
            "a refused matrix must not have executed anything"
        );
        // And the same submission with every cell keyed is accepted, so the
        // refusal is about the mixture rather than about keys themselves.
        for (index, cell) in body["cells"].as_array_mut().unwrap().iter_mut().enumerate() {
            if cell["request"]["idempotency_key"].is_null() {
                cell["request"]["idempotency_key"] = json!(format!("all-keyed-{index}"));
            }
        }
        let (status, accepted) = post_json(app, "/eval/matrix", body).await;
        assert_eq!(status, StatusCode::OK, "{accepted}");
        assert_eq!(store.executions.load(Ordering::SeqCst), 4);
    }

    /// A cell that is refused comes back as a cell with no run, beside the cells
    /// that ran.
    ///
    /// The cells execute concurrently, so a matrix whose first cell asks for a
    /// secret this deployment does not hold settles the rest on real machines
    /// and then fails. Answering "400" and keeping the matrix id to itself
    /// would leave those runs executed, billed, and reachable only through an id
    /// the caller was never told and cannot derive.
    #[tokio::test]
    async fn a_refused_cell_does_not_hide_the_cells_that_ran() {
        let store = QueueStore::new(vec![node_with(16, 64, true)]);
        let app = eval_app_for(
            new_id(),
            store.clone(),
            vec![Scope::SandboxesWrite, Scope::SandboxesRead],
        );
        let mut body = matrix_body(3, 3);
        // The resolver is disabled in this app, so any secret request fails.
        body["cells"][1]["request"]["workload"]["secrets"] = json!(["not-held"]);
        let (status, matrix) = post_json(app.clone(), "/eval/matrix", body).await;
        assert_eq!(status, StatusCode::OK, "{matrix}");
        let cells = matrix["results"]
            .as_array()
            .expect("every cell is reported");
        assert_eq!(cells.len(), 3, "{matrix}");
        let refused = &cells[1];
        assert_eq!(refused["axis"]["task"], "cell-1", "{refused}");
        assert!(
            refused["run"].is_null(),
            "a refused cell has no run to report: {refused}"
        );
        let reason = refused["error"].as_str().unwrap_or_default();
        assert!(!reason.is_empty(), "and it says why: {refused}");
        // The cells around it really did run, and they are still findable.
        for cell in [&cells[0], &cells[2]] {
            assert!(!cell["run"]["id"].as_str().unwrap_or_default().is_empty());
            assert!(cell["error"].is_null(), "{cell}");
        }
        assert_eq!(store.executions.load(Ordering::SeqCst), 2, "only two ran");
        let id = matrix["matrix_id"].as_str().expect("a matrix id");
        let (status, recovered) = get_json(app, &format!("/eval/matrix/{id}?limit=10")).await;
        assert_eq!(status, StatusCode::OK, "{recovered}");
        assert_eq!(
            recovered["cells"].as_array().expect("cells").len(),
            2,
            "the runs that executed must be recoverable by matrix id: {recovered}"
        );
    }

    /// A cluster with nothing free is a reason to wait, not a reason to refuse.
    ///
    /// The batch is admitted in full and settles cell by cell as slots free up,
    /// and the response says it is running one at a time rather than pretending
    /// it got the width it asked for.
    #[tokio::test]
    async fn a_busy_cluster_queues_a_matrix_instead_of_refusing_it() {
        let store = QueueStore::new(vec![node_with(0, 0, true)]);
        let app = eval_app_for(new_id(), store.clone(), vec![Scope::SandboxesWrite]);
        let (status, body) = post_json(app, "/eval/matrix", matrix_body(3, 8)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["effective_parallel"], 1, "{body}");
        assert_eq!(body["results"].as_array().expect("cells").len(), 3);
        assert_eq!(
            store.peak(),
            1,
            "a full cluster still gets exactly one waiter"
        );
    }

    /// A cell's labels stay on its own run, whatever order the cells finished
    /// in and whatever each of them needs from a runtime.
    ///
    /// The matrix asks for twelve machines and the queue runs four, with uneven
    /// cells finishing out of order, and one cell demands a runtime the rest do
    /// not. Every cell must still come back beside the axis it was submitted
    /// with, carrying the requirements it asked for: a run that quietly lost
    /// its isolation class or swapped axes with a neighbour would be an
    /// evaluation that reported on the wrong experiment.
    #[tokio::test]
    async fn matrix_cells_keep_their_axis_and_their_requirements() {
        let store = QueueStore::new(vec![node_with(16, 64, true)]);
        let app = eval_app_for(new_id(), store.clone(), vec![Scope::SandboxesWrite]);
        let mut body = matrix_body(8, 8);
        // One cell needs a runtime the others do not, and it is not the first.
        body["cells"][5]["request"] = json!({
            "workload": {"command": ["true"]},
            "requirements": {"full_kernel_isolation": true},
            "requested_runtime": "firecracker",
        });
        let (status, response) = post_json(app, "/eval/matrix", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let matrix = response["matrix_id"].as_str().expect("a matrix id");
        let results = response["results"].as_array().expect("cells");
        for (index, cell) in results.iter().enumerate() {
            assert_eq!(cell["axis"]["task"], format!("cell-{index}"), "{cell}");
            assert_eq!(cell["run"]["matrix_id"], matrix, "{cell}");
            assert_eq!(
                cell["run"]["requirements"]["full_kernel_isolation"],
                json!(index == 5),
                "a cell's isolation requirement was rewritten: {cell}"
            );
        }
        let recovered = store
            .list_matrix_cells(
                results[0]["run"]["tenant_id"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
                matrix.parse().unwrap(),
                256,
                None,
            )
            .await
            .expect("durable matrix");
        for (index, cell) in recovered.cells.iter().enumerate() {
            let identity = cell.run.matrix_cell.as_ref().expect("admitted identity");
            assert_eq!(identity.index, index as u32);
            assert_eq!(identity.axis["task"], format!("cell-{index}"));
        }
    }

    #[tokio::test]
    async fn replayed_matrix_joins_its_original_runs_and_recovers_original_labels() {
        let store = QueueStore::new(vec![node_with(16, 64, true)]);
        let app = eval_app_for(
            new_id(),
            store.clone(),
            vec![Scope::SandboxesWrite, Scope::SandboxesRead],
        );
        let mut request = matrix_body(3, 3);
        for (index, cell) in request["cells"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            cell["request"]["idempotency_key"] = json!(format!("recover-{index}"));
        }
        let (status, first) = post_json(app.clone(), "/eval/matrix", request.clone()).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let (status, replay) = post_json(app.clone(), "/eval/matrix", request).await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["matrix_id"], first["matrix_id"]);
        for (original, repeated) in first["results"]
            .as_array()
            .unwrap()
            .iter()
            .zip(replay["results"].as_array().unwrap())
        {
            assert_eq!(repeated["run"]["id"], original["run"]["id"]);
        }
        assert_eq!(
            store.executions.load(Ordering::SeqCst),
            3,
            "replay executed a cell twice"
        );
        let matrix = replay["matrix_id"].as_str().unwrap();
        let (status, recovered) = get_json(app, &format!("/eval/matrix/{matrix}?limit=2")).await;
        assert_eq!(status, StatusCode::OK, "{recovered}");
        assert!(
            recovered["next"].is_object(),
            "a bounded read lost its continuation"
        );
        assert_eq!(recovered["cells"][0]["axis"]["task"], "cell-0");
        assert_eq!(recovered["cells"][1]["axis"]["task"], "cell-1");
        assert_eq!(
            recovered["cells"][0]["run"]["id"],
            first["results"][0]["run"]["id"]
        );
    }

    /// A recovered matrix is one bounded page, in order, with its labels.
    ///
    /// Twelve cells and a limit of five: three reads, no cell twice and none
    /// missing, each still attached to the axis it was submitted with.
    #[tokio::test]
    async fn a_matrix_is_recovered_in_bounded_pages_that_keep_their_order() {
        let tenant = new_id();
        let other = new_id();
        let matrix = new_id();
        let store = QueueStore::new(vec![node_with(16, 64, true)]);
        {
            let mut cells = store.cells.lock().expect("cells");
            for index in 0..12u32 {
                for owner in [tenant, other] {
                    let mut axis = BTreeMap::new();
                    axis.insert("task".to_owned(), format!("cell-{index}"));
                    // Whole seconds, in submission order, so the page boundary
                    // the cursor names is one the ordering can actually break on.
                    let requested_at =
                        chrono::DateTime::from_timestamp(1_700_000_000 + i64::from(index), 0)
                            .expect("a whole second");
                    let run = aiec_core::run::Run {
                        id: new_id(),
                        tenant_id: owner,
                        state: RunState::Succeeded,
                        requested_at,
                        queued_at: Some(requested_at),
                        started_at: None,
                        completed_at: None,
                        workload: Default::default(),
                        resources: Default::default(),
                        requirements: Default::default(),
                        placement: Default::default(),
                        results: Default::default(),
                        failure_reason: None,
                        retention: Default::default(),
                        retained_sandbox_id: None,
                        retained_until: None,
                        idempotency_key: None,
                        parent_run_id: None,
                        matrix_id: Some(matrix),
                        matrix_cell: Some(aiec_core::run::MatrixCellIdentity {
                            index,
                            axis: axis.clone(),
                        }),
                    };
                    cells.push((
                        owner,
                        MatrixCell {
                            run,
                            index: Some(index),
                            axis: Some(axis),
                        },
                    ));
                }
            }
        }
        let reader = eval_app_for(tenant, store, vec![Scope::SandboxesRead]);
        let mut seen: Vec<String> = Vec::new();
        let mut path = format!("/eval/matrix/{matrix}?limit=5");
        for page in 0..3 {
            let (status, body) = get_json(reader.clone(), &path).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let cells = body["cells"].as_array().expect("cells");
            assert_eq!(cells.len(), if page < 2 { 5 } else { 2 }, "{body}");
            for cell in cells {
                seen.push(cell["axis"]["task"].as_str().expect("a task").to_owned());
            }
            match body["next"].as_object() {
                Some(next) => {
                    let requested_at = next["requested_at"].as_str().expect("a cursor");
                    let id = next["id"].as_str().expect("a cursor");
                    path = format!(
                        "/eval/matrix/{matrix}?limit=5&after_requested_at={requested_at}&after_id={id}"
                    );
                }
                None => {
                    assert_eq!(page, 2, "the last page must be the last one: {body}");
                }
            }
        }
        assert_eq!(
            seen,
            (0..12)
                .map(|index| format!("cell-{index}"))
                .collect::<Vec<_>>(),
            "paging must return every cell once, in submission order"
        );
    }

    /// A matrix is readable by a key that may read, and invisible to a key that
    /// may only start things - and a matrix belonging to another tenant does not
    /// exist as far as this one is concerned.
    #[tokio::test]
    async fn reading_a_matrix_needs_the_read_scope_and_respects_the_tenant() {
        let tenant = new_id();
        let store = QueueStore::new(vec![node_with(16, 64, true)]);
        store.cells.lock().expect("cells").push((
            new_id(),
            MatrixCell {
                run: cell_run(new_id(), new_id(), RunState::Succeeded),
                index: Some(0),
                axis: Some(BTreeMap::from([("task".to_owned(), "cell-0".to_owned())])),
            },
        ));
        let matrix = new_id();
        store.cells.lock().expect("cells").push((
            tenant,
            MatrixCell {
                run: cell_run(tenant, matrix, RunState::Succeeded),
                index: Some(0),
                axis: Some(BTreeMap::from([("task".to_owned(), "cell-0".to_owned())])),
            },
        ));

        let writer = eval_app_for(tenant, store.clone(), vec![Scope::SandboxesWrite]);
        let (status, body) = get_json(writer, &format!("/eval/matrix/{matrix}")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], "forbidden");

        let reader = eval_app_for(tenant, store.clone(), vec![Scope::SandboxesRead]);
        let (status, body) = get_json(reader.clone(), &format!("/eval/matrix/{matrix}")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["cells"].as_array().expect("cells").len(), 1);

        // Somebody else's matrix is not an empty page; it is nothing at all.
        let stranger = eval_app_for(new_id(), store, vec![Scope::SandboxesRead]);
        let (status, body) = get_json(stranger, &format!("/eval/matrix/{matrix}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], "not_found");
    }

    fn cell_run(tenant: TenantId, matrix: Uuid, state: RunState) -> Run {
        aiec_core::run::Run {
            id: new_id(),
            tenant_id: tenant,
            state,
            requested_at: chrono::Utc::now(),
            queued_at: Some(chrono::Utc::now()),
            started_at: None,
            completed_at: None,
            workload: Default::default(),
            resources: Default::default(),
            requirements: Default::default(),
            placement: Default::default(),
            results: Default::default(),
            failure_reason: None,
            retention: Default::default(),
            retained_sandbox_id: None,
            retained_until: None,
            idempotency_key: None,
            parent_run_id: None,
            matrix_id: Some(matrix),
            matrix_cell: None,
        }
    }
}
