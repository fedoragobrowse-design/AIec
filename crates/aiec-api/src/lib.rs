use aiec_core::*;
use aiec_core::{
    platform::Platform,
    policy::PolicyOperation,
    run::{CleanupReport, Run, RunArtifactRef, RunEvent, RunState},
    runtime::SandboxRuntime,
    snapshots::{SnapshotKind, SnapshotRequest, verify_archive_checksum},
    storage::{ArtifactStore, GetObjectOptions, MetadataStore, PageCursor, SandboxPage},
};
use chrono::DateTime;
pub mod account;
pub mod artifact_gc;
mod composition;
pub mod eval_matrix;
pub mod evaluations;
pub mod guard;
mod guard_proposals;
mod guard_release;
pub use guard_proposals::ReviewProposalBody;
pub use guard_release::ReleaseBody;
pub mod omp;
#[cfg(test)]
mod provision_ownership_tests;
pub mod ratelimit;
pub(crate) mod repo_cache;
#[cfg(test)]
mod run_paging_tests;
mod run_queue;
pub mod run_secrets;
pub mod runs;
mod worker;
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use chrono::Utc;
pub use composition::{DefaultPolicy, DevelopmentScheduler};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use std::sync::atomic::AtomicI64;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;
pub use worker::{
    HttpOwnershipVerifier, HttpWorkerClient, OwnershipCheck, OwnershipRecord, OwnershipVerifier,
    WorkerClient, WorkerClientError, WorkerError, WorkerGuestProfile, WorkerHeartbeat,
    WorkerOperation, WorkerRegistration, WorkerRequest, WorkerResponse, WorkerRuntime,
    WorkerService, WorkerStatus, WorkerValue,
};

#[derive(Clone)]
pub struct AppState {
    pub platform: Platform,
    runtime_kind: RuntimeKind,
    production: bool,
    requests: Arc<AtomicU64>,
    worker_token: Option<Arc<str>>,
    lease_ttl_seconds: u64,
    secrets: SecretStore,
    run_secrets: run_secrets::RunSecretResolver,
    repo_cache: Arc<repo_cache::RepositoryCache>,
    run_queue_limits: aiec_core::run_queue::RunQueueLimits,
    upload_slots: Arc<Semaphore>,
    snapshot_slots: Arc<Semaphore>,
    /// Per-tenant / per-client admission control for the public API.
    limiter: Arc<ratelimit::RateLimiter>,
    /// Aggregate execution budget for hosted capacity. Reaching it stops new
    /// sandbox creation instead of risking a provider overage.
    execution_budget: Option<ExecutionBudget>,
    /// When true, only microVM-class runtimes are offered to tenants.
    hosted_only: bool,
    /// Invite codes accepted by public signup. Empty means signup is closed.
    invites: Arc<Vec<String>>,
    /// Incident notifier for Guard quarantines. Absent means notifications are
    /// explicitly disabled, which is reported as such rather than as success.
    guard_notifier: Option<Arc<dyn aiec_guard::watchdog::Notifier>>,
}

/// A global ceiling on hosted execution spend.
#[derive(Clone, Debug)]
pub struct ExecutionBudget {
    /// Total units the control plane may consume before creation stops.
    limit_units: i64,
    /// Units consumed so far.
    spent_units: Arc<AtomicI64>,
}

impl ExecutionBudget {
    fn new(limit_units: i64) -> Self {
        Self {
            limit_units,
            spent_units: Arc::new(AtomicI64::new(0)),
        }
    }

    /// Returns true when another unit of spend fits inside the ceiling.
    fn admits(&self) -> bool {
        self.spent_units.load(Ordering::Relaxed) < self.limit_units
    }

    /// Records consumed usage. The durable usage ledger remains the billing
    /// record; this is the stop-loss that protects a finite free allowance.
    fn charge(&self, units: i64) {
        self.spent_units.fetch_add(units.max(0), Ordering::Relaxed);
    }
}

type SecretMap = HashMap<String, SecretEntry>;
type SecretStore = Arc<Mutex<HashMap<(TenantId, Uuid), SecretMap>>>;
struct SecretEntry {
    value: String,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Deserialize)]
struct SecretBody {
    value: String,
}

#[derive(Serialize)]
struct SecretMetadata {
    name: String,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Deserialize)]
struct ArtifactBody {
    content_base64: String,
}

#[derive(Serialize)]
struct ArtifactResponse {
    metadata: Option<aiec_core::storage::ObjectMetadata>,
    content_base64: Option<String>,
}

#[derive(Serialize)]
struct ArtifactDownload {
    key: String,
    size_bytes: u64,
    checksum_sha256: String,
    content_base64: String,
}

const ARTIFACT_MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_SECRETS_PER_SANDBOX: usize = 32;

fn artifact_key(tenant: TenantId, sandbox: Uuid, name: &str) -> Result<String, ApiFailure> {
    if name.is_empty()
        || name.len() > 128
        || name
            .as_bytes()
            .iter()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "artifact name contains unsupported characters",
        ));
    }
    Ok(format!(
        "tenants/{tenant}/sandboxes/{sandbox}/artifacts/{name}"
    ))
}

/// The URL a run artifact's bytes are served from.
///
/// The name is percent-encoded rather than pasted in. An artifact's name is the
/// path it had inside the sandbox - `/workspace/report.txt` - so concatenating it
/// produced a URL the route could not match, and a listing whose own links 404.
/// Only the reserved characters are escaped, which leaves an ordinary name such as
/// `report.txt` readable and still round-trips a nested one exactly.
fn run_artifact_download_url(run: Uuid, name: &str) -> String {
    let mut encoded = String::with_capacity(name.len());
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("/v1/runs/{run}/artifacts/{encoded}")
}

fn validate_secret_name(name: &str) -> Result<(), ApiFailure> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "secret name must contain only uppercase ASCII letters, digits, and underscores",
        ));
    }
    Ok(())
}
impl AppState {
    pub fn new(platform: Platform) -> Self {
        Self::with_limits(platform, default_rate_limit(), None)
    }
    /// The development backend keeps the same admission behaviour so a
    /// self-hoster sees exactly what a public tenant experiences.
    pub fn development(platform: Platform) -> Self {
        Self::with_limits(platform, default_rate_limit(), None)
            .development_mode(RuntimeKind::BwrapDev)
    }
    fn with_limits(
        platform: Platform,
        limit: ratelimit::RateLimit,
        execution_budget: Option<ExecutionBudget>,
    ) -> Self {
        Self {
            lease_ttl_seconds: 300,
            platform,
            production: true,
            requests: Arc::new(AtomicU64::new(0)),
            runtime_kind: RuntimeKind::Firecracker,
            worker_token: None,
            secrets: Arc::new(Mutex::new(HashMap::new())),
            run_secrets: run_secrets::RunSecretResolver::disabled(),
            repo_cache: Arc::new(repo_cache::RepositoryCache::from_env()),
            guard_notifier: None,
            run_queue_limits: Default::default(),
            upload_slots: Arc::new(Semaphore::new(2)),
            snapshot_slots: Arc::new(Semaphore::new(2)),
            limiter: Arc::new(ratelimit::RateLimiter::new(limit)),
            execution_budget,
            // Permissive by default: a self-hoster may run any runtime they
            // configured. The Cloud composition root calls `with_hosted_only`
            // to restrict external tenants to microVM isolation.
            hosted_only: false,
            invites: Arc::new(Vec::new()),
        }
    }
    fn development_mode(mut self, kind: RuntimeKind) -> Self {
        self.production = false;
        self.runtime_kind = kind;
        self
    }
    pub fn with_run_secrets(mut self, resolver: run_secrets::RunSecretResolver) -> Self {
        self.run_secrets = resolver;
        self
    }
    pub fn run_secrets(&self) -> &run_secrets::RunSecretResolver {
        &self.run_secrets
    }
    pub fn with_run_queue_limits(mut self, limits: aiec_core::run_queue::RunQueueLimits) -> Self {
        self.run_queue_limits = limits;
        self
    }
    pub fn run_queue_limits(&self) -> aiec_core::run_queue::RunQueueLimits {
        self.run_queue_limits
    }
    /// The node-local repository object cache, consulted before a clone.
    pub(crate) fn repo_cache(&self) -> &Arc<repo_cache::RepositoryCache> {
        &self.repo_cache
    }
    /// Applies an explicit rate limit, used by the composition root.
    pub fn with_rate_limit(mut self, limit: ratelimit::RateLimit) -> Self {
        self.limiter = Arc::new(ratelimit::RateLimiter::new(limit));
        self
    }
    /// Applies a global execution budget in whole usage units.
    pub fn with_execution_budget(mut self, limit_units: i64) -> Self {
        self.execution_budget = Some(ExecutionBudget::new(limit_units.max(0)));
        self
    }
    /// True when a hosted execution budget is configured and already spent.
    pub fn execution_budget_exhausted(&self) -> bool {
        self.execution_budget
            .as_ref()
            .is_some_and(|budget| !budget.admits())
    }
    /// Charges the hosted execution budget for a sandbox of this shape.
    pub fn charge_execution(&self, units: i64) {
        if let Some(budget) = &self.execution_budget {
            budget.charge(units);
        }
    }
    /// The limiter applied to the public API.
    pub fn limiter(&self) -> &ratelimit::RateLimiter {
        &self.limiter
    }
    /// Whether this deployment offers a runtime to tenants.
    ///
    /// A hosted deployment refuses container and process runtimes outright, so
    /// an external tenant cannot request a weaker isolation boundary than the
    /// one they were given. Self-hosted deployments may opt out and offer every
    /// runtime they have configured.
    pub fn allows_runtime(&self, kind: RuntimeKind) -> bool {
        if self.hosted_only {
            return kind == RuntimeKind::Firecracker || kind == RuntimeKind::Hosted;
        }
        // A self-hoster is trusted with their own boundary; the rule that
        // untrusted workloads use microVMs is enforced by the Cloud deployment.
        true
    }
    /// Sets the invite codes accepted by public signup.
    pub fn with_invites(mut self, invites: Vec<String>) -> Self {
        self.invites = Arc::new(invites);
        self
    }
    /// The configured invite codes.
    pub fn invites(&self) -> &[String] {
        &self.invites
    }
    /// Restricts tenants to microVM-class runtimes.
    pub fn with_hosted_only(mut self, hosted_only: bool) -> Self {
        self.hosted_only = hosted_only;
        self
    }
    /// Attaches the incident notifier quarantines publish through.
    pub fn with_guard_notifier(
        mut self,
        notifier: Option<Arc<dyn aiec_guard::watchdog::Notifier>>,
    ) -> Self {
        self.guard_notifier = notifier;
        self
    }
    /// The configured incident notifier, or none when notifications are off.
    pub fn guard_notifier(&self) -> Option<Arc<dyn aiec_guard::watchdog::Notifier>> {
        self.guard_notifier.clone()
    }
    pub fn with_worker_token(mut self, token: impl Into<String>) -> Self {
        self.worker_token = Some(Arc::from(token.into().as_str()));
        self
    }
    pub fn with_lease_ttl(mut self, seconds: u64) -> Self {
        self.lease_ttl_seconds = seconds.clamp(1, 3600);
        self
    }
    pub fn with_runtime_kind(mut self, runtime_kind: RuntimeKind) -> Self {
        self.runtime_kind = runtime_kind;
        self
    }

    pub fn runtime_kind(&self) -> RuntimeKind {
        self.runtime_kind
    }
    pub fn runtime(&self) -> Arc<dyn SandboxRuntime> {
        self.platform.runtime()
    }
    pub fn runtime_registry(&self) -> Option<Arc<aiec_core::runtime::RuntimeRegistry>> {
        self.platform.runtime_registry()
    }

    pub fn runtime_for(&self, sandbox: &Sandbox) -> Result<Arc<dyn SandboxRuntime>, CoreError> {
        self.platform
            .runtime_registry()
            .and_then(|registry| registry.lookup(sandbox.runtime))
            .or_else(|| (self.runtime_kind == sandbox.runtime).then(|| self.platform.runtime()))
            .ok_or_else(|| {
                CoreError::Unavailable(format!(
                    "runtime {} is not registered",
                    sandbox.runtime.as_str()
                ))
            })
    }
    pub fn repository(&self) -> Arc<dyn MetadataStore> {
        self.platform.metadata_store()
    }
    pub fn scheduler(&self) -> Arc<dyn aiec_core::scheduler::Scheduler> {
        self.platform.scheduler()
    }
    pub fn artifact_store(&self) -> Option<Arc<dyn ArtifactStore>> {
        self.platform.artifact_store()
    }
    pub fn is_production(&self) -> bool {
        self.production
    }

    /// Commits a state transition that follows a worker-owned operation.
    ///
    /// When the sandbox is leased, the transition is fenced by the current
    /// lease generation, so a worker that has been superseded cannot commit a
    /// late result. Development stores without lease support keep the plain
    /// compare-and-set transition.
    async fn commit_state(
        &self,
        sandbox: &Sandbox,
        expected: SandboxState,
        next: SandboxState,
    ) -> Result<Sandbox, CoreError> {
        let ownership = match self.repository().sandbox_ownership(sandbox.id).await {
            Ok(ownership) => ownership,
            Err(CoreError::Unsupported(_)) => None,
            Err(error) => return Err(error),
        };
        match ownership {
            Some(ownership) => {
                self.repository()
                    .update_state_with_lease(
                        sandbox.tenant_id,
                        sandbox.id,
                        expected,
                        next,
                        ownership.lease_id,
                        ownership.generation,
                    )
                    .await?;
            }
            None if self.production && sandbox.runtime != RuntimeKind::Hosted => {
                return Err(CoreError::Transient(
                    "sandbox has no active unexpired lease".into(),
                ));
            }
            None => {
                self.repository()
                    .update_state(sandbox.tenant_id, sandbox.id, expected, next, None)
                    .await?;
            }
        }
        self.repository()
            .get_sandbox(sandbox.tenant_id, sandbox.id)
            .await
    }

    /// Commits a state transition that follows a worker-owned operation, fenced
    /// by the lease that operation ran under.
    ///
    /// `commit_state` cannot be used on a recovery path. It looks up who owns
    /// the sandbox *now* and fences against that, which is right for a worker
    /// asking "may I still write?" and wrong for a recovery pass asking "may I
    /// still write?" — both ask the same question of the store, but a recovery
    /// pass already knows its own lease, and re-reading is a way of asking a
    /// lease that is no longer its own. Between reading the reassignment and
    /// committing, the sandbox can be reassigned again; the store would then
    /// happily fence the stale pass against the *new* lease and the write
    /// would succeed on a sandbox this caller no longer owns.
    async fn commit_state_as(
        &self,
        sandbox: &Sandbox,
        expected: SandboxState,
        next: SandboxState,
        lease_id: LeaseId,
        generation: i64,
    ) -> Result<Sandbox, CoreError> {
        self.repository()
            .update_state_with_lease(
                sandbox.tenant_id,
                sandbox.id,
                expected,
                next,
                lease_id,
                generation,
            )
            .await?;
        self.repository()
            .get_sandbox(sandbox.tenant_id, sandbox.id)
            .await
    }

    async fn secret_values(
        &self,
        tenant_id: TenantId,
        sandbox_id: Uuid,
    ) -> BTreeMap<String, String> {
        let now = Utc::now();
        let mut secrets = self.secrets.lock().await;
        let Some(values) = secrets.get_mut(&(tenant_id, sandbox_id)) else {
            return BTreeMap::new();
        };
        values.retain(|_, entry| entry.expires_at > now);
        values
            .iter()
            .map(|(name, entry)| (name.clone(), entry.value.clone()))
            .collect()
    }
}
#[derive(Debug)]
pub(crate) struct ApiFailure {
    status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
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
            CoreError::QuotaExceeded(m) => {
                Self::new(StatusCode::TOO_MANY_REQUESTS, "quota_exceeded", m)
            }
            CoreError::Unavailable(m) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "backend_unavailable", m)
            }
            // Advertised as a distinct code so a client can retry on the type
            // rather than reading the message for a word it recognises.
            CoreError::Transient(m) => Self::new(StatusCode::CONFLICT, "transient", m),
            CoreError::Unsupported(m) => Self::new(StatusCode::NOT_IMPLEMENTED, "unsupported", m),
            CoreError::Backend(m) => Self::new(StatusCode::INTERNAL_SERVER_ERROR, "backend", m),
            CoreError::Io(e) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string())
            }
        }
    }
}
type ApiResult<T> = Result<Json<T>, ApiFailure>;

pub async fn bootstrap_api_key(
    repository: &dyn MetadataStore,
    raw_key: &str,
    tenant_id: TenantId,
    scopes: &[Scope],
) -> Result<Uuid, CoreError> {
    validate_api_key(raw_key)?;
    let digest = key_digest(raw_key);
    let validate_existing = |existing: ApiKeyRecord| -> Result<Uuid, CoreError> {
        if existing.tenant_id != tenant_id
            || existing.revoked_at.is_some()
            || existing
                .expires_at
                .is_some_and(|expires_at| expires_at <= Utc::now())
            || scopes.iter().any(|scope| !existing.scopes.contains(scope))
        {
            return Err(CoreError::Conflict(
                "bootstrap API key already exists with different ownership, lifecycle, or scopes"
                    .into(),
            ));
        }
        Ok(existing.id)
    };
    match repository.find_key(&digest).await {
        Ok(existing) => validate_existing(existing),
        Err(CoreError::NotFound(_)) => {
            let candidate = ApiKeyRecord {
                id: new_id(),
                tenant_id,
                digest,
                scopes: scopes.to_vec(),
                expires_at: None,
                revoked_at: None,
                // Bootstrap keys are operator-issued, not self-service, so the
                // label records that rather than pretending a stranger chose it.
                name: "bootstrap".to_string(),
                created_at: Utc::now(),
                last_used_at: None,
            };
            let candidate_id = candidate.id;
            match repository.put_key(candidate).await {
                Ok(()) => Ok(candidate_id),
                Err(CoreError::Conflict(_)) => repository
                    .find_key(&digest)
                    .await
                    .and_then(validate_existing),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}
pub fn router(state: AppState) -> Router {
    // Authentication selects the tenant bucket; refused credentials still
    // consume their peer bucket. Each protected request is admitted once.
    // Signup is deliberately outside the auth layer: it is how a stranger
    // obtains a credential in the first place. It is invite-gated, and rate
    // limited like everything else.
    let public = Router::new().route("/account", post(signup));
    let protected = protected_routes(&state).route("/account", get(current_account));
    let workers = worker_routes().layer(middleware::from_fn_with_state(state.clone(), worker_auth));
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .nest(
            "/v1",
            public.layer(middleware::from_fn_with_state(state.clone(), rate_limit)),
        )
        .nest(
            "/v1",
            protected
                .merge(key_routes())
                .layer(middleware::from_fn_with_state(state.clone(), auth)),
        )
        .nest("/v1/workers", workers)
        .layer(middleware::from_fn_with_state(state.clone(), count_request))
        .with_state(state)
}

/// Default sustained rate for the public API. Generous enough for a real
/// coding agent, tight enough that one tenant cannot monopolise the control
/// plane.
fn default_rate_limit() -> ratelimit::RateLimit {
    ratelimit::RateLimit::new(20.0, 60)
}

/// Admits a request against the tenant (when authenticated) or the peer
/// address. Returns 429 with a machine-readable code and a `Retry-After`
/// header so clients can back off correctly.
async fn rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    match rate_limit_response(&state, &request) {
        Some(response) => response,
        None => next.run(request).await,
    }
}

fn rate_limit_response(state: &AppState, request: &Request) -> Option<Response> {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip());
    let tenant = request.extensions().get::<Principal>().map(|p| p.tenant_id);
    let key = ratelimit::limit_key(tenant, peer);
    let decision = state.limiter().check(&key);
    (!decision.allowed).then(|| limited_response(decision.retry_after_seconds))
}

fn limited_response(retry_after_seconds: u64) -> Response {
    let body = ApiErrorBody {
        code: "rate_limited".to_string(),
        message: "request rate limit exceeded for this tenant; retry later".to_string(),
        request_id: new_id(),
    };
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ApiErrorEnvelope { error: body }),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert("retry-after", value);
    }
    response
}
async fn count_request(State(state): State<AppState>, request: Request, next: Next) -> Response {
    state.requests.fetch_add(1, Ordering::Relaxed);
    let operation_id = request
        .headers()
        .get("x-operation-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or_else(new_id);
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&operation_id.to_string()) {
        response.headers_mut().insert("x-operation-id", value);
    }
    tracing::info!(request_id = %operation_id, method = %method, path = %path, status = response.status().as_u16(), "api request");
    response
}

/// Tenant self-service key management. Requires an authenticated caller, so a
/// key can only ever manage keys inside its own tenant.
fn key_routes() -> Router<AppState> {
    Router::new()
        .route("/keys", get(list_keys).post(create_key))
        .route("/keys/{id}", delete(revoke_key))
}

/// Creates an account from an invite and returns its first API key.
async fn signup(
    State(s): State<AppState>,
    Json(body): Json<account::SignupRequest>,
) -> ApiResult<Value> {
    if !account::invite_is_valid(s.invites(), &body.invite) {
        // Do not distinguish a wrong code from signup being closed: either
        // would let an unauthenticated caller enumerate the deployment.
        return Err(ApiFailure::new(
            StatusCode::FORBIDDEN,
            "invite_rejected",
            "that invite code is not valid. Public alpha is invite only.",
        ));
    }
    let (account, key) = account::create_account(s.repository().as_ref(), body)
        .await
        .map_err(ApiFailure::from)?;
    let _ = s
        .repository()
        .append_audit_event(aiec_core::storage::AuditEvent {
            id: new_id(),
            occurred_at: Utc::now(),
            tenant_id: Some(account.id),
            actor: format!("user:{}", account.id),
            action: "account.created".to_string(),
            subject_type: "tenant".to_string(),
            subject_id: Some(account.id.to_string()),
            result: "success".to_string(),
            request_id: None,
            remote_addr: None,
            // Never the key itself: only the fact that one was issued.
            detail: json!({ "key_id": key.id }),
        })
        .await;
    Ok(Json(json!({ "account": account, "key": key })))
}

/// The authenticated caller's own account.
async fn current_account(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Value> {
    let tenant = s
        .repository()
        .get_tenant(p.tenant_id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(
        json!({ "id": tenant.id, "name": tenant.name, "created_at": tenant.created_at }),
    ))
}

/// Lists the caller's keys as metadata. Secrets are never returned.
async fn list_keys(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Value> {
    let keys = account::list_keys_for(s.repository().as_ref(), p.tenant_id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(json!({ "keys": keys })))
}

/// Issues a new key for the caller's tenant.
async fn create_key(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Json(body): Json<account::CreateKeyRequest>,
) -> ApiResult<Value> {
    // What was asked for, before any decision about who may ask. The default
    // is a real grant like any other and has to answer to the same rule; when
    // this was decided inside the `else`, the convenient branch was the
    // unguarded one and a key holding a single narrow scope could omit the
    // field to be handed `sandboxes:write`.
    let requested = if body.scopes.is_empty() {
        account::DEFAULT_KEY_SCOPES.to_vec()
    } else {
        let mut parsed = Vec::new();
        for scope in &body.scopes {
            parsed.push(Scope::parse(scope).map_err(ApiFailure::from)?);
        }
        parsed
    };
    // A key may not grant a privilege its holder does not have. Without this,
    // a read-only key could mint itself an admin key and then revoke the
    // tenant's real credentials. Admin keeps its own message because it is
    // the one scope whose absence is a platform problem rather than a
    // tenant's own over-grant.
    if requested.contains(&Scope::Admin) && !p.scopes.contains(&Scope::Admin) {
        return Err(ApiFailure::new(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "only a key that already holds admin may create another admin key",
        ));
    }
    for scope in &requested {
        p.authorize(scope.clone()).map_err(|_| {
            ApiFailure::new(
                StatusCode::FORBIDDEN,
                "insufficient_scope",
                format!("this key cannot grant the {:?} scope", scope),
            )
        })?;
    }
    let scopes = requested;
    let (created, _record) = account::create_key(
        s.repository().as_ref(),
        p.tenant_id,
        &body.name,
        scopes,
        body.expires_in_days,
    )
    .await
    .map_err(ApiFailure::from)?;
    let _ = s
        .repository()
        .append_audit_event(aiec_core::storage::AuditEvent {
            id: new_id(),
            occurred_at: Utc::now(),
            tenant_id: Some(p.tenant_id),
            actor: format!("key:{}", p.key_id),
            action: "api_key.created".to_string(),
            subject_type: "api_key".to_string(),
            subject_id: Some(created.id.to_string()),
            result: "success".to_string(),
            request_id: None,
            remote_addr: None,
            detail: json!({ "name": created.name, "scopes": created.scopes }),
        })
        .await;
    Ok(Json(json!(created)))
}

/// Revokes a key in the caller's tenant.
async fn revoke_key(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    // A key may not revoke the credential it is currently authenticating with:
    // that would lock the tenant out of its own account with no way back in.
    if id == p.key_id {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "cannot_revoke_current_key",
            "a key cannot revoke itself; create a replacement key first, then revoke this one",
        ));
    }
    // A key may only destroy credentials at or below its own authority.
    //
    // The only rule here used to be "not the one you are authenticating
    // with", which stops self-lockout and nothing else. A key holding a single
    // narrow scope could therefore revoke any other key in the tenant,
    // including the tenant's `admin` key and every key the platform holds for
    // it. Revocation is not undoable - there is no un-revoke - and the way
    // back in is an invite, so that is a permanent denial of service handed to
    // the least privileged credential in the tenant.
    //
    // The rule matches the one that already governs minting: you cannot grant
    // or destroy a privilege you do not hold yourself.
    let target = s
        .repository()
        .get_key(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?
        .ok_or_else(|| {
            ApiFailure::new(
                StatusCode::NOT_FOUND,
                "key_not_found",
                format!("no key {id} in this tenant"),
            )
        })?;
    for scope in &target.scopes {
        p.authorize(scope.clone()).map_err(|_| {
            ApiFailure::new(
                StatusCode::FORBIDDEN,
                "insufficient_scope",
                format!("this key cannot revoke a key holding the {:?} scope", scope),
            )
        })?;
    }
    s.repository()
        .revoke_key(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let _ = s
        .repository()
        .append_audit_event(aiec_core::storage::AuditEvent {
            id: new_id(),
            occurred_at: Utc::now(),
            tenant_id: Some(p.tenant_id),
            actor: format!("key:{}", p.key_id),
            action: "api_key.revoked".to_string(),
            subject_type: "api_key".to_string(),
            subject_id: Some(id.to_string()),
            result: "success".to_string(),
            request_id: None,
            remote_addr: None,
            detail: json!({}),
        })
        .await;
    Ok(Json(json!({ "revoked": id })))
}

fn protected_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .merge(evaluations::routes())
        .route("/sandboxes", post(create_sandbox).get(list_sandboxes))
        .route("/sandboxes/{id}", get(get_sandbox).delete(delete_sandbox))
        .route("/sandboxes/{id}/start", post(start_sandbox))
        .route("/sandboxes/{id}/stop", post(stop_sandbox))
        .route("/sandboxes/{id}/resume", post(resume_sandbox))
        .route("/sandboxes/{id}/pause", post(pause_sandbox))
        .route("/sandboxes/{id}/exec", post(exec_sandbox))
        .route("/sandboxes/{id}/git/diff", post(git_diff))
        .route("/sandboxes/{id}/secrets", get(list_secrets))
        .route(
            "/sandboxes/{id}/secrets/{name}",
            put(put_secret).delete(delete_secret),
        )
        .route(
            "/sandboxes/{id}/artifacts/{name}",
            post(upload_artifact)
                .layer(axum::extract::DefaultBodyLimit::max(
                    ARTIFACT_MAX_BYTES.div_ceil(3) * 4 + 1024,
                ))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    artifact_upload_admission,
                ))
                .merge(get(download_artifact).delete(delete_artifact)),
        )
        .route("/sandboxes/{id}/artifacts", get(list_artifacts))
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
        .route("/runs", post(create_run).get(list_runs))
        .route("/runs/{id}", get(get_run))
        .route("/runs/{id}/events", get(list_run_events))
        .route("/runs/{id}/attempts", get(list_run_attempts))
        .route("/runs/{id}/artifacts", get(list_run_artifacts))
        // A wildcard, because an artifact's name is a path inside the sandbox:
        // `/workspace/report.txt` has to be addressable as one artifact. The
        // handler matches it against the run's recorded names, never against an
        // object key, so a wider capture cannot widen what is readable.
        .route("/runs/{id}/artifacts/{*name}", get(download_run_artifact))
        .route("/runs/{id}/cancel", post(cancel_run))
        .merge(guard::routes())
        .merge(guard_proposals::routes())
        .route(
            "/sandboxes/{id}/guard/release",
            axum::routing::post(guard_release::release_sandbox),
        )
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
        .route("/{node}/leases/{lease}/renew", post(renew_worker_lease))
        .route(
            "/{node}/leases/{lease}/complete",
            post(complete_worker_lease),
        )
        .route("/{node}/ownership/{sandbox_id}", get(sandbox_ownership))
        .route("/{node}/guard/reserve", post(guard::reserve_guard_budget))
        .route(
            "/{node}/guard/quarantine",
            post(guard::worker_guard_quarantine),
        )
        .route("/{id}/drain", post(drain_worker))
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
) -> ApiResult<Vec<aiec_core::storage::WorkerAssignment>> {
    Ok(Json(
        state
            .repository()
            .claim_worker_assignments(
                id,
                query.limit.min(128),
                query.lease_ttl_seconds.clamp(1, 3600),
            )
            .await
            .map_err(ApiFailure::from)?,
    ))
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
) -> ApiResult<aiec_core::storage::WorkerRegistration> {
    let now = Utc::now();
    let record = aiec_core::storage::WorkerRegistration {
        node_id: registration.node_id,
        name: registration.name,
        runtime: registration.runtime,
        capabilities: registration.capabilities,
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
        started_at: now,
        last_heartbeat: now,
    };
    let node_id = state
        .repository()
        .register_worker(record.clone())
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(aiec_core::storage::WorkerRegistration {
        node_id,
        ..record
    }))
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
    let status = state
        .repository()
        .heartbeat_worker(aiec_core::storage::WorkerHeartbeat {
            node_id: heartbeat.node_id,
            // Capacity is not copied through. The wire type still accepts it so
            // an older worker keeps working, and this is where the disconnect
            // happens: the store never wrote these, and now the API does not
            // carry them either.
            sandbox_count: heartbeat.sandbox_count,
            healthy: heartbeat.healthy,
            version: heartbeat.version,
            metadata: heartbeat.metadata,
            last_error: heartbeat.last_error,
        })
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(json!(status)))
}

async fn worker_status(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let status = state
        .repository()
        .get_worker(id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(json!(status)))
}

/// Body for the worker drain control.
#[derive(Deserialize)]
struct DrainWorkerBody {
    /// True stops new placement; false resumes it.
    draining: bool,
    #[serde(default)]
    reason: Option<String>,
}

/// Stops or resumes new sandbox placement on a worker.
///
/// Draining is deliberately not the same as `healthy = false`: a draining
/// worker keeps heartbeating and keeps serving the sandboxes it already holds,
/// so it can be upgraded or restarted without disrupting running work. The
/// scheduler refuses to place new sandboxes on it, and lease recovery will not
/// move anything onto it.
async fn drain_worker(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    body: Option<Json<DrainWorkerBody>>,
) -> ApiResult<Value> {
    let request = body.map(|Json(value)| value).unwrap_or(DrainWorkerBody {
        draining: true,
        reason: None,
    });
    let status = state
        .repository()
        .set_worker_draining(id, request.draining, request.reason.as_deref())
        .await
        .map_err(ApiFailure::from)?;
    // Draining a worker is an operational action worth recording.
    let detail = json!({ "reason": request.reason });
    let _ = state
        .repository()
        .append_audit_event(aiec_core::storage::AuditEvent {
            id: new_id(),
            occurred_at: Utc::now(),
            tenant_id: None,
            actor: "system".to_string(),
            action: if request.draining {
                "worker.drain".to_string()
            } else {
                "worker.undrain".to_string()
            },
            subject_type: "worker".to_string(),
            subject_id: Some(id.to_string()),
            result: "success".to_string(),
            request_id: None,
            remote_addr: None,
            // Operator text only: a drain reason never carries a credential.
            detail,
        })
        .await;
    Ok(Json(json!(status)))
}

/// Fencing payload shared by the worker lease endpoints.
#[derive(Deserialize)]
struct LeaseMutationBody {
    tenant_id: Uuid,
    generation: i64,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    result: Value,
}

/// Rejects a lease mutation coming from a worker that does not hold the lease.
async fn require_lease_owner(
    state: &AppState,
    node: WorkerId,
    lease: LeaseId,
    tenant: TenantId,
) -> Result<(), ApiFailure> {
    let held = state
        .repository()
        .get_worker_lease(tenant, lease)
        .await
        .map_err(ApiFailure::from)?;
    if held.node_id != node {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "lease is not held by this worker",
        ));
    }
    Ok(())
}

async fn renew_worker_lease(
    State(state): State<AppState>,
    Path((node, lease)): Path<(WorkerId, LeaseId)>,
    Json(body): Json<LeaseMutationBody>,
) -> ApiResult<aiec_core::storage::WorkerLease> {
    require_lease_owner(&state, node, lease, body.tenant_id).await?;
    Ok(Json(
        state
            .repository()
            .renew_worker_lease(
                body.tenant_id,
                lease,
                body.generation,
                body.ttl_seconds
                    .unwrap_or(state.lease_ttl_seconds)
                    .clamp(1, 3600),
            )
            .await
            .map_err(ApiFailure::from)?,
    ))
}

async fn complete_worker_lease(
    State(state): State<AppState>,
    Path((node, lease)): Path<(WorkerId, LeaseId)>,
    Json(body): Json<LeaseMutationBody>,
) -> ApiResult<aiec_core::storage::WorkerLease> {
    require_lease_owner(&state, node, lease, body.tenant_id).await?;
    Ok(Json(
        state
            .repository()
            .complete_worker_lease(body.tenant_id, lease, body.generation, body.result)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

/// Reports the durable lease ownership a worker must check before acting.
async fn sandbox_ownership(
    State(state): State<AppState>,
    Path((node, sandbox_id)): Path<(WorkerId, SandboxId)>,
) -> ApiResult<OwnershipRecord> {
    let ownership = state
        .repository()
        .sandbox_ownership(sandbox_id)
        .await
        .map_err(ApiFailure::from)?
        .ok_or_else(|| {
            ApiFailure::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "sandbox has no active lease",
            )
        })?;
    if ownership.node_id != node {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "sandbox is owned by another worker",
        ));
    }
    Ok(Json(OwnershipRecord {
        node_id: ownership.node_id,
        lease_id: ownership.lease_id,
        generation: ownership.generation,
        expires_at: ownership.expires_at,
    }))
}

async fn reconcile_workers(State(state): State<AppState>) -> ApiResult<Value> {
    let actions = state
        .repository()
        .reconcile_expired_leases(RECONCILE_LIMIT)
        .await
        .map_err(ApiFailure::from)?;
    // Eligibility, not who asked: a machine a run still owns, or one whose
    // teardown has started, is never rebuilt from here.
    let recoveries = recover_expired_leases(&state, &actions).await;
    let workers = state
        .repository()
        .list_workers(true)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(
        json!({"actions": actions, "workers": workers, "recoveries": recoveries}),
    ))
}

/// Upper bound on leases inspected and recovered by one reconcile call.
const RECONCILE_LIMIT: u32 = 100;

/// Outcome of one recovered sandbox, reported to the operator.
#[derive(Serialize)]
struct RecoveryOutcome {
    sandbox_id: Uuid,
    lease_id: Uuid,
    generation: Option<i64>,
    status: &'static str,
    detail: Option<String>,
}

/// Sandbox states whose expired lease must be recovered rather than abandoned.
fn is_recoverable_state(state: SandboxState) -> bool {
    matches!(
        state,
        SandboxState::Creating
            | SandboxState::Starting
            | SandboxState::Running
            | SandboxState::Paused
            | SandboxState::Stopped
            | SandboxState::Snapshotting
    )
}

/// Reassigns every lease the reconciler just expired and places the sandbox on
/// its new owner, reconstructing the workspace from the newest stored archive.
///
/// The pass is bounded and idempotent: a lease that was already reassigned or
/// that has no healthy worker with capacity is left to a later pass, and a
/// failure releases the replacement lease instead of leaving a half-owned
/// sandbox behind.
async fn recover_expired_leases(
    state: &AppState,
    actions: &[aiec_core::storage::ReconciliationAction],
) -> Vec<RecoveryOutcome> {
    let mut outcomes = Vec::new();
    for action in actions.iter().take(RECONCILE_LIMIT as usize) {
        let (Some(sandbox_id), Some(lease_id)) = (action.sandbox_id, action.lease_id) else {
            continue;
        };
        let Ok(sandbox) = state
            .repository()
            .get_sandbox(action.tenant_id, sandbox_id)
            .await
        else {
            continue;
        };
        if !is_recoverable_state(sandbox.state) {
            continue;
        }
        match state.repository().reassign_expired_lease(lease_id).await {
            Ok(Some(reassignment)) => {
                outcomes.push(place_recovered_sandbox(state, reassignment).await);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%sandbox_id, %lease_id, %error, "lease reassignment failed");
                outcomes.push(RecoveryOutcome {
                    sandbox_id,
                    lease_id,
                    generation: None,
                    status: "failed",
                    detail: Some(error.to_string()),
                });
            }
        }
    }
    outcomes
}

/// Places a reassigned sandbox on its new owner and marks it running.
async fn place_recovered_sandbox(
    state: &AppState,
    reassignment: aiec_core::storage::Reassignment,
) -> RecoveryOutcome {
    let sandbox_id = reassignment.sandbox.id;
    let lease_id = reassignment.lease.id;
    let generation = reassignment.lease.generation;
    let mut sandbox = reassignment.sandbox;
    let mut expected = sandbox.state;
    let runtime = match state.runtime_for(&sandbox) {
        Ok(runtime) => runtime,
        Err(error) => {
            return abandon_recovery(state, &sandbox, expected, generation, lease_id, error).await;
        }
    };
    if let Err(error) = runtime.create(&sandbox).await {
        return abandon_recovery(state, &sandbox, expected, generation, lease_id, error).await;
    }
    if let Err(error) = state
        .commit_state_as(
            &sandbox,
            expected,
            SandboxState::Starting,
            lease_id,
            generation,
        )
        .await
    {
        return abandon_recovery(state, &sandbox, expected, generation, lease_id, error).await;
    }
    sandbox.state = SandboxState::Starting;
    expected = SandboxState::Starting;
    if let Err(error) = runtime.start(&sandbox).await {
        return abandon_recovery(state, &sandbox, expected, generation, lease_id, error).await;
    }
    if let Err(error) = restore_workspace(state, &sandbox).await {
        return abandon_recovery(state, &sandbox, expected, generation, lease_id, error).await;
    }
    match state
        .commit_state_as(
            &sandbox,
            expected,
            SandboxState::Running,
            lease_id,
            generation,
        )
        .await
    {
        Ok(_) => RecoveryOutcome {
            sandbox_id,
            lease_id,
            generation: Some(generation),
            status: "recovered",
            detail: None,
        },
        Err(error) => {
            abandon_recovery(state, &sandbox, expected, generation, lease_id, error).await
        }
    }
}

/// Restores the newest stored workspace archive onto a recovered sandbox.
///
/// The bytes come from shared object storage, not from the worker that
/// captured them: that worker is gone, and its state directory went with it.
/// The archive is verified against the checksum recorded with the snapshot, so
/// a missing or damaged object fails recovery instead of quietly handing the
/// sandbox an empty workspace.
async fn restore_workspace(state: &AppState, sandbox: &Sandbox) -> Result<(), CoreError> {
    // Named, not scanned: recovery wants the one archive to restore from, and a
    // sandbox that has taken thousands of snapshots keeps all of them.
    let stored = state
        .repository()
        .latest_stored_snapshot(sandbox.tenant_id, sandbox.id, "workspace")
        .await?;
    let Some(stored) = stored else {
        tracing::warn!(
            sandbox_id = %sandbox.id,
            "recovered sandbox has no workspace archive; starting with an empty workspace"
        );
        return Ok(());
    };
    import_stored_workspace(state, sandbox, &stored).await
}

async fn import_stored_workspace(
    state: &AppState,
    sandbox: &Sandbox,
    stored: &aiec_core::storage::StoredSnapshot,
) -> Result<(), CoreError> {
    if !stored.complete || stored.kind != "workspace" || stored.tenant_id != sandbox.tenant_id {
        return Err(CoreError::Conflict(
            "a complete tenant-owned workspace snapshot is required".into(),
        ));
    }
    let object_key = stored
        .workspace_object_key
        .clone()
        .unwrap_or_else(|| stored.object_key.clone());
    let store = state.artifact_store().ok_or_else(|| {
        CoreError::Conflict(
            "artifact storage is not configured; a captured workspace cannot be restored".into(),
        )
    })?;
    let archive = store
        .get_checked(
            &object_key,
            &GetObjectOptions {
                if_match: None,
                expected_checksum_sha256: Some(stored.checksum_sha256.clone()),
            },
        )
        .await
        // Not `Conflict`: nothing about the caller's request conflicts with
        // anything. Bytes in shared storage that do not match the digest the
        // snapshot was captured under are an integrity failure on our side,
        // and a 409 would tell the caller to retry a request that cannot
        // succeed until the stored archive is repaired.
        .map_err(|error| {
            CoreError::Backend(format!(
                "workspace archive {object_key} is unreadable: {error}"
            ))
        })?;
    // The store was asked to honor the precondition, but recovery is the one
    // place where wrong bytes would be indistinguishable from a lost
    // workspace, so the control plane checks the digest itself.
    verify_archive_checksum(&archive, &stored.checksum_sha256)?;
    state
        .runtime_for(sandbox)?
        .import_workspace_archive(sandbox, &archive)
        .await
}

/// Releases the replacement lease and parks the sandbox for a later attempt.
async fn abandon_recovery(
    state: &AppState,
    sandbox: &Sandbox,
    expected: SandboxState,
    generation: i64,
    lease_id: LeaseId,
    error: CoreError,
) -> RecoveryOutcome {
    tracing::warn!(
        sandbox_id = %sandbox.id,
        %lease_id,
        %error,
        "recovered sandbox could not be placed"
    );
    if let Err(failure) = state
        .commit_state_as(
            sandbox,
            expected,
            SandboxState::Failed,
            lease_id,
            generation,
        )
        .await
    {
        tracing::warn!(
            sandbox_id = %sandbox.id,
            %failure,
            "recovered sandbox could not be marked failed"
        );
    }
    // Fenced, and named. `Scheduler::release` takes only a tenant and a
    // sandbox, so the store picks whichever lease is newest — which for a
    // pass that has already been superseded is somebody else's lease, and
    // releasing it credits back capacity the new owner is still using while
    // its sandbox is still live.
    if let Err(failure) = state
        .repository()
        .release_worker_lease(
            sandbox.tenant_id,
            lease_id,
            generation,
            "recovery abandoned the placement",
        )
        .await
    {
        tracing::warn!(
            sandbox_id = %sandbox.id,
            %lease_id,
            %generation,
            %failure,
            "the recovery lease could not be released"
        );
    }
    RecoveryOutcome {
        sandbox_id: sandbox.id,
        lease_id,
        generation: Some(generation),
        status: "failed",
        detail: Some(error.to_string()),
    }
}
async fn auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiFailure> {
    let authentication = authenticate_request(&state, request.headers())
        .await
        .map(|principal| request.extensions_mut().insert(principal));
    if let Some(response) = rate_limit_response(&state, &request) {
        return Ok(response);
    }
    authentication?;
    Ok(next.run(request).await)
}

async fn authenticate_request(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<Principal, ApiFailure> {
    let raw = headers
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
        .repository()
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
    Ok(Principal {
        tenant_id: key.tenant_id,
        key_id: key.id,
        scopes: key.scopes,
    })
}
/// Liveness: the process is up and serving. Deliberately dependency-free so a
/// database blip does not get the process killed.
async fn health() -> Json<Value> {
    Json(json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}))
}

/// Readiness: the control plane can actually accept new workloads.
///
/// A static "ready" is wrong for a public API: if the database is unreachable,
/// object storage is unusable, or no worker can take a sandbox, the instance
/// must not advertise itself as ready or a rolling deploy will keep traffic
/// flowing into a control plane that cannot serve it.
async fn ready(State(state): State<AppState>) -> Response {
    let mut checks = serde_json::Map::new();
    let mut ready = true;

    // `ping`, not a worker listing. Readiness answers on an unauthenticated
    // and unthrottled route — a load balancer has no credential to present —
    // and its only question is whether the database responds. Listing every
    // worker to discard the result made an anonymous probe cost a full-table
    // read, which is the shape of an amplification bug rather than a health
    // check.
    match state.repository().ping().await {
        Ok(()) => {
            checks.insert("database".to_string(), json!("ok"));
        }
        // A store that does not implement worker listing is a development
        // backend, not a broken database. Only a real error means "not ready".
        Err(CoreError::Unsupported(_)) => {
            checks.insert("database".to_string(), json!("not_applicable"));
        }
        Err(error) => {
            ready = false;
            // The log names the failing dependency, never a credential.
            checks.insert("database".to_string(), json!("unavailable"));
            tracing::warn!(%error, "readiness check failed: database");
        }
    }

    if state.execution_budget_exhausted() {
        ready = false;
        checks.insert("execution_budget".to_string(), json!("exhausted"));
    }

    let status = if ready { "ready" } else { "not_ready" };
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(json!({"status": status, "checks": checks}))).into_response()
}
async fn metrics(State(state): State<AppState>) -> Response {
    // Summed by the database. Two totals are the whole report, and `/metrics`
    // is public like `/ready`, so shipping the fleet to the process to add it
    // up made the cost of an anonymous scrape proportional to the fleet.
    let (available_vcpus, available_memory) = state
        .repository()
        .node_capacity_totals()
        .await
        .map(|totals| (totals.available_vcpus, totals.available_memory_bytes))
        .unwrap_or_default();
    let body = format!(
        "# TYPE aiec_api_requests_total counter\naiec_api_requests_total {}\n# TYPE aiec_node_available_vcpus gauge\naiec_node_available_vcpus {}\n# TYPE aiec_node_available_memory_bytes gauge\naiec_node_available_memory_bytes {}\n",
        state.requests.load(Ordering::Relaxed),
        available_vcpus,
        available_memory
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

#[derive(Deserialize)]
struct CreateSandboxBody {
    #[serde(flatten)]
    request: CreateSandboxRequest,
    runtime: Option<String>,
    isolation: Option<String>,
}

/// The four measured steps of provisioning, in the order they happen. A timed
/// step is measured on the shared path so a caller can tell a slow reservation
/// from a slow boot; `results.phase_ms` reports these as `placement.*`.
#[derive(Default)]
pub(crate) struct ProvisionTimings {
    pub scheduler_ms: u64,
    pub allocation_ms: u64,
    pub boot_ms: u64,
    pub workspace_ms: u64,
}

pub(crate) struct ProvisionedSandbox {
    pub sandbox: Sandbox,
    pub timings: ProvisionTimings,
}

/// Brings a sandbox from a row to a running machine.
///
/// One path for the sandbox API and for runs, deliberately. A run that
/// reproduced only part of this took no worker lease, so every command it tried
/// to run failed with "active sandbox lease not found" - which looks like a
/// runtime bug and is actually a missing scheduling step.
///
/// Capacity is reserved before anything expensive starts, so a refused
/// placement never leaves a half-built machine behind.
pub(crate) async fn provision_sandbox(
    s: &AppState,
    tenant: TenantId,
    request_id: Uuid,
    x: Sandbox,
    required_capabilities: aiec_core::runtime::RuntimeCapabilities,
    run_id: Option<Uuid>,
    authorization_present: bool,
) -> Result<ProvisionedSandbox, ApiFailure> {
    let mut x = x;
    let mut timings = ProvisionTimings::default();
    let floor = s.runtime_for(&x)?.capabilities().minimum_disk_mb;
    x.disk_mb = x.disk_mb.max(u32::try_from(floor).map_err(|_| {
        ApiFailure::from(CoreError::LimitExceeded(
            "runtime disk floor exceeds supported capacity".into(),
        ))
    })?);
    let admission = CreateSandboxRequest {
        image: x.image_id.clone(),
        cpu: x.cpu,
        memory_mb: x.memory_mb,
        disk_mb: x.disk_mb,
        timeout_seconds: x.timeout_seconds,
        network: x.network.clone(),
        environment: x.environment.clone(),
    };
    validate_create(&admission, MAX_LIFETIME_SECONDS).map_err(ApiFailure::from)?;
    if let Some(policy) = s.platform.policy() {
        let decision = policy.evaluate(PolicyOperation::CreateSandbox(&admission));
        if !decision.allowed {
            return Err(ApiFailure::new(
                StatusCode::BAD_REQUEST,
                "policy_denied",
                decision
                    .reason
                    .unwrap_or_else(|| "request denied by policy".into()),
            ));
        }
    }
    if !s.allows_runtime(x.runtime) {
        return Err(ApiFailure::new(
            StatusCode::FORBIDDEN,
            "runtime_not_permitted",
            format!(
                "runtime {} is not available to this deployment",
                x.runtime.as_str()
            ),
        ));
    }
    // Hosted capacity is reached through the provider inside the runtime, not
    // through a leased worker node, so there is nothing for the worker
    // scheduler to place. Worker-backed runtimes are scheduled as before.
    let scheduled_at = std::time::Instant::now();
    let mut dispatch = None;
    if s.is_production() && x.runtime != RuntimeKind::Hosted {
        let admission = s
            .scheduler()
            .schedule_for_provision(aiec_core::scheduler::ScheduleRequest {
                tenant_id: tenant,
                request_id,
                sandbox: x,
                preferred_worker: None,
                lease_ttl: std::time::Duration::from_secs(s.lease_ttl_seconds),
                required_capabilities,
                run_id,
            })
            .await
            .map_err(|error| match error {
                CoreError::QuotaExceeded(message) => {
                    ApiFailure::new(StatusCode::TOO_MANY_REQUESTS, "quota_exceeded", message)
                }
                other => ApiFailure::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "scheduler_unavailable",
                    other.to_string(),
                ),
            })?;
        x = admission.scheduled.sandbox;
        if !admission.acquired {
            timings.scheduler_ms = scheduled_at.elapsed().as_millis() as u64;
            if matches!(x.state, SandboxState::Creating | SandboxState::Starting) {
                return Err(ApiFailure::new(
                    StatusCode::CONFLICT,
                    "sandbox_provisioning",
                    "the idempotent sandbox request is already provisioning",
                ));
            }
            return Ok(ProvisionedSandbox {
                sandbox: x,
                timings,
            });
        }
        dispatch = Some(aiec_core::scheduler::WorkerDispatch {
            endpoint: admission.scheduled.worker_endpoint,
            lease_id: admission.scheduled.lease_id,
            generation: admission.scheduled.lease_generation,
        });
    } else {
        if let Some(run_id) = run_id {
            x = s
                .repository()
                .create_attempt_sandbox(run_id, request_id, x, required_capabilities)
                .await
                .map_err(ApiFailure::from)?;
        } else {
            s.repository()
                .create_sandbox(x.clone())
                .await
                .map_err(ApiFailure::from)?;
        }
    }
    timings.scheduler_ms = scheduled_at.elapsed().as_millis() as u64;
    worker::provision_scope(
        tenant,
        x.id,
        dispatch.clone(),
        provision_admitted_sandbox(s, tenant, x, timings, dispatch, authorization_present),
    )
    .await
}

/// State writes and rollback use the lease acquired by this call, never a fresh
/// ownership lookup that can silently adopt a replacement's authority.
async fn commit_provision_state(
    s: &AppState,
    sandbox: &Sandbox,
    expected: SandboxState,
    next: SandboxState,
    dispatch: Option<&aiec_core::scheduler::WorkerDispatch>,
) -> Result<(), CoreError> {
    match dispatch {
        Some(dispatch) => {
            s.repository()
                .update_state_with_lease(
                    sandbox.tenant_id,
                    sandbox.id,
                    expected,
                    next,
                    dispatch.lease_id,
                    dispatch.generation,
                )
                .await
        }
        None => s
            .repository()
            .update_state(sandbox.tenant_id, sandbox.id, expected, next, None)
            .await
            .map(|_| ()),
    }
}

async fn provision_admitted_sandbox(
    s: &AppState,
    tenant: TenantId,
    mut x: Sandbox,
    mut timings: ProvisionTimings,
    dispatch: Option<aiec_core::scheduler::WorkerDispatch>,
    authorization_present: bool,
) -> Result<ProvisionedSandbox, ApiFailure> {
    if x.state != SandboxState::Creating {
        return Ok(ProvisionedSandbox {
            sandbox: x,
            timings,
        });
    }
    let guard = guard::initialize_guard_budget(s.repository().as_ref(), &x).await;
    let allocated = guard.is_ok();
    let provision = async {
        guard.map_err(ApiFailure::from)?;
        let allocated_at = std::time::Instant::now();
        s.runtime_for(&x)?
            .create(&x)
            .await
            .map_err(ApiFailure::from)?;
        timings.allocation_ms = allocated_at.elapsed().as_millis() as u64;
        commit_provision_state(
            s,
            &x,
            SandboxState::Creating,
            SandboxState::Starting,
            dispatch.as_ref(),
        )
        .await
        .map_err(ApiFailure::from)?;
        x.state = SandboxState::Starting;
        let booted_at = std::time::Instant::now();
        s.runtime_for(&x)?
            .start(&x)
            .await
            .map_err(ApiFailure::from)?;
        timings.boot_ms = booted_at.elapsed().as_millis() as u64;
        let workspace_at = std::time::Instant::now();
        prepare_environment(s, &x, &x.environment, authorization_present).await?;
        timings.workspace_ms = workspace_at.elapsed().as_millis() as u64;
        commit_provision_state(
            s,
            &x,
            SandboxState::Starting,
            SandboxState::Running,
            dispatch.as_ref(),
        )
        .await
        .map_err(ApiFailure::from)?;
        x.state = SandboxState::Running;
        Ok::<(), ApiFailure>(())
    }
    .await;

    if let Err(error) = provision {
        // This atomic state/lease CAS is teardown initiation. Recovery and
        // admission cannot replace a Destroying sandbox after it succeeds.
        if let Err(fence_error) =
            commit_provision_state(s, &x, x.state, SandboxState::Destroying, dispatch.as_ref())
                .await
        {
            // Losing this CAS means another actor owns the sandbox now, and
            // this path may not stop anything on its behalf. The machine's
            // cleanup belongs to recovery, which fences on the lease it holds.
            //
            // Dispatching a destroy from here instead is refused by the
            // regression `replaced_owner_failure_never_destroys_the_new_lease_machine`.
            // `Destroy` is addressed by sandbox id rather than by machine, so
            // destroying here would act on whichever machine this sandbox has
            // *now* — on a takeover, the replacement owner's, on the same node,
            // which is the ordinary shape of a lease handover. The worker would
            // reject the dispatch as a superseded lease, but a rollback that
            // depends on being refused is not a rollback: it only stops the
            // machine when the control plane and the worker happen to disagree.
            return Err(ApiFailure::new(
                StatusCode::CONFLICT,
                "sandbox_not_owned",
                format!(
                    "{}; rollback ownership refused: {fence_error}",
                    error.message
                ),
            ));
        }
        let cleanup = if allocated {
            // The scoped worker dispatch still carries the original lease.
            // Capacity is released only after runtime teardown confirms stop.
            runs::destroy_with_retry(s, tenant, x.id).await
        } else {
            // Guard initialization failed before runtime allocation.
            s.repository()
                .delete_sandbox(tenant, x.id)
                .await
                .map_err(|e| e.to_string())
        };
        if let Err(cleanup_error) = cleanup {
            return Err(ApiFailure::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime_unavailable",
                format!("{}; cleanup failed: {cleanup_error}", error.message),
            ));
        }
        return Err(error);
    }
    // A hosted sandbox is charged one vCPU-second unit per allocated vCPU per
    // hour of requested lifetime. This is a stop-loss against a finite provider
    // allowance, not a bill: the durable usage ledger remains the record.
    if x.runtime == RuntimeKind::Hosted {
        let seconds = i64::try_from(x.timeout_seconds).unwrap_or(i64::MAX);
        let units = i64::from(x.cpu) * ((seconds + 3599) / 3600);
        s.charge_execution(units.max(1));
    }
    Ok(ProvisionedSandbox {
        sandbox: x,
        timings,
    })
}

fn create_response(sandbox: Sandbox, reason: &str) -> Response {
    // A response that does not say it is running on a weaker boundary would let
    // an operator believe a microVM guarantee they did not get.
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", axum::http::header::CONTENT_TYPE.as_str())
        .header("x-aiec-selection-reason", reason);
    if let Some(notice) = isolation_notice::notice(sandbox.runtime) {
        response = response.header("x-aiec-isolation", notice);
    }
    response
        .body(axum::body::Body::from(
            serde_json::to_vec(&sandbox).unwrap_or_else(|_| b"{}".to_vec()),
        ))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Whether any healthy, live worker in this deployment advertises egress
/// enforcement.
///
/// This is the fact the runtime-kind selection cannot answer for itself, and
/// the fact placement depends on: a governed machine may only be placed where
/// the rules can actually be installed, while the control plane's own runtime
/// profile says nothing about its workers.
pub(crate) async fn worker_enforces_egress(state: &AppState) -> Result<bool, CoreError> {
    Ok(state
        .repository()
        .list_workers(false)
        .await?
        .iter()
        .any(|worker| worker.registration.capabilities.network_policy))
}

/// Whether the operator has explicitly accepted a weaker isolation boundary.
fn reduced_isolation_allowed() -> bool {
    std::env::var("AIEC_ALLOW_REDUCED_ISOLATION").as_deref() == Ok("1")
}
async fn create_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<CreateSandboxBody>,
) -> Result<Response, ApiFailure> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let requested_runtime = match body.runtime.as_deref() {
        Some("firecracker") => Some(RuntimeKind::Firecracker),
        Some("docker") => Some(RuntimeKind::Docker),
        Some("bwrap-dev" | "bwrap_dev") => Some(RuntimeKind::BwrapDev),
        // Hosted capacity is a real Firecracker-backed provider reached through
        // the runtime abstraction, not a weaker isolation tier.
        Some("hosted" | "e2b") => Some(RuntimeKind::Hosted),
        Some("auto") | None => None,
        Some(other) => {
            return Err(ApiFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("unsupported runtime {other}"),
            ));
        }
    };
    let minimum_isolation = match body.isolation.as_deref() {
        Some("container") => Some(aiec_core::runtime::RuntimeIsolation::Container),
        Some("microvm") => Some(aiec_core::runtime::RuntimeIsolation::MicroVm),
        Some("process") => Some(aiec_core::runtime::RuntimeIsolation::Process),
        Some("full_vm") => Some(aiec_core::runtime::RuntimeIsolation::FullVm),
        None => None,
        Some(other) => {
            return Err(ApiFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("unsupported isolation {other}"),
            ));
        }
    };
    let guarded = body.request.environment.guard.is_some();
    let required = aiec_core::runtime::RuntimeCapabilities {
        exec: true,
        files: true,
        // A guarded sandbox needs a worker that can enforce its egress, so the
        // capability is demanded at placement rather than discovered at boot.
        network_policy: guarded,
        ..Default::default()
    };
    // The registry profile describes the control plane's own runtime, not the
    // workers that will actually run the machine. Asking it to vouch for egress
    // enforcement makes a worker-proxied deployment refuse every guarded
    // sandbox, because a proxy reports what it can do rather than what its
    // nodes can do. Placement already filters nodes by the full requirement,
    // so the kind selection only gets to veto when nothing in the deployment
    // offers the capability at all - which keeps the refusal fail-closed.
    let mut kind_requirement = required.clone();
    if guarded && worker_enforces_egress(&s).await.map_err(ApiFailure::from)? {
        kind_requirement.network_policy = false;
    }
    let (runtime_kind, _selection_reason) = if let Some(registry) = s.runtime_registry() {
        let selection = registry
            .select(requested_runtime, &kind_requirement, minimum_isolation)
            .await
            .map_err(|error| match error {
                CoreError::Unavailable(message) => {
                    ApiFailure::new(StatusCode::BAD_REQUEST, "runtime_unavailable", message)
                }
                other => ApiFailure::from(other),
            })?;
        (selection.runtime, selection.reason)
    } else {
        (
            requested_runtime.unwrap_or(s.runtime_kind()),
            format!("configured runtime {}", s.runtime_kind().as_str()),
        )
    };
    if requested_runtime == Some(RuntimeKind::Firecracker) && !s.is_production() {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "firecracker requests require the production server",
        ));
    }
    if requested_runtime == Some(RuntimeKind::BwrapDev) && s.is_production() {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "bwrap-dev is not available in production",
        ));
    }
    // Public policy: a tenant may not downgrade their own isolation. This is
    // checked against the runtime that was actually *selected*, not the one that
    // was requested: an omitted or "auto" field would otherwise bypass it.
    if !s.allows_runtime(runtime_kind) {
        return Err(ApiFailure::new(
            StatusCode::FORBIDDEN,
            "runtime_not_permitted",
            format!(
                "runtime {} is not available to this deployment; hosted workloads run on microVM isolation",
                runtime_kind.as_str()
            ),
        ));
    }
    // Hosted execution is finite. When the configured global budget is spent,
    // new hosted sandboxes stop cleanly with a capacity error instead of
    // silently becoming provider overage. Also keyed on the selected runtime.
    if runtime_kind == RuntimeKind::Hosted && s.execution_budget_exhausted() {
        return Err(ApiFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporary_capacity_unavailable",
            "the hosted execution budget is exhausted; no new sandboxes are being created right now",
        ));
    }
    let mut r = body.request;
    if runtime_kind == RuntimeKind::Firecracker && r.environment.guard.is_none() {
        r.environment.guard = Some(Default::default());
    }
    if r.environment.guard.is_some() {
        // Guard assumes an attacker-controlled guest behind a boundary the host
        // owns. Running it on a weaker runtime is possible, but only when an
        // operator has said so once in configuration, and the answer then says
        // what was given up.
        if let Err(reason) = isolation_notice::guarded_allowed(
            runtime_kind,
            isolation_notice::ReducedIsolation {
                allowed: reduced_isolation_allowed(),
            },
        ) {
            return Err(ApiFailure::new(
                StatusCode::BAD_REQUEST,
                "guard_runtime_unavailable",
                reason,
            ));
        }
    }
    r.environment.guard_policy_hash = r
        .environment
        .guard
        .as_ref()
        .map(|guard| guard.effective_policy().and_then(|policy| policy.hash()))
        .transpose()
        .map_err(|error| ApiFailure::from(CoreError::InvalidRequest(error.to_string())))?;
    validate_create(&r, MAX_LIFETIME_SECONDS).map_err(ApiFailure::from)?;
    if let Some(policy) = s.platform.policy() {
        let decision = policy.evaluate(PolicyOperation::CreateSandbox(&r));
        if !decision.allowed {
            return Err(ApiFailure::new(
                StatusCode::BAD_REQUEST,
                "policy_denied",
                decision
                    .reason
                    .unwrap_or_else(|| "request denied by policy".into()),
            ));
        }
    }
    let resolved_image_id = admit_image(&s, runtime_kind, &r.image).await?;
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
    let x = Sandbox {
        id: request_id,
        tenant_id: p.tenant_id,
        runtime: runtime_kind,
        image_id: resolved_image_id,
        state: SandboxState::Creating,
        cpu: r.cpu,
        memory_mb: r.memory_mb,
        node_id: None,
        disk_mb: r.disk_mb,
        timeout_seconds: r.timeout_seconds,
        network: r.network,
        environment: r.environment.clone(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    };
    let x = provision_sandbox(&s, p.tenant_id, request_id, x, required, None, false).await?;
    Ok(create_response(x.sandbox, &_selection_reason))
}

/// The image a machine is allowed to boot, for whichever path is starting one.
///
/// The signed manifest resolver is the only thing that decides whether an
/// image is one this deployment serves, so every path that boots a machine
/// goes through it: a caller-supplied string is a request for an image, never
/// an admission to boot one. `create_sandbox` and `restore_snapshot` used to
/// disagree here, and the restore path took the caller's string verbatim, so
/// the manifest admission the create path depends on was missing from the one
/// path that boots a machine from a stored snapshot.
async fn admit_image(
    s: &AppState,
    runtime: RuntimeKind,
    image: &str,
) -> Result<String, ApiFailure> {
    let reference = aiec_core::images::ImageReference::new(image).map_err(ApiFailure::from)?;
    if runtime == RuntimeKind::Firecracker {
        if let Some(images) = s.platform.images() {
            return Ok(images
                .resolve(&reference)
                .await
                .map_err(ApiFailure::from)?
                .image_id);
        }
        if s.is_production() {
            return Err(ApiFailure::from(CoreError::Conflict(
                "Firecracker image admission is not configured".into(),
            )));
        }
        Ok(image_id(image))
    } else if let Some(images) = s.platform.images() {
        images.resolve(&reference).await.map_err(ApiFailure::from)?;
        Ok(reference.as_str().to_owned())
    } else {
        Ok(reference.as_str().to_owned())
    }
}
async fn prepare_environment(
    state: &AppState,
    sandbox: &Sandbox,
    environment: &EnvironmentSpec,
    authorization_present: bool,
) -> Result<(), ApiFailure> {
    let runtime = state.runtime_for(sandbox)?;
    match &environment.workspace {
        WorkspaceSpec::Empty => {}
        WorkspaceSpec::Snapshot { snapshot_id } => {
            let stored = state
                .repository()
                .get_stored_snapshot(sandbox.tenant_id, *snapshot_id)
                .await
                .map_err(ApiFailure::from)?;
            if snapshot_kind(&stored.kind)? != SnapshotKind::Workspace {
                return Err(ApiFailure::from(CoreError::Conflict(
                    "snapshot-derived workspace requires a workspace snapshot".into(),
                )));
            }
            import_stored_workspace(state, sandbox, &stored)
                .await
                .map_err(ApiFailure::from)?;
        }
        WorkspaceSpec::Git {
            repo,
            reference,
            shallow,
        } => {
            // Tenant isolation is not a credential identity: any Run carrying
            // secret references or caller exec environment bypasses the cache,
            // including before those values are installed in its fresh sandbox.
            let secrets = state.secret_values(sandbox.tenant_id, sandbox.id).await;
            let cached = state
                .repo_cache()
                .prepare(
                    runtime.as_ref(),
                    sandbox,
                    repo,
                    reference.as_deref(),
                    *shallow,
                    authorization_present || !secrets.is_empty(),
                )
                .await
                .map_err(ApiFailure::from)?;
            if !cached {
                let mut clone = vec!["git".into(), "clone".into()];
                if *shallow {
                    clone.push("--depth".into());
                    clone.push("1".into());
                }
                clone.push(repo.clone());
                clone.push("/workspace/repository".into());
                run_setup_command(runtime.as_ref(), sandbox, clone).await?;
                if let Some(reference) = reference {
                    run_setup_command(
                        runtime.as_ref(),
                        sandbox,
                        vec![
                            "git".into(),
                            "-C".into(),
                            "/workspace/repository".into(),
                            "checkout".into(),
                            "--detach".into(),
                            reference.clone(),
                        ],
                    )
                    .await?;
                }
            }
        }
    }
    for layer in &environment.layers {
        if layer.content_base64.is_empty() {
            continue;
        }
        use base64::Engine;
        let content = base64::engine::general_purpose::STANDARD
            .decode(&layer.content_base64)
            .map_err(|_| {
                ApiFailure::from(CoreError::InvalidRequest(
                    "invalid environment layer payload".into(),
                ))
            })?;
        if hex::encode(sha2::Sha256::digest(&content)) != layer.content_digest {
            return Err(ApiFailure::from(CoreError::InvalidRequest(
                "environment layer digest mismatch".into(),
            )));
        }
        let path = format!(
            "/workspace/.aiec/layers/{}/{}",
            layer.kind.as_str(),
            layer.name
        );
        if let Some(parent) = path.rsplit_once('/').map(|(parent, _)| parent) {
            state
                .runtime_for(sandbox)?
                .make_directory(
                    sandbox,
                    MakeDirectoryRequest {
                        path: parent.into(),
                    },
                )
                .await
                .map_err(ApiFailure::from)?;
        }
        state
            .runtime_for(sandbox)?
            .put_file(
                sandbox,
                PutFileRequest {
                    path,
                    content_base64: layer.content_base64.clone(),
                    mode: Some(0o444),
                },
            )
            .await
            .map_err(ApiFailure::from)?;
    }
    for toolkit in &environment.toolkits {
        for command in &toolkit.setup_commands {
            run_setup_command(runtime.as_ref(), sandbox, command.clone()).await?;
        }
    }
    Ok(())
}

async fn run_setup_command(
    runtime: &dyn SandboxRuntime,
    sandbox: &Sandbox,
    command: Vec<String>,
) -> Result<(), ApiFailure> {
    let result = runtime
        .exec(
            sandbox,
            ExecRequest {
                command,
                working_directory: Some("/workspace".into()),
                environment: BTreeMap::new(),
                timeout_seconds: 300,
                stdin: None,
            },
        )
        .await
        .map_err(ApiFailure::from)?;
    if result.exit_code != 0 || result.timed_out {
        return Err(ApiFailure::new(
            StatusCode::BAD_GATEWAY,
            "environment_setup_failed",
            format!(
                "environment setup exited with {} (timed_out={})",
                result.exit_code, result.timed_out
            ),
        ));
    }
    Ok(())
}

async fn artifact_upload_admission(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = state.upload_slots.clone().try_acquire_owned() else {
        return ApiFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "artifact_upload_busy",
            "artifact upload capacity is occupied",
        )
        .into_response();
    };
    next.run(request).await
}

async fn upload_artifact(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(Uuid, String)>,
    Json(body): Json<ArtifactBody>,
) -> ApiResult<ArtifactResponse> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    s.repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let store = s.artifact_store().ok_or_else(|| {
        ApiFailure::new(
            StatusCode::NOT_IMPLEMENTED,
            "artifacts_unavailable",
            "artifact storage is not configured",
        )
    })?;
    if body.content_base64.len() > ARTIFACT_MAX_BYTES.div_ceil(3) * 4 {
        return Err(ApiFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "limit_exceeded",
            "artifact exceeds the 64 MiB limit",
        ));
    }
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body.content_base64)
        .map_err(|_| {
            ApiFailure::new(StatusCode::BAD_REQUEST, "invalid_request", "invalid base64")
        })?;
    if bytes.len() > ARTIFACT_MAX_BYTES {
        return Err(ApiFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "limit_exceeded",
            "artifact exceeds the 64 MiB limit",
        ));
    }
    let object_key = artifact_key(p.tenant_id, id, &name)?;
    // Reserved before the write and completed after it. The artifact sweeper
    // discovers reclaimable objects by scanning `artifact_objects`
    // (claim_artifact_deletions, artifact_gc.rs:283), so an object written
    // without a row there is invisible to the GC for the life of the
    // deployment: this route was the only production writer of the object
    // store that skipped the pairing, which made every artifact uploaded
    // through it permanent storage, up to 64 MiB per request.
    s.repository()
        .reserve_artifact_upload(p.tenant_id, None, &object_key)
        .await
        .map_err(ApiFailure::from)?;
    let metadata = tokio::time::timeout(
        std::time::Duration::from_secs(artifact_gc::MAX_ARTIFACT_UPLOAD_SECONDS),
        store.put(&object_key, bytes::Bytes::from(bytes)),
    )
    .await
    .map_err(|_| ApiFailure::from(CoreError::Unavailable("artifact upload timed out".into())))?
    .map_err(ApiFailure::from)?;
    s.repository()
        .complete_artifact_upload(p.tenant_id, None, &object_key)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(ArtifactResponse {
        metadata: Some(metadata),
        content_base64: None,
    }))
}

async fn download_artifact(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(Uuid, String)>,
) -> ApiResult<ArtifactDownload> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    s.repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let store = s.artifact_store().ok_or_else(|| {
        ApiFailure::new(
            StatusCode::NOT_IMPLEMENTED,
            "artifacts_unavailable",
            "artifact storage is not configured",
        )
    })?;
    let key = artifact_key(p.tenant_id, id, &name)?;
    let mut download = match store
        .get_verified(
            &key,
            &GetObjectOptions::default(),
            ARTIFACT_MAX_BYTES as u64,
        )
        .await
    {
        Ok(download) => download,
        Err(CoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiFailure::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "artifact not found",
            ));
        }
        Err(error) => return Err(ApiFailure::from(error)),
    };
    // JSON compatibility requires an encoded string, but never a second
    // whole decoded object beside it. Carry at most two bytes across chunks.
    use base64::Engine;
    let encoder = base64::engine::general_purpose::STANDARD;
    let mut content_base64 =
        String::with_capacity((download.metadata.size_bytes as usize).div_ceil(3) * 4);
    let mut carry = [0_u8; 3];
    let mut carry_len = 0;
    while let Some(chunk) = download.body.next_chunk().await.map_err(ApiFailure::from)? {
        let mut offset = 0;
        if carry_len != 0 {
            let take = (3 - carry_len).min(chunk.len());
            carry[carry_len..carry_len + take].copy_from_slice(&chunk[..take]);
            carry_len += take;
            offset = take;
            if carry_len == 3 {
                encoder.encode_string(carry, &mut content_base64);
                carry_len = 0;
            }
        }
        let end = offset + (chunk.len() - offset) / 3 * 3;
        encoder.encode_string(&chunk[offset..end], &mut content_base64);
        let remainder = &chunk[end..];
        carry[carry_len..carry_len + remainder.len()].copy_from_slice(remainder);
        carry_len += remainder.len();
    }
    encoder.encode_string(&carry[..carry_len], &mut content_base64);
    Ok(Json(ArtifactDownload {
        key,
        size_bytes: download.metadata.size_bytes,
        checksum_sha256: download.metadata.checksum_sha256,
        content_base64,
    }))
}

async fn delete_artifact(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(Uuid, String)>,
) -> ApiResult<Value> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    s.repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let store = s.artifact_store().ok_or_else(|| {
        ApiFailure::new(
            StatusCode::NOT_IMPLEMENTED,
            "artifacts_unavailable",
            "artifact storage is not configured",
        )
    })?;
    store
        .delete(&artifact_key(p.tenant_id, id, &name)?)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(json!({"status": "deleted"})))
}

async fn list_artifacts(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Vec<aiec_core::storage::ObjectMetadata>> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    s.repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let store = s.artifact_store().ok_or_else(|| {
        ApiFailure::new(
            StatusCode::NOT_IMPLEMENTED,
            "artifacts_unavailable",
            "artifact storage is not configured",
        )
    })?;
    let objects = store
        .list(&format!(
            "tenants/{}/sandboxes/{id}/artifacts/",
            p.tenant_id
        ))
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(objects))
}
/// Sandbox page size when the caller states none.
const DEFAULT_SANDBOX_PAGE: u32 = 50;

#[derive(Clone, Debug, Default, Deserialize)]
struct ListSandboxesQuery {
    /// Sandboxes to return. The store clamps this to
    /// `aiec_core::storage::MAX_SANDBOX_PAGE`, so a caller cannot ask for a
    /// response the control plane has no bound on.
    #[serde(default)]
    limit: Option<u32>,
    /// The previous page's last sandbox: when it was created, and which one.
    ///
    /// Both halves or neither. A cursor with only a timestamp has no sandbox to
    /// start after, and one with only an id cannot order a page that has not
    /// been read; guessing either would silently return the wrong page.
    #[serde(default)]
    after_created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    after_id: Option<Uuid>,
}

/// Reads one bounded page of the caller's sandboxes, newest first.
///
/// This used to return the tenant's entire sandbox list in one response. That
/// list is their whole history and only grows — destroying a sandbox is a state
/// transition, and nothing deletes the row — so the response size was a
/// function of how long the tenant had been on the system. The page now carries
/// its own successor, so a caller that stops reading knows it stopped at a page
/// boundary rather than having silently been given a truncated list.
async fn list_sandboxes(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Query(query): Query<ListSandboxesQuery>,
) -> ApiResult<SandboxPage> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    let after = match (query.after_created_at, query.after_id) {
        (None, None) => None,
        (Some(created_at), Some(id)) => Some(PageCursor { created_at, id }),
        _ => {
            return Err(ApiFailure::from(CoreError::InvalidRequest(
                "after_created_at and after_id must be given together".into(),
            )));
        }
    };
    Ok(Json(
        s.repository()
            .list_sandboxes(
                p.tenant_id,
                query.limit.unwrap_or(DEFAULT_SANDBOX_PAGE),
                after,
            )
            .await
            .map_err(ApiFailure::from)?,
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
        s.repository()
            .get_sandbox(p.tenant_id, id)
            .await
            .map_err(ApiFailure::from)?,
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
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    // Same teardown the run path uses. Two callers, one order, one meaning of
    // "destroyed": the machine is stopped before the row is forgotten.
    // Mapped through `from`, not flattened to one code. A teardown that lost a
    // lease race or hit a deadlock arrives as `transient` and the caller should
    // be able to see that and try again; collapsing every failure into
    // `scheduler_unavailable` would hide the one distinction a client needs.
    crate::runs::tear_down_sandbox(&s, p.tenant_id, id, &x)
        .await
        .map_err(ApiFailure::from)?;
    s.secrets.lock().await.remove(&(p.tenant_id, id));
    Ok(Json(json!({"status":"destroyed"})))
}

async fn put_secret(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(Uuid, String)>,
    Json(body): Json<SecretBody>,
) -> ApiResult<SecretMetadata> {
    if s.is_production() {
        return Err(ApiFailure::new(
            StatusCode::NOT_IMPLEMENTED,
            "secret_store_unavailable",
            "durable production secret storage is not configured",
        ));
    }
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    validate_secret_name(&name)?;
    let sandbox = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if sandbox.state == SandboxState::Destroyed {
        return Err(ApiFailure::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "sandbox not found",
        ));
    }
    if body.value.is_empty() || body.value.len() > 16 * 1024 || body.value.as_bytes().contains(&0) {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "secret value must be 1..16384 bytes without NUL",
        ));
    }
    let expires_at = Utc::now() + chrono::Duration::hours(1);
    let mut secrets = s.secrets.lock().await;
    let entries = secrets.entry((p.tenant_id, id)).or_default();
    if !entries.contains_key(&name) && entries.len() >= MAX_SECRETS_PER_SANDBOX {
        return Err(ApiFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "limit_exceeded",
            "sandbox has too many active secrets",
        ));
    }
    entries.insert(
        name.clone(),
        SecretEntry {
            value: body.value,
            expires_at,
        },
    );
    drop(secrets);
    Ok(Json(SecretMetadata { name, expires_at }))
}

async fn delete_secret(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(Uuid, String)>,
) -> ApiResult<Value> {
    if s.is_production() {
        return Err(ApiFailure::new(
            StatusCode::NOT_IMPLEMENTED,
            "secret_store_unavailable",
            "durable production secret storage is not configured",
        ));
    }
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let sandbox = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if sandbox.state == SandboxState::Destroyed {
        return Err(ApiFailure::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "sandbox not found",
        ));
    }
    let removed = s
        .secrets
        .lock()
        .await
        .get_mut(&(p.tenant_id, id))
        .is_some_and(|values| values.remove(&name).is_some());
    Ok(Json(
        json!({"status": if removed { "revoked" } else { "not_found" }}),
    ))
}

async fn list_secrets(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Vec<SecretMetadata>> {
    if s.is_production() {
        return Err(ApiFailure::new(
            StatusCode::NOT_IMPLEMENTED,
            "secret_store_unavailable",
            "durable production secret storage is not configured",
        ));
    }
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    let sandbox = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if sandbox.state == SandboxState::Destroyed {
        return Err(ApiFailure::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "sandbox not found",
        ));
    }
    let now = Utc::now();
    let mut secrets = s.secrets.lock().await;
    let values = secrets.entry((p.tenant_id, id)).or_default();
    values.retain(|_, entry| entry.expires_at > now);
    Ok(Json(
        values
            .iter()
            .map(|(name, entry)| SecretMetadata {
                name: name.clone(),
                expires_at: entry.expires_at,
            })
            .collect(),
    ))
}

async fn pause_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Sandbox> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let mut x = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    s.runtime_for(&x)?
        .pause(&x)
        .await
        .map_err(ApiFailure::from)?;
    x = s
        .commit_state(&x, SandboxState::Running, SandboxState::Paused)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(x))
}
async fn start_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Sandbox> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let mut x = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let old = x.state;
    x.state = SandboxState::Starting;
    s.runtime_for(&x)?
        .start(&x)
        .await
        .map_err(ApiFailure::from)?;
    s.commit_state(&x, old, SandboxState::Starting)
        .await
        .map_err(ApiFailure::from)?;
    x.state = SandboxState::Starting;
    s.commit_state(&x, SandboxState::Starting, SandboxState::Running)
        .await
        .map_err(ApiFailure::from)?;
    x.state = SandboxState::Running;
    Ok(Json(x))
}
async fn stop_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Sandbox> {
    if let Err(error) = p.authorize(Scope::SandboxesWrite) {
        // Recorded before returning: a refusal by policy is the most
        // security-relevant event a handler can produce, and audit_log is
        // append-only, so an unrecorded refusal cannot be reconstructed later.
        record_sandbox_action(&s, &p, id, "sandbox.stop", "denied", &json!({})).await;
        return Err(ApiFailure::from(error));
    }
    let x = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if x.state != SandboxState::Running {
        return Err(ApiFailure::from(CoreError::Conflict(
            "sandbox is not running".into(),
        )));
    }
    s.runtime_for(&x)?
        .stop(&x)
        .await
        .map_err(ApiFailure::from)?;
    s.commit_state(&x, SandboxState::Running, SandboxState::Stopping)
        .await
        .map_err(ApiFailure::from)?;
    let x = s
        .commit_state(&x, SandboxState::Stopping, SandboxState::Stopped)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(x))
}
async fn resume_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Sandbox> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let x = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if x.state != SandboxState::Paused {
        return Err(ApiFailure::from(CoreError::Conflict(
            "sandbox is not paused".into(),
        )));
    }
    // A quarantine in progress freezes the machine for an operator. Resuming it
    // here would hand a guest execution back between the watchdog's pause and
    // its durable mark, and the incident would then describe a paused capture
    // of a machine that is running.
    if x.environment.guard.is_some()
        && s.repository()
            .get_guard_incident(p.tenant_id, id)
            .await
            .is_ok()
    {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "sandbox is held under a Guard incident",
        ));
    }
    s.runtime_for(&x)?
        .resume(&x)
        .await
        .map_err(ApiFailure::from)?;
    let x = s
        .commit_state(&x, SandboxState::Paused, SandboxState::Running)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(x))
}
/// Records a sandbox lifecycle action, notably a policy refusal.
async fn record_sandbox_action(
    state: &AppState,
    principal: &Principal,
    sandbox_id: Uuid,
    action: &str,
    result: &str,
    detail: &Value,
) {
    let _ = state
        .repository()
        .append_audit_event(aiec_core::storage::AuditEvent {
            id: new_id(),
            occurred_at: Utc::now(),
            tenant_id: Some(principal.tenant_id),
            actor: format!("key:{}", principal.key_id),
            action: action.to_string(),
            subject_type: "sandbox".to_string(),
            subject_id: Some(sandbox_id.to_string()),
            result: result.to_string(),
            request_id: None,
            remote_addr: None,
            detail: detail.clone(),
        })
        .await;
}

/// Records a sandbox file operation in the audit trail.
///
/// Whether the operation succeeded is reported; its payload never is.
async fn record_sandbox_file(
    state: &AppState,
    principal: &Principal,
    sandbox_id: Uuid,
    action: &str,
    ok: bool,
    detail: &Value,
) {
    let _ = state
        .repository()
        .append_audit_event(aiec_core::storage::AuditEvent {
            id: new_id(),
            occurred_at: Utc::now(),
            tenant_id: Some(principal.tenant_id),
            actor: format!("key:{}", principal.key_id),
            action: action.to_string(),
            subject_type: "sandbox".to_string(),
            subject_id: Some(sandbox_id.to_string()),
            result: if ok { "success" } else { "failure" }.to_string(),
            request_id: None,
            remote_addr: None,
            detail: detail.clone(),
        })
        .await;
}

/// Records one sandbox exec in the audit trail.
///
/// The detail is passed in already scrubbed by the caller. An audit write never
/// fails the operation it describes: losing the record is bad, refusing the
/// user's command because the record could not be written is worse.
async fn record_sandbox_exec(
    state: &AppState,
    principal: &Principal,
    sandbox_id: Uuid,
    result: &str,
    exit_code: Option<i32>,
    duration_ms: Option<u64>,
    detail: &Value,
) {
    let mut detail = detail.clone();
    if let Some(object) = detail.as_object_mut() {
        object.insert("exit_code".to_owned(), json!(exit_code));
        object.insert("duration_ms".to_owned(), json!(duration_ms));
    }
    let _ = state
        .repository()
        .append_audit_event(aiec_core::storage::AuditEvent {
            id: new_id(),
            occurred_at: Utc::now(),
            tenant_id: Some(principal.tenant_id),
            actor: format!("key:{}", principal.key_id),
            action: "sandbox.exec".to_string(),
            subject_type: "sandbox".to_string(),
            subject_id: Some(sandbox_id.to_string()),
            result: result.to_string(),
            // The principal carries no request id; correlation is by sandbox id
            // and time, which is what this log is for.
            request_id: None,
            remote_addr: None,
            detail,
        })
        .await;
}

async fn exec_sandbox(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(b): Json<ExecBody>,
) -> ApiResult<ExecResult> {
    if let Err(error) = p.authorize(Scope::SandboxesWrite) {
        // Recorded before returning: a refusal by policy is the most
        // security-relevant event a handler can produce, and audit_log is
        // append-only, so an unrecorded refusal cannot be reconstructed later.
        record_sandbox_exec(
            &s,
            &p,
            id,
            "denied",
            None,
            None,
            &json!({ "denied": "sandboxes:write", "command": b.command }),
        )
        .await;
        return Err(ApiFailure::from(error));
    }
    let x = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if x.state != SandboxState::Running {
        return Err(ApiFailure::from(CoreError::Conflict(
            "sandbox is not running".into(),
        )));
    }
    let mut r = b.into_request()?;
    validate_exec(&r).map_err(ApiFailure::from)?;

    // Recorded before the tenant's secrets are merged in, and deliberately as
    // shapes rather than values: `audit_log.detail` is not a secret store, and
    // logging the request wholesale would write every injected secret to disk in
    // plaintext. Environment keys are named so a reader can see what the command
    // was given, never what those values were.
    let audit_detail = json!({
        "command": r.command,
        "cwd": r.working_directory,
        "timeout_seconds": r.timeout_seconds,
        "env_keys": r.environment.keys().collect::<Vec<_>>(),
        "stdin_bytes": r.stdin.as_deref().map(str::len),
    });

    r.environment.extend(s.secret_values(p.tenant_id, id).await);
    let started = std::time::Instant::now();
    let outcome = s.runtime_for(&x)?.exec(&x, r).await;
    let duration_ms = started.elapsed().as_millis() as u64;
    match &outcome {
        Ok(result) => {
            record_sandbox_exec(
                &s,
                &p,
                id,
                "success",
                Some(result.exit_code),
                Some(duration_ms),
                &audit_detail,
            )
            .await;
        }
        Err(_) => {
            record_sandbox_exec(
                &s,
                &p,
                id,
                "failure",
                None,
                Some(duration_ms),
                &audit_detail,
            )
            .await;
        }
    }
    Ok(Json(outcome.map_err(ApiFailure::from)?))
}

async fn git_diff(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    let sandbox = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if sandbox.state != SandboxState::Running {
        return Err(ApiFailure::from(CoreError::Conflict(
            "sandbox is not running".into(),
        )));
    }
    let result = s
        // The sandbox's own runtime, not the deployment's primary one. Every
        // other sandbox verb dispatches through `runtime_for`, so on a
        // deployment whose primary runtime is Docker a Firecracker sandbox had
        // its `git_diff` executed by the Docker path - which is either not the
        // machine holding the repository, or a machine that does not exist.
        .runtime_for(&sandbox)?
        .exec(
            &sandbox,
            ExecRequest {
                command: vec![
                    "git".into(),
                    "-C".into(),
                    "/workspace/repository".into(),
                    "diff".into(),
                    "--binary".into(),
                ],
                working_directory: Some("/workspace".into()),
                environment: BTreeMap::new(),
                timeout_seconds: 60,
                stdin: None,
            },
        )
        .await
        .map_err(ApiFailure::from)?;
    if result.exit_code != 0 || result.timed_out {
        return Err(ApiFailure::new(
            StatusCode::BAD_GATEWAY,
            "git_diff_failed",
            format!(
                "git diff exited with {} (timed_out={})",
                result.exit_code, result.timed_out
            ),
        ));
    }
    Ok(Json(json!({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
    })))
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
    if let Err(error) = p.authorize(Scope::SandboxesWrite) {
        record_sandbox_file(
            &s,
            &p,
            id,
            "sandbox.file.write",
            false,
            &json!({ "denied": "sandboxes:write", "path": r.path }),
        )
        .await;
        return Err(ApiFailure::from(error));
    }
    let x = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    // The path and the size, never the content: what was written is the payload
    // and may be a secret the caller is staging inside the sandbox.
    // The decoded size, not the base64 length: a reader comparing this against
    // a diff or an object-store listing would otherwise be off by a third.
    let decoded_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &r.content_base64,
    )
    .map(|bytes| bytes.len())
    .unwrap_or(r.content_base64.len());
    let detail = json!({ "path": r.path, "bytes": decoded_bytes });
    let outcome = s.runtime_for(&x)?.put_file(&x, r).await;
    record_sandbox_file(&s, &p, id, "sandbox.file.write", outcome.is_ok(), &detail).await;
    outcome.map_err(ApiFailure::from)?;
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
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(
        s.runtime_for(&x)?
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
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(
        s.runtime_for(&x)?
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
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    s.runtime_for(&x)?
        .delete_file(&x, DeleteFileRequest { path: q.path })
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
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    s.runtime_for(&x)?
        .make_directory(&x, r)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(json!({"status":"created"})))
}
fn snapshot_kind_name(kind: SnapshotKind) -> &'static str {
    match kind {
        SnapshotKind::VirtualMachine => "virtual_machine",
        SnapshotKind::Memory => "memory",
        SnapshotKind::Workspace => "workspace",
    }
}

fn snapshot_kind(value: &str) -> Result<SnapshotKind, ApiFailure> {
    match value {
        "virtual_machine" => Ok(SnapshotKind::VirtualMachine),
        "memory" => Ok(SnapshotKind::Memory),
        "workspace" => Ok(SnapshotKind::Workspace),
        other => Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "snapshot_kind",
            format!("unsupported snapshot kind {other}"),
        )),
    }
}

async fn create_snapshot(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    body: Option<Json<CreateSnapshotRequest>>,
) -> ApiResult<Snapshot> {
    let request = body.map(|Json(value)| value).unwrap_or_default();
    p.authorize(Scope::SnapshotsWrite)
        .map_err(ApiFailure::from)?;
    let _permit = s.snapshot_slots.acquire().await.map_err(|_| {
        ApiFailure::from(CoreError::Unavailable("snapshot operations closed".into()))
    })?;
    let mut x = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let provider = s.platform.snapshots().ok_or_else(|| {
        ApiFailure::new(
            StatusCode::NOT_IMPLEMENTED,
            "snapshots_unavailable",
            "the configured runtime does not provide snapshots",
        )
    })?;
    let capabilities = provider.capabilities();
    // A caller that names no kind gets the kind this control plane can actually
    // finish, which is the workspace one. It used to default to `VirtualMachine`
    // whenever the runtime advertised microVM capture, and that default was the
    // common case on the production runtime.
    let kind = request.kind.unwrap_or(SnapshotKind::Workspace);
    let supported = match kind {
        SnapshotKind::Workspace => capabilities.workspace,
        // A VM or memory capture is not something this control plane can
        // finish, whatever the runtime says it can take. Completing one needs a
        // memory object, a disk object and a workspace object recorded on the
        // snapshot row, and `CapturedSnapshot` carries none of them: the only
        // path that stores a capture's bytes is the workspace one. Asking the
        // capability flag alone ran the whole capture, left the provider's
        // snapshot on the worker's disk, and then failed the row on the
        // completeness check with a Conflict nobody could act on.
        //
        // Refusing before `capture` runs is the difference between an honest
        // "this kind is not supported" and a failed capture that also leaks
        // worker-local state.
        SnapshotKind::VirtualMachine | SnapshotKind::Memory => false,
    };
    if !supported {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "unsupported_snapshot_kind",
            format!(
                "snapshot kind {} is not supported",
                snapshot_kind_name(kind)
            ),
        ));
    }
    let old = x.state;
    x.state = SandboxState::Snapshotting;
    s.commit_state(&x, old, SandboxState::Snapshotting)
        .await
        .map_err(ApiFailure::from)?;
    let outcome: Result<Snapshot, ApiFailure> = async {
        let mut captured = provider
            .capture(
                &x,
                &SnapshotRequest {
                    kind,
                    // Tenant-prefixed like every other object key in the
                    // system, so the bytes say whose they are to anyone reading
                    // the bucket, and so the upload claim can check the prefix
                    // rather than trusting the caller's tenancy.
                    object_key: format!("tenants/{}/snapshots/{id}/{}", p.tenant_id, new_id()),
                },
            )
            .await
            .map_err(ApiFailure::from)?;
        // A workspace capture only survives the worker that produced it if the
        // archive is stored where every worker can read it. Persisting before the
        // metadata row exists means a stored snapshot never points at bytes that
        // nobody else can reach.
        if captured.kind == SnapshotKind::Workspace {
            if captured.archive.is_empty() {
                return Err(ApiFailure::new(
                    StatusCode::CONFLICT,
                    "snapshot_not_portable",
                    "the runtime returned no workspace archive to store",
                ));
            }
            let store = s.artifact_store().ok_or_else(|| {
                ApiFailure::new(
                    StatusCode::NOT_IMPLEMENTED,
                    "artifacts_unavailable",
                    "artifact storage is not configured",
                )
            })?;
            let repository = s.repository();
            repository
                .reserve_artifact_upload(p.tenant_id, None, &captured.object_key)
                .await
                .map_err(ApiFailure::from)?;
            let stored = tokio::time::timeout(
                std::time::Duration::from_secs(artifact_gc::MAX_ARTIFACT_UPLOAD_SECONDS),
                store.put(
                    &captured.object_key,
                    bytes::Bytes::from(std::mem::take(&mut captured.archive)),
                ),
            )
            .await
            .map_err(|_| {
                ApiFailure::from(CoreError::Unavailable("snapshot upload timed out".into()))
            })?
            .map_err(ApiFailure::from)?;
            repository
                .complete_artifact_upload(p.tenant_id, None, &captured.object_key)
                .await
                .map_err(ApiFailure::from)?;
            if stored.checksum_sha256 != captured.checksum_sha256 {
                return Err(ApiFailure::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "snapshot_archive_corrupt",
                    "the stored workspace archive does not match the captured bytes",
                ));
            }
        }
        let snap = Snapshot {
            id: captured.id,
            tenant_id: p.tenant_id,
            sandbox_id: id,
            object_key: captured.object_key.clone(),
            size_bytes: captured.size_bytes,
            image_id: x.image_id.clone(),
            created_at: Utc::now(),
        };
        // One write only: `put_stored_snapshot` records every column of the
        // `snapshots` row, so the separate metadata insert was a second insert of
        // the same primary key and failed the whole capture.
        s.repository()
            .put_stored_snapshot(aiec_core::storage::StoredSnapshot {
                id: snap.id,
                tenant_id: p.tenant_id,
                sandbox_id: id,
                object_key: captured.object_key.clone(),
                manifest_object_key: format!("{}.manifest.json", snap.object_key),
                memory_object_key: None,
                disk_object_key: None,
                // A workspace capture stores the workspace under the primary object
                // key; a memory or VM capture stores it in a separate artifact. Only
                // claim the object the provider actually produced, so "complete"
                // means what it says and recovery can find the archive.
                workspace_object_key: (captured.kind
                    == aiec_core::snapshots::SnapshotKind::Workspace)
                    .then(|| captured.object_key.clone()),
                size_bytes: captured.size_bytes,
                image_id: snap.image_id.clone(),
                checksum_sha256: captured.checksum_sha256,
                kind: snapshot_kind_name(captured.kind).into(),
                complete: true,
                manifest: json!({"kind": snapshot_kind_name(captured.kind), "runtime": x.runtime}),
                created_at: snap.created_at,
            })
            .await
            .map_err(ApiFailure::from)?;
        Ok(snap)
    }
    .await;
    let resumed = s.commit_state(&x, SandboxState::Snapshotting, old).await;
    match (outcome, resumed) {
        (Ok(snapshot), Ok(_)) => Ok(Json(snapshot)),
        (Err(error), Ok(_)) => Err(error),
        (outcome, Err(error)) => {
            tracing::error!(
                sandbox_id = %id,
                %error,
                capture_error = ?outcome.err().map(|failure| failure.message),
                "snapshot operation could not restore the sandbox state",
            );
            Err(ApiFailure::from(error))
        }
    }
}
/// The paging parameters every sandbox-scoped history listing takes.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ListHistoryQuery {
    /// Rows to return. Clamped to the ceiling by the store as well as here.
    #[serde(default)]
    limit: Option<u32>,
    /// The previous page's last row: when it was created, and which one. Both
    /// halves or neither.
    #[serde(default)]
    after_created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    after_id: Option<Uuid>,
}

/// Default page size for a sandbox's history listings.
const DEFAULT_HISTORY_PAGE: u32 = 50;

/// Reads the paired paging cursor, refusing half of one.
///
/// All three paged history routes - snapshots, Guard proposals, Guard tool
/// approvals - take the same two query parameters and have to mean the same
/// thing by them, so the rule lives here once. A cursor with only a timestamp
/// names no row to start after, and one with only an id cannot order a page
/// that has not been read; guessing either would silently return the wrong
/// page rather than fail.
pub(crate) fn page_cursor(
    created_at: Option<DateTime<Utc>>,
    id: Option<Uuid>,
) -> Result<Option<PageCursor>, ApiFailure> {
    match (created_at, id) {
        (None, None) => Ok(None),
        (Some(created_at), Some(id)) => Ok(Some(PageCursor { created_at, id })),
        _ => Err(ApiFailure::from(CoreError::InvalidRequest(
            "after_created_at and after_id must be given together".into(),
        ))),
    }
}

/// The run listing's cursor. Same pair-or-nothing rule as [`page_cursor`], and
/// the same reason: a half-supplied cursor would otherwise silently page from
/// an instant with no identity, which is a different query rather than an
/// error the caller can see.
fn run_cursor(
    requested_at: Option<DateTime<Utc>>,
    id: Option<Uuid>,
) -> Result<Option<aiec_core::storage::MatrixCursor>, ApiFailure> {
    match (requested_at, id) {
        (None, None) => Ok(None),
        (Some(requested_at), Some(id)) => {
            Ok(Some(aiec_core::storage::MatrixCursor { requested_at, id }))
        }
        _ => Err(ApiFailure::from(CoreError::InvalidRequest(
            "after_requested_at and after_id must be given together".into(),
        ))),
    }
}

async fn list_snapshots(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListHistoryQuery>,
) -> ApiResult<aiec_core::storage::SnapshotPage> {
    p.authorize(Scope::SnapshotsRead)
        .map_err(ApiFailure::from)?;
    let after = page_cursor(query.after_created_at, query.after_id)?;
    // Clamped at the route as well as in the store, so the response and the
    // query agree about what a limit is: the caller cannot read past the
    // maximum by naming it, and a store that forgot to clamp is not the thing
    // that gets to decide.
    let limit = query
        .limit
        .unwrap_or(DEFAULT_HISTORY_PAGE)
        .clamp(1, aiec_core::storage::MAX_SNAPSHOT_PAGE);
    Ok(Json(
        s.repository()
            .list_snapshots(p.tenant_id, id, limit, after)
            .await
            .map_err(ApiFailure::from)?,
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
    if let Some(policy) = s.platform.policy() {
        let decision = policy.evaluate(PolicyOperation::RestoreSnapshot(&r));
        if !decision.allowed {
            return Err(ApiFailure::new(
                StatusCode::BAD_REQUEST,
                "policy_denied",
                decision
                    .reason
                    .unwrap_or_else(|| "restore denied by policy".into()),
            ));
        }
    }
    let stored = s
        .repository()
        .get_stored_snapshot(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let kind = snapshot_kind(&stored.kind)?;
    // Capture refuses a provider capture because this control plane cannot
    // finish one, and restore has the same limit from the other end: the bytes
    // a `virtual_machine` or `memory` row names are not recorded anywhere this
    // path can read, so the only thing it could do is allocate a machine, boot
    // whatever the provider still had, and then tear it down again - through
    // `schedule` rather than owned admission, and with a teardown no state fence
    // behind it. Rows of those kinds exist in older databases, so the refusal
    // is explicit rather than an assumption that they never did.
    if kind != SnapshotKind::Workspace {
        let named = match kind {
            SnapshotKind::VirtualMachine => "virtual_machine",
            SnapshotKind::Memory => "memory",
            SnapshotKind::Workspace => unreachable!("checked above"),
        };
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "unsupported_snapshot_kind",
            format!(
                "restoring a {named} snapshot is not supported; this deployment restores workspace snapshots"
            ),
        ));
    }
    if !stored.complete {
        return Err(ApiFailure::from(CoreError::Conflict(
            "snapshot is incomplete".into(),
        )));
    }
    let runtime = match r.runtime {
        Some(runtime) => runtime,
        None => match stored.manifest.get("runtime") {
            Some(value) => RuntimeKind::deserialize(value).map_err(|error| {
                ApiFailure::from(CoreError::Conflict(format!(
                    "invalid snapshot runtime: {error}"
                )))
            })?,
            None => {
                s.repository()
                    .get_sandbox(p.tenant_id, stored.sandbox_id)
                    .await
                    .map_err(ApiFailure::from)?
                    .runtime
            }
        },
    };
    if !s.allows_runtime(runtime) {
        return Err(ApiFailure::new(
            StatusCode::FORBIDDEN,
            "runtime_not_permitted",
            "this deployment offers microVM-class isolation only; process and container runtimes are self-hosted only",
        ));
    }
    // A restore boots a machine, so the image it boots is admitted the same way
    // a create admits one. Taking `r.image` verbatim meant the only boot path
    // that skipped the signed manifest resolver was the one booting an image
    // the deployment never vouched for: a tenant with any complete snapshot
    // could name any image string and get it into a microVM. An image the
    // caller does not name is the snapshot's own, which was admitted when the
    // snapshot was taken.
    let image_id = match r.image.as_deref() {
        Some(image) => admit_image(&s, runtime, image).await?,
        None => stored.image_id.clone(),
    };
    let now = Utc::now();
    let mut x = Sandbox {
        id: new_id(),
        tenant_id: p.tenant_id,
        node_id: None,
        image_id,
        state: SandboxState::Restoring,
        runtime,
        cpu: r.cpu.unwrap_or(1),
        memory_mb: r.memory_mb.unwrap_or(512),
        disk_mb: r.disk_mb.unwrap_or(2048),
        timeout_seconds: 900,
        network: NetworkPolicy::default(),
        environment: Default::default(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    };
    // Ordinary admission, readiness and rollback: workspace bytes come from
    // shared storage, never a provider's worker-local capture path.
    x.state = SandboxState::Creating;
    x.environment.workspace = WorkspaceSpec::Snapshot { snapshot_id: id };
    let request_id = x.id;
    let restored = provision_sandbox(
        &s,
        p.tenant_id,
        request_id,
        x,
        aiec_core::runtime::RuntimeCapabilities {
            portable_workspace: true,
            workspace_snapshot: true,
            ..Default::default()
        },
        None,
        false,
    )
    .await?;
    Ok(Json(restored.sandbox))
}
async fn delete_snapshot(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    p.authorize(Scope::SnapshotsWrite)
        .map_err(ApiFailure::from)?;
    s.repository()
        .delete_snapshot(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(json!({"status":"deleted"})))
}
async fn usage(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Vec<UsageSummary>> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    let events = s
        .repository()
        .usage(p.tenant_id)
        .await
        .map_err(ApiFailure::from)?;
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

// -- runs ---------------------------------------------------------------------

/// Carries the id of the run a request produced, so a client can log or
/// follow it without parsing the document that carries it too.
const RUN_ID_HEADER: &str = "x-aiec-run-id";

/// Run page size when the caller states none.
const DEFAULT_RUN_PAGE: u32 = 50;

/// Ceiling on a run page. A caller asking for their whole history in one
/// response is asking the control plane to hold it all in memory, and the
/// tenant's own history is not a reason to skip the bound.
const MAX_RUN_PAGE: u32 = 200;

#[derive(Deserialize)]
struct ListRunsQuery {
    state: Option<String>,
    limit: Option<u32>,
    /// `requested_at` of the last run of the previous page.
    after_requested_at: Option<DateTime<Utc>>,
    /// Identifier of that run, which breaks a `requested_at` tie.
    after_id: Option<Uuid>,
}

/// A run's artifact plus where its bytes are.
#[derive(Serialize)]
struct RunArtifactResponse {
    #[serde(flatten)]
    artifact: RunArtifactRef,
    /// Absolute within the API, so it can be handed to anything that speaks
    /// HTTP rather than being reassembled by the caller.
    download_url: String,
}

/// Starts a run and returns it settled.
///
/// This handler is synchronous on purpose, and that is not an oversight to be
/// tidied away: `submit_and_execute` creates the run, drives it and destroys
/// the machine it used before it returns, and the state it hands back is the
/// only record that the work actually happened. Answering early and finishing
/// in the background would detach the run's lifetime from the request that
/// asked for it, and with it the caller's ability to see a machine that
/// outlived its run.
async fn create_run(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    Json(mut request): Json<runs::RunRequest>,
) -> Result<Response, ApiFailure> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    // The header only fills a gap: a key stated in the body is the more
    // specific of the two, and quietly overriding it would execute neither
    // request the caller thought they were making.
    if request.idempotency_key.is_none()
        && let Some(key) = headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|key| !key.is_empty())
    {
        request.idempotency_key = Some(key.to_owned());
    }
    let run = runs::submit_and_execute(&s, p.tenant_id, request)
        .await
        .map_err(ApiFailure::from)?;
    run_response(StatusCode::CREATED, &run)
}

/// Lists the caller's runs, newest first.
///
/// The response stays a bare array, so a client that never pages is unaffected.
/// It is paged anyway: `after_requested_at` with `after_id` continues past the
/// last run of the previous page, and a caller that stops at `MAX_RUN_PAGE` can
/// say which run it stopped after rather than discovering the ceiling by
/// counting.
async fn list_runs(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Query(query): Query<ListRunsQuery>,
) -> ApiResult<Vec<Run>> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    let state = match query.state.as_deref() {
        Some(raw) => Some(RunState::parse(raw.trim()).ok_or_else(|| {
            ApiFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("unknown run state `{raw}`"),
            )
        })?),
        None => None,
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_RUN_PAGE)
        .clamp(1, MAX_RUN_PAGE);
    let after = run_cursor(query.after_requested_at, query.after_id)?;
    Ok(Json(
        s.repository()
            .list_runs(p.tenant_id, state, limit, after)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

/// Reads one of the caller's runs.
async fn get_run(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Run> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    // The tenant is part of the lookup, not a check afterwards: a run that
    // belongs to somebody else has to read as missing, because a 403 would
    // confirm the id exists and hand out a directory of other people's work.
    Ok(Json(
        s.repository()
            .get_run(p.tenant_id, id)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

/// A run's history, in the order it happened.
async fn list_run_events(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Vec<RunEvent>> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    // The event table carries no tenant of its own, so ownership is settled
    // first: without this, a run belonging to another tenant would answer with
    // an empty history and read as "this run has no events".
    s.repository()
        .get_run(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(
        s.repository()
            .list_run_events(p.tenant_id, id)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

/// Every attempt a run made, in order.
///
/// Written on both outcomes, and readable here: attempts that cannot be read
/// are just a number, and "it failed twice then passed" is the fact a caller
/// evaluating an agent most needs.
async fn list_run_attempts(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    // Tenant-scoped first, so a foreign run is 404 rather than an empty list.
    s.repository()
        .get_run(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let attempts = s
        .repository()
        .list_run_attempts(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(json!(attempts)))
}

/// The artifacts a run collected, with a URL for each one's bytes.
async fn list_run_artifacts(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Vec<RunArtifactResponse>> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    s.repository()
        .get_run(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let artifacts = s
        .repository()
        .list_run_artifacts(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(
        artifacts
            .into_iter()
            .map(|artifact| RunArtifactResponse {
                download_url: run_artifact_download_url(id, &artifact.name),
                artifact,
            })
            .collect(),
    ))
}

/// Fetches one artifact's bytes.
///
/// The name arrives percent-decoded by the router, so a listing's own URL
/// resolves back to the exact name that was recorded - `/workspace/report.txt`
/// included - while a hand-written URL still has to name an artifact this run
/// actually collected.
async fn download_run_artifact(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((id, name)): Path<(Uuid, String)>,
) -> Result<Response, ApiFailure> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    s.repository()
        .get_run(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let artifact = s
        .repository()
        .list_run_artifacts(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?
        .into_iter()
        // The name is matched against the run's own records rather than turned
        // into an object key: a caller-supplied path must not be able to name a
        // key the run never collected.
        .find(|artifact| artifact.name == name)
        .ok_or_else(|| ApiFailure::from(CoreError::NotFound("run artifact not found".into())))?;
    let store = s.artifact_store().ok_or_else(|| {
        ApiFailure::new(
            StatusCode::NOT_IMPLEMENTED,
            "artifacts_unavailable",
            "artifact storage is not configured",
        )
    })?;
    // Read back under the checksum that was recorded at collection, when there is
    // one. The alternative is serving whatever is at the key now, which is how a
    // corrupted or overwritten object reaches a caller as if it were the file
    // their task produced.
    let expected = artifact
        .checksum_sha256
        .as_deref()
        .map(|checksum| checksum.to_owned());
    let download = match store
        .get_verified(
            &artifact.object_key,
            &GetObjectOptions {
                if_match: None,
                expected_checksum_sha256: expected,
            },
            ARTIFACT_MAX_BYTES as u64,
        )
        .await
    {
        Ok(download) => download,
        Err(CoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiFailure::from(CoreError::NotFound(
                "run artifact not found".into(),
            )));
        }
        Err(error) => return Err(ApiFailure::from(error)),
    };
    if artifact.size_bytes < 0 || artifact.size_bytes as u64 != download.metadata.size_bytes {
        return Err(ApiFailure::from(CoreError::Conflict(
            "stored artifact size does not match its recorded size".into(),
        )));
    }
    // The recorded content type is a stored string, so it is used only if it
    // is still a legal header value; otherwise the bytes are served as the
    // opaque thing they are.
    let content_type = artifact
        .content_type
        .filter(|value| HeaderValue::from_str(value).is_ok())
        .and_then(|value| HeaderValue::from_str(&value).ok())
        .unwrap_or_else(|| HeaderValue::from_static("application/octet-stream"));
    let size_bytes = download.metadata.size_bytes;
    let stream = futures::stream::try_unfold(download.body, |mut body| async move {
        match body.next_chunk().await? {
            Some(bytes) => Ok(Some((bytes, body))),
            None => Ok::<_, CoreError>(None),
        }
    });
    let mut response = axum::body::Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&size_bytes.to_string())
            .map_err(|error| ApiFailure::from(CoreError::Backend(error.to_string())))?,
    );
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    Ok(response)
}

/// Stops a run and reclaims the machine it was holding.
///
/// Cancelling a run that has already finished is not a failure. The caller's
/// intent -- no machine of mine is still working -- is already true, and a
/// second cancel after a first one succeeded must not look like a mistake.
async fn cancel_run(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiFailure> {
    p.authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    let store = s.repository();
    let run = store
        .get_run(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if run.state.is_terminal() {
        return run_response(StatusCode::OK, &run);
    }
    let cancelled = match store
        .update_run_state(p.tenant_id, id, run.state, RunState::Cancelled)
        .await
    {
        Ok(cancelled) => cancelled,
        // The run moved while this request was in flight. If it finished in the
        // meantime the caller gets the outcome they asked for; if it is still
        // live, the state genuinely changed under us and saying so is more
        // honest than cancelling a run nobody can identify any more.
        Err(CoreError::Conflict(_)) | Err(CoreError::NotFound(_)) => {
            let current = store
                .get_run(p.tenant_id, id)
                .await
                .map_err(ApiFailure::from)?;
            if current.state.is_terminal() {
                return run_response(StatusCode::OK, &current);
            }
            return Err(ApiFailure::from(CoreError::Conflict(
                "run state changed".into(),
            )));
        }
        Err(error) => return Err(ApiFailure::from(error)),
    };
    let (cancelled, released) = release_run_sandboxes(&s, &cancelled).await;
    runs::event(
        &s,
        &cancelled,
        "run.cancelled",
        json!({ "destroyed_sandboxes": released }),
    )
    .await;
    run_response(StatusCode::OK, &cancelled)
}

/// Destroys the machines a cancelled run was holding.
///
/// The run is cancelled before this runs, so a machine that will not go is
/// reported on the run's results rather than logged and forgotten: capacity
/// nobody believes is still held is capacity nobody reclaims.
///
/// The run to show the caller, and the machines that were actually reclaimed,
/// both come back: "cancelled" on its own does not say whether the compute went
/// with it.
async fn release_run_sandboxes(state: &AppState, run: &Run) -> (Run, Vec<Uuid>) {
    let mut released = Vec::new();
    let mut results = run.results.clone();
    let held = state
        .repository()
        .list_run_sandboxes(run.tenant_id, run.id)
        .await
        .unwrap_or_default();
    for link in held {
        // The same teardown as a normal finish, so cancelling stops the machine
        // rather than only forgetting it.
        let outcome = match state
            .repository()
            .get_sandbox(run.tenant_id, link.sandbox_id)
            .await
        {
            Ok(sandbox) => {
                runs::tear_down_sandbox(state, run.tenant_id, link.sandbox_id, &sandbox).await
            }
            Err(CoreError::NotFound(_)) => continue,
            Err(error) => Err(error),
        };
        match outcome {
            Ok(()) => released.push(link.sandbox_id),
            Err(error) => {
                tracing::warn!(
                    run_id = %run.id,
                    sandbox_id = %link.sandbox_id,
                    error = %error,
                    "could not destroy a cancelled run's sandbox"
                );
                results.cleanup_failed = Some(CleanupReport {
                    sandbox_id: link.sandbox_id,
                    error: error.to_string(),
                });
            }
        }
    }
    let settled = match state
        .repository()
        .record_run_results(run.tenant_id, run.id, results, run.state)
        .await
    {
        Ok(updated) => updated,
        Err(error) => {
            tracing::warn!(
                run_id = %run.id,
                error = %error,
                "could not record a cancelled run's results"
            );
            run.clone()
        }
    };
    (settled, released)
}

/// Renders a run with its id in a header as well as in the body.
fn run_response(status: StatusCode, run: &Run) -> Result<Response, ApiFailure> {
    let id = HeaderValue::from_str(&run.id.to_string()).map_err(|error| {
        ApiFailure::from(CoreError::Backend(format!(
            "run id is not a header value: {error}"
        )))
    })?;
    let mut response = (status, Json(run)).into_response();
    response.headers_mut().insert(RUN_ID_HEADER, id);
    Ok(response)
}
/// Starts the periodic lease sweeper.
///
/// This exists because capacity was only ever reclaimed by an operator calling
/// `POST /v1/reconcile`. A cluster that leaked a machine therefore stayed
/// exhausted forever, with the only remedy a manual request - which is not a
/// remedy, it is a page someone has to be on. Every leaked sandbox becomes a
/// permanent reduction in capacity, and enough of them take the cluster down.
///
/// The pass is bounded, idempotent, and logged, and it runs in its own task so
/// a slow database cannot delay serving requests.
/// How long a sandbox may sit in a non-terminal state before it is considered
/// abandoned. Long enough that placement, image pull and start all comfortably
/// fit inside it.
const STRANDED_GRACE: chrono::Duration = chrono::Duration::minutes(10);

/// Upper bound on abandoned sandboxes released in one pass.
const STRANDED_LIMIT: u32 = 50;

/// Upper bound on leases released in one pass because their sandbox is done.
const ORPHANED_LEASE_LIMIT: u32 = 200;

/// Upper bound on pages of abandoned sandboxes examined in one pass.
///
/// A pass that reclaims nothing stops on its own; this is the backstop for the
/// case where every page makes a little progress and the backlog is larger than
/// any single tick should spend.
const STRANDED_MAX_PAGES: u32 = 4;

struct MaintenanceTasks([tokio::task::JoinHandle<()>; 2]);

impl Drop for MaintenanceTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

fn spawn_maintenance(state: AppState) -> Result<MaintenanceTasks, std::io::Error> {
    let config = artifact_gc::ArtifactGcConfig::from_env()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let artifact_state = state.clone();
    let artifacts = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(store) = artifact_state.artifact_store() else {
                continue;
            };
            let repository = artifact_state.repository();
            match artifact_gc::sweep_artifacts(repository.as_ref(), store.as_ref(), &config).await {
                Ok(outcome) if outcome.claimed > 0 || outcome.temporary_files_deleted > 0 => {
                    tracing::info!(
                        claimed = outcome.claimed,
                        deleted = outcome.deleted,
                        retrying = outcome.retrying,
                        stale_claims = outcome.stale_claims,
                        temporary_files_deleted = outcome.temporary_files_deleted,
                        "artifact reclamation completed",
                    );
                }
                Ok(_) => {}
                Err(CoreError::Unsupported(_)) if !artifact_state.is_production() => {}
                Err(error) => tracing::warn!(%error, "artifact reclamation failed"),
            }
        }
    });
    Ok(MaintenanceTasks([spawn_lease_sweeper(state), artifacts]))
}

fn spawn_lease_sweeper(state: AppState) -> tokio::task::JoinHandle<()> {
    // Announced at startup and on every pass. A background task that panics is
    // silent - tokio drops it and nothing is ever reclaimed again - so its
    // presence has to be visible from outside or "the sweeper is not running"
    // is indistinguishable from "the sweeper is running and has nothing to do".
    tracing::info!("the lease sweeper is starting");
    tokio::spawn(async move {
        // Short enough that a dead machine does not hold capacity for long,
        // long enough to be uninteresting.
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            sweep_once(&state).await;
        }
    })
}

/// One pass: return capacity held by dead leases, then release sandboxes that
/// no lease and no unfinished run accounts for.
async fn sweep_once(state: &AppState) {
    match state.repository().retained_runs_due(Utc::now(), 50).await {
        Ok(runs) => {
            for run in runs {
                if let Err(error) = runs::expire_retention(state, &run).await {
                    tracing::warn!(
                        run_id = %run.id,
                        error = %error,
                        "could not reclaim expired retention; retrying on the next sweep"
                    );
                }
            }
        }
        Err(CoreError::Unsupported(_)) if !state.is_production() => {}
        Err(error) => {
            tracing::warn!(error = %error, "could not list expired run retention");
        }
    }
    let expired = match state
        .repository()
        .reconcile_expired_leases(RECONCILE_LIMIT)
        .await
    {
        Ok(actions) => {
            let count = actions.len();
            if count > 0 {
                tracing::info!(
                    expired = count,
                    "the lease sweeper returned capacity held by expired leases"
                );
            }
            count
        }
        Err(error) => {
            tracing::warn!(error = %error, "the lease sweeper could not list expiries");
            return;
        }
    };
    let mut seen = 0usize;
    // Deliberately not calling `recover_expired_leases`. That re-places the
    // sandbox on a new worker and rebuilds its workspace, which is right when an
    // operator asks for it and exactly wrong on a timer: it would resurrect
    // machines for sandboxes whose runs finished long ago, turning a reclaimed
    // slot back into a workload nobody asked for. Reclaiming is automatic;
    // resurrecting stays a deliberate act.

    // Leases that are still valid but belong to a sandbox already destroyed or
    // failed. Neither of the two reclaim paths below can see these: the lease is
    // alive, so the expiry pass skips it, and the sandbox is terminal, so the
    // stranded pass never selects it. A parallel soak left two vCPUs debited
    // because of exactly this, flat across three batches - the ledger was
    // internally consistent and still wrong.
    match state
        .repository()
        .release_orphaned_leases(ORPHANED_LEASE_LIMIT)
        .await
    {
        Ok(outcome) if outcome.released > 0 || outcome.already_released > 0 => tracing::info!(
            released = outcome.released,
            already_released = outcome.already_released,
            "the lease sweeper released leases whose sandbox had already finished"
        ),
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(error = %error, "could not release leases orphaned by finished sandboxes");
        }
    }

    // Sandboxes in a non-terminal state that nothing accounts for. Expiring a
    // lease returns the capacity, but the row stayed counted against the
    // tenant's active-sandbox quota forever - and quota is checked before
    // placement, so enough of them and a tenant cannot submit any work at all
    // while nodes report free capacity. That is how this host came to refuse
    // every run.
    let mut reclaimed = 0usize;
    // Paging is bounded by both a page count and evidence of progress.
    //
    // The page count alone is not enough, and the comment that used to claim
    // otherwise was wrong. A sandbox whose teardown keeps failing - an
    // unreachable worker, a fenced lease, a database error - is left untouched,
    // so it still matches the query and comes back on the next page. A loop that
    // only exits on a short page therefore never exits: it re-selects the same
    // fifty rows forever, with no sleep, and the sweeper never reaches its
    // ticker again. Stopping when a page reclaims nothing fixes that directly,
    // because a page that made no progress will not make progress on the next
    // one either, and the next tick can try again after the cause clears.
    for _ in 0..STRANDED_MAX_PAGES {
        let stranded = match state
            .repository()
            .list_stranded_sandboxes(Utc::now() - STRANDED_GRACE, STRANDED_LIMIT)
            .await
        {
            Ok(stranded) => stranded,
            Err(error) => {
                tracing::warn!(error = %error, "could not look for stranded sandboxes");
                return;
            }
        };
        if stranded.is_empty() {
            break;
        }
        seen += stranded.len();
        let mut reclaimed_this_page = 0usize;
        for sandbox in &stranded {
            match runs::abandon_sandbox(state, sandbox.tenant_id, sandbox.id, sandbox).await {
                Ok(()) => {
                    reclaimed += 1;
                    reclaimed_this_page += 1;
                }
                Err(error) => tracing::warn!(
                    sandbox_id = %sandbox.id,
                    error = %error,
                    "could not reclaim a stranded sandbox"
                ),
            }
        }
        if stranded.len() < STRANDED_LIMIT as usize || reclaimed_this_page == 0 {
            if reclaimed_this_page == 0 && !stranded.is_empty() {
                tracing::warn!(
                    stranded = stranded.len(),
                    "stranded sandboxes could not be reclaimed; leaving them for a later pass"
                );
            }
            break;
        }
    }
    tracing::debug!(expired, stranded = seen, reclaimed, "lease sweep complete");
    if reclaimed > 0 {
        tracing::info!(
            reclaimed,
            "the lease sweeper released sandboxes no run or lease accounted for"
        );
    }
}

/// Starts the Run executor when the store can queue, and holds it for the
/// lifetime of the listener.
///
/// The executor is service state, not listener state, so both entry points
/// start it: an API that stops claiming runs on shutdown leaves admitted work
/// waiting for lease recovery instead of finishing what it already owns.
fn start_run_executor(
    state: &AppState,
) -> Result<Option<run_queue::RunQueueDispatcher>, std::io::Error> {
    if !state.repository().supports_run_queue() {
        return Ok(None);
    }
    run_queue::spawn(state.clone(), state.run_queue_limits())
        .map(Some)
        .map_err(|error| {
            // Continuing here would admit runs that nothing can ever claim, and
            // hold each response open until the queue deadline expires it.
            tracing::error!(%error, "invalid Run queue limits; refusing to serve");
            std::io::Error::other(error.to_string())
        })
}

pub async fn serve(state: AppState, addr: std::net::SocketAddr) -> Result<(), std::io::Error> {
    let _maintenance = spawn_maintenance(state.clone())?;
    let executor = start_run_executor(&state)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let outcome = axum::serve(listener, app(state)).await;
    if let Some(executor) = executor {
        executor.shutdown().await;
    }
    outcome
}

pub async fn serve_tls(
    state: AppState,
    addr: std::net::SocketAddr,
    cert_path: impl AsRef<std::path::Path>,
    key_path: impl AsRef<std::path::Path>,
) -> Result<(), std::io::Error> {
    // The sweeper is a property of the control plane, not of a listener, so it
    // starts here as well as on the plain listener.
    let _maintenance = spawn_maintenance(state.clone())?;
    let executor = start_run_executor(&state)?;
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;
    let outcome = axum_server::bind_rustls(addr, config)
        // Without ConnectInfo the limiter cannot see the peer address, so every
        // unauthenticated caller collapsed into one shared bucket.
        .serve(app(state).into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await;
    if let Some(executor) = executor {
        executor.shutdown().await;
    }
    outcome
}

pub async fn serve_worker(
    service: WorkerService,
    addr: std::net::SocketAddr,
) -> Result<(), std::io::Error> {
    serve_worker_until(service, addr, std::future::pending()).await
}

/// Serves the worker until `shutdown` resolves, and not before the requests
/// already in flight have finished.
///
/// The distinction is the whole point. A worker that drops its listener on the
/// signal leaves a half-served create holding that sandbox's lifecycle gate,
/// and anything that then waits on the same gate - reclaiming the machines
/// this process is still running - waits behind it. Draining first means the
/// process is finished serving before it starts tidying up.
pub async fn serve_worker_until(
    service: WorkerService,
    addr: std::net::SocketAddr,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    // A worker holds no leases of its own, so it gets no sweeper.
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, service.router())
        .with_graceful_shutdown(shutdown)
        .await
}

pub async fn serve_worker_tls(
    service: WorkerService,
    addr: std::net::SocketAddr,
    cert_path: impl AsRef<std::path::Path>,
    key_path: impl AsRef<std::path::Path>,
) -> Result<(), std::io::Error> {
    serve_worker_tls_until(service, addr, cert_path, key_path, std::future::pending()).await
}

/// Serves the worker over TLS until `shutdown` resolves, bounded by how long a
/// request already in flight may hold the process open.
pub async fn serve_worker_tls_until(
    service: WorkerService,
    addr: std::net::SocketAddr,
    cert_path: impl AsRef<std::path::Path>,
    key_path: impl AsRef<std::path::Path>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;
    let handle = axum_server::Handle::new();
    let trigger = handle.clone();
    // Bounded, because the exit path that follows this one has to finish too:
    // a drain with no end would let one long request keep a worker's machines
    // on the host indefinitely, which is the leak this ordering exists to
    // close.
    tokio::spawn(async move {
        shutdown.await;
        trigger.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
    });
    axum_server::bind_rustls(addr, config)
        .handle(handle)
        .serve(
            service
                .router()
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiec_core::run::{
        Placement, RetentionPolicy, Run, RunArtifactRef, RunAttempt, RunEvent, RunResults,
        RunSandbox, RunState, WorkloadSpec,
    };
    use aiec_core::storage::{
        AuditEvent, MetadataStore, ObjectMetadata, Reassignment, SandboxEvent, SandboxOwnership,
        StoredSnapshot, TenantRecord, WorkerHeartbeat as HeartbeatRecord, WorkerLease,
        WorkerRegistration as RegistrationRecord, WorkerStatus as WorkerRecord,
    };
    use axum::{body::Body, http::Request};
    use std::collections::HashMap as TestMap;
    use tokio::sync::Mutex as TestMutex;
    use tower::util::ServiceExt;

    /// Metadata store double: the in-memory repository plus a lease table with
    /// generation compare-and-set and a run table, so the fencing and run
    /// routes can be exercised without a database.
    ///
    /// The run tables are here rather than in `MemoryRepository` because that
    /// store keeps no runs: a double that answered `Unsupported` could not show
    /// a cross-tenant read at all, which is the one thing the run routes exist
    /// to guarantee. The tenant filter is the point, so it is implemented the
    /// way the real store does it -- a row keyed by id, readable only by its
    /// owner, and missing to everyone else.
    #[derive(Default)]
    struct LeasedRepository {
        inner: Arc<aiec_storage::MemoryRepository>,
        leases: TestMutex<TestMap<Uuid, WorkerLease>>,
        runs: TestMutex<TestMap<Uuid, Run>>,
        run_events: TestMutex<TestMap<Uuid, Vec<RunEvent>>>,
        run_sandboxes: TestMutex<TestMap<Uuid, Vec<RunSandbox>>>,
        run_artifacts: TestMutex<TestMap<Uuid, Vec<RunArtifactRef>>>,
        run_attempts: TestMutex<TestMap<Uuid, Vec<RunAttempt>>>,
        /// Sandboxes created for a run, keyed by the request id that asked for
        /// them, so a retried request joins the machine it already has.
        sandbox_requests: TestMutex<TestMap<(Uuid, Uuid), SandboxId>>,
        /// When set, `record_run_failure` fails like a database that has gone
        /// away mid-settlement, so the run-execution failure path can be
        /// observed under a store that refuses the write.
        refuse_failure_writes: TestMutex<bool>,
    }

    impl LeasedRepository {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: aiec_storage::MemoryRepository::new(),
                leases: TestMutex::new(TestMap::new()),
                runs: TestMutex::new(TestMap::new()),
                run_events: TestMutex::new(TestMap::new()),
                run_sandboxes: TestMutex::new(TestMap::new()),
                run_artifacts: TestMutex::new(TestMap::new()),
                sandbox_requests: TestMutex::new(TestMap::new()),
                run_attempts: TestMutex::new(TestMap::new()),
                refuse_failure_writes: TestMutex::new(false),
            })
        }

        async fn insert(&self, lease: WorkerLease) {
            self.leases.lock().await.insert(lease.id, lease);
        }

        /// Puts a run in the table as though it had been created earlier, so a
        /// test can act on a run in a state no reachable amount of waiting would
        /// produce.
        async fn seed(&self, run: Run) {
            self.runs.lock().await.insert(run.id, run);
        }

        async fn stored_run(&self, tenant: Uuid, id: Uuid) -> Result<Run, CoreError> {
            self.runs
                .lock()
                .await
                .get(&id)
                .filter(|run| run.tenant_id == tenant)
                .cloned()
                .ok_or_else(|| CoreError::NotFound("run not found".into()))
        }

        /// The run a child row hangs off, under the tenant that owns it.
        ///
        /// Child rows carry no tenant of their own, so the tenant is settled
        /// here rather than read back off the row: a run belonging to someone
        /// else is not a run this caller may hang anything off, and a machine
        /// belonging to someone else is not one of this tenant's.
        async fn child_run(
            &self,
            tenant: Uuid,
            id: Uuid,
            machine: Option<Uuid>,
        ) -> Result<Run, CoreError> {
            let run = self.stored_run(tenant, id).await?;
            if let Some(machine) = machine
                && self.inner.get_sandbox(tenant, machine).await.is_err()
            {
                return Err(CoreError::Conflict(
                    "a run may only name a machine belonging to its own tenant".into(),
                ));
            }
            Ok(run)
        }
    }

    fn lease(tenant: Uuid, sandbox: Uuid, node: Uuid, generation: i64) -> WorkerLease {
        let now = Utc::now();
        WorkerLease {
            id: new_id(),
            tenant_id: tenant,
            sandbox_id: sandbox,
            node_id: node,
            generation,
            status: "active".into(),
            reason: None,
            expires_at: now + chrono::Duration::seconds(300),
            created_at: now,
            updated_at: now,
        }
    }

    fn platform(store: Arc<LeasedRepository>, runtime: Arc<dyn SandboxRuntime>) -> Platform {
        Platform::builder()
            .runtime(runtime.clone())
            .runtime_registry(Arc::new(aiec_core::runtime::RuntimeRegistry::with_runtime(
                RuntimeKind::Docker,
                runtime,
            )))
            .metadata_store(store)
            .scheduler(Arc::new(DevelopmentScheduler))
            .policy(Arc::new(DefaultPolicy))
            .build()
            .expect("platform")
    }

    fn test_state(store: Arc<LeasedRepository>, runtime: Arc<dyn SandboxRuntime>) -> AppState {
        AppState::development(platform(store, runtime)).with_worker_token("worker-token")
    }

    async fn worker_request(
        state: &AppState,
        method: axum::http::Method,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", "Bearer worker-token")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app(state.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn ownership_route_reports_the_durable_lease_to_its_owner() {
        let store = LeasedRepository::new();
        let tenant = new_id();
        let sandbox = new_id();
        let node = new_id();
        store.insert(lease(tenant, sandbox, node, 4)).await;
        let state = test_state(store, Arc::new(FenceRuntime));
        let (status, value) = worker_request(
            &state,
            axum::http::Method::GET,
            &format!("/v1/workers/{node}/ownership/{sandbox}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["node_id"], node.to_string());
        assert_eq!(value["generation"], 4);
        assert!(value["lease_id"].is_string());
    }

    #[tokio::test]
    async fn ownership_route_conflicts_for_a_foreign_node() {
        let store = LeasedRepository::new();
        let tenant = new_id();
        let sandbox = new_id();
        let node = new_id();
        let foreign = new_id();
        store.insert(lease(tenant, sandbox, node, 2)).await;
        let state = test_state(store, Arc::new(FenceRuntime));
        let (status, value) = worker_request(
            &state,
            axum::http::Method::GET,
            &format!("/v1/workers/{foreign}/ownership/{sandbox}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"]["code"], "conflict");
    }

    #[tokio::test]
    async fn ownership_route_reports_not_found_for_an_unleased_sandbox() {
        let store = LeasedRepository::new();
        let node = new_id();
        let state = test_state(store, Arc::new(FenceRuntime));
        let (status, value) = worker_request(
            &state,
            axum::http::Method::GET,
            &format!("/v1/workers/{node}/ownership/{}", new_id()),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(value["error"]["code"], "not_found");
    }

    #[tokio::test]
    async fn complete_route_rejects_a_superseded_generation() {
        let store = LeasedRepository::new();
        let tenant = new_id();
        let sandbox = new_id();
        let node = new_id();
        let held = lease(tenant, sandbox, node, 5);
        store.insert(held.clone()).await;
        let state = test_state(store.clone(), Arc::new(FenceRuntime));
        let (status, value) = worker_request(
            &state,
            axum::http::Method::POST,
            &format!("/v1/workers/{node}/leases/{}/complete", held.id),
            json!({"tenant_id": tenant, "generation": 4, "result": {"status": "late"}}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"]["code"], "conflict");
        assert_eq!(store.leases.lock().await[&held.id].status, "active");
    }

    #[tokio::test]
    async fn complete_route_rejects_a_lease_held_by_another_worker() {
        let store = LeasedRepository::new();
        let tenant = new_id();
        let sandbox = new_id();
        let node = new_id();
        let held = lease(tenant, sandbox, node, 1);
        store.insert(held.clone()).await;
        let state = test_state(store, Arc::new(FenceRuntime));
        let (status, value) = worker_request(
            &state,
            axum::http::Method::POST,
            &format!("/v1/workers/{}/leases/{}/complete", new_id(), held.id),
            json!({"tenant_id": tenant, "generation": 1}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            value["error"]["message"],
            "lease is not held by this worker"
        );
    }

    #[tokio::test]
    async fn renew_route_extends_the_current_generation_only() {
        let store = LeasedRepository::new();
        let tenant = new_id();
        let sandbox = new_id();
        let node = new_id();
        let held = lease(tenant, sandbox, node, 3);
        let previous_expiry = held.expires_at;
        store.insert(held.clone()).await;
        let state = test_state(store.clone(), Arc::new(FenceRuntime));
        let (status, value) = worker_request(
            &state,
            axum::http::Method::POST,
            &format!("/v1/workers/{node}/leases/{}/renew", held.id),
            json!({"tenant_id": tenant, "generation": 2}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"]["code"], "conflict");
        let (status, value) = worker_request(
            &state,
            axum::http::Method::POST,
            &format!("/v1/workers/{node}/leases/{}/renew", held.id),
            json!({"tenant_id": tenant, "generation": 3, "ttl_seconds": 600}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["generation"], 3);
        let renewed: WorkerLease = serde_json::from_value(value.clone()).expect("renewed lease");
        assert!(renewed.expires_at > previous_expiry);
    }

    struct FenceRuntime;
    #[async_trait::async_trait]
    impl SandboxRuntime for FenceRuntime {
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
        async fn destroy(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
            let _ = sandbox;
            Ok(())
        }
        async fn health(&self) -> aiec_core::runtime::RuntimeHealth {
            aiec_core::runtime::RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> aiec_core::runtime::RuntimeCapabilities {
            aiec_core::runtime::RuntimeCapabilities::default()
        }
    }

    #[async_trait::async_trait]
    impl MetadataStore for LeasedRepository {
        async fn create_sandbox(&self, value: Sandbox) -> Result<(), CoreError> {
            self.inner.create_sandbox(value).await
        }
        async fn get_sandbox(&self, tenant: TenantId, id: SandboxId) -> Result<Sandbox, CoreError> {
            self.inner.get_sandbox(tenant, id).await
        }
        async fn list_sandboxes(
            &self,
            tenant: TenantId,
            limit: u32,
            after: Option<PageCursor>,
        ) -> Result<SandboxPage, CoreError> {
            self.inner.list_sandboxes(tenant, limit, after).await
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
            match self.sandbox_ownership(id).await? {
                Some(ownership)
                    if ownership.lease_id == lease_id && ownership.generation >= generation =>
                {
                    self.inner
                        .update_state(tenant, id, expected, next, None)
                        .await
                        .map(|_| ())
                }
                Some(_) => Err(CoreError::Transient(
                    "stale sandbox lease generation".into(),
                )),
                None => Err(CoreError::Conflict("sandbox has no active lease".into())),
            }
        }
        async fn delete_sandbox(&self, tenant: TenantId, id: SandboxId) -> Result<(), CoreError> {
            self.inner.delete_sandbox(tenant, id).await
        }
        async fn put_key(&self, value: ApiKeyRecord) -> Result<(), CoreError> {
            self.inner.put_key(value).await
        }
        async fn get_key(&self, tenant: Uuid, id: Uuid) -> Result<Option<ApiKeyRecord>, CoreError> {
            self.inner.get_key(tenant, id).await
        }

        async fn find_key(&self, digest: &[u8; 32]) -> Result<ApiKeyRecord, CoreError> {
            self.inner.find_key(digest).await
        }
        async fn revoke_key(&self, tenant: TenantId, id: Uuid) -> Result<(), CoreError> {
            self.inner.revoke_key(tenant, id).await
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
            limit: u32,
            after: Option<aiec_core::storage::PageCursor>,
        ) -> Result<aiec_core::storage::SnapshotPage, CoreError> {
            self.inner
                .list_snapshots(tenant, sandbox, limit, after)
                .await
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
        async fn ping(&self) -> Result<(), CoreError> {
            self.inner.ping().await
        }

        async fn node_capacity_totals(&self) -> Result<aiec_core::NodeCapacity, CoreError> {
            self.inner.node_capacity_totals().await
        }

        async fn list_nodes(&self) -> Result<Vec<Node>, CoreError> {
            self.inner.list_nodes().await
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
        async fn latest_stored_snapshot(
            &self,
            tenant: TenantId,
            sandbox: SandboxId,
            kind: &str,
        ) -> Result<Option<StoredSnapshot>, CoreError> {
            self.inner
                .latest_stored_snapshot(tenant, sandbox, kind)
                .await
        }
        async fn create_sandbox_idempotent(
            &self,
            tenant: TenantId,
            request_id: RequestId,
            sandbox: Sandbox,
        ) -> Result<Sandbox, CoreError> {
            // A run asks for its machine by the run's own id, so a retried
            // placement has to join the machine it already has rather than
            // take a second one.
            let mut requests = self.sandbox_requests.lock().await;
            let key = (tenant, request_id);
            if let Some(existing) = requests.get(&key) {
                return self.inner.get_sandbox(tenant, *existing).await;
            }
            let id = sandbox.id;
            self.inner.create_sandbox(sandbox).await?;
            requests.insert(key, id);
            self.inner.get_sandbox(tenant, id).await
        }
        async fn register_worker(&self, value: RegistrationRecord) -> Result<Uuid, CoreError> {
            self.inner.register_worker(value).await
        }
        async fn heartbeat_worker(
            &self,
            heartbeat: HeartbeatRecord,
        ) -> Result<WorkerRecord, CoreError> {
            self.inner.heartbeat_worker(heartbeat).await
        }
        async fn get_worker(&self, node_id: WorkerId) -> Result<WorkerRecord, CoreError> {
            self.inner.get_worker(node_id).await
        }
        async fn list_workers(
            &self,
            include_unhealthy: bool,
        ) -> Result<Vec<WorkerRecord>, CoreError> {
            self.inner.list_workers(include_unhealthy).await
        }
        async fn list_keys(&self, tenant: Uuid) -> Result<Vec<ApiKeyRecord>, CoreError> {
            self.inner.list_keys(tenant).await
        }
        async fn set_worker_draining(
            &self,
            node_id: WorkerId,
            draining: bool,
            reason: Option<&str>,
        ) -> Result<WorkerRecord, CoreError> {
            self.inner
                .set_worker_draining(node_id, draining, reason)
                .await
        }
        async fn claim_worker_assignments(
            &self,
            node_id: WorkerId,
            limit: u32,
            lease_ttl_seconds: u64,
        ) -> Result<Vec<aiec_core::storage::WorkerAssignment>, CoreError> {
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
        ) -> Result<Vec<aiec_core::storage::WorkerAssignment>, CoreError> {
            self.inner
                .list_worker_assignments(tenant, node_id, status, limit)
                .await
        }
        async fn list_worker_assignments_for_node(
            &self,
            node_id: WorkerId,
            status: Option<&str>,
            limit: u32,
        ) -> Result<Vec<aiec_core::storage::WorkerAssignment>, CoreError> {
            self.inner
                .list_worker_assignments_for_node(node_id, status, limit)
                .await
        }
        async fn get_worker_lease(
            &self,
            tenant: TenantId,
            lease_id: LeaseId,
        ) -> Result<WorkerLease, CoreError> {
            self.leases
                .lock()
                .await
                .get(&lease_id)
                .filter(|held| held.tenant_id == tenant)
                .cloned()
                .ok_or_else(|| CoreError::NotFound("lease not found".into()))
        }
        async fn get_active_worker_lease(
            &self,
            tenant: TenantId,
            sandbox: SandboxId,
        ) -> Result<WorkerLease, CoreError> {
            self.leases
                .lock()
                .await
                .values()
                .find(|held| {
                    held.tenant_id == tenant
                        && held.sandbox_id == sandbox
                        && held.status == "active"
                })
                .cloned()
                .ok_or_else(|| CoreError::NotFound("lease not found".into()))
        }
        async fn renew_worker_lease(
            &self,
            tenant: TenantId,
            lease_id: LeaseId,
            generation: i64,
            ttl_seconds: u64,
        ) -> Result<WorkerLease, CoreError> {
            let mut leases = self.leases.lock().await;
            let held = leases
                .get_mut(&lease_id)
                .filter(|held| held.tenant_id == tenant && held.status == "active")
                .ok_or_else(|| CoreError::NotFound("lease not found".into()))?;
            if held.generation != generation {
                return Err(CoreError::Conflict("stale lease generation".into()));
            }
            held.expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds as i64);
            held.updated_at = Utc::now();
            Ok(held.clone())
        }
        async fn complete_worker_lease(
            &self,
            tenant: TenantId,
            lease_id: LeaseId,
            generation: i64,
            _result: Value,
        ) -> Result<WorkerLease, CoreError> {
            let mut leases = self.leases.lock().await;
            let held = leases
                .get_mut(&lease_id)
                .filter(|held| held.tenant_id == tenant && held.status == "active")
                .ok_or_else(|| CoreError::NotFound("lease not found".into()))?;
            if held.generation != generation {
                return Err(CoreError::Conflict("stale lease generation".into()));
            }
            held.status = "completed".into();
            held.reason = Some("completed".into());
            held.updated_at = Utc::now();
            Ok(held.clone())
        }
        async fn release_worker_lease(
            &self,
            tenant: TenantId,
            lease_id: LeaseId,
            generation: i64,
            reason: &str,
        ) -> Result<WorkerLease, CoreError> {
            let mut leases = self.leases.lock().await;
            let held = leases
                .get_mut(&lease_id)
                .filter(|held| held.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("lease not found".into()))?;
            if held.generation != generation {
                return Err(CoreError::Conflict("stale lease generation".into()));
            }
            held.status = "released".into();
            held.reason = Some(reason.into());
            held.updated_at = Utc::now();
            Ok(held.clone())
        }
        async fn reconcile_expired_leases(
            &self,
            limit: u32,
        ) -> Result<Vec<aiec_core::storage::ReconciliationAction>, CoreError> {
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
            Ok(self
                .leases
                .lock()
                .await
                .values()
                .find(|held| held.sandbox_id == sandbox_id && held.status == "active")
                .map(|held| SandboxOwnership {
                    node_id: held.node_id,
                    lease_id: held.id,
                    generation: held.generation,
                    expires_at: held.expires_at,
                }))
        }
        async fn list_reconciliation_actions(
            &self,
            tenant: TenantId,
            limit: u32,
        ) -> Result<Vec<aiec_core::storage::ReconciliationAction>, CoreError> {
            self.inner.list_reconciliation_actions(tenant, limit).await
        }
        async fn begin_sandbox_operation(
            &self,
            value: aiec_core::storage::SandboxOperation,
        ) -> Result<aiec_core::storage::SandboxOperation, CoreError> {
            self.inner.begin_sandbox_operation(value).await
        }
        async fn complete_sandbox_operation(
            &self,
            tenant: TenantId,
            request_id: RequestId,
            result: Value,
        ) -> Result<aiec_core::storage::SandboxOperation, CoreError> {
            self.inner
                .complete_sandbox_operation(tenant, request_id, result)
                .await
        }
        async fn fail_sandbox_operation(
            &self,
            tenant: TenantId,
            request_id: RequestId,
            error: Value,
        ) -> Result<aiec_core::storage::SandboxOperation, CoreError> {
            self.inner
                .fail_sandbox_operation(tenant, request_id, error)
                .await
        }
        async fn get_sandbox_operation(
            &self,
            tenant: TenantId,
            request_id: RequestId,
        ) -> Result<aiec_core::storage::SandboxOperation, CoreError> {
            self.inner.get_sandbox_operation(tenant, request_id).await
        }
        async fn put_image(&self, value: ImageRecord) -> Result<(), CoreError> {
            self.inner.put_image(value).await
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
        async fn get_image(&self, id: &str) -> Result<ImageRecord, CoreError> {
            self.inner.get_image(id).await
        }
        async fn create_run(&self, run: Run) -> Result<Run, CoreError> {
            let mut runs = self.runs.lock().await;
            // A retried request carrying a key it already used joins the run
            // that key produced rather than starting a second one.
            if let Some(key) = run.idempotency_key.as_deref()
                && let Some(existing) = runs.values().find(|stored| {
                    stored.tenant_id == run.tenant_id
                        && stored.idempotency_key.as_deref() == Some(key)
                })
            {
                return Ok(existing.clone());
            }
            runs.insert(run.id, run.clone());
            Ok(run)
        }

        async fn get_run(&self, tenant: TenantId, id: Uuid) -> Result<Run, CoreError> {
            self.stored_run(tenant, id).await
        }

        async fn list_runs(
            &self,
            tenant: TenantId,
            state: Option<RunState>,
            limit: u32,
            after: Option<aiec_core::storage::MatrixCursor>,
        ) -> Result<Vec<Run>, CoreError> {
            let mut page: Vec<Run> = self
                .runs
                .lock()
                .await
                .values()
                .filter(|run| {
                    run.tenant_id == tenant
                        && state.is_none_or(|state| run.state == state)
                        && after.is_none_or(|cursor| {
                            (run.requested_at, run.id) < (cursor.requested_at, cursor.id)
                        })
                })
                .cloned()
                .collect();
            page.sort_by(|a, b| b.requested_at.cmp(&a.requested_at).then(b.id.cmp(&a.id)));
            page.truncate(limit as usize);
            Ok(page)
        }

        async fn update_run_state(
            &self,
            tenant: TenantId,
            id: Uuid,
            from: RunState,
            to: RunState,
        ) -> Result<Run, CoreError> {
            if !from.can_transition_to(to) {
                return Err(CoreError::Conflict("invalid run state transition".into()));
            }
            let mut runs = self.runs.lock().await;
            let run = runs
                .get_mut(&id)
                .filter(|run| run.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("run not found".into()))?;
            if run.state != from {
                return Err(CoreError::Conflict("run state changed".into()));
            }
            run.state = to;
            if to.is_terminal() && run.completed_at.is_none() {
                run.completed_at = Some(Utc::now());
            }
            Ok(run.clone())
        }

        async fn record_run_results(
            &self,
            tenant: TenantId,
            id: Uuid,
            results: RunResults,
            state: RunState,
        ) -> Result<Run, CoreError> {
            let mut runs = self.runs.lock().await;
            let run = runs
                .get_mut(&id)
                .filter(|run| run.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("run not found".into()))?;
            if run.state != state && !run.state.can_transition_to(state) {
                return Err(CoreError::Conflict("invalid run state transition".into()));
            }
            run.results = results;
            run.state = state;
            if state.is_terminal() && run.completed_at.is_none() {
                run.completed_at = Some(Utc::now());
            }
            Ok(run.clone())
        }

        async fn record_run_failure(
            &self,
            tenant: TenantId,
            id: Uuid,
            results: RunResults,
            reason: Option<String>,
        ) -> Result<Run, CoreError> {
            if *self.refuse_failure_writes.lock().await {
                return Err(CoreError::Backend("the store refused the write".into()));
            }
            let mut runs = self.runs.lock().await;
            let run = runs
                .get_mut(&id)
                .filter(|run| run.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("run not found".into()))?;
            // The same guard the real store applies: a run that already reached
            // a terminal verdict keeps it and still records why, so a cancelled
            // run whose execution then fails is not reported as failed. A run
            // already failed keeps the results and reason the first write took,
            // so a repeated settlement cannot erase the evidence.
            let already_failed = run.state == RunState::Failed;
            if !already_failed {
                if run.state != RunState::Succeeded && run.state != RunState::Cancelled {
                    run.results = results;
                    run.failure_reason = reason;
                    run.state = RunState::Failed;
                    if run.completed_at.is_none() {
                        run.completed_at = Some(Utc::now());
                    }
                } else {
                    run.results = results;
                    run.failure_reason = reason;
                }
            }
            Ok(run.clone())
        }

        async fn append_run_event(
            &self,
            tenant: TenantId,
            event: RunEvent,
        ) -> Result<(), CoreError> {
            self.child_run(tenant, event.run_id, event.sandbox_id)
                .await?;
            let mut events = self.run_events.lock().await;
            let history = events.entry(event.run_id).or_default();
            history.push(event);
            history.sort_by_key(|event| (event.occurred_at, event.id));
            Ok(())
        }

        async fn list_run_events(
            &self,
            tenant: TenantId,
            run: Uuid,
        ) -> Result<Vec<RunEvent>, CoreError> {
            self.stored_run(tenant, run).await?;
            Ok(self
                .run_events
                .lock()
                .await
                .get(&run)
                .cloned()
                .unwrap_or_default())
        }

        async fn link_run_sandbox(
            &self,
            tenant: TenantId,
            link: RunSandbox,
        ) -> Result<(), CoreError> {
            self.child_run(tenant, link.run_id, Some(link.sandbox_id))
                .await?;
            let mut links = self.run_sandboxes.lock().await;
            let held = links.entry(link.run_id).or_default();
            held.retain(|held| held.sandbox_id != link.sandbox_id);
            held.push(link);
            Ok(())
        }

        async fn list_run_sandboxes(
            &self,
            tenant: TenantId,
            run: Uuid,
        ) -> Result<Vec<RunSandbox>, CoreError> {
            self.stored_run(tenant, run).await?;
            Ok(self
                .run_sandboxes
                .lock()
                .await
                .get(&run)
                .cloned()
                .unwrap_or_default())
        }

        async fn put_run_artifacts(
            &self,
            tenant: TenantId,
            run: Uuid,
            artifacts: Vec<RunArtifactRef>,
        ) -> Result<(), CoreError> {
            self.stored_run(tenant, run).await?;
            self.run_artifacts.lock().await.insert(run, artifacts);
            Ok(())
        }
        async fn reserve_artifact_upload(
            &self,
            tenant: TenantId,
            run: Option<Uuid>,
            key: &str,
        ) -> Result<(), CoreError> {
            if let Some(run) = run {
                self.stored_run(tenant, run).await?;
            }
            self.inner.reserve_artifact_upload(tenant, None, key).await
        }

        async fn complete_artifact_upload(
            &self,
            tenant: TenantId,
            run: Option<Uuid>,
            key: &str,
        ) -> Result<(), CoreError> {
            if let Some(run) = run {
                self.stored_run(tenant, run).await?;
            }
            self.inner.complete_artifact_upload(tenant, None, key).await
        }

        async fn list_run_artifacts(
            &self,
            tenant: TenantId,
            run: Uuid,
        ) -> Result<Vec<RunArtifactRef>, CoreError> {
            self.stored_run(tenant, run).await?;
            Ok(self
                .run_artifacts
                .lock()
                .await
                .get(&run)
                .cloned()
                .unwrap_or_default())
        }

        async fn record_run_attempt(
            &self,
            tenant: TenantId,
            attempt: RunAttempt,
        ) -> Result<(), CoreError> {
            self.child_run(tenant, attempt.run_id, attempt.sandbox_id)
                .await?;
            let mut attempts = self.run_attempts.lock().await;
            let history = attempts.entry(attempt.run_id).or_default();
            // An attempt number is recorded once. Re-recording it would rewrite
            // the evidence of what a previous try actually did.
            if history
                .iter()
                .any(|stored| stored.attempt_number == attempt.attempt_number)
            {
                return Err(CoreError::Conflict("attempt already recorded".into()));
            }
            // Only a try may be recorded as one, and only while unfinished.
            if attempt.completed_at.is_some()
                || !matches!(attempt.state, RunState::Running | RunState::Preparing)
            {
                return Err(CoreError::Conflict(
                    "only an unfinished attempt may be started".into(),
                ));
            }
            history.push(attempt);
            Ok(())
        }

        async fn complete_run_attempt(
            &self,
            tenant: TenantId,
            attempt: RunAttempt,
        ) -> Result<(), CoreError> {
            self.stored_run(tenant, attempt.run_id).await?;
            let mut attempts = self.run_attempts.lock().await;
            let history = attempts.entry(attempt.run_id).or_default();
            let stored = history
                .iter_mut()
                .find(|candidate| candidate.attempt_number == attempt.attempt_number)
                .ok_or_else(|| CoreError::NotFound("run attempt not found".into()))?;
            *stored = attempt;
            Ok(())
        }

        async fn create_attempt_sandbox(
            &self,
            run_id: Uuid,
            attempt_id: Uuid,
            sandbox: Sandbox,
            _required: aiec_core::runtime::RuntimeCapabilities,
        ) -> Result<Sandbox, CoreError> {
            self.stored_run(sandbox.tenant_id, run_id).await?;
            // The machine exists as a row before it exists as a runtime, and the
            // rest of the run - usage, destruction, the sweeper - reads that row.
            self.inner.create_sandbox(sandbox.clone()).await?;
            let mut attempts = self.run_attempts.lock().await;
            let stored = attempts
                .get_mut(&run_id)
                .and_then(|history| history.iter_mut().find(|entry| entry.id == attempt_id))
                .ok_or_else(|| CoreError::NotFound("run attempt not found".into()))?;
            // Placement commits the link before the machine exists, so cleanup
            // can always find what a run held even if creation then failed.
            self.link_run_sandbox(
                sandbox.tenant_id,
                RunSandbox {
                    run_id,
                    sandbox_id: sandbox.id,
                    role: "primary".into(),
                },
            )
            .await?;
            stored.sandbox_id = Some(sandbox.id);
            Ok(sandbox)
        }

        async fn list_run_attempts(
            &self,
            tenant: TenantId,
            run: Uuid,
        ) -> Result<Vec<RunAttempt>, CoreError> {
            self.stored_run(tenant, run).await?;
            let mut attempts = self
                .run_attempts
                .lock()
                .await
                .get(&run)
                .cloned()
                .unwrap_or_default();
            attempts.sort_by_key(|attempt| attempt.attempt_number);
            Ok(attempts)
        }

        async fn set_run_placement(
            &self,
            tenant: TenantId,
            id: Uuid,
            placement: Placement,
        ) -> Result<Run, CoreError> {
            // Placement is decided once. A later write may not move where the
            // run went, or a results write could rewrite history.
            let mut runs = self.runs.lock().await;
            let stored = runs
                .get_mut(&id)
                .filter(|run| run.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("run not found".into()))?;
            if stored.placement.runtime.is_some() {
                return Ok(stored.clone());
            }
            stored.placement = placement;
            Ok(stored.clone())
        }

        async fn set_run_failure(
            &self,
            tenant: TenantId,
            id: Uuid,
            failure_reason: Option<String>,
            state: RunState,
        ) -> Result<Run, CoreError> {
            let mut runs = self.runs.lock().await;
            let stored = runs
                .get_mut(&id)
                .filter(|run| run.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("run not found".into()))?;
            if stored.state.is_terminal() {
                return Ok(stored.clone());
            }
            stored.failure_reason = failure_reason;
            stored.state = state;
            stored.completed_at = Some(chrono::Utc::now());
            Ok(stored.clone())
        }

        async fn retain_run_sandbox(
            &self,
            tenant: TenantId,
            id: Uuid,
            sandbox_id: Uuid,
            until: chrono::DateTime<chrono::Utc>,
        ) -> Result<Run, CoreError> {
            self.child_run(tenant, id, Some(sandbox_id)).await?;
            let mut runs = self.runs.lock().await;
            let stored = runs
                .get_mut(&id)
                .filter(|run| run.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("run not found".into()))?;
            // Restating the same retention is a retry and succeeds; a second
            // machine is refused, because the one being displaced would keep a
            // row the sweeper never selects and hold its capacity forever.
            if let Some(kept) = stored.retained_sandbox_id
                && kept != sandbox_id
            {
                return Err(CoreError::Conflict(
                    "run already retains a different machine".into(),
                ));
            }
            // A run may only keep a machine it actually used. Cleanup reads the
            // links to decide what to tear down, so a retention naming anything
            // else makes the two disagree.
            if !self
                .run_sandboxes
                .lock()
                .await
                .get(&id)
                .is_some_and(|held| held.iter().any(|link| link.sandbox_id == sandbox_id))
            {
                return Err(CoreError::Conflict(
                    "a run may only keep a machine it used".into(),
                ));
            }
            stored.retained_sandbox_id = Some(sandbox_id);
            stored.retained_until = Some(until);
            Ok(stored.clone())
        }

        async fn clear_run_retention(
            &self,
            tenant: TenantId,
            id: Uuid,
            sandbox_id: SandboxId,
        ) -> Result<Run, CoreError> {
            let mut runs = self.runs.lock().await;
            let stored = runs
                .get_mut(&id)
                .filter(|run| run.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("run not found".into()))?;
            // Only the machine that was actually retained may be released, so a
            // late sweeper cannot clear a retention a later run recorded.
            if stored.retained_sandbox_id == Some(sandbox_id) {
                stored.retained_sandbox_id = None;
                stored.retained_until = None;
                if stored
                    .results
                    .cleanup_failed
                    .as_ref()
                    .is_some_and(|report| report.sandbox_id == sandbox_id)
                {
                    stored.results.cleanup_failed = None;
                }
            }
            Ok(stored.clone())
        }

        async fn record_retention_cleanup_failure(
            &self,
            tenant: TenantId,
            id: Uuid,
            sandbox_id: SandboxId,
            error: String,
        ) -> Result<Run, CoreError> {
            let mut runs = self.runs.lock().await;
            let stored = runs
                .get_mut(&id)
                .filter(|run| run.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("run not found".into()))?;
            if stored.retained_sandbox_id == Some(sandbox_id) {
                stored.results.cleanup_failed = Some(CleanupReport { sandbox_id, error });
            }
            Ok(stored.clone())
        }

        async fn retained_runs_due(
            &self,
            now: chrono::DateTime<chrono::Utc>,
            limit: u32,
        ) -> Result<Vec<Run>, CoreError> {
            Ok(self
                .runs
                .lock()
                .await
                .values()
                .filter(|run| run.retained_until.is_some_and(|until| until <= now))
                .take(limit as usize)
                .cloned()
                .collect())
        }

        async fn delete_run(&self, tenant: TenantId, id: Uuid) -> Result<(), CoreError> {
            let mut runs = self.runs.lock().await;
            runs.get(&id)
                .filter(|run| run.tenant_id == tenant)
                .ok_or_else(|| CoreError::NotFound("run not found".into()))?;
            // A run with recorded history is evidence, not scratch.
            if self
                .run_events
                .lock()
                .await
                .get(&id)
                .is_some_and(|events| !events.is_empty())
            {
                return Err(CoreError::Conflict("run has recorded history".into()));
            }
            // Deleting the row also deletes the only index the sweeper and
            // cleanup have on the machines this run holds.
            if self
                .run_sandboxes
                .lock()
                .await
                .get(&id)
                .is_some_and(|links| !links.is_empty())
                || runs
                    .get(&id)
                    .is_some_and(|run| run.retained_sandbox_id.is_some())
            {
                return Err(CoreError::Conflict("run still owns a machine".into()));
            }
            runs.remove(&id);
            Ok(())
        }
    }

    /// Runtime double that records the archives a recovery hands it, standing in
    /// for the worker that has just taken ownership of a reassigned sandbox.
    struct AdoptingRuntime {
        imported: TestMutex<Vec<Vec<u8>>>,
        destroyed: TestMutex<Vec<Uuid>>,
    }

    #[async_trait::async_trait]
    impl SandboxRuntime for AdoptingRuntime {
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
        async fn import_workspace_archive(
            &self,
            _: &Sandbox,
            archive: &[u8],
        ) -> Result<(), CoreError> {
            self.imported.lock().await.push(archive.to_vec());
            Ok(())
        }
        async fn destroy(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
            self.destroyed.lock().await.push(sandbox.id);
            Ok(())
        }
        async fn health(&self) -> aiec_core::runtime::RuntimeHealth {
            aiec_core::runtime::RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> aiec_core::runtime::RuntimeCapabilities {
            aiec_core::runtime::RuntimeCapabilities::default()
        }
    }

    /// Snapshot provider double that hands back fixed archive bytes, standing
    /// in for a capture taken on a worker that is about to die.
    struct FixedSnapshotProvider {
        archive: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl aiec_core::snapshots::SnapshotProvider for FixedSnapshotProvider {
        fn capabilities(&self) -> aiec_core::snapshots::SnapshotCapabilities {
            aiec_core::snapshots::SnapshotCapabilities {
                workspace: true,
                ..Default::default()
            }
        }
        async fn capture(
            &self,
            _: &Sandbox,
            request: &aiec_core::snapshots::SnapshotRequest,
        ) -> Result<aiec_core::snapshots::CapturedSnapshot, CoreError> {
            Ok(aiec_core::snapshots::CapturedSnapshot::from_archive(
                new_id(),
                request.kind,
                request.object_key.clone(),
                self.archive.clone(),
            ))
        }
        /// Recovery must not route through the provider: this succeeds without
        /// touching the new owner's runtime, so a test that expects the
        /// captured bytes to arrive can only pass through the object store.
        async fn restore(
            &self,
            _: &Sandbox,
            snapshot: &aiec_core::snapshots::SnapshotMetadata,
        ) -> Result<(), CoreError> {
            if snapshot.kind != SnapshotKind::Workspace {
                return Err(CoreError::Unsupported("unsupported snapshot kind".into()));
            }
            Ok(())
        }
    }

    struct RecoveryFixture {
        state: AppState,
        store: Arc<dyn ArtifactStore>,
        runtime: Arc<AdoptingRuntime>,
        repository: Arc<aiec_storage::MemoryRepository>,
        root: std::path::PathBuf,
    }

    impl RecoveryFixture {
        fn new(archive: Vec<u8>) -> Self {
            let root = std::env::temp_dir().join(format!("af-recovery-{}", new_id()));
            let repository = aiec_storage::MemoryRepository::new();
            let store: Arc<dyn ArtifactStore> =
                Arc::new(aiec_storage::FilesystemObjectStore::new(&root));
            let metadata: Arc<dyn MetadataStore> = repository.clone();
            let runtime = Arc::new(AdoptingRuntime {
                imported: TestMutex::new(Vec::new()),
                destroyed: TestMutex::new(Vec::new()),
            });
            let platform = Platform::builder()
                .runtime(runtime.clone())
                .runtime_registry(Arc::new(aiec_core::runtime::RuntimeRegistry::with_runtime(
                    RuntimeKind::Docker,
                    runtime.clone(),
                )))
                .metadata_store(metadata)
                .scheduler(Arc::new(DevelopmentScheduler))
                .artifact_store(store.clone())
                .snapshots(Arc::new(FixedSnapshotProvider { archive }))
                .policy(Arc::new(DefaultPolicy))
                .build()
                .expect("platform");
            Self {
                state: AppState::development(platform),
                store,
                runtime,
                repository,
                root,
            }
        }

        async fn sandbox(&self, tenant: Uuid) -> Sandbox {
            self.sandbox_created_at(tenant, Utc::now()).await
        }

        /// A sandbox created at a stated instant.
        ///
        /// `created_at` is what the sandbox page orders by, so a test that
        /// asserts the order has to control it: several sandboxes created in the
        /// same wall-clock microsecond sort by something the test does not get
        /// to choose, and an ordering assertion that depends on that passes
        /// about half the time either way.
        async fn sandbox_created_at(&self, tenant: Uuid, created_at: DateTime<Utc>) -> Sandbox {
            let sandbox = Sandbox {
                id: new_id(),
                tenant_id: tenant,
                node_id: None,
                image_id: "alpine:3.21".into(),
                state: SandboxState::Running,
                runtime: RuntimeKind::Docker,
                cpu: 1,
                memory_mb: 128,
                disk_mb: 512,
                timeout_seconds: 60,
                network: NetworkPolicy::Disabled,
                environment: Default::default(),
                created_at,
                updated_at: created_at,
                runtime_path: None,
            };
            self.repository
                .create_sandbox(sandbox.clone())
                .await
                .expect("create sandbox");
            sandbox
        }

        async fn store_snapshot(
            &self,
            sandbox: &Sandbox,
            object_key: &str,
            archive: &[u8],
        ) -> StoredSnapshot {
            let stored = StoredSnapshot {
                id: new_id(),
                tenant_id: sandbox.tenant_id,
                sandbox_id: sandbox.id,
                object_key: object_key.into(),
                manifest_object_key: format!("{object_key}.manifest.json"),
                memory_object_key: None,
                disk_object_key: None,
                workspace_object_key: Some(object_key.into()),
                size_bytes: archive.len() as u64,
                image_id: sandbox.image_id.clone(),
                checksum_sha256: aiec_core::snapshots::archive_checksum(archive),
                kind: "workspace".into(),
                complete: true,
                manifest: json!({"kind": "workspace"}),
                created_at: Utc::now(),
            };
            self.repository
                .put_stored_snapshot(stored.clone())
                .await
                .expect("store snapshot");
            stored
        }
    }

    impl Drop for RecoveryFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn principal(tenant: Uuid) -> Principal {
        Principal {
            tenant_id: tenant,
            key_id: new_id(),
            scopes: vec![Scope::SnapshotsWrite, Scope::SnapshotsRead],
        }
    }

    /// A tenant's sandbox list is their entire history, and it only grows:
    /// destroying a sandbox transitions its row rather than deleting it, and
    /// nothing reclaims it. So this route used to read the whole history into
    /// one response, which let any tenant decide how much the control plane
    /// holds in memory.
    ///
    /// Capping it without a successor would be worse than the original defect:
    /// a truncated list is indistinguishable from a complete one, and the older
    /// rows would be unreachable rather than merely slow. So the page carries
    /// its own successor, and this walks the whole history through it and checks
    /// that every sandbox appears exactly once, in the expected order. That
    /// equality is what pins the subtle part: the cursor has to name the last
    /// sandbox *returned*, not the row held back to prove another page exists.
    /// Pointing it at the held-back row pages past it, and this walk would end
    /// with that sandbox silently missing.
    #[tokio::test]
    async fn a_sandbox_list_pages_through_the_whole_history_and_says_where_it_continues() {
        let fixture = RecoveryFixture::new(b"{}".to_vec());
        let tenant = new_id();
        // Timestamps a second apart and oldest-first, so the expected order is
        // known exactly. Relying on wall-clock ordering here would pass about
        // half the time even with no ordering at all, which is not a test.
        let base = DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
            .expect("the current time is representable");
        let total = aiec_core::storage::MAX_SANDBOX_PAGE as usize + 5;
        let mut ids = Vec::with_capacity(total);
        for index in 0..total {
            let record = fixture
                .sandbox_created_at(tenant, base + chrono::Duration::seconds(index as i64))
                .await;
            ids.push(record.id);
        }
        let newest_first: Vec<Uuid> = ids.iter().rev().copied().collect();

        let caller = Principal {
            tenant_id: tenant,
            key_id: new_id(),
            scopes: vec![Scope::SandboxesRead],
        };
        let page = |limit: Option<u32>, after: Option<PageCursor>| {
            let state = fixture.state.clone();
            let caller = caller.clone();
            async move {
                list_sandboxes(
                    State(state),
                    Extension(caller),
                    Query(ListSandboxesQuery {
                        limit,
                        after_created_at: after.map(|cursor| cursor.created_at),
                        after_id: after.map(|cursor| cursor.id),
                    }),
                )
                .await
                .map(|Json(page)| page)
                .unwrap_or_else(|error| panic!("list sandboxes: {error:?}"))
            }
        };

        // Walk the whole history a few at a time. Seven divides neither the
        // total nor its remainder evenly: a page size that divides evenly would
        // let a cursor that skipped exactly one row still produce the right
        // count.
        let per_page = 7;
        let mut walked: Vec<Uuid> = Vec::with_capacity(total);
        let mut cursor: Option<PageCursor> = None;
        let mut pages = 0usize;
        loop {
            let response = page(Some(per_page), cursor).await;
            assert!(
                response.sandboxes.len() <= per_page as usize,
                "a page returned more than was asked for"
            );
            assert!(!response.sandboxes.is_empty(), "a page came back empty");
            let more = response.next.is_some();
            if let Some(next) = response.next {
                let last = response.sandboxes.last().expect("the page is not empty");
                assert_eq!(
                    (next.created_at, next.id),
                    (last.created_at, last.id),
                    "the cursor must name the last sandbox returned, or the walk skips one"
                );
                cursor = Some(next);
            }
            walked.extend(response.sandboxes.into_iter().map(|sandbox| sandbox.id));
            pages += 1;
            if !more {
                break;
            }
            assert!(
                pages < total,
                "the cursor named a next page but the history had already run out"
            );
        }
        assert_eq!(
            walked, newest_first,
            "paging must reproduce the whole history exactly once, newest first"
        );

        // The ceiling, the default and a zero, through the route because each
        // passes on a store that happens to be small.
        assert_eq!(
            page(Some(100_000), None).await.sandboxes.len(),
            aiec_core::storage::MAX_SANDBOX_PAGE as usize,
            "an oversized limit must be capped at the ceiling, not honoured"
        );
        assert_eq!(
            page(None, None).await.sandboxes.len(),
            DEFAULT_SANDBOX_PAGE as usize,
            "a caller that states no limit gets the default page, not everything"
        );
        assert_eq!(
            page(Some(0), None).await.sandboxes.len(),
            1,
            "a zero limit must be raised to one rather than returning nothing"
        );
    }

    /// Two sandboxes created in the same instant have no ordering by time
    /// alone, so the tie is broken by id. That is exactly where comparing the
    /// cursor's two halves independently goes wrong: `created_at <` alone
    /// lets the walk re-visit everything sharing that timestamp, and `id <`
    /// alone lets it jump over rows. The tuple comparison is what makes a
    /// shared timestamp survivable, so it is checked here rather than assumed.
    #[tokio::test]
    async fn a_sandbox_page_cursor_survives_a_shared_creation_timestamp() {
        let fixture = RecoveryFixture::new(b"{}".to_vec());
        let tenant = new_id();
        let shared = DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
            .expect("the current time is representable");
        let mut ids = Vec::new();
        for _ in 0..3 {
            let record = fixture.sandbox_created_at(tenant, shared).await;
            ids.push(record.id);
        }
        ids.sort_unstable();
        let expected: Vec<Uuid> = ids.iter().rev().copied().collect();

        // One at a time, so the cursor is re-read between every pair.
        let mut walked = Vec::new();
        let mut cursor: Option<PageCursor> = None;
        loop {
            let response = fixture
                .repository
                .list_sandboxes(tenant, 1, cursor)
                .await
                .expect("read a page");
            walked.extend(response.sandboxes.iter().map(|sandbox| sandbox.id));
            match response.next {
                Some(next) => {
                    cursor = Some(next);
                    assert!(walked.len() < 3, "the cursor never ran out");
                }
                None => break,
            }
        }
        assert_eq!(
            walked, expected,
            "sandboxes sharing a creation timestamp must still page exactly once"
        );
    }

    /// Half a cursor cannot name a position: a timestamp alone has no sandbox
    /// to start after, and an id alone cannot order a page that has not been
    /// read. Guessing either would return a page the caller cannot tell apart
    /// from the one they asked for.
    #[tokio::test]
    async fn a_sandbox_cursor_given_one_half_is_refused() {
        let fixture = RecoveryFixture::new(b"{}".to_vec());
        let caller = Principal {
            tenant_id: new_id(),
            key_id: new_id(),
            scopes: vec![Scope::SandboxesRead],
        };
        let half = DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
            .expect("the current time is representable");
        for query in [
            ListSandboxesQuery {
                limit: None,
                after_created_at: Some(half),
                after_id: None,
            },
            ListSandboxesQuery {
                limit: None,
                after_created_at: None,
                after_id: Some(new_id()),
            },
        ] {
            let failure = list_sandboxes(
                State(fixture.state.clone()),
                Extension(caller.clone()),
                Query(query),
            )
            .await
            .expect_err("half a cursor must not resolve to a page");
            assert_eq!(failure.status, StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn corrupt_workspace_restore_reclaims_the_new_computer() {
        let archive = b"{\"version\":1,\"entries\":[]}".to_vec();
        let fixture = RecoveryFixture::new(archive.clone());
        let tenant = new_id();
        let source = fixture.sandbox(tenant).await;
        let key = format!("{}-workspace", source.id);
        let stored = fixture.store_snapshot(&source, &key, &archive).await;
        fixture
            .store
            .put(&key, bytes::Bytes::from_static(b"corrupt archive"))
            .await
            .unwrap();

        let error = restore_snapshot(
            State(fixture.state.clone()),
            Extension(principal(tenant)),
            Path(stored.id),
            Json(RestoreSnapshotRequest {
                image: None,
                cpu: None,
                memory_mb: None,
                disk_mb: None,
                runtime: Some(RuntimeKind::Docker),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        let sandboxes = fixture
            .repository
            .list_sandboxes(tenant, aiec_core::storage::MAX_SANDBOX_PAGE, None)
            .await
            .unwrap();
        assert_eq!(
            sandboxes
                .sandboxes
                .iter()
                .filter(|value| value.state != SandboxState::Destroyed)
                .map(|value| value.id)
                .collect::<Vec<_>>(),
            vec![source.id],
        );
        assert_eq!(
            fixture
                .repository
                .get_sandbox(tenant, source.id)
                .await
                .unwrap()
                .state,
            SandboxState::Running,
        );
    }

    /// The isolation boundary applies to a restore that survives it. This used
    /// to be asserted on the `memory` branch, which no longer exists: that
    /// branch is refused before a runtime is chosen now, so a boundary it could
    /// be caught by proves nothing about the branch that remains. What is
    /// checked here is the surviving one, and it refuses before it allocates.
    #[tokio::test]
    async fn workspace_restore_respects_the_deployment_isolation_boundary() {
        let mut fixture = RecoveryFixture::new(b"archive".to_vec());
        fixture.state = fixture.state.clone().with_hosted_only(true);
        let tenant = new_id();
        let source = fixture.sandbox(tenant).await;
        let stored = fixture
            .store_snapshot(&source, "snapshot", b"archive")
            .await;
        let error = restore_snapshot(
            State(fixture.state.clone()),
            Extension(principal(tenant)),
            Path(stored.id),
            Json(RestoreSnapshotRequest {
                image: None,
                cpu: None,
                memory_mb: None,
                disk_mb: None,
                runtime: Some(RuntimeKind::Docker),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.code, "runtime_not_permitted");
        assert_eq!(
            fixture
                .repository
                .list_sandboxes(tenant, aiec_core::storage::MAX_SANDBOX_PAGE, None)
                .await
                .unwrap()
                .sandboxes
                .iter()
                .map(|sandbox| sandbox.id)
                .collect::<Vec<_>>(),
            vec![source.id]
        );
    }

    /// A machine-kind snapshot names bytes this control plane cannot read, so
    /// the restore is refused before anything is allocated. The rollback it
    /// used to run is the same one ordinary provisioning runs, and that is what
    /// the surviving branch uses.
    #[tokio::test]
    async fn a_machine_kind_restore_is_refused_before_anything_is_allocated() {
        let fixture = RecoveryFixture::new(b"archive".to_vec());
        let tenant = new_id();
        let source = fixture.sandbox(tenant).await;
        let mut stored = fixture
            .store_snapshot(&source, "snapshot", b"archive")
            .await;
        stored.id = new_id();
        stored.kind = "virtual_machine".into();
        stored.workspace_object_key = None;
        stored.memory_object_key = Some("snapshot.memory".into());
        stored.disk_object_key = Some("snapshot.disk".into());
        fixture
            .repository
            .put_stored_snapshot(stored.clone())
            .await
            .unwrap();

        let error = restore_snapshot(
            State(fixture.state.clone()),
            Extension(principal(tenant)),
            Path(stored.id),
            Json(RestoreSnapshotRequest {
                image: None,
                cpu: None,
                memory_mb: None,
                disk_mb: None,
                runtime: Some(RuntimeKind::Docker),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "unsupported_snapshot_kind");
        assert_eq!(
            fixture
                .repository
                .list_sandboxes(tenant, aiec_core::storage::MAX_SANDBOX_PAGE, None)
                .await
                .unwrap()
                .sandboxes
                .iter()
                .map(|sandbox| sandbox.id)
                .collect::<Vec<_>>(),
            vec![source.id],
            "a refused restore allocated a machine to tear down again"
        );
        assert!(
            fixture.runtime.destroyed.lock().await.is_empty(),
            "a refused restore destroyed something"
        );
    }
    /// A workspace captured on a worker is worthless if the bytes die with that
    /// worker, so the capture path must leave them in shared object storage.
    #[tokio::test]
    async fn a_captured_workspace_is_stored_where_any_worker_can_read_it() {
        let archive = b"{\"version\":1,\"entries\":[]}".to_vec();
        let fixture = RecoveryFixture::new(archive.clone());
        let tenant = new_id();
        let sandbox = fixture.sandbox(tenant).await;

        let created = create_snapshot(
            State(fixture.state.clone()),
            Extension(principal(tenant)),
            Path(sandbox.id),
            Some(Json(CreateSnapshotRequest {
                kind: Some(SnapshotKind::Workspace),
            })),
        )
        .await
        .expect("create snapshot");

        let stored = fixture
            .store
            .get_checked(
                &created.object_key,
                &GetObjectOptions {
                    if_match: None,
                    expected_checksum_sha256: Some(aiec_core::snapshots::archive_checksum(
                        &archive,
                    )),
                },
            )
            .await
            .expect("stored archive");
        assert_eq!(stored, archive);
        let row = fixture
            .repository
            .get_stored_snapshot(tenant, created.id)
            .await
            .expect("snapshot row");
        assert_eq!(
            row.workspace_object_key.as_deref(),
            Some(created.object_key.as_str())
        );
    }

    /// The end-to-end recovery case: the capturing worker is gone, so the new
    /// owner must be handed the bytes from shared storage.
    #[tokio::test]
    async fn a_recovered_sandbox_is_given_the_captured_archive() {
        let archive = b"{\"version\":1,\"entries\":[\"notes\"]}".to_vec();
        let fixture = RecoveryFixture::new(archive.clone());
        let sandbox = fixture.sandbox(new_id()).await;
        let object_key = format!("{}-workspace", sandbox.id);
        fixture
            .store
            .put(&object_key, bytes::Bytes::copy_from_slice(&archive))
            .await
            .expect("store archive");
        fixture
            .store_snapshot(&sandbox, &object_key, &archive)
            .await;

        restore_workspace(&fixture.state, &sandbox)
            .await
            .expect("restore workspace");
        assert_eq!(fixture.runtime.imported.lock().await.as_slice(), &[archive]);
    }

    /// A damaged archive must abort recovery. Handing the sandbox an empty
    /// workspace would lose its state with no signal at all.
    #[tokio::test]
    async fn a_corrupted_archive_fails_recovery_instead_of_restoring_nothing() {
        let fixture = RecoveryFixture::new(b"captured".to_vec());
        let sandbox = fixture.sandbox(new_id()).await;
        let object_key = format!("{}-workspace", sandbox.id);
        fixture
            .store
            .put(&object_key, bytes::Bytes::from_static(b"tampered"))
            .await
            .expect("store archive");
        fixture
            .store_snapshot(&sandbox, &object_key, b"captured")
            .await;

        assert!(matches!(
            restore_workspace(&fixture.state, &sandbox).await,
            Err(CoreError::Backend(_))
        ));
        assert!(fixture.runtime.imported.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_missing_archive_fails_recovery() {
        let fixture = RecoveryFixture::new(b"captured".to_vec());
        let sandbox = fixture.sandbox(new_id()).await;
        fixture
            .store_snapshot(&sandbox, &format!("{}-absent", sandbox.id), b"captured")
            .await;

        assert!(restore_workspace(&fixture.state, &sandbox).await.is_err());
        assert!(fixture.runtime.imported.lock().await.is_empty());
    }

    /// Scheduler double that records what it was asked to release.
    ///
    /// `Scheduler::release` takes only a tenant and a sandbox, so a caller that
    /// has lost its lease cannot say which lease it meant: the store picks the
    /// newest active one. That is what makes the recovery path's release
    /// unbounded, and this records the observable consequence rather than
    /// asserting on the argument list.
    #[derive(Default, Clone)]
    struct ReleaseRecordingScheduler {
        released: std::sync::Arc<std::sync::Mutex<Vec<Uuid>>>,
    }

    #[async_trait::async_trait]
    impl aiec_core::scheduler::Scheduler for ReleaseRecordingScheduler {
        async fn schedule(
            &self,
            request: aiec_core::scheduler::ScheduleRequest,
        ) -> Result<aiec_core::scheduler::ScheduledSandbox, CoreError> {
            Ok(aiec_core::scheduler::ScheduledSandbox {
                sandbox: request.sandbox,
                worker_id: TenantId::nil(),
                worker_endpoint: String::new(),
                lease_id: SandboxId::nil(),
                lease_generation: 0,
            })
        }

        async fn dispatch_target(
            &self,
            _: TenantId,
            _: SandboxId,
        ) -> Result<aiec_core::scheduler::WorkerDispatch, CoreError> {
            Err(CoreError::Unsupported("no dispatch".into()))
        }

        async fn release(&self, _: TenantId, sandbox_id: SandboxId) -> Result<(), CoreError> {
            self.released
                .lock()
                .map(|mut log| log.push(sandbox_id))
                .map_err(|_| CoreError::Backend("release log poisoned".into()))
        }
    }

    /// A recovery pass that has been superseded must not write state or
    /// release a lease.
    ///
    /// Recovery is given a `Reassignment` — one lease, one generation. It then
    /// placed the sandbox through `commit_state`, which looks up *whoever owns
    /// the sandbox now* and fences against that. So if the sandbox is
    /// reassigned again while the runtime is starting, the superseded pass
    /// writes `Running` under the new owner's lease and marks it failed under
    /// the new owner's lease too, and releases through `Scheduler::release`,
    /// which cannot name a lease and therefore releases whichever one is
    /// newest. Every one of those is an operation performed by a caller that no
    /// longer holds the sandbox.
    #[tokio::test]
    async fn a_superseded_recovery_pass_neither_writes_state_nor_releases_a_lease() {
        let root = std::env::temp_dir().join(format!("af-recovery-fence-{}", new_id()));
        let repository = LeasedRepository::new();
        let store: Arc<dyn ArtifactStore> =
            Arc::new(aiec_storage::FilesystemObjectStore::new(&root));
        let runtime = Arc::new(AdoptingRuntime {
            imported: TestMutex::new(Vec::new()),
            destroyed: TestMutex::new(Vec::new()),
        });
        let scheduler = ReleaseRecordingScheduler::default();
        let platform = Platform::builder()
            .runtime(runtime.clone())
            .runtime_registry(Arc::new(aiec_core::runtime::RuntimeRegistry::with_runtime(
                RuntimeKind::Docker,
                runtime.clone(),
            )))
            .metadata_store(repository.clone())
            .scheduler(Arc::new(scheduler.clone()))
            .artifact_store(store)
            .snapshots(Arc::new(FixedSnapshotProvider {
                archive: b"{\"version\":1,\"entries\":[]}".to_vec(),
            }))
            .policy(Arc::new(DefaultPolicy))
            .build()
            .expect("platform");
        let state = AppState::development(platform);

        let now = Utc::now();
        let sandbox = Sandbox {
            id: new_id(),
            tenant_id: new_id(),
            node_id: Some(new_id()),
            image_id: "alpine:3.21".into(),
            state: SandboxState::Starting,
            runtime: RuntimeKind::Docker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: NetworkPolicy::Disabled,
            environment: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        };
        repository
            .create_sandbox(sandbox.clone())
            .await
            .expect("create sandbox");

        // The lease this recovery pass was handed...
        let mine = WorkerLease {
            id: new_id(),
            tenant_id: sandbox.tenant_id,
            sandbox_id: sandbox.id,
            node_id: sandbox.node_id.expect("node"),
            generation: 1,
            status: "active".into(),
            expires_at: now + chrono::Duration::seconds(60),
            created_at: now,
            updated_at: now,
            reason: Some("recovery".into()),
        };
        // ...and the lease that replaced it while the runtime was starting.
        let theirs = WorkerLease {
            id: new_id(),
            generation: 2,
            ..mine.clone()
        };
        repository.insert(mine.clone()).await;
        repository.insert(theirs.clone()).await;
        repository.leases.lock().await.insert(mine.id, {
            let mut superseded = mine.clone();
            superseded.status = "expired".into();
            superseded
        });

        let outcome = place_recovered_sandbox(
            &state,
            aiec_core::storage::Reassignment {
                sandbox: sandbox.clone(),
                lease: mine.clone(),
            },
        )
        .await;

        assert_eq!(
            outcome.status, "failed",
            "a superseded recovery pass reported success"
        );
        assert_eq!(
            state
                .repository()
                .get_sandbox(sandbox.tenant_id, sandbox.id)
                .await
                .expect("read back")
                .state,
            SandboxState::Starting,
            "a superseded recovery pass wrote state on the new owner's lease"
        );
        assert!(
            scheduler
                .released
                .lock()
                .map(|log| log.is_empty())
                .unwrap_or(false),
            "a superseded recovery pass released a lease through the scheduler, \
             which cannot name the lease it meant"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Scheduler whose `release` reports that there is nothing to release.
    ///
    /// This is the ordinary production answer when the lease already expired and
    /// the sweeper returned its capacity, or when another teardown got there
    /// first. It is not a failure of the teardown.
    #[derive(Default, Clone)]
    struct NoLeaseToReleaseScheduler;

    #[async_trait::async_trait]
    impl aiec_core::scheduler::Scheduler for NoLeaseToReleaseScheduler {
        async fn schedule(
            &self,
            request: aiec_core::scheduler::ScheduleRequest,
        ) -> Result<aiec_core::scheduler::ScheduledSandbox, CoreError> {
            Ok(aiec_core::scheduler::ScheduledSandbox {
                sandbox: request.sandbox,
                worker_id: TenantId::nil(),
                worker_endpoint: String::new(),
                lease_id: SandboxId::nil(),
                lease_generation: 0,
            })
        }

        async fn dispatch_target(
            &self,
            _: TenantId,
            _: SandboxId,
        ) -> Result<aiec_core::scheduler::WorkerDispatch, CoreError> {
            Err(CoreError::Unsupported("no dispatch".into()))
        }

        async fn release(&self, _: TenantId, _: SandboxId) -> Result<(), CoreError> {
            Err(CoreError::NotFound("active sandbox lease not found".into()))
        }
    }

    /// A teardown that stops the machine must not then leave its row behind.
    ///
    /// The order is deliberate: capacity is released only after the runtime
    /// confirms the machine is stopped, so a failed stop cannot hand capacity
    /// back against a machine that is still running. But `release` reporting
    /// there is nothing to release is not a failed stop. It is the expected
    /// answer when the lease already expired and the sweeper returned its
    /// capacity, or when a concurrent teardown released it first. The row then
    /// survived with a state the quota counts as active
    /// (`state NOT IN ('destroyed','failed')`), so a machine that was genuinely
    /// gone kept consuming the tenant's active-sandbox budget until an operator
    /// noticed. The `?` here is what turned "already released" into "never
    /// deleted".
    #[tokio::test]
    async fn a_teardown_still_deletes_its_row_when_there_is_no_lease_left_to_release() {
        let repository = LeasedRepository::new();
        let runtime = Arc::new(AdoptingRuntime {
            imported: TestMutex::new(Vec::new()),
            destroyed: TestMutex::new(Vec::new()),
        });
        let platform = Platform::builder()
            .runtime(runtime.clone())
            .runtime_registry(Arc::new(aiec_core::runtime::RuntimeRegistry::with_runtime(
                RuntimeKind::Docker,
                runtime.clone(),
            )))
            .metadata_store(repository.clone())
            .scheduler(Arc::new(NoLeaseToReleaseScheduler))
            .artifact_store(Arc::new(aiec_storage::FilesystemObjectStore::new(
                std::env::temp_dir().join(format!("af-teardown-{}", new_id())),
            )))
            .snapshots(Arc::new(FixedSnapshotProvider {
                archive: b"{\"version\":1,\"entries\":[]}".to_vec(),
            }))
            .policy(Arc::new(DefaultPolicy))
            .build()
            .expect("platform");
        // `AppState::new`, not `development`: the lease release is production
        // behaviour and a development state skips it entirely.
        let state = AppState::new(platform);

        let now = Utc::now();
        let sandbox = Sandbox {
            id: new_id(),
            tenant_id: new_id(),
            node_id: Some(new_id()),
            image_id: "alpine:3.21".into(),
            state: SandboxState::Running,
            runtime: RuntimeKind::Docker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: NetworkPolicy::Disabled,
            environment: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        };
        repository
            .create_sandbox(sandbox.clone())
            .await
            .expect("create sandbox");

        let outcome =
            crate::runs::tear_down_sandbox(&state, sandbox.tenant_id, sandbox.id, &sandbox).await;

        assert!(
            !matches!(outcome, Err(CoreError::NotFound(_))),
            "a stopped machine was reported as gone: {outcome:?}"
        );
        assert!(
            runtime.destroyed.lock().await.contains(&sandbox.id),
            "the machine was never stopped"
        );
        // `delete_sandbox` marks the row destroyed rather than removing it, and
        // that is what stops it counting: the quota counts rows where
        // `state NOT IN ('destroyed','failed')`. So the property under test is
        // the state, not the absence of the row.
        let after = state
            .repository()
            .get_sandbox(sandbox.tenant_id, sandbox.id)
            .await
            .expect("read back");
        assert_eq!(
            after.state,
            SandboxState::Destroyed,
            "the row was left in a state the tenant's active-sandbox quota counts"
        );
    }

    /// A sandbox that was never captured has nothing to restore, which is a
    /// legitimate case: it starts empty rather than failing.
    #[tokio::test]
    async fn a_sandbox_without_any_capture_starts_empty() {
        let fixture = RecoveryFixture::new(b"captured".to_vec());
        let sandbox = fixture.sandbox(new_id()).await;

        restore_workspace(&fixture.state, &sandbox)
            .await
            .expect("empty recovery");
        assert!(fixture.runtime.imported.lock().await.is_empty());
    }

    /// Runtime double that runs commands successfully, so a run submitted
    /// through the API is driven all the way to a terminal state rather than
    /// stopping at the first capability the cluster does not have.
    #[derive(Default, Clone)]
    struct DestroyRecorder {
        destroyed: std::sync::Arc<std::sync::Mutex<Vec<Uuid>>>,
    }

    impl DestroyRecorder {
        fn destroyed(&self) -> Vec<Uuid> {
            self.destroyed
                .lock()
                .map(|log| log.clone())
                .unwrap_or_default()
        }
    }

    /// A double that records which sandboxes were actually stopped.
    ///
    /// The bug this exists for was a cleanup that set the row to `destroyed`
    /// and never stopped the machine, leaving containers running while the
    /// control plane reported them gone. Assertions about rows and capacity all
    /// passed while that was happening; the observable that would have caught
    /// it is the one the old code never produced.
    /// Blocks inside `exec` until released, so a test can hold a run in flight
    /// for as long as it needs. `RunRuntime` returns immediately, which makes
    /// "submit twice" race rather than reproduce: the first request is usually
    /// already settled when the second arrives, and a broken guard passes.
    #[derive(Clone, Default)]
    struct RunRuntime {
        recorder: Option<DestroyRecorder>,
        /// Raw file bytes served by the chunk transfer and public JSON reader.
        files: Option<std::sync::Arc<TestMap<String, bytes::Bytes>>>,
        failing_command: Option<Vec<String>>,
        forbid_destroy: bool,
    }

    impl RunRuntime {
        /// Records into a recorder the caller owns, so the test reads the same
        /// log the runtime wrote to.
        fn recording(recorder: DestroyRecorder) -> Self {
            Self {
                recorder: Some(recorder),
                ..Self::default()
            }
        }

        fn serving(mut self, files: TestMap<String, bytes::Bytes>) -> Self {
            self.files = Some(std::sync::Arc::new(files));
            self
        }
        fn file_bytes(&self, path: &str) -> Result<bytes::Bytes, CoreError> {
            match &self.files {
                Some(files) => files
                    .get(path)
                    .cloned()
                    .ok_or_else(|| CoreError::NotFound(format!("no such file: {path}"))),
                None => Ok(bytes::Bytes::from(format!("contents of {path}"))),
            }
        }
    }

    #[async_trait::async_trait]
    impl SandboxRuntime for RunRuntime {
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
        async fn exec(&self, _: &Sandbox, request: ExecRequest) -> Result<ExecResult, CoreError> {
            Ok(ExecResult {
                exit_code: i32::from(self.failing_command.as_ref() == Some(&request.command)),
                stdout: request.command.join(" "),
                stderr: String::new(),
                duration_ms: 1,
                timed_out: false,
            })
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), CoreError> {
            Ok(())
        }
        async fn get_file(&self, _: &Sandbox, path: &str) -> Result<FileContent, CoreError> {
            use base64::Engine;
            let bytes = self.file_bytes(path)?;
            Ok(FileContent {
                path: path.to_owned(),
                content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            })
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            request: aiec_core::runtime::FileChunkRequest,
        ) -> Result<aiec_core::runtime::FileChunk, CoreError> {
            let bytes = self.file_bytes(&request.path)?;
            let size_bytes = bytes.len() as u64;
            let version = hex::encode(sha2::Sha256::digest(&bytes));
            request.validate()?;
            let start = request.offset as usize;
            let end = start.saturating_add(request.length).min(bytes.len());
            let chunk = aiec_core::runtime::FileChunk {
                bytes: if start <= end {
                    bytes.slice(start..end)
                } else {
                    bytes::Bytes::new()
                },
                size_bytes,
                version,
                eof: end == bytes.len(),
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
        async fn destroy(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
            assert!(!self.forbid_destroy, "runtime teardown before allocation");
            if let Some(recorder) = &self.recorder
                && let Ok(mut log) = recorder.destroyed.lock()
            {
                log.push(sandbox.id);
            }
            Ok(())
        }
        async fn health(&self) -> aiec_core::runtime::RuntimeHealth {
            aiec_core::runtime::RuntimeHealth::healthy()
        }
        /// Advertises what the executor requires of a machine. Without exec and
        /// files here, placement refuses the runtime and no run ever reaches a
        /// command, which would test the scheduler rather than these routes.
        fn capabilities(&self) -> aiec_core::runtime::RuntimeCapabilities {
            aiec_core::runtime::RuntimeCapabilities {
                exec: true,
                files: true,
                docker_image: true,
                isolation: aiec_core::runtime::RuntimeIsolation::Container,
                ..Default::default()
            }
        }
    }

    /// An API key of the shape the auth middleware accepts.
    fn run_api_key() -> String {
        format!("af_live_{}", "ab".repeat(24))
    }

    /// A run as an earlier attempt would have left it.
    fn settled_run(tenant: Uuid, state: RunState) -> Run {
        let now = Utc::now();
        Run {
            id: new_id(),
            tenant_id: tenant,
            state,
            requested_at: now,
            queued_at: Some(now),
            started_at: Some(now),
            completed_at: state.is_terminal().then_some(now),
            workload: Default::default(),
            resources: Default::default(),
            requirements: Default::default(),
            placement: Default::default(),
            results: Default::default(),
            failure_reason: None,
            retention: RetentionPolicy::Destroy,
            retained_sandbox_id: None,
            retained_until: None,
            idempotency_key: None,
            parent_run_id: None,
            matrix_id: None,
            matrix_cell: None,
        }
    }

    /// The tables hanging off a run carry no tenant of their own, so the tenant
    /// has to arrive with the write. This store is what every run route is
    /// exercised against, so the same association the database closes has to be
    /// closed here: the link list is what cleanup reads to decide what to tear
    /// down, and a machine belonging to another tenant in it can never be
    /// destroyed by the destroy that is fenced on it.
    #[tokio::test]
    async fn a_run_only_links_keeps_and_records_machines_from_its_own_tenant() {
        let fixture = RunFixture::new();
        let outsider = new_id();
        let now = Utc::now();
        let until = now + chrono::Duration::hours(1);
        let later = now + chrono::Duration::hours(2);

        async fn machine(store: &LeasedRepository, tenant: Uuid) -> Sandbox {
            let now = Utc::now();
            let machine = Sandbox {
                id: new_id(),
                tenant_id: tenant,
                node_id: None,
                image_id: "alpine:3.21".into(),
                state: SandboxState::Running,
                runtime: RuntimeKind::Docker,
                cpu: 1,
                memory_mb: 128,
                disk_mb: 512,
                timeout_seconds: 60,
                network: NetworkPolicy::Disabled,
                environment: Default::default(),
                created_at: now,
                updated_at: now,
                runtime_path: None,
            };
            store.create_sandbox(machine.clone()).await.unwrap();
            machine
        }

        let run = settled_run(fixture.tenant, RunState::Succeeded);
        fixture.store.seed(run.clone()).await;
        let theirs = machine(&fixture.store, outsider).await;

        assert!(matches!(
            fixture
                .store
                .link_run_sandbox(
                    fixture.tenant,
                    RunSandbox {
                        run_id: run.id,
                        sandbox_id: theirs.id,
                        role: "primary".into(),
                    },
                )
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert!(
            fixture
                .store
                .list_run_sandboxes(fixture.tenant, run.id)
                .await
                .unwrap()
                .is_empty(),
            "a refused link leaves nothing behind for cleanup to find"
        );

        assert!(matches!(
            fixture
                .store
                .append_run_event(
                    fixture.tenant,
                    RunEvent {
                        id: new_id(),
                        run_id: run.id,
                        sandbox_id: Some(theirs.id),
                        event_type: "sandbox.assigned".into(),
                        occurred_at: now,
                        detail: json!({}),
                    },
                )
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert!(
            fixture
                .store
                .list_run_events(fixture.tenant, run.id)
                .await
                .unwrap()
                .is_empty(),
            "history is append-only, so a refused event must leave no row either"
        );
        assert!(matches!(
            fixture
                .store
                .record_run_attempt(
                    fixture.tenant,
                    RunAttempt {
                        id: new_id(),
                        run_id: run.id,
                        attempt_number: 1,
                        sandbox_id: Some(theirs.id),
                        state: RunState::Running,
                        failure_reason: None,
                        started_at: now,
                        completed_at: None,
                        placement: Default::default(),
                        results: Default::default(),
                    },
                )
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert!(
            fixture
                .store
                .list_run_attempts(fixture.tenant, run.id)
                .await
                .unwrap()
                .is_empty()
        );

        assert!(matches!(
            fixture
                .store
                .retain_run_sandbox(fixture.tenant, run.id, theirs.id, until)
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert_eq!(
            fixture
                .store
                .get_run(fixture.tenant, run.id)
                .await
                .unwrap()
                .retained_sandbox_id,
            None
        );

        // A machine of this tenant's own that the run never used is refused for
        // the neighbouring reason: retention and the link list have to agree,
        // or cleanup tears down the machine the run asked to keep.
        let unlinked = machine(&fixture.store, fixture.tenant).await;
        assert!(matches!(
            fixture
                .store
                .retain_run_sandbox(fixture.tenant, run.id, unlinked.id, until)
                .await,
            Err(CoreError::Conflict(_))
        ));

        let kept = machine(&fixture.store, fixture.tenant).await;
        let second = machine(&fixture.store, fixture.tenant).await;
        for held in [&kept, &second] {
            fixture
                .store
                .link_run_sandbox(
                    fixture.tenant,
                    RunSandbox {
                        run_id: run.id,
                        sandbox_id: held.id,
                        role: "primary".into(),
                    },
                )
                .await
                .unwrap();
        }
        let retained = fixture
            .store
            .retain_run_sandbox(fixture.tenant, run.id, kept.id, until)
            .await
            .unwrap();
        assert_eq!(retained.retained_sandbox_id, Some(kept.id));

        // Restating the same retention is a retry of one decision, not a second
        // one, so it succeeds and takes the later expiry.
        let retried = fixture
            .store
            .retain_run_sandbox(fixture.tenant, run.id, kept.id, later)
            .await
            .unwrap();
        assert_eq!(retried.retained_until, Some(later));

        assert!(matches!(
            fixture
                .store
                .retain_run_sandbox(fixture.tenant, run.id, second.id, until)
                .await,
            Err(CoreError::Conflict(_))
        ));
        let after = fixture.store.get_run(fixture.tenant, run.id).await.unwrap();
        assert_eq!(
            (after.retained_sandbox_id, after.retained_until),
            (Some(kept.id), Some(later)),
            "the refused second machine left the first one's retention untouched"
        );

        // Another tenant naming this run gets no answer at all: whether the run
        // exists is not theirs to learn.
        assert!(matches!(
            fixture
                .store
                .retain_run_sandbox(outsider, run.id, kept.id, until)
                .await,
            Err(CoreError::NotFound(_))
        ));
    }

    /// The run routes driven over real HTTP against the real router, with a
    /// store that keeps runs and a runtime that runs commands.
    /// Retention is judged on the run's outcome, so it has to be decided before
    /// anything is torn down.
    ///
    /// A live cluster cannot produce this deterministically - it needs a run
    /// that fails *and* a machine to keep - which is exactly why it is pinned
    /// here instead of left to a dogfood run that might not reach the branch.
    #[tokio::test]
    async fn a_failed_run_that_asked_to_be_kept_keeps_its_machine() {
        use aiec_core::run::{RetentionPolicy, RunState};

        let policy = RetentionPolicy::KeepOnFailure;
        let failure_reason = Some("the task did not succeed".to_owned());

        // What the executor now does: decide, then clean up.
        let succeeded = failure_reason.is_none();
        assert!(!succeeded, "a run with a reason is not a success");
        assert!(
            policy.should_retain(succeeded),
            "a run that asked to keep its machine on failure must keep it"
        );
        // And the opposite, so the test is not vacuous.
        assert!(!policy.should_retain(true));

        let destroy = RetentionPolicy::Destroy;
        assert!(
            !destroy.should_retain(false),
            "retention=destroy must release a failed machine too"
        );
        assert_eq!(RunState::Failed.as_str(), "failed");
    }

    /// A recovered Run must stop reporting a teardown that has since succeeded.
    ///
    /// The queue dispatcher finishes a Run only when its results carry no
    /// `cleanup_failed`. Carrying a *previous* failure forward meant a Run
    /// whose machines were all gone still answered "cleanup failed", so the
    /// dispatcher re-leased it on every recovery tick and never finished the
    /// queue row. Three such Runs - created minutes apart, their sandboxes
    /// destroyed with all of them - wedged the queue and starved queued work.
    /// Reclaiming has to clear the stale report before it retries, or the retry
    /// can never succeed.
    #[tokio::test]
    async fn reclaiming_clears_a_cleanup_report_that_predates_the_retry() {
        let fixture = RunFixture::new();
        let sandbox_id = new_id();

        // A run that finished minutes ago and whose machine has since been
        // destroyed, still carrying the report of the teardown that failed
        // before it. This is the exact shape three wedged queue rows had.
        let mut run = settled_run(fixture.tenant, RunState::Succeeded);
        run.results.cleanup_failed = Some(aiec_core::run::CleanupReport {
            sandbox_id,
            error: "conflict: worker lease generation or status changed".into(),
        });
        // The machine has to actually exist, and has to be running: without it
        // the first reclaim tears nothing down, and comparing two counts of
        // zero would pass whether or not the guard works.
        let now = Utc::now();
        fixture
            .store
            .create_sandbox(Sandbox {
                id: sandbox_id,
                tenant_id: fixture.tenant,
                node_id: None,
                image_id: "alpine:3.21".into(),
                state: aiec_core::SandboxState::Running,
                runtime: RuntimeKind::Docker,
                cpu: 1,
                memory_mb: 128,
                disk_mb: 512,
                timeout_seconds: 60,
                network: NetworkPolicy::Disabled,
                environment: Default::default(),
                created_at: now,
                updated_at: now,
                runtime_path: None,
            })
            .await
            .expect("the run's machine exists");
        fixture.store.seed(run.clone()).await;
        fixture
            .store
            .link_run_sandbox(
                fixture.tenant,
                RunSandbox {
                    run_id: run.id,
                    sandbox_id,
                    role: "primary".into(),
                },
            )
            .await
            .expect("the run owns a machine");

        let reclaimed = crate::runs::reclaim_run(&fixture.state, &run)
            .await
            .expect("reclaim a run with nothing left to destroy");
        assert!(
            reclaimed.results.cleanup_failed.is_none(),
            "a run whose machine is gone must stop reporting a failed teardown, \
             or the dispatcher re-leases it forever and starves queued work"
        );

        // Persisted, not just returned: the queue row is finished from what is
        // stored, so an in-memory clear would still wedge the dispatcher.
        let stored = fixture
            .store
            .get_run(fixture.tenant, run.id)
            .await
            .expect("the reclaimed run is still readable");
        assert!(
            stored.results.cleanup_failed.is_none(),
            "the cleared report must be persisted"
        );

        // A second pass over the same machine must not invent a teardown. The
        // outer per-attempt cleanup re-enters after `execute` has already
        // released the machine, and `destroy_with_retry` answers success for a
        // sandbox that is already gone - so without a guard the run's history
        // carried two `sandbox.destroyed` events for one machine, overstating
        // what was released.
        let events = || async {
            fixture
                .store
                .list_run_events(fixture.tenant, run.id)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|event| event.event_type == "sandbox.destroyed")
                .count()
        };
        let before = events().await;
        // Meaningful only if the first pass really tore a machine down: a count
        // of zero would let this test pass no matter what the second pass did.
        assert!(
            before >= 1,
            "the fixture must produce a real teardown before the second pass, \
             or this test cannot detect a duplicated one"
        );
        crate::runs::reclaim_run(&fixture.state, &stored)
            .await
            .expect("a second reclaim over the same machine");
        assert_eq!(
            events().await,
            before,
            "a machine that was already gone is not torn down again, and must not \
             be recorded as if it were"
        );
    }

    #[tokio::test]
    async fn retention_expiry_clears_a_failure_recorded_after_its_read() {
        let fixture = RunFixture::new();
        let now = Utc::now();
        let sandbox = Sandbox {
            id: new_id(),
            tenant_id: fixture.tenant,
            node_id: None,
            image_id: "alpine:3.21".into(),
            state: SandboxState::Running,
            runtime: RuntimeKind::Docker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: NetworkPolicy::Disabled,
            environment: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        };
        fixture.store.create_sandbox(sandbox.clone()).await.unwrap();
        let mut run = settled_run(fixture.tenant, RunState::Failed);
        run.retained_sandbox_id = Some(sandbox.id);
        run.retained_until = Some(now - chrono::Duration::seconds(1));
        fixture.store.seed(run.clone()).await;
        // A second sweeper records a failure after this sweeper reads the run.
        let mut results = run.results.clone();
        results.cleanup_failed = Some(CleanupReport {
            sandbox_id: sandbox.id,
            error: "a concurrent expiry failed".into(),
        });
        fixture
            .store
            .record_run_results(fixture.tenant, run.id, results, run.state)
            .await
            .unwrap();
        runs::expire_retention(&fixture.state, &run).await.unwrap();
        let stored = fixture.store.get_run(fixture.tenant, run.id).await.unwrap();
        assert_eq!(stored.retained_sandbox_id, None);
        assert_eq!(stored.retained_until, None);
        assert!(stored.results.cleanup_failed.is_none());
        assert_eq!(
            fixture
                .store
                .get_sandbox(fixture.tenant, sandbox.id)
                .await
                .unwrap()
                .state,
            SandboxState::Destroyed
        );
    }

    /// A finished run must stop its machine, not merely forget it.
    ///
    /// The bug this pins shipped twice. Cleanup called
    /// `repository().delete_sandbox`, which sets the row to `destroyed` and
    /// credits the node's capacity back, so every assertion about rows and
    /// capacity passed while seventeen containers kept running on the worker.
    /// The observable that would have caught it is the one the old code never
    /// produced: the runtime being told to stop.
    #[tokio::test]
    async fn finishing_a_run_stops_the_machine_it_used() {
        let store = LeasedRepository::new();
        let tenant = new_id();
        let key = run_api_key();
        let root = std::env::temp_dir().join(format!("af-teardown-{}", new_id()));
        let objects: Arc<dyn ArtifactStore> =
            Arc::new(aiec_storage::FilesystemObjectStore::new(&root));
        let recorder = DestroyRecorder::default();
        let runtime: Arc<dyn SandboxRuntime> = Arc::new(RunRuntime::recording(recorder.clone()));
        let metadata: Arc<dyn MetadataStore> = store.clone();
        let platform = Platform::builder()
            .runtime(runtime.clone())
            .runtime_registry(Arc::new(aiec_core::runtime::RuntimeRegistry::with_runtime(
                RuntimeKind::Docker,
                runtime,
            )))
            .metadata_store(metadata)
            .scheduler(Arc::new(DevelopmentScheduler))
            .artifact_store(objects)
            .policy(Arc::new(DefaultPolicy))
            .build()
            .expect("platform");
        let state = AppState::development(platform).with_worker_token("worker-token");

        // The key has to exist before the request, exactly as a tenant's would.
        store
            .put_key(ApiKeyRecord {
                id: new_id(),
                tenant_id: tenant,
                digest: key_digest(&key),
                scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
                expires_at: None,
                revoked_at: None,
                name: "teardown".to_owned(),
                created_at: Utc::now(),
                last_used_at: None,
            })
            .await
            .expect("put key");

        // Through the HTTP layer, so this exercises the path a caller uses
        // rather than a private entry point that might diverge from it.
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/runs")
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "workload": {"image": "python:3.13", "command": ["/bin/sh", "-lc", "true"]},
                    "requested_runtime": "docker",
                    "retention": "destroy",
                })
                .to_string(),
            ))
            .expect("run request");
        let response = app(state.clone()).oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let run: Run = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!("run json: {} / {}", status, String::from_utf8_lossy(&bytes))
        });
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(run.state, RunState::Succeeded);
        let stopped = recorder.destroyed();
        assert_eq!(
            stopped.len(),
            1,
            "a finished run must stop exactly the machine it used"
        );
        let linked = store
            .list_run_sandboxes(tenant, run.id)
            .await
            .expect("run sandboxes");
        assert_eq!(stopped, vec![linked[0].sandbox_id]);
    }

    /// An artifact uploaded to a sandbox must be something the sweeper can
    /// find.
    ///
    /// The sweeper discovers reclaimable objects by scanning the
    /// `artifact_objects` ledger, and only `reserve_artifact_upload` writes
    /// rows into it. This route wrote straight to the object store, so the
    /// bytes landed with nothing pointing at them: no row, no claim, no
    /// deletion, for the life of the deployment - 64 MiB per request that
    /// nothing could take back. Every other production writer of the object
    /// store pairs the reserve with the put; this one did not.
    ///
    /// The assertion is the sweeper's own output rather than a ledger read:
    /// aged past the pending grace, a claim must name this key.
    #[tokio::test]
    async fn an_artifact_uploaded_to_a_sandbox_is_reclaimable() {
        let store = aiec_storage::MemoryRepository::new();
        let tenant = new_id();
        let key = run_api_key();
        let sandbox_id = new_id();
        let root = std::env::temp_dir().join(format!("af-artifact-gc-{}", new_id()));
        let objects: Arc<dyn ArtifactStore> =
            Arc::new(aiec_storage::FilesystemObjectStore::new(&root));
        let metadata: Arc<dyn MetadataStore> = store.clone();
        let platform = Platform::builder()
            .runtime(Arc::new(RunRuntime::recording(DestroyRecorder::default())))
            .metadata_store(metadata)
            .scheduler(Arc::new(DevelopmentScheduler))
            .artifact_store(objects)
            .policy(Arc::new(DefaultPolicy))
            .build()
            .expect("platform");
        let state = AppState::development(platform).with_worker_token("worker-token");

        store
            .put_key(ApiKeyRecord {
                id: new_id(),
                tenant_id: tenant,
                digest: key_digest(&key),
                scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
                expires_at: None,
                revoked_at: None,
                name: "artifact gc".to_owned(),
                created_at: Utc::now(),
                last_used_at: None,
            })
            .await
            .expect("put key");
        let now = Utc::now();
        store
            .create_sandbox(Sandbox {
                id: sandbox_id,
                tenant_id: tenant,
                node_id: None,
                image_id: "alpine:3.21".into(),
                state: aiec_core::SandboxState::Running,
                runtime: RuntimeKind::Docker,
                cpu: 1,
                memory_mb: 128,
                disk_mb: 512,
                timeout_seconds: 60,
                network: NetworkPolicy::Disabled,
                environment: Default::default(),
                created_at: now,
                updated_at: now,
                runtime_path: None,
            })
            .await
            .expect("sandbox exists");

        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/sandboxes/{sandbox_id}/artifacts/report.txt"))
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "content_base64": "Y2hhcmdlIHN0YXlsIHVucmVhY2hhYmxl" })
                    .to_string(),
            ))
            .expect("artifact request");
        let response = app(state.clone()).oneshot(request).await.expect("response");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the upload itself must succeed; this is about what it leaves behind"
        );

        // Past the pending grace, so a key written at upload time is claimable.
        let claims = store
            .claim_artifact_deletions(
                Utc::now() + chrono::Duration::seconds(3_600),
                3_600,
                600,
                100,
                300,
            )
            .await
            .expect("claim");
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            claims.iter().any(|claim| claim.key.contains("report.txt")),
            "the uploaded artifact is invisible to the sweeper; it claimed {:?}",
            claims
                .iter()
                .map(|claim| claim.key.clone())
                .collect::<Vec<_>>()
        );
    }

    /// The same idempotency key must not run the workload twice.
    ///
    /// The old guard asked whether the run was finished. A client retrying
    /// while the first request is still in flight gets that in-flight row back,
    /// it is not finished, and the workload runs again on a second machine with
    /// a second charge - then the two executions fight over one row and the
    /// loser's terminal write overwrites the winner's outcome.
    /// A key that already names a run must not start that workload again.
    ///
    /// The guard used to ask whether the run was finished. A run that is still
    /// in flight is not finished, so a client retrying while the first request
    /// is running got the in-flight row, passed the check, and executed the
    /// whole workload again on a second machine and a second charge - after
    /// which two executions fight over one row and the loser's final write
    /// overwrites the winner's outcome.
    ///
    /// The run here is deliberately `running`, not finished: that is the state
    /// the old check waved through, so this test fails against it rather than
    /// passing on a state both versions agree about.
    #[tokio::test]
    async fn a_retried_key_does_not_restart_an_unfinished_run() {
        let runtime = Arc::new(RunRuntime::default());
        let fixture = RunFixture::with_runtime(runtime);
        let request = crate::runs::RunRequest {
            workload: WorkloadSpec {
                image: Some("python:3.13".into()),
                command: vec!["/bin/sh".into(), "-lc".into(), "true".into()],
                ..WorkloadSpec::default()
            },
            requested_runtime: Some("docker".into()),
            retention: RetentionPolicy::Destroy,
            idempotency_key: Some("already-going".into()),
            ..crate::runs::RunRequest::default()
        };

        // A previous submit for this key is still running.
        let mut existing = settled_run(fixture.tenant, RunState::Running);
        existing.idempotency_key = Some("already-going".into());
        fixture
            .store
            .create_run(existing.clone())
            .await
            .expect("seed the in-flight run");

        let run = crate::runs::submit_and_execute(&fixture.state, fixture.tenant, request.clone())
            .await
            .expect("submit");
        let _ = std::fs::remove_dir_all(&fixture.root);

        assert_eq!(
            run.id, existing.id,
            "a retried key must return the run that already exists"
        );
        assert_eq!(
            run.state,
            RunState::Running,
            "a retried key must not have executed anything"
        );
        let machines = fixture
            .store
            .list_run_sandboxes(fixture.tenant, existing.id)
            .await
            .expect("run sandboxes");
        assert!(
            machines.is_empty(),
            "a retried key placed {} machines for a run already in flight",
            machines.len()
        );
    }

    #[tokio::test]
    async fn api_limits_authenticated_tenants_independently_of_peer_address() {
        let mut fixture = RunFixture::new();
        fixture.state = fixture
            .state
            .clone()
            .with_rate_limit(ratelimit::RateLimit::new(0.0001, 1));
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let other_key = format!("af_live_{}", "cd".repeat(24));
        fixture.issue_key(new_id(), &other_key).await;
        let app = router(fixture.state.clone());
        let request = |key: &str, peer: &str| {
            let mut request = Request::builder()
                .uri("/v1/sandboxes")
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap();
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ));
            request
        };
        assert_eq!(
            app.clone()
                .oneshot(request(&fixture.key, "127.0.0.1:1000"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // Moving addresses must not reset a tenant's budget.
        assert_eq!(
            app.clone()
                .oneshot(request(&fixture.key, "127.0.0.2:1000"))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // A different tenant behind the same address owns a separate budget.
        assert_eq!(
            app.clone()
                .oneshot(request(&other_key, "127.0.0.1:1000"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(request("invalid", "127.0.0.3:1000"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.oneshot(request("invalid", "127.0.0.3:1000"))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    struct RunFixture {
        state: AppState,
        store: Arc<LeasedRepository>,
        objects: Arc<dyn ArtifactStore>,
        tenant: Uuid,
        key: String,
        root: std::path::PathBuf,
    }

    #[tokio::test]
    async fn refused_guard_budget_initialization_reclaims_admitted_sandbox() {
        let fixture = RunFixture::with_runtime(Arc::new(RunRuntime {
            forbid_destroy: true,
            ..Default::default()
        }));
        let now = Utc::now();
        let sandbox = Sandbox {
            id: new_id(),
            tenant_id: fixture.tenant,
            node_id: None,
            image_id: "alpine:3.21".into(),
            state: SandboxState::Creating,
            runtime: RuntimeKind::Docker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: NetworkPolicy::Disabled,
            environment: aiec_core::EnvironmentSpec {
                guard: Some(aiec_guard::policy::GuardConfig::default()),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
            runtime_path: None,
        };
        // This store deliberately lacks Guard budget persistence. Admission
        // has completed, but no runtime allocation has been attempted.
        assert!(
            provision_sandbox(
                &fixture.state,
                fixture.tenant,
                new_id(),
                sandbox.clone(),
                Default::default(),
                None,
                false
            )
            .await
            .is_err()
        );
        assert_eq!(
            fixture
                .store
                .get_sandbox(fixture.tenant, sandbox.id)
                .await
                .unwrap()
                .state,
            SandboxState::Destroyed
        );
    }

    /// A run whose settlement the store refuses must not look finished.
    ///
    /// `fail()` used to write the results and then the failure verdict as two
    /// statements, both `tracing::warn!`-and-carry-on, and returned `Ok(())`
    /// whatever the store said. A database that went away mid-settlement
    /// therefore produced a durable `run.failed` event on a run still in
    /// `running`, with no verdict and no reason: the caller got `200` with a
    /// live run, and the event log said it had failed. The caller has to be
    /// told instead - the run is unsettled and still running, which is the
    /// truth, rather than reported as successfully failed.
    #[tokio::test]
    async fn a_run_whose_settlement_is_refused_is_reported_unsettled() {
        let fixture = RunFixture::with_runtime(Arc::new(RunRuntime::default()));
        *fixture.store.refuse_failure_writes.lock().await = true;
        let mut run = settled_run(fixture.tenant, RunState::Running);
        fixture.store.seed(run.clone()).await;
        let mut results = RunResults::default();
        let mut phases = BTreeMap::new();
        let error = crate::runs::settle_failure(
            &fixture.state,
            fixture.tenant,
            &mut run,
            Some("the workload failed".into()),
            &mut results,
            &mut phases,
        )
        .await
        .expect_err("a refused settlement must be reported");
        assert!(matches!(error, CoreError::Backend(_)), "{error:?}");
        let stored = fixture
            .store
            .get_run(fixture.tenant, run.id)
            .await
            .expect("run row");
        assert_eq!(
            stored.state,
            RunState::Running,
            "a run the store refused to settle must not be recorded as settled"
        );
        assert!(
            !fixture
                .store
                .run_events
                .lock()
                .await
                .get(&run.id)
                .is_some_and(|events| events.iter().any(|e| e.event_type == "run.failed")),
            "no failure event for a failure that was never durably recorded"
        );
    }

    impl RunFixture {
        fn new() -> Self {
            Self::with_runtime(Arc::new(RunRuntime::default()))
        }

        /// The same fixture with a different runtime, so a test that needs a
        /// runtime which blocks or counts has not hand-rolled a second platform
        /// setup that can quietly stop placing sandboxes.
        fn with_runtime(runtime: Arc<dyn SandboxRuntime>) -> Self {
            let root = std::env::temp_dir().join(format!("af-runs-{}", new_id()));
            let objects: Arc<dyn ArtifactStore> =
                Arc::new(aiec_storage::FilesystemObjectStore::new(&root));
            Self::with_parts(runtime, objects, root)
        }

        /// The same fixture over a caller-supplied object store, so a test can
        /// make storage fail rather than only succeed. A collection failure that
        /// cannot be produced is a failure nobody notices is handled.
        fn with_object_store(objects: Arc<dyn ArtifactStore>) -> Self {
            let root = std::env::temp_dir().join(format!("af-runs-{}", new_id()));
            Self::with_parts(Arc::new(RunRuntime::default()), objects, root)
        }

        fn with_parts(
            runtime: Arc<dyn SandboxRuntime>,
            objects: Arc<dyn ArtifactStore>,
            root: std::path::PathBuf,
        ) -> Self {
            let store = LeasedRepository::new();
            let tenant = new_id();
            let key = run_api_key();
            let metadata: Arc<dyn MetadataStore> = store.clone();
            let platform = Platform::builder()
                .runtime(runtime.clone())
                .runtime_registry(Arc::new(aiec_core::runtime::RuntimeRegistry::with_runtime(
                    RuntimeKind::Docker,
                    runtime,
                )))
                .metadata_store(metadata)
                .scheduler(Arc::new(DevelopmentScheduler))
                .artifact_store(objects.clone())
                .policy(Arc::new(DefaultPolicy))
                .build()
                .expect("platform");
            let state = AppState::development(platform).with_worker_token("worker-token");
            Self {
                state,
                store,
                objects,
                tenant,
                key,
                root,
            }
        }

        /// Issues a key for `tenant`. Each tenant gets its own, because a
        /// request is only ever seen as the principal its key resolves to.
        async fn issue_key(&self, tenant: Uuid, key: &str) {
            self.store
                .put_key(ApiKeyRecord {
                    id: new_id(),
                    tenant_id: tenant,
                    digest: key_digest(key),
                    scopes: vec![Scope::SandboxesRead, Scope::SandboxesWrite],
                    expires_at: None,
                    revoked_at: None,
                    name: "runs".to_owned(),
                    created_at: Utc::now(),
                    last_used_at: None,
                })
                .await
                .expect("put key");
        }

        async fn call(
            &self,
            method: axum::http::Method,
            path: &str,
            key: &str,
            body: Value,
        ) -> (StatusCode, HeaderMap, Vec<u8>) {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("run request");
            let response = app(self.state.clone())
                .oneshot(request)
                .await
                .expect("run response");
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("run body");
            (status, headers, bytes.to_vec())
        }

        async fn call_json(
            &self,
            method: axum::http::Method,
            path: &str,
            body: Value,
        ) -> (StatusCode, Value) {
            let (status, _, bytes) = self.call(method, path, &self.key, body).await;
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        /// Submits a run that does nothing, and returns it as the caller saw it.
        async fn submit(&self) -> Value {
            let (status, value) = self
                .call_json(
                    axum::http::Method::POST,
                    "/v1/runs",
                    json!({ "workload": { "command": ["true"] } }),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "submit: {value}");
            value
        }
    }

    impl Drop for RunFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn run_document(value: &Value) -> Run {
        serde_json::from_value(value.clone()).expect("run document")
    }

    /// Submitting a run creates it, runs it, and answers with the settled
    /// document -- the caller is told what happened rather than that something
    /// was started.
    #[tokio::test]
    async fn a_submitted_run_comes_back_settled_with_its_id() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;

        let value = fixture.submit().await;
        let run = run_document(&value);
        assert_eq!(run.tenant_id, fixture.tenant);
        assert_eq!(run.state, RunState::Succeeded);
        assert_eq!(
            run.results.task.as_ref().map(|task| task.exit_code),
            Some(0)
        );
    }

    /// The id is in a header so a client can follow the run from a log line,
    /// and it has to be the run that was just created.
    #[tokio::test]
    async fn a_created_run_reports_its_id_in_a_header() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;

        let (status, headers, bytes) = fixture
            .call(
                axum::http::Method::POST,
                "/v1/runs",
                &fixture.key,
                json!({ "workload": { "command": ["true"] } }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let value: Value = serde_json::from_slice(&bytes).expect("run document");
        assert_eq!(
            headers.get(RUN_ID_HEADER).map(|value| value.to_str().ok()),
            Some(Some(value["id"].as_str().unwrap_or_default()))
        );
    }

    /// A retried request must not run the work twice; the key it already used
    /// brings back the run that key produced.
    #[tokio::test]
    async fn a_retried_request_with_the_same_idempotency_key_reuses_the_run() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let submit_with_key = |key: Option<String>| {
            let (state, raw) = (fixture.state.clone(), fixture.key.clone());
            async move {
                let mut builder = Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/runs")
                    .header("authorization", format!("Bearer {raw}"))
                    .header("content-type", "application/json");
                if let Some(key) = key.as_deref() {
                    builder = builder.header("idempotency-key", key);
                }
                let request = builder
                    .body(Body::from(
                        json!({ "workload": { "command": ["true"] } }).to_string(),
                    ))
                    .expect("run request");
                let response = app(state).oneshot(request).await.expect("run response");
                assert_eq!(response.status(), StatusCode::CREATED);
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("run body");
                serde_json::from_slice::<Value>(&body).expect("run document")
            }
        };

        let first = submit_with_key(Some("retry-me".to_owned())).await;
        let retried = submit_with_key(Some("retry-me".to_owned())).await;
        assert_eq!(
            first["id"], retried["id"],
            "a retried request executed the work a second time"
        );
        let unkeyed = submit_with_key(None).await;
        assert_ne!(
            unkeyed["id"], retried["id"],
            "a request without the key joined a run it never named"
        );
    }

    /// The run a caller submitted is the run they read back.
    #[tokio::test]
    async fn a_run_can_be_read_back_by_id() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let created = fixture.submit().await;

        let (status, value) = fixture
            .call_json(
                axum::http::Method::GET,
                &format!("/v1/runs/{}", created["id"].as_str().unwrap_or_default()),
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["id"], created["id"]);
        assert_eq!(value["state"], created["state"]);
    }

    /// A run belonging to somebody else has to read as missing. A 403 would
    /// confirm the id exists, which turns the run ids into a directory of other
    /// tenants' work.
    #[tokio::test]
    async fn another_tenants_run_reads_as_missing_rather_than_forbidden() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let created = fixture.submit().await;
        let stranger_key = run_api_key().replace("ab", "cd");
        let stranger = new_id();
        fixture.issue_key(stranger, &stranger_key).await;

        let (status, _, bytes) = fixture
            .call(
                axum::http::Method::GET,
                &format!("/v1/runs/{}", created["id"].as_str().unwrap_or_default()),
                &stranger_key,
                Value::Null,
            )
            .await;
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {value}");
        assert_eq!(value["error"]["code"], "not_found");
    }

    /// The list is a tenant's own history, and only its own.
    #[tokio::test]
    async fn a_tenant_does_not_see_another_tenants_runs() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let created = fixture.submit().await;
        let stranger_key = run_api_key().replace("ab", "cd");
        fixture.issue_key(new_id(), &stranger_key).await;

        let (status, mine) = fixture
            .call_json(axum::http::Method::GET, "/v1/runs", Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK);
        let listed: Vec<Value> = serde_json::from_value(mine).expect("run list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["id"], created["id"]);

        let (_, _, theirs) = fixture
            .call(
                axum::http::Method::GET,
                "/v1/runs",
                &stranger_key,
                Value::Null,
            )
            .await;
        let listed: Vec<Value> = serde_json::from_slice(&theirs).expect("run list");
        assert!(
            listed.is_empty(),
            "another tenant's runs leaked: {listed:?}"
        );
    }

    /// A state filter narrows the page, and a limit below the floor is clamped
    /// rather than rejected: the caller asked for runs, not for a refusal.
    #[tokio::test]
    async fn a_run_page_is_filtered_by_state() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        fixture.submit().await;
        fixture
            .store
            .seed(settled_run(fixture.tenant, RunState::Running))
            .await;

        let (status, value) = fixture
            .call_json(
                axum::http::Method::GET,
                "/v1/runs?state=running&limit=0",
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let listed: Vec<Run> = serde_json::from_value(value).expect("run list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, RunState::Running);

        let (status, _) = fixture
            .call_json(
                axum::http::Method::GET,
                "/v1/runs?state=nonsense",
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The history of a run reads in the order it happened, starting with the
    /// creation the executor records before any work starts.
    #[tokio::test]
    async fn a_runs_events_are_returned_in_order() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let created = fixture.submit().await;
        let id = created["id"].as_str().unwrap_or_default().to_owned();

        let (status, value) = fixture
            .call_json(
                axum::http::Method::GET,
                &format!("/v1/runs/{id}/events"),
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let events: Vec<RunEvent> = serde_json::from_value(value).expect("event list");
        assert!(!events.is_empty(), "a run with no history is undebuggable");
        assert_eq!(
            events.first().map(|event| event.event_type.as_str()),
            Some("run.created")
        );
        assert!(events.iter().all(|event| event.run_id.to_string() == id));
    }

    /// The bytes a run collects are the file's bytes, described by the file's
    /// own size and digest, and the listing's URL serves exactly those bytes.
    ///
    /// Driven through a real run rather than by seeding the artifact table,
    /// because every one of the defects this covers lived between the sandbox
    /// and the table and left a hand-written row looking perfectly correct. The
    /// payload is binary on purpose: NUL bytes and invalid UTF-8 are what a base64
    /// text file mangles, and they are the reason the artifact is decoded rather
    /// than stored as the transport encoding.
    #[tokio::test]
    async fn a_collected_artifact_is_the_file_its_bytes_not_their_base64() {
        let mut files = TestMap::new();
        files.insert(
            "/workspace/report.bin".to_owned(),
            bytes::Bytes::from_static(&[0x00, 0xff, 0xfe, b'h', b'i']),
        );
        let fixture = RunFixture::with_runtime(Arc::new(RunRuntime::default().serving(files)));
        fixture.issue_key(fixture.tenant, &fixture.key).await;

        let (status, submitted) = fixture
            .call_json(
                axum::http::Method::POST,
                "/v1/runs",
                json!({
                    "workload": {
                        "command": ["/bin/sh", "-lc", "printf hello > /workspace/report.bin"],
                        "artifacts": ["/workspace/report.bin"],
                    },
                    "requested_runtime": "docker",
                    "retention": "destroy",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "submit: {submitted}");
        let run_id = submitted["id"].as_str().unwrap_or_default().to_owned();

        // The absolute path is the ordinary way to ask, and it is what came back
        // empty from a live cluster: the object key was built by pasting the path
        // into `.../runs/{id}/`, producing an empty component the store rejects,
        // and the rejection was skipped like any other.
        let artifacts = submitted["results"]["artifacts"]
            .as_array()
            .expect("collected artifacts");
        assert_eq!(
            artifacts.len(),
            1,
            "a run that asked for a file it wrote collected nothing: {submitted}"
        );
        assert_eq!(artifacts[0]["name"], "/workspace/report.bin");
        assert_eq!(
            artifacts[0]["size_bytes"], 5,
            "the recorded size must be the file's, not the base64 text's"
        );
        assert_eq!(
            artifacts[0]["checksum_sha256"],
            hex::encode(sha2::Sha256::digest([0x00, 0xff, 0xfe, b'h', b'i']))
        );

        let (status, listed) = fixture
            .call_json(
                axum::http::Method::GET,
                &format!("/v1/runs/{run_id}/artifacts"),
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let listed: Vec<Value> = serde_json::from_value(listed).expect("artifact list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["name"], "/workspace/report.bin");

        let url = listed[0]["download_url"].as_str().unwrap_or_default();
        assert!(
            !url.ends_with("/artifacts//workspace/report.bin"),
            "an absolute name must be escaped, not pasted into the path: {url}"
        );
        let (status, _, bytes) = fixture
            .call(axum::http::Method::GET, url, &fixture.key, Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK, "download {url}");
        assert_eq!(
            bytes,
            vec![0x00, 0xff, 0xfe, b'h', b'i'],
            "the downloaded bytes must be the file's"
        );
    }

    #[tokio::test]
    async fn collection_accepts_empty_and_limit_files_and_rejects_over_limit() {
        for size in [0, aiec_core::MAX_FILE, aiec_core::MAX_FILE + 1] {
            let name = "/workspace/boundary.bin";
            let payload = bytes::Bytes::from(vec![0x9b; size]);
            let mut files = TestMap::new();
            files.insert(name.to_owned(), payload.clone());
            let fixture = RunFixture::with_runtime(Arc::new(RunRuntime::default().serving(files)));
            fixture.issue_key(fixture.tenant, &fixture.key).await;
            let (status, submitted) = fixture
                .call_json(
                    axum::http::Method::POST,
                    "/v1/runs",
                    json!({
                        "workload": {"command": ["true"], "artifacts": [name]},
                        "requested_runtime": "docker",
                    }),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{submitted}");
            if size > aiec_core::MAX_FILE {
                assert_eq!(submitted["state"], "failed");
                assert_eq!(submitted["results"]["artifacts"], json!([]));
            } else {
                assert_eq!(submitted["state"], "succeeded", "{submitted}");
                let artifacts = &submitted["results"]["artifacts"];
                assert_eq!(artifacts[0]["size_bytes"], size);
                assert_eq!(
                    artifacts[0]["checksum_sha256"],
                    hex::encode(sha2::Sha256::digest(&payload))
                );
                let id = submitted["id"].as_str().expect("run id");
                let (status, _, downloaded) = fixture
                    .call(
                        axum::http::Method::GET,
                        &format!("/v1/runs/{id}/artifacts/%2Fworkspace%2Fboundary.bin"),
                        &fixture.key,
                        Value::Null,
                    )
                    .await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(downloaded.as_slice(), payload.as_ref());
            }
        }
    }

    #[tokio::test]
    async fn a_corrupted_run_artifact_is_rejected_before_success_headers() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let run = settled_run(fixture.tenant, RunState::Succeeded);
        fixture.store.seed(run.clone()).await;
        let key = crate::runs::run_artifact_key(fixture.tenant, run.id, "report.bin");
        let stored = fixture
            .objects
            .put(&key, bytes::Bytes::from_static(b"good"))
            .await
            .unwrap();
        fixture
            .store
            .put_run_artifacts(
                fixture.tenant,
                run.id,
                vec![RunArtifactRef {
                    name: "report.bin".into(),
                    object_key: key.clone(),
                    size_bytes: stored.size_bytes as i64,
                    checksum_sha256: Some(stored.checksum_sha256),
                    content_type: Some("application/octet-stream".into()),
                }],
            )
            .await
            .unwrap();
        tokio::fs::write(fixture.root.join(&key), b"evil")
            .await
            .unwrap();
        let (status, headers, _) = fixture
            .call(
                axum::http::Method::GET,
                &format!("/v1/runs/{}/artifacts/report.bin", run.id),
                &fixture.key,
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_ne!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream")
        );
    }

    /// An artifact collected by a run outlives the machine that produced it.
    ///
    /// The whole point of collecting is that the caller gets the file back, and
    /// a `retention: destroy` run is the normal case: the sandbox is gone before
    /// the response is written, so anything that only existed inside it is gone
    /// too. This asserts against the run's own recorded URL rather than a
    /// hand-seeded row, so it fails if collection itself stops happening.
    #[tokio::test]
    async fn a_collected_artifact_outlives_the_machine_that_produced_it() {
        let mut files = TestMap::new();
        files.insert(
            "/workspace/out/result.json".to_owned(),
            bytes::Bytes::from_static(br#"{"ok":true}"#),
        );
        let recorder = DestroyRecorder::default();
        let runtime = Arc::new(RunRuntime::recording(recorder.clone()).serving(files));
        let fixture = RunFixture::with_runtime(runtime);
        fixture.issue_key(fixture.tenant, &fixture.key).await;

        let (status, submitted) = fixture
            .call_json(
                axum::http::Method::POST,
                "/v1/runs",
                json!({
                    "workload": {
                        "command": ["/bin/sh", "-lc", "true"],
                        "artifacts": ["/workspace/out/result.json"],
                    },
                    "requested_runtime": "docker",
                    "retention": "destroy",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "submit: {submitted}");
        let run_id = submitted["id"].as_str().unwrap_or_default().to_owned();
        assert_eq!(
            recorder.destroyed().len(),
            1,
            "the machine must be gone for this to mean anything"
        );

        // A nested name is the shape that broke the old single-segment route: the
        // listing produced `/artifacts//workspace/out/result.json`, which matched
        // nothing, so a collected nested artifact could be listed but never read.
        let (status, listed) = fixture
            .call_json(
                axum::http::Method::GET,
                &format!("/v1/runs/{run_id}/artifacts"),
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let listed: Vec<Value> = serde_json::from_value(listed).expect("artifact list");
        assert_eq!(listed.len(), 1);
        let url = listed[0]["download_url"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let (status, _, bytes) = fixture
            .call(axum::http::Method::GET, &url, &fixture.key, Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK, "download {url}");
        assert_eq!(bytes, br#"{"ok":true}"#);
    }

    /// A URL only serves the artifact it names. Widening the route to reach nested
    /// names must not turn the rest of the key space into a readable one.
    #[tokio::test]
    async fn a_run_artifact_url_serves_only_a_name_the_run_collected() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let run = settled_run(fixture.tenant, RunState::Succeeded);
        fixture.store.seed(run.clone()).await;
        let key = crate::runs::run_artifact_key(fixture.tenant, run.id, "/workspace/report.txt");
        fixture
            .store
            .put_run_artifacts(
                fixture.tenant,
                run.id,
                vec![RunArtifactRef {
                    name: "/workspace/report.txt".to_owned(),
                    object_key: key.clone(),
                    size_bytes: 4,
                    checksum_sha256: None,
                    content_type: Some("application/octet-stream".to_owned()),
                }],
            )
            .await
            .expect("record artifacts");
        fixture
            .objects
            .put(&key, bytes::Bytes::from_static(b"data"))
            .await
            .expect("store artifact");

        for name in [
            "/workspace/other.txt",
            "/workspace/report.txt/../../escape",
            "/",
            "/tenants/other-tenant/sandboxes/x/artifacts/y",
        ] {
            let encoded: String = name
                .bytes()
                .map(|byte| match byte {
                    b'-' | b'.' | b'_' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => {
                        char::from(byte).to_string()
                    }
                    other => format!("%{other:02X}"),
                })
                .collect();
            let (status, _, _) = fixture
                .call(
                    axum::http::Method::GET,
                    &format!("/v1/runs/{}/artifacts/{encoded}", run.id),
                    &fixture.key,
                    Value::Null,
                )
                .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{name} is not an artifact this run collected"
            );
        }
    }

    /// One tenant's key cannot read another tenant's run artifact, and cannot
    /// discover that it exists by listing.
    #[tokio::test]
    async fn another_tenant_cannot_read_a_runs_artifacts() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let run = settled_run(fixture.tenant, RunState::Succeeded);
        let key = crate::runs::run_artifact_key(fixture.tenant, run.id, "/workspace/report.txt");
        fixture
            .objects
            .put(&key, bytes::Bytes::from_static(b"private output"))
            .await
            .expect("store artifact");
        fixture.store.seed(run.clone()).await;
        fixture
            .store
            .put_run_artifacts(
                fixture.tenant,
                run.id,
                vec![RunArtifactRef {
                    name: "/workspace/report.txt".to_owned(),
                    object_key: key,
                    size_bytes: 14,
                    checksum_sha256: None,
                    content_type: Some("application/octet-stream".to_owned()),
                }],
            )
            .await
            .expect("record artifacts");

        let outsider = new_id();
        let outsider_key = format!("af_live_{}", "cd".repeat(24));
        fixture.issue_key(outsider, &outsider_key).await;

        let (status, _, _) = fixture
            .call(
                axum::http::Method::GET,
                &format!("/v1/runs/{}/artifacts", run.id),
                &outsider_key,
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, bytes) = fixture
            .call(
                axum::http::Method::GET,
                &format!("/v1/runs/{}/artifacts/%%2Fworkspace%%2Freport.txt", run.id),
                &outsider_key,
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            !bytes.windows(6).any(|window| window == b"private"),
            "a cross-tenant read leaked the artifact"
        );
    }

    /// Storage failing mid-collection fails the run rather than quietly producing
    /// a shorter list than the caller asked for.
    #[tokio::test]
    async fn a_run_fails_when_artifact_storage_rejects_the_write() {
        let objects: Arc<dyn ArtifactStore> = Arc::new(UnwritableStore);
        let fixture = RunFixture::with_object_store(objects);
        fixture.issue_key(fixture.tenant, &fixture.key).await;

        let (status, submitted) = fixture
            .call_json(
                axum::http::Method::POST,
                "/v1/runs",
                json!({
                    "workload": {
                        "command": ["/bin/sh", "-lc", "true"],
                        "artifacts": ["/workspace/report.txt"],
                    },
                    "requested_runtime": "docker",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "submit: {submitted}");
        assert_eq!(
            submitted["state"], "failed",
            "a run whose artifacts were never stored must not report success"
        );
    }

    /// A machine asked to be kept must survive a failure that happens late.
    ///
    /// `execute` releases the attempt's machine before it returns, then reports
    /// the outcome as an error so the caller can classify it. The caller used to
    /// read that as "still held" and ran cleanup a second time - this time with
    /// `retention_seconds = None`, which destroys. So a `keep_on_failure` run
    /// that failed while *collecting artifacts* lost the machine the caller had
    /// asked to keep, and nothing in the response said so.
    #[tokio::test]
    async fn a_machine_kept_on_failure_survives_a_collection_failure() {
        let objects: Arc<dyn ArtifactStore> = Arc::new(UnwritableStore);
        let fixture = RunFixture::with_object_store(objects);
        fixture.issue_key(fixture.tenant, &fixture.key).await;

        let (status, submitted) = fixture
            .call_json(
                axum::http::Method::POST,
                "/v1/runs",
                json!({
                    "workload": {
                        "command": ["/bin/sh", "-lc", "exit 3"],
                        "artifacts": ["/workspace/report.txt"],
                    },
                    "requested_runtime": "docker",
                    "retention": "keep_on_failure",
                    "retained_seconds": 3600,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "submit: {submitted}");
        let run = run_document(&submitted);
        assert_eq!(run.state, RunState::Failed, "the run should have failed");

        let Some(retained) = run.retained_sandbox_id else {
            panic!("a keep_on_failure run must report a machine it kept: {submitted}");
        };
        let sandbox = fixture
            .store
            .get_sandbox(fixture.tenant, retained)
            .await
            .expect("the retained machine is still readable");
        assert_ne!(
            sandbox.state,
            aiec_core::SandboxState::Destroyed,
            "the machine the caller asked to keep was destroyed by a second cleanup"
        );
    }

    #[tokio::test]
    async fn a_permanent_setup_failure_keeps_its_debugging_machine_without_retrying() {
        let failed_setup = vec!["/bin/sh".into(), "-lc".into(), "exit 1".into()];
        let fixture = RunFixture::with_runtime(Arc::new(RunRuntime {
            failing_command: Some(failed_setup.clone()),
            ..Default::default()
        }));
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let (status, submitted) = fixture
            .call_json(
                axum::http::Method::POST,
                "/v1/runs",
                json!({
                    "workload": {
                        "setup": [failed_setup],
                        "command": ["true"],
                    },
                    "requested_runtime": "docker",
                    "max_attempts": 2,
                    "retention": "keep_on_failure",
                    "retained_seconds": 3600,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let run = run_document(&submitted);
        assert_eq!(run.state, RunState::Failed);
        assert!(
            run.results.task.is_none(),
            "the task must not run after setup failed"
        );
        let sandboxes = fixture
            .store
            .list_sandboxes(fixture.tenant, aiec_core::storage::MAX_SANDBOX_PAGE, None)
            .await
            .unwrap();
        assert_eq!(
            sandboxes.sandboxes.len(),
            1,
            "a failed setup is permanent, not a fresh-machine retry"
        );
        assert_eq!(run.retained_sandbox_id, Some(sandboxes.sandboxes[0].id));
        assert_eq!(sandboxes.sandboxes[0].state, SandboxState::Running);
    }

    /// A storage refusal must cost one machine, not one per remaining attempt.
    ///
    /// The test above cannot tell the two behaviours apart: it runs at the
    /// default `max_attempts: 1`, where "retry on a fresh machine" has nowhere
    /// to go. With a higher bound the old classification spent a whole sandbox
    /// re-running a task that had already exited 0, and re-collecting the same
    /// bytes to reach the same refusal - once per remaining attempt. The run
    /// still fails either way; what must not change is the number of machines.
    #[tokio::test]
    async fn a_rejected_artifact_is_retried_on_no_further_machine() {
        let objects: Arc<dyn ArtifactStore> = Arc::new(UnwritableStore);
        let fixture = RunFixture::with_object_store(objects);
        fixture.issue_key(fixture.tenant, &fixture.key).await;

        let (status, submitted) = fixture
            .call_json(
                axum::http::Method::POST,
                "/v1/runs",
                json!({
                    "workload": {
                        "command": ["/bin/sh", "-lc", "true"],
                        "artifacts": ["/workspace/report.txt"],
                    },
                    "requested_runtime": "docker",
                    "max_attempts": 3,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "submit: {submitted}");
        let run = run_document(&submitted);
        assert_eq!(
            run.state,
            RunState::Failed,
            "an artifact that was never stored is not a success"
        );

        let attempts = fixture
            .store
            .list_run_attempts(fixture.tenant, run.id)
            .await
            .expect("attempts are readable");
        assert_eq!(
            attempts.len(),
            1,
            "a store that refuses every write would otherwise cost a machine per \
             attempt, re-running a workload that already succeeded"
        );
    }

    /// An artifact store whose every write fails.
    ///
    /// Real enough to be worth having: the point is that collection has a failure
    /// path at all, and a store that only ever succeeds cannot produce one.
    struct UnwritableStore;

    #[async_trait::async_trait]
    impl ArtifactStore for UnwritableStore {
        async fn put(&self, _: &str, _: bytes::Bytes) -> Result<ObjectMetadata, CoreError> {
            Err(CoreError::Transient(
                "the object store is unavailable".into(),
            ))
        }
        async fn get(&self, _: &str) -> Result<Vec<u8>, CoreError> {
            Err(CoreError::NotFound("no such object".into()))
        }
        async fn get_checked(&self, _: &str, _: &GetObjectOptions) -> Result<Vec<u8>, CoreError> {
            Err(CoreError::NotFound("no such object".into()))
        }
        async fn put_stream(
            &self,
            _: &str,
            _: &mut dyn aiec_core::storage::ArtifactSource,
            _: u64,
        ) -> Result<ObjectMetadata, CoreError> {
            Err(CoreError::Transient(
                "the object store is unavailable".into(),
            ))
        }
        async fn get_verified(
            &self,
            _: &str,
            _: &GetObjectOptions,
            _: u64,
        ) -> Result<aiec_core::storage::ArtifactDownload, CoreError> {
            Err(CoreError::NotFound("no such object".into()))
        }
        async fn delete(&self, _: &str) -> Result<(), CoreError> {
            Ok(())
        }
        async fn list(&self, _: &str) -> Result<Vec<ObjectMetadata>, CoreError> {
            Ok(Vec::new())
        }
        async fn delete_if_match(&self, _: &str, _: &str) -> Result<(), CoreError> {
            Ok(())
        }
    }

    /// Cancelling a finished run is not a failure: the caller wanted no machine
    /// of theirs left working, and there already is none.
    #[tokio::test]
    async fn cancelling_a_finished_run_returns_it_unchanged() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let created = fixture.submit().await;
        let id = created["id"].as_str().unwrap_or_default().to_owned();

        let (status, value) = fixture
            .call_json(
                axum::http::Method::POST,
                &format!("/v1/runs/{id}/cancel"),
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["id"], created["id"]);
        assert_eq!(value["state"], created["state"]);
        assert_eq!(value["state"], "succeeded");
        assert_eq!(value["completed_at"], created["completed_at"]);
    }

    /// Cancelling a run that is still working stops it and reclaims the machine
    /// it was holding. The sandbox is the expensive part: a cancelled run that
    /// left one behind would be holding capacity nobody is paying for.
    #[tokio::test]
    async fn cancelling_a_live_run_stops_it_and_reclaims_its_machine() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let run = settled_run(fixture.tenant, RunState::Running);
        let sandbox = Sandbox {
            id: new_id(),
            tenant_id: fixture.tenant,
            node_id: None,
            image_id: "aiec-coding:latest".into(),
            state: SandboxState::Running,
            runtime: RuntimeKind::Docker,
            cpu: 1,
            memory_mb: 512,
            disk_mb: 1024,
            timeout_seconds: 60,
            network: NetworkPolicy::Disabled,
            environment: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            runtime_path: None,
        };
        fixture
            .store
            .create_sandbox(sandbox.clone())
            .await
            .expect("create sandbox");
        fixture.store.seed(run.clone()).await;
        fixture
            .store
            .link_run_sandbox(
                fixture.tenant,
                RunSandbox {
                    run_id: run.id,
                    sandbox_id: sandbox.id,
                    role: "primary".into(),
                },
            )
            .await
            .expect("link sandbox");

        let (status, value) = fixture
            .call_json(
                axum::http::Method::POST,
                &format!("/v1/runs/{}/cancel", run.id),
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "cancel: {value}");
        assert_eq!(value["state"], "cancelled");
        // Deleting a sandbox is a state change, not a row removal: what matters
        // is that the machine is no longer running the work.
        assert_eq!(
            fixture
                .store
                .get_sandbox(fixture.tenant, sandbox.id)
                .await
                .map(|sandbox| sandbox.state)
                .expect("sandbox row"),
            SandboxState::Destroyed,
            "a cancelled run left its machine running"
        );
    }

    /// A tenant that cannot see a run cannot cancel it either: the ownership
    /// check is the same one the read uses, so cancellation is not a way to
    /// stop somebody else's work.
    #[tokio::test]
    async fn cancelling_another_tenants_run_reads_as_missing() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let created = fixture.submit().await;
        let stranger_key = run_api_key().replace("ab", "cd");
        fixture.issue_key(new_id(), &stranger_key).await;

        let (status, _, bytes) = fixture
            .call(
                axum::http::Method::POST,
                &format!(
                    "/v1/runs/{}/cancel",
                    created["id"].as_str().unwrap_or_default()
                ),
                &stranger_key,
                Value::Null,
            )
            .await;
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {value}");
        assert_eq!(
            fixture
                .store
                .stored_run(fixture.tenant, run_document(&created).id)
                .await
                .map(|run| run.state)
                .expect("run"),
            RunState::Succeeded
        );
    }

    /// The read scope is enough to read a run and its history, and a key
    /// without it is refused before any run is touched.
    #[tokio::test]
    async fn a_key_without_the_read_scope_cannot_read_a_run() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let created = fixture.submit().await;
        let reader_key = run_api_key().replace("ab", "cd");
        fixture
            .store
            .put_key(ApiKeyRecord {
                id: new_id(),
                tenant_id: fixture.tenant,
                digest: key_digest(&reader_key),
                scopes: vec![Scope::SnapshotsRead],
                expires_at: None,
                revoked_at: None,
                name: "snapshots only".to_owned(),
                created_at: Utc::now(),
                last_used_at: None,
            })
            .await
            .expect("put key");

        let (status, _, _) = fixture
            .call(
                axum::http::Method::GET,
                &format!("/v1/runs/{}", created["id"].as_str().unwrap_or_default()),
                &reader_key,
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
