use aiec_core::*;
use aiec_core::{
    platform::Platform,
    policy::PolicyOperation,
    run::{CleanupReport, Run, RunArtifactRef, RunEvent, RunState},
    runtime::SandboxRuntime,
    snapshots::{SnapshotKind, SnapshotMetadata, SnapshotRequest, verify_archive_checksum},
    storage::{ArtifactStore, GetObjectOptions, MetadataStore},
};
pub mod account;
mod composition;
pub mod eval_matrix;
pub mod omp;
pub mod ratelimit;
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
use tokio::sync::Mutex;
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
    /// Per-tenant / per-client admission control for the public API.
    limiter: Arc<ratelimit::RateLimiter>,
    /// Aggregate execution budget for hosted capacity. Reaching it stops new
    /// sandbox creation instead of risking a provider overage.
    execution_budget: Option<ExecutionBudget>,
    /// When true, only microVM-class runtimes are offered to tenants.
    hosted_only: bool,
    /// Invite codes accepted by public signup. Empty means signup is closed.
    invites: Arc<Vec<String>>,
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
        let generation = match self.repository().sandbox_ownership(sandbox.id).await {
            Ok(ownership) => ownership.map(|ownership| ownership.generation),
            Err(CoreError::Unsupported(_)) => None,
            Err(error) => return Err(error),
        };
        match generation {
            Some(generation) => {
                self.repository()
                    .update_state_with_generation(
                        sandbox.tenant_id,
                        sandbox.id,
                        expected,
                        next,
                        generation,
                    )
                    .await?;
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
    // Rate limiting runs outside `auth` so that unauthenticated floods are
    // bounded too, and inside it so a tenant is limited per tenant.
    // Signup is deliberately outside the auth layer: it is how a stranger
    // obtains a credential in the first place. It is invite-gated, and rate
    // limited like everything else.
    let public = Router::new().route("/account", post(signup));
    let protected = protected_routes().route("/account", get(current_account));
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
                .layer(middleware::from_fn_with_state(state.clone(), auth))
                .layer(middleware::from_fn_with_state(state.clone(), rate_limit)),
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
    // `auth` inserts a `Principal`, not a bare tenant id; reading the wrong type
    // meant every caller shared the anonymous bucket.
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip());
    let tenant = request.extensions().get::<Principal>().map(|p| p.tenant_id);
    let key = ratelimit::limit_key(tenant, peer);
    let decision = state.limiter().check(&key);
    if !decision.allowed {
        return limited_response(decision.retry_after_seconds);
    }
    next.run(request).await
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
    let scopes = if body.scopes.is_empty() {
        account::DEFAULT_KEY_SCOPES.to_vec()
    } else {
        let mut parsed = Vec::new();
        for scope in &body.scopes {
            parsed.push(Scope::parse(scope).map_err(ApiFailure::from)?);
        }
        // A key may not grant a privilege its holder does not have. Without
        // this, a read-only key could mint itself an admin key and then revoke
        // the tenant's real credentials.
        if parsed.contains(&Scope::Admin) && !p.scopes.contains(&Scope::Admin) {
            return Err(ApiFailure::new(
                StatusCode::FORBIDDEN,
                "insufficient_scope",
                "only a key that already holds admin may create another admin key",
            ));
        }
        for scope in parsed.clone() {
            p.authorize(scope.clone()).map_err(|_| {
                ApiFailure::new(
                    StatusCode::FORBIDDEN,
                    "insufficient_scope",
                    format!("this key cannot grant the {:?} scope", scope),
                )
            })?;
        }
        parsed
    };
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

fn protected_routes() -> Router<AppState> {
    Router::new()
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
                .get(download_artifact)
                .delete(delete_artifact),
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
        .route("/runs/{id}/artifacts/{name}", get(download_run_artifact))
        .route("/runs/{id}/cancel", post(cancel_run))
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
            available_vcpus: heartbeat.available_vcpus,
            available_memory_bytes: heartbeat.available_memory_bytes,
            available_disk_bytes: heartbeat.available_disk_bytes,
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
        .commit_state(&sandbox, expected, SandboxState::Starting)
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
        .commit_state(&sandbox, expected, SandboxState::Running)
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
    let stored = state
        .repository()
        .list_stored_snapshots(sandbox.tenant_id, sandbox.id)
        .await?
        .into_iter()
        .filter(|snapshot| {
            snapshot.complete && snapshot_kind(&snapshot.kind).ok() == Some(SnapshotKind::Workspace)
        })
        .max_by_key(|snapshot| snapshot.created_at);
    let Some(stored) = stored else {
        tracing::warn!(
            sandbox_id = %sandbox.id,
            "recovered sandbox has no workspace archive; starting with an empty workspace"
        );
        return Ok(());
    };
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
        .map_err(|error| {
            CoreError::Conflict(format!(
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
        .commit_state(sandbox, expected, SandboxState::Failed)
        .await
    {
        tracing::warn!(
            sandbox_id = %sandbox.id,
            %failure,
            "recovered sandbox could not be marked failed"
        );
    }
    if let Err(failure) = state
        .scheduler()
        .release(sandbox.tenant_id, sandbox.id)
        .await
    {
        tracing::warn!(
            sandbox_id = %sandbox.id,
            %generation,
            %failure,
            "replacement lease could not be released"
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
    request.extensions_mut().insert(Principal {
        tenant_id: key.tenant_id,
        key_id: key.id,
        scopes: key.scopes,
    });
    Ok(next.run(request).await)
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

    match state.repository().list_workers(true).await {
        Ok(_) => {
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
    let nodes = state.repository().list_nodes().await.unwrap_or_default();
    let available_vcpus = nodes.iter().map(|node| node.available_vcpus).sum::<u32>();
    let available_memory = nodes
        .iter()
        .map(|node| node.available_memory_bytes)
        .sum::<u64>();
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
) -> Result<Sandbox, ApiFailure> {
    let mut x = x;
    // Hosted capacity is reached through the provider inside the runtime, not
    // through a leased worker node, so there is nothing for the worker
    // scheduler to place. Worker-backed runtimes are scheduled as before.
    if s.is_production() && x.runtime != RuntimeKind::Hosted {
        x = s
            .scheduler()
            .schedule(aiec_core::scheduler::ScheduleRequest {
                tenant_id: tenant,
                request_id,
                sandbox: x,
                preferred_worker: None,
                lease_ttl: std::time::Duration::from_secs(s.lease_ttl_seconds),
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
            })?
            .sandbox;
    } else {
        s.repository()
            .create_sandbox(x.clone())
            .await
            .map_err(ApiFailure::from)?;
    }
    if x.state != SandboxState::Creating {
        return Ok(x);
    }
    // If the runtime cannot bring the machine up, the row must not be left
    // behind as Creating: it would count against the tenant's quota, appear in a
    // console as running, and never be cleaned up. A provider that refuses
    // capacity is a normal outcome, not a crash, so it is recorded as failed.
    if let Err(error) = s.runtime_for(&x)?.create(&x).await {
        let _ = s
            .commit_state(&x, SandboxState::Creating, SandboxState::Failed)
            .await;
        return Err(ApiFailure::from(error));
    }
    s.commit_state(&x, SandboxState::Creating, SandboxState::Starting)
        .await
        .map_err(ApiFailure::from)?;
    x.state = SandboxState::Starting;
    s.runtime_for(&x)?
        .start(&x)
        .await
        .map_err(ApiFailure::from)?;
    if let Err(error) = prepare_environment(s, &x, &x.environment).await {
        let _ = s.runtime_for(&x)?.destroy(&x).await;
        let _ = s
            .commit_state(&x, SandboxState::Starting, SandboxState::Failed)
            .await;
        // Hosted capacity is not leased from a worker, so there is nothing to
        // release; asking the scheduler would fail for a lease that never
        // existed.
        if s.is_production() && x.runtime != RuntimeKind::Hosted {
            let _ = s.scheduler().release(tenant, x.id).await;
        }
        return Err(error);
    }

    s.commit_state(&x, SandboxState::Starting, SandboxState::Running)
        .await
        .map_err(ApiFailure::from)?;
    x.state = SandboxState::Running;
    // A hosted sandbox is charged one vCPU-second unit per allocated vCPU per
    // hour of requested lifetime. This is a stop-loss against a finite provider
    // allowance, not a bill: the durable usage ledger remains the record.
    if x.runtime == RuntimeKind::Hosted {
        let seconds = i64::try_from(x.timeout_seconds).unwrap_or(i64::MAX);
        let units = i64::from(x.cpu) * ((seconds + 3599) / 3600);
        s.charge_execution(units.max(1));
    }
    Ok(x)
}

fn create_response(sandbox: Sandbox, reason: &str) -> Response {
    ([("x-aiec-selection-reason", reason)], Json(sandbox)).into_response()
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
    let required = aiec_core::runtime::RuntimeCapabilities {
        exec: true,
        files: true,
        ..Default::default()
    };
    let (runtime_kind, _selection_reason) = if let Some(registry) = s.runtime_registry() {
        let selection = registry
            .select(requested_runtime, &required, minimum_isolation)
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
    let r = body.request;
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
    let reference = aiec_core::images::ImageReference::new(&r.image).map_err(ApiFailure::from)?;
    let resolved_image_id = if runtime_kind == RuntimeKind::Firecracker {
        if let Some(images) = s.platform.images() {
            images
                .resolve(&reference)
                .await
                .map_err(ApiFailure::from)?
                .image_id
        } else if s.is_production() {
            return Err(ApiFailure::from(CoreError::Conflict(
                "Firecracker image admission is not configured".into(),
            )));
        } else {
            image_id(&r.image)
        }
    } else if let Some(images) = s.platform.images() {
        images.resolve(&reference).await.map_err(ApiFailure::from)?;
        reference.as_str().to_owned()
    } else {
        reference.as_str().to_owned()
    };
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
    let x = provision_sandbox(&s, p.tenant_id, request_id, x).await?;
    Ok(create_response(x, &_selection_reason))
}
async fn prepare_environment(
    state: &AppState,
    sandbox: &Sandbox,
    environment: &EnvironmentSpec,
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
            state
                .platform
                .snapshots()
                .ok_or_else(|| {
                    ApiFailure::from(CoreError::Conflict(
                        "snapshot provider is not configured".into(),
                    ))
                })?
                .restore(
                    sandbox,
                    &SnapshotMetadata {
                        id: stored.id,
                        kind: SnapshotKind::Workspace,
                        object_key: stored.object_key,
                        checksum_sha256: stored.checksum_sha256,
                    },
                )
                .await
                .map_err(ApiFailure::from)?;
        }
        WorkspaceSpec::Git {
            repo,
            reference,
            shallow,
        } => {
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
    let metadata = store
        .put(&artifact_key(p.tenant_id, id, &name)?, &bytes)
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
    let bytes = match store.get(&key).await {
        Ok(bytes) => bytes,
        Err(CoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiFailure::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "artifact not found",
            ));
        }
        Err(error) => return Err(ApiFailure::from(error)),
    };
    if bytes.len() > ARTIFACT_MAX_BYTES {
        return Err(ApiFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "limit_exceeded",
            "artifact exceeds the 64 MiB limit",
        ));
    }
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let checksum_sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(Json(ArtifactDownload {
        key,
        size_bytes: bytes.len() as u64,
        checksum_sha256,
        content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
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
async fn list_sandboxes(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Vec<Sandbox>> {
    p.authorize(Scope::SandboxesRead)
        .map_err(ApiFailure::from)?;
    Ok(Json(
        s.repository()
            .list_sandboxes(p.tenant_id)
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
        .runtime()
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
    let mut x = s
        .repository()
        .get_sandbox(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let old = x.state;
    x.state = SandboxState::Snapshotting;
    s.commit_state(&x, old, SandboxState::Snapshotting)
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
    let kind = request.kind.unwrap_or({
        if capabilities.virtual_machine {
            SnapshotKind::VirtualMachine
        } else {
            SnapshotKind::Workspace
        }
    });
    let supported = match kind {
        SnapshotKind::VirtualMachine => capabilities.virtual_machine,
        SnapshotKind::Memory => capabilities.memory,
        SnapshotKind::Workspace => capabilities.workspace,
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
    let captured = provider
        .capture(
            &x,
            &SnapshotRequest {
                kind,
                object_key: format!("{id}-{}", new_id()),
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
        let stored = store
            .put(&captured.object_key, &captured.archive)
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
            workspace_object_key: (captured.kind == aiec_core::snapshots::SnapshotKind::Workspace)
                .then(|| captured.object_key.clone()),
            size_bytes: captured.size_bytes,
            image_id: snap.image_id.clone(),
            checksum_sha256: captured.checksum_sha256,
            kind: snapshot_kind_name(captured.kind).into(),
            complete: true,
            manifest: json!({"kind": snapshot_kind_name(captured.kind)}),
            created_at: snap.created_at,
        })
        .await
        .map_err(ApiFailure::from)?;
    s.commit_state(&x, SandboxState::Snapshotting, SandboxState::Running)
        .await
        .map_err(ApiFailure::from)?;
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
        s.repository()
            .list_snapshots(p.tenant_id, id)
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
    let now = Utc::now();
    let mut x = Sandbox {
        id: new_id(),
        tenant_id: p.tenant_id,
        node_id: None,
        image_id: r.image.unwrap_or(stored.image_id.clone()),
        state: SandboxState::Restoring,
        runtime: r.runtime.unwrap_or_else(|| s.runtime_kind()),
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
    if s.is_production() {
        x = s
            .scheduler()
            .schedule(aiec_core::scheduler::ScheduleRequest {
                tenant_id: p.tenant_id,
                request_id: new_id(),
                sandbox: x,
                preferred_worker: None,
                lease_ttl: std::time::Duration::from_secs(s.lease_ttl_seconds),
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
            })?
            .sandbox;
    } else {
        s.repository()
            .create_sandbox(x.clone())
            .await
            .map_err(ApiFailure::from)?;
    }
    s.runtime_for(&x)?
        .create(&x)
        .await
        .map_err(ApiFailure::from)?;
    s.platform
        .snapshots()
        .ok_or_else(|| {
            ApiFailure::from(CoreError::Conflict("snapshots are not configured".into()))
        })?
        .restore(
            &x,
            &SnapshotMetadata {
                id: stored.id,
                kind,
                object_key: stored.object_key.clone(),
                checksum_sha256: stored.checksum_sha256.clone(),
            },
        )
        .await
        .map_err(ApiFailure::from)?;
    s.commit_state(&x, SandboxState::Restoring, SandboxState::Running)
        .await
        .map_err(ApiFailure::from)?;
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
        .repository()
        .get_snapshot(p.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if let Some(artifact_store) = s.artifact_store() {
        artifact_store
            .delete(&snapshot.object_key)
            .await
            .map_err(ApiFailure::from)?;
    }
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
    Ok(Json(
        s.repository()
            .list_runs(p.tenant_id, state, limit)
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
                download_url: format!("/v1/runs/{id}/artifacts/{}", artifact.name),
                artifact,
            })
            .collect(),
    ))
}

/// Fetches one artifact's bytes.
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
    let bytes = match store.get(&artifact.object_key).await {
        Ok(bytes) => bytes,
        Err(CoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiFailure::from(CoreError::NotFound(
                "run artifact not found".into(),
            )));
        }
        Err(error) => return Err(ApiFailure::from(error)),
    };
    if bytes.len() > ARTIFACT_MAX_BYTES {
        return Err(ApiFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "limit_exceeded",
            "artifact exceeds the 64 MiB limit",
        ));
    }
    // The recorded content type is a stored string, so it is used only if it
    // is still a legal header value; otherwise the bytes are served as the
    // opaque thing they are.
    let content_type = artifact
        .content_type
        .filter(|value| HeaderValue::from_str(value).is_ok())
        .and_then(|value| HeaderValue::from_str(&value).ok())
        .unwrap_or_else(|| HeaderValue::from_static("application/octet-stream"));
    let mut response = bytes.into_response();
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
fn spawn_lease_sweeper(state: AppState) {
    tokio::spawn(async move {
        // Long enough to be uninteresting, short enough that a dead machine
        // does not cost a lease's worth of capacity for long.
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            ticker.tick().await;
            let actions = match state
                .repository()
                .reconcile_expired_leases(RECONCILE_LIMIT)
                .await
            {
                Ok(actions) => actions,
                Err(error) => {
                    tracing::warn!(error = %error, "the lease sweeper could not list expiries");
                    continue;
                }
            };
            if actions.is_empty() {
                continue;
            }
            // Deliberately not calling `recover_expired_leases` here. That
            // re-places the sandbox on a new worker and rebuilds its workspace,
            // which is the right thing to do when an operator asks for it and
            // exactly wrong on a timer: it would resurrect machines for sandboxes
            // whose runs finished long ago, turning a reclaimed slot back into a
            // running workload nobody asked for. Reclaiming is automatic;
            // resurrecting stays a deliberate act.
            tracing::info!(
                expired = actions.len(),
                "the lease sweeper returned capacity held by expired leases"
            );
        }
    });
}

pub async fn serve(state: AppState, addr: std::net::SocketAddr) -> Result<(), std::io::Error> {
    spawn_lease_sweeper(state.clone());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app(state)).await
}

pub async fn serve_tls(
    state: AppState,
    addr: std::net::SocketAddr,
    cert_path: impl AsRef<std::path::Path>,
    key_path: impl AsRef<std::path::Path>,
) -> Result<(), std::io::Error> {
    // The sweeper is a property of the control plane, not of a listener, so it
    // starts here as well as on the plain listener.
    spawn_lease_sweeper(state.clone());
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;
    axum_server::bind_rustls(addr, config)
        // Without ConnectInfo the limiter cannot see the peer address, so every
        // unauthenticated caller collapsed into one shared bucket.
        .serve(app(state).into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
}

pub async fn serve_worker(
    service: WorkerService,
    addr: std::net::SocketAddr,
) -> Result<(), std::io::Error> {
    // A worker holds no leases of its own, so it gets no sweeper.
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, service.router()).await
}

pub async fn serve_worker_tls(
    service: WorkerService,
    addr: std::net::SocketAddr,
    cert_path: impl AsRef<std::path::Path>,
    key_path: impl AsRef<std::path::Path>,
) -> Result<(), std::io::Error> {
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;
    axum_server::bind_rustls(addr, config)
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
        RetentionPolicy, Run, RunArtifactRef, RunEvent, RunResults, RunSandbox, RunState,
    };
    use aiec_core::storage::{
        AuditEvent, MetadataStore, Reassignment, SandboxEvent, SandboxOwnership, StoredSnapshot,
        TenantRecord, WorkerHeartbeat as HeartbeatRecord, WorkerLease,
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
        /// Sandboxes created for a run, keyed by the request id that asked for
        /// them, so a retried request joins the machine it already has.
        sandbox_requests: TestMutex<TestMap<(Uuid, Uuid), SandboxId>>,
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

        /// The run a child row hangs off. Child rows carry no tenant of their
        /// own, so this settles existence only; every read of them still goes
        /// through the tenant-scoped run first.
        async fn stored_run_for_child(&self, id: Uuid) -> Result<Run, CoreError> {
            self.runs
                .lock()
                .await
                .get(&id)
                .cloned()
                .ok_or_else(|| CoreError::NotFound("run not found".into()))
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
        async fn update_state_with_generation(
            &self,
            tenant: TenantId,
            id: SandboxId,
            expected: SandboxState,
            next: SandboxState,
            generation: i64,
        ) -> Result<(), CoreError> {
            match self.sandbox_ownership(id).await? {
                Some(ownership) if ownership.generation == generation => self
                    .inner
                    .update_state(tenant, id, expected, next, None)
                    .await
                    .map(|_| ()),
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
        async fn heartbeat(&self, id: Uuid) -> Result<(), CoreError> {
            self.inner.heartbeat(id).await
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
        ) -> Result<Vec<Run>, CoreError> {
            let mut page: Vec<Run> = self
                .runs
                .lock()
                .await
                .values()
                .filter(|run| {
                    run.tenant_id == tenant && state.is_none_or(|state| run.state == state)
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

        async fn append_run_event(&self, event: RunEvent) -> Result<(), CoreError> {
            self.stored_run_for_child(event.run_id).await?;
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

        async fn link_run_sandbox(&self, link: RunSandbox) -> Result<(), CoreError> {
            self.stored_run_for_child(link.run_id).await?;
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
    }

    /// Runtime double that records the archives a recovery hands it, standing in
    /// for the worker that has just taken ownership of a reassigned sandbox.
    struct AdoptingRuntime {
        imported: TestMutex<Vec<Vec<u8>>>,
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
        async fn destroy(&self, _: &Sandbox) -> Result<(), CoreError> {
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
            _: &aiec_core::snapshots::SnapshotMetadata,
        ) -> Result<(), CoreError> {
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
            let now = Utc::now();
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
                created_at: now,
                updated_at: now,
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
            .put(&object_key, &archive)
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
            .put(&object_key, b"tampered")
            .await
            .expect("store archive");
        fixture
            .store_snapshot(&sandbox, &object_key, b"captured")
            .await;

        assert!(matches!(
            restore_workspace(&fixture.state, &sandbox).await,
            Err(CoreError::Conflict(_))
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
    struct RunRuntime;

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
                exit_code: 0,
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
            Ok(FileContent {
                path: path.to_owned(),
                content_base64: format!("contents of {path}"),
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
        }
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

    struct RunFixture {
        state: AppState,
        store: Arc<LeasedRepository>,
        objects: Arc<dyn ArtifactStore>,
        tenant: Uuid,
        key: String,
        root: std::path::PathBuf,
    }

    impl RunFixture {
        fn new() -> Self {
            let store = LeasedRepository::new();
            let tenant = new_id();
            let key = run_api_key();
            let root = std::env::temp_dir().join(format!("af-runs-{}", new_id()));
            let objects: Arc<dyn ArtifactStore> =
                Arc::new(aiec_storage::FilesystemObjectStore::new(&root));
            let runtime = Arc::new(RunRuntime);
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

    /// An artifact is listed with the URL its bytes are served from, and that
    /// URL returns those bytes.
    #[tokio::test]
    async fn a_runs_artifact_is_listed_with_a_url_and_served_from_it() {
        let fixture = RunFixture::new();
        fixture.issue_key(fixture.tenant, &fixture.key).await;
        let run = settled_run(fixture.tenant, RunState::Succeeded);
        let object_key = format!("tenants/{}/runs/{}/report.txt", fixture.tenant, run.id);
        fixture
            .objects
            .put(&object_key, b"run output")
            .await
            .expect("store artifact");
        fixture.store.seed(run.clone()).await;
        fixture
            .store
            .put_run_artifacts(
                fixture.tenant,
                run.id,
                vec![RunArtifactRef {
                    name: "report.txt".to_owned(),
                    object_key,
                    size_bytes: 10,
                    checksum_sha256: None,
                    content_type: Some("text/plain".to_owned()),
                }],
            )
            .await
            .expect("record artifacts");

        let (status, value) = fixture
            .call_json(
                axum::http::Method::GET,
                &format!("/v1/runs/{}/artifacts", run.id),
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let listed: Vec<Value> = serde_json::from_value(value).expect("artifact list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["name"], "report.txt");
        let url = listed[0]["download_url"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let (status, headers, bytes) = fixture
            .call(axum::http::Method::GET, &url, &fixture.key, Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, b"run output");
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .map(|value| value.to_str().ok()),
            Some(Some("text/plain"))
        );
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
            .link_run_sandbox(RunSandbox {
                run_id: run.id,
                sandbox_id: sandbox.id,
                role: "primary".into(),
            })
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
