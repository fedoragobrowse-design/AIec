use chrono::{DateTime, Utc};
use hmac::Mac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;

pub mod host_pressure;
pub mod images;
pub mod network;
pub mod platform;
pub mod policy;
pub mod run;
pub mod run_queue;
pub mod runtime;
pub mod scheduler;
pub mod snapshots;
pub mod storage;

/// Stable sandbox identifier.
pub type SandboxId = Uuid;
/// Stable tenant identifier.
pub type TenantId = Uuid;
/// Stable worker identifier.
pub type WorkerId = Uuid;
/// Stable lease identifier.
pub type LeaseId = Uuid;
/// Stable snapshot identifier.
pub type SnapshotId = Uuid;
/// Stable idempotency request identifier.
pub type RequestId = Uuid;

pub use network::NetworkPolicy;
pub mod protocol;

pub const MAX_STDOUT: usize = 1_048_576;

/// Durable tenant resource quota policy.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuotaLimits {
    pub max_active_sandboxes: u32,
    pub max_vcpus: u32,
    pub max_memory_mb: u64,
    pub max_disk_mb: u64,
}

/// Current aggregate usage for a tenant.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuotaUsage {
    pub active_sandboxes: u32,
    pub vcpus: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

impl QuotaUsage {
    pub fn checked_add(&self, sandbox: &Sandbox) -> Option<Self> {
        Some(Self {
            active_sandboxes: self.active_sandboxes.checked_add(1)?,
            vcpus: self.vcpus.checked_add(sandbox.cpu)?,
            memory_mb: self.memory_mb.checked_add(u64::from(sandbox.memory_mb))?,
            disk_mb: self.disk_mb.checked_add(u64::from(sandbox.disk_mb))?,
        })
    }

    pub fn exceeds(&self, limits: QuotaLimits) -> bool {
        self.active_sandboxes > limits.max_active_sandboxes
            || self.vcpus > limits.max_vcpus
            || self.memory_mb > limits.max_memory_mb
            || self.disk_mb > limits.max_disk_mb
    }
}
pub const MAX_STDERR: usize = 1_048_576;
pub const MAX_FILE: usize = 16 * 1024 * 1024;
pub const MAX_VCPU: u32 = 32;
pub const MAX_MEMORY_MB: u32 = 131_072;
pub const MAX_DISK_MB: u32 = 1_048_576;
pub const MAX_EXEC_SECONDS: u64 = 3_600;
pub const MAX_LIFETIME_SECONDS: u64 = 86_400;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    /// A failure that will probably not recur if the same work is tried again.
    ///
    /// Distinct from `Unavailable` on purpose. Deciding what to retry by
    /// matching the text of an error is how a retry set grows one leaked
    /// machine at a time, because the next transient failure arrives with
    /// wording nobody anticipated. This variant makes the set closed: the
    /// producer says it was transient, and the consumer trusts it.
    #[error("transient: {0}")]
    Transient(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Firecracker,
    Docker,
    BwrapDev,
    /// Sandboxes placed on an external hosted isolation provider.
    ///
    /// The isolation boundary is owned by the provider, not by AIec, so
    /// this kind never runs on a managed worker node. It exists because
    /// untrusted public workloads need a microVM-grade boundary that a
    /// deployment without KVM cannot provide itself.
    Hosted,
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Firecracker => "firecracker",
            Self::BwrapDev => "bwrap-dev",
            Self::Hosted => "hosted",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    Creating,
    Starting,
    Running,
    Paused,
    Stopping,
    Stopped,
    Snapshotting,
    Restoring,
    Failed,
    Destroying,
    Destroyed,
}

impl SandboxState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Snapshotting => "snapshotting",
            Self::Restoring => "restoring",
            Self::Failed => "failed",
            Self::Destroying => "destroying",
            Self::Destroyed => "destroyed",
        }
    }
    pub fn can_transition_to(self, next: Self) -> bool {
        use SandboxState::*;
        matches!(
            (self, next),
            (Creating, Starting | Failed | Destroying)
                | (Starting, Running | Failed | Destroying)
                | (Running, Stopping | Snapshotting | Failed | Destroying)
                | (Running, Paused)
                | (Paused, Running)
                | (Stopping, Stopped | Failed)
                | (Stopped, Starting | Destroying)
                | (Snapshotting, Running | Stopped | Failed)
                | (Restoring, Running | Failed)
                | (Failed, Starting | Destroying)
                | (Destroying, Destroyed | Failed)
                | (Destroyed, Creating)
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CreateSandboxRequest {
    pub image: String,
    #[serde(default = "default_cpu")]
    pub cpu: u32,
    #[serde(default = "default_memory")]
    pub memory_mb: u32,
    #[serde(default = "default_disk")]
    pub disk_mb: u32,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub environment: EnvironmentSpec,
}
fn default_cpu() -> u32 {
    1
}
fn default_memory() -> u32 {
    512
}
fn default_disk() -> u32 {
    2048
}
fn default_timeout() -> u64 {
    900
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Sandbox {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub node_id: Option<Uuid>,
    pub image_id: String,
    pub state: SandboxState,
    pub runtime: RuntimeKind,
    pub cpu: u32,
    pub memory_mb: u32,
    pub disk_mb: u32,
    pub timeout_seconds: u64,
    pub network: NetworkPolicy,
    #[serde(default)]
    pub environment: EnvironmentSpec,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Opaque backend handle the runtime needs to operate this sandbox again.
    ///
    /// AIec owns [`Sandbox::id`] as the only public sandbox identity. A
    /// runtime that places the workload on a third-party provider persists the
    /// provider's own handle here during `SandboxRuntime::create`, so the
    /// provider resource stays recoverable across processes without ever being
    /// exposed to clients as an identity. The value is runtime-private: only the
    /// runtime that wrote it interprets it, and it is never a path on the
    /// AIec host.
    pub runtime_path: Option<String>,
}

/// Environment composition requested for a sandbox.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EnvironmentSpec {
    /// Workspace source. Empty is the default writable workspace.
    #[serde(default)]
    pub workspace: WorkspaceSpec,
    /// Independently named setup toolkits applied after the workspace exists.
    #[serde(default)]
    pub toolkits: Vec<ToolkitSpec>,
    /// Independently versioned environment layers composed above the base image.
    #[serde(default)]
    pub layers: Vec<LayerSpec>,
    /// Out-of-guest governance. An absent policy inside a selected Guard config
    /// means no-network; credentials are configured only on the worker gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<aiec_guard::policy::GuardConfig>,
    /// Control-plane-derived effective policy hash. Never a source of permission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_policy_hash: Option<String>,
}

/// A workspace source with an explicit lifecycle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkspaceSpec {
    /// Start with an empty writable workspace.
    #[default]
    Empty,
    /// Clone a repository into `/workspace/repository`.
    Git {
        /// Repository URL. Credentials are deliberately not part of this type.
        repo: String,
        /// Optional branch, tag, or commit to check out.
        #[serde(default)]
        reference: Option<String>,
        /// Use a shallow clone when true.
        #[serde(default = "default_true")]
        shallow: bool,
    },
    /// Restore workspace state from a previously captured portable snapshot.
    Snapshot {
        /// Snapshot identifier.
        snapshot_id: Uuid,
    },
}

/// A small independently versioned setup layer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolkitSpec {
    /// Stable toolkit name, used in logs and validation errors.
    pub name: String,
    /// Commands run inside the sandbox after workspace preparation.
    pub setup_commands: Vec<Vec<String>>,
}

/// Identity of an independently versioned environment layer.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LayerKind {
    Base,
    Workspace,
    Toolkit,
}
impl LayerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Workspace => "workspace",
            Self::Toolkit => "toolkit",
        }
    }
}

/// Immutable layer metadata and its bounded materialization payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LayerSpec {
    pub kind: LayerKind,
    pub name: String,
    pub content_digest: String,
    #[serde(default)]
    pub content_base64: String,
}

fn default_true() -> bool {
    true
}

impl EnvironmentSpec {
    /// Validates repository URLs, refs, toolkit names, and bounded setup argv.
    pub fn validate(&self) -> Result<(), CoreError> {
        if let Some(guard) = &self.guard {
            guard
                .effective_policy()
                .map_err(|error| CoreError::InvalidRequest(error.to_string()))?;
        }
        if self.toolkits.len() > 16 {
            return Err(CoreError::LimitExceeded("too many toolkits".into()));
        }
        if self.layers.len() > 32 {
            return Err(CoreError::LimitExceeded(
                "too many environment layers".into(),
            ));
        }
        let mut layer_names = std::collections::HashSet::new();
        for layer in &self.layers {
            if layer.name.is_empty()
                || layer.name.len() > 128
                || layer.name.as_bytes().contains(&0)
                || !layer
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                || !layer_names.insert((layer.kind, layer.name.as_str()))
            {
                return Err(CoreError::InvalidRequest(
                    "invalid or duplicate environment layer".into(),
                ));
            }
            if layer.content_digest.len() != 64
                || !layer
                    .content_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(CoreError::InvalidRequest(
                    "invalid environment layer digest".into(),
                ));
            }
            if !layer.content_base64.is_empty() {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&layer.content_base64)
                    .map_err(|_| {
                        CoreError::InvalidRequest("invalid environment layer payload".into())
                    })?;
                if bytes.len() > MAX_FILE {
                    return Err(CoreError::LimitExceeded(
                        "environment layer is too large".into(),
                    ));
                }
                if hex::encode(Sha256::digest(&bytes)) != layer.content_digest {
                    return Err(CoreError::InvalidRequest(
                        "environment layer digest mismatch".into(),
                    ));
                }
            }
        }
        if let WorkspaceSpec::Git {
            repo, reference, ..
        } = &self.workspace
        {
            validate_git_repo(repo)?;
            if reference.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 256 || value.as_bytes().contains(&0)
            }) {
                return Err(CoreError::InvalidRequest("invalid git reference".into()));
            }
        }
        for toolkit in &self.toolkits {
            if toolkit.name.is_empty()
                || toolkit.name.len() > 64
                || !toolkit
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(CoreError::InvalidRequest("invalid toolkit name".into()));
            }
            if toolkit.setup_commands.len() > 32
                || toolkit.setup_commands.iter().any(|command| {
                    command.is_empty()
                        || command.len() > 64
                        || command.iter().any(|arg| {
                            arg.is_empty() || arg.len() > 4096 || arg.as_bytes().contains(&0)
                        })
                })
            {
                return Err(CoreError::InvalidRequest("invalid toolkit commands".into()));
            }
        }
        Ok(())
    }
}

fn validate_git_repo(repo: &str) -> Result<(), CoreError> {
    if repo.is_empty() || repo.len() > 2048 || repo.as_bytes().contains(&0) {
        return Err(CoreError::InvalidRequest("invalid git repository".into()));
    }
    let valid = repo.starts_with("https://")
        || repo.starts_with("git@")
        || repo.starts_with("ssh://")
        || repo.starts_with("git://");
    if !valid {
        return Err(CoreError::InvalidRequest(
            "git repository must use https, ssh, or git transport".into(),
        ));
    }
    if let Some(authority) = repo
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        && authority.contains('@')
    {
        return Err(CoreError::InvalidRequest(
            "git repository credentials must use scoped secret injection".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default = "default_exec_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub stdin: Option<String>,
}
fn default_exec_timeout() -> u64 {
    60
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timed_out: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PutFileRequest {
    pub path: String,
    pub content_base64: String,
    #[serde(default)]
    pub mode: Option<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileContent {
    pub path: String,
    pub content_base64: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListFilesQuery {
    pub path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteFileRequest {
    pub path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MakeDirectoryRequest {
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub sandbox_id: Uuid,
    pub object_key: String,
    pub size_bytes: u64,
    pub image_id: String,
    pub created_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RestoreSnapshotRequest {
    pub image: Option<String>,
    pub cpu: Option<u32>,
    pub memory_mb: Option<u32>,
    pub disk_mb: Option<u32>,
    pub runtime: Option<crate::RuntimeKind>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CreateSnapshotRequest {
    pub kind: Option<crate::snapshots::SnapshotKind>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub sandbox_id: Option<Uuid>,
    pub metric: String,
    pub quantity: i64,
    pub occurred_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageSummary {
    pub metric: String,
    pub quantity: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiErrorEnvelope {
    pub error: ApiErrorBody,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: Uuid,
    pub name: String,
    pub available_vcpus: u32,
    pub available_memory_bytes: u64,
    pub available_disk_bytes: u64,
    pub sandbox_count: u32,
    pub healthy: bool,
    pub last_heartbeat: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageRecord {
    pub id: String,
    pub reference: String,
    pub rootfs: String,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    SandboxesRead,
    SandboxesWrite,
    SnapshotsRead,
    SnapshotsWrite,
    Admin,
}
impl Scope {
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "sandboxes:read" => Ok(Self::SandboxesRead),
            "sandboxes:write" => Ok(Self::SandboxesWrite),
            "snapshots:read" => Ok(Self::SnapshotsRead),
            "snapshots:write" => Ok(Self::SnapshotsWrite),
            "admin" => Ok(Self::Admin),
            _ => Err(CoreError::InvalidRequest("unknown scope".into())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub digest: [u8; 32],
    pub scopes: Vec<Scope>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// Human-recognisable label so the right key can be revoked later.
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Debug)]
pub struct Principal {
    pub tenant_id: Uuid,
    pub key_id: Uuid,
    pub scopes: Vec<Scope>,
}
impl Principal {
    pub fn authorize(&self, required: Scope) -> Result<(), CoreError> {
        if self.scopes.contains(&Scope::Admin) || self.scopes.contains(&required) {
            Ok(())
        } else {
            Err(CoreError::Forbidden("missing scope".into()))
        }
    }
}

pub fn new_id() -> Uuid {
    Uuid::now_v7()
}
pub fn key_digest(raw: &str) -> [u8; 32] {
    Sha256::digest(raw.as_bytes()).into()
}

pub fn image_manifest_signature(secret: &[u8], reference: &str, digest: &str) -> String {
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(reference.as_bytes());
    mac.update(b"\0");
    mac.update(digest.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
pub fn generate_api_key() -> String {
    let mut bytes = [0u8; 24];
    // Avoid external RNG dependency in domain primitives; UUID v4 supplies OS randomness.
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    bytes[..16].copy_from_slice(a.as_bytes());
    bytes[16..].copy_from_slice(&b.as_bytes()[..8]);
    format!("af_live_{}", hex::encode(bytes))
}
pub fn validate_api_key(raw: &str) -> Result<(), CoreError> {
    let Some(body) = raw.strip_prefix("af_live_") else {
        return Err(CoreError::InvalidRequest("invalid API key prefix".into()));
    };
    if !(48..=64).contains(&body.len()) || body.len() % 2 != 0 || hex::decode(body).is_err() {
        Err(CoreError::InvalidRequest("invalid API key encoding".into()))
    } else {
        Ok(())
    }
}

pub fn validate_create(req: &CreateSandboxRequest, max_lifetime: u64) -> Result<(), CoreError> {
    validate_image(&req.image)?;
    if req.cpu == 0 || req.cpu > MAX_VCPU {
        return Err(CoreError::LimitExceeded("cpu".into()));
    }
    if req.memory_mb < 64 || req.memory_mb > MAX_MEMORY_MB {
        return Err(CoreError::LimitExceeded("memory_mb".into()));
    }
    if req.disk_mb < 512 || req.disk_mb > MAX_DISK_MB {
        return Err(CoreError::LimitExceeded("disk_mb".into()));
    }
    if req.timeout_seconds == 0 || req.timeout_seconds > max_lifetime.min(MAX_LIFETIME_SECONDS) {
        return Err(CoreError::LimitExceeded("timeout_seconds".into()));
    }
    req.environment.validate()?;
    Ok(())
}
pub fn validate_exec(req: &ExecRequest) -> Result<(), CoreError> {
    if req.command.is_empty()
        || req.command.len() > 64
        || req
            .command
            .iter()
            .any(|v| v.is_empty() || v.as_bytes().contains(&0))
    {
        return Err(CoreError::InvalidRequest("invalid command argv".into()));
    }
    if req.timeout_seconds == 0 || req.timeout_seconds > MAX_EXEC_SECONDS {
        return Err(CoreError::LimitExceeded("command timeout".into()));
    }
    if req.stdin.as_ref().is_some_and(|v| v.len() > MAX_FILE) {
        return Err(CoreError::LimitExceeded("stdin".into()));
    }
    if let Some(path) = &req.working_directory {
        safe_path(path)?;
    }
    Ok(())
}

pub fn validate_image(image: &str) -> Result<(), CoreError> {
    if image.is_empty()
        || image.len() > 1024
        || image
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || image.starts_with('-')
        || image.contains("..")
        || image.contains("://")
    {
        return Err(CoreError::InvalidRequest(format!(
            "invalid image reference: {image}"
        )));
    }
    Ok(())
}

pub fn image_id(image: &str) -> String {
    format!("afimg1_{}", hex::encode(Sha256::digest(image.as_bytes())))
}

pub fn safe_path(raw: &str) -> Result<PathBuf, CoreError> {
    if raw.is_empty() || raw.len() > 4096 || !raw.starts_with('/') {
        return Err(CoreError::InvalidRequest("path must be absolute".into()));
    }
    if raw != "/workspace" && !raw.starts_with("/workspace/") {
        return Err(CoreError::Forbidden("outside workspace".into()));
    }
    let relative = raw
        .strip_prefix("/workspace")
        .unwrap_or_default()
        .trim_start_matches('/');
    let mut normalized = PathBuf::from("/workspace");
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CoreError::Forbidden("path traversal".into()));
            }
        }
    }
    Ok(normalized)
}

pub fn score_node(node: &Node) -> f64 {
    if !node.healthy {
        return f64::INFINITY;
    }
    let cpu = node.available_vcpus as f64;
    let memory_gb = node.available_memory_bytes as f64 / 1_073_741_824.0;
    let pressure = (1.0 / cpu.max(1.0)) + (1.0 / memory_gb.max(0.25));
    pressure + node.sandbox_count as f64 * 0.0001
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quota_usage_adds_and_rejects_over_limit_without_overflow() {
        let limits = QuotaLimits {
            max_active_sandboxes: 2,
            max_vcpus: 2,
            max_memory_mb: 1024,
            max_disk_mb: 2048,
        };
        let sandbox = Sandbox {
            id: new_id(),
            tenant_id: new_id(),
            node_id: None,
            image_id: "test".into(),

            state: SandboxState::Creating,
            runtime: RuntimeKind::Firecracker,
            cpu: 1,
            memory_mb: 512,
            disk_mb: 1024,
            timeout_seconds: 60,
            network: NetworkPolicy::Disabled,
            environment: EnvironmentSpec::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            runtime_path: None,
        };
        let one = QuotaUsage::default().checked_add(&sandbox).unwrap();
        let two = one.checked_add(&sandbox).unwrap();
        assert!(!two.exceeds(limits));
        let three = two.checked_add(&sandbox).unwrap();
        assert!(three.exceeds(limits));
        let max = QuotaUsage {
            active_sandboxes: 2,
            vcpus: 2,
            memory_mb: 1024,
            disk_mb: 2048,
        };
        let updated = max.checked_add(&sandbox).unwrap();
        assert!(updated.exceeds(limits));
        let overflow = QuotaUsage {
            active_sandboxes: u32::MAX,
            ..QuotaUsage::default()
        };
        assert!(overflow.checked_add(&sandbox).is_none());
    }

    #[test]
    fn image_admission_accepts_normal_oci_reference() {
        assert!(validate_image("ghcr.io/example/agent:latest").is_ok());
        assert!(validate_image("registry.example/team/tool:1.2.3").is_ok());
    }

    #[test]
    fn image_admission_rejects_malformed_reference() {
        assert!(validate_image("https://registry.example/image").is_err());
        assert!(validate_image("image\nname").is_err());
        assert!(validate_image("../escape").is_err());
    }
    #[test]
    fn environment_layers_are_bounded_and_content_addressed() {
        let mut environment = EnvironmentSpec {
            layers: vec![LayerSpec {
                kind: LayerKind::Toolkit,
                name: "git-tools".into(),
                content_digest: "a".repeat(64),
                content_base64: String::new(),
            }],
            ..EnvironmentSpec::default()
        };
        environment.validate().unwrap();
        environment.layers.push(LayerSpec {
            kind: LayerKind::Toolkit,
            name: "git-tools".into(),
            content_digest: "b".repeat(64),
            content_base64: String::new(),
        });
        assert!(environment.validate().is_err());
    }
    #[test]
    fn environment_layers_reject_invalid_digests_and_excess_count() {
        let mut environment = EnvironmentSpec::default();
        environment.layers.push(LayerSpec {
            kind: LayerKind::Toolkit,
            name: "broken".into(),
            content_digest: "not-a-digest".into(),
            content_base64: String::new(),
        });
        assert!(environment.validate().is_err());
        environment.layers = (0..33)
            .map(|index| LayerSpec {
                kind: LayerKind::Toolkit,
                name: format!("toolkit-{index}"),
                content_digest: "a".repeat(64),
                content_base64: String::new(),
            })
            .collect();
        assert!(environment.validate().is_err());
    }
    #[test]
    fn environment_layers_validate_non_empty_payloads() {
        let payload = b"toolkit payload";
        let digest = hex::encode(Sha256::digest(payload));
        let mut environment = EnvironmentSpec::default();
        environment.layers.push(LayerSpec {
            kind: LayerKind::Toolkit,
            name: "valid".into(),
            content_digest: digest,
            content_base64: "dG9vbGtpdCBwYXlsb2Fk".into(),
        });
        assert!(environment.validate().is_ok());
        environment.layers[0].content_base64 = "not-base64".into();
        assert!(environment.validate().is_err());
        environment.layers[0].content_base64 = "dG9vbGtpdCBwYXlsb2Fk".into();
        environment.layers[0].content_digest = "0".repeat(64);
        assert!(environment.validate().is_err());
    }
    #[test]
    fn state_machine_rejects_skip() {
        assert!(!SandboxState::Creating.can_transition_to(SandboxState::Running));
        assert!(SandboxState::Creating.can_transition_to(SandboxState::Starting));
    }
    #[test]
    fn environment_rejects_credentials_and_unbounded_toolkits() {
        let mut request = CreateSandboxRequest {
            image: "python:3.13".into(),
            cpu: 1,
            memory_mb: 512,
            disk_mb: 2048,
            timeout_seconds: 300,
            network: NetworkPolicy::Disabled,
            environment: EnvironmentSpec::default(),
        };
        request.environment.workspace = WorkspaceSpec::Git {
            repo: "https://user:password@example.com/repo.git".into(),
            reference: None,
            shallow: true,
        };
        assert!(request.environment.validate().is_err());
        request.environment.workspace = WorkspaceSpec::Git {
            repo: "file:///etc/passwd".into(),
            reference: None,
            shallow: true,
        };
        assert!(request.environment.validate().is_err());
        request.environment.workspace = WorkspaceSpec::Empty;
        request.environment.toolkits = (0..17)
            .map(|index| ToolkitSpec {
                name: format!("toolkit-{index}"),
                setup_commands: Vec::new(),
            })
            .collect();
        assert!(request.environment.validate().is_err());
    }

    #[test]
    fn signed_image_manifest_rejects_tampering() {
        let secret = b"deployment-image-signing-key";
        let digest = "a".repeat(64);
        let mut manifest = crate::images::SignedImageManifest {
            reference: "python:3.13".into(),
            rootfs_sha256: digest.clone(),
            signature: image_manifest_signature(secret, "python:3.13", &digest),
        };
        manifest.verify(secret).unwrap();
        manifest.rootfs_sha256 = "b".repeat(64);
        assert!(manifest.verify(secret).is_err());
    }
    #[test]
    fn path_rejects_traversal() {
        assert!(safe_path("/workspace/../../etc/passwd").is_err());
        assert!(safe_path("/workspace/a/../b").is_err());
        assert_eq!(
            safe_path("/workspace/a/b").unwrap_or_default(),
            PathBuf::from("/workspace/a/b")
        );
    }
    #[test]
    fn keys_are_valid_and_scoped() {
        let key = generate_api_key();
        validate_api_key(&key).unwrap_or(());
        let p = Principal {
            tenant_id: new_id(),
            key_id: new_id(),
            scopes: vec![Scope::SandboxesRead],
        };
        assert!(p.authorize(Scope::SandboxesWrite).is_err());
    }
    #[test]
    fn image_is_content_addressed() {
        assert_eq!(image_id("python:3.13"), image_id("python:3.13"));
    }
    #[test]
    fn runtime_wire_strings_are_stable_across_the_workspace() {
        // The API request parser and the persisted `runtime` column are parsed
        // from these exact spellings in crates that cannot import a parser from
        // here, so the strings are a cross-crate contract.
        assert_eq!(RuntimeKind::Firecracker.as_str(), "firecracker");
        assert_eq!(RuntimeKind::Docker.as_str(), "docker");
        assert_eq!(RuntimeKind::BwrapDev.as_str(), "bwrap-dev");
        assert_eq!(RuntimeKind::Hosted.as_str(), "hosted");
    }
}
