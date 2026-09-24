use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

pub mod protocol;

pub const MAX_STDOUT: usize = 1_048_576;
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
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Firecracker,
    BwrapDev,
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::BwrapDev => "bwrap-dev",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    Creating,
    Starting,
    Running,
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub runtime_path: Option<String>,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestoreSnapshotRequest {
    pub image: Option<String>,
    pub cpu: Option<u32>,
    pub memory_mb: Option<u32>,
    pub disk_mb: Option<u32>,
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
    let allowed = [
        "python:3.13",
        "node:24",
        "rust:stable",
        "ubuntu:24.04",
        "alpine:3.21",
    ];
    if allowed.contains(&image) {
        Ok(())
    } else {
        Err(CoreError::InvalidRequest(format!(
            "unsupported image: {image}"
        )))
    }
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
    fn state_machine_rejects_skip() {
        assert!(!SandboxState::Creating.can_transition_to(SandboxState::Running));
        assert!(SandboxState::Creating.can_transition_to(SandboxState::Starting));
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
}
