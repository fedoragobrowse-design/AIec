//! Runtime boundary and capability discovery.
//!
//! Runtime implementations translate generic sandbox operations to a backend
//! such as a local jail or a virtual machine. Backend-specific configuration
//! never appears in these contracts.

use crate::{
    DeleteFileRequest, ExecRequest, ExecResult, FileEntry, FileContent, MakeDirectoryRequest,
    PutFileRequest, Sandbox,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use crate::{SandboxId, TenantId};

/// Capabilities advertised by a sandbox runtime implementation.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeCapabilities {
    /// Whether the runtime can snapshot and restore a stopped VM.
    pub vm_snapshot: bool,
    /// Whether execution can resume with memory state intact.
    pub memory_resume: bool,
    /// Whether the runtime enforces a caller-provided network policy.
    pub network_policy: bool,
    /// Whether hardware accelerators can be assigned to a sandbox.
    pub gpu: bool,
    /// Whether the runtime can pause a running sandbox.
    pub pause: bool,
    /// Whether filesystem-only workspace snapshots are available.
    pub workspace_snapshot: bool,
    /// Whether guest communication uses a VSock-like transport.
    pub vsock: bool,
}

/// Current operational health of a runtime.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeHealth {
    /// Whether the runtime is ready to accept work.
    pub healthy: bool,
    /// Human-readable detail, especially when unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl RuntimeHealth {
    /// Creates a healthy status with no diagnostic message.
    pub fn healthy() -> Self {
        Self { healthy: true, message: None }
    }

    /// Creates an unhealthy status with a diagnostic message.
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self { healthy: false, message: Some(message.into()) }
    }
}

/// Backend-neutral lifecycle and workload operations for sandboxes.
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    /// Allocates backend resources for a sandbox.
    async fn create(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Starts a previously created sandbox.
    async fn start(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Gracefully stops a running sandbox.
    async fn stop(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Executes a command inside a sandbox.
    async fn exec(
        &self,
        sandbox: &Sandbox,
        request: ExecRequest,
    ) -> Result<ExecResult, crate::CoreError>;
    /// Writes a file into a sandbox.
    async fn put_file(
        &self,
        sandbox: &Sandbox,
        request: PutFileRequest,
    ) -> Result<(), crate::CoreError>;
    /// Reads a file from a sandbox.
    async fn get_file(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<FileContent, crate::CoreError>;
    /// Lists a directory in a sandbox.
    async fn list_files(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<Vec<FileEntry>, crate::CoreError>;
    /// Removes a file from a sandbox.
    async fn delete_file(
        &self,
        sandbox: &Sandbox,
        request: DeleteFileRequest,
    ) -> Result<(), crate::CoreError>;
    /// Creates a directory in a sandbox.
    async fn make_directory(
        &self,
        sandbox: &Sandbox,
        request: MakeDirectoryRequest,
    ) -> Result<(), crate::CoreError>;
    /// Releases all resources owned by a sandbox.
    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Reports current runtime health.
    async fn health(&self) -> RuntimeHealth;
    /// Reports immutable backend capabilities.
    fn capabilities(&self) -> RuntimeCapabilities;
}
