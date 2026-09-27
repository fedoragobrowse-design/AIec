//! Runtime boundary and capability discovery.
//!
//! Runtime implementations translate generic sandbox operations to a backend
//! such as a local jail or a virtual machine. Backend-specific configuration
//! never appears in these contracts.

use crate::{
    DeleteFileRequest, ExecRequest, ExecResult, FileContent, FileEntry, MakeDirectoryRequest,
    PutFileRequest, Sandbox,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::RuntimeKind;
pub use crate::{SandboxId, TenantId};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeIsolation {
    #[default]
    Process,
    Container,
    MicroVm,
    FullVm,
}

impl RuntimeIsolation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Container => "container",
            Self::MicroVm => "microvm",
            Self::FullVm => "full_vm",
        }
    }
}

/// Capabilities advertised by a sandbox runtime implementation.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeCapabilities {
    /// Isolation class advertised by the runtime.
    pub isolation: RuntimeIsolation,
    /// Whether command execution is supported.
    pub exec: bool,
    /// Whether workspace file operations are supported.
    pub files: bool,
    /// Whether exec output can be streamed.
    pub streaming: bool,
    /// Whether pseudo-terminal sessions are supported.
    pub pty: bool,
    /// Whether standard OCI/Docker images are accepted.
    pub docker_image: bool,
    /// Whether a guest control agent is used.
    pub guest_agent: bool,
    /// Whether the boundary is a full hardware-isolated kernel.
    pub full_kernel_isolation: bool,
    /// Whether workspace artifacts are portable across runtime instances.
    pub portable_workspace: bool,
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
    /// Whether pause releases host runtime resources rather than only suspending execution.
    pub pause_reclaims_resources: bool,
    /// Whether filesystem-only workspace snapshots are available.
    pub workspace_snapshot: bool,
    /// Whether guest communication uses a VSock-like transport.
    pub vsock: bool,
    /// Whether the guest image is a verified coding-capable artifact.
    pub coding_guest: bool,
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
        Self {
            healthy: true,
            message: None,
        }
    }

    /// Creates an unhealthy status with a diagnostic message.
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            healthy: false,
            message: Some(message.into()),
        }
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
    /// Pauses a running sandbox while retaining its runtime state.
    async fn pause(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Resumes a paused sandbox.
    async fn resume(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
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
    /// Replaces a sandbox workspace with a portable archive captured elsewhere.
    ///
    /// Recovery assigns a sandbox to a new runtime instance that never held
    /// the captured state, so the archive travels with the snapshot instead of
    /// living in the capturing runtime's local state directory. Implementations
    /// must fail rather than leave the workspace empty when the bytes cannot
    /// be applied.
    async fn import_workspace_archive(
        &self,
        sandbox: &Sandbox,
        archive: &[u8],
    ) -> Result<(), crate::CoreError>;
    /// Releases all resources owned by a sandbox.
    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Reports current runtime health.
    async fn health(&self) -> RuntimeHealth;
    /// Reports immutable backend capabilities.
    fn capabilities(&self) -> RuntimeCapabilities;
}

/// Result of selecting a runtime from a registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSelection {
    pub runtime: crate::RuntimeKind,
    pub capabilities: RuntimeCapabilities,
    pub reason: String,
}

/// Core-owned registry of runtime implementations.
#[derive(Clone, Default)]
pub struct RuntimeRegistry {
    entries: Vec<(crate::RuntimeKind, Arc<dyn SandboxRuntime>)>,
}

impl RuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, kind: crate::RuntimeKind, runtime: Arc<dyn SandboxRuntime>) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|(existing, _)| *existing == kind)
        {
            entry.1 = runtime;
        } else {
            self.entries.push((kind, runtime));
        }
    }

    pub fn with_runtime(kind: crate::RuntimeKind, runtime: Arc<dyn SandboxRuntime>) -> Self {
        let mut registry = Self::new();
        registry.register(kind, runtime);
        registry
    }

    pub fn lookup(&self, kind: crate::RuntimeKind) -> Option<Arc<dyn SandboxRuntime>> {
        self.entries
            .iter()
            .find(|(existing, _)| *existing == kind)
            .map(|(_, runtime)| runtime.clone())
    }

    pub fn capabilities(&self, kind: crate::RuntimeKind) -> Option<RuntimeCapabilities> {
        self.lookup(kind).map(|runtime| runtime.capabilities())
    }

    pub async fn health(&self, kind: crate::RuntimeKind) -> Option<RuntimeHealth> {
        let runtime = self.lookup(kind)?;
        Some(runtime.health().await)
    }

    pub fn kinds(&self) -> Vec<crate::RuntimeKind> {
        self.entries.iter().map(|(kind, _)| *kind).collect()
    }

    pub async fn select(
        &self,
        requested: Option<crate::RuntimeKind>,
        required: &RuntimeCapabilities,
        minimum_isolation: Option<RuntimeIsolation>,
    ) -> Result<RuntimeSelection, crate::CoreError> {
        if let Some(kind) = requested {
            let runtime = self.lookup(kind).ok_or_else(|| {
                crate::CoreError::Unavailable(format!("runtime {kind:?} is not registered"))
            })?;
            let capabilities = runtime.capabilities();
            if !capabilities_satisfy(&capabilities, required, minimum_isolation) {
                return Err(crate::CoreError::Unsupported(format!(
                    "runtime {kind:?} lacks required capabilities"
                )));
            }
            return Ok(RuntimeSelection {
                runtime: kind,
                capabilities,
                reason: format!("explicit runtime {kind:?} selected"),
            });
        }
        let order = if minimum_isolation.is_some_and(|isolation| {
            matches!(
                isolation,
                RuntimeIsolation::MicroVm | RuntimeIsolation::FullVm
            )
        }) {
            [
                RuntimeKind::Firecracker,
                RuntimeKind::Docker,
                RuntimeKind::BwrapDev,
            ]
        } else {
            [
                RuntimeKind::Docker,
                RuntimeKind::Firecracker,
                RuntimeKind::BwrapDev,
            ]
        };
        for kind in order {
            let Some(runtime) = self.lookup(kind) else {
                continue;
            };
            if !runtime.health().await.healthy {
                continue;
            }
            let capabilities = runtime.capabilities();
            if capabilities_satisfy(&capabilities, required, minimum_isolation) {
                return Ok(RuntimeSelection {
                    runtime: kind,
                    capabilities,
                    reason: format!("policy selected {kind:?} from available capable runtimes"),
                });
            }
        }
        Err(crate::CoreError::Unavailable(
            "no available runtime satisfies requested capabilities".into(),
        ))
    }
}

fn capabilities_satisfy(
    actual: &RuntimeCapabilities,
    required: &RuntimeCapabilities,
    minimum: Option<RuntimeIsolation>,
) -> bool {
    (!required.exec || actual.exec)
        && (!required.files || actual.files)
        && (!required.streaming || actual.streaming)
        && (!required.pty || actual.pty)
        && (!required.docker_image || actual.docker_image)
        && (!required.guest_agent || actual.guest_agent)
        && (!required.full_kernel_isolation || actual.full_kernel_isolation)
        && (!required.portable_workspace || actual.portable_workspace)
        && (!required.vm_snapshot || actual.vm_snapshot)
        && (!required.memory_resume || actual.memory_resume)
        && (!required.network_policy || actual.network_policy)
        && (!required.pause || actual.pause)
        && (!required.workspace_snapshot || actual.workspace_snapshot)
        && minimum.is_none_or(|minimum| isolation_rank(actual.isolation) >= isolation_rank(minimum))
}

fn isolation_rank(isolation: RuntimeIsolation) -> u8 {
    match isolation {
        RuntimeIsolation::Process => 0,
        RuntimeIsolation::Container => 1,
        RuntimeIsolation::MicroVm => 2,
        RuntimeIsolation::FullVm => 3,
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;
    use crate::{RuntimeKind, Sandbox};

    struct TestRuntime {
        capabilities: RuntimeCapabilities,
        healthy: bool,
    }

    #[async_trait]
    impl SandboxRuntime for TestRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn start(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, crate::CoreError> {
            Ok(ExecResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: 0,
                timed_out: false,
            })
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn get_file(&self, _: &Sandbox, path: &str) -> Result<FileContent, crate::CoreError> {
            Ok(FileContent {
                path: path.into(),
                content_base64: String::new(),
            })
        }
        async fn list_files(
            &self,
            _: &Sandbox,
            _: &str,
        ) -> Result<Vec<FileEntry>, crate::CoreError> {
            Ok(Vec::new())
        }
        async fn delete_file(
            &self,
            _: &Sandbox,
            _: DeleteFileRequest,
        ) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn import_workspace_archive(
            &self,
            _: &Sandbox,
            _: &[u8],
        ) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn health(&self) -> RuntimeHealth {
            if self.healthy {
                RuntimeHealth::healthy()
            } else {
                RuntimeHealth::unhealthy("test")
            }
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            self.capabilities.clone()
        }
    }

    #[tokio::test]
    async fn registry_explicit_lookup_and_auto_prefers_available_runtimes() {
        let container = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::Container,
                exec: true,
                files: true,
                ..Default::default()
            },
            healthy: true,
        });
        let microvm = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::MicroVm,
                exec: true,
                files: true,
                full_kernel_isolation: true,
                ..Default::default()
            },
            healthy: true,
        });
        let mut registry = RuntimeRegistry::new();
        registry.register(RuntimeKind::Docker, container);
        registry.register(RuntimeKind::Firecracker, microvm);
        assert!(registry.lookup(RuntimeKind::Docker).is_some());
        assert_eq!(registry.kinds().len(), 2);
        let selected = registry
            .select(
                None,
                &RuntimeCapabilities {
                    exec: true,
                    files: true,
                    ..Default::default()
                },
                Some(RuntimeIsolation::MicroVm),
            )
            .await
            .unwrap();
        assert_eq!(selected.runtime, RuntimeKind::Firecracker);
        assert!(selected.reason.contains("policy selected"));
    }
    #[tokio::test]
    async fn registry_explicit_docker_and_firecracker_capabilities() {
        let docker = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::Container,
                exec: true,
                files: true,
                docker_image: true,
                ..Default::default()
            },
            healthy: true,
        });
        let firecracker = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::MicroVm,
                exec: true,
                files: true,
                full_kernel_isolation: true,
                guest_agent: true,
                ..Default::default()
            },
            healthy: true,
        });
        let mut registry = RuntimeRegistry::new();
        registry.register(RuntimeKind::Docker, docker);
        registry.register(RuntimeKind::Firecracker, firecracker);
        let required = RuntimeCapabilities {
            exec: true,
            files: true,
            ..Default::default()
        };
        let docker_selection = registry
            .select(Some(RuntimeKind::Docker), &required, None)
            .await
            .unwrap();
        assert_eq!(docker_selection.runtime, RuntimeKind::Docker);
        let microvm_selection = registry
            .select(
                Some(RuntimeKind::Firecracker),
                &required,
                Some(RuntimeIsolation::MicroVm),
            )
            .await
            .unwrap();
        assert_eq!(microvm_selection.runtime, RuntimeKind::Firecracker);
    }
}
