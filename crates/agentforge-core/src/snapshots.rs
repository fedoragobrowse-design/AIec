//! Runtime-neutral snapshot descriptions and provider boundary.

use crate::{Sandbox, SnapshotId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Semantics preserved by a snapshot artifact.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    /// Full virtual machine state, including memory and disk.
    VirtualMachine,
    /// Virtual machine memory state with disk handled separately.
    Memory,
    /// Portable sandbox workspace filesystem.
    Workspace,
}

/// Kinds a snapshot provider can create and restore.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SnapshotCapabilities {
    /// Full VM snapshots are supported.
    pub virtual_machine: bool,
    /// Memory-only resume artifacts are supported.
    pub memory: bool,
    /// Workspace-only snapshots are supported.
    pub workspace: bool,
    /// Snapshots can be restored into a different sandbox instance.
    pub cross_instance_restore: bool,
}

impl Default for SnapshotCapabilities {
    fn default() -> Self {
        Self {
            virtual_machine: false,
            memory: false,
            workspace: true,
            cross_instance_restore: true,
        }
    }
}

/// Request to capture one sandbox into an artifact store.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotRequest {
    /// Snapshot semantics to preserve.
    pub kind: SnapshotKind,
    /// Object key reserved for the primary artifact.
    pub object_key: String,
}

/// Result of a successful snapshot capture.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedSnapshot {
    /// Durable snapshot identifier.
    pub id: SnapshotId,
    /// Semantics that were captured.
    pub kind: SnapshotKind,
    /// Primary artifact object key.
    pub object_key: String,
    /// Total artifact size in bytes.
    pub size_bytes: u64,
    /// Lowercase hexadecimal SHA-256 checksum.
    pub checksum_sha256: String,
}

/// Durable metadata required to restore a snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// Durable snapshot identifier.
    pub id: SnapshotId,
    /// Semantics to restore.
    pub kind: SnapshotKind,
    /// Primary artifact object key.
    pub object_key: String,
    /// Expected SHA-256 checksum.
    pub checksum_sha256: String,
}

/// Creates and restores snapshots while keeping storage orchestration separate.
#[async_trait]
pub trait SnapshotProvider: Send + Sync {
    /// Reports supported snapshot semantics.
    fn capabilities(&self) -> SnapshotCapabilities;
    /// Captures a sandbox and returns its durable metadata.
    async fn capture(
        &self,
        sandbox: &Sandbox,
        request: &SnapshotRequest,
    ) -> Result<CapturedSnapshot, crate::CoreError>;
    /// Restores a sandbox from previously captured metadata.
    async fn restore(
        &self,
        sandbox: &Sandbox,
        snapshot: &SnapshotMetadata,
    ) -> Result<(), crate::CoreError>;
}
