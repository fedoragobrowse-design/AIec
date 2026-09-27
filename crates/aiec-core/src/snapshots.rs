//! Runtime-neutral snapshot descriptions and provider boundary.

use crate::{CoreError, Sandbox, SnapshotId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Largest portable workspace archive that may cross a process or wire
/// boundary, in serialized bytes.
///
/// A capture or import above this is rejected before allocation, so an
/// oversized artifact cannot exhaust a control plane or worker.
pub const MAX_WORKSPACE_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

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
            cross_instance_restore: false,
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
    /// Lowercase hexadecimal SHA-256 checksum of the archive bytes.
    pub checksum_sha256: String,
    /// Serialized artifact bytes, as produced by the provider.
    ///
    /// Handing the bytes back is what makes a capture portable: the control
    /// plane persists them in shared object storage under `object_key`, so a
    /// worker that never ran this sandbox can restore it. It stays empty for
    /// providers whose artifact is not a portable archive.
    #[serde(default, with = "archive_bytes")]
    pub archive: Vec<u8>,
}

impl CapturedSnapshot {
    /// Builds a capture result from serialized archive bytes, deriving the
    /// size and checksum so the durable record always describes the artifact
    /// the provider actually produced.
    pub fn from_archive(
        id: SnapshotId,
        kind: SnapshotKind,
        object_key: impl Into<String>,
        archive: Vec<u8>,
    ) -> Self {
        Self {
            id,
            kind,
            object_key: object_key.into(),
            size_bytes: archive.len() as u64,
            checksum_sha256: archive_checksum(&archive),
            archive,
        }
    }
}

/// Returns the lowercase hexadecimal SHA-256 digest of `archive` bytes.
pub fn archive_checksum(archive: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(archive))
}

/// Checks `archive` against an expected lowercase hexadecimal SHA-256 digest.
///
/// A snapshot whose bytes no longer match the record is a conflict, never an
/// empty workspace: silently recovering nothing would lose a sandbox's state
/// without any signal.
pub fn verify_archive_checksum(archive: &[u8], expected_sha256: &str) -> Result<(), CoreError> {
    if archive_checksum(archive).eq_ignore_ascii_case(expected_sha256) {
        Ok(())
    } else {
        Err(CoreError::Conflict(
            "workspace archive checksum does not match the stored snapshot".into(),
        ))
    }
}

/// Encodes archive bytes as base64 on the wire, matching `protocol`.
mod archive_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(serde::de::Error::custom)
    }
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableWorkspaceEntry {
    pub path: String,
    pub directory: bool,
    #[serde(default)]
    pub content_base64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableWorkspaceArchive {
    pub version: u8,
    pub entries: Vec<PortableWorkspaceEntry>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capture_describes_the_bytes_it_carries() {
        let archive = b"{\"version\":1,\"entries\":[]}".to_vec();
        let captured = CapturedSnapshot::from_archive(
            SnapshotId::new_v4(),
            SnapshotKind::Workspace,
            "workspace-1",
            archive.clone(),
        );
        assert_eq!(captured.size_bytes, archive.len() as u64);
        assert_eq!(captured.checksum_sha256, archive_checksum(&archive));
        assert!(verify_archive_checksum(&archive, &captured.checksum_sha256).is_ok());
    }

    /// The worker wire is JSON, so a capture must still deliver the archive
    /// bytes to a control plane that never shared a disk with the worker.
    #[test]
    fn capture_bytes_survive_the_wire_encoding() {
        let archive = vec![0_u8, 1, 2, 250, 251, 252];
        let captured = CapturedSnapshot::from_archive(
            SnapshotId::new_v4(),
            SnapshotKind::Workspace,
            "workspace-1",
            archive.clone(),
        );
        let encoded = serde_json::to_string(&captured).expect("encode capture");
        let decoded: CapturedSnapshot = serde_json::from_str(&encoded).expect("decode capture");
        assert_eq!(decoded.archive, archive);
        assert_eq!(decoded, captured);
    }

    /// An older control plane or worker that never learned about the field must
    /// still decode a capture rather than fail the whole snapshot call.
    #[test]
    fn a_capture_without_archive_bytes_still_decodes() {
        let captured: CapturedSnapshot = serde_json::from_str(
            r#"{"id":"00000000-0000-0000-0000-000000000001","kind":"workspace","object_key":"k","size_bytes":4,"checksum_sha256":"ab"}"#,
        )
        .expect("decode capture");
        assert!(captured.archive.is_empty());
    }

    #[test]
    fn a_tampered_archive_is_a_conflict() {
        let archive = b"original".to_vec();
        let checksum = archive_checksum(&archive);
        assert!(matches!(
            verify_archive_checksum(b"tampered", &checksum),
            Err(CoreError::Conflict(_))
        ));
    }
}
