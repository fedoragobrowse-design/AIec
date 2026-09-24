use agentforge_core::{
    CoreError,
    snapshots::{SnapshotCapabilities, SnapshotKind, SnapshotMetadata},
    storage::StoredSnapshot,
};

/// Maps persisted AgentForge snapshot kinds to the runtime-neutral Core enum.
pub fn snapshot_kind(kind: &str) -> Result<SnapshotKind, CoreError> {
    match kind {
        "vm" | "virtual_machine" => Ok(SnapshotKind::VirtualMachine),
        "memory" => Ok(SnapshotKind::Memory),
        "filesystem" | "workspace" => Ok(SnapshotKind::Workspace),
        _ => Err(CoreError::Unsupported(format!(
            "snapshot kind `{kind}`"
        ))),
    }
}

/// Maps detailed relational snapshot metadata to provider-neutral restore metadata.
pub fn snapshot_metadata(value: &StoredSnapshot) -> Result<SnapshotMetadata, CoreError> {
    if !value.complete {
        return Err(CoreError::Conflict("snapshot metadata is incomplete".into()));
    }
    if value.checksum_sha256.len() != 64
        || !value
            .checksum_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CoreError::Conflict(
            "snapshot metadata has an invalid checksum".into(),
        ));
    }
    Ok(SnapshotMetadata {
        id: value.id,
        kind: snapshot_kind(&value.kind)?,
        object_key: value.object_key.clone(),
        checksum_sha256: value.checksum_sha256.clone(),
    })
}

/// Reports the capabilities of a provider that supports the supplied persisted kinds.
pub fn snapshot_capabilities(kinds: &[SnapshotKind]) -> SnapshotCapabilities {
    SnapshotCapabilities {
        virtual_machine: kinds.contains(&SnapshotKind::VirtualMachine),
        memory: kinds.contains(&SnapshotKind::Memory),
        workspace: kinds.contains(&SnapshotKind::Workspace),
        cross_instance_restore: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentforge_core::new_id;
    use serde_json::json;

    #[test]
    fn detailed_metadata_maps_to_restore_contract() {
        let value = StoredSnapshot {
            id: new_id(),
            tenant_id: new_id(),
            sandbox_id: new_id(),
            object_key: "tenant/snapshot/workspace".into(),
            manifest_object_key: "tenant/snapshot/manifest".into(),
            memory_object_key: None,
            disk_object_key: None,
            workspace_object_key: Some("tenant/snapshot/workspace".into()),
            size_bytes: 42,
            image_id: "image".into(),
            checksum_sha256: "a".repeat(64),
            kind: "filesystem".into(),
            complete: true,
            manifest: json!({"schema": 1}),
            created_at: chrono::Utc::now(),
        };
        let mapped = snapshot_metadata(&value).unwrap();
        assert_eq!(mapped.kind, SnapshotKind::Workspace);
        assert_eq!(mapped.object_key, value.object_key);
        assert!(snapshot_capabilities(&[SnapshotKind::Workspace]).workspace);
    }
}
