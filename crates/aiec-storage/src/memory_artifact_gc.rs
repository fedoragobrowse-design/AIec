//! Volatile counterpart of the durable ledger for the development metadata store.
//! This store has snapshots, but does not implement Run persistence.
use crate::{MemoryData, MemoryRepository, StoreError, object_store::validate_object_key};
use aiec_core::{
    CoreError,
    storage::{ArtifactDeletion, StoredSnapshot},
};
use chrono::{DateTime, Duration, Utc};
use std::ops::Bound;
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ObjectState {
    Pending,
    Available,
    Deleting,
    Deleted,
}

pub(super) struct MemoryArtifact {
    tenant: Uuid,
    state: ObjectState,
    updated_at: DateTime<Utc>,
    retry_at: DateTime<Utc>,
    claim: Option<Uuid>,
    lease_until: Option<DateTime<Utc>>,
    references: usize,
}

impl MemoryArtifact {
    fn new(tenant: Uuid, state: ObjectState, now: DateTime<Utc>) -> Self {
        Self {
            tenant,
            state,
            updated_at: now,
            retry_at: now,
            claim: None,
            lease_until: None,
            references: 0,
        }
    }
}

pub(super) fn stored_keys(value: &StoredSnapshot) -> [Option<&str>; 5] {
    [
        Some(&value.object_key),
        Some(&value.manifest_object_key),
        value.memory_object_key.as_deref(),
        value.disk_object_key.as_deref(),
        value.workspace_object_key.as_deref(),
    ]
}

pub(super) fn link_keys(
    data: &mut MemoryData,
    tenant: Uuid,
    keys: &[Option<&str>],
) -> Result<(), StoreError> {
    for key in keys.iter().flatten() {
        validate_object_key(key)?;
        if data.artifact_objects.get(*key).is_some_and(|object| {
            matches!(object.state, ObjectState::Deleting | ObjectState::Deleted)
        }) {
            return Err(StoreError::Conflict(
                "artifact key is being deleted or has expired".into(),
            ));
        }
    }
    let now = Utc::now();
    for (index, key) in keys.iter().enumerate() {
        let Some(key) = key else { continue };
        if keys[..index].contains(&Some(*key)) {
            continue;
        }
        if let Some(object) = data.artifact_objects.get_mut(*key) {
            object.state = ObjectState::Available;
            object.updated_at = now;
            object.references += 1;
        } else {
            let mut object = MemoryArtifact::new(tenant, ObjectState::Available, now);
            object.references = 1;
            data.artifact_objects.insert((*key).to_owned(), object);
        }
    }
    Ok(())
}

pub(super) fn unlink_keys(data: &mut MemoryData, keys: &[Option<&str>]) {
    for (index, key) in keys.iter().enumerate() {
        let Some(key) = key else { continue };
        if keys[..index].contains(&Some(*key)) {
            continue;
        }
        if let Some(object) = data.artifact_objects.get_mut(*key) {
            object.references -= 1;
        }
    }
}

impl MemoryRepository {
    pub(crate) async fn reserve_artifact_upload(
        &self,
        tenant: Uuid,
        run: Option<Uuid>,
        key: &str,
    ) -> Result<(), CoreError> {
        if run.is_some() {
            return Err(CoreError::Unsupported("memory Run storage".into()));
        }
        validate_object_key(key).map_err(crate::core_error)?;
        let now = Utc::now();
        let mut data = self.data.write().await;
        // The development store permits sandbox creation without a tenant row;
        // the owned sandbox/key/snapshot still establishes that tenant's identity.
        let known = data.tenants.contains_key(&tenant)
            || data
                .sandboxes
                .values()
                .any(|value| value.tenant_id == tenant)
            || data.keys.values().any(|value| value.tenant_id == tenant)
            || data
                .snapshots
                .values()
                .any(|value| value.tenant_id == tenant)
            || data
                .stored_snapshots
                .values()
                .any(|value| value.tenant_id == tenant);
        if !known {
            return Err(CoreError::NotFound("tenant not found".into()));
        }
        if let Some(object) = data.artifact_objects.get_mut(key) {
            if object.tenant != tenant
                || matches!(object.state, ObjectState::Deleting | ObjectState::Deleted)
            {
                return Err(CoreError::Conflict(
                    "object key belongs to another owner or has expired".into(),
                ));
            }
            object.updated_at = now;
        } else {
            data.artifact_objects.insert(
                key.to_owned(),
                MemoryArtifact::new(tenant, ObjectState::Pending, now),
            );
        }
        Ok(())
    }

    pub(crate) async fn complete_artifact_upload(
        &self,
        tenant: Uuid,
        run: Option<Uuid>,
        key: &str,
    ) -> Result<(), CoreError> {
        if run.is_some() {
            return Err(CoreError::Unsupported("memory Run storage".into()));
        }
        let mut data = self.data.write().await;
        let object = data
            .artifact_objects
            .get_mut(key)
            .filter(|object| object.tenant == tenant)
            .ok_or_else(|| CoreError::NotFound("upload ownership not found".into()))?;
        let expired = matches!(object.state, ObjectState::Deleting | ObjectState::Deleted);
        object.state = if expired {
            ObjectState::Deleting
        } else {
            ObjectState::Available
        };
        object.claim = None;
        object.lease_until = None;
        object.updated_at = Utc::now();
        object.retry_at = object.updated_at;
        if expired {
            return Err(CoreError::Conflict(
                "upload completed after its ownership expired".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn claim_artifact_deletions(
        &self,
        now: DateTime<Utc>,
        retention_seconds: i64,
        pending_grace_seconds: i64,
        limit: u32,
        lease_seconds: i64,
    ) -> Result<Vec<ArtifactDeletion>, CoreError> {
        if !(1..=315_360_000).contains(&retention_seconds)
            || !(600..=315_360_000).contains(&pending_grace_seconds)
            || !(1..=1000).contains(&limit)
            || !(1..=3600).contains(&lease_seconds)
        {
            return Err(CoreError::InvalidRequest(
                "invalid artifact GC bounds".into(),
            ));
        }
        let abandoned = now
            .checked_sub_signed(Duration::seconds(pending_grace_seconds))
            .ok_or_else(|| CoreError::InvalidRequest("artifact upload grace overflow".into()))?;
        let lease_until = now
            .checked_add_signed(Duration::seconds(lease_seconds))
            .ok_or_else(|| CoreError::InvalidRequest("artifact deletion lease overflow".into()))?;
        let mut data = self.data.write().await;
        let cursor = data.artifact_scan.take();
        let start = cursor.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
        let mut claims = Vec::new();
        let mut last = None;
        // Bound inspections as well as deletions, without cloning every ledger
        // row into a candidate list. Continue after this cursor on the next tick.
        for (key, object) in data
            .artifact_objects
            .range_mut::<str, _>((start, Bound::Unbounded))
            .take(limit as usize)
        {
            last = Some(key);
            if object.state == ObjectState::Deleted
                || object.references != 0
                || object.retry_at > now
                || object.lease_until.is_some_and(|lease| lease > now)
                || (object.state != ObjectState::Deleting && object.updated_at > abandoned)
            {
                continue;
            }
            let claim = Uuid::new_v4();
            object.state = ObjectState::Deleting;
            object.claim = Some(claim);
            object.lease_until = Some(lease_until);
            claims.push(ArtifactDeletion {
                key: key.clone(),
                tenant_id: object.tenant,
                claim,
            });
        }
        let next = last.cloned();
        data.artifact_scan = next;
        Ok(claims)
    }

    pub(crate) async fn finish_artifact_deletion(
        &self,
        key: &str,
        claim: Uuid,
        deleted: bool,
        retry_at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        let mut data = self.data.write().await;
        let object = data
            .artifact_objects
            .get_mut(key)
            .filter(|object| object.state == ObjectState::Deleting && object.claim == Some(claim))
            .ok_or_else(|| CoreError::Conflict("stale artifact deletion claim".into()))?;
        object.state = if deleted {
            ObjectState::Deleted
        } else {
            ObjectState::Deleting
        };
        object.claim = None;
        object.lease_until = None;
        object.retry_at = retry_at;
        object.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiec_core::{
        Snapshot,
        storage::{MetadataStore, TenantRecord},
    };
    use serde_json::json;

    async fn tenant(repository: &MemoryRepository) -> Uuid {
        let id = Uuid::new_v4();
        repository
            .put_tenant(TenantRecord {
                id,
                name: format!("memory-{id}"),
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        id
    }

    async fn age(repository: &MemoryRepository, now: DateTime<Utc>) {
        for object in repository.data.write().await.artifact_objects.values_mut() {
            object.updated_at = now - Duration::hours(2);
            object.retry_at = object.updated_at;
        }
    }

    async fn claims(repository: &MemoryRepository, now: DateTime<Utc>) -> Vec<ArtifactDeletion> {
        let mut result = Vec::new();
        for _ in 0..4 {
            result.extend(
                repository
                    .claim_artifact_deletions(now, 3600, 600, 100, 300)
                    .await
                    .unwrap(),
            );
        }
        result
    }

    fn snapshot(tenant: Uuid, key: &str) -> Snapshot {
        Snapshot {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            sandbox_id: Uuid::new_v4(),
            object_key: key.into(),
            size_bytes: 4,
            image_id: "image".into(),
            created_at: Utc::now(),
        }
    }

    fn stored(value: &Snapshot, manifest: &str, shared: &str) -> StoredSnapshot {
        StoredSnapshot {
            id: value.id,
            tenant_id: value.tenant_id,
            sandbox_id: value.sandbox_id,
            object_key: value.object_key.clone(),
            manifest_object_key: manifest.into(),
            memory_object_key: None,
            disk_object_key: None,
            workspace_object_key: Some(shared.into()),
            size_bytes: 4,
            image_id: "image".into(),
            checksum_sha256: "a".repeat(64),
            kind: "workspace".into(),
            complete: true,
            manifest: json!({}),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn memory_snapshot_references_preserve_other_tenants_and_reject_late_linking() {
        let repository = MemoryRepository::new();
        let a = tenant(&repository).await;
        let b = tenant(&repository).await;
        let now = Utc::now();
        repository
            .reserve_artifact_upload(a, None, "shared")
            .await
            .unwrap();
        repository
            .complete_artifact_upload(a, None, "shared")
            .await
            .unwrap();
        let first = snapshot(a, "primary-a");
        let second = snapshot(b, "primary-b");
        // One write per snapshot, exactly as PostgreSQL records it: the stored
        // row is the snapshot, so it also carries the basic view.
        MetadataStore::put_stored_snapshot(&*repository, stored(&first, "manifest-a", "shared"))
            .await
            .unwrap();
        MetadataStore::put_stored_snapshot(&*repository, stored(&second, "manifest-b", "shared"))
            .await
            .unwrap();
        age(&repository, now).await;
        assert!(claims(&repository, now).await.is_empty());
        assert!(
            MetadataStore::delete_snapshot(&*repository, b, first.id)
                .await
                .is_err()
        );
        assert_eq!(
            MetadataStore::get_snapshot(&*repository, a, first.id)
                .await
                .unwrap()
                .object_key,
            "primary-a"
        );
        MetadataStore::delete_snapshot(&*repository, a, first.id)
            .await
            .unwrap();
        let released = claims(&repository, now).await;
        let mut keys = released
            .iter()
            .map(|claim| claim.key.as_str())
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, vec!["manifest-a", "primary-a"]);
        assert!(
            MetadataStore::put_snapshot(&*repository, snapshot(a, "primary-a"))
                .await
                .is_err()
        );
        MetadataStore::delete_snapshot(&*repository, b, second.id)
            .await
            .unwrap();
        let released = claims(&repository, now).await;
        let mut keys = released
            .iter()
            .map(|claim| claim.key.as_str())
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, vec!["manifest-b", "primary-b", "shared"]);
        assert_eq!(
            released
                .iter()
                .find(|claim| claim.key == "shared")
                .unwrap()
                .tenant_id,
            a
        );
    }

    #[tokio::test]
    async fn stored_only_snapshots_are_visible_gettable_and_deletable_by_their_owner() {
        let repository = MemoryRepository::new();
        let owner = tenant(&repository).await;
        let stranger = tenant(&repository).await;
        let now = Utc::now();
        let value = snapshot(owner, "primary");
        let sandbox = value.sandbox_id;
        // The workspace role reuses the primary key, as a workspace capture does.
        let stored = stored(&value, "manifest", "primary");
        MetadataStore::put_stored_snapshot(&*repository, stored.clone())
            .await
            .unwrap();
        let listed = MetadataStore::list_snapshots(&*repository, owner, sandbox)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, value.id);
        assert_eq!(listed[0].object_key, "primary");
        assert_eq!(
            MetadataStore::get_snapshot(&*repository, owner, value.id)
                .await
                .unwrap()
                .size_bytes,
            4
        );
        assert!(
            MetadataStore::list_snapshots(&*repository, stranger, sandbox)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            MetadataStore::get_snapshot(&*repository, stranger, value.id)
                .await
                .is_err()
        );
        age(&repository, now).await;
        // Another tenant can neither retire the snapshot nor release its objects.
        assert!(
            MetadataStore::delete_snapshot(&*repository, stranger, value.id)
                .await
                .is_err()
        );
        assert_eq!(
            MetadataStore::get_stored_snapshot(&*repository, owner, value.id)
                .await
                .unwrap(),
            stored
        );
        assert!(claims(&repository, now).await.is_empty());
        MetadataStore::delete_snapshot(&*repository, owner, value.id)
            .await
            .unwrap();
        assert!(
            MetadataStore::get_snapshot(&*repository, owner, value.id)
                .await
                .is_err()
        );
        assert!(
            MetadataStore::get_stored_snapshot(&*repository, owner, value.id)
                .await
                .is_err()
        );
        let mut released = claims(&repository, now).await;
        released.sort_by(|left, right| left.key.cmp(&right.key));
        assert_eq!(
            released
                .iter()
                .map(|claim| claim.key.as_str())
                .collect::<Vec<_>>(),
            vec!["manifest", "primary"]
        );
    }

    #[tokio::test]
    async fn bounded_inspection_reaches_garbage_behind_a_protected_prefix() {
        let repository = MemoryRepository::new();
        let tenant_id = tenant(&repository).await;
        let now = Utc::now();
        for index in 0..5 {
            let key = format!("a/protected-{index}");
            repository
                .reserve_artifact_upload(tenant_id, None, &key)
                .await
                .unwrap();
            repository
                .complete_artifact_upload(tenant_id, None, &key)
                .await
                .unwrap();
            let value = snapshot(tenant_id, &key);
            MetadataStore::put_stored_snapshot(
                &*repository,
                stored(&value, &format!("{key}.manifest"), &key),
            )
            .await
            .unwrap();
        }
        let garbage = "z-garbage";
        repository
            .reserve_artifact_upload(tenant_id, None, garbage)
            .await
            .unwrap();
        repository
            .complete_artifact_upload(tenant_id, None, garbage)
            .await
            .unwrap();
        age(&repository, now).await;
        // Five snapshots each hold two objects, so the ledger holds ten protected
        // keys ahead of the garbage. A pass inspects two entries and moves on,
        // so the protected prefix costs passes of its own and never starves the
        // garbage that sorts behind it.
        for pass in 1..=5 {
            assert!(
                repository
                    .claim_artifact_deletions(now, 3600, 600, 2, 300)
                    .await
                    .unwrap()
                    .is_empty(),
                "pass {pass} inspected only protected keys"
            );
        }
        let claims = repository
            .claim_artifact_deletions(now, 3600, 600, 2, 300)
            .await
            .unwrap();
        assert_eq!(
            claims
                .iter()
                .map(|claim| claim.key.as_str())
                .collect::<Vec<_>>(),
            vec![garbage]
        );
    }

    #[tokio::test]
    async fn memory_upload_ownership_and_retry_claims_survive_failed_deletion() {
        let repository = MemoryRepository::new();
        let a = tenant(&repository).await;
        let b = tenant(&repository).await;
        let now = Utc::now();
        repository
            .reserve_artifact_upload(a, None, "archive")
            .await
            .unwrap();
        assert!(
            repository
                .reserve_artifact_upload(b, None, "archive")
                .await
                .is_err()
        );
        assert!(
            repository
                .complete_artifact_upload(b, None, "archive")
                .await
                .is_err()
        );
        age(&repository, now).await;
        let first = claims(&repository, now).await.remove(0);
        repository
            .finish_artifact_deletion("archive", first.claim, false, now + Duration::seconds(60))
            .await
            .unwrap();
        assert!(
            claims(&repository, now + Duration::seconds(59))
                .await
                .is_empty()
        );
        let retry = claims(&repository, now + Duration::seconds(61))
            .await
            .remove(0);
        assert_ne!(retry.claim, first.claim);
        assert!(
            repository
                .finish_artifact_deletion("archive", first.claim, true, now)
                .await
                .is_err()
        );
        repository
            .finish_artifact_deletion("archive", retry.claim, true, now)
            .await
            .unwrap();
        assert!(
            repository
                .reserve_artifact_upload(a, None, "archive")
                .await
                .is_err()
        );
        assert!(
            claims(&repository, now + Duration::hours(1))
                .await
                .is_empty()
        );
        // A late producer acknowledgement rearms deletion rather than restoring
        // the retired key as a referenceable object.
        assert!(
            repository
                .complete_artifact_upload(a, None, "archive")
                .await
                .is_err()
        );
        assert_eq!(
            claims(&repository, now + Duration::hours(1)).await[0].key,
            "archive"
        );
    }
}
