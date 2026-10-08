//! Parity tests for `renew_worker_lease` across the two metadata stores.
//!
//! The Postgres implementation encodes a contract the worker depends on: a TTL
//! outside `1..=3600` is a fencing refusal (`Conflict`, surfaced as 409), an
//! expired lease reports expiry rather than the generic generation message,
//! and a stale generation reports the shared resync string. The in-memory
//! implementation previously answered TTL violations as `InvalidRequest` and
//! collapsed expiry and generation mismatch into one message, so a caller
//! distinguishing "renew sooner" from "someone else owns this" got different
//! answers per backend.

use crate::MemoryRepository;
use aiec_core::{CoreError, storage::MetadataStore};
use chrono::{Duration, Utc};
use uuid::Uuid;

async fn insert_lease(
    repository: &MemoryRepository,
    tenant: Uuid,
    lease_id: Uuid,
    generation: i64,
    expires_at: chrono::DateTime<Utc>,
) {
    let now = Utc::now();
    repository.data.write().await.leases.insert(
        lease_id,
        aiec_core::storage::WorkerLease {
            id: lease_id,
            tenant_id: tenant,
            sandbox_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
            generation,
            status: "active".into(),
            reason: None,
            expires_at,
            created_at: now,
            updated_at: now,
        },
    );
}
#[tokio::test]
async fn an_out_of_range_ttl_is_a_fencing_refusal_not_a_caller_error() {
    let repository = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let lease_id = Uuid::new_v4();
    insert_lease(
        &repository,
        tenant,
        lease_id,
        1,
        Utc::now() + Duration::minutes(10),
    )
    .await;
    let error = repository
        .renew_worker_lease(tenant, lease_id, 1, 0)
        .await
        .expect_err("TTL 0 must be refused");
    assert!(
        matches!(error, CoreError::Conflict(_)),
        "TTL refusal must be Conflict, got {error:?}"
    );
}

#[tokio::test]
async fn an_expired_lease_reports_expiry_not_generation_drift() {
    let repository = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let lease_id = Uuid::new_v4();
    insert_lease(
        &repository,
        tenant,
        lease_id,
        1,
        Utc::now() - Duration::minutes(1),
    )
    .await;
    let error = repository
        .renew_worker_lease(tenant, lease_id, 1, 300)
        .await
        .expect_err("expired lease must be refused");
    assert!(
        matches!(error, CoreError::Conflict(ref message) if message == "worker lease has expired"),
        "expiry must be distinguishable, got {error:?}"
    );
}

#[tokio::test]
async fn a_stale_generation_reports_the_shared_resync_message() {
    let repository = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let lease_id = Uuid::new_v4();
    insert_lease(
        &repository,
        tenant,
        lease_id,
        2,
        Utc::now() + Duration::minutes(10),
    )
    .await;
    let error = repository
        .renew_worker_lease(tenant, lease_id, 1, 300)
        .await
        .expect_err("stale generation must be refused");
    assert!(
        matches!(error, CoreError::Conflict(ref message) if message == "worker lease generation or status changed"),
        "generation mismatch must match Postgres, got {error:?}"
    );
}
