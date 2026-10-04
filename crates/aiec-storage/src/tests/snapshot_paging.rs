//! Parity tests for the in-memory snapshot listing.
//!
//! `list_snapshots` has two implementations that must agree: the Postgres
//! keyset query and the in-memory sort-and-slice. They are separate code
//! behind the same contract, and the in-memory one is what a developer
//! deployment runs against, so a divergence is not merely theoretical — it is
//! the behaviour of every non-Postgres install.
//!
//! The way the two can disagree is specific. Postgres fetches `limit + 1` and
//! names the *last returned* row as the cursor; the in-memory version holds
//! the same extra row. Pointing the cursor at the held-back row instead makes
//! every page silently skip one snapshot, and the listing still looks
//! plausible — fewer rows, a `next` that keeps coming, no error. The only way
//! to see it is to walk to the end and count.
//!
//! The corresponding Postgres cases live in `postgres/tests/guard_durable.rs`.

use crate::{MemoryRepository, Snapshot};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

fn snapshot(
    tenant: Uuid,
    sandbox_id: Uuid,
    object_key: &str,
    created_at: DateTime<Utc>,
) -> Snapshot {
    Snapshot {
        id: Uuid::new_v4(),
        tenant_id: tenant,
        sandbox_id,
        object_key: object_key.into(),
        size_bytes: 1024,
        image_id: "image".into(),
        created_at,
    }
}

/// Walks the whole listing one bounded page at a time and returns every id it
/// saw, plus the number of requests it took. A caller that pages to the end
/// must see each snapshot exactly once: a skip loses data and a repeat makes
/// the walk never terminate.
async fn walk_to_end(
    store: &MemoryRepository,
    tenant: Uuid,
    sandbox_id: Uuid,
    limit: u32,
) -> (Vec<Uuid>, usize) {
    let mut seen = Vec::new();
    let mut cursor = None;
    let mut requests = 0;
    loop {
        requests += 1;
        assert!(
            requests <= 64,
            "listing did not terminate after {requests} requests"
        );
        let page = store
            .list_snapshots(tenant, sandbox_id, limit, cursor)
            .await
            .unwrap();
        // Guard against the two failure shapes a repeating cursor produces:
        // an empty page that still promises a successor, and a cursor that
        // never advances.
        if let Some(next) = page.next {
            assert!(
                !page.snapshots.is_empty(),
                "an empty page must not carry a successor cursor"
            );
            assert!(
                !cursor.is_some_and(|cursor| cursor == next),
                "the cursor did not advance"
            );
        }
        seen.extend(page.snapshots.iter().map(|entry| entry.id));
        match page.next {
            None => break,
            Some(next) => cursor = Some(next),
        }
    }
    (seen, requests)
}

/// Paging the in-memory store to the end returns every snapshot, in the order
/// the Postgres keyset defines, with nothing skipped between pages.
#[tokio::test]
async fn an_in_memory_snapshot_walk_loses_no_snapshot_between_pages() {
    let store = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let sandbox_id = Uuid::new_v4();
    let base = Utc::now();

    let mut written = Vec::new();
    for index in 0..7 {
        let entry = snapshot(
            tenant,
            sandbox_id,
            &format!("tenants/{tenant}/snapshots/{index}"),
            base + Duration::seconds(i64::from(index)),
        );
        written.push(entry.id);
        store.put_snapshot(entry).await.unwrap();
    }

    let (seen, requests) = walk_to_end(&store, tenant, sandbox_id, 2).await;

    assert_eq!(
        seen.len(),
        written.len(),
        "the walk returned {} of {} snapshots after {requests} requests; a page \
         boundary is dropping a row",
        seen.len(),
        written.len()
    );
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), written.len(), "the walk repeated a snapshot");

    // Newest first, the order `ORDER BY created_at DESC, id DESC` produces.
    let mut expected = written;
    expected.reverse();
    assert_eq!(
        seen, expected,
        "pages did not assemble into one descending list"
    );
}

/// The page boundary is the id tie-breaker when timestamps are equal.
///
/// `created_at` is not unique, and several snapshots taken in the same instant
/// is the normal case rather than an edge. A keyset that cannot break the tie
/// either skips a row or repeats it.
#[tokio::test]
async fn snapshots_sharing_a_timestamp_page_on_their_ids() {
    let store = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let sandbox_id = Uuid::new_v4();
    let same = Utc::now();

    let mut written = Vec::new();
    for index in 0..6 {
        let entry = snapshot(
            tenant,
            sandbox_id,
            &format!("tenants/{tenant}/snapshots/tie-{index}"),
            same,
        );
        written.push(entry.id);
        store.put_snapshot(entry).await.unwrap();
    }

    let (seen, _) = walk_to_end(&store, tenant, sandbox_id, 2).await;
    assert_eq!(seen.len(), written.len(), "the tied walk lost a snapshot");

    // `(created_at, id)` descending: with every timestamp equal, the walk is
    // exactly the ids in descending order.
    let mut expected = written;
    expected.sort_by(|left, right| right.cmp(left));
    assert_eq!(seen, expected);
}

/// The store clamps a caller asking for more than the ceiling, and the clamp
/// holds at the low end too — a zero limit must still return a page rather
/// than divide the walk or return nothing at all.
#[tokio::test]
async fn the_in_memory_page_bound_holds_at_both_ends() {
    let store = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let sandbox_id = Uuid::new_v4();
    let base = Utc::now();

    for index in 0..4 {
        store
            .put_snapshot(snapshot(
                tenant,
                sandbox_id,
                &format!("tenants/{tenant}/snapshots/bound-{index}"),
                base + Duration::seconds(i64::from(index)),
            ))
            .await
            .unwrap();
    }

    // The page is walked newest-first, so the cursor that has nothing after
    // it is one *older* than every row — a cursor newer than everything names
    // a position nothing was ever returned from, and legitimately matches the
    // whole history. Both directions are pinned here because the difference
    // between them is invisible until a walk runs off the end.
    let exhausted = store
        .list_snapshots(
            tenant,
            sandbox_id,
            u32::MAX,
            Some(crate::PageCursor {
                created_at: base - Duration::seconds(3600),
                id: Uuid::nil(),
            }),
        )
        .await
        .unwrap();
    assert!(
        exhausted.snapshots.is_empty(),
        "a cursor older than the whole history must return nothing"
    );
    assert!(exhausted.next.is_none());

    let before_everything = store
        .list_snapshots(
            tenant,
            sandbox_id,
            u32::MAX,
            Some(crate::PageCursor {
                created_at: base + Duration::seconds(3600),
                id: Uuid::nil(),
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        before_everything.snapshots.len(),
        4,
        "a cursor newer than everything matches the whole history"
    );

    // Zero is not a page size; it is clamped up so the listing still answers.
    let zero = store
        .list_snapshots(tenant, sandbox_id, 0, None)
        .await
        .unwrap();
    assert!(
        !zero.snapshots.is_empty(),
        "a zero limit clamped to the floor must still return a page"
    );
}

/// The listing is scoped to one sandbox and one tenant, and the page walk does
/// not widen that scope as it follows the cursor.
#[tokio::test]
async fn the_in_memory_snapshot_walk_stays_inside_its_sandbox_and_tenant() {
    let store = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let other_tenant = Uuid::new_v4();
    let sandbox_id = Uuid::new_v4();
    let other_sandbox = Uuid::new_v4();
    let base = Utc::now();

    for index in 0..3 {
        store
            .put_snapshot(snapshot(
                tenant,
                sandbox_id,
                &format!("tenants/{tenant}/snapshots/mine-{index}"),
                base + Duration::seconds(i64::from(index)),
            ))
            .await
            .unwrap();
    }
    store
        .put_snapshot(snapshot(
            tenant,
            other_sandbox,
            "tenants/x/other-sandbox",
            base,
        ))
        .await
        .unwrap();
    store
        .put_snapshot(snapshot(
            other_tenant,
            sandbox_id,
            "tenants/y/foreign-tenant",
            base,
        ))
        .await
        .unwrap();

    let (seen, _) = walk_to_end(&store, tenant, sandbox_id, 2).await;
    assert_eq!(
        seen.len(),
        3,
        "the walk crossed a tenant or sandbox boundary"
    );

    let foreign = store
        .list_snapshots(other_tenant, sandbox_id, 10, None)
        .await
        .unwrap();
    assert_eq!(foreign.snapshots.len(), 1);
    assert_eq!(foreign.snapshots[0].object_key, "tenants/y/foreign-tenant");
}
