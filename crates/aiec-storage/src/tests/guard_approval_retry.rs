//! Parity tests for the in-memory approval store.
//!
//! `get_or_put_guard_tool_approval` has two implementations that must agree:
//! the Postgres upsert and the in-memory `put_guard_tool_approval`. They are
//! separate code with the same contract, and a divergence is invisible until a
//! deployment runs against the backend that has the wrong one. These exercise
//! the retry rules against the in-memory store so both sides are held to the
//! same behaviour.
//!
//! The corresponding Postgres cases live in `postgres/guard/approvals.rs`.

use crate::{GuardToolApproval, MemoryRepository};
use aiec_core::ApprovalState;
use chrono::{Duration, Utc};
use uuid::Uuid;

fn pending(
    tenant: Uuid,
    sandbox_id: Uuid,
    requester: Uuid,
    digest: &str,
    now: chrono::DateTime<Utc>,
) -> GuardToolApproval {
    GuardToolApproval {
        id: Uuid::new_v4(),
        tenant_id: tenant,
        sandbox_id,
        tool: "sandbox.write_file".into(),
        request_digest: digest.into(),
        detail: Some("/etc/rc".into()),
        requested_by_key_id: requester,
        requested_by_label: format!("key:{requester}"),
        state: ApprovalState::Pending,
        decided_by_key_id: None,
        decided_by_label: None,
        decided_at: None,
        expires_at: now + Duration::minutes(5),
        consumed_at: None,
        created_at: now,
    }
}

const DIGEST: &str = "d3175fb4d201e2176a3947c92bd56d55fa3eb6a4421394af86f80eeff2515ee6";

/// A retry of the same ask joins the request already open rather than adding a
/// second row to the operator queue.
#[tokio::test]
async fn a_retry_joins_the_request_already_open() {
    let store = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let sandbox = Uuid::new_v4();
    let requester = Uuid::new_v4();
    let now = Utc::now();

    let first = pending(tenant, sandbox, requester, DIGEST, now);
    let stored = store.put_guard_tool_approval(first).await.unwrap();
    let again = store
        .put_guard_tool_approval(pending(tenant, sandbox, requester, DIGEST, now))
        .await
        .unwrap();

    assert_eq!(
        stored.id, again.id,
        "a retry must join the open request, not mint a second one"
    );
    assert_eq!(
        store
            .list_guard_tool_approvals(stored.tenant_id, sandbox)
            .await
            .unwrap()
            .len(),
        1,
        "the operator queue must not grow on retry"
    );
}

/// A pending row whose window has closed still holds the live slot, and
/// `decide` refuses an expired request. Handing it back unchanged would make
/// the ask permanently unaskable, so a retry must reopen it.
#[tokio::test]
async fn a_retry_after_expiry_reopens_the_request() {
    let store = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let sandbox = Uuid::new_v4();
    let requester = Uuid::new_v4();

    // Genuinely past due, judged against the store's own clock.
    let created = Utc::now() - Duration::minutes(10);
    let mut first = pending(tenant, sandbox, requester, DIGEST, created);
    first.expires_at = created + Duration::seconds(30);
    let stored = store.put_guard_tool_approval(first).await.unwrap();
    assert!(
        stored.expires_at <= Utc::now(),
        "the test needs an already-expired request to retry after"
    );

    let now = Utc::now();
    let reopened = store
        .put_guard_tool_approval(pending(tenant, sandbox, requester, DIGEST, now))
        .await
        .unwrap();

    assert_eq!(
        reopened.id, stored.id,
        "reopening must reuse the expired row rather than duplicate the ask"
    );
    assert!(
        reopened.expires_at > now,
        "the live request must carry a usable window, or the retry is stuck"
    );
    assert_eq!(
        reopened.state,
        ApprovalState::Pending,
        "the reopened request must be pending, not decided"
    );

    let decided = store
        .decide_guard_tool_approval(aiec_core::storage::ApprovalDecisionRequest {
            tenant: stored.tenant_id,
            sandbox,
            request_id: reopened.id,
            decision: ApprovalState::Granted,
            decided_by_key_id: Uuid::new_v4(),
            decided_by_label: "key:operator",
            at: now + Duration::seconds(1),
        })
        .await
        .unwrap();
    assert!(
        decided.is_some(),
        "a retry after expiry must produce a request an operator can act on"
    );
}

/// The reopen is judged against the store's own clock, not the caller's
/// `created_at`.
///
/// This is the only input where the two clocks disagree. A client replaying a
/// recorded request resends the original `created_at` while asking for a fresh
/// window, so the caller's clock says the stored deadline is still in the
/// future (it is later than a creation time from ten minutes ago) and returns
/// the stale row unchanged — leaving the ask permanently stuck — while the
/// store's own clock sees the deadline has closed and reopens it. Postgres
/// reads `now()`, so without the store clock the two backends would disagree
/// about the same request.
#[tokio::test]
async fn a_retry_asking_for_a_new_window_is_judged_against_the_store_clock() {
    let store = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let sandbox = Uuid::new_v4();
    let requester = Uuid::new_v4();

    // An original ask whose window has since closed.
    let created = Utc::now() - Duration::minutes(10);
    let mut first = pending(tenant, sandbox, requester, DIGEST, created);
    first.expires_at = created + Duration::seconds(30);
    let stored = store.put_guard_tool_approval(first).await.unwrap();
    assert!(
        stored.expires_at <= Utc::now(),
        "the test needs an already-closed window to retry after"
    );

    // The retry carries the original `created_at` — a client resending a recorded
    // request — but asks for a fresh window, and is a distinct call rather than a
    // replay of the same row.
    let mut retry = pending(tenant, sandbox, requester, DIGEST, created);
    retry.expires_at = Utc::now() + Duration::minutes(5);
    let reopened = store.put_guard_tool_approval(retry).await.unwrap();

    assert_eq!(
        reopened.id, stored.id,
        "reopening must reuse the expired row rather than duplicate the ask"
    );
    assert!(
        reopened.expires_at > Utc::now(),
        "the store's own clock must decide the reopen; a stale `created_at` on the \
retry must not leave the ask stuck with a window that has already closed"
    );
    assert_eq!(
        reopened.created_at, stored.created_at,
        "when the ask was made is what was asked, and a retry does not restate it"
    );
}

/// The security-relevant half of the reopen: a retry must not extend a request
/// that is still open. If it could, the asker could keep an approval alive
/// indefinitely by retrying it, so it would never actually go stale while
/// waiting for a human.
#[tokio::test]
async fn a_retry_cannot_push_back_a_deadline_still_open() {
    let store = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let sandbox = Uuid::new_v4();
    let requester = Uuid::new_v4();
    let now = Utc::now();

    let mut first = pending(tenant, sandbox, requester, DIGEST, now);
    first.expires_at = now + Duration::seconds(30);
    let stored = store.put_guard_tool_approval(first).await.unwrap();

    // The same ask again, asking for a much longer window.
    let mut greedy = pending(tenant, sandbox, requester, DIGEST, now);
    greedy.expires_at = now + Duration::hours(24);
    let again = store.put_guard_tool_approval(greedy).await.unwrap();

    assert_eq!(again.id, stored.id);
    assert_eq!(
        again.expires_at, stored.expires_at,
        "an operator is judging this request; a retry must not move its deadline"
    );
    assert_eq!(
        again.created_at, stored.created_at,
        "when the ask was made is what was asked"
    );

    // The deadline that actually binds is the short one, not the day-long one
    // the retry asked for.
    let decided = store
        .decide_guard_tool_approval(aiec_core::storage::ApprovalDecisionRequest {
            tenant: stored.tenant_id,
            sandbox,
            request_id: again.id,
            decision: ApprovalState::Granted,
            decided_by_key_id: Uuid::new_v4(),
            decided_by_label: "key:operator",
            at: stored.expires_at + Duration::seconds(1),
        })
        .await
        .unwrap();
    assert!(
        decided.is_none(),
        "the retry's longer window must not have become the binding deadline"
    );
}

/// Asking again after a refusal is a new ask, not a replay of the one somebody
/// already turned down.
#[tokio::test]
async fn asking_again_after_a_denial_is_a_new_request() {
    let store = MemoryRepository::new();
    let tenant = Uuid::new_v4();
    let sandbox = Uuid::new_v4();
    let requester = Uuid::new_v4();
    let now = Utc::now();

    let stored = store
        .put_guard_tool_approval(pending(tenant, sandbox, requester, DIGEST, now))
        .await
        .unwrap();
    let denied = store
        .decide_guard_tool_approval(aiec_core::storage::ApprovalDecisionRequest {
            tenant: stored.tenant_id,
            sandbox,
            request_id: stored.id,
            decision: ApprovalState::Denied,
            decided_by_key_id: Uuid::new_v4(),
            decided_by_label: "key:operator",
            at: now + Duration::seconds(1),
        })
        .await
        .unwrap()
        .expect("a denial must be recorded");

    let again = store
        .put_guard_tool_approval(pending(tenant, sandbox, requester, DIGEST, now))
        .await
        .unwrap();
    assert_ne!(
        again.id, denied.id,
        "a refused ask must not be resurrected by asking again"
    );
    assert_eq!(again.state, ApprovalState::Pending);
}
