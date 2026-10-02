//! Durable requests for high-risk tool calls, and the human decisions on them.
//!
//! A request is written by the asker and decided by a different authenticated
//! identity. Both halves are stored rather than held in memory: an approval
//! that disappeared on restart would either strand a call a human permitted or,
//! worse, read as a refusal nobody made.
//!
//! Deciding and spending are single conditional statements. That is what makes
//! a grant single-use and a self-approval impossible without a lock held across
//! the decision — two checks racing produce one winner and one refusal.

use aiec_core::{ApprovalDecisionRequest, ApprovalState, CoreError, GuardToolApproval};
use chrono::{DateTime, Utc};
use sqlx::Row;

use crate::{PostgresRepository, StoreError, core_error, database_error};

fn map(error: StoreError) -> CoreError {
    core_error(error)
}

/// A refusal the database itself declined, as opposed to an outage.
///
/// The check violations here are policy refusals with a reason — self-approval,
/// a rewritten request, a re-armed grant — not corruption, so they are reported
/// as `Forbidden` rather than as the generic invariant `database_error` maps
/// check violations to. `database_error` still does the SQLSTATE work.
fn refused(error: sqlx::Error) -> CoreError {
    if let sqlx::Error::Database(ref inner) = error
        && inner.code().as_deref() == Some("23514")
    {
        return CoreError::Forbidden("approval request was refused".into());
    }
    map(database_error(error))
}

fn approval_from_row(row: &sqlx::postgres::PgRow) -> Result<GuardToolApproval, StoreError> {
    let state = match row
        .try_get::<String, _>("state")
        .map_err(database_error)?
        .as_str()
    {
        "pending" => ApprovalState::Pending,
        "granted" => ApprovalState::Granted,
        "denied" => ApprovalState::Denied,
        other => {
            return Err(database_error(sqlx::Error::Protocol(format!(
                "unknown approval state {other:?}"
            ))));
        }
    };
    Ok(GuardToolApproval {
        id: row.try_get("id").map_err(database_error)?,
        tenant_id: row.try_get("tenant_id").map_err(database_error)?,
        sandbox_id: row.try_get("sandbox_id").map_err(database_error)?,
        tool: row.try_get("tool").map_err(database_error)?,
        request_digest: row.try_get("request_digest").map_err(database_error)?,
        detail: row.try_get("detail").map_err(database_error)?,
        requested_by_key_id: row.try_get("requested_by_key_id").map_err(database_error)?,
        requested_by_label: row.try_get("requested_by_label").map_err(database_error)?,
        state,
        decided_by_key_id: row.try_get("decided_by_key_id").map_err(database_error)?,
        decided_by_label: row.try_get("decided_by_label").map_err(database_error)?,
        decided_at: row.try_get("decided_at").map_err(database_error)?,
        expires_at: row.try_get("expires_at").map_err(database_error)?,
        consumed_at: row.try_get("consumed_at").map_err(database_error)?,
        created_at: row.try_get("created_at").map_err(database_error)?,
    })
}

const COLUMNS: &str = "id, tenant_id, sandbox_id, tool, request_digest, detail, \
                       requested_by_key_id, requested_by_label, state, decided_by_key_id, \
                       decided_by_label, decided_at, expires_at, consumed_at, created_at";

impl PostgresRepository {
    /// Records the asker's request. The state is always `pending`: this path
    /// cannot decide anything, which is what keeps an asker from approving.
    pub(crate) async fn put_guard_tool_approval(
        &self,
        approval: GuardToolApproval,
    ) -> Result<GuardToolApproval, CoreError> {
        let row = sqlx::query(&format!(
            "INSERT INTO guard_tool_approvals \
             (id, tenant_id, sandbox_id, tool, request_digest, detail, requested_by_key_id, \
              requested_by_label, state, decided_by_key_id, decided_by_label, decided_at, \
              expires_at, consumed_at, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',NULL,NULL,NULL,$9,NULL,$10) \
             RETURNING {COLUMNS}"
        ))
        .bind(approval.id)
        .bind(approval.tenant_id)
        .bind(approval.sandbox_id)
        .bind(&approval.tool)
        .bind(&approval.request_digest)
        .bind(&approval.detail)
        .bind(approval.requested_by_key_id)
        .bind(&approval.requested_by_label)
        .bind(approval.expires_at)
        .bind(approval.created_at)
        .fetch_one(&self.pool)
        .await
        .map_err(refused)?;
        approval_from_row(&row).map_err(map)
    }

    /// Applies an operator's decision to one pending request.
    ///
    /// The conditions are in the `WHERE` clause, not in Rust: `state = 'pending'`
    /// and `requested_by <> $3` are what make a second decision and a
    /// self-decision both no-ops here rather than something a later route
    /// forgets to re-check. The database trigger refuses the same pair again as
    /// a backstop, so neither layer is load-bearing alone.
    ///
    /// `ON CONFLICT ... WHERE state = 'pending'` resolves to the partial unique
    /// index on the live-request key, so a retry of the same ask returns the
    /// request already open instead of a second row for a human to wade
    /// through. `DO UPDATE` rather than `DO NOTHING` so the existing row is
    /// returned; with `DO NOTHING` the caller would get no row and would have
    /// to go looking for one it had just written.
    ///
    /// The trigger still forbids rewriting what was asked: identity, tool,
    /// digest, requester, label, detail and `created_at` are immutable on every
    /// update, and the update below touches none of them.
    ///
    /// `expires_at` is the one field the trigger now permits to move, and only
    /// for a pending row whose window has already closed — see migration
    /// `0022_guard_tool_approval_expired_reopen.sql`.
    ///
    /// On the relationship to migration 0021, which keeps the *oldest* pending
    /// row of each duplicate group. The two are complementary rather than in
    /// tension. 0021 picks the row whose expiry is earliest so collapsing
    /// duplicates cannot leave an operator holding a request whose window has
    /// already closed — it chooses which row closes soonest. The reopen makes
    /// that imminent closing recoverable instead of terminal; without it,
    /// "closes soonest" would quietly become "becomes undecidable and
    /// permanently unaskable".
    ///
    /// The alternative — leaving the closed row stale and minting a fresh one
    /// beside it — was rejected. `state` admits only `pending`, `granted` and
    /// `denied`, so retiring the old row out of the live index means writing it
    /// as `denied`. That fabricates an operator refusal nobody made and tells
    /// the asker "a human said no" for a request that merely timed out; 0021
    /// additionally requires a non-null reviewer label on any non-pending row,
    /// so it would have to invent an approver identity to satisfy the
    /// constraint. Refreshing in place asks the same question again with a
    /// real window, which is what the retry actually means.
    ///
    /// The reopen is a conditional `CASE` rather than a `DO UPDATE ... WHERE`.
    /// A conditional `WHERE` returns *no row* when the condition is false, so a
    /// retry of a still-open request would come back with nothing and the
    /// caller would fail on the fetch instead of being handed the request it
    /// asked about. With `CASE` every conflict returns the row, and the
    /// condition decides only what is written to it.
    ///
    /// Reopening is load-bearing rather than defensive. The partial index
    /// counts a row by `state`, so an expired `pending` row still holds the
    /// live slot; since `decide` requires an unexpired request, such a row can
    /// never be decided and no grant can ever be spent against it. Returning
    /// it unchanged would make the ask permanently unaskable.
    ///
    /// The comparison is against the database clock, not the caller's
    /// `created_at`. A client replaying a recorded request would otherwise
    /// carry its original timestamps and the row would never reopen, which is
    /// the failure this exists to prevent.
    ///
    /// An unexpired row is left alone and returned as-is, so a genuine retry
    /// joins the request an operator may already be looking at, and its
    /// deadline is not quietly pushed back by whoever happens to retry.
    pub(crate) async fn get_or_put_guard_tool_approval(
        &self,
        approval: GuardToolApproval,
    ) -> Result<GuardToolApproval, CoreError> {
        let row = sqlx::query(&format!(
            "INSERT INTO guard_tool_approvals \
             (id, tenant_id, sandbox_id, tool, request_digest, detail, requested_by_key_id, \
              requested_by_label, state, decided_by_key_id, decided_by_label, decided_at, \
              expires_at, consumed_at, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',NULL,NULL,NULL,$9,NULL,$10) \
             ON CONFLICT (tenant_id, sandbox_id, requested_by_key_id, tool, request_digest) \
             WHERE state = 'pending' \
             DO UPDATE SET \
                 expires_at = CASE WHEN guard_tool_approvals.expires_at <= now() \
                                   THEN EXCLUDED.expires_at \
                                   ELSE guard_tool_approvals.expires_at END \
             RETURNING {COLUMNS}"
        ))
        .bind(approval.id)
        .bind(approval.tenant_id)
        .bind(approval.sandbox_id)
        .bind(&approval.tool)
        .bind(&approval.request_digest)
        .bind(&approval.detail)
        .bind(approval.requested_by_key_id)
        .bind(&approval.requested_by_label)
        .bind(approval.expires_at)
        .bind(approval.created_at)
        .fetch_one(&self.pool)
        .await
        .map_err(refused)?;
        approval_from_row(&row).map_err(map)
    }

    /// Applies an operator's decision to one pending request.
    ///
    /// The conditions are in the `WHERE` clause, not in Rust: `state = 'pending'`
    /// and `requested_by <> $3` are what make a second decision and a
    /// self-decision both no-ops here rather than something a later route
    /// forgets to re-check. The database trigger refuses the same pair again as
    /// a backstop, so neither layer is load-bearing alone.
    pub(crate) async fn decide_guard_tool_approval(
        &self,
        request: ApprovalDecisionRequest<'_>,
    ) -> Result<Option<GuardToolApproval>, CoreError> {
        let state = match request.decision {
            ApprovalState::Granted => "granted",
            ApprovalState::Denied => "denied",
            ApprovalState::Pending => return Ok(None),
        };
        // `requested_by_key_id <> $3` is the self-approval refusal, on the
        // key id rather than the label: a label like `key:<uuid>/oncall` would
        // otherwise make the same key compare unequal to itself.
        //
        // `expires_at > $4` refuses to decide a request that has already timed
        // out. Without it an operator can grant an expired ask, and the grant
        // is then dead on arrival: `consume_guard_tool_approval` will never
        // spend it, so the queue would show a decision that can never be used
        // and the asker would have to ask again from scratch.
        let row = sqlx::query(&format!(
            "UPDATE guard_tool_approvals \
             SET state = $5, decided_by_key_id = $3, decided_by_label = $7, decided_at = $4 \
             WHERE id = $1 AND tenant_id = $2 AND sandbox_id = $6 \
               AND state = 'pending' AND requested_by_key_id <> $3 AND expires_at > $4 \
             RETURNING {COLUMNS}"
        ))
        .bind(request.request_id)
        .bind(request.tenant)
        .bind(request.decided_by_key_id)
        .bind(request.at)
        .bind(state)
        .bind(request.sandbox)
        .bind(request.decided_by_label)
        .fetch_optional(&self.pool)
        .await
        .map_err(refused)?;
        row.as_ref().map(approval_from_row).transpose().map_err(map)
    }

    /// Every request recorded against a sandbox, newest first.
    ///
    /// State and expiry are left for the caller to evaluate, so the decision is
    /// made against what the row says at the instant it is asked rather than
    /// against whatever a reaper last tidied.
    pub(crate) async fn list_guard_tool_approvals(
        &self,
        tenant: uuid::Uuid,
        sandbox: uuid::Uuid,
    ) -> Result<Vec<GuardToolApproval>, CoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM guard_tool_approvals \
             WHERE tenant_id = $1 AND sandbox_id = $2 ORDER BY created_at DESC, id"
        ))
        .bind(tenant)
        .bind(sandbox)
        .fetch_all(&self.pool)
        .await
        .map_err(refused)?;
        rows.iter()
            .map(approval_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(map)
    }

    /// Spends a granted, unspent, unexpired approval for exactly this call.
    ///
    /// `None` means somebody else won the race, the grant expired, it was
    /// already spent, or it never matched. All four are refusals, and the
    /// caller is not told which — the distinction would tell a probing agent
    /// how many approvals exist.
    pub(crate) async fn consume_guard_tool_approval(
        &self,
        tenant: uuid::Uuid,
        sandbox: uuid::Uuid,
        tool: &str,
        request_digest: &str,
        requested_by_key_id: uuid::Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<GuardToolApproval>, CoreError> {
        // `requested_by_key_id = $6` binds the grant to the key that asked for
        // it. Without it, any sandbox-write key in the tenant could spend
        // another harness's approval for an identical call — the approval would
        // be real, and it would still be the wrong one.
        let row = sqlx::query(&format!(
            "UPDATE guard_tool_approvals SET consumed_at = $5 \
             WHERE id = ( \
               SELECT id FROM guard_tool_approvals \
               WHERE tenant_id = $1 AND sandbox_id = $2 AND tool = $3 \
                 AND request_digest = $4 AND requested_by_key_id = $6 \
                 AND state = 'granted' \
                 AND consumed_at IS NULL AND expires_at > $5 \
               ORDER BY decided_at DESC, id \
               FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) RETURNING {COLUMNS}"
        ))
        .bind(tenant)
        .bind(sandbox)
        .bind(tool)
        .bind(request_digest)
        .bind(now)
        .bind(requested_by_key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(refused)?;
        row.as_ref().map(approval_from_row).transpose().map_err(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::tests::{drop_test_schema, isolated_repository_and_tenant};
    use aiec_core::new_id;
    use uuid::Uuid;

    /// A digest of the shape the API accepts. The content is arbitrary: these
    /// tests are about the lifecycle around it, and the canonicalisation of
    /// what goes *into* it is tested where it is computed.
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_DIGEST: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn pending(
        sandbox_id: Uuid,
        requester: Uuid,
        digest: &str,
        now: DateTime<Utc>,
    ) -> GuardToolApproval {
        GuardToolApproval {
            id: new_id(),
            sandbox_id,
            tenant_id: new_id(),
            tool: "sandbox.write_file".into(),
            request_digest: digest.into(),
            detail: Some("/etc/rc".into()),
            requested_by_key_id: requester,
            requested_by_label: format!("key:{requester}"),
            state: ApprovalState::Pending,
            decided_by_key_id: None,
            decided_by_label: None,
            decided_at: None,
            expires_at: now + chrono::Duration::minutes(5),
            consumed_at: None,
            created_at: now,
        }
    }

    /// Creates a sandbox in `tenant` so the foreign key has something to point
    /// at. The approval table references `sandboxes(id, tenant_id)`, which is
    /// deliberate: an approval for a sandbox in another tenant should not be
    /// storable at all.
    async fn sandbox_for(repository: &PostgresRepository, tenant: Uuid) -> Uuid {
        let sandbox = crate::postgres::tests::sandbox_record(tenant);
        repository.create_sandbox(sandbox.clone()).await.unwrap();
        sandbox.id
    }

    /// The whole positive path, against a real database: ask, decide from a
    /// different identity, then spend the grant.
    ///
    /// Every step asserts the row rather than trusting the return value, so a
    /// query that reported success while writing the wrong thing fails here.
    #[tokio::test]
    async fn a_grant_from_another_identity_is_spendable_exactly_once() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let decider = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, requester, DIGEST, now);
        approval.tenant_id = tenant;

        let stored = repository.put_guard_tool_approval(approval).await.unwrap();
        assert_eq!(stored.state, ApprovalState::Pending);
        assert!(stored.decided_by_key_id.is_none());

        let granted = repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: stored.id,
                decision: ApprovalState::Granted,
                decided_by_key_id: decider,
                decided_by_label: &format!("key:{decider}"),
                at: now,
            })
            .await
            .unwrap()
            .expect("a distinct identity may grant");
        assert_eq!(granted.state, ApprovalState::Granted);
        assert_eq!(granted.decided_by_key_id, Some(decider));
        assert!(granted.consumed_at.is_none());

        let spent = repository
            .consume_guard_tool_approval(tenant, sandbox_id, &granted.tool, DIGEST, requester, now)
            .await
            .unwrap()
            .expect("the grant matches the call it was made for");
        assert!(spent.consumed_at.is_some());

        // One time only. The second spend matches no unconsumed row.
        let again = repository
            .consume_guard_tool_approval(tenant, sandbox_id, &granted.tool, DIGEST, requester, now)
            .await
            .unwrap();
        assert!(again.is_none(), "a spent approval is not a capability");

        drop_test_schema(&repository, admin, schema).await;
    }

    /// Two identical asks are one request.
    ///
    /// A refused call is retried, so the retry path is not hypothetical. If
    /// each retry added a row, an operator opening the queue would find a
    /// hundred identical pending requests and the one decision they are being
    /// asked for buried underneath them.
    #[tokio::test]
    async fn a_retry_of_the_same_ask_joins_the_request_already_open() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut first = pending(sandbox_id, requester, DIGEST, now);
        first.tenant_id = tenant;
        let mut retry = pending(sandbox_id, requester, DIGEST, now);
        retry.tenant_id = tenant;
        // Distinct ids, because the retry is a fresh call, not a replay of the
        // same row.
        assert_ne!(first.id, retry.id);

        let stored = repository
            .get_or_put_guard_tool_approval(first)
            .await
            .unwrap();
        let again = repository
            .get_or_put_guard_tool_approval(retry)
            .await
            .unwrap();
        assert_eq!(
            stored.id, again.id,
            "a retry must return the request already open, not mint a second one"
        );

        let rows: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {schema}.guard_tool_approvals \
             WHERE sandbox_id = $1 AND state = 'pending'"
        ))
        .bind(sandbox_id)
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(rows, 1, "exactly one live request may exist for an ask");
        drop_test_schema(&repository, admin, schema).await;
    }

    /// A pending row whose window has closed must not hold the live slot for
    /// ever.
    ///
    /// The partial unique index counts a row by `state`, not by whether anyone
    /// can still act on it, so an expired `pending` row still occupies it. That
    /// row can never be decided — `decide` requires an unexpired request — and
    /// `get_or_put` returns it unchanged, so every later retry of the same ask
    /// is handed back a request that no operator is able to grant and no
    /// consumer is able to spend. The ask is stuck permanently, with no way to
    /// ask again.
    #[tokio::test]
    async fn a_retry_after_the_open_request_expired_gets_a_usable_one() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        // Genuinely past due, judged by the database clock rather than by a
        // timestamp this test invents: the reopen condition reads `now()`.
        let created = Utc::now() - chrono::Duration::minutes(10);
        let mut first = pending(sandbox_id, requester, DIGEST, created);
        first.tenant_id = tenant;
        first.expires_at = created + chrono::Duration::seconds(30);
        let stored = repository
            .get_or_put_guard_tool_approval(first)
            .await
            .unwrap();
        let now = Utc::now();
        assert!(
            stored.expires_at < now,
            "the test needs an already-expired request to retry after"
        );

        // The retry arrives after the open request's window has closed.
        let mut retry = pending(sandbox_id, requester, DIGEST, now);
        retry.tenant_id = tenant;
        retry.expires_at = now + chrono::Duration::minutes(5);
        let reopened = repository
            .get_or_put_guard_tool_approval(retry)
            .await
            .unwrap();

        // The same row is reused with a fresh window rather than a second row
        // minted: the ask is the same question, and a retry should not grow the
        // operator queue. What matters is that the request handed back is one
        // somebody can actually act on.
        assert_eq!(
            reopened.id, stored.id,
            "reopening must reuse the expired row rather than duplicate the ask"
        );
        assert!(
            reopened.expires_at > now,
            "the live request must carry a usable window, or the retry is stuck"
        );
        assert!(
            reopened.state == ApprovalState::Pending,
            "the reopened request must be pending, not decided"
        );

        // And it is actually decidable, not merely newer.
        let decider = new_id();
        let decided = repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: reopened.id,
                decision: ApprovalState::Granted,
                decided_by_key_id: decider,
                decided_by_label: "key:operator",
                at: now + chrono::Duration::seconds(1),
            })
            .await
            .unwrap();
        assert!(
            decided.is_some(),
            "a retry after expiry must produce a request an operator can act on"
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    /// The security-relevant half of the reopen: a retry must not extend a
    /// request that is still open.
    ///
    /// Migration `0022` permits `expires_at` to move, so the guarantee that a
    /// deadline cannot be pushed back is now carried by the *condition* on
    /// that permission rather than by refusing every update. If that condition
    /// were dropped, the asker could keep a request alive indefinitely by
    /// retrying it — handing back the same row with a fresh window every time —
    /// so an approval never actually goes stale while the asker waits for a
    /// human. The reopened window must apply only to a row that has already
    /// closed.
    #[tokio::test]
    async fn a_retry_cannot_push_back_the_deadline_of_a_request_still_open() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut first = pending(sandbox_id, requester, DIGEST, now);
        first.tenant_id = tenant;
        first.expires_at = now + chrono::Duration::seconds(30);
        let stored = repository
            .get_or_put_guard_tool_approval(first)
            .await
            .unwrap();

        // The same ask again, asking for a much longer window.
        let mut retry = pending(sandbox_id, requester, DIGEST, now);
        retry.tenant_id = tenant;
        retry.expires_at = now + chrono::Duration::hours(24);
        let again = repository
            .get_or_put_guard_tool_approval(retry)
            .await
            .unwrap();

        assert_eq!(again.id, stored.id);
        assert_eq!(
            again.expires_at, stored.expires_at,
            "an operator is judging this request; a retry must not move its deadline"
        );
        assert_eq!(
            again.created_at, stored.created_at,
            "when the ask was made is what was asked"
        );

        // And the deadline the operator sees is the one that actually binds:
        // the short window, not the day-long one the retry asked for.
        let decider = new_id();
        let too_late = stored.expires_at + chrono::Duration::seconds(1);
        let decided = repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: again.id,
                decision: ApprovalState::Granted,
                decided_by_key_id: decider,
                decided_by_label: "key:operator",
                at: too_late,
            })
            .await
            .unwrap();
        assert!(
            decided.is_none(),
            "the retry's longer window must not have become the binding deadline"
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    /// A different argument digest is a different question, so it must not be
    /// folded into the request already open — that would silently widen one
    /// human decision to cover a call they never saw.
    #[tokio::test]
    async fn a_different_call_is_not_joined_to_an_open_request() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut first = pending(sandbox_id, requester, DIGEST, now);
        first.tenant_id = tenant;
        let mut other = pending(sandbox_id, requester, OTHER_DIGEST, now);
        other.tenant_id = tenant;

        let stored = repository
            .get_or_put_guard_tool_approval(first)
            .await
            .unwrap();
        let separate = repository
            .get_or_put_guard_tool_approval(other)
            .await
            .unwrap();
        assert_ne!(
            stored.id, separate.id,
            "an approval binds one call's arguments, so a different digest is a new ask"
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    /// After a denial, asking again is a new ask rather than a replay of the
    /// one somebody already turned down.
    #[tokio::test]
    async fn asking_again_after_a_denial_is_a_new_request() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let decider = new_id();
        let now = Utc::now();
        let mut first = pending(sandbox_id, requester, DIGEST, now);
        first.tenant_id = tenant;
        let stored = repository
            .get_or_put_guard_tool_approval(first)
            .await
            .unwrap();
        assert!(
            repository
                .decide_guard_tool_approval(ApprovalDecisionRequest {
                    tenant,
                    sandbox: sandbox_id,
                    request_id: stored.id,
                    decision: ApprovalState::Denied,
                    decided_by_key_id: decider,
                    decided_by_label: "key:operator",
                    at: now + chrono::Duration::seconds(1),
                })
                .await
                .unwrap()
                .is_some()
        );

        let mut again = pending(sandbox_id, requester, DIGEST, now);
        again.tenant_id = tenant;
        let second = repository
            .get_or_put_guard_tool_approval(again)
            .await
            .unwrap();
        assert_ne!(
            stored.id, second.id,
            "a denied ask must not be resurrected by a retry"
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    /// An operator cannot grant a request that has already timed out.
    ///
    /// It would be refused later anyway — `consume` requires an unexpired
    /// grant — but recording it as granted puts a decision in the operator
    /// queue that can never be used, and tells the asker a human said yes.
    #[tokio::test]
    async fn an_expired_request_cannot_be_decided() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let decider = new_id();
        let created = Utc::now();
        let mut approval = pending(sandbox_id, requester, DIGEST, created);
        approval.tenant_id = tenant;
        approval.expires_at = created + chrono::Duration::seconds(30);
        let stored = repository.put_guard_tool_approval(approval).await.unwrap();
        let expired_at = stored.expires_at + chrono::Duration::seconds(1);

        let decided = repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: stored.id,
                decision: ApprovalState::Granted,
                decided_by_key_id: decider,
                decided_by_label: "key:operator",
                at: expired_at,
            })
            .await
            .unwrap();
        assert!(
            decided.is_none(),
            "an expired request must stay undecided rather than be granted"
        );
        let after = repository
            .list_guard_tool_approvals(tenant, sandbox_id)
            .await
            .unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].state, ApprovalState::Pending);
        assert!(after[0].decided_at.is_none());
        drop_test_schema(&repository, admin, schema).await;
    }

    /// A grant is for one call, not for a tool at one path. Different bytes are
    /// a different digest and match nothing.
    #[tokio::test]
    async fn a_grant_does_not_cover_a_different_call() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, requester, DIGEST, now);
        approval.tenant_id = tenant;
        let stored = repository.put_guard_tool_approval(approval).await.unwrap();
        repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: stored.id,
                decision: ApprovalState::Granted,
                decided_by_key_id: new_id(),
                decided_by_label: "key:operator",
                at: now,
            })
            .await
            .unwrap();

        let other = repository
            .consume_guard_tool_approval(
                tenant,
                sandbox_id,
                "sandbox.write_file",
                OTHER_DIGEST,
                requester,
                now,
            )
            .await
            .unwrap();
        assert!(
            other.is_none(),
            "an approval of one call must not authorise another"
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    /// Another key in the same tenant, holding only `SandboxesWrite`, must not
    /// be able to spend an approval somebody else requested. Without this the
    /// requester binding is decoration.
    #[tokio::test]
    async fn another_tenant_key_cannot_spend_this_approvers_grant() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, requester, DIGEST, now);
        approval.tenant_id = tenant;
        let stored = repository.put_guard_tool_approval(approval).await.unwrap();
        repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: stored.id,
                decision: ApprovalState::Granted,
                decided_by_key_id: new_id(),
                decided_by_label: "key:operator",
                at: now,
            })
            .await
            .unwrap();

        let stolen = repository
            .consume_guard_tool_approval(
                tenant,
                sandbox_id,
                "sandbox.write_file",
                DIGEST,
                new_id(), // a different key with sandbox write
                now,
            )
            .await
            .unwrap();
        assert!(stolen.is_none(), "the grant belongs to the key that asked");
        drop_test_schema(&repository, admin, schema).await;
    }

    /// Scope separation cannot be the only defence: one key may hold both
    /// `SandboxesWrite` and `GuardApprove`, and `admin` satisfies both. The
    /// database refuses the self-decision, and the store reports no decision
    /// rather than an error the caller might retry past.
    #[tokio::test]
    async fn a_key_holding_every_scope_still_cannot_approve_its_own_request() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let omnipotent = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, omnipotent, DIGEST, now);
        approval.tenant_id = tenant;
        let stored = repository.put_guard_tool_approval(approval).await.unwrap();

        let decided = repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: stored.id,
                decision: ApprovalState::Granted,
                decided_by_key_id: omnipotent,
                decided_by_label: &format!("key:{omnipotent}/admin"),
                at: now,
            })
            .await;
        assert!(
            decided.unwrap().is_none(),
            "self-approval is refused however much authority the key holds"
        );
        // And the request is still waiting, not quietly granted on the way to
        // being reported as a refusal.
        let after = repository
            .list_guard_tool_approvals(tenant, sandbox_id)
            .await
            .unwrap();
        assert_eq!(after[0].state, ApprovalState::Pending);
        assert!(after[0].decided_by_key_id.is_none());
        drop_test_schema(&repository, admin, schema).await;
    }

    /// A decision is final. Re-deciding a granted request - to deny it, or to
    /// re-grant it under a different operator - is refused.
    #[tokio::test]
    async fn a_decided_request_cannot_be_decided_again() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, requester, DIGEST, now);
        approval.tenant_id = tenant;
        let stored = repository.put_guard_tool_approval(approval).await.unwrap();
        repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: stored.id,
                decision: ApprovalState::Denied,
                decided_by_key_id: new_id(),
                decided_by_label: "key:operator",
                at: now,
            })
            .await
            .unwrap()
            .expect("denial by another identity is allowed");

        let again = repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: stored.id,
                decision: ApprovalState::Granted,
                decided_by_key_id: new_id(),
                decided_by_label: "key:other-operator",
                at: now,
            })
            .await;
        assert!(
            again.unwrap().is_none(),
            "a denial is not a placeholder to be overwritten"
        );
        // The original decision is the one that stands, with the operator who
        // actually made it.
        let after = repository
            .list_guard_tool_approvals(tenant, sandbox_id)
            .await
            .unwrap();
        assert_eq!(after[0].state, ApprovalState::Denied);
        assert_eq!(after[0].decided_by_label.as_deref(), Some("key:operator"));
        drop_test_schema(&repository, admin, schema).await;
    }

    /// An unanswered request has a lifetime. Past it, spending the grant fails
    /// even though it was genuinely made.
    #[tokio::test]
    async fn an_expired_grant_is_not_spendable() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, requester, DIGEST, now);
        approval.tenant_id = tenant;
        let stored = repository.put_guard_tool_approval(approval).await.unwrap();
        repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: stored.id,
                decision: ApprovalState::Granted,
                decided_by_key_id: new_id(),
                decided_by_label: "key:operator",
                at: now,
            })
            .await
            .unwrap();

        let late = repository
            .consume_guard_tool_approval(
                tenant,
                sandbox_id,
                "sandbox.write_file",
                DIGEST,
                requester,
                now + chrono::Duration::hours(1),
            )
            .await
            .unwrap();
        assert!(
            late.is_none(),
            "an expired approval is no longer an approval"
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    /// A denial is a decision, so a spend must find nothing - it must not find
    /// a pending row and treat the absence of a grant as permission.
    #[tokio::test]
    async fn a_denied_request_is_not_spendable() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, requester, DIGEST, now);
        approval.tenant_id = tenant;
        let stored = repository.put_guard_tool_approval(approval).await.unwrap();
        repository
            .decide_guard_tool_approval(ApprovalDecisionRequest {
                tenant,
                sandbox: sandbox_id,
                request_id: stored.id,
                decision: ApprovalState::Denied,
                decided_by_key_id: new_id(),
                decided_by_label: "key:operator",
                at: now,
            })
            .await
            .unwrap();

        let denied = repository
            .consume_guard_tool_approval(
                tenant,
                sandbox_id,
                "sandbox.write_file",
                DIGEST,
                requester,
                now,
            )
            .await
            .unwrap();
        assert!(denied.is_none());
        drop_test_schema(&repository, admin, schema).await;
    }

    /// The operator's queue has to be reachable, or the flow cannot be driven.
    #[tokio::test]
    async fn the_operator_can_list_what_is_waiting() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, requester, DIGEST, now);
        approval.tenant_id = tenant;
        let stored = repository.put_guard_tool_approval(approval).await.unwrap();

        let listed = repository
            .list_guard_tool_approvals(tenant, sandbox_id)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, stored.id);
        assert_eq!(listed[0].state, ApprovalState::Pending);
        // The digest travels with it, so the operator decides about a specific
        // call rather than about a tool.
        assert_eq!(listed[0].request_digest, DIGEST);
        drop_test_schema(&repository, admin, schema).await;
    }

    /// The migration's own constraints are only as good as their presence. This
    /// asserts the table, the check constraint and the trigger actually exist
    /// in a migrated database, because the whole argument for putting the
    /// self-approval refusal in SQL rather than only in the route is that the
    /// database enforces it whatever the caller.
    #[tokio::test]
    async fn the_database_itself_carries_the_constraints() {
        let Some((repository, _tenant, _admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        // Scoped to this test's schema: `information_schema.triggers` reports
        // every schema the search path can see, and these tests each create
        // one, so an unscoped count grows with the number of tests that ran
        // before rather than with what the migration installed.
        let trigger: String = sqlx::query_scalar(
            "SELECT count(*)::text FROM pg_trigger \
             WHERE tgname = 'guard_tool_approval_monotonic' \
             AND NOT tgisinternal \
             AND tgrelid = format('guard_tool_approvals')::regclass \
             AND tgrelid = to_regclass($1)",
        )
        .bind(format!("{schema}.guard_tool_approvals"))
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(trigger, "1", "the decision trigger must exist");

        // The column constraints, as distinct from the trigger.
        let check: String = sqlx::query_scalar(
            "SELECT count(*)::text FROM pg_constraint \
             WHERE conrelid = to_regclass($1) AND contype = 'c'",
        )
        .bind(format!("{schema}.guard_tool_approvals"))
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert!(
            check.parse::<i64>().unwrap() >= 4,
            "expected the state, digest and timestamp check constraints, found {check}"
        );
        drop_test_schema(&repository, _admin, schema).await;
    }

    /// The trigger is a backstop for writes that never come through the store,
    /// and a backstop nobody exercises is indistinguishable from a comment.
    /// These insert directly, so the only thing that can refuse is the
    /// migration itself.
    #[tokio::test]
    async fn the_trigger_refuses_a_self_approval_written_behind_the_store() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let key = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, key, DIGEST, now);
        approval.tenant_id = tenant;

        let insert = format!(
            "INSERT INTO {schema}.guard_tool_approvals \
             (id, sandbox_id, tenant_id, tool, request_digest, detail, \
              requested_by_key_id, requested_by_label, state, expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'granted', $9, $10)"
        );
        // The same key on both sides of the decision.
        let result = sqlx::query(&insert)
            .bind(approval.id)
            .bind(sandbox_id)
            .bind(tenant)
            .bind(&approval.tool)
            .bind(&approval.request_digest)
            .bind(&approval.detail)
            .bind(key)
            .bind(format!("key:{key}"))
            .bind(approval.expires_at)
            .bind(approval.created_at)
            .execute(&repository.pool)
            .await;
        assert!(
            result.is_err(),
            "a direct write must not be able to grant a key's own request"
        );
        drop_test_schema(&repository, admin, schema).await;
    }

    /// And it refuses a request whose requester is rewritten after the fact.
    /// The store never does this, but a bug that did would be invisible from
    /// the store's own tests.
    #[tokio::test]
    async fn the_trigger_refuses_a_rewritten_requester() {
        let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await
        else {
            return;
        };
        let sandbox_id = sandbox_for(&repository, tenant).await;
        let requester = new_id();
        let now = Utc::now();
        let mut approval = pending(sandbox_id, requester, DIGEST, now);
        approval.tenant_id = tenant;
        let stored = repository.put_guard_tool_approval(approval).await.unwrap();

        let rewritten = sqlx::query(&format!(
            "UPDATE {schema}.guard_tool_approvals SET requested_by_key_id = $1 WHERE id = $2"
        ))
        .bind(new_id())
        .bind(stored.id)
        .execute(&repository.pool)
        .await;
        assert!(
            rewritten.is_err(),
            "the requester is fixed once asked; a later write cannot reassign it"
        );
        drop_test_schema(&repository, admin, schema).await;
    }
}
