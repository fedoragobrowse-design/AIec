use super::*;
use aiec_core::GuardProposal;
use aiec_core::storage::{BudgetDebit, GuardBudgetState, GuardFence, GuardIdentity, GuardIncident};
use aiec_guard::proposals::{ProposalRequest, ProposalState};

fn budget(tenant: Uuid, id: Uuid) -> GuardBudgetState {
    GuardBudgetState {
        identity: GuardIdentity {
            tenant_id: tenant,
            sandbox_id: id,
            policy_hash: "a".repeat(64),
        },
        expires_at: Utc::now() + chrono::Duration::minutes(10),
        max_model_requests: 17,
        max_bytes_in: 34,
        max_bytes_out: 51,
        model_requests: 0,
        bytes_in: 0,
        bytes_out: 0,
        quarantined: false,
    }
}
fn incident(state: &GuardBudgetState, fence: GuardFence) -> GuardIncident {
    let genesis = "0".repeat(64);
    GuardIncident {
        id: new_id(),
        identity: state.identity.clone(),
        fence,
        rules: Vec::new(),
        triggered_at: Utc::now(),
        network_cut_at: None,
        paused_at: None,
        snapshot_id: None,
        completed_at: None,
        events: Vec::new(),
        event_start_sequence: 1,
        event_previous_hash: genesis.clone(),
        event_sequence: 0,
        event_head: genesis,
        errors: Vec::new(),
        notified_at: None,
        report: String::new(),
    }
}
async fn place(
    repository: &PostgresRepository,
    tenant: Uuid,
    worker: Uuid,
) -> (GuardBudgetState, GuardFence) {
    let placed = schedule_test_sandbox(repository, tenant, new_id(), sandbox(tenant), Some(worker))
        .await
        .unwrap();
    let state = budget(tenant, placed.sandbox.id);
    let fence = GuardFence {
        lease_id: placed.lease_id,
        generation: placed.lease_generation,
    };
    (state, fence)
}

#[tokio::test]
async fn postgres_guard_exact_ceiling_survives_reopen_and_cannot_be_reset() {
    let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await else {
        return;
    };
    let worker = register_test_worker(&repository, tenant).await;
    let (state, fence) = place(&repository, tenant, worker).await;
    repository.put_guard_budget(state.clone()).await.unwrap();
    let renewed = repository
        .renew_worker_lease(tenant, fence.lease_id, fence.generation, 120)
        .await
        .unwrap();
    assert!(renewed.generation > fence.generation);
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let repository = repository.clone();
        let identity = state.identity.clone();
        tasks.push(tokio::spawn(async move {
            repository
                .reserve_guard_budget(
                    identity,
                    fence,
                    BudgetDebit {
                        model_requests: 1,
                        bytes_in: 2,
                        bytes_out: 3,
                    },
                )
                .await
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 17);
    let spent = repository
        .get_guard_budget(tenant, state.identity.sandbox_id)
        .await
        .unwrap();
    assert_eq!(
        (spent.model_requests, spent.bytes_in, spent.bytes_out),
        (17, 34, 51)
    );
    assert_eq!(
        repository.put_guard_budget(state.clone()).await.unwrap(),
        spent
    );
    let mut changed = state.clone();
    changed.max_bytes_in += 1;
    assert!(matches!(
        repository.put_guard_budget(changed).await,
        Err(StoreError::Conflict(_))
    ));
    let mut foreign = state.identity.clone();
    foreign.tenant_id = new_id();
    assert!(matches!(
        repository
            .reserve_guard_budget(foreign, fence, BudgetDebit::default())
            .await,
        Err(StoreError::NotFound)
    ));
    for stale in [
        GuardFence {
            lease_id: new_id(),
            ..fence
        },
        GuardFence {
            generation: renewed.generation + 1,
            ..fence
        },
        GuardFence {
            generation: 0,
            ..fence
        },
    ] {
        assert!(
            repository
                .reserve_guard_budget(state.identity.clone(), stale, BudgetDebit::default())
                .await
                .is_err()
        );
        assert!(
            repository
                .mark_guard_quarantined(tenant, state.identity.sandbox_id, stale)
                .await
                .is_err()
        );
        assert!(
            repository
                .put_guard_incident(incident(&state, stale))
                .await
                .is_err()
        );
    }
    let pending = repository
        .put_guard_incident(incident(&state, fence))
        .await
        .unwrap();
    // A genuinely independent pool reloads committed state, not a process-local cache.
    let search_path = format!("SET search_path TO {schema}");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query(&search_path).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let reopened = PostgresRepository::from_pool(pool);
    assert_eq!(
        reopened
            .get_guard_budget(tenant, state.identity.sandbox_id)
            .await
            .unwrap(),
        spent
    );
    assert_eq!(
        reopened.put_guard_budget(state.clone()).await.unwrap(),
        spent
    );
    let durable_pending = reopened
        .get_guard_incident(tenant, state.identity.sandbox_id)
        .await
        .unwrap();
    assert_eq!(durable_pending.id, pending.id);
    assert!(durable_pending.completed_at.is_none());
    assert!(
        reopened
            .list_expired_guard_budgets(Utc::now(), aiec_core::storage::REAPER_GUARD_WINDOW)
            .await
            .unwrap()
            .contains(&spent)
    );
    assert!(
        reopened
            .reserve_guard_budget(
                state.identity.clone(),
                fence,
                BudgetDebit {
                    model_requests: 1,
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .get_guard_budget(tenant, state.identity.sandbox_id)
            .await
            .unwrap(),
        spent
    );
    reopened.pool.close().await;
    drop_test_schema(&repository, admin, schema).await;
}

#[tokio::test]
async fn postgres_guard_lifetime_quarantine_and_pending_progress_are_durable_and_latched() {
    let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await else {
        return;
    };
    let worker = register_test_worker(&repository, tenant).await;
    let (mut expired, expired_fence) = place(&repository, tenant, worker).await;
    expired.expires_at = Utc::now() - chrono::Duration::seconds(1);
    repository.put_guard_budget(expired.clone()).await.unwrap();
    assert!(matches!(
        repository
            .reserve_guard_budget(
                expired.identity.clone(),
                expired_fence,
                BudgetDebit::default()
            )
            .await,
        Err(StoreError::QuotaExceeded(_))
    ));
    assert!(
        repository
            .list_expired_guard_budgets(Utc::now(), aiec_core::storage::REAPER_GUARD_WINDOW)
            .await
            .unwrap()
            .contains(&expired)
    );
    let (state, fence) = place(&repository, tenant, worker).await;
    let id = state.identity.sandbox_id;
    repository.put_guard_budget(state.clone()).await.unwrap();
    let pending = repository
        .put_guard_incident(incident(&state, fence))
        .await
        .unwrap();
    let quarantined = repository
        .mark_guard_quarantined(tenant, id, fence)
        .await
        .unwrap();
    assert_eq!(quarantined.state, SandboxState::Quarantined);
    // Idempotent: a second mark changes nothing. Compared field by field rather
    // than as whole structs, because the row round trip truncates timestamps to
    // the database's microsecond precision and that difference is not what this
    // assertion is about.
    let repeated = repository
        .mark_guard_quarantined(tenant, id, fence)
        .await
        .unwrap();
    assert_eq!(repeated.id, quarantined.id);
    assert_eq!(repeated.state, quarantined.state);
    assert_eq!(repeated.tenant_id, quarantined.tenant_id);
    assert_eq!(repeated.node_id, quarantined.node_id);
    assert_eq!(repeated.runtime_path, quarantined.runtime_path);
    assert_eq!(
        repository.get_sandbox(tenant, id).await.unwrap().state,
        SandboxState::Quarantined
    );
    assert!(
        repository
            .put_guard_budget(state.clone())
            .await
            .unwrap()
            .quarantined
    );
    assert!(
        repository
            .reserve_guard_budget(state.identity.clone(), fence, BudgetDebit::default())
            .await
            .is_err()
    );
    for next in [
        SandboxState::Paused,
        SandboxState::Running,
        SandboxState::Starting,
        SandboxState::Failed,
        SandboxState::Destroying,
    ] {
        assert!(
            repository
                .update_state(tenant, id, SandboxState::Quarantined, next, None)
                .await
                .is_err()
        );
    }
    assert!(repository.delete_sandbox(tenant, id).await.is_err());
    let mut applied = pending.clone();
    applied.network_cut_at = Some(Utc::now());
    applied.paused_at = Some(Utc::now());
    applied.snapshot_id = Some("preserved-workspace".into());
    applied.report = "Authoritative report".into();
    applied.completed_at = Some(Utc::now());
    let completed = repository.put_guard_incident(applied).await.unwrap();
    let mut duplicate = pending;
    duplicate.id = new_id();
    let retained = repository.put_guard_incident(duplicate).await.unwrap();
    assert_eq!(retained.id, completed.id);
    assert_eq!(retained.snapshot_id, completed.snapshot_id);
    assert_eq!(retained.network_cut_at, completed.network_cut_at);
    assert_eq!(retained.paused_at, completed.paused_at);
    assert_eq!(retained.completed_at, completed.completed_at);
    assert!(matches!(
        repository.get_guard_incident(new_id(), id).await,
        Err(StoreError::NotFound)
    ));
    let before_capacity = node_capacity(&repository).await;
    expire_lease(&repository, fence.lease_id).await;
    repository.reconcile_expired_leases(100).await.unwrap();
    assert_eq!(node_capacity(&repository).await, before_capacity);
    assert!(
        repository
            .reassign_expired_lease(fence.lease_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repository.get_sandbox(tenant, id).await.unwrap().state,
        SandboxState::Quarantined
    );
    assert!(
        !repository
            .list_stranded_sandboxes(Utc::now() + chrono::Duration::seconds(1), 100)
            .await
            .unwrap()
            .iter()
            .any(|sandbox| sandbox.id == id)
    );
    assert!(
        sqlx::query("UPDATE sandboxes SET state='paused' WHERE id=$1")
            .bind(id)
            .execute(&repository.pool)
            .await
            .is_err()
    );
    assert!(sqlx::query("UPDATE guard_budgets SET payload=jsonb_set(payload,'{quarantined}','false') WHERE sandbox_id=$1").bind(id).execute(&repository.pool).await.is_err());
    assert!(
        repository.put_guard_incident(completed).await.is_err(),
        "expired authority cannot update an incident"
    );
    drop_test_schema(&repository, admin, schema).await;
}

/// A release is the only exit from a quarantine, and it is the only exit that
/// is meant to work: it has to move both latches, in one transaction, with the
/// operator's name on both. What it must not become is a way to disable the
/// latches, which is what the previous implementation did.
#[tokio::test]
async fn postgres_guard_release_clears_both_latches_and_leaves_them_armed() {
    let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await else {
        return;
    };
    let worker = register_test_worker(&repository, tenant).await;
    let (state, fence) = place(&repository, tenant, worker).await;
    let id = state.identity.sandbox_id;
    repository.put_guard_budget(state.clone()).await.unwrap();
    repository
        .mark_guard_quarantined(tenant, id, fence)
        .await
        .unwrap();

    let released = repository
        .release_guard_quarantine(tenant, id, "operator@example.com")
        .await
        .unwrap();
    assert_eq!(released.state, SandboxState::Paused);
    assert!(
        !repository
            .get_guard_budget(tenant, id)
            .await
            .unwrap()
            .quarantined,
        "the durable mark is what a later read reports, so a release that leaves it is not a release"
    );
    let (mark_at, mark_by): (Option<chrono::DateTime<Utc>>, Option<String>) = sqlx::query_as(
        "SELECT guard_released_at, guard_released_by FROM guard_budgets WHERE sandbox_id=$1",
    )
    .bind(id)
    .fetch_one(&repository.pool)
    .await
    .unwrap();
    assert!(mark_at.is_some() && mark_by.as_deref() == Some("operator@example.com"));

    // The old implementation disabled the sandbox latch for the table, which is
    // catalog state and permanent: nothing in the release path ever turned it
    // back on. The catalog is the honest place to assert that it is still
    // armed, and it is a property no assertion about rows can see.
    for trigger in ["guard_quarantine_latched", "guard_budget_monotone"] {
        let (enabled,): (String,) = sqlx::query_as(
            "SELECT tgenabled::text FROM pg_trigger
              WHERE tgrelid IN ('sandboxes'::regclass, 'guard_budgets'::regclass)
                AND tgname = $1",
        )
        .bind(trigger)
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(enabled, "O", "{trigger} must not be left disabled");
    }
    // A release marker is the one thing an ordinary write cannot produce, and
    // this budget is no longer quarantined, which is exactly the case the
    // marker branch refuses.
    assert!(
        sqlx::query("UPDATE guard_budgets SET guard_released_at = now() WHERE sandbox_id=$1")
            .bind(id)
            .execute(&repository.pool)
            .await
            .is_err(),
        "a release marker applies only to a quarantined budget"
    );
    assert!(
        repository
            .release_guard_quarantine(tenant, id, "operator@example.com")
            .await
            .is_err(),
        "a release is not repeatable: the second one has nothing to release"
    );
    drop_test_schema(&repository, admin, schema).await;
}

/// The memory repository has no trigger, so the narrowing 0023 exists to make -
/// that an approved policy may rebind a budget to the hash the sandbox now
/// carries - is a property only the database can refuse. 0024 replaced the
/// whole function to add the release path and re-froze the entire identity
/// object, which put the rebind back exactly where 0023 found it, and the
/// memory test stayed green throughout. The catalog is the place that can see
/// it, so the catalog is where it is asserted.
#[tokio::test]
async fn postgres_guard_budget_rebinds_its_policy_hash_without_moving_ownership() {
    let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await else {
        return;
    };
    let worker = register_test_worker(&repository, tenant).await;
    let (state, fence) = place(&repository, tenant, worker).await;
    repository.put_guard_budget(state.clone()).await.unwrap();
    repository
        .reserve_guard_budget(
            state.identity.clone(),
            fence,
            BudgetDebit {
                model_requests: 5,
                bytes_in: 11,
                bytes_out: 13,
            },
        )
        .await
        .unwrap();

    let mut approved = state.clone();
    approved.identity.policy_hash = "c".repeat(64);
    let rebound = repository
        .put_guard_budget(approved.clone())
        .await
        .expect("an approved policy rebinds the budget it was opened against");
    assert_eq!(rebound.identity, approved.identity);
    assert_eq!(
        (rebound.model_requests, rebound.bytes_in, rebound.bytes_out),
        (5, 11, 13),
        "usage spent under the previous policy is still spent"
    );

    // The narrowing is to the two ownership fields, not to the identity as a
    // whole and not to policy_hash: everything else about the identity is
    // still frozen.
    for (_, column, value) in [
        (
            "identity.sandbox_id",
            "{identity,sandbox_id}",
            new_id().to_string(),
        ),
        (
            "identity.tenant_id",
            "{identity,tenant_id}",
            new_id().to_string(),
        ),
    ] {
        assert!(
            sqlx::query(&format!(
                "UPDATE guard_budgets SET payload=jsonb_set(payload, '{column}', to_jsonb($2::text)) WHERE sandbox_id=$1"
            ))
            .bind(approved.identity.sandbox_id)
            .bind(value)
            .execute(&repository.pool)
            .await
            .is_err(),
            "{column} is ownership and may not move"
        );
    }
    // And an approval still cannot buy a second allowance.
    let mut raised = approved.clone();
    raised.max_model_requests = approved.max_model_requests + 1;
    assert!(matches!(
        repository.put_guard_budget(raised).await,
        Err(StoreError::Conflict(_))
    ));
    drop_test_schema(&repository, admin, schema).await;
}

/// A proposal id is looked up on its own, so the row that comes back need not
/// belong to the caller. The in-memory store refuses that outright; the SQL
/// write has to refuse it too, or the two backends disagree about who owns a
/// proposal — and the database trigger cannot help, because `tenant_id` is not
/// in the SET clause, so the update looks like a same-tenant write to it.
///
/// The attack here presents the owner's row exactly as the database returned it,
/// changing only the tenant it claims to be writing as. That is the shape that
/// matters, and it is the only one that reaches the update: the immutability
/// check compares `agent_id`, `request`, `base_policy_hash` and `created_at`
/// against the stored row, so anything else is refused for an unrelated reason.
///
/// `created_at` is the subtle one. It is built from `Utc::now()`, which is
/// nanoseconds, and stored as `timestamptz`, which is microseconds — so a
/// caller round-tripping the row gets a value that is no longer equal to the
/// one it sent. Rebuilding from the stored proposal is not incidental: it is
/// what a caller that read the row actually holds.
/// A sandbox's proposal history is paged, and the page says where it stopped.
///
/// Nothing reclaims a proposal row and `guard:propose` is unbounded, so this
/// table grows for as long as the sandbox lives. Reading it whole made the
/// response a function of how long the tenant had been on the system. The page
/// carries its successor for the same reason the sandbox list does: a caller
/// that stops has to be able to say it stopped at a boundary rather than having
/// been handed a truncated list that reads as complete.
#[tokio::test]
async fn a_sandbox_proposal_history_is_paged_and_says_where_it_stopped() {
    let Some((repository, owner, _admin, _schema)) = isolated_repository_and_tenant().await else {
        return;
    };
    let worker = super::register_test_worker(&repository, owner).await;
    let sandbox_id =
        schedule_test_sandbox(&repository, owner, new_id(), sandbox(owner), Some(worker))
            .await
            .unwrap()
            .sandbox
            .id;

    // Every row shares one timestamp, which is the case that makes the id
    // tie-breaker load-bearing rather than decorative: without it a keyset
    // predicate has no way to say which rows a page already returned.
    let created_at = Utc::now();
    for _ in 0..5 {
        repository
            .put_guard_proposal(GuardProposal {
                id: new_id(),
                tenant_id: owner,
                sandbox_id,
                agent_id: "key:owner".into(),
                request: ProposalRequest {
                    summary: "add an egress destination".into(),
                    allow: Vec::new(),
                },
                base_policy_hash: "b".repeat(64),
                state: ProposalState::Pending,
                decided_by: None,
                decided_at: None,
                created_at,
            })
            .await
            .unwrap();
    }

    let first = repository
        .list_guard_proposals(owner, sandbox_id, 2, None)
        .await
        .unwrap();
    assert_eq!(first.proposals.len(), 2, "the bound must reach the query");
    let cursor = first.next.expect("three more rows cannot fit in one page");

    let second = repository
        .list_guard_proposals(owner, sandbox_id, 2, Some(cursor))
        .await
        .unwrap();
    assert_eq!(second.proposals.len(), 2);

    let third = repository
        .list_guard_proposals(owner, sandbox_id, 2, Some(second.next.unwrap()))
        .await
        .unwrap();
    assert_eq!(
        third.proposals.len(),
        1,
        "the last page is short and must say so"
    );
    assert!(
        third.next.is_none(),
        "a page that returned the last row must not claim another follows"
    );

    // Paging to the end must show every row exactly once. This is the failure a
    // cursor pointing at the held-back row would cause: that row is skipped and
    // a caller paging to the end is never shown it.
    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = repository
            .list_guard_proposals(owner, sandbox_id, 2, cursor)
            .await
            .unwrap();
        seen.extend(page.proposals.iter().map(|row| row.id));
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 5, "a row was skipped or repeated: {seen:?}");
}
/// The bound has to reach the database, and nothing else can show that.
///
/// The rows are trimmed in Rust after the fetch, so removing `LIMIT` from the
/// SQL leaves every behavioural test in this file passing while the database
/// goes on materialising the sandbox's entire proposal history for a page of
/// fifty. That is the exact shape of the defect the paging exists to remove,
/// reached by a code change that reads like a simplification. So the plan is
/// asked instead of the result: a top-level `Limit` node is the push-down, and
/// its absence is the bug.
#[tokio::test]
async fn the_proposal_page_bound_is_pushed_down_to_the_database() {
    let Some((repository, owner, _admin, _schema)) = isolated_repository_and_tenant().await else {
        return;
    };

    let plan: serde_json::Value = sqlx::query_scalar(&format!(
        "EXPLAIN (FORMAT JSON) {}",
        crate::postgres::guard::proposals::LIST_PROPOSALS_SQL
    ))
    .bind(owner)
    .bind(new_id())
    .bind(None::<chrono::DateTime<Utc>>)
    .bind(None::<Uuid>)
    .bind(50_i64)
    .fetch_one(&repository.pool)
    .await
    .expect("the plan must run");

    assert!(
        has_top_level_limit(&plan),
        "the proposal page must be limited by the database, not only trimmed \
         afterwards: {plan}"
    );

    // The approval queue, which is the more exposed of the two: the sandbox
    // itself can ask for a row with nothing but `sandboxes:write`.
    let plan: serde_json::Value = sqlx::query_scalar(&format!(
        "EXPLAIN (FORMAT JSON) {}",
        crate::postgres::guard::approvals::LIST_APPROVALS_SQL
    ))
    .bind(owner)
    .bind(new_id())
    .bind(None::<chrono::DateTime<Utc>>)
    .bind(None::<Uuid>)
    .bind(50_i64)
    .fetch_one(&repository.pool)
    .await
    .expect("the plan must run");
    assert!(
        has_top_level_limit(&plan),
        "the approval page must be limited by the database, not only trimmed \
         afterwards: {plan}"
    );
}

/// Walks an `EXPLAIN (FORMAT JSON)` document looking for a `Limit` node.
///
/// The document is an array whose first element holds the root under `Plan`,
/// and `Plans` holds its children. A limit buried under a scan is not the same
/// as a limit bounding the whole statement, so this reads the root only.
fn has_top_level_limit(plan: &serde_json::Value) -> bool {
    plan[0]["Plan"]["Node Type"] == "Limit"
}

#[tokio::test]
async fn a_proposal_id_from_another_tenant_cannot_be_decided_through_it() {
    let Some((repository, owner, _admin, _schema)) = isolated_repository_and_tenant().await else {
        return;
    };

    // A second, real tenant. It needs no sandbox of its own: the ownership
    // check reads the row's tenant and sandbox, and a foreign tenant id alone
    // is enough to make the write a stranger's, which is the case under test.
    let stranger = new_id();
    repository
        .put_tenant(TenantRecord {
            id: stranger,
            name: format!("stranger-{stranger}"),
            created_at: Utc::now(),
        })
        .await
        .unwrap();

    let worker = super::register_test_worker(&repository, owner).await;
    let sandbox_id =
        schedule_test_sandbox(&repository, owner, new_id(), sandbox(owner), Some(worker))
            .await
            .unwrap()
            .sandbox
            .id;

    let proposal = GuardProposal {
        id: new_id(),
        tenant_id: owner,
        sandbox_id,
        agent_id: "key:owner".into(),
        request: ProposalRequest {
            summary: "add an egress destination".into(),
            allow: Vec::new(),
        },
        base_policy_hash: "b".repeat(64),
        state: ProposalState::Pending,
        decided_by: None,
        decided_at: None,
        created_at: Utc::now(),
    };
    let proposal_id = proposal.id;
    repository.put_guard_proposal(proposal).await.unwrap();
    // Re-read, because the insert returns the value it was handed rather than
    // what the row now holds. Without this the caller is still holding the
    // nanosecond `created_at` it sent, and the comparison below fails on
    // precision rather than on ownership.
    let stored = repository
        .get_guard_proposal(owner, sandbox_id, proposal_id)
        .await
        .unwrap();
    assert!(matches!(stored.state, ProposalState::Pending));

    // The identical row, now presented by a different tenant, approving it.
    // Only `tenant_id` differs, so nothing else refuses it.
    let attempt = repository
        .put_guard_proposal(GuardProposal {
            tenant_id: stranger,
            state: ProposalState::Approved {
                policy_hash: "c".repeat(64),
            },
            decided_by: Some("operator".into()),
            decided_at: Some(Utc::now()),
            ..stored
        })
        .await;
    assert!(
        attempt.is_err(),
        "a proposal id from another tenant was decided: {attempt:?}"
    );

    // And the owner's proposal is exactly as it was left.
    let after = repository
        .get_guard_proposal(owner, sandbox_id, stored.id)
        .await
        .unwrap();
    assert!(
        matches!(after.state, ProposalState::Pending),
        "the owner's proposal was moved to {:?}",
        after.state
    );
    assert_eq!(after.decided_by, None, "a stranger wrote the operator name");
    assert_eq!(after.decided_at, None, "a stranger wrote the decision time");
}

/// A sandbox's snapshot history is paged, and says where it stopped.
///
/// Snapshots are retained until somebody deletes them and nothing prunes them,
/// so this table grows for the life of the sandbox. It was read whole.
#[tokio::test]
async fn a_snapshot_history_is_paged_and_says_where_it_stopped() {
    let Some((repository, owner, _admin, _schema)) = isolated_repository_and_tenant().await else {
        return;
    };
    let worker = super::register_test_worker(&repository, owner).await;
    let sandbox_id =
        schedule_test_sandbox(&repository, owner, new_id(), sandbox(owner), Some(worker))
            .await
            .unwrap()
            .sandbox
            .id;

    // One timestamp for all five rows, so `id` is the only thing that can order
    // them. A keyset without it cannot say which rows a page already returned.
    let created_at = Utc::now();
    let mut ids = Vec::new();
    for index in 0..5 {
        let id = new_id();
        ids.push(id);
        repository
            .put_snapshot(aiec_core::Snapshot {
                id,
                tenant_id: owner,
                sandbox_id,
                object_key: format!("snapshots/{id}.tar"),
                size_bytes: 1024 + index,
                image_id: "img-test".into(),
                created_at,
            })
            .await
            .unwrap();
    }

    let first = repository
        .list_snapshots(owner, sandbox_id, 2, None)
        .await
        .unwrap();
    assert_eq!(first.snapshots.len(), 2, "the bound must reach the query");
    assert!(
        first.next.is_some(),
        "three more rows cannot fit in one page"
    );

    // Newest first, and the page must be internally ordered: a keyset that
    // returns the right rows in the wrong order makes the caller walk them
    // backwards.
    assert!(
        first.snapshots[0].created_at >= first.snapshots[1].created_at,
        "a page must come back newest first"
    );

    let last = repository
        .list_snapshots(owner, sandbox_id, 200, None)
        .await
        .unwrap();
    assert!(
        last.next.is_none(),
        "a page that returned the last row must not claim another follows"
    );

    // Paging to the end shows every row exactly once. This is the failure a
    // cursor aimed at the held-back row produces: that row is never returned to
    // anybody, and a caller paging to the end believes it saw everything.
    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = repository
            .list_snapshots(owner, sandbox_id, 2, cursor)
            .await
            .unwrap();
        seen.extend(page.snapshots.iter().map(|row| row.id));
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    seen.sort();
    ids.sort();
    assert_eq!(seen, ids, "every snapshot exactly once, none skipped");

    // Another tenant's sandbox history is not visible, and an unknown sandbox
    // is empty rather than an error.
    assert!(
        repository
            .list_snapshots(owner, new_id(), 200, None)
            .await
            .unwrap()
            .snapshots
            .is_empty()
    );
}

/// The page bound reaches the database, not only the trimming that follows.
///
/// The behavioural test above cannot see this: the rows are trimmed in Rust
/// after the fetch, so deleting `LIMIT` from the SQL leaves it passing while the
/// database goes on materialising every snapshot the sandbox ever had.
#[tokio::test]
async fn the_snapshot_page_bound_is_pushed_down_to_the_database() {
    let Some((repository, _owner, _admin, _schema)) = isolated_repository_and_tenant().await else {
        return;
    };
    let plan: serde_json::Value = sqlx::query_scalar(&format!(
        "EXPLAIN (FORMAT JSON) {}",
        crate::postgres::LIST_SNAPSHOTS_SQL
    ))
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .bind(None::<chrono::DateTime<Utc>>)
    .bind(None::<Uuid>)
    .bind(50_i64)
    .fetch_one(&repository.pool)
    .await
    .expect("the plan must run");
    // The document is an array whose first element holds the root under `Plan`
    // and its children under `Plans`. A limit buried under a scan is not a
    // limit bounding the statement.
    assert_eq!(
        plan[0]["Plan"]["Node Type"], "Limit",
        "the snapshot page must be limited by the database, not only trimmed \
         afterwards: {plan}"
    );
    let _ = tokio::time::timeout(Duration::from_secs(1), repository.pool.close()).await;
}

/// The reaper's window is work, not candidates.
///
/// Already-quarantined budgets are never destroyed until an operator releases
/// the sandbox, so those rows accumulate for as long as the tenant keeps the
/// machine. Reporting them meant the oldest rows - sandbox ids are time-ordered
/// - filled the window with work the reaper skips, and a budget that still
/// needed enforcing was never reached. Same property the memory store holds.
#[tokio::test]
async fn handled_guard_budgets_cannot_fill_the_reapers_window() {
    let Some((repository, tenant, admin, schema)) = isolated_repository_and_tenant().await else {
        return;
    };
    let window = aiec_core::storage::REAPER_GUARD_WINDOW;

    // The reaper's list is not tenant-scoped and quarantined sandboxes are the
    // ones a tenant has not released, so a realistic backlog spans tenants. The
    // default quota of eight active sandboxes per tenant is also why it cannot
    // all belong to one.
    let mut fleets: Vec<(Uuid, Uuid)> = Vec::new();
    for index in 0..12 {
        let owner = if index == 0 {
            tenant
        } else {
            let id = new_id();
            repository
                .put_tenant(TenantRecord {
                    id,
                    name: format!("reaper-window-{index}-{id}"),
                    created_at: Utc::now(),
                })
                .await
                .unwrap();
            id
        };
        // Each test worker offers two vCPUs.
        for _ in 0..4 {
            fleets.push((owner, register_test_worker(&repository, owner).await));
        }
    }
    let mut expected = Vec::new();
    for index in 0..(window + 5) {
        let handled = index < window;
        let (owner, worker) = fleets[index % fleets.len()];
        let (mut state, fence) = place(&repository, owner, worker).await;
        state.expires_at = Utc::now() - chrono::Duration::hours(1);
        repository.put_guard_budget(state.clone()).await.unwrap();
        if handled {
            repository
                .mark_guard_quarantined(owner, state.identity.sandbox_id, fence)
                .await
                .unwrap();
        } else {
            expected.push(state.identity.sandbox_id);
        }
    }
    expected.sort();

    let mut seen = Vec::new();
    let mut ticks = 0;
    loop {
        let tick = repository
            .list_expired_guard_budgets(Utc::now(), window)
            .await
            .unwrap();
        if tick.is_empty() {
            break;
        }
        assert!(
            tick.len() <= window,
            "a tick returned more than its own window"
        );
        ticks += 1;
        assert!(ticks <= 2, "the backlog should drain in a second tick");
        for budget in &tick {
            seen.push(budget.identity.sandbox_id);
        }
        // Quarantine so the next tick sees past them, as the reaper does.
        for budget in &tick {
            let _ = sqlx::query(
                "UPDATE guard_budgets SET payload = jsonb_set(payload, '{quarantined}', 'true') \
                 WHERE sandbox_id = $1",
            )
            .bind(budget.identity.sandbox_id)
            .execute(&repository.pool)
            .await
            .unwrap();
        }
    }
    seen.sort();
    assert_eq!(
        seen, expected,
        "ticking through the backlog should reach every budget that still needs \
         enforcing, exactly once"
    );
    repository.pool.close().await;
    drop_test_schema(&repository, admin, schema).await;
}

/// The window reaches the database. Without this the query materialises every
/// expired budget in the deployment and the bound only exists afterwards.
#[tokio::test]
async fn the_guard_reaper_window_is_pushed_down_to_the_database() {
    let Some((repository, _tenant, admin, schema)) = isolated_repository_and_tenant().await else {
        return;
    };
    let plan: serde_json::Value = sqlx::query_scalar(&format!(
        "EXPLAIN (FORMAT JSON) {}",
        crate::postgres::EXPIRED_GUARD_BUDGETS_SQL
    ))
    .bind(Utc::now())
    .bind(aiec_core::storage::REAPER_GUARD_WINDOW as i64)
    .fetch_one(&repository.pool)
    .await
    .expect("the plan must run");
    assert_eq!(
        plan[0]["Plan"]["Node Type"], "Limit",
        "the reaper's window must bound the query, not only the rows kept \
         afterwards: {plan}"
    );
    repository.pool.close().await;
    drop_test_schema(&repository, admin, schema).await;
}
