use super::*;
use aiec_core::storage::{BudgetDebit, GuardBudgetState, GuardFence, GuardIdentity, GuardIncident};

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
            .list_expired_guard_budgets(Utc::now())
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
            .list_expired_guard_budgets(Utc::now())
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
