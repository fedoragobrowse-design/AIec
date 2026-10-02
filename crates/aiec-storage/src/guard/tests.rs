use super::*;
use aiec_core::{CoreError, Principal, RuntimeKind, Scope};
use chrono::Duration;
use std::sync::Arc;

fn budget(identity: GuardIdentity) -> GuardBudgetState {
    GuardBudgetState {
        identity,
        expires_at: Utc::now() + Duration::minutes(10),
        max_model_requests: 17,
        max_bytes_in: 34,
        max_bytes_out: 51,
        model_requests: 0,
        bytes_in: 0,
        bytes_out: 0,
        quarantined: false,
    }
}

fn incident(identity: GuardIdentity, fence: GuardFence) -> GuardIncident {
    let genesis = "0".repeat(64);
    GuardIncident {
        id: Uuid::new_v4(),
        identity,
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

async fn fixture() -> (Arc<MemoryRepository>, GuardBudgetState, GuardFence) {
    let repository = MemoryRepository::new();
    let now = Utc::now();
    let identity = GuardIdentity {
        sandbox_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        policy_hash: "a".repeat(64),
    };
    let fence = GuardFence {
        lease_id: Uuid::new_v4(),
        generation: 2,
    };
    let sandbox = Sandbox {
        id: identity.sandbox_id,
        tenant_id: identity.tenant_id,
        node_id: Some(Uuid::new_v4()),
        image_id: "test".into(),
        state: SandboxState::Running,
        runtime: RuntimeKind::Firecracker,
        cpu: 1,
        memory_mb: 64,
        disk_mb: 512,
        timeout_seconds: 600,
        network: Default::default(),
        environment: Default::default(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    };
    repository.create_sandbox(sandbox.clone()).await.unwrap();
    repository.data.write().await.leases.insert(
        fence.lease_id,
        WorkerLease {
            id: fence.lease_id,
            tenant_id: identity.tenant_id,
            sandbox_id: identity.sandbox_id,
            node_id: sandbox.node_id.unwrap(),
            generation: 3,
            status: "active".into(),
            reason: None,
            expires_at: now + Duration::minutes(10),
            created_at: now,
            updated_at: now,
        },
    );
    let budget = budget(identity);
    repository.put_guard_budget(budget.clone()).await.unwrap();
    (repository, budget, fence)
}

#[tokio::test]
async fn concurrent_reservations_commit_exact_ceiling_and_all_dimensions_atomically() {
    let (repository, budget, fence) = fixture().await;
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let repository = repository.clone();
        let identity = budget.identity.clone();
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
    let state = repository
        .get_guard_budget(budget.identity.tenant_id, budget.identity.sandbox_id)
        .await
        .unwrap();
    assert_eq!(
        (state.model_requests, state.bytes_in, state.bytes_out),
        (17, 34, 51)
    );
    assert!(
        repository
            .list_expired_guard_budgets(Utc::now())
            .await
            .unwrap()
            .contains(&state)
    );
    assert_eq!(
        repository.put_guard_budget(budget.clone()).await.unwrap(),
        state
    );
    let mut changed = budget;
    changed.expires_at += Duration::seconds(1);
    assert!(matches!(
        repository.put_guard_budget(changed).await,
        Err(StoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn lifetime_byte_ceiling_and_overflow_refuse_without_partial_debits() {
    let (repository, budget, fence) = fixture().await;
    assert!(
        repository
            .reserve_guard_budget(
                budget.identity.clone(),
                fence,
                BudgetDebit {
                    model_requests: 1,
                    bytes_in: 35,
                    bytes_out: 0
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .get_guard_budget(budget.identity.tenant_id, budget.identity.sandbox_id)
            .await
            .unwrap(),
        budget
    );
    // Seed already-accounted usage at the boundary to exercise the u64 overflow branch.
    {
        let mut data = repository.data.write().await;
        let state = data
            .guard_budgets
            .get_mut(&budget.identity.sandbox_id)
            .unwrap();
        state.max_bytes_out = u64::MAX;
        state.bytes_out = u64::MAX;
    }
    assert!(
        repository
            .reserve_guard_budget(
                budget.identity.clone(),
                fence,
                BudgetDebit {
                    model_requests: 1,
                    bytes_out: 1,
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    let before = repository
        .get_guard_budget(budget.identity.tenant_id, budget.identity.sandbox_id)
        .await
        .unwrap();
    assert_eq!(before.model_requests, 0);
    let expired_at = Utc::now() - Duration::seconds(1);
    repository
        .data
        .write()
        .await
        .guard_budgets
        .get_mut(&budget.identity.sandbox_id)
        .unwrap()
        .expires_at = expired_at;
    assert!(matches!(
        repository
            .reserve_guard_budget(budget.identity.clone(), fence, BudgetDebit::default())
            .await,
        Err(StoreError::QuotaExceeded(_))
    ));
    assert_eq!(
        repository
            .list_expired_guard_budgets(Utc::now())
            .await
            .unwrap()[0]
            .expires_at,
        expired_at
    );
}

#[tokio::test]
async fn an_approved_policy_change_rebinds_the_budget_without_refilling_it() {
    let (repository, budget, fence) = fixture().await;
    repository
        .put_guard_budget(budget.clone())
        .await
        .expect("budget initialized");
    repository
        .reserve_guard_budget(
            budget.identity.clone(),
            fence,
            BudgetDebit {
                model_requests: 5,
                bytes_in: 11,
                bytes_out: 13,
            },
        )
        .await
        .expect("the sandbox spends under its own policy");

    // The human approves a change: the policy identity moves, and the budget
    // follows it rather than being replaced by a fresh allowance.
    let mut approved = budget.clone();
    approved.identity.policy_hash = "c".repeat(64);
    let rebound = repository
        .put_guard_budget(approved.clone())
        .await
        .expect("the budget follows the approved policy");
    assert_eq!(rebound.identity, approved.identity);
    assert_eq!(rebound.model_requests, 5);
    assert_eq!(rebound.bytes_in, 11);
    assert_eq!(rebound.bytes_out, 13);
    assert_eq!(rebound.max_model_requests, budget.max_model_requests);

    // The ceilings themselves do not move, in either direction.
    let mut raised = approved.clone();
    raised.max_model_requests = budget.max_model_requests + 1;
    assert!(matches!(
        repository.put_guard_budget(raised).await,
        Err(StoreError::Conflict(_))
    ));

    // And the sandbox still spends against the ceiling it started with.
    let spent = repository
        .reserve_guard_budget(
            approved.identity.clone(),
            fence,
            BudgetDebit {
                model_requests: 12,
                bytes_in: 0,
                bytes_out: 0,
            },
        )
        .await
        .expect("the remaining allowance survives the approval");
    assert_eq!(spent.model_requests, 17);
}

#[tokio::test]
async fn tenant_policy_and_stale_ownership_cannot_spend_or_quarantine() {
    let (repository, budget, fence) = fixture().await;
    let tenant = budget.identity.tenant_id;
    let id = budget.identity.sandbox_id;
    let foreign = Uuid::new_v4();
    assert!(matches!(
        repository.get_guard_budget(foreign, id).await,
        Err(StoreError::NotFound)
    ));
    let mut identity = budget.identity.clone();
    identity.tenant_id = foreign;
    assert!(matches!(
        repository
            .reserve_guard_budget(identity, fence, BudgetDebit::default())
            .await,
        Err(StoreError::NotFound)
    ));
    let mut wrong_policy = budget.identity.clone();
    wrong_policy.policy_hash = "b".repeat(64);
    assert!(
        repository
            .reserve_guard_budget(wrong_policy, fence, BudgetDebit::default())
            .await
            .is_err()
    );
    for stale in [
        GuardFence {
            lease_id: Uuid::new_v4(),
            ..fence
        },
        GuardFence {
            generation: 4,
            ..fence
        },
        GuardFence {
            generation: 0,
            ..fence
        },
    ] {
        assert!(
            repository
                .reserve_guard_budget(budget.identity.clone(), stale, BudgetDebit::default())
                .await
                .is_err()
        );
        assert!(
            repository
                .mark_guard_quarantined(tenant, id, stale)
                .await
                .is_err()
        );
        assert!(
            repository
                .put_guard_incident(incident(budget.identity.clone(), stale))
                .await
                .is_err()
        );
    }
    repository
        .data
        .write()
        .await
        .leases
        .get_mut(&fence.lease_id)
        .unwrap()
        .expires_at = Utc::now() - Duration::seconds(1);
    assert!(
        repository
            .reserve_guard_budget(budget.identity.clone(), fence, BudgetDebit::default())
            .await
            .is_err()
    );
    assert_eq!(
        repository.get_guard_budget(tenant, id).await.unwrap(),
        budget
    );
}

#[tokio::test]
async fn quarantine_and_incident_retries_preserve_applied_stages_and_identity() {
    let (repository, budget, fence) = fixture().await;
    let tenant = budget.identity.tenant_id;
    let id = budget.identity.sandbox_id;
    let initial = incident(budget.identity.clone(), fence);
    repository
        .put_guard_incident(initial.clone())
        .await
        .unwrap();
    assert!(matches!(
        repository.get_guard_incident(Uuid::new_v4(), id).await,
        Err(StoreError::NotFound)
    ));
    let quarantined = repository
        .mark_guard_quarantined(tenant, id, fence)
        .await
        .unwrap();
    assert_eq!(
        repository
            .mark_guard_quarantined(tenant, id, fence)
            .await
            .unwrap(),
        quarantined
    );
    assert!(
        repository
            .put_guard_budget(budget.clone())
            .await
            .unwrap()
            .quarantined
    );
    assert!(
        repository
            .reserve_guard_budget(budget.identity.clone(), fence, BudgetDebit::default())
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
    let mut applied = initial.clone();
    applied.network_cut_at = Some(Utc::now());
    applied.paused_at = Some(Utc::now());
    applied.snapshot_id = Some("forensic-preservation".into());
    applied.report = "Authoritative quarantine report".into();
    applied.completed_at = Some(Utc::now());
    let completed = repository.put_guard_incident(applied).await.unwrap();
    let mut retry = initial;
    retry.id = Uuid::new_v4();
    let restored = repository.put_guard_incident(retry).await.unwrap();
    assert_eq!(restored.id, completed.id);
    assert_eq!(restored.triggered_at, completed.triggered_at);
    assert_eq!(restored.network_cut_at, completed.network_cut_at);
    assert_eq!(restored.paused_at, completed.paused_at);
    assert_eq!(restored.snapshot_id, completed.snapshot_id);
    assert_eq!(restored.completed_at, completed.completed_at);
    let mut rewritten = completed.clone();
    rewritten.snapshot_id = Some("different-state".into());
    assert!(repository.put_guard_incident(rewritten).await.is_err());
    let mut bad_anchor = completed.clone();
    bad_anchor.event_head = "f".repeat(64);
    assert!(repository.put_guard_incident(bad_anchor).await.is_err());
    assert_eq!(
        repository.get_guard_incident(tenant, id).await.unwrap().id,
        completed.id
    );
}

#[test]
fn narrow_guard_scopes_never_authorize_generic_mutation() {
    let principal = Principal {
        tenant_id: Uuid::new_v4(),
        key_id: Uuid::new_v4(),
        scopes: vec![
            Scope::parse("guard:read").unwrap(),
            Scope::parse("guard:heartbeat").unwrap(),
            Scope::parse("guard:quarantine").unwrap(),
        ],
    };
    assert!(principal.authorize(Scope::GuardRead).is_ok());
    assert!(principal.authorize(Scope::GuardHeartbeat).is_ok());
    assert!(principal.authorize(Scope::GuardQuarantine).is_ok());
    assert!(matches!(
        principal.authorize(Scope::SandboxesWrite),
        Err(CoreError::Forbidden(_))
    ));
    assert!(matches!(
        principal.authorize(Scope::SnapshotsWrite),
        Err(CoreError::Forbidden(_))
    ));
    let encoded = serde_json::to_value(&principal.scopes).unwrap();
    assert_eq!(
        serde_json::from_value::<Vec<Scope>>(encoded).unwrap(),
        principal.scopes
    );
}

#[tokio::test]
async fn incident_evidence_extends_only_its_original_verified_prefix() {
    use aiec_guard::events::{EventInput, GuardEvent};
    let (repository, budget, fence) = fixture().await;
    let identity = &budget.identity;
    let input = EventInput {
        sandbox_id: identity.sandbox_id,
        tenant_id: identity.tenant_id,
        policy_hash: identity.policy_hash.clone(),
        reason: "denied by policy".into(),
        ..Default::default()
    };
    let first = GuardEvent::new(Utc::now(), Uuid::new_v4(), input.clone(), "1".repeat(64)).unwrap();
    let mut pending = incident(identity.clone(), fence);
    pending.events.push(first.clone());
    pending.event_start_sequence = 41;
    pending.event_previous_hash = first.previous_hash.clone();
    pending.event_sequence = 41;
    pending.event_head = first.current_hash.clone();
    let original = repository
        .put_guard_incident(pending.clone())
        .await
        .unwrap();
    let second = GuardEvent::new(
        Utc::now(),
        Uuid::new_v4(),
        input.clone(),
        first.current_hash.clone(),
    )
    .unwrap();
    let mut extended = original.clone();
    extended.events.push(second.clone());
    extended.event_sequence = 42;
    extended.event_head = second.current_hash.clone();
    extended.network_cut_at = Some(Utc::now());
    let applied = repository.put_guard_incident(extended).await.unwrap();
    let retried = repository.put_guard_incident(pending).await.unwrap();
    assert_eq!(retried.events, vec![first.clone(), second]);
    assert_eq!(retried.event_sequence, 42);
    assert_eq!(retried.event_head, applied.event_head);
    assert_eq!(retried.network_cut_at, applied.network_cut_at);
    let mut forged = applied.clone();
    forged.events[0].reason = "changed after hashing".into();
    assert!(repository.put_guard_incident(forged).await.is_err());
    let mut substituted = applied.clone();
    let mut replacement_input = input;
    replacement_input.reason = "valid hash but different evidence".into();
    substituted.events = vec![
        GuardEvent::new(
            first.timestamp,
            first.event_id,
            replacement_input,
            first.previous_hash.clone(),
        )
        .unwrap(),
    ];
    substituted.event_sequence = 41;
    substituted.event_head = substituted.events[0].current_hash.clone();
    assert!(repository.put_guard_incident(substituted).await.is_err());
    let mut incomplete = applied;
    incomplete.completed_at = Some(Utc::now());
    assert!(repository.put_guard_incident(incomplete).await.is_err());
    assert_eq!(
        repository
            .get_guard_incident(identity.tenant_id, identity.sandbox_id)
            .await
            .unwrap()
            .id,
        original.id
    );
}
