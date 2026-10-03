//! PostgreSQL admission plus the real API/WorkerRuntime provisioning path.
use super::*;
use aiec_core::scheduler::{ScheduleRequest, Scheduler};
use aiec_core::storage::{MetadataStore, TenantRecord, WorkerRegistration};
use aiec_storage::{PostgresRepository, PostgresScheduler};
use async_trait::async_trait;
use axum::body::Body;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashSet;
use tokio::sync::Semaphore;
use tower::ServiceExt;
use worker::{
    WorkerClient, WorkerClientError, WorkerOperation, WorkerRequest, WorkerResponse, WorkerValue,
};

const WORKER_TOKEN: &str = "provision-regression-worker-token";

struct GatedWorker {
    creates: AtomicU64,
    first_create_entered: Semaphore,
    release_create: Semaphore,
    duplicate_entered: Semaphore,
    release_duplicate: Semaphore,
    start_entered: Semaphore,
    release_start: Semaphore,
    destroy_entered: Semaphore,
    release_destroy: Semaphore,
    failed_lease: Mutex<Option<Uuid>>,
    machines: Mutex<HashSet<Uuid>>,
    destroyed: Mutex<Vec<Uuid>>,
    requests: Mutex<Vec<(String, Uuid)>>,
}

impl GatedWorker {
    fn new() -> Self {
        Self {
            creates: AtomicU64::new(0),
            first_create_entered: Semaphore::new(0),
            release_create: Semaphore::new(0),
            duplicate_entered: Semaphore::new(0),
            release_duplicate: Semaphore::new(0),
            start_entered: Semaphore::new(0),
            release_start: Semaphore::new(0),
            destroy_entered: Semaphore::new(0),
            release_destroy: Semaphore::new(0),
            failed_lease: Mutex::new(None),
            machines: Mutex::new(HashSet::new()),
            destroyed: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

async fn gate(semaphore: &Semaphore) {
    tokio::time::timeout(std::time::Duration::from_secs(10), semaphore.acquire())
        .await
        .expect("provisioning gate was never reached")
        .unwrap()
        .forget();
}

#[async_trait]
impl WorkerClient for GatedWorker {
    async fn invoke(
        &self,
        endpoint: &str,
        request: WorkerRequest,
    ) -> Result<WorkerResponse, WorkerClientError> {
        self.requests
            .lock()
            .await
            .push((endpoint.to_owned(), request.lease_id));
        let result = match request.operation {
            WorkerOperation::Create { .. } => {
                let count = self.creates.fetch_add(1, Ordering::SeqCst);
                let inserted = self.machines.lock().await.insert(request.lease_id);
                if !inserted {
                    self.duplicate_entered.add_permits(1);
                    gate(&self.release_duplicate).await;
                    Err(CoreError::Backend("duplicate allocation refused".into()).into())
                } else {
                    if count == 0 {
                        self.first_create_entered.add_permits(1);
                        gate(&self.release_create).await;
                    }
                    Ok(WorkerValue::Unit)
                }
            }
            WorkerOperation::Start { .. } => {
                self.start_entered.add_permits(1);
                gate(&self.release_start).await;
                if *self.failed_lease.lock().await == Some(request.lease_id) {
                    Err(CoreError::Backend("owned start failed".into()).into())
                } else if !self.machines.lock().await.contains(&request.lease_id) {
                    Err(CoreError::NotFound("winner machine was destroyed".into()).into())
                } else {
                    Ok(WorkerValue::Unit)
                }
            }
            WorkerOperation::Destroy { .. } => {
                self.destroy_entered.add_permits(1);
                gate(&self.release_destroy).await;
                self.machines.lock().await.remove(&request.lease_id);
                self.destroyed.lock().await.push(request.lease_id);
                Ok(WorkerValue::Unit)
            }
            other => panic!("unexpected provisioning operation: {other:?}"),
        };
        Ok(WorkerResponse {
            request_id: request.request_id,
            result,
        })
    }

    async fn get_file_chunk(
        &self,
        _: &str,
        _: WorkerRequest,
        _: aiec_core::runtime::FileChunkRequest,
    ) -> Result<aiec_core::runtime::FileChunk, CoreError> {
        panic!("empty environment does not read files")
    }
}

struct Fixture {
    repository: Arc<PostgresRepository>,
    scheduler: Arc<PostgresScheduler>,
    client: Arc<GatedWorker>,
    state: AppState,
    tenant: Uuid,
    node: Uuid,
    admin: sqlx::PgPool,
    schema: String,
}

impl Fixture {
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("provision_test_{}", new_id().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let search_path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |connection, _| {
                let search_path = search_path.clone();
                Box::pin(async move {
                    sqlx::query(&search_path).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        let repository = Arc::new(PostgresRepository::from_pool(pool));
        repository.migrate().await.unwrap();
        let tenant = new_id();
        repository
            .put_tenant(TenantRecord {
                id: tenant,
                name: format!("provision-{tenant}"),
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        let node = new_id();
        let capabilities = aiec_core::runtime::RuntimeCapabilities {
            exec: true,
            files: true,
            docker_image: true,
            isolation: aiec_core::runtime::RuntimeIsolation::Container,
            ..Default::default()
        };
        repository.register_worker(WorkerRegistration {
            node_id: node, name: format!("provision-worker-{node}"), runtime: RuntimeKind::Docker,
            capabilities: capabilities.clone(), control_endpoint: "http://first-worker".into(),
            total_vcpus: 2, available_vcpus: 2,
            total_memory_bytes: 512 * 1_048_576, available_memory_bytes: 512 * 1_048_576,
            total_disk_bytes: 2048 * 1_048_576, available_disk_bytes: 2048 * 1_048_576,
            healthy: true, version: 1,
            metadata: json!({"pressure": aiec_core::host_pressure::HostPressure::from_measurements(
                format!("provision-host-{node}"), Utc::now(),
                aiec_core::host_pressure::HostMeasurements {
                    total_vcpus: Some(2), available_vcpus: Some(2),
                    total_memory_bytes: Some(512 * 1_048_576), memory_available_bytes: Some(512 * 1_048_576),
                    total_disk_bytes: Some(2048 * 1_048_576), disk_available_bytes: Some(2048 * 1_048_576),
                },
                aiec_core::host_pressure::HostReserves::from_mib(0, 0),
            ).to_metadata()}),
            started_at: Utc::now(), last_heartbeat: Utc::now(),
        }).await.unwrap();
        let scheduler = Arc::new(PostgresScheduler::new((*repository).clone()));
        let client = Arc::new(GatedWorker::new());
        let runtime = Arc::new(worker::WorkerRuntime::new(
            client.clone(),
            scheduler.clone(),
            capabilities,
        ));
        let platform = Platform::builder()
            .runtime(runtime)
            .metadata_store(repository.clone())
            .scheduler(scheduler.clone())
            .build()
            .unwrap();
        let state = AppState::new(platform)
            .with_runtime_kind(RuntimeKind::Docker)
            .with_worker_token(WORKER_TOKEN);
        Some(Self {
            repository,
            scheduler,
            client,
            state,
            tenant,
            node,
            admin,
            schema,
        })
    }

    async fn reconcile(&self, query: &str) -> (StatusCode, Value) {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/workers/reconcile{query}"))
            .header("authorization", format!("Bearer {WORKER_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let response = router(self.state.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn expire(&self, lease: Uuid) {
        sqlx::query("UPDATE sandbox_leases SET expires_at=now()-interval '1 second' WHERE id=$1")
            .bind(lease)
            .execute(&self.repository.pool)
            .await
            .unwrap();
    }

    async fn requests(&self) -> Vec<(String, Uuid)> {
        self.client.requests.lock().await.clone()
    }

    fn sandbox(&self) -> Sandbox {
        Sandbox {
            id: new_id(),
            tenant_id: self.tenant,
            node_id: None,
            image_id: "alpine:3.21".into(),
            state: SandboxState::Creating,
            runtime: RuntimeKind::Docker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: NetworkPolicy::Disabled,
            environment: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            runtime_path: None,
        }
    }

    fn launch(
        &self,
        request_id: Uuid,
        sandbox: Sandbox,
    ) -> tokio::task::JoinHandle<Result<ProvisionedSandbox, ApiFailure>> {
        let state = self.state.clone();
        let tenant = self.tenant;
        tokio::spawn(async move {
            provision_sandbox(
                &state,
                tenant,
                request_id,
                sandbox,
                Default::default(),
                None,
                false,
            )
            .await
        })
    }

    fn launch_run(
        &self,
        run: Uuid,
        request_id: Uuid,
        sandbox: Sandbox,
    ) -> tokio::task::JoinHandle<Result<ProvisionedSandbox, ApiFailure>> {
        let state = self.state.clone();
        let tenant = self.tenant;
        tokio::spawn(async move {
            provision_sandbox(
                &state,
                tenant,
                request_id,
                sandbox,
                Default::default(),
                Some(run),
                false,
            )
            .await
        })
    }

    async fn available(&self) -> i32 {
        sqlx::query_scalar("SELECT available_vcpus FROM nodes WHERE id=$1")
            .bind(self.node)
            .fetch_one(&self.repository.pool)
            .await
            .unwrap()
    }

    async fn close(self) {
        self.repository.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}

#[tokio::test]
async fn automatic_reconcile_leaves_a_run_owned_machine_alone() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    // A run attempt's executor owns this machine. Store-level eligibility
    // refuses it, so the maintenance pass must not rebuild it either.
    let run = aiec_core::run::Run {
        id: new_id(),
        tenant_id: f.tenant,
        state: aiec_core::run::RunState::Running,
        requested_at: Utc::now(),
        queued_at: None,
        started_at: None,
        completed_at: None,
        workload: aiec_core::run::WorkloadSpec::default(),
        resources: aiec_core::run::ResourceRequirements::default(),
        requirements: aiec_core::run::CapabilityRequirements::default(),
        placement: aiec_core::run::Placement::default(),
        results: aiec_core::run::RunResults::default(),
        failure_reason: None,
        retention: aiec_core::run::RetentionPolicy::default(),
        retained_sandbox_id: None,
        retained_until: None,
        idempotency_key: None,
        parent_run_id: None,
        matrix_id: None,
        matrix_cell: None,
    };
    f.repository.create_run(run.clone()).await.unwrap();
    // Admission links the machine to the attempt it is provisioning for, so a
    // recorded attempt awaiting compute is what the request id names.
    let attempt_id = new_id();
    f.repository
        .record_run_attempt(
            f.tenant,
            aiec_core::run::RunAttempt {
                id: attempt_id,
                run_id: run.id,
                attempt_number: 1,
                sandbox_id: None,
                state: aiec_core::run::RunState::Running,
                failure_reason: None,
                started_at: Utc::now(),
                completed_at: None,
                placement: Default::default(),
                results: Default::default(),
            },
        )
        .await
        .unwrap();
    let sandbox = f.sandbox();
    let owner = f.launch_run(run.id, attempt_id, sandbox.clone());
    gate(&f.client.first_create_entered).await;
    f.client.release_create.add_permits(1);
    gate(&f.client.start_entered).await;
    f.client.release_start.add_permits(1);
    let running = owner.await.unwrap().unwrap();
    assert_eq!(running.sandbox.state, SandboxState::Running);
    let original = f
        .repository
        .get_active_worker_lease(f.tenant, sandbox.id)
        .await
        .unwrap();
    f.expire(original.id).await;
    let before = f.requests().await.len();

    let (status, body) = f.reconcile("").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["recoveries"].as_array().map(Vec::len), Some(0));
    assert!(
        f.repository
            .get_active_worker_lease(f.tenant, sandbox.id)
            .await
            .is_err(),
        "expired run-owned lease must not be recovered"
    );
    assert_eq!(
        f.requests().await.len(),
        before,
        "reconcile rebuilt a run-owned machine"
    );
    assert!(f.client.machines.lock().await.contains(&original.id));
    f.close().await;
}

#[tokio::test]
async fn concurrent_idempotent_provision_cannot_destroy_the_blocked_winner() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let sandbox = f.sandbox();
    let request_id = new_id();
    let winner = f.launch(request_id, sandbox.clone());
    gate(&f.client.first_create_entered).await;
    let retry = f.launch(request_id, sandbox.clone());
    // A second Create for a lease that already allocated is the pre-fix
    // signature of duplicate live provisioning; watch for it without ever
    // blocking the assertion path.
    let duplicate_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let duplicate_seen_task = duplicate_seen.clone();
    let watched_client = f.client.clone();
    let monitor = tokio::spawn(async move {
        if tokio::time::timeout(
            std::time::Duration::from_millis(500),
            watched_client.duplicate_entered.acquire(),
        )
        .await
        .is_ok()
        {
            duplicate_seen_task.store(true, Ordering::SeqCst);
        }
    });
    f.client.release_create.add_permits(1);
    gate(&f.client.start_entered).await;
    f.client.release_duplicate.add_permits(1);
    f.client.release_destroy.add_permits(1);
    monitor.await.unwrap();
    assert!(
        !duplicate_seen.load(Ordering::SeqCst),
        "a live provisioning replay allocated a second machine"
    );
    let retried = retry.await.unwrap();
    assert!(
        retried.is_err(),
        "a live provisioning replay must be a refusal"
    );
    let lease = f
        .repository
        .get_active_worker_lease(f.tenant, sandbox.id)
        .await
        .unwrap();
    assert!(
        f.client.machines.lock().await.contains(&lease.id),
        "retry destroyed the blocked winner"
    );
    assert_eq!(
        f.client.creates.load(Ordering::SeqCst),
        1,
        "replay reached runtime allocation"
    );
    assert!(f.client.destroyed.lock().await.is_empty());
    assert_eq!(f.available().await, 1);
    f.client.release_start.add_permits(1);
    let running = winner.await.unwrap().unwrap();
    assert_eq!(running.sandbox.state, SandboxState::Running);
    let replay = provision_sandbox(
        &f.state,
        f.tenant,
        request_id,
        f.sandbox(),
        Default::default(),
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(replay.sandbox.id, sandbox.id);
    assert_eq!(replay.sandbox.state, SandboxState::Running);
    assert_eq!(f.client.creates.load(Ordering::SeqCst), 1);
    f.close().await;
}

#[tokio::test]
async fn renewed_owner_failure_stops_before_crediting_capacity() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let sandbox = f.sandbox();
    let owner = f.launch(new_id(), sandbox.clone());
    gate(&f.client.first_create_entered).await;
    f.client.release_create.add_permits(1);
    gate(&f.client.start_entered).await;
    let lease = f
        .repository
        .get_active_worker_lease(f.tenant, sandbox.id)
        .await
        .unwrap();
    f.repository
        .renew_worker_lease(f.tenant, lease.id, lease.generation, 60)
        .await
        .unwrap();
    *f.client.failed_lease.lock().await = Some(lease.id);
    f.client.release_start.add_permits(1);
    gate(&f.client.destroy_entered).await;
    assert_eq!(
        f.repository
            .get_sandbox(f.tenant, sandbox.id)
            .await
            .unwrap()
            .state,
        SandboxState::Destroying
    );
    assert_eq!(f.available().await, 1, "stop has not yet been confirmed");
    assert!(f.client.machines.lock().await.contains(&lease.id));
    // Expiry cannot reassign or credit an in-flight owned rollback.
    sqlx::query("UPDATE sandbox_leases SET expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(lease.id)
        .execute(&f.repository.pool)
        .await
        .unwrap();
    f.repository.reconcile_expired_leases(10).await.unwrap();
    assert_eq!(
        f.available().await,
        1,
        "expiry credited a machine teardown has not stopped"
    );
    assert!(
        f.repository
            .reassign_expired_lease(lease.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.scheduler
            .schedule(ScheduleRequest {
                tenant_id: f.tenant,
                request_id: new_id(),
                sandbox: sandbox.clone(),
                preferred_worker: None,
                lease_ttl: std::time::Duration::from_secs(60),
                required_capabilities: Default::default(),
                run_id: None,
            })
            .await
            .is_err()
    );
    f.client.release_destroy.add_permits(1);
    assert!(owner.await.unwrap().is_err());
    assert_eq!(*f.client.destroyed.lock().await, vec![lease.id]);
    assert!(!f.client.machines.lock().await.contains(&lease.id));
    assert_eq!(f.available().await, 2);
    assert_eq!(
        f.repository
            .get_sandbox(f.tenant, sandbox.id)
            .await
            .unwrap()
            .state,
        SandboxState::Destroyed
    );
    f.close().await;
}

#[tokio::test]
async fn replaced_owner_failure_never_destroys_the_new_lease_machine() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let sandbox = f.sandbox();
    let request_id = new_id();
    let old = f.launch(request_id, sandbox.clone());
    gate(&f.client.first_create_entered).await;
    f.client.release_create.add_permits(1);
    gate(&f.client.start_entered).await;
    let old_lease = f
        .repository
        .get_active_worker_lease(f.tenant, sandbox.id)
        .await
        .unwrap();
    *f.client.failed_lease.lock().await = Some(old_lease.id);
    sqlx::query("UPDATE sandbox_leases SET expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(old_lease.id)
        .execute(&f.repository.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE nodes SET control_endpoint='http://replacement-worker' WHERE id=$1")
        .bind(f.node)
        .execute(&f.repository.pool)
        .await
        .unwrap();
    let replacement = f.launch(request_id, sandbox.clone());
    gate(&f.client.start_entered).await;
    let new_lease = f
        .repository
        .get_active_worker_lease(f.tenant, sandbox.id)
        .await
        .unwrap();
    assert_ne!(old_lease.id, new_lease.id);
    assert!(f.client.machines.lock().await.contains(&new_lease.id));
    let requests_before = f.client.requests.lock().await.len();
    f.client.release_start.add_permits(2);
    f.client.release_destroy.add_permits(1);
    assert!(old.await.unwrap().is_err());
    let running = replacement.await.unwrap().unwrap();
    assert_eq!(running.sandbox.state, SandboxState::Running);
    assert!(f.client.machines.lock().await.contains(&new_lease.id));
    assert!(
        f.client.destroyed.lock().await.is_empty(),
        "stale owner dispatched teardown"
    );
    assert_eq!(
        f.client.requests.lock().await.len(),
        requests_before,
        "stale owner resolved replacement dispatch"
    );
    assert_eq!(f.available().await, 1);
    f.close().await;
}
