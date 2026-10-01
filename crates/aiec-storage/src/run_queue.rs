//! Short transactions for admission, fair dispatch and fenced recovery.
use aiec_core::{
    CoreError,
    run::{Run, RunState},
    run_queue::{RunQueueClaim, RunQueueLimits},
};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    PostgresRepository, StoreError, database_error,
    postgres::{insert_run_tx, run_from_row},
};

/// Ceiling on a single run's whole queue-to-terminal life. A day of execution
/// is far past any real agent workload, and an uncapped budget would let one
/// request hold an active slot indefinitely.
const MAX_EXECUTION_SECONDS: u64 = 86_520;

/// Grace on top of the caller's command timeout for placement and teardown.
const PLACEMENT_GRACE_SECONDS: u64 = 120;

/// Serializes admission counts and dispatch ordering across every process.
/// The lock is transaction-scoped; no executor or runtime I/O happens under it.
async fn gate(tx: &mut Transaction<'_, Postgres>) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(1095320899, 1381322321)")
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    Ok(())
}

async fn claim_row(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<RunQueueClaim, StoreError> {
    let row = sqlx::query(
        "SELECT r.*, q.request AS queue_request, q.owner AS queue_owner, \
        q.lease_until, q.execution_deadline, q.status AS queue_status \
        FROM runs r JOIN run_queue q ON q.run_id = r.id WHERE r.id = $1",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await
    .map_err(database_error)?;
    Ok(RunQueueClaim {
        run: run_from_row(&row)?,
        request: row.try_get("queue_request")?,
        owner: row.try_get("queue_owner")?,
        lease_until: row.try_get("lease_until")?,
        execution_deadline: row.try_get("execution_deadline")?,
        reclaiming: row.try_get::<String, _>("queue_status")? == "reclaiming",
    })
}

async fn retire_run(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    reason: &str,
) -> Result<(), StoreError> {
    // Lock order is queue then Run throughout the queue implementation.
    sqlx::query(
        "UPDATE runs SET state = 'failed', completed_at = now(), failure_reason = $2 \
        WHERE id = $1 AND state NOT IN ('succeeded','failed','cancelled')",
    )
    .bind(id)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    sqlx::query(
        "UPDATE run_attempts SET state = 'failed', completed_at = now(), \
        failure_reason = COALESCE(failure_reason, $2) WHERE run_id = $1 AND completed_at IS NULL",
    )
    .bind(id)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    // Snapshots of results, placement and sandbox links are deliberately retained.
    Ok(())
}

impl PostgresRepository {
    pub(crate) async fn enqueue_run(
        &self,
        run: Run,
        request: Value,
        limits: RunQueueLimits,
    ) -> Result<Run, StoreError> {
        let limits = limits.validate().map_err(StoreError::Core)?;
        if run.state != RunState::Queued || !request.is_object() {
            return Err(StoreError::Conflict(
                "queue admission requires a queued Run and request object".into(),
            ));
        }
        let seconds = run
            .workload
            .timeout_seconds
            .unwrap_or(600)
            .checked_add(PLACEMENT_GRACE_SECONDS)
            .filter(|seconds| *seconds <= MAX_EXECUTION_SECONDS)
            .and_then(|seconds| u32::try_from(seconds).ok())
            .ok_or_else(|| {
                StoreError::Core(CoreError::InvalidRequest(format!(
                    "workload timeout_seconds must be at most {}",
                    MAX_EXECUTION_SECONDS - PLACEMENT_GRACE_SECONDS
                )))
            })?;

        let mut tx = self.pool.begin().await.map_err(database_error)?;
        gate(&mut tx).await?;
        // Resolve retries before admission: even a full queue must join the original.
        if let Some(key) = &run.idempotency_key
            && let Some(row) =
                sqlx::query("SELECT * FROM runs WHERE tenant_id = $1 AND idempotency_key = $2")
                    .bind(run.tenant_id)
                    .bind(key)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(database_error)?
        {
            let existing = run_from_row(&row)?;
            tx.commit().await.map_err(database_error)?;
            return Ok(existing);
        }
        let row = sqlx::query("SELECT count(*) AS global_count, \
            count(*) FILTER (WHERE tenant_id = $1) AS tenant_count FROM run_queue WHERE status <> 'finished'")
            .bind(run.tenant_id).fetch_one(&mut *tx).await.map_err(database_error)?;
        if row.try_get::<i64, _>("global_count")? >= i64::from(limits.global_pending)
            || row.try_get::<i64, _>("tenant_count")? >= i64::from(limits.tenant_pending)
        {
            return Err(StoreError::QuotaExceeded(
                "Run queue admission limit reached".into(),
            ));
        }
        let proposed = run.id;
        let created = insert_run_tx(&mut tx, run).await?;
        // A legacy synchronous creator can race us on the same idempotency key.
        if created.id == proposed {
            sqlx::query(
                "INSERT INTO run_queue_tenants(tenant_id) VALUES ($1) ON CONFLICT DO NOTHING",
            )
            .bind(created.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
            sqlx::query(
                "INSERT INTO run_queue(run_id,tenant_id,request,queue_deadline,execution_seconds) \
                VALUES ($1,$2,$3,now() + $4 * interval '1 second',$5)",
            )
            .bind(created.id)
            .bind(created.tenant_id)
            .bind(request)
            .bind(i64::from(limits.queue_timeout_seconds))
            .bind(i64::from(seconds))
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(created)
    }

    pub(crate) async fn claim_run_queue(
        &self,
        owner: Uuid,
        limits: RunQueueLimits,
    ) -> Result<Option<RunQueueClaim>, StoreError> {
        let limits = limits.validate().map_err(StoreError::Core)?;
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        gate(&mut tx).await?;
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM run_queue WHERE status IN ('executing','reclaiming')",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
        if active >= i64::from(limits.max_active) {
            return Ok(None);
        }
        // Fairness by how much a tenant is already holding, counted once.
        //
        // The same ordering written as a correlated subquery recomputes the
        // active count for every candidate row it sorts, so the cost of picking
        // one run grows with the length of the queue it is picking from. A
        // grouped aggregate is computed once over the rows that are actually
        // active and joined by tenant: the same order, the same fairness, and a
        // claim that reads the queue rather than re-counting it per candidate.
        //
        // `FOR UPDATE ... SKIP LOCKED` still applies to the queue rows only, and
        // the grouping is in the CTE rather than this statement's own level,
        // which is what keeps the locking clause legal.
        let id: Option<Uuid> = sqlx::query_scalar(
            "WITH busy AS (SELECT tenant_id, count(*) AS active FROM run_queue \
              WHERE status IN ('executing','reclaiming') GROUP BY tenant_id) \
            SELECT q.run_id FROM run_queue q \
            JOIN run_queue_tenants t ON t.tenant_id = q.tenant_id \
            JOIN runs r ON r.id = q.run_id \
            LEFT JOIN busy b ON b.tenant_id = q.tenant_id \
            WHERE q.status = 'queued' AND q.queue_deadline > now() AND r.state = 'queued' \
            ORDER BY COALESCE(b.active, 0), t.last_dispatched_at NULLS FIRST, \
              q.enqueued_at, q.run_id FOR UPDATE OF q SKIP LOCKED LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        let Some(id) = id else {
            return Ok(None);
        };
        sqlx::query("UPDATE run_queue SET status = 'executing', owner = $2, \
            lease_until = LEAST(now() + $3 * interval '1 second', now() + execution_seconds * interval '1 second'), \
            execution_deadline = now() + execution_seconds * interval '1 second' WHERE run_id = $1")
            .bind(id).bind(owner).bind(i64::from(limits.lease_seconds))
            .execute(&mut *tx).await.map_err(database_error)?;
        sqlx::query(
            "UPDATE run_queue_tenants SET last_dispatched_at = now() \
            WHERE tenant_id = (SELECT tenant_id FROM run_queue WHERE run_id = $1)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        let claim = claim_row(&mut tx, id).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(Some(claim))
    }

    pub(crate) async fn recover_run_queue(
        &self,
        owner: Uuid,
        limits: RunQueueLimits,
    ) -> Result<Option<RunQueueClaim>, StoreError> {
        let limits = limits.validate().map_err(StoreError::Core)?;
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        gate(&mut tx).await?;
        let row = sqlx::query("SELECT q.run_id, q.status, q.failure_reason, r.state FROM run_queue q \
            JOIN runs r ON r.id = q.run_id WHERE \
            (q.status IN ('executing','reclaiming') AND q.lease_until <= now()) OR \
            (q.status = 'queued' AND (q.queue_deadline <= now() OR r.state <> 'queued')) \
            ORDER BY (q.status = 'queued'), q.enqueued_at, q.run_id FOR UPDATE OF q SKIP LOCKED LIMIT 1")
            .fetch_optional(&mut *tx).await.map_err(database_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id: Uuid = row.try_get("run_id")?;
        let status: String = row.try_get("status")?;
        // Turning an expired queued entry into cleanup also needs a bounded slot.
        if status == "queued" {
            let active: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM run_queue WHERE status IN ('executing','reclaiming')",
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
            if active >= i64::from(limits.max_active) {
                return Ok(None);
            }
        }
        let previous: Option<String> = row.try_get("failure_reason")?;
        let reason = previous.unwrap_or_else(|| {
            if status == "queued" {
                if row.try_get::<String, _>("state").ok().as_deref() == Some("queued") {
                    "Run queue deadline exceeded".into()
                } else {
                    "Run stopped before dispatch".into()
                }
            } else {
                "Run executor lease or execution deadline expired".into()
            }
        });
        sqlx::query(
            "UPDATE run_queue SET status = 'reclaiming', owner = $2, \
            lease_until = now() + $3 * interval '1 second', failure_reason = $4 WHERE run_id = $1",
        )
        .bind(id)
        .bind(owner)
        .bind(i64::from(limits.lease_seconds))
        .bind(&reason)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        retire_run(&mut tx, id, &reason).await?;
        let claim = claim_row(&mut tx, id).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(Some(claim))
    }

    pub(crate) async fn heartbeat_run_queue(
        &self,
        tenant: Uuid,
        run: Uuid,
        owner: Uuid,
        lease_seconds: u32,
    ) -> Result<bool, StoreError> {
        if !(6..=300).contains(&lease_seconds) {
            return Err(StoreError::Conflict("invalid queue lease".into()));
        }
        let result = sqlx::query(
            "UPDATE run_queue SET lease_until = CASE WHEN status = 'executing' \
            THEN LEAST(now() + $4 * interval '1 second', execution_deadline) \
            ELSE now() + $4 * interval '1 second' END \
            WHERE tenant_id = $1 AND run_id = $2 AND owner = $3 AND lease_until > now() \
            AND status IN ('executing','reclaiming') \
            AND (status = 'reclaiming' OR execution_deadline > now())",
        )
        .bind(tenant)
        .bind(run)
        .bind(owner)
        .bind(i64::from(lease_seconds))
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn fail_run_queue(
        &self,
        tenant: Uuid,
        run: Uuid,
        owner: Uuid,
        reason: String,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let result = sqlx::query(
            "UPDATE run_queue SET status = 'reclaiming', failure_reason = $4 \
            WHERE tenant_id = $1 AND run_id = $2 AND owner = $3 AND status = 'executing' \
            AND lease_until > now() AND execution_deadline > now()",
        )
        .bind(tenant)
        .bind(run)
        .bind(owner)
        .bind(&reason)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        retire_run(&mut tx, run, &reason).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(true)
    }

    pub(crate) async fn finish_run_queue(
        &self,
        tenant: Uuid,
        run: Uuid,
        owner: Uuid,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE run_queue q SET status = 'finished', owner = NULL, lease_until = NULL \
            FROM runs r WHERE q.run_id = r.id AND q.tenant_id = $1 AND q.run_id = $2 \
            AND q.owner = $3 AND q.lease_until > now() AND q.status IN ('executing','reclaiming') \
            AND (q.status = 'reclaiming' OR q.execution_deadline > now()) \
            AND r.state IN ('succeeded','failed','cancelled') \
            AND COALESCE(r.results->>'cleanup_failed','') = ''",
        )
        .bind(tenant)
        .bind(run)
        .bind(owner)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn run_queue_finished(
        &self,
        tenant: Uuid,
        run: Uuid,
    ) -> Result<bool, StoreError> {
        let row = sqlx::query(
            "SELECT q.status FROM runs r LEFT JOIN run_queue q ON q.run_id = r.id \
            WHERE r.tenant_id = $1 AND r.id = $2",
        )
        .bind(tenant)
        .bind(run)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
        let status: Option<String> = row.try_get("status")?;
        Ok(status.is_none_or(|status| status == "finished"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiec_core::{
        new_id,
        run::{RetentionPolicy, RunResults, WorkloadSpec},
    };
    use chrono::Utc;
    use serde_json::json;
    use sqlx::{PgPool, postgres::PgPoolOptions};

    struct Fixture {
        repository: PostgresRepository,
        admin: PgPool,
        schema: String,
    }

    impl Fixture {
        async fn new() -> Option<Self> {
            let url = std::env::var("DATABASE_URL")
                .ok()
                .filter(|url| !url.trim().is_empty())?;
            let admin = PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .unwrap();
            let schema = format!("queue_test_{}", new_id().simple());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .unwrap();
            let search_path = format!("SET search_path TO {schema}");
            let pool = PgPoolOptions::new()
                .max_connections(10)
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
            let repository = PostgresRepository::from_pool(pool);
            repository.migrate().await.unwrap();
            Some(Self {
                repository,
                admin,
                schema,
            })
        }

        async fn tenant(&self) -> Uuid {
            let id = new_id();
            sqlx::query("INSERT INTO tenants(id,name) VALUES ($1,$2)")
                .bind(id)
                .bind(format!("queue-{id}"))
                .execute(&self.repository.pool)
                .await
                .unwrap();
            id
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

    fn run(tenant: Uuid, key: Option<&str>) -> Run {
        Run {
            id: new_id(),
            tenant_id: tenant,
            state: RunState::Queued,
            requested_at: Utc::now(),
            queued_at: Some(Utc::now()),
            started_at: None,
            completed_at: None,
            workload: WorkloadSpec {
                command: vec!["true".into()],
                ..Default::default()
            },
            resources: Default::default(),
            requirements: Default::default(),
            placement: Default::default(),
            results: RunResults::default(),
            failure_reason: None,
            retention: RetentionPolicy::Destroy,
            retained_sandbox_id: None,
            retained_until: None,
            idempotency_key: key.map(str::to_owned),
            parent_run_id: None,
            matrix_id: None,
            matrix_cell: None,
        }
    }

    #[tokio::test]
    async fn atomic_admission_joins_retries_and_bounds_concurrent_claims_fairly() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let repository = &fixture.repository;
        let a = fixture.tenant().await;
        let b = fixture.tenant().await;
        let c = fixture.tenant().await;
        let limits = RunQueueLimits {
            global_pending: 3,
            tenant_pending: 2,
            max_active: 2,
            ..Default::default()
        };
        let first = run(a, Some("same"));
        let retry = run(a, Some("same"));
        let (first, retry) = tokio::join!(
            repository.enqueue_run(
                first,
                json!({"requested_runtime":"docker","max_attempts":3}),
                limits
            ),
            repository.enqueue_run(
                retry,
                json!({"requested_runtime":"firecracker","max_attempts":1}),
                limits
            )
        );
        let first = first.unwrap();
        assert_eq!(first.id, retry.unwrap().id);
        repository
            .enqueue_run(run(a, None), json!({}), limits)
            .await
            .unwrap();
        assert!(matches!(
            repository
                .enqueue_run(run(a, None), json!({}), limits)
                .await,
            Err(StoreError::QuotaExceeded(_))
        ));
        repository
            .enqueue_run(run(b, None), json!({}), limits)
            .await
            .unwrap();
        assert!(matches!(
            repository
                .enqueue_run(run(c, None), json!({}), limits)
                .await,
            Err(StoreError::QuotaExceeded(_))
        ));
        assert_eq!(
            repository
                .enqueue_run(run(a, Some("same")), json!({}), limits)
                .await
                .unwrap()
                .id,
            first.id
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM runs")
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        assert_eq!(count, 3, "refused admission must not leave an orphan Run");
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let repository = repository.clone();
            tasks.spawn(async move { repository.claim_run_queue(new_id(), limits).await.unwrap() });
        }
        let mut claims = Vec::new();
        while let Some(result) = tasks.join_next().await {
            if let Some(claim) = result.unwrap() {
                claims.push(claim);
            }
        }
        assert_eq!(claims.len(), 2);
        assert_ne!(claims[0].run.id, claims[1].run.id);
        let tenants: std::collections::HashSet<_> =
            claims.iter().map(|claim| claim.run.tenant_id).collect();
        assert_eq!(tenants, [a, b].into_iter().collect());
        let request: Value = sqlx::query_scalar("SELECT request FROM run_queue WHERE run_id = $1")
            .bind(first.id)
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        assert!(
            request == json!({"requested_runtime":"docker","max_attempts":3})
                || request == json!({"requested_runtime":"firecracker","max_attempts":1})
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn expired_owners_cannot_revive_and_recovery_preserves_evidence_until_cleanup() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let repository = &fixture.repository;
        let tenant = fixture.tenant().await;
        let limits = RunQueueLimits::default();
        let run = repository
            .enqueue_run(
                run(tenant, None),
                json!({"workload": {"secrets": ["TOKEN"]}}),
                limits,
            )
            .await
            .unwrap();
        let owner = new_id();
        let claim = repository
            .claim_run_queue(owner, limits)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.run.id, run.id);
        let fixed_deadline = claim.execution_deadline;
        assert!(
            repository
                .heartbeat_run_queue(tenant, run.id, owner, limits.lease_seconds)
                .await
                .unwrap()
        );
        let deadline =
            sqlx::query_scalar("SELECT execution_deadline FROM run_queue WHERE run_id = $1")
                .bind(run.id)
                .fetch_one(&repository.pool)
                .await
                .unwrap();
        assert_eq!(fixed_deadline, deadline);
        let attempt = new_id();
        let evidence = json!({"phase_ms":{"task":8}});
        sqlx::query("INSERT INTO run_attempts(id,run_id,attempt_number,state,results) VALUES ($1,$2,1,'running',$3)")
            .bind(attempt).bind(run.id).bind(&evidence).execute(&repository.pool).await.unwrap();
        sqlx::query(
            "UPDATE run_queue SET lease_until = now() - interval '1 second' WHERE run_id = $1",
        )
        .bind(run.id)
        .execute(&repository.pool)
        .await
        .unwrap();
        assert!(
            !repository
                .heartbeat_run_queue(tenant, run.id, owner, limits.lease_seconds)
                .await
                .unwrap()
        );
        assert!(
            !repository
                .fail_run_queue(tenant, run.id, owner, "stale".into())
                .await
                .unwrap()
        );
        assert!(
            !repository
                .finish_run_queue(tenant, run.id, owner)
                .await
                .unwrap()
        );
        let new_owner = new_id();
        let recovered = repository
            .recover_run_queue(new_owner, limits)
            .await
            .unwrap()
            .unwrap();
        assert!(recovered.reclaiming);
        assert_eq!(recovered.run.state, RunState::Failed);
        assert_eq!(recovered.execution_deadline, fixed_deadline);
        assert!(recovered.run.failure_reason.unwrap().contains("lease"));
        let row = sqlx::query("SELECT state, completed_at IS NOT NULL AS complete, results FROM run_attempts WHERE id = $1")
            .bind(attempt).fetch_one(&repository.pool).await.unwrap();
        assert_eq!(row.try_get::<String, _>("state").unwrap(), "failed");
        assert!(row.try_get::<bool, _>("complete").unwrap());
        assert_eq!(row.try_get::<Value, _>("results").unwrap(), evidence);
        assert!(
            !repository
                .heartbeat_run_queue(tenant, run.id, owner, limits.lease_seconds)
                .await
                .unwrap()
        );
        assert!(!repository.run_queue_finished(tenant, run.id).await.unwrap());
        sqlx::query("UPDATE runs SET results = jsonb_set(results, '{cleanup_failed}', \
            jsonb_build_object('sandbox_id', $2::text, 'error', 'runtime unavailable')) WHERE id = $1")
            .bind(run.id).bind(new_id()).execute(&repository.pool).await.unwrap();
        assert!(
            !repository
                .finish_run_queue(tenant, run.id, new_owner)
                .await
                .unwrap()
        );
        sqlx::query(
            "UPDATE run_queue SET lease_until = now() - interval '1 second' WHERE run_id = $1",
        )
        .bind(run.id)
        .execute(&repository.pool)
        .await
        .unwrap();
        let cleanup_owner = new_id();
        let retry = repository
            .recover_run_queue(cleanup_owner, limits)
            .await
            .unwrap()
            .unwrap();
        assert!(retry.reclaiming);
        assert_eq!(
            retry
                .run
                .results
                .cleanup_failed
                .as_ref()
                .map(|report| report.error.as_str()),
            Some("runtime unavailable")
        );
        sqlx::query("UPDATE runs SET results = results - 'cleanup_failed' WHERE id = $1")
            .bind(run.id)
            .execute(&repository.pool)
            .await
            .unwrap();
        assert!(
            repository
                .finish_run_queue(tenant, run.id, cleanup_owner)
                .await
                .unwrap()
        );
        assert!(repository.run_queue_finished(tenant, run.id).await.unwrap());
        assert!(
            !repository
                .heartbeat_run_queue(tenant, run.id, cleanup_owner, limits.lease_seconds)
                .await
                .unwrap()
        );
        fixture.close().await;
    }

    /// A tenant already holding a slot does not get a second one while an
    /// idle tenant's run waits, however long that run has been waiting.
    ///
    /// This is the property the dispatch order is for, and it is invisible to
    /// a queue of one tenant. Tenant A's second run is older and would win on
    /// age alone; tenant B's run has never been dispatched and sorts ahead of
    /// it. A rewrite that grouped the active counts wrongly - or dropped them -
    /// would keep serving A and starve B until A's queue drained.
    #[tokio::test]
    async fn dispatch_counts_what_a_tenant_already_holds_before_its_age() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let repository = &fixture.repository;
        let a = fixture.tenant().await;
        let b = fixture.tenant().await;
        let limits = RunQueueLimits {
            max_active: 4,
            ..Default::default()
        };
        let a_first = repository
            .enqueue_run(run(a, None), json!({}), limits)
            .await
            .unwrap();
        let a_second = repository
            .enqueue_run(run(a, None), json!({}), limits)
            .await
            .unwrap();
        let b_only = repository
            .enqueue_run(run(b, None), json!({}), limits)
            .await
            .unwrap();
        // A's run is made to look older than B's, so age alone would hand the
        // second slot straight back to the tenant that already holds the first.
        sqlx::query(
            "UPDATE run_queue SET enqueued_at = '2000-01-01'::timestamptz \
             WHERE run_id = ANY($1::uuid[])",
        )
        .bind([a_first.id, a_second.id])
        .execute(&repository.pool)
        .await
        .unwrap();
        // B has never been dispatched, which on its own would put it first
        // whatever the counts say. Giving it a dispatch time as recent as A's
        // takes that shortcut away, so the second claim can only be explained by
        // what the two tenants are holding.
        sqlx::query("UPDATE run_queue_tenants SET last_dispatched_at = now() WHERE tenant_id = $1")
            .bind(b)
            .execute(&repository.pool)
            .await
            .unwrap();
        let first = repository
            .claim_run_queue(new_id(), limits)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.run.id, a_first.id);
        let second = repository
            .claim_run_queue(new_id(), limits)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            second.run.id, b_only.id,
            "a tenant holding a slot must not take the next one from an idle tenant"
        );
        assert_ne!(second.run.id, a_second.id);
        // Once both tenants hold one, the tie falls to who was dispatched
        // longest ago, so the run that has waited longest is served next.
        let third = repository
            .claim_run_queue(new_id(), limits)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(third.run.id, a_second.id);
        fixture.close().await;
    }

    #[tokio::test]
    async fn expired_queue_entries_never_execute_and_dispatch_rotates_tenants() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let repository = &fixture.repository;
        let a = fixture.tenant().await;
        let b = fixture.tenant().await;
        let limits = RunQueueLimits {
            max_active: 1,
            ..Default::default()
        };
        let a1 = repository
            .enqueue_run(run(a, None), json!({}), limits)
            .await
            .unwrap();
        let a2 = repository
            .enqueue_run(run(a, None), json!({}), limits)
            .await
            .unwrap();
        let b1 = repository
            .enqueue_run(run(b, None), json!({}), limits)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE run_queue SET enqueued_at = '2000-01-01'::timestamptz WHERE run_id = $1",
        )
        .bind(a1.id)
        .execute(&repository.pool)
        .await
        .unwrap();
        let first = repository
            .claim_run_queue(new_id(), limits)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.run.id, a1.id);
        sqlx::query("UPDATE runs SET state = 'succeeded', completed_at = now() WHERE id = $1")
            .bind(a1.id)
            .execute(&repository.pool)
            .await
            .unwrap();
        assert!(
            repository
                .finish_run_queue(a, a1.id, first.owner)
                .await
                .unwrap()
        );
        let next = repository
            .claim_run_queue(new_id(), limits)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            next.run.id, b1.id,
            "last dispatch order must prevent a busy tenant monopolizing a slot"
        );
        sqlx::query("UPDATE runs SET state = 'succeeded', completed_at = now() WHERE id = $1")
            .bind(b1.id)
            .execute(&repository.pool)
            .await
            .unwrap();
        assert!(
            repository
                .finish_run_queue(b, b1.id, next.owner)
                .await
                .unwrap()
        );
        sqlx::query(
            "UPDATE run_queue SET queue_deadline = now() - interval '1 second' WHERE run_id = $1",
        )
        .bind(a2.id)
        .execute(&repository.pool)
        .await
        .unwrap();
        assert!(
            repository
                .claim_run_queue(new_id(), limits)
                .await
                .unwrap()
                .is_none()
        );
        let expired = repository
            .recover_run_queue(new_id(), limits)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expired.run.id, a2.id);
        assert!(expired.reclaiming);
        assert_eq!(expired.run.state, RunState::Failed);
        assert_eq!(
            expired.run.failure_reason.as_deref(),
            Some("Run queue deadline exceeded")
        );
        assert!(expired.execution_deadline.is_none());
        fixture.close().await;
    }
}
