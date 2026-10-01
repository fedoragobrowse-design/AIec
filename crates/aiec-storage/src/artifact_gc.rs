//! Durable upload ownership and bounded, reference-safe deletion claims.
use crate::{PostgresRepository, StoreError, database_error};
use aiec_core::storage::ArtifactDeletion;
use chrono::{DateTime, Duration, Utc};
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

const MAX_BATCH: u32 = 1000;
const MIN_PENDING_GRACE_SECONDS: i64 = 600;

/// One live ledger row read by the bounded sweep window.
struct Candidate {
    key: String,
    tenant_id: Uuid,
    owner_run_id: Option<Uuid>,
    state: String,
    updated_at: DateTime<Utc>,
    retry_at: DateTime<Utc>,
    lease_until: Option<DateTime<Utc>>,
}

impl Candidate {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            key: row.try_get("object_key")?,
            tenant_id: row.try_get("tenant_id")?,
            owner_run_id: row.try_get("owner_run_id")?,
            state: row.try_get("state")?,
            updated_at: row.try_get("updated_at")?,
            retry_at: row.try_get("retry_at")?,
            lease_until: row.try_get("lease_until")?,
        })
    }
}

impl PostgresRepository {
    pub(crate) async fn reserve_artifact_upload(
        &self,
        tenant: Uuid,
        run: Option<Uuid>,
        key: &str,
    ) -> Result<(), StoreError> {
        crate::object_store::validate_object_key(key)?;
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        if let Some(run) = run {
            if !key.starts_with(&format!("tenants/{tenant}/runs/{run}/")) {
                return Err(StoreError::InvalidObjectKey(
                    "upload key is outside its Run".into(),
                ));
            }
            let row = sqlx::query("SELECT state, artifacts_expired_at FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(tenant).bind(run).fetch_optional(&mut *tx).await.map_err(database_error)?
                .ok_or(StoreError::NotFound)?;
            let state: String = row.try_get("state")?;
            if matches!(state.as_str(), "succeeded" | "failed" | "cancelled")
                || row
                    .try_get::<Option<DateTime<Utc>>, _>("artifacts_expired_at")?
                    .is_some()
            {
                return Err(StoreError::Conflict("Run no longer accepts uploads".into()));
            }
        } else {
            // A key that does not name its tenant is refused here, at the
            // claim, rather than noticed later by whoever reads the bucket. The
            // Run branch gets the same check against its own prefix; this is
            // the equivalent for an object no Run owns.
            if !key.starts_with(&format!("tenants/{tenant}/")) {
                return Err(StoreError::InvalidObjectKey(
                    "upload key does not name its tenant".into(),
                ));
            }
            sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR KEY SHARE")
                .bind(tenant)
                .fetch_optional(&mut *tx)
                .await
                .map_err(database_error)?
                .ok_or(StoreError::NotFound)?;
        }
        let row = sqlx::query(
            "INSERT INTO artifact_objects(object_key,tenant_id,owner_run_id,state) VALUES($1,$2,$3,'pending') \
             ON CONFLICT(object_key) DO UPDATE SET updated_at=now() \
             WHERE artifact_objects.tenant_id=EXCLUDED.tenant_id \
               AND artifact_objects.owner_run_id IS NOT DISTINCT FROM EXCLUDED.owner_run_id \
               AND artifact_objects.state IN ('pending','available') RETURNING object_key"
        ).bind(key).bind(tenant).bind(run).fetch_optional(&mut *tx).await.map_err(database_error)?;
        if row.is_none() {
            return Err(StoreError::Conflict(
                "object key belongs to another owner or has expired".into(),
            ));
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    pub(crate) async fn complete_artifact_upload(
        &self,
        tenant: Uuid,
        run: Option<Uuid>,
        key: &str,
    ) -> Result<(), StoreError> {
        // Even a late successful PUT must leave a deletion intent. In particular,
        // never acknowledge it as live after a deletion claim has been issued.
        let row = sqlx::query(
            "UPDATE artifact_objects SET \
             state=CASE WHEN state IN ('deleting','deleted') THEN 'deleting' ELSE 'available' END, \
             claim=NULL, lease_until=NULL, retry_at=now(), updated_at=now() \
             WHERE object_key=$1 AND tenant_id=$2 AND owner_run_id IS NOT DISTINCT FROM $3 \
             RETURNING state",
        )
        .bind(key)
        .bind(tenant)
        .bind(run)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or(StoreError::NotFound)?;
        if row.try_get::<String, _>("state")? == "deleting" {
            return Err(StoreError::Conflict(
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
    ) -> Result<Vec<ArtifactDeletion>, StoreError> {
        if !(1..=315_360_000).contains(&retention_seconds)
            || !(MIN_PENDING_GRACE_SECONDS..=315_360_000).contains(&pending_grace_seconds)
            || !(1..=MAX_BATCH).contains(&limit)
            || !(1..=3600).contains(&lease_seconds)
        {
            return Err(StoreError::Conflict("invalid artifact GC bounds".into()));
        }
        let expiry = now
            .checked_sub_signed(Duration::seconds(retention_seconds))
            .ok_or_else(|| StoreError::Conflict("artifact retention overflow".into()))?;
        let abandoned = now
            .checked_sub_signed(Duration::seconds(pending_grace_seconds))
            .ok_or_else(|| StoreError::Conflict("artifact upload grace overflow".into()))?;
        let lease_until = now
            .checked_add_signed(Duration::seconds(lease_seconds))
            .ok_or_else(|| StoreError::Conflict("artifact deletion lease overflow".into()))?;
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        let runs = sqlx::query(
            "SELECT id FROM runs WHERE state IN ('succeeded','failed','cancelled') \
             AND completed_at <= $1 AND artifacts_expired_at IS NULL \
             AND retained_sandbox_id IS NULL AND (retained_until IS NULL OR retained_until <= $2) \
             ORDER BY completed_at,id LIMIT $3 FOR UPDATE SKIP LOCKED",
        )
        .bind(expiry)
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        for row in runs {
            let id: Uuid = row.try_get("id")?;
            sqlx::query("UPDATE runs SET artifacts_expired_at=$2, results=jsonb_set(results,'{artifacts}','[]'::jsonb) WHERE id=$1")
                .bind(id).bind(now).execute(&mut *tx).await.map_err(database_error)?;
            sqlx::query("INSERT INTO run_events(id,run_id,type,occurred_at,detail) VALUES($1,$2,'artifacts.expired',$3,$4)")
                .bind(Uuid::new_v4()).bind(id).bind(now)
                .bind(serde_json::json!({"retention_seconds": retention_seconds}))
                .execute(&mut *tx).await.map_err(database_error)?;
        }
        // Reference retirement is bounded independently of the number of files
        // any one Run produced. Expired Runs are hidden from artifact listing
        // immediately, while these rows drain over subsequent sweeps.
        sqlx::query(
            "DELETE FROM run_artifacts WHERE id IN ( \
             SELECT a.id FROM run_artifacts a JOIN runs r ON r.id=a.run_id \
             WHERE r.artifacts_expired_at IS NOT NULL ORDER BY a.id \
             LIMIT $1 FOR UPDATE OF a SKIP LOCKED)",
        )
        .bind(i64::from(limit))
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        // Reference insertion takes this same object row lock in database
        // triggers. Once claimed, new Run/snapshot references are rejected.
        //
        // A pass reads one bounded keyset window of the ledger, continues after
        // the last row it read, and wraps when the window runs off the end.
        // Eligibility is decided for those rows alone, so a pass never grows
        // with the number of protected objects in front of the garbage, and a
        // protected prefix cannot starve the keys that sort behind it.
        let continuation: Option<Option<String>> = sqlx::query_scalar(
            "SELECT last_object_key FROM artifact_gc_scan WHERE id FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        let Some(cursor) = continuation else {
            // Another sweeper holds this pass's continuation key.
            tx.commit().await.map_err(database_error)?;
            return Ok(Vec::new());
        };
        let mut window =
            Self::candidate_window_after(&mut tx, cursor.as_deref().unwrap_or(""), limit).await?;
        if window.len() < limit as usize
            && let Some(cursor) = cursor.as_deref()
        {
            let remaining = limit - window.len() as u32;
            window.extend(Self::candidate_window_up_to(&mut tx, cursor, remaining).await?);
        }
        let mut claims = Vec::with_capacity(window.len());
        let mut issued = Vec::with_capacity(window.len());
        if !window.is_empty() {
            // One indexed probe per window key, across every Run, every tenant
            // and every snapshot role. The window, not the ledger, bounds it.
            let keys: Vec<String> = window
                .iter()
                .map(|candidate| candidate.key.clone())
                .collect();
            let referenced = Self::referenced_keys(&mut tx, &keys).await?;
            let owners: Vec<Uuid> = window
                .iter()
                .filter_map(|candidate| candidate.owner_run_id)
                .collect();
            let live_owners = Self::live_owner_runs(&mut tx, &owners, now).await?;
            for candidate in &window {
                if candidate.retry_at > now
                    || candidate.lease_until.is_some_and(|lease| lease > now)
                    || (candidate.state != "deleting" && candidate.updated_at > abandoned)
                    || referenced.contains(&candidate.key)
                    || candidate
                        .owner_run_id
                        .is_some_and(|owner| live_owners.contains(&owner))
                {
                    continue;
                }
                let claim = Uuid::new_v4();
                issued.push((candidate.key.clone(), claim));
                claims.push(ArtifactDeletion {
                    key: candidate.key.clone(),
                    tenant_id: candidate.tenant_id,
                    claim,
                });
            }
        }
        if !issued.is_empty() {
            let (keys, tokens): (Vec<String>, Vec<Uuid>) = issued
                .iter()
                .map(|(key, claim)| (key.clone(), *claim))
                .unzip();
            let updated = sqlx::query(
                "UPDATE artifact_objects o SET state='deleting',claim=w.claim,lease_until=$2,attempts=o.attempts+1 \
                 FROM unnest($1::text[],$3::uuid[]) AS w(object_key,claim) WHERE o.object_key = w.object_key"
            ).bind(keys).bind(lease_until).bind(tokens).execute(&mut *tx).await.map_err(database_error)?;
            if updated.rows_affected() as usize != issued.len() {
                return Err(StoreError::Conflict(
                    "artifact claim lost its locked window".into(),
                ));
            }
        }
        // The window's last row is the continuation point: the next pass resumes
        // after it, and an exhausted ledger starts again at its first key.
        sqlx::query("UPDATE artifact_gc_scan SET last_object_key=$1,updated_at=now() WHERE id")
            .bind(window.last().map(|candidate| candidate.key.clone()))
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(claims)
    }

    /// The next `limit` live ledger rows after `cursor`, locked in key order.
    /// Only the keyset bound and the tombstone state narrow the window here:
    /// eligibility is decided afterwards, for the rows of the window only.
    async fn candidate_window_after(
        transaction: &mut Transaction<'_, Postgres>,
        cursor: &str,
        limit: u32,
    ) -> Result<Vec<Candidate>, StoreError> {
        let rows = sqlx::query(
            "SELECT object_key,tenant_id,owner_run_id,state,updated_at,retry_at,lease_until \
             FROM artifact_objects WHERE state <> 'deleted' AND object_key > $1 ORDER BY object_key \
             LIMIT $2 FOR UPDATE SKIP LOCKED"
        ).bind(cursor).bind(i64::from(limit))
            .fetch_all(&mut **transaction).await.map_err(database_error)?;
        rows.iter()
            .map(Candidate::from_row)
            .collect::<Result<_, sqlx::Error>>()
            .map_err(StoreError::from)
    }

    /// The wraparound page: live ledger rows at or before `cursor`, filling the
    /// window the tail page left short.
    async fn candidate_window_up_to(
        transaction: &mut Transaction<'_, Postgres>,
        cursor: &str,
        limit: u32,
    ) -> Result<Vec<Candidate>, StoreError> {
        let rows = sqlx::query(
            "SELECT object_key,tenant_id,owner_run_id,state,updated_at,retry_at,lease_until \
             FROM artifact_objects WHERE state <> 'deleted' AND object_key <= $1 ORDER BY object_key \
             LIMIT $2 FOR UPDATE SKIP LOCKED"
        ).bind(cursor).bind(i64::from(limit))
            .fetch_all(&mut **transaction).await.map_err(database_error)?;
        rows.iter()
            .map(Candidate::from_row)
            .collect::<Result<_, sqlx::Error>>()
            .map_err(StoreError::from)
    }

    /// Window keys that still carry a durable reference anywhere: a Run
    /// artifact row, a Run result artifact, or any snapshot object role.
    async fn referenced_keys(
        transaction: &mut Transaction<'_, Postgres>,
        keys: &[String],
    ) -> Result<HashSet<String>, StoreError> {
        let rows = sqlx::query(
            "SELECT DISTINCT page.object_key FROM unnest($1::text[]) AS page(object_key) \
             WHERE EXISTS (SELECT 1 FROM run_artifacts a WHERE a.object_key = page.object_key) \
             OR EXISTS (SELECT 1 FROM runs r WHERE r.results->'artifacts' \
                 @> jsonb_build_array(jsonb_build_object('object_key', page.object_key))) \
             OR EXISTS (SELECT 1 FROM snapshots s WHERE \
                 ARRAY[s.object_key,s.manifest_object_key,s.memory_object_key,s.disk_object_key,s.workspace_object_key] \
                    @> ARRAY[page.object_key])"
        ).bind(keys).fetch_all(&mut **transaction).await.map_err(database_error)?;
        rows.iter()
            .map(|row| row.try_get::<String, _>("object_key"))
            .collect::<Result<HashSet<String>, sqlx::Error>>()
            .map_err(StoreError::from)
    }

    /// Window owner Runs that are still active or retained. An object whose
    /// producing Run is live is not abandoned, however old the ledger row is.
    async fn live_owner_runs(
        transaction: &mut Transaction<'_, Postgres>,
        owners: &[Uuid],
        now: DateTime<Utc>,
    ) -> Result<HashSet<Uuid>, StoreError> {
        let rows = sqlx::query(
            "SELECT id FROM runs WHERE id = ANY($1::uuid[]) \
             AND (state NOT IN ('succeeded','failed','cancelled') \
                  OR retained_sandbox_id IS NOT NULL OR retained_until > $2)",
        )
        .bind(owners)
        .bind(now)
        .fetch_all(&mut **transaction)
        .await
        .map_err(database_error)?;
        rows.iter()
            .map(|row| row.try_get::<Uuid, _>("id"))
            .collect::<Result<HashSet<Uuid>, sqlx::Error>>()
            .map_err(StoreError::from)
    }

    pub(crate) async fn finish_artifact_deletion(
        &self,
        key: &str,
        claim: Uuid,
        deleted: bool,
        retry_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE artifact_objects SET state=CASE WHEN $3 THEN 'deleted' ELSE 'deleting' END, \
             claim=NULL, lease_until=NULL, retry_at=$4, updated_at=now() \
             WHERE object_key=$1 AND claim=$2 AND state='deleting'",
        )
        .bind(key)
        .bind(claim)
        .bind(deleted)
        .bind(retry_at)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::Conflict("stale artifact deletion claim".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FilesystemObjectStore;
    use aiec_core::{
        run::RunArtifactRef,
        storage::{ArtifactStore, MetadataStore, StoredSnapshot},
    };
    use bytes::Bytes;
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
                .filter(|value| !value.trim().is_empty())?;
            let admin = PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .unwrap();
            let schema = format!("artifact_gc_test_{}", Uuid::new_v4().simple());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .unwrap();
            let search_path = format!("SET search_path TO {schema}");
            let pool = PgPoolOptions::new()
                .max_connections(6)
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
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO tenants(id,name) VALUES($1,$2)")
                .bind(id)
                .bind(format!("gc-{id}"))
                .execute(&self.repository.pool)
                .await
                .unwrap();
            id
        }

        async fn run(&self, tenant: Uuid) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO runs(id,tenant_id,state) VALUES($1,$2,'collecting')")
                .bind(id)
                .bind(tenant)
                .execute(&self.repository.pool)
                .await
                .unwrap();
            id
        }

        async fn artifact(&self, tenant: Uuid, run: Uuid, key: &str) {
            MetadataStore::put_run_artifacts(
                &self.repository,
                tenant,
                run,
                vec![RunArtifactRef {
                    name: "report".into(),
                    object_key: key.into(),
                    size_bytes: 4,
                    checksum_sha256: None,
                    content_type: None,
                }],
            )
            .await
            .unwrap();
        }

        async fn age_objects(&self, now: DateTime<Utc>) {
            sqlx::query("UPDATE artifact_objects SET created_at=$1,updated_at=$1,retry_at=$1")
                .bind(now - Duration::hours(2))
                .execute(&self.repository.pool)
                .await
                .unwrap();
        }

        async fn terminal(&self, run: Uuid, completed_at: DateTime<Utc>) {
            sqlx::query("UPDATE runs SET state='failed',completed_at=$2 WHERE id=$1")
                .bind(run)
                .bind(completed_at)
                .execute(&self.repository.pool)
                .await
                .unwrap();
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
    async fn expiry_preserves_live_cross_tenant_results_and_retained_evidence() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let now = Utc::now();
        let a = fixture.tenant().await;
        let b = fixture.tenant().await;
        let expired = fixture.run(a).await;
        let live = fixture.run(b).await;
        let retained = fixture.run(a).await;
        let recent = fixture.run(a).await;
        let key = format!("tenants/{a}/runs/{expired}/report");
        let retained_key = format!("tenants/{a}/runs/{retained}/report");
        let recent_key = format!("tenants/{a}/runs/{recent}/report");
        fixture.artifact(a, expired, &key).await;
        fixture.artifact(a, retained, &retained_key).await;
        fixture.artifact(a, recent, &recent_key).await;
        // A Run's results are also durable references, even when a previous
        // metadata-finalization failure left no row in run_artifacts.
        sqlx::query("UPDATE runs SET results=$2 WHERE id=$1")
            .bind(live)
            .bind(json!({"artifacts":[{"name":"shared","object_key":key,"size_bytes":4}]}))
            .execute(&fixture.repository.pool)
            .await
            .unwrap();
        fixture.terminal(expired, now - Duration::hours(3)).await;
        fixture.terminal(retained, now - Duration::hours(3)).await;
        fixture.terminal(recent, now - Duration::minutes(1)).await;
        sqlx::query("UPDATE runs SET retained_sandbox_id=$2,retained_until=$3 WHERE id=$1")
            .bind(retained)
            .bind(Uuid::new_v4())
            .bind(now - Duration::minutes(1))
            .execute(&fixture.repository.pool)
            .await
            .unwrap();
        // An aged orphan is not abandoned while its producer is still live.
        let pending = format!("tenants/{b}/runs/{live}/pending");
        fixture
            .repository
            .reserve_artifact_upload(b, Some(live), &pending)
            .await
            .unwrap();
        fixture.age_objects(now).await;
        assert!(
            fixture
                .repository
                .claim_artifact_deletions(now, 3600, 600, 100, 300)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            MetadataStore::list_run_artifacts(&fixture.repository, a, expired)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            MetadataStore::list_run_artifacts(&fixture.repository, a, retained)
                .await
                .unwrap()[0]
                .object_key,
            retained_key
        );
        assert_eq!(
            MetadataStore::list_run_artifacts(&fixture.repository, a, recent)
                .await
                .unwrap()[0]
                .object_key,
            recent_key
        );
        let marker: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT artifacts_expired_at FROM runs WHERE id=$1")
                .bind(expired)
                .fetch_one(&fixture.repository.pool)
                .await
                .unwrap();
        assert_eq!(marker.unwrap().timestamp_micros(), now.timestamp_micros());
        let event: String = sqlx::query_scalar("SELECT type FROM run_events WHERE run_id=$1")
            .bind(expired)
            .fetch_one(&fixture.repository.pool)
            .await
            .unwrap();
        assert_eq!(event, "artifacts.expired");
        sqlx::query("UPDATE runs SET results='{}'::jsonb WHERE id=$1")
            .bind(live)
            .execute(&fixture.repository.pool)
            .await
            .unwrap();
        let claims = fixture
            .repository
            .claim_artifact_deletions(now, 3600, 600, 100, 300)
            .await
            .unwrap();
        assert_eq!(
            claims
                .iter()
                .map(|claim| claim.key.as_str())
                .collect::<Vec<_>>(),
            vec![key.as_str()]
        );
        assert_eq!(claims[0].tenant_id, a);
        assert!(
            MetadataStore::put_run_artifacts(&fixture.repository, b, expired, Vec::new())
                .await
                .is_err()
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn failed_external_delete_retries_and_stale_acks_cannot_retire_new_claims() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let tenant = fixture.tenant().await;
        let now = Utc::now();
        let run = fixture.run(tenant).await;
        let key = format!("tenants/{tenant}/runs/{run}/archive");
        fixture
            .repository
            .reserve_artifact_upload(tenant, Some(run), &key)
            .await
            .unwrap();
        assert!(
            fixture
                .repository
                .complete_artifact_upload(Uuid::new_v4(), Some(run), &key)
                .await
                .is_err()
        );
        sqlx::query("DELETE FROM runs WHERE id=$1")
            .bind(run)
            .execute(&fixture.repository.pool)
            .await
            .unwrap();
        fixture.age_objects(now).await;
        let root = std::env::temp_dir().join(format!("aiec-gc-delete-{}", Uuid::new_v4()));
        let store = FilesystemObjectStore::new(&root);
        // A real failed backend operation, not a mock that echoes its inputs.
        tokio::fs::create_dir_all(root.join(&key)).await.unwrap();
        let claim = fixture
            .repository
            .claim_artifact_deletions(now, 3600, 600, 1, 300)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(claim.key, key);
        assert!(ArtifactStore::delete(&store, &claim.key).await.is_err());
        fixture
            .repository
            .finish_artifact_deletion(&key, claim.claim, false, now + Duration::seconds(60))
            .await
            .unwrap();
        assert!(
            fixture
                .repository
                .claim_artifact_deletions(now + Duration::seconds(59), 3600, 600, 1, 300)
                .await
                .unwrap()
                .is_empty()
        );
        let retry = fixture
            .repository
            .claim_artifact_deletions(now + Duration::seconds(61), 3600, 600, 1, 300)
            .await
            .unwrap()
            .remove(0);
        assert_ne!(retry.claim, claim.claim);
        assert!(
            fixture
                .repository
                .finish_artifact_deletion(&key, claim.claim, true, now)
                .await
                .is_err()
        );
        tokio::fs::remove_dir(root.join(&key)).await.unwrap();
        ArtifactStore::put(&store, &key, Bytes::from_static(b"data"))
            .await
            .unwrap();
        ArtifactStore::delete(&store, &retry.key).await.unwrap();
        fixture
            .repository
            .finish_artifact_deletion(&key, retry.claim, true, now)
            .await
            .unwrap();
        assert!(!root.join(&key).exists());
        assert!(
            fixture
                .repository
                .claim_artifact_deletions(now + Duration::hours(1), 3600, 600, 100, 300)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            fixture
                .repository
                .reserve_artifact_upload(tenant, None, &key)
                .await
                .is_err()
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
        fixture.close().await;
    }

    #[tokio::test]
    async fn an_object_key_that_does_not_name_its_tenant_is_refused() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let tenant = fixture.tenant().await;
        // Snapshot archives used to be keyed `{sandbox}-{uuid}`, with the tenant
        // living only in the row. Every other object key names its tenant, and
        // this branch is the only one that had no prefix to check, so a key
        // belonging to nobody in particular was accepted.
        for key in [
            "snapshot-archive".to_owned(),
            format!("sandbox-{}", Uuid::new_v4()),
            format!("tenants/{}/snapshots/{}", Uuid::new_v4(), Uuid::new_v4()),
        ] {
            assert!(
                fixture
                    .repository
                    .reserve_artifact_upload(tenant, None, &key)
                    .await
                    .is_err(),
                "{key} should not be claimable by tenant {tenant}"
            );
        }
        // And the tenant's own key still is, or the check is just a wall.
        let mine = format!("tenants/{tenant}/snapshots/{}", Uuid::new_v4());
        fixture
            .repository
            .reserve_artifact_upload(tenant, None, &mine)
            .await
            .unwrap();
        fixture.close().await;
    }

    #[tokio::test]
    async fn reference_creation_and_deletion_claims_are_atomic() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let tenant = fixture.tenant().await;
        let run = fixture.run(tenant).await;
        let now = Utc::now();
        let key = format!("tenants/{tenant}/shared");
        fixture
            .repository
            .reserve_artifact_upload(tenant, None, &key)
            .await
            .unwrap();
        fixture.age_objects(now).await;
        let mut reference = fixture.repository.pool.begin().await.unwrap();
        sqlx::query("INSERT INTO run_artifacts(id,run_id,name,object_key,size_bytes) VALUES($1,$2,'shared',$3,4)")
            .bind(Uuid::new_v4()).bind(run).bind(&key).execute(&mut *reference).await.unwrap();
        // The reference is invisible to this transaction, but its object row
        // lock forces the claimant to skip it instead of deleting underneath it.
        assert!(
            fixture
                .repository
                .claim_artifact_deletions(now, 3600, 600, 100, 300)
                .await
                .unwrap()
                .is_empty()
        );
        reference.commit().await.unwrap();
        fixture.age_objects(now).await;
        assert!(
            fixture
                .repository
                .claim_artifact_deletions(now, 3600, 600, 100, 300)
                .await
                .unwrap()
                .is_empty()
        );
        sqlx::query("DELETE FROM run_artifacts WHERE run_id=$1")
            .bind(run)
            .execute(&fixture.repository.pool)
            .await
            .unwrap();
        let claim = fixture
            .repository
            .claim_artifact_deletions(now, 3600, 600, 1, 300)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(claim.key, key);
        assert!(sqlx::query("INSERT INTO run_artifacts(id,run_id,name,object_key,size_bytes) VALUES($1,$2,'late',$3,4)")
            .bind(Uuid::new_v4()).bind(run).bind(&key).execute(&fixture.repository.pool).await.is_err());
        assert!(
            sqlx::query("UPDATE runs SET results=$2 WHERE id=$1")
                .bind(run)
                .bind(json!({"artifacts":[{"object_key":key}]}))
                .execute(&fixture.repository.pool)
                .await
                .is_err()
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn snapshot_roles_block_deletion_and_batches_resume_without_reusing_claims() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let tenant = fixture.tenant().await;
        let other_tenant = fixture.tenant().await;
        let now = Utc::now();
        let shared = format!("tenants/{tenant}/shared");
        fixture
            .repository
            .reserve_artifact_upload(tenant, None, &shared)
            .await
            .unwrap();
        let sandbox = Uuid::new_v4();
        sqlx::query("INSERT INTO sandboxes(id,tenant_id,image_id,state,runtime,cpu,memory_mb,disk_mb,timeout_seconds,network,created_at,updated_at) \
            VALUES($1,$2,'image','destroyed','docker',1,128,128,60,'{}',now(),now())")
            .bind(sandbox).bind(other_tenant).execute(&fixture.repository.pool).await.unwrap();
        let snapshot = Uuid::new_v4();
        sqlx::query("INSERT INTO snapshots(id,tenant_id,sandbox_id,object_key,manifest_object_key,workspace_object_key,size_bytes,image_id,created_at) \
            VALUES($1,$2,$3,$4,$5,$6,4,'image',now())")
            .bind(snapshot)
            .bind(other_tenant)
            .bind(sandbox)
            .bind(format!("tenants/{other_tenant}/aaa-snapshot/image"))
            .bind(format!("tenants/{other_tenant}/aaa-snapshot/image.manifest.json"))
            .bind(&shared)
            .execute(&fixture.repository.pool).await.unwrap();
        let keys = [
            format!("tenants/{tenant}/zzz-orphan-a"),
            format!("tenants/{tenant}/zzz-orphan-b"),
        ];
        for key in &keys {
            fixture
                .repository
                .reserve_artifact_upload(tenant, None, key)
                .await
                .unwrap();
        }
        fixture.age_objects(now).await;
        // The two protected snapshot keys sort first. A pass inspects one bounded
        // window, so it claims nothing until the window has moved past them, and
        // the orphans behind them are drained rather than starved.
        let mut claimed = Vec::new();
        for _ in 0..16 {
            let batch = fixture
                .repository
                .claim_artifact_deletions(now, 3600, 600, 1, 300)
                .await
                .unwrap();
            assert!(batch.len() <= 1, "one pass claims at most its window");
            claimed.extend(batch);
            if claimed.len() == keys.len() {
                break;
            }
        }
        // No starvation: the orphans behind the protected keys are eventually
        // drained rather than blocked forever by a window that refuses to scan
        // past them.
        assert_eq!(claimed.len(), keys.len());
        // How many passes came back empty is a property of the whole table, and
        // this suite shares one database with tests that are ageing their own
        // objects concurrently, so it is not asserted here. What is asserted is
        // the part this code decides: a pass claims at most its window and does
        // not skip ahead of a protected row to reach an eligible one.
        let mut claimed_keys = claimed
            .iter()
            .map(|claim| claim.key.clone())
            .collect::<Vec<_>>();
        claimed_keys.sort();
        assert_eq!(claimed_keys, keys);
        assert!(
            fixture
                .repository
                .claim_artifact_deletions(now, 3600, 600, 100, 300)
                .await
                .unwrap()
                .is_empty()
        );
        let reclaimed = fixture
            .repository
            .claim_artifact_deletions(now + Duration::seconds(301), 3600, 600, 100, 300)
            .await
            .unwrap();
        let mut reclaimed_keys = reclaimed
            .iter()
            .map(|claim| claim.key.clone())
            .collect::<Vec<_>>();
        reclaimed_keys.sort();
        assert_eq!(reclaimed_keys, keys);
        assert!(
            reclaimed
                .iter()
                .all(|claim| !claimed.iter().any(|earlier| earlier.claim == claim.claim))
        );
        sqlx::query("DELETE FROM snapshots WHERE id=$1")
            .bind(snapshot)
            .execute(&fixture.repository.pool)
            .await
            .unwrap();
        let released = fixture
            .repository
            .claim_artifact_deletions(now + Duration::seconds(301), 3600, 600, 100, 300)
            .await
            .unwrap();
        let mut released_keys = released
            .iter()
            .map(|claim| claim.key.as_str())
            .collect::<Vec<_>>();
        released_keys.sort();
        // The protected keys are another tenant's and sort ahead of this
        // tenant's orphans, so the window has to move past them before it
        // reaches anything it may delete.
        // Named so the ordering this test is about holds by construction rather
        // than by whichever way two random tenant ids happen to compare. The
        // protected keys must sort ahead of the orphans; that is the premise,
        // and a premise that depends on a UUID is a premise that fails
        // intermittently for reasons the test never mentions.
        let protected_image = format!("tenants/{other_tenant}/aaa-snapshot/image");
        let protected_manifest = format!("tenants/{other_tenant}/aaa-snapshot/image.manifest.json");
        let mut expected = vec![
            shared.as_str(),
            protected_image.as_str(),
            protected_manifest.as_str(),
        ];
        expected.sort();
        assert_eq!(released_keys, expected);
        fixture.close().await;
    }

    #[tokio::test]
    async fn stored_only_snapshots_are_listed_and_released_only_for_their_owner() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let tenant = fixture.tenant().await;
        let stranger = fixture.tenant().await;
        let now = Utc::now();
        let sandbox = Uuid::new_v4();
        sqlx::query("INSERT INTO sandboxes(id,tenant_id,image_id,state,runtime,cpu,memory_mb,disk_mb,timeout_seconds,network,created_at,updated_at) \
            VALUES($1,$2,'image','destroyed','docker',1,128,128,60,'{}',now(),now())")
            .bind(sandbox).bind(tenant).execute(&fixture.repository.pool).await.unwrap();
        // Tenant-prefixed, because a claim is refused for a key that does not
        // name its tenant, and the API writes every object key that way.
        let primary = format!("tenants/{tenant}/snapshots/{sandbox}/primary");
        let manifest = format!("tenants/{tenant}/snapshots/{sandbox}/primary.manifest.json");
        for key in [&primary, &manifest] {
            fixture
                .repository
                .reserve_artifact_upload(tenant, None, key)
                .await
                .unwrap();
        }
        // One write, exactly as the API records a capture.
        let stored = StoredSnapshot {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            sandbox_id: sandbox,
            object_key: primary.clone(),
            manifest_object_key: manifest.clone(),
            memory_object_key: None,
            disk_object_key: None,
            workspace_object_key: Some(primary.clone()),
            size_bytes: 4,
            image_id: "image".into(),
            checksum_sha256: "a".repeat(64),
            kind: "workspace".into(),
            complete: true,
            manifest: json!({}),
            created_at: now,
        };
        MetadataStore::put_stored_snapshot(&fixture.repository, stored.clone())
            .await
            .unwrap();
        let listed = MetadataStore::list_snapshots(&fixture.repository, tenant, sandbox)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, stored.id);
        assert_eq!(listed[0].object_key, primary);
        assert!(
            MetadataStore::list_snapshots(&fixture.repository, stranger, sandbox)
                .await
                .unwrap()
                .is_empty()
        );
        fixture.age_objects(now).await;
        // Another tenant retires nothing and releases no object.
        assert!(
            MetadataStore::delete_snapshot(&fixture.repository, stranger, stored.id)
                .await
                .is_err()
        );
        assert!(
            fixture
                .repository
                .claim_artifact_deletions(now, 3600, 600, 100, 300)
                .await
                .unwrap()
                .is_empty()
        );
        MetadataStore::delete_snapshot(&fixture.repository, tenant, stored.id)
            .await
            .unwrap();
        assert!(
            MetadataStore::get_snapshot(&fixture.repository, tenant, stored.id)
                .await
                .is_err()
        );
        let released = fixture
            .repository
            .claim_artifact_deletions(now, 3600, 600, 100, 300)
            .await
            .unwrap();
        let mut released_keys = released
            .iter()
            .map(|claim| claim.key.as_str())
            .collect::<Vec<_>>();
        released_keys.sort();
        let mut expected = vec![manifest.as_str(), primary.as_str()];
        expected.sort();
        assert_eq!(released_keys, expected);
        fixture.close().await;
    }

    #[tokio::test]
    async fn terminal_expiry_retires_large_artifact_sets_in_bounded_batches() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let tenant = fixture.tenant().await;
        let run = fixture.run(tenant).await;
        let now = Utc::now();
        let artifacts = (0..3)
            .map(|index| RunArtifactRef {
                name: format!("report-{index}"),
                object_key: format!("tenants/{tenant}/runs/{run}/report-{index}"),
                size_bytes: 4,
                checksum_sha256: None,
                content_type: None,
            })
            .collect::<Vec<_>>();
        MetadataStore::put_run_artifacts(&fixture.repository, tenant, run, artifacts.clone())
            .await
            .unwrap();
        sqlx::query("UPDATE runs SET results=$2 WHERE id=$1")
            .bind(run)
            .bind(json!({"artifacts": artifacts}))
            .execute(&fixture.repository.pool)
            .await
            .unwrap();
        fixture.terminal(run, now - Duration::hours(3)).await;
        fixture.age_objects(now).await;
        let mut claimed = Vec::new();
        for remaining in (0..3).rev() {
            let claims = fixture
                .repository
                .claim_artifact_deletions(now, 3600, 600, 1, 300)
                .await
                .unwrap();
            assert_eq!(claims.len(), 1);
            claimed.push(claims[0].key.clone());
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM run_artifacts WHERE run_id=$1")
                    .bind(run)
                    .fetch_one(&fixture.repository.pool)
                    .await
                    .unwrap();
            assert_eq!(count, remaining);
            assert!(
                MetadataStore::list_run_artifacts(&fixture.repository, tenant, run)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        claimed.sort();
        assert_eq!(
            claimed,
            artifacts
                .iter()
                .map(|artifact| artifact.object_key.clone())
                .collect::<Vec<_>>()
        );
        let results: serde_json::Value = sqlx::query_scalar("SELECT results FROM runs WHERE id=$1")
            .bind(run)
            .fetch_one(&fixture.repository.pool)
            .await
            .unwrap();
        assert_eq!(results["artifacts"], json!([]));
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM run_events WHERE run_id=$1 AND type='artifacts.expired'",
        )
        .bind(run)
        .fetch_one(&fixture.repository.pool)
        .await
        .unwrap();
        assert_eq!(events, 1);
        assert!(
            fixture
                .repository
                .claim_artifact_deletions(now, 3600, 600, 1, 300)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            MetadataStore::put_run_artifacts(&fixture.repository, tenant, run, artifacts)
                .await
                .is_err()
        );
        fixture.close().await;
    }
}
