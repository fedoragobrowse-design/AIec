//! Bounded artifact reclamation. Only storage decides whether a key is safe;
//! every external delete runs after its durable claim transaction has committed.
use aiec_core::{
    CoreError,
    storage::{ArtifactStore, MetadataStore},
};
use chrono::{Duration, Utc};
use futures::{StreamExt, stream};

pub const MAX_ARTIFACT_UPLOAD_SECONDS: u64 = 300;
const DELETE_TIMEOUT_SECONDS: u64 = 10;
const DELETE_CONCURRENCY: usize = 4;
const DELETION_LEASE_SECONDS: i64 = 300;
const RETRY_SECONDS: i64 = 60;

#[derive(Clone, Debug)]
pub struct ArtifactGcConfig {
    /// Terminal Run evidence remains available for this long after completion.
    pub retention_seconds: i64,
    /// Unreferenced uploads and abandoned local staging files must be this old.
    /// Always longer than the maximum upload deadline.
    pub pending_grace_seconds: i64,
    /// Independent bound for Run expiry, metadata retirement, deletes and temp scanning.
    pub batch_size: u32,
}

impl Default for ArtifactGcConfig {
    fn default() -> Self {
        Self {
            retention_seconds: 30 * 24 * 3600,
            pending_grace_seconds: 3600,
            batch_size: 100,
        }
    }
}

impl ArtifactGcConfig {
    pub fn from_env() -> Result<Self, CoreError> {
        fn number<T: std::str::FromStr>(name: &str, fallback: T) -> Result<T, CoreError> {
            match std::env::var(name) {
                Ok(value) => value
                    .parse()
                    .map_err(|_| CoreError::InvalidRequest(format!("{name} must be an integer"))),
                Err(std::env::VarError::NotPresent) => Ok(fallback),
                Err(_) => Err(CoreError::InvalidRequest(format!("{name} is not UTF-8"))),
            }
        }
        let defaults = Self::default();
        let config = Self {
            retention_seconds: number(
                "AIEC_ARTIFACT_RETENTION_SECONDS",
                defaults.retention_seconds,
            )?,
            pending_grace_seconds: number(
                "AIEC_ARTIFACT_PENDING_GRACE_SECONDS",
                defaults.pending_grace_seconds,
            )?,
            batch_size: number("AIEC_ARTIFACT_GC_BATCH_SIZE", defaults.batch_size)?,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), CoreError> {
        if !(1..=315_360_000).contains(&self.retention_seconds)
            || !(600..=315_360_000).contains(&self.pending_grace_seconds)
            || !(1..=100).contains(&self.batch_size)
        {
            return Err(CoreError::InvalidRequest(
                "artifact GC retention must be 1..315360000 seconds, pending grace 600..315360000 seconds, and batch size 1..100".into()
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ArtifactGcOutcome {
    pub claimed: usize,
    pub deleted: usize,
    pub retrying: usize,
    pub stale_claims: usize,
    pub temporary_files_deleted: u32,
}

pub async fn sweep_artifacts(
    repository: &dyn MetadataStore,
    store: &dyn ArtifactStore,
    config: &ArtifactGcConfig,
) -> Result<ArtifactGcOutcome, CoreError> {
    config.validate()?;
    let now = Utc::now();
    let claims = repository
        .claim_artifact_deletions(
            now,
            config.retention_seconds,
            config.pending_grace_seconds,
            config.batch_size,
            DELETION_LEASE_SECONDS,
        )
        .await?;
    let mut outcome = ArtifactGcOutcome {
        claimed: claims.len(),
        ..Default::default()
    };
    let mut deletions = stream::iter(claims).map(|claim| async move {
        let deleted = match tokio::time::timeout(
            std::time::Duration::from_secs(DELETE_TIMEOUT_SECONDS), store.delete(&claim.key)
        ).await {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                tracing::warn!(tenant = %claim.tenant_id, key = %claim.key, %error, "artifact deletion will retry");
                false
            }
            Err(_) => {
                tracing::warn!(tenant = %claim.tenant_id, key = %claim.key, "artifact deletion timed out; will retry");
                false
            }
        };
        let acknowledged = repository.finish_artifact_deletion(
            &claim.key, claim.claim, deleted, Utc::now() + Duration::seconds(RETRY_SECONDS),
        ).await;
        if let Err(error) = &acknowledged {
            tracing::warn!(key = %claim.key, %error, "artifact deletion claim acknowledgement failed");
        }
        (deleted, acknowledged.is_ok())
    }).buffer_unordered(DELETE_CONCURRENCY);
    while let Some((deleted, acknowledged)) = deletions.next().await {
        if !acknowledged {
            outcome.stale_claims += 1;
        } else if deleted {
            outcome.deleted += 1;
        } else {
            outcome.retrying += 1;
        }
    }
    outcome.temporary_files_deleted = store
        .cleanup_temporary_uploads(
            now - Duration::seconds(config.pending_grace_seconds),
            config.batch_size,
        )
        .await?;
    Ok(outcome)
}
