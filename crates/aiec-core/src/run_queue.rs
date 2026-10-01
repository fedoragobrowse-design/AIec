//! Durable Run admission and executor ownership, independent of HTTP requests.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CoreError, run::Run};

/// Cluster-wide ceilings; every dispatcher sharing a database uses the same limits.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RunQueueLimits {
    pub global_pending: u32,
    pub tenant_pending: u32,
    pub max_active: u32,
    pub queue_timeout_seconds: u32,
    pub lease_seconds: u32,
}

impl Default for RunQueueLimits {
    fn default() -> Self {
        Self {
            global_pending: 1024,
            tenant_pending: 128,
            max_active: 4,
            queue_timeout_seconds: 300,
            lease_seconds: 30,
        }
    }
}

impl RunQueueLimits {
    /// Read once during service construction, never on an admission request.
    pub fn from_env() -> Result<Self, CoreError> {
        fn value(name: &str, default: u32) -> Result<u32, CoreError> {
            match std::env::var(name) {
                Ok(value) => value
                    .parse()
                    .map_err(|_| CoreError::InvalidRequest(format!("{name} must be an integer"))),
                Err(std::env::VarError::NotPresent) => Ok(default),
                Err(_) => Err(CoreError::InvalidRequest(format!("{name} must be UTF-8"))),
            }
        }
        let defaults = Self::default();
        Self {
            global_pending: value("AIEC_RUN_QUEUE_GLOBAL_PENDING", defaults.global_pending)?,
            tenant_pending: value("AIEC_RUN_QUEUE_TENANT_PENDING", defaults.tenant_pending)?,
            max_active: value("AIEC_RUN_QUEUE_MAX_ACTIVE", defaults.max_active)?,
            queue_timeout_seconds: value(
                "AIEC_RUN_QUEUE_TIMEOUT_SECONDS",
                defaults.queue_timeout_seconds,
            )?,
            lease_seconds: value("AIEC_RUN_QUEUE_LEASE_SECONDS", defaults.lease_seconds)?,
        }
        .validate()
    }

    pub fn validate(self) -> Result<Self, CoreError> {
        if self.global_pending == 0
            || self.global_pending > 100_000
            || self.tenant_pending == 0
            || self.tenant_pending > self.global_pending
            || self.max_active == 0
            || self.max_active > 256
            || self.max_active > self.global_pending
            || !(1..=86_400).contains(&self.queue_timeout_seconds)
            || !(6..=300).contains(&self.lease_seconds)
        {
            return Err(CoreError::InvalidRequest("invalid Run queue limits".into()));
        }
        Ok(self)
    }
}

/// A committed ownership grant. `request` contains unresolved secret references.
/// Never log or expose this document through public queue diagnostics.
#[derive(Clone, Debug)]
pub struct RunQueueClaim {
    pub run: Run,
    pub request: serde_json::Value,
    pub owner: Uuid,
    pub lease_until: DateTime<Utc>,
    /// Fixed once execution starts; heartbeats cannot extend it.
    pub execution_deadline: Option<DateTime<Utc>>,
    /// Recovery grants authorize teardown only, never executing the request again.
    pub reclaiming: bool,
}
