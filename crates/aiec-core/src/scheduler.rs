//! Placement requests and lease-aware scheduling contracts.

use crate::runtime::RuntimeCapabilities;
use crate::{Sandbox, TenantId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub use crate::{LeaseId, RequestId, SandboxId, WorkerId};

/// Resources and placement constraints for one sandbox.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScheduleRequest {
    /// Tenant that owns the sandbox.
    pub tenant_id: TenantId,
    /// Caller idempotency key.
    pub request_id: RequestId,
    /// Sandbox to place.
    pub sandbox: Sandbox,
    /// Requested worker, when placement is pinned.
    pub preferred_worker: Option<WorkerId>,
    /// Duration of the worker lease.
    pub lease_ttl: Duration,
    /// Capabilities required of the actual worker, not only its runtime kind.
    #[serde(default)]
    pub required_capabilities: RuntimeCapabilities,
    /// Owning Run, linked atomically before any slow provisioning begins.
    #[serde(default)]
    pub run_id: Option<uuid::Uuid>,
}

/// Result of successfully acquiring capacity and a lease.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScheduledSandbox {
    /// Persisted sandbox, including its assigned worker.
    pub sandbox: Sandbox,
    /// Worker selected for execution.
    pub worker_id: WorkerId,
    /// Endpoint used to dispatch work to the worker.
    pub worker_endpoint: String,
    /// Fencing token for the acquired lease.
    pub lease_id: LeaseId,
    /// Monotonic generation used to reject stale lease holders.
    pub lease_generation: i64,
}

/// Atomic provisioning admission. A replay is never permission to build or roll back.
#[derive(Clone, Debug, PartialEq)]
pub struct ProvisionAdmission {
    pub scheduled: ScheduledSandbox,
    /// True only for the call that acquired a new lease, not a live-lease replay.
    pub acquired: bool,
}

/// Dispatch authority read from one active lease and its worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerDispatch {
    pub endpoint: String,
    pub lease_id: LeaseId,
    pub generation: i64,
}

/// Selects a worker and maintains the correctness boundary for work leases.
#[async_trait]
pub trait Scheduler: Send + Sync {
    /// Atomically places a sandbox and acquires a fenced lease.
    async fn schedule(
        &self,
        request: ScheduleRequest,
    ) -> Result<ScheduledSandbox, crate::CoreError>;
    /// Places a sandbox and distinguishes a newly acquired lease from a replay.
    ///
    /// Implementations must determine `acquired` in the admission transaction.
    /// A scheduler without that distinction cannot safely provision.
    async fn schedule_for_provision(
        &self,
        _request: ScheduleRequest,
    ) -> Result<ProvisionAdmission, crate::CoreError> {
        Err(crate::CoreError::Unsupported(
            "scheduler does not support owned provisioning admission".into(),
        ))
    }
    /// Resolves endpoint and fencing identity atomically from an unexpired lease.
    async fn dispatch_target(
        &self,
        tenant_id: TenantId,
        sandbox_id: SandboxId,
    ) -> Result<WorkerDispatch, crate::CoreError>;
    /// Releases any active lease for a sandbox.
    async fn release(
        &self,
        tenant_id: TenantId,
        sandbox_id: SandboxId,
    ) -> Result<(), crate::CoreError>;
}
