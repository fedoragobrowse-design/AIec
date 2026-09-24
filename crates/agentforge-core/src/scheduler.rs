//! Placement requests and lease-aware scheduling contracts.

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

/// Selects a worker and maintains the correctness boundary for work leases.
#[async_trait]
pub trait Scheduler: Send + Sync {
    /// Atomically places a sandbox and acquires a fenced lease.
    async fn schedule(
        &self,
        request: ScheduleRequest,
    ) -> Result<ScheduledSandbox, crate::CoreError>;
    /// Resolves the current worker endpoint for a sandbox.
    async fn worker_endpoint(
        &self,
        tenant_id: TenantId,
        sandbox_id: SandboxId,
    ) -> Result<String, crate::CoreError>;
    /// Releases any active lease for a sandbox.
    async fn release(
        &self,
        tenant_id: TenantId,
        sandbox_id: SandboxId,
    ) -> Result<(), crate::CoreError>;
}
