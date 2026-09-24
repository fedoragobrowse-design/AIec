use agentforge_core::{
    policy::{PlatformPolicy, PolicyDecision, PolicyOperation},
    scheduler::{ScheduleRequest, ScheduledSandbox, Scheduler},
    CoreError, CreateSandboxRequest, RestoreSnapshotRequest, Sandbox, TenantId, SandboxId,
};
use async_trait::async_trait;

/// AgentForge's resource and lifetime policy applied before scheduling.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultPolicy;

impl PlatformPolicy for DefaultPolicy {
    fn evaluate(&self, operation: PolicyOperation<'_>) -> PolicyDecision {
        let result = match operation {
            PolicyOperation::CreateSandbox(request) => validate_create(request),
            PolicyOperation::RestoreSnapshot(request) => validate_restore(request),
            PolicyOperation::Sandbox(sandbox) => validate_sandbox(sandbox),
        };
        match result {
            Ok(()) => PolicyDecision::allow(),
            Err(error) => PolicyDecision::deny(error.to_string()),
        }
    }
}

fn validate_create(request: &CreateSandboxRequest) -> Result<(), CoreError> {
    agentforge_core::validate_create(request, agentforge_core::MAX_LIFETIME_SECONDS)
}

fn validate_restore(request: &RestoreSnapshotRequest) -> Result<(), CoreError> {
    validate_optional_resources(request.cpu, request.memory_mb, request.disk_mb)
}

fn validate_sandbox(sandbox: &Sandbox) -> Result<(), CoreError> {
    validate_resources(sandbox.cpu, sandbox.memory_mb, sandbox.disk_mb)
}

fn validate_optional_resources(
    cpu: Option<u32>,
    memory_mb: Option<u32>,
    disk_mb: Option<u32>,
) -> Result<(), CoreError> {
    validate_resources(cpu.unwrap_or(1), memory_mb.unwrap_or(512), disk_mb.unwrap_or(2048))
}

fn validate_resources(cpu: u32, memory_mb: u32, disk_mb: u32) -> Result<(), CoreError> {
    if cpu == 0 || cpu > agentforge_core::MAX_VCPU {
        return Err(CoreError::LimitExceeded("invalid vCPU count".into()));
    }
    if memory_mb == 0 || memory_mb > agentforge_core::MAX_MEMORY_MB {
        return Err(CoreError::LimitExceeded("invalid memory size".into()));
    }
    if disk_mb == 0 || disk_mb > agentforge_core::MAX_DISK_MB {
        return Err(CoreError::LimitExceeded("invalid disk size".into()));
    }
    Ok(())
}

/// Scheduler slot for the single-process development distribution.
///
/// Development execution is local to the API process, so no worker endpoint is
/// dispatched. The production launcher replaces this with the storage-backed
/// Core scheduler and never uses this implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct DevelopmentScheduler;

#[async_trait]
impl Scheduler for DevelopmentScheduler {
    async fn schedule(
        &self,
        request: ScheduleRequest,
    ) -> Result<ScheduledSandbox, CoreError> {
        Ok(ScheduledSandbox {
            sandbox: request.sandbox,
            worker_id: TenantId::nil(),
            worker_endpoint: String::new(),
            lease_id: SandboxId::nil(),
            lease_generation: 0,
        })
    }

    async fn worker_endpoint(
        &self,
        _tenant_id: TenantId,
        _sandbox_id: SandboxId,
    ) -> Result<String, CoreError> {
        Ok(String::new())
    }

    async fn release(
        &self,
        _tenant_id: TenantId,
        _sandbox_id: SandboxId,
    ) -> Result<(), CoreError> {
        Ok(())
    }
}
