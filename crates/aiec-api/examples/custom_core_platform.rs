use aiec_core::{
    CreateSandboxRequest, NetworkPolicy, Sandbox, SandboxState,
    network::{NetworkAttachment, NetworkBackend, NetworkCapabilities},
    platform::Platform,
    policy::{PlatformPolicy, PolicyDecision, PolicyOperation},
    runtime::{RuntimeCapabilities, RuntimeHealth, SandboxRuntime},
    scheduler::{ScheduleRequest, ScheduledSandbox, Scheduler},
    snapshots::{SnapshotCapabilities, SnapshotProvider},
    storage::MetadataStore,
};
use aiec_runtime::BubblewrapRuntime;
use aiec_storage::{FilesystemObjectStore, MemoryRepository, StandardImageResolver};
use async_trait::async_trait;
use std::sync::Arc;

struct SingleCpuPolicy;

impl PlatformPolicy for SingleCpuPolicy {
    fn evaluate(&self, operation: PolicyOperation<'_>) -> PolicyDecision {
        match operation {
            PolicyOperation::CreateSandbox(request) if request.cpu > 1 => {
                PolicyDecision::deny("custom platform permits one vCPU")
            }
            PolicyOperation::Sandbox(sandbox) if sandbox.cpu > 1 => {
                PolicyDecision::deny("custom platform permits one vCPU")
            }
            _ => PolicyDecision::allow(),
        }
    }
}

struct InlineScheduler;

#[async_trait]
impl Scheduler for InlineScheduler {
    async fn schedule(
        &self,
        request: ScheduleRequest,
    ) -> Result<ScheduledSandbox, aiec_core::CoreError> {
        if request.request_id.is_nil() {
            return Err(aiec_core::CoreError::InvalidRequest(
                "request id is required".into(),
            ));
        }
        Ok(ScheduledSandbox {
            sandbox: request.sandbox,
            worker_id: request.tenant_id,
            worker_endpoint: "inline://worker".into(),
            lease_id: request.request_id,
            lease_generation: 1,
        })
    }

    async fn dispatch_target(
        &self,
        _tenant_id: aiec_core::TenantId,
        _sandbox_id: aiec_core::SandboxId,
    ) -> Result<aiec_core::scheduler::WorkerDispatch, aiec_core::CoreError> {
        Err(aiec_core::CoreError::Unsupported(
            "inline execution does not dispatch to workers".into(),
        ))
    }

    async fn release(
        &self,
        _tenant_id: aiec_core::TenantId,
        _sandbox_id: aiec_core::SandboxId,
    ) -> Result<(), aiec_core::CoreError> {
        Ok(())
    }
}

struct CompileOnlyNetwork;

#[async_trait]
impl NetworkBackend for CompileOnlyNetwork {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            restricted_allowlists: true,
            dns_controls: true,
            bandwidth_limits: true,
        }
    }

    async fn prepare(
        &self,
        _sandbox: &Sandbox,
        policy: &NetworkPolicy,
    ) -> Result<NetworkAttachment, aiec_core::CoreError> {
        if policy.is_enabled() {
            return Err(aiec_core::CoreError::Unsupported(
                "example network validates policy but does not create host interfaces".into(),
            ));
        }
        Ok(NetworkAttachment::default())
    }

    async fn release(
        &self,
        _sandbox: &Sandbox,
        _attachment: &NetworkAttachment,
    ) -> Result<(), aiec_core::CoreError> {
        Ok(())
    }
}

fn sandbox(tenant_id: aiec_core::TenantId) -> Sandbox {
    let now = chrono::Utc::now();
    Sandbox {
        id: aiec_core::new_id(),
        tenant_id,
        node_id: None,
        image_id: aiec_core::image_id("python:3.13"),
        state: SandboxState::Creating,
        runtime: aiec_core::RuntimeKind::BwrapDev,
        cpu: 1,
        memory_mb: 512,
        disk_mb: 2048,
        timeout_seconds: 300,
        network: NetworkPolicy::Disabled,
        environment: Default::default(),
        created_at: now,
        updated_at: now,
        runtime_path: None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state_dir = std::env::temp_dir().join(format!("aiec-core-example-{}", aiec_core::new_id()));
    std::fs::create_dir_all(&state_dir)?;

    let runtime = Arc::new(BubblewrapRuntime::new(&state_dir));
    let runtime_trait: Arc<dyn SandboxRuntime> = runtime.clone();
    let snapshots: Arc<dyn SnapshotProvider> = runtime;
    let metadata: Arc<dyn MetadataStore> = MemoryRepository::new();
    let scheduler: Arc<dyn Scheduler> = Arc::new(InlineScheduler);
    let artifacts: Arc<dyn aiec_core::storage::ArtifactStore> =
        Arc::new(FilesystemObjectStore::new(state_dir.join("artifacts")));
    let network: Arc<dyn NetworkBackend> = Arc::new(CompileOnlyNetwork);
    let images: Arc<dyn aiec_core::images::ImageResolver> =
        Arc::new(StandardImageResolver::new("/dev/null"));
    let policy: Arc<dyn PlatformPolicy> = Arc::new(SingleCpuPolicy);

    let platform = Platform::builder()
        .runtime(runtime_trait.clone())
        .metadata_store(metadata)
        .scheduler(scheduler.clone())
        .artifact_store(artifacts.clone())
        .network(network.clone())
        .images(images)
        .snapshots(snapshots)
        .policy(policy.clone())
        .build()?;

    let tenant_id = aiec_core::new_id();
    let scheduled = scheduler
        .schedule(ScheduleRequest {
            tenant_id,
            request_id: aiec_core::new_id(),
            sandbox: sandbox(tenant_id),
            preferred_worker: None,
            lease_ttl: std::time::Duration::from_secs(60),
            required_capabilities: Default::default(),
            run_id: None,
        })
        .await?;
    assert_eq!(scheduled.worker_endpoint, "inline://worker");

    let valid = CreateSandboxRequest {
        image: "python:3.13".into(),
        cpu: 1,
        memory_mb: 512,
        disk_mb: 2048,
        timeout_seconds: 300,
        network: NetworkPolicy::Disabled,
        environment: Default::default(),
    };
    assert!(
        policy
            .evaluate(PolicyOperation::CreateSandbox(&valid))
            .allowed
    );
    let oversized = CreateSandboxRequest { cpu: 2, ..valid };
    assert!(
        !policy
            .evaluate(PolicyOperation::CreateSandbox(&oversized))
            .allowed
    );

    let metadata = platform.artifact_store().expect("artifact store");
    let stored = metadata
        .put(
            "validation/artifact",
            bytes::Bytes::from_static(b"core-extension"),
        )
        .await?;
    assert_eq!(stored.size_bytes, 14);
    assert_eq!(
        metadata.get("validation/artifact").await?,
        b"core-extension"
    );
    metadata.delete("validation/artifact").await?;

    let attachment = network
        .prepare(&scheduled.sandbox, &NetworkPolicy::Disabled)
        .await?;
    assert!(attachment.resource.is_empty());
    assert!(platform.runtime().capabilities().workspace_snapshot);
    assert!(
        platform
            .snapshots()
            .expect("snapshot provider")
            .capabilities()
            .workspace
    );
    let _: RuntimeCapabilities = platform.runtime().capabilities();
    let _: RuntimeHealth = platform.runtime().health().await;
    let _: SnapshotCapabilities = platform
        .snapshots()
        .expect("snapshot provider")
        .capabilities();

    std::fs::remove_dir_all(&state_dir)?;
    println!(
        "custom Core platform validated: runtime={:?}, scheduler={}, artifact=filesystem, network=custom",
        platform.runtime().capabilities(),
        scheduled.worker_endpoint
    );
    Ok(())
}
