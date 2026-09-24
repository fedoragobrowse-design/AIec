//! Dependency-injection composition for an AgentForge deployment.

use crate::{
    images::ImageResolver,
    network::NetworkBackend,
    policy::PlatformPolicy,
    runtime::SandboxRuntime,
    scheduler::Scheduler,
    snapshots::SnapshotProvider,
    storage::{ArtifactStore, MetadataStore},
    CoreError,
};
use std::sync::Arc;

/// Validated set of backend trait objects used by a distribution.
#[derive(Clone)]
pub struct Platform {
    runtime: Arc<dyn SandboxRuntime>,
    metadata_store: Arc<dyn MetadataStore>,
    scheduler: Arc<dyn Scheduler>,
    artifact_store: Option<Arc<dyn ArtifactStore>>,
    network: Option<Arc<dyn NetworkBackend>>,
    images: Option<Arc<dyn ImageResolver>>,
    snapshots: Option<Arc<dyn SnapshotProvider>>,
    policy: Option<Arc<dyn PlatformPolicy>>,
}

impl Platform {
    /// Starts a builder containing no components.
    pub fn builder() -> PlatformBuilder {
        PlatformBuilder::new()
    }

    /// Returns the configured sandbox runtime.
    pub fn runtime(&self) -> Arc<dyn SandboxRuntime> {
        self.runtime.clone()
    }

    /// Returns the configured metadata store.
    pub fn metadata_store(&self) -> Arc<dyn MetadataStore> {
        self.metadata_store.clone()
    }

    /// Returns the configured scheduler.
    pub fn scheduler(&self) -> Arc<dyn Scheduler> {
        self.scheduler.clone()
    }

    /// Returns the optional artifact store.
    pub fn artifact_store(&self) -> Option<Arc<dyn ArtifactStore>> {
        self.artifact_store.clone()
    }

    /// Returns the optional network backend.
    pub fn network(&self) -> Option<Arc<dyn NetworkBackend>> {
        self.network.clone()
    }

    /// Returns the optional image resolver.
    pub fn images(&self) -> Option<Arc<dyn ImageResolver>> {
        self.images.clone()
    }

    /// Returns the optional snapshot provider.
    pub fn snapshots(&self) -> Option<Arc<dyn SnapshotProvider>> {
        self.snapshots.clone()
    }

    /// Returns the optional platform policy.
    pub fn policy(&self) -> Option<Arc<dyn PlatformPolicy>> {
        self.policy.clone()
    }
}

/// Type-safe builder for required and optional platform components.
#[derive(Default)]
pub struct PlatformBuilder {
    runtime: Option<Arc<dyn SandboxRuntime>>,
    metadata_store: Option<Arc<dyn MetadataStore>>,
    scheduler: Option<Arc<dyn Scheduler>>,
    artifact_store: Option<Arc<dyn ArtifactStore>>,
    network: Option<Arc<dyn NetworkBackend>>,
    images: Option<Arc<dyn ImageResolver>>,
    snapshots: Option<Arc<dyn SnapshotProvider>>,
    policy: Option<Arc<dyn PlatformPolicy>>,
}

impl PlatformBuilder {
    /// Creates an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the required sandbox runtime.
    pub fn runtime(mut self, runtime: Arc<dyn SandboxRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Sets the required metadata store.
    pub fn metadata_store(mut self, metadata_store: Arc<dyn MetadataStore>) -> Self {
        self.metadata_store = Some(metadata_store);
        self
    }

    /// Sets the required scheduler.
    pub fn scheduler(mut self, scheduler: Arc<dyn Scheduler>) -> Self {
        self.scheduler = Some(scheduler);
        self
    }

    /// Sets the optional artifact store.
    pub fn artifact_store(mut self, artifact_store: Arc<dyn ArtifactStore>) -> Self {
        self.artifact_store = Some(artifact_store);
        self
    }

    /// Sets the optional network backend.
    pub fn network(mut self, network: Arc<dyn NetworkBackend>) -> Self {
        self.network = Some(network);
        self
    }

    /// Sets the optional image resolver.
    pub fn images(mut self, images: Arc<dyn ImageResolver>) -> Self {
        self.images = Some(images);
        self
    }

    /// Sets the optional snapshot provider.
    pub fn snapshots(mut self, snapshots: Arc<dyn SnapshotProvider>) -> Self {
        self.snapshots = Some(snapshots);
        self
    }

    /// Sets the optional platform policy.
    pub fn policy(mut self, policy: Arc<dyn PlatformPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Validates required components and constructs the platform.
    pub fn build(self) -> Result<Platform, CoreError> {
        let missing = |name: &str| CoreError::InvalidRequest(format!("platform component `{name}` is required"));
        Ok(Platform {
            runtime: self.runtime.ok_or_else(|| missing("runtime"))?,
            metadata_store: self.metadata_store.ok_or_else(|| missing("metadata_store"))?,
            scheduler: self.scheduler.ok_or_else(|| missing("scheduler"))?,
            artifact_store: self.artifact_store,
            network: self.network,
            images: self.images,
            snapshots: self.snapshots,
            policy: self.policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_requires_runtime_metadata_and_scheduler() {
        assert!(Platform::builder().build().is_err());
    }
}
