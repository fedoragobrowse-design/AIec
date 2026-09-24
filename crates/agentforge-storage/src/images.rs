use agentforge_core::{
    CoreError,
    images::{ImageDigest, ImageReference, ImageResolver, ResolvedImage},
    image_id,
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const STANDARD_REFERENCES: &[&str] = &[
    "python:3.13",
    "node:24",
    "rust:stable",
    "ubuntu:24.04",
    "alpine:3.21",
];

/// Resolves AgentForge's standard image names to stable content-derived IDs.
#[derive(Clone, Debug)]
pub struct StandardImageResolver {
    rootfs: Arc<str>,
    size_bytes: u64,
}

impl StandardImageResolver {
    /// Creates a resolver for a runtime root filesystem whose size is not known statically.
    pub fn new(rootfs: impl Into<String>) -> Self {
        Self {
            rootfs: Arc::from(rootfs.into()),
            size_bytes: 0,
        }
    }

    /// Creates a resolver with known root filesystem size metadata.
    pub fn with_size(rootfs: impl Into<String>, size_bytes: u64) -> Self {
        Self {
            rootfs: Arc::from(rootfs.into()),
            size_bytes,
        }
    }

    /// Returns the image names supported by the standard distribution.
    pub fn references() -> &'static [&'static str] {
        STANDARD_REFERENCES
    }

    /// Returns the stable AgentForge content ID for an image reference.
    pub fn content_id(reference: &str) -> String {
        image_id(reference)
    }
}

#[async_trait]
impl ImageResolver for StandardImageResolver {
    async fn resolve(
        &self,
        reference: &ImageReference,
    ) -> Result<ResolvedImage, CoreError> {
        if !STANDARD_REFERENCES.contains(&reference.as_str()) {
            return Err(CoreError::InvalidRequest(format!(
                "unsupported image: {}",
                reference.as_str()
            )));
        }
        let digest = ImageDigest::new(hex::encode(Sha256::digest(reference.as_str().as_bytes())))?;
        Ok(ResolvedImage {
            reference: reference.clone(),
            image_id: Self::content_id(reference.as_str()),
            rootfs: self.rootfs.to_string(),
            digest,
            size_bytes: self.size_bytes,
            architecture: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn standard_reference_keeps_existing_content_id() {
        let resolver = StandardImageResolver::with_size("/images/rootfs.ext4", 4096);
        let reference = ImageReference::new("python:3.13").unwrap();
        let image = resolver.resolve(&reference).await.unwrap();
        assert_eq!(image.image_id, image_id("python:3.13"));
        assert_eq!(image.rootfs, "/images/rootfs.ext4");
        assert_eq!(image.size_bytes, 4096);
        assert_eq!(image.digest.as_str().len(), 64);
    }

    #[tokio::test]
    async fn custom_reference_is_rejected_by_standard_registry() {
        let resolver = StandardImageResolver::new("/images/rootfs.ext4");
        let reference = ImageReference::new("private:custom").unwrap();
        assert!(resolver.resolve(&reference).await.is_err());
    }
}
