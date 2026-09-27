use agentforge_core::{
    CoreError, image_id,
    images::{ImageDigest, ImageReference, ImageResolver, ResolvedImage, SignedImageManifest},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};

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
    async fn resolve(&self, reference: &ImageReference) -> Result<ResolvedImage, CoreError> {
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

/// Resolves an administrator-signed rootfs for Firecracker and standard OCI
/// references for container runtimes.
#[derive(Clone, Debug)]
pub struct SignedImageResolver {
    rootfs: Arc<str>,
    manifest: SignedImageManifest,
    secret: Arc<[u8]>,
    standard: StandardImageResolver,
}

impl SignedImageResolver {
    pub fn from_manifest(
        rootfs: impl Into<String>,
        manifest_path: impl AsRef<Path>,
        secret: impl AsRef<[u8]>,
    ) -> Result<Self, CoreError> {
        let rootfs = rootfs.into();
        let secret = secret.as_ref();
        let manifest_bytes = std::fs::read(manifest_path).map_err(CoreError::Io)?;
        let manifest: SignedImageManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| CoreError::Backend(error.to_string()))?;
        if secret.len() < 32 {
            return Err(CoreError::InvalidRequest(
                "image manifest secret must contain at least 32 bytes".into(),
            ));
        }
        manifest.verify(secret)?;
        if !std::path::Path::new(&rootfs).is_file() {
            return Err(CoreError::Unavailable(
                "signed image rootfs is missing".into(),
            ));
        }
        Ok(Self {
            rootfs: Arc::from(rootfs.clone()),
            manifest,
            secret: Arc::from(secret),
            standard: StandardImageResolver::new(rootfs),
        })
    }

    async fn rootfs_digest(&self) -> Result<ImageDigest, CoreError> {
        use tokio::io::AsyncReadExt;
        let mut file = tokio::fs::File::open(self.rootfs.as_ref())
            .await
            .map_err(CoreError::Io)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer).await.map_err(CoreError::Io)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        ImageDigest::new(hex::encode(hasher.finalize()))
    }
}

#[async_trait]
impl ImageResolver for SignedImageResolver {
    async fn resolve(&self, reference: &ImageReference) -> Result<ResolvedImage, CoreError> {
        if self.manifest.reference != reference.as_str() {
            return self.standard.resolve(reference).await;
        }
        self.manifest.verify(&self.secret)?;
        let actual = self.rootfs_digest().await?;
        if !actual
            .as_str()
            .eq_ignore_ascii_case(&self.manifest.rootfs_sha256)
        {
            return Err(CoreError::Forbidden(
                "signed image rootfs digest mismatch".into(),
            ));
        }
        let size_bytes = tokio::fs::metadata(self.rootfs.as_ref())
            .await
            .map_err(CoreError::Io)?
            .len();
        Ok(ResolvedImage {
            reference: reference.clone(),
            image_id: image_id(reference.as_str()),
            rootfs: self.rootfs.to_string(),
            digest: actual,
            size_bytes,
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

    #[tokio::test]
    async fn signed_resolver_verifies_rootfs_and_reference() {
        let root = std::env::temp_dir().join(format!("agentforge-image-{}", uuid::Uuid::now_v7()));
        std::fs::write(&root, b"rootfs").unwrap();
        let digest = hex::encode(Sha256::digest(b"rootfs"));
        let secret = b"image-test-secret-32-bytes-long!";
        let manifest_path = root.with_extension("manifest.json");
        let manifest = SignedImageManifest {
            reference: "python:3.13".into(),
            rootfs_sha256: digest.clone(),
            signature: agentforge_core::image_manifest_signature(secret, "python:3.13", &digest),
        };
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let resolver = SignedImageResolver::from_manifest(
            root.to_string_lossy().into_owned(),
            &manifest_path,
            secret,
        )
        .unwrap();
        let image = resolver
            .resolve(&ImageReference::new("python:3.13").unwrap())
            .await
            .unwrap();
        assert_eq!(image.digest.as_str(), digest);
        let container_image = resolver
            .resolve(&ImageReference::new("ubuntu:24.04").unwrap())
            .await
            .unwrap();
        assert_eq!(container_image.reference.as_str(), "ubuntu:24.04");
        assert!(
            resolver
                .resolve(&ImageReference::new("private:custom").unwrap())
                .await
                .is_err()
        );
        std::fs::write(&root, b"tampered").unwrap();
        assert!(
            resolver
                .resolve(&ImageReference::new("python:3.13").unwrap())
                .await
                .is_err()
        );
        let _ = std::fs::remove_file(root);
        let _ = std::fs::remove_file(manifest_path);
    }

    #[test]
    fn signed_resolver_rejects_invalid_signature_at_load() {
        let root = std::env::temp_dir().join(format!("agentforge-image-{}", uuid::Uuid::now_v7()));
        std::fs::write(&root, b"rootfs").unwrap();
        let manifest_path = root.with_extension("manifest.json");
        let manifest = SignedImageManifest {
            reference: "python:3.13".into(),
            rootfs_sha256: "0".repeat(64),
            signature: "00".repeat(32),
        };
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(
            SignedImageResolver::from_manifest(
                root.to_string_lossy().into_owned(),
                &manifest_path,
                b"secret-32-bytes-long-for-testing!",
            )
            .is_err()
        );
        let _ = std::fs::remove_file(root);
        let _ = std::fs::remove_file(manifest_path);
    }

    #[test]
    fn signed_resolver_rejects_short_secret() {
        let root = std::env::temp_dir().join(format!("agentforge-image-{}", uuid::Uuid::now_v7()));
        std::fs::write(&root, b"rootfs").unwrap();
        let manifest_path = root.with_extension("manifest.json");
        let manifest = SignedImageManifest {
            reference: "python:3.13".into(),
            rootfs_sha256: "0".repeat(64),
            signature: "00".repeat(32),
        };
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let error = SignedImageResolver::from_manifest(
            root.to_string_lossy().into_owned(),
            &manifest_path,
            b"short",
        )
        .unwrap_err();
        assert!(error.to_string().contains("at least 32 bytes"));
        let _ = std::fs::remove_file(root);
        let _ = std::fs::remove_file(manifest_path);
    }
}
