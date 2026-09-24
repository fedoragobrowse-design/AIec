//! Backend-neutral image references, digests, and resolution.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// An image name optionally qualified by a tag or digest.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ImageReference(String);

impl ImageReference {
    /// Creates a reference without interpreting its tag or digest.
    pub fn new(value: impl Into<String>) -> Result<Self, crate::CoreError> {
        let value = value.into();
        if value.is_empty() || value.len() > 1024 || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(crate::CoreError::InvalidRequest("invalid image reference".into()));
        }
        Ok(Self(value))
    }

    /// Returns the reference as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ImageReference {
    type Err = crate::CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// A lowercase, 64-character SHA-256 image digest.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ImageDigest(String);

impl ImageDigest {
    /// Parses a hexadecimal SHA-256 digest.
    pub fn new(value: impl Into<String>) -> Result<Self, crate::CoreError> {
        let value = value.into();
        if value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(crate::CoreError::InvalidRequest("invalid SHA-256 digest".into()));
        }
        Ok(Self(value))
    }

    /// Returns the hexadecimal digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ImageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ImageDigest {
    type Err = crate::CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Immutable image selected by an [`ImageResolver`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedImage {
    /// User-facing reference that was resolved.
    pub reference: ImageReference,
    /// Stable backend image identifier.
    pub image_id: String,
    /// Runtime-ready root filesystem location.
    pub rootfs: String,
    /// Content digest used for integrity and caching.
    pub digest: ImageDigest,
    /// Root filesystem size in bytes.
    pub size_bytes: u64,
    /// Target CPU architecture, when known.
    pub architecture: Option<String>,
}

/// Resolves human-facing image names to immutable runtime images.
#[async_trait]
pub trait ImageResolver: Send + Sync {
    /// Resolves an image reference without executing it.
    async fn resolve(
        &self,
        reference: &ImageReference,
    ) -> Result<ResolvedImage, crate::CoreError>;
}
