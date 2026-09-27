//! Guest image artifact metadata and integrity verification.
//!
//! The guest image build writes a `guest-capabilities.json` document next to the
//! root filesystem it produced. The runtime refuses to advertise capabilities it
//! cannot prove, so a missing document is simply "no metadata" while a present
//! document with a root filesystem that does not match it is a hard failure.

use crate::RuntimeError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Metadata document written by the guest image build.
pub const GUEST_ARTIFACT_FILE: &str = "guest-capabilities.json";

/// Capability profile name of a coding-capable guest.
pub const CODING_PROFILE: &str = "coding";

/// Capability a coding-capable guest must advertise.
pub const CAPABILITY_GIT: &str = "git";

/// Capability a coding-capable guest must advertise to validate TLS.
pub const CAPABILITY_CA_CERTIFICATES: &str = "ca-certificates";

/// Size of the buffer used to stream an image through the digest.
const DIGEST_CHUNK: usize = 1024 * 1024;

/// Build metadata recorded for a Firecracker guest image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestArtifact {
    /// Version of the artifact build.
    pub artifact_version: String,
    /// Base distribution the root filesystem was built from.
    pub base: String,
    /// Capability profile, such as `coding`.
    pub profile: String,
    /// Individual capabilities present in the image.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Reported `git --version`, when git is part of the image.
    #[serde(default)]
    pub git_version: Option<String>,
    /// Version of the AgentForge guest agent inside the image.
    pub guest_agent_version: String,
    /// Hex-encoded SHA-256 of the root filesystem.
    pub rootfs_sha256: String,
    /// Hex-encoded SHA-256 of the kernel, when the build recorded one.
    #[serde(default)]
    pub kernel_sha256: Option<String>,
}

impl GuestArtifact {
    /// Reports whether the artifact describes a coding-capable guest.
    pub fn is_coding_guest(&self) -> bool {
        self.profile == CODING_PROFILE
            && self
                .capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_GIT)
    }
}

/// Reads guest artifact metadata from `path` without touching the images.
pub fn load_guest_artifact(path: &Path) -> Result<GuestArtifact, RuntimeError> {
    if !path.is_file() {
        return Err(RuntimeError::Unavailable(format!(
            "guest artifact metadata {} is missing",
            path.display()
        )));
    }
    let contents = std::fs::read_to_string(path).map_err(|error| {
        RuntimeError::Unavailable(format!(
            "guest artifact metadata {} is unreadable: {error}",
            path.display()
        ))
    })?;
    serde_json::from_str(&contents).map_err(|error| {
        RuntimeError::Unavailable(format!(
            "guest artifact metadata {} is malformed: {error}",
            path.display()
        ))
    })
}

/// Loads the artifact recorded in `dir` and verifies the images it describes.
///
/// Fails closed: missing metadata, a missing or unreadable root filesystem, a
/// root filesystem whose digest does not match the recorded one, and a recorded
/// kernel digest that does not match the configured kernel are all errors.
pub fn verify_guest_artifact(
    dir: &Path,
    rootfs: &Path,
    kernel: &Path,
) -> Result<GuestArtifact, RuntimeError> {
    let artifact = load_guest_artifact(&dir.join(GUEST_ARTIFACT_FILE))?;
    verify_digest(rootfs, &artifact.rootfs_sha256, "root filesystem")?;
    if let Some(expected) = &artifact.kernel_sha256 {
        verify_digest(kernel, expected, "kernel image")?;
    }
    Ok(artifact)
}

/// Compares the streamed digest of `path` against the recorded value.
fn verify_digest(path: &Path, expected: &str, label: &str) -> Result<(), RuntimeError> {
    if !path.is_file() {
        return Err(RuntimeError::Unavailable(format!(
            "guest {label} {} is missing",
            path.display()
        )));
    }
    let actual = file_sha256(path)?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(RuntimeError::Unavailable(format!(
            "guest {label} {} sha256 mismatch: recorded {expected}, actual {actual}",
            path.display()
        )));
    }
    Ok(())
}

/// Streams `path` through SHA-256 without holding the image in memory.
fn file_sha256(path: &Path) -> Result<String, RuntimeError> {
    let mut file = std::fs::File::open(path).map_err(|error| {
        RuntimeError::Unavailable(format!(
            "guest artifact {} is unreadable: {error}",
            path.display()
        ))
    })?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; DIGEST_CHUNK];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            RuntimeError::Unavailable(format!(
                "guest artifact {} is unreadable: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("af-artifact-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("artifact directory");
        dir
    }

    fn write_artifact(dir: &Path, rootfs_sha256: &str, capabilities: &str) {
        std::fs::write(
            dir.join(GUEST_ARTIFACT_FILE),
            format!(
                r#"{{"artifact_version":"1.0.0","base":"debian-12","profile":"coding","capabilities":{capabilities},"git_version":"git version 2.39.5","guest_agent_version":"0.1.0","rootfs_sha256":"{rootfs_sha256}"}}"#
            ),
        )
        .expect("artifact metadata");
    }

    #[test]
    fn matching_rootfs_digest_is_accepted() {
        let dir = artifact_dir("ok");
        let rootfs = dir.join("agentforge-rootfs.ext4");
        let kernel = dir.join("vmlinux");
        std::fs::write(&rootfs, b"root filesystem bytes").expect("rootfs");
        std::fs::write(&kernel, b"kernel bytes").expect("kernel");
        let digest = file_sha256(&rootfs).expect("digest");
        write_artifact(&dir, &digest, r#"["git","ca-certificates","python3"]"#);
        let artifact = verify_guest_artifact(&dir, &rootfs, &kernel).expect("verified artifact");
        assert!(artifact.is_coding_guest());
        assert_eq!(artifact.capabilities.len(), 3);
        assert!(artifact.kernel_sha256.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mismatched_rootfs_digest_reports_both_values() {
        let dir = artifact_dir("mismatch");
        let rootfs = dir.join("agentforge-rootfs.ext4");
        let kernel = dir.join("vmlinux");
        std::fs::write(&rootfs, b"tampered").expect("rootfs");
        std::fs::write(&kernel, b"kernel bytes").expect("kernel");
        write_artifact(&dir, &"a".repeat(64), r#"["git"]"#);
        let error = verify_guest_artifact(&dir, &rootfs, &kernel)
            .expect_err("digest mismatch must fail closed");
        let message = error.to_string();
        assert!(message.contains("sha256 mismatch"), "{message}");
        assert!(message.contains(&"a".repeat(64)), "{message}");
        assert!(
            message.contains(&file_sha256(&rootfs).expect("digest")),
            "{message}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_rootfs_is_reported_before_any_digest() {
        let dir = artifact_dir("missing-rootfs");
        let rootfs = dir.join("absent.ext4");
        let kernel = dir.join("vmlinux");
        std::fs::write(&kernel, b"kernel bytes").expect("kernel");
        write_artifact(&dir, &"b".repeat(64), r#"["git"]"#);
        let error = verify_guest_artifact(&dir, &rootfs, &kernel)
            .expect_err("missing rootfs must fail closed");
        assert!(error.to_string().contains("is missing"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_metadata_document_is_reported() {
        let dir = artifact_dir("missing-metadata");
        let rootfs = dir.join("agentforge-rootfs.ext4");
        std::fs::write(&rootfs, b"root filesystem bytes").expect("rootfs");
        let error = load_guest_artifact(&dir.join(GUEST_ARTIFACT_FILE))
            .expect_err("missing metadata must fail");
        assert!(error.to_string().contains("is missing"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recorded_kernel_digest_is_verified_when_present() {
        let dir = artifact_dir("kernel");
        let rootfs = dir.join("agentforge-rootfs.ext4");
        let kernel = dir.join("vmlinux");
        std::fs::write(&rootfs, b"root filesystem bytes").expect("rootfs");
        std::fs::write(&kernel, b"kernel bytes").expect("kernel");
        let rootfs_digest = file_sha256(&rootfs).expect("digest");
        let kernel_digest = file_sha256(&kernel).expect("digest");
        std::fs::write(
            dir.join(GUEST_ARTIFACT_FILE),
            format!(
                r#"{{"artifact_version":"1.0.0","base":"debian-12","profile":"coding","capabilities":["git"],"guest_agent_version":"0.1.0","rootfs_sha256":"{rootfs_digest}","kernel_sha256":"{kernel_digest}"}}"#
            ),
        )
        .expect("artifact metadata");
        verify_guest_artifact(&dir, &rootfs, &kernel).expect("verified artifact");
        std::fs::write(&kernel, b"different kernel bytes").expect("kernel");
        let error = verify_guest_artifact(&dir, &rootfs, &kernel)
            .expect_err("kernel digest mismatch must fail closed");
        assert!(error.to_string().contains("kernel image"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_coding_profiles_are_not_reported_as_coding_guests() {
        let coding = GuestArtifact {
            artifact_version: "1.0.0".into(),
            base: "debian-12".into(),
            profile: CODING_PROFILE.into(),
            capabilities: vec![CAPABILITY_GIT.into()],
            git_version: Some("git version 2.39.5".into()),
            guest_agent_version: "0.1.0".into(),
            rootfs_sha256: "c".repeat(64),
            kernel_sha256: None,
        };
        assert!(coding.is_coding_guest());
        let no_git = GuestArtifact {
            capabilities: vec![CAPABILITY_CA_CERTIFICATES.into()],
            ..coding.clone()
        };
        assert!(!no_git.is_coding_guest());
        let wrong_profile = GuestArtifact {
            profile: "minimal".into(),
            ..coding
        };
        assert!(!wrong_profile.is_coding_guest());
    }
}
