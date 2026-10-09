use aiec_core::{
    CoreError, image_id,
    images::{ImageDigest, ImageReference, ImageResolver, ResolvedImage, SignedImageManifest},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::Metadata,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

/// Buffer the rootfs is hashed through.
///
/// Fixed size on purpose: it is the one allocation a verification makes, and a
/// rootfs is measured in gigabytes.
const ROOTFS_HASH_CHUNK: usize = 1024 * 1024;

/// Locks a mutex whose poisoning would otherwise be a wrong answer rather than
/// a reason to refuse every later one.
fn cache_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The identity a verified rootfs digest is valid for.
///
/// A pathname is not an identity - an image can be replaced at the same path -
/// and neither is a length, because an image can be rewritten in place to the
/// same length. What makes the bytes nameable is the device and inode they live
/// on, their length, and both of their timestamps at nanosecond resolution.
/// `mtime` on its own is whole seconds on this platform, so a rootfs rewritten
/// in place with the same length inside the same second is a different image
/// with an identical key, and the verdict for the bytes it replaced would be
/// handed to bytes nobody hashed. `ctime` closes the rest of that door: it
/// cannot be set by a writer at all, so it moves even when `mtime` is restored
/// afterwards.
///
/// What this cannot see is a rewrite that preserves size, inode, device and
/// every timestamp, which means writing over the image's own blocks without
/// letting the filesystem record it. Re-hashing is the only defence against
/// that, and doing it per resolve is the cost the cache exists to avoid.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RootfsIdentity {
    /// The path the file was reached by, so a rename to another name and a
    /// replacement at this one are not the same key.
    rootfs: Arc<str>,
    dev: u64,
    ino: u64,
    len: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

impl RootfsIdentity {
    /// Builds the identity of an already-stat'ed file.
    fn of(rootfs: &Arc<str>, metadata: &Metadata) -> Self {
        Self {
            rootfs: rootfs.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.size(),
            mtime_sec: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime_sec: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    /// Reads the identity of the file currently at `rootfs`.
    fn read(rootfs: &Arc<str>) -> Result<Self, CoreError> {
        let metadata = std::fs::metadata(Path::new(rootfs.as_ref())).map_err(CoreError::Io)?;
        Self::check_regular(&metadata)?;
        Ok(Self::of(rootfs, &metadata))
    }

    /// Refuses anything that is not a regular file.
    ///
    /// A directory fails the read anyway and a device or a fifo does not: a
    /// fifo is an open that never returns, and hashing it would park a resolve
    /// on a path no timeout is watching.
    fn check_regular(metadata: &Metadata) -> Result<(), CoreError> {
        if !metadata.is_file() {
            return Err(CoreError::Unavailable(
                "signed image rootfs is not a regular file".into(),
            ));
        }
        Ok(())
    }
}

/// A verified rootfs digest, and everything it is an answer about.
#[derive(Clone)]
struct VerifiedRootfs {
    /// The file the digest was computed over, including its length, which is
    /// the size a resolution reports.
    identity: RootfsIdentity,
    /// The signed manifest digest this verdict was checked against, so a
    /// verdict recorded for one manifest is never read back for another.
    expected: String,
    digest: ImageDigest,
}

/// What the resolver holds between resolutions.
#[derive(Default)]
struct VerifiedState {
    /// The one remembered verdict.
    ///
    /// One entry, deliberately. A resolver is configured with a single rootfs,
    /// so a map here would not be a cache, it would be memory nobody asked for:
    /// the resolver is cloned into every request path, so a map that grew with
    /// distinct rootfs would grow with the process.
    entry: Option<VerifiedRootfs>,
    /// Whether a verification is running for this resolver right now.
    hashing: bool,
}

/// A verified digest cache for one signed rootfs, shared by every clone of the
/// resolver that holds it.
///
/// Concurrent resolutions of the same image share one hash rather than each
/// reading the same multi-gigabyte file: the caller that arrives while a
/// verification is running waits for that verdict instead of starting a second
/// reader of the same disk the guests are about to share.
#[derive(Clone)]
struct VerifiedDigestCache {
    state: Arc<Mutex<VerifiedState>>,
    /// Bumped every time a verification settles.
    ///
    /// A watcher subscribes while it still holds the state lock, so it cannot
    /// miss the settling of the verification it is waiting for.
    settled: tokio::sync::watch::Sender<u64>,
}

impl std::fmt::Debug for VerifiedDigestCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = cache_lock(&self.state);
        formatter
            .debug_struct("VerifiedDigestCache")
            .field("verified", &state.entry.is_some())
            .field("hashing", &state.hashing)
            .finish()
    }
}

/// What a caller should do next, decided with the state lock held.
enum Next {
    /// These bytes are already verified.
    Cached(VerifiedRootfs),
    /// Another caller is verifying these bytes; wait for that verdict.
    Waiting(tokio::sync::watch::Receiver<u64>),
    /// No verdict and no verification running: hash it.
    Verify,
}

impl VerifiedDigestCache {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(VerifiedState::default())),
            settled: tokio::sync::watch::Sender::new(0),
        }
    }

    /// Decides the next step for one attempt.
    ///
    /// Synchronous on purpose. A lock guard held across an await makes the
    /// whole resolution future un-`Send`, and the alternative - holding the lock
    /// over the hash - would serialise a multi-gigabyte read against every
    /// waiter.
    fn next(&self, identity: &RootfsIdentity, expected: &str) -> Next {
        let mut state = cache_lock(&self.state);
        if let Some(entry) = state.entry.as_ref() {
            if entry.expected == expected && entry.identity == *identity {
                return Next::Cached(entry.clone());
            }
            // A verdict about other bytes is not an answer to this question. It
            // is dropped rather than kept beside the new one: this cache holds
            // one image, so keeping the old would evict the only entry that can
            // ever be a hit.
            state.entry = None;
        }
        if state.hashing {
            // Subscribed under the lock, so the verification in flight cannot
            // settle between the check above and the subscription below.
            return Next::Waiting(self.settled.subscribe());
        }
        state.hashing = true;
        Next::Verify
    }

    /// Returns the verified digest for the rootfs, hashing it when the
    /// remembered verdict is not about these bytes.
    async fn resolve(
        &self,
        rootfs: &Arc<str>,
        expected: &str,
    ) -> Result<VerifiedRootfs, CoreError> {
        loop {
            // Read once per attempt. Everything below is decided against this
            // identity, including the file the hash is read from.
            let identity = RootfsIdentity::read(rootfs)?;
            match self.next(&identity, expected) {
                Next::Cached(verified) => return Ok(verified),
                Next::Waiting(mut settled) => {
                    let _ = settled.changed().await;
                    continue;
                }
                Next::Verify => {}
            }

            // The guard is what makes cancellation safe: a resolve dropped
            // mid-hash must not leave the resolver looking busy, or every later
            // resolution would wait for a verification nobody is running.
            let mut in_flight = InFlight {
                cache: self,
                armed: true,
            };
            let verified = match hash_verified_rootfs(rootfs, &identity, expected).await {
                Ok(verified) => verified,
                Err(error) => {
                    // A failed or unstable verification remembers nothing: an
                    // entry here would be a verdict about bytes nobody can
                    // name, and a waiter's retry is what must see the failure.
                    in_flight.settle(None);
                    return Err(error);
                }
            };
            in_flight.settle(Some(verified.clone()));
            return Ok(verified);
        }
    }

    /// Records a settled verification and releases its waiters.
    fn settle(&self, entry: Option<VerifiedRootfs>) {
        {
            let mut state = cache_lock(&self.state);
            state.hashing = false;
            state.entry = entry;
        }
        self.settled.send_modify(|generation| *generation += 1);
    }
}

/// A verification that is running and must be settled or abandoned.
struct InFlight<'a> {
    cache: &'a VerifiedDigestCache,
    armed: bool,
}

impl InFlight<'_> {
    fn settle(&mut self, entry: Option<VerifiedRootfs>) {
        self.armed = false;
        self.cache.settle(entry);
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if self.armed {
            // An unwind or a cancellation reaches here. The entry is not
            // written and the waiters are released with nothing to wait for
            // but a resolver that is free to try again.
            self.cache.settle(None);
        }
    }
}

/// Reported when the rootfs is not one stable set of bytes for the whole hash.
fn unstable_rootfs() -> CoreError {
    CoreError::Unavailable("signed image rootfs changed while it was being verified".into())
}

/// Hashes the rootfs and checks it against the signed manifest digest.
///
/// The identity is checked three times, because a hash is only an answer to the
/// question "are these the signed bytes" if the bytes it read are the bytes
/// that were there for the whole read: once against the opened handle, so a
/// path replaced between the check and the open cannot be hashed under the
/// identity of what it replaced, once against the handle after the read, so a
/// file written while it was hashed is not accepted on the strength of its
/// first half, and once against the path, so a rename away or a swap behind the
/// handle does not leave a verdict about a file nobody asked for.
async fn hash_verified_rootfs(
    rootfs: &Arc<str>,
    identity: &RootfsIdentity,
    expected: &str,
) -> Result<VerifiedRootfs, CoreError> {
    let mut file = tokio::fs::File::open(Path::new(rootfs.as_ref()))
        .await
        .map_err(CoreError::Io)?;
    let opened = file.metadata().await.map_err(CoreError::Io)?;
    RootfsIdentity::check_regular(&opened)?;
    if &RootfsIdentity::of(rootfs, &opened) != identity {
        return Err(unstable_rootfs());
    }

    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; ROOTFS_HASH_CHUNK];
    let hashed_bytes = {
        use tokio::io::AsyncReadExt;
        let mut hashed_bytes = 0_u64;
        loop {
            let read = file.read(&mut buffer).await.map_err(CoreError::Io)?;
            if read == 0 {
                break;
            }
            hashed_bytes += read as u64;
            hasher.update(&buffer[..read]);
        }
        hashed_bytes
    };
    if hashed_bytes != identity.len {
        return Err(unstable_rootfs());
    }

    let after_read = file.metadata().await.map_err(CoreError::Io)?;
    if &RootfsIdentity::of(rootfs, &after_read) != identity {
        return Err(unstable_rootfs());
    }
    if RootfsIdentity::read(rootfs)? != *identity {
        return Err(unstable_rootfs());
    }

    let actual = ImageDigest::new(hex::encode(hasher.finalize()))?;
    if !actual.as_str().eq_ignore_ascii_case(expected) {
        return Err(CoreError::Forbidden(
            "signed image rootfs digest mismatch".into(),
        ));
    }
    Ok(VerifiedRootfs {
        identity: identity.clone(),
        expected: expected.to_owned(),
        digest: actual,
    })
}

const STANDARD_REFERENCES: &[&str] = &[
    "python:3.13",
    "node:24",
    "rust:stable",
    "ubuntu:24.04",
    "alpine:3.21",
    // Prebuilt GUI variants of the docker/bwrap-dev guest (see
    // guest/Dockerfile.gui): same content-id derivation, no new mechanism.
    "aiec/gui-browser",
    "aiec/gui-desktop",
    "aiec/gui-playwright",
];

/// Resolves AIec's standard image names to stable content-derived IDs.
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

    /// Returns the stable AIec content ID for an image reference.
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
///
/// Each manifest is authenticated once, when the resolver is built, and is
/// then immutable owned data: nothing can change a reference or an expected
/// digest behind a resolver's back. Re-deriving the HMAC on every resolution
/// therefore re-proves a fact that cannot have changed, while the check that
/// *can* change - whether the bytes on disk are still the signed bytes - is
/// what decides a resolution.
///
/// The signing secret is not retained. It has no use after construction, and
/// holding it for the life of the process would put it in every core dump,
/// every `Debug` print and every heap snapshot taken while the resolver lives.
///
/// A resolver holds one entry per signed reference (the base plus any `-gui`
/// variants): each entry carries its own rootfs path and its own expected
/// digest, verified independently. A single-manifest resolver is just a map
/// with one entry; its behavior is unchanged.
#[derive(Clone)]
pub struct SignedImageResolver {
    manifests: Vec<SignedEntry>,
    /// Shared with every clone of this resolver, so concurrent resolutions of
    /// the same image read it once.
    verified: VerifiedDigestCache,
    standard: StandardImageResolver,
}

/// One signed reference: the manifest the operator signed plus the rootfs it
/// vouches for. The rootfs lives beside the manifest entry rather than in a
/// single shared field so variants can point at different ext4 files.
#[derive(Clone)]
struct SignedEntry {
    rootfs: Arc<str>,
    manifest: SignedImageManifest,
}

impl fmt::Debug for SignedImageResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SignedImageResolver");
        for entry in &self.manifests {
            debug.field("reference", &entry.manifest.reference);
            debug.field("rootfs", &entry.rootfs);
        }
        debug.field("verified", &self.verified).finish()
    }
}

impl SignedImageResolver {
    pub fn from_manifest(
        rootfs: impl Into<String>,
        manifest_path: impl AsRef<Path>,
        secret: impl AsRef<[u8]>,
    ) -> Result<Self, CoreError> {
        Self::from_manifests(
            [(rootfs.into(), manifest_path.as_ref().to_path_buf())],
            secret,
        )
    }

    /// Builds a resolver from several (rootfs, manifest) pairs - the base
    /// plus any `-gui` variants the operator signed. Every pair is
    /// authenticated and identity-checked exactly as the single-manifest path
    /// was; duplicate references are refused so a later manifest cannot shadow
    /// an earlier one.
    pub fn from_manifests(
        pairs: impl IntoIterator<Item = (String, std::path::PathBuf)>,
        secret: impl AsRef<[u8]>,
    ) -> Result<Self, CoreError> {
        let secret = secret.as_ref();
        if secret.len() < 32 {
            return Err(CoreError::InvalidRequest(
                "image manifest secret must contain at least 32 bytes".into(),
            ));
        }
        let mut manifests = Vec::new();
        for (rootfs, manifest_path) in pairs {
            let manifest_bytes = std::fs::read(&manifest_path).map_err(CoreError::Io)?;
            let manifest: SignedImageManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|error| CoreError::Backend(error.to_string()))?;
            manifest.verify(secret)?;
            let rootfs = Arc::<str>::from(rootfs.clone());
            // Read through the same identity check a resolution uses, so a rootfs
            // that is missing, unreadable or not a regular file is refused here
            // with the message it would get later rather than at first use.
            RootfsIdentity::read(&rootfs).map_err(|error| match error {
                CoreError::Io(_) => CoreError::Unavailable("signed image rootfs is missing".into()),
                other => other,
            })?;
            if manifests
                .iter()
                .any(|e: &SignedEntry| e.manifest.reference == manifest.reference)
            {
                return Err(CoreError::InvalidRequest(format!(
                    "duplicate signed image reference: {}",
                    manifest.reference
                )));
            }
            manifests.push(SignedEntry { rootfs, manifest });
        }
        if manifests.is_empty() {
            return Err(CoreError::InvalidRequest(
                "no image manifests supplied".into(),
            ));
        }
        let standard = StandardImageResolver::new(manifests[0].rootfs.as_ref());
        Ok(Self {
            manifests,
            verified: VerifiedDigestCache::new(),
            standard,
        })
    }
}

#[async_trait]
impl ImageResolver for SignedImageResolver {
    async fn resolve(&self, reference: &ImageReference) -> Result<ResolvedImage, CoreError> {
        let entry = self
            .manifests
            .iter()
            .find(|e| e.manifest.reference == reference.as_str());
        let Some(entry) = entry else {
            return self.standard.resolve(reference).await;
        };
        // Every resolution of a signed reference passes through here. A
        // resolution answered from the cache was answered for these exact bytes
        // under this exact expected digest; anything else is hashed, and the
        // hash is checked for stability either side of the read.
        let verified = self
            .verified
            .resolve(&entry.rootfs, &entry.manifest.rootfs_sha256)
            .await?;
        Ok(ResolvedImage {
            reference: reference.clone(),
            image_id: image_id(reference.as_str()),
            rootfs: entry.rootfs.to_string(),
            digest: verified.digest,
            size_bytes: verified.identity.len,
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
        let root = std::env::temp_dir().join(format!("aiec-image-{}", uuid::Uuid::now_v7()));
        std::fs::write(&root, b"rootfs").unwrap();
        let digest = hex::encode(Sha256::digest(b"rootfs"));
        let secret = b"image-test-secret-32-bytes-long!";
        let manifest_path = root.with_extension("manifest.json");
        let manifest = SignedImageManifest {
            reference: "python:3.13".into(),
            rootfs_sha256: digest.clone(),
            signature: aiec_core::image_manifest_signature(secret, "python:3.13", &digest),
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

    /// Two signed references resolve to their own rootfs files: the base
    /// keeps its bytes and a `-gui` variant resolves beside it, each through
    /// its own digest check. A duplicate reference is refused at load so a
    /// later manifest cannot shadow an earlier one.
    #[tokio::test]
    async fn signed_resolver_serves_base_and_gui_variant() {
        let secret = b"image-test-secret-32-bytes-long!";
        let write_pair = |name: &str, bytes: &[u8], reference: &str| {
            let root =
                std::env::temp_dir().join(format!("aiec-image-{}-{name}", uuid::Uuid::now_v7()));
            std::fs::write(&root, bytes).unwrap();
            let digest = hex::encode(Sha256::digest(bytes));
            let manifest = SignedImageManifest {
                reference: reference.into(),
                rootfs_sha256: digest,
                signature: aiec_core::image_manifest_signature(
                    secret,
                    reference,
                    &hex::encode(Sha256::digest(bytes)),
                ),
            };
            let path = root.with_extension("manifest.json");
            std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            (root.to_string_lossy().into_owned(), path)
        };
        let (base_root, base_manifest) = write_pair("base", b"base-rootfs", "aiec/firecracker");
        let (gui_root, gui_manifest) =
            write_pair("gui", b"gui-rootfs", "aiec/firecracker-gui-browser");
        let resolver = SignedImageResolver::from_manifests(
            [
                (base_root.clone(), base_manifest.clone()),
                (gui_root.clone(), gui_manifest.clone()),
            ],
            secret,
        )
        .unwrap();
        let base = resolver
            .resolve(&ImageReference::new("aiec/firecracker").unwrap())
            .await
            .unwrap();
        assert_eq!(base.rootfs, base_root);
        let gui = resolver
            .resolve(&ImageReference::new("aiec/firecracker-gui-browser").unwrap())
            .await
            .unwrap();
        assert_eq!(gui.rootfs, gui_root);
        assert_ne!(base.digest.as_str(), gui.digest.as_str());
        // Same reference twice is a load error, not a silent shadow.
        assert!(
            SignedImageResolver::from_manifests(
                [
                    (base_root.clone(), base_manifest.clone()),
                    (base_root.clone(), base_manifest.clone()),
                ],
                secret,
            )
            .is_err()
        );
        for path in [base_root, gui_root] {
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_file(base_manifest);
        let _ = std::fs::remove_file(gui_manifest);
    }

    #[tokio::test]
    async fn gui_docker_references_resolve_to_content_ids() {
        let resolver = StandardImageResolver::new("/images/rootfs.ext4");
        for reference in [
            "aiec/gui-browser",
            "aiec/gui-desktop",
            "aiec/gui-playwright",
        ] {
            let image = resolver
                .resolve(&ImageReference::new(reference).unwrap())
                .await
                .unwrap();
            assert_eq!(image.image_id, image_id(reference));
        }
    }

    #[test]
    fn signed_resolver_rejects_invalid_signature_at_load() {
        let root = std::env::temp_dir().join(format!("aiec-image-{}", uuid::Uuid::now_v7()));
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
        let root = std::env::temp_dir().join(format!("aiec-image-{}", uuid::Uuid::now_v7()));
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

    /// Puts a file's modification time back to a whole second, so a test can
    /// reproduce the granularity a seconds-resolution key cannot see.
    fn restore_mtime(path: &std::path::Path, seconds: i64) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let raw = CString::new(path.as_os_str().as_bytes()).expect("path");
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: seconds,
                tv_nsec: 0,
            },
        ];
        let set = unsafe { libc::utimensat(libc::AT_FDCWD, raw.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(set, 0, "could not restore the modification time");
    }

    /// A signed resolver over a rootfs holding `contents`.
    fn signed_resolver(
        root: &std::path::Path,
        contents: &[u8],
        reference: &str,
    ) -> SignedImageResolver {
        std::fs::write(root, contents).expect("rootfs");
        let digest = hex::encode(Sha256::digest(contents));
        let secret = b"image-test-secret-32-bytes-long!";
        let manifest_path = root.with_extension("manifest.json");
        let manifest = SignedImageManifest {
            reference: reference.into(),
            rootfs_sha256: digest.clone(),
            signature: aiec_core::image_manifest_signature(secret, reference, &digest),
        };
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("write");
        SignedImageResolver::from_manifest(
            root.to_string_lossy().into_owned(),
            &manifest_path,
            secret,
        )
        .expect("resolver")
    }

    fn temp_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("aiec-image-{label}-{}", uuid::Uuid::now_v7()))
    }

    /// A rewrite of the same length, with the whole-second modification time
    /// forced back, is a different image.
    ///
    /// This is the case a seconds-resolution key cannot see, and the cache this
    /// replaces re-hashed unconditionally, so it was correct. A key built from
    /// the length and the whole-second modification time would be identical
    /// before and after the rewrite, and the digest recorded for the bytes it
    /// replaced would be handed to bytes nobody hashed. The nanosecond fields
    /// are what keep the two apart.
    #[tokio::test]
    async fn same_length_rewrite_with_a_restored_mtime_is_rejected() {
        let root = temp_root("rewrite");
        let resolver = signed_resolver(&root, b"rootfs", "python:3.13");
        let reference = ImageReference::new("python:3.13").unwrap();
        resolver.resolve(&reference).await.expect("first resolve");

        let seconds = std::fs::metadata(&root).expect("metadata").mtime();
        std::fs::write(&root, b"ROOTFS").expect("rewrite");
        restore_mtime(&root, seconds);

        let error = resolver
            .resolve(&reference)
            .await
            .expect_err("a rewritten image must not be served from the previous verdict");
        assert!(
            error.to_string().contains("digest mismatch"),
            "an image that is no longer the signed bytes must be refused, got: {error}"
        );
        let _ = std::fs::remove_file(&root);
        let _ = std::fs::remove_file(root.with_extension("manifest.json"));
    }

    /// An atomic replacement at the same path is a different file, even when the
    /// pathname, the length and the modification second are the same.
    ///
    /// The rename that installs a new image is the normal way one is deployed,
    /// and it produces a new inode at the old name. A verdict recorded for the
    /// file it replaced must not survive it.
    #[tokio::test]
    async fn an_atomic_replacement_at_the_same_path_is_rejected() {
        let root = temp_root("replace");
        let resolver = signed_resolver(&root, b"rootfs", "python:3.13");
        let reference = ImageReference::new("python:3.13").unwrap();
        resolver.resolve(&reference).await.expect("first resolve");

        let staged = root.with_extension("staged");
        std::fs::write(&staged, b"other image").expect("stage");
        let seconds = std::fs::metadata(&root).expect("metadata").mtime();
        std::fs::rename(&staged, &root).expect("atomic replacement");
        restore_mtime(&root, seconds);

        let error = resolver
            .resolve(&reference)
            .await
            .expect_err("a replaced image must not be served from the previous verdict");
        assert!(
            error.to_string().contains("digest mismatch"),
            "an image that is no longer the signed bytes must be refused, got: {error}"
        );
        let _ = std::fs::remove_file(&root);
        let _ = std::fs::remove_file(root.with_extension("manifest.json"));
    }

    /// A redeployment that installs the signed bytes again is accepted.
    ///
    /// The identity is a property of the bytes, not of the file that happened to
    /// hold them. Refusing this would make an atomic redeploy of an unchanged
    /// image look like tampering, which is the failure mode that trains an
    /// operator to disable verification.
    #[tokio::test]
    async fn redeploying_the_signed_bytes_at_a_new_inode_is_accepted() {
        let root = temp_root("redeploy");
        let resolver = signed_resolver(&root, b"rootfs", "python:3.13");
        let reference = ImageReference::new("python:3.13").unwrap();
        resolver.resolve(&reference).await.expect("first resolve");

        let staged = root.with_extension("staged");
        std::fs::write(&staged, b"rootfs").expect("stage");
        std::fs::rename(&staged, &root).expect("atomic replacement");

        let image = resolver
            .resolve(&reference)
            .await
            .expect("the signed bytes are the signed bytes wherever they are read from");
        assert_eq!(
            image.digest.as_str(),
            hex::encode(Sha256::digest(b"rootfs"))
        );
        let _ = std::fs::remove_file(&root);
        let _ = std::fs::remove_file(root.with_extension("manifest.json"));
    }

    /// A failed resolution trusts nothing and blocks nothing afterwards.
    ///
    /// The cache shares one verification between concurrent callers, so a
    /// refusal has to leave the resolver able to try again rather than looking
    /// permanently busy. This is the sequence an operator repair produces:
    /// refuse, restore the image, resolve.
    #[tokio::test]
    async fn a_refused_rootfs_does_not_block_a_later_repair() {
        let root = temp_root("repair");
        let resolver = signed_resolver(&root, b"rootfs", "python:3.13");
        let reference = ImageReference::new("python:3.13").unwrap();
        resolver.resolve(&reference).await.expect("first resolve");

        std::fs::write(&root, b"tampered").expect("tamper");
        assert!(
            resolver.resolve(&reference).await.is_err(),
            "a modified image must be refused"
        );

        std::fs::write(&root, b"rootfs").expect("repair");
        let image = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            resolver.resolve(&reference),
        )
        .await
        .expect("a refused resolution must not leave later ones waiting")
        .expect("a repaired image resolves");
        assert_eq!(
            image.digest.as_str(),
            hex::encode(Sha256::digest(b"rootfs"))
        );
        let _ = std::fs::remove_file(&root);
        let _ = std::fs::remove_file(root.with_extension("manifest.json"));
    }

    /// A rootfs that disappears between resolutions is refused, not cached.
    #[tokio::test]
    async fn a_removed_rootfs_is_refused() {
        let root = temp_root("removed");
        let resolver = signed_resolver(&root, b"rootfs", "python:3.13");
        let reference = ImageReference::new("python:3.13").unwrap();
        resolver.resolve(&reference).await.expect("first resolve");

        std::fs::remove_file(&root).expect("remove");
        assert!(
            resolver.resolve(&reference).await.is_err(),
            "an image that is no longer on disk must not resolve"
        );
        let _ = std::fs::remove_file(root.with_extension("manifest.json"));
    }

    /// Concurrent cold resolutions all return the verified digest.
    ///
    /// They share one verification rather than each reading the same file, and
    /// a caller that arrives mid-verification must get that verification's
    /// answer - not a stale entry from before it, and not a wait that never
    /// ends. The deadline is the check that matters here: a shared lock with no
    /// cancellation path shows up as a resolve that never returns.
    #[tokio::test]
    async fn concurrent_cold_resolutions_all_return_the_verified_digest() {
        let root = temp_root("concurrent");
        // On the heap: two four-megabyte stack temporaries overflow a test
        // thread, and a test that cannot run is not a test.
        let contents = vec![7_u8; 4 * 1024 * 1024];
        let resolver = signed_resolver(&root, &contents, "python:3.13");
        let reference = ImageReference::new("python:3.13").unwrap();
        let expected = hex::encode(Sha256::digest(&contents));

        let callers = (0..8)
            .map(|_| {
                let resolver = resolver.clone();
                let reference = reference.clone();
                tokio::spawn(
                    async move { resolver.resolve(&reference).await.map(|image| image.digest) },
                )
            })
            .collect::<Vec<_>>();

        let resolved = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let mut digests = Vec::new();
            for caller in callers {
                digests.push(
                    caller
                        .await
                        .expect("caller")
                        .expect("every concurrent resolution returns the verified digest"),
                );
            }
            digests
        })
        .await
        .expect("concurrent resolutions must not deadlock");

        for digest in resolved {
            assert_eq!(digest.as_str(), expected);
        }
        let _ = std::fs::remove_file(&root);
        let _ = std::fs::remove_file(root.with_extension("manifest.json"));
    }

    /// Debug output of a resolver does not carry the signing secret.
    ///
    /// The resolver outlives every request it serves, so anything that prints
    /// one - a log line, a panic message, a support dump - puts the secret in
    /// front of whoever reads it.
    #[test]
    fn debug_output_does_not_carry_the_signing_secret() {
        let root = temp_root("debug");
        let resolver = signed_resolver(&root, b"rootfs", "python:3.13");
        let printed = format!("{resolver:?}");
        assert!(
            !printed.contains("image-test-secret"),
            "the signing secret must not be reachable through Debug: {printed}"
        );
        assert!(printed.contains("python:3.13"), "{printed}");
        let _ = std::fs::remove_file(&root);
        let _ = std::fs::remove_file(root.with_extension("manifest.json"));
    }
}
