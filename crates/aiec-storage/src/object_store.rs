use crate::{StoreError, core_error};
use aiec_core::{
    CoreError,
    storage::{ArtifactDownload, ArtifactSource, ArtifactStore, GetObjectOptions, ObjectMetadata},
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use hmac::{Hmac, Mac};
use reqwest::{Method, Url, header};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::{ReaderStream, StreamReader};
use uuid::Uuid;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const TRANSFER_CHUNK_BYTES: usize = aiec_core::runtime::FILE_CHUNK_BYTES;
const LEGACY_DOWNLOAD_LIMIT: u64 = aiec_core::snapshots::MAX_WORKSPACE_ARCHIVE_BYTES as u64;

struct BytesSource(Bytes);

#[async_trait]
impl ArtifactSource for BytesSource {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, CoreError> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let length = self.0.len().min(TRANSFER_CHUNK_BYTES);
        Ok(Some(self.0.split_to(length)))
    }
}

// Anonymous files have no directory entry, so cancellation, errors and dropped
// downloads reclaim their disk space simply by closing the owned descriptor.
async fn anonymous_spool() -> Result<tokio::fs::File, StoreError> {
    let file = tokio::task::spawn_blocking(|| {
        let path = std::env::temp_dir().join(format!(".aiec-spool.{}.tmp", Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path)?;
        std::fs::remove_file(&path)?;
        Ok::<_, std::io::Error>(file)
    })
    .await
    .map_err(|error| StoreError::ObjectStore(error.to_string()))??;
    Ok(tokio::fs::File::from_std(file))
}

struct SpoolSource {
    file: tokio::fs::File,
    remaining: u64,
}

#[async_trait]
impl ArtifactSource for SpoolSource {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, CoreError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let length = self.remaining.min(TRANSFER_CHUNK_BYTES as u64) as usize;
        let mut bytes = BytesMut::with_capacity(length);
        while bytes.len() < length {
            let remaining = length - bytes.len();
            let count = (&mut self.file)
                .take(remaining as u64)
                .read_buf(&mut bytes)
                .await
                .map_err(|error| core_error(error.into()))?;
            if count == 0 {
                return Err(CoreError::Backend(
                    "verified artifact spool was truncated".into(),
                ));
            }
        }
        self.remaining -= length as u64;
        Ok(Some(bytes.freeze()))
    }
}

struct UploadOwner {
    path: PathBuf,
    file: std::fs::File,
}

impl Drop for UploadOwner {
    fn drop(&mut self) {
        // Synchronous unlink is deliberate: no spawned cleanup can outlive a
        // cancelled upload or race a subsequent GC pass after lock release.
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn upload_owner(path: PathBuf) -> Result<UploadOwner, StoreError> {
    tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path)?;
        let owner = UploadOwner { path, file };
        lock_temporary_file(&owner.file)?;
        Ok::<_, std::io::Error>(owner)
    })
    .await
    .map_err(|error| StoreError::ObjectStore(error.to_string()))?
    .map_err(Into::into)
}

fn check_size(size: u64, max_bytes: u64) -> Result<(), StoreError> {
    if size > max_bytes {
        return Err(CoreError::LimitExceeded("artifact body exceeds byte limit".into()).into());
    }
    Ok(())
}

async fn write_source(
    source: &mut dyn ArtifactSource,
    file: &mut tokio::fs::File,
    max_bytes: u64,
) -> Result<(u64, [u8; 32]), StoreError> {
    let mut size = 0u64;
    let mut digest = Sha256::new();
    while let Some(bytes) = source.next_chunk().await? {
        if bytes.is_empty() || bytes.len() > TRANSFER_CHUNK_BYTES {
            return Err(CoreError::InvalidRequest(
                "artifact source must yield 1..=65536 bytes".into(),
            )
            .into());
        }
        size = size
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| CoreError::LimitExceeded("artifact body size overflow".into()))?;
        check_size(size, max_bytes)?;
        digest.update(&bytes);
        file.write_all(&bytes).await?;
    }
    file.flush().await?;
    Ok((size, digest.finalize().into()))
}

async fn hash_reader(
    reader: &mut (impl AsyncRead + Unpin),
    mut spool: Option<&mut tokio::fs::File>,
    max_bytes: u64,
) -> Result<(u64, String), StoreError> {
    let mut size = 0u64;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; TRANSFER_CHUNK_BYTES];
    loop {
        // At the limit read only one sentinel byte, never another full chunk.
        let length = (max_bytes.saturating_sub(size).saturating_add(1))
            .min(TRANSFER_CHUNK_BYTES as u64) as usize;
        let count = reader.read(&mut buffer[..length]).await?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| CoreError::LimitExceeded("artifact body size overflow".into()))?;
        check_size(size, max_bytes)?;
        digest.update(&buffer[..count]);
        if let Some(file) = spool.as_mut() {
            file.write_all(&buffer[..count]).await?;
        }
    }
    if let Some(file) = spool {
        file.flush().await?;
        file.rewind().await?;
    }
    Ok((size, hex::encode(digest.finalize())))
}

fn verify_digest(actual: &str, options: &GetObjectOptions) -> Result<(), StoreError> {
    if let Some(expected) = &options.expected_checksum_sha256 {
        validate_checksum(expected)?;
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(StoreError::ObjectStore(
                "stored object checksum mismatch".into(),
            ));
        }
    }
    Ok(())
}

async fn collect_download(mut download: ArtifactDownload) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::with_capacity(download.metadata.size_bytes as usize);
    while let Some(chunk) = download.body.next_chunk().await? {
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn validate_object_key(key: &str) -> Result<(), StoreError> {
    if key.is_empty() || key.len() > 1024 {
        return Err(StoreError::InvalidObjectKey(
            "key must contain 1 to 1024 bytes".into(),
        ));
    }
    if key.starts_with('/')
        || key.ends_with('/')
        || key.contains('\\')
        || key.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(StoreError::InvalidObjectKey(
            "key has an unsafe path component".into(),
        ));
    }
    if key
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(StoreError::InvalidObjectKey(
            "key contains traversal or an empty component".into(),
        ));
    }
    Ok(())
}

fn is_within(root: &Path, path: &Path) -> bool {
    path == root || path.starts_with(root)
}

#[derive(Clone, Default)]
pub struct FilesystemObjectStore {
    pub root: PathBuf,
    mutation_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    temporary_scan: std::sync::Arc<tokio::sync::Mutex<Vec<tokio::fs::ReadDir>>>,
}

impl FilesystemObjectStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            mutation_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            temporary_scan: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    async fn root(&self) -> Result<PathBuf, StoreError> {
        tokio::fs::create_dir_all(&self.root).await?;
        Ok(tokio::fs::canonicalize(&self.root).await?)
    }

    async fn safe_path(&self, key: &str, leaf_may_be_missing: bool) -> Result<PathBuf, StoreError> {
        validate_object_key(key)?;
        let root = self.root().await?;
        let mut current = root.clone();
        let components: Vec<&str> = key.split('/').collect();
        let last = components.len().saturating_sub(1);
        for (index, component) in components.iter().enumerate() {
            current.push(component);
            match tokio::fs::symlink_metadata(&current).await {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    let resolved = tokio::fs::canonicalize(&current).await?;
                    if !is_within(&root, &resolved) {
                        return Err(StoreError::InvalidObjectKey(
                            "symlink escapes object-store root".into(),
                        ));
                    }
                    if !tokio::fs::metadata(&current).await?.is_dir() {
                        return Err(StoreError::InvalidObjectKey(
                            "symlink leaf is not a directory".into(),
                        ));
                    }
                    current = resolved;
                }
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) if index < last => {
                    return Err(StoreError::InvalidObjectKey(
                        "a parent component is not a directory".into(),
                    ));
                }
                Ok(_) if !leaf_may_be_missing => {}
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if index < last {
                        tokio::fs::create_dir(&current).await?;
                    } else if !leaf_may_be_missing {
                        return Err(error.into());
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        if current.exists() {
            let resolved = tokio::fs::canonicalize(&current).await?;
            if !is_within(&root, &resolved) {
                return Err(StoreError::InvalidObjectKey(
                    "object path escapes object-store root".into(),
                ));
            }
        }
        Ok(current)
    }

    async fn existing_path(&self, key: &str) -> Result<PathBuf, StoreError> {
        validate_object_key(key)?;
        let root = self.root().await?;
        let mut current = root.clone();
        let components: Vec<&str> = key.split('/').collect();
        let last = components.len().saturating_sub(1);
        for (index, component) in components.iter().enumerate() {
            current.push(component);
            match tokio::fs::symlink_metadata(&current).await {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    let resolved = tokio::fs::canonicalize(&current).await?;
                    if !is_within(&root, &resolved) {
                        return Err(StoreError::InvalidObjectKey(
                            "symlink escapes object-store root".into(),
                        ));
                    }
                    if !tokio::fs::metadata(&current).await?.is_dir() {
                        return Err(StoreError::InvalidObjectKey(
                            "symlink leaf is not a directory".into(),
                        ));
                    }
                    current = resolved;
                }
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) if index < last => {
                    return Err(StoreError::InvalidObjectKey(
                        "a parent component is not a directory".into(),
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(current),
                Err(error) => return Err(error.into()),
            }
        }
        if current.exists() {
            let resolved = tokio::fs::canonicalize(&current).await?;
            if !is_within(&root, &resolved) {
                return Err(StoreError::InvalidObjectKey(
                    "object path escapes object-store root".into(),
                ));
            }
        }
        Ok(current)
    }

    async fn delete_path(&self, key: &str) -> Result<(), StoreError> {
        let path = self.existing_path(key).await?;
        match tokio::fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Most objects one `list` call will describe.
///
/// This is not a page size and there is no successor cursor: the route that
/// calls this lists one sandbox's artifacts, and the point is to bound work
/// rather than serve a page. It matters because on this backend `list` returns
/// a checksum and a size for every object it finds, and computes them by reading
/// each file end to end. Listing metadata therefore costs the bytes of the whole
/// prefix, not just its directory entries — so without a bound, an ordinary
/// tenant that can upload artifacts by name decides how much of the object store
/// a single `GET` reads.
///
/// Past the bound the call is refused rather than truncated. A short list is
/// indistinguishable from a complete one, which is the failure this exists to
/// prevent; the refusal says there is more here than one call will describe.
pub const MAX_LISTED_OBJECTS: usize = 1000;

impl FilesystemObjectStore {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMetadata>, StoreError> {
        let prefix = prefix.trim_end_matches('/');
        let root = self.root().await?;
        let base = self.existing_path(prefix).await?;
        if !base.exists() {
            return Ok(Vec::new());
        }
        let base_metadata = tokio::fs::symlink_metadata(&base).await?;
        if base_metadata.file_type().is_symlink() {
            return Err(StoreError::InvalidObjectKey(
                "object prefix is a symlink".into(),
            ));
        }
        if !base_metadata.is_dir() {
            return Err(StoreError::InvalidObjectKey(
                "object prefix is not a directory".into(),
            ));
        }
        let mut pending = vec![base];
        let mut objects = Vec::new();
        while let Some(directory) = pending.pop() {
            let mut entries = tokio::fs::read_dir(&directory).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let metadata = tokio::fs::symlink_metadata(&path).await?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with('.') && name.ends_with(".tmp") {
                    continue;
                }
                if metadata.file_type().is_symlink() {
                    return Err(StoreError::InvalidObjectKey(
                        "object tree contains a symlink".into(),
                    ));
                }
                if metadata.is_dir() {
                    pending.push(path);
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }
                let key = path
                    .strip_prefix(&root)
                    .map_err(|_| StoreError::InvalidObjectKey("object path escaped root".into()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                // Checked before the read, not after: hashing is the expensive
                // part, and a prefix just over the bound must cost no more
                // than the bound allows rather than discovering the overflow
                // one whole file too late.
                if objects.len() >= MAX_LISTED_OBJECTS {
                    return Err(StoreError::ListingLimitExceeded(format!(
                        "more than {MAX_LISTED_OBJECTS} objects under the prefix; \
                         listing them all is refused rather than truncated"
                    )));
                }
                let mut file = tokio::fs::File::open(&path).await?;
                let (size_bytes, digest) = hash_reader(&mut file, None, u64::MAX).await?;
                objects.push(ObjectMetadata {
                    key,
                    size_bytes,
                    checksum_sha256: digest.clone(),
                    etag: Some(digest),
                });
            }
        }
        objects.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(objects)
    }
    async fn put(&self, key: &str, bytes: Bytes) -> Result<ObjectMetadata, StoreError> {
        let limit = bytes.len() as u64;
        self.put_stream(key, &mut BytesSource(bytes), limit).await
    }

    async fn put_stream(
        &self,
        key: &str,
        source: &mut dyn ArtifactSource,
        max_bytes: u64,
    ) -> Result<ObjectMetadata, StoreError> {
        let _mutation_guard = self.mutation_lock.lock().await;
        let path = self.safe_path(key, true).await?;
        let parent = path
            .parent()
            .ok_or_else(|| StoreError::InvalidObjectKey("missing object parent".into()))?;
        let owner =
            upload_owner(parent.join(format!(".aiec-upload.{}.tmp", Uuid::new_v4()))).await?;
        let mut file = tokio::fs::File::from_std(owner.file.try_clone()?);
        let (size_bytes, digest) = write_source(source, &mut file, max_bytes).await?;
        let digest = hex::encode(digest);
        file.sync_all().await?;
        drop(file);
        // No await between publication and owner drop: cancellation cannot
        // leave a background rename racing cleanup of the staging file.
        std::fs::rename(&owner.path, &path)?;
        Ok(ObjectMetadata {
            key: key.to_owned(),
            size_bytes,
            checksum_sha256: digest.clone(),
            etag: Some(digest),
        })
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        self.get_checked(key, &GetObjectOptions::default()).await
    }

    async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, StoreError> {
        collect_download(
            self.get_verified(key, options, LEGACY_DOWNLOAD_LIMIT)
                .await?,
        )
        .await
    }

    async fn get_verified(
        &self,
        key: &str,
        options: &GetObjectOptions,
        max_bytes: u64,
    ) -> Result<ArtifactDownload, StoreError> {
        if let Some(expected) = &options.expected_checksum_sha256 {
            validate_checksum(expected)?;
        }
        if let Some(expected) = &options.if_match {
            validate_checksum(expected.trim_matches('"'))?;
        }
        let path = self.safe_path(key, false).await?;
        let mut file = tokio::fs::File::open(path).await?;
        let declared_size = file.metadata().await?.len();
        check_size(declared_size, max_bytes)?;
        let mut spool = anonymous_spool().await?;
        let (size_bytes, digest) = hash_reader(&mut file, Some(&mut spool), max_bytes).await?;
        if declared_size != size_bytes {
            return Err(StoreError::ObjectStore(
                "filesystem object size changed during read".into(),
            ));
        }
        verify_digest(&digest, options)?;
        if let Some(expected) = &options.if_match
            && !digest.eq_ignore_ascii_case(expected.trim_matches('"'))
        {
            return Err(StoreError::ObjectStore(
                "filesystem ETag precondition failed".into(),
            ));
        }
        Ok(ArtifactDownload {
            metadata: ObjectMetadata {
                key: key.to_owned(),
                size_bytes,
                checksum_sha256: digest.clone(),
                etag: Some(digest),
            },
            body: Box::new(SpoolSource {
                file: spool,
                remaining: size_bytes,
            }),
        })
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.delete_path(key).await
    }

    async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), StoreError> {
        let _mutation_guard = self.mutation_lock.lock().await;
        let path = self.existing_path(key).await?;
        let mut file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let (_, actual) = hash_reader(&mut file, None, u64::MAX).await?;
        if actual.eq_ignore_ascii_case(etag.trim_matches('"')) {
            match tokio::fs::remove_file(path).await {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        } else {
            Err(StoreError::ObjectStore(
                "filesystem ETag precondition failed".into(),
            ))
        }
    }
}

fn lock_temporary_file(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // Advisory ownership survives process crashes and spans all store instances.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "local artifact upload ownership requires Unix file locks",
        ))
    }
}

impl FilesystemObjectStore {
    async fn cleanup_temporary_uploads(
        &self,
        older_than: DateTime<Utc>,
        limit: u32,
    ) -> Result<u32, StoreError> {
        if !(1..=1000).contains(&limit) {
            return Err(StoreError::Conflict(
                "invalid temporary upload scan bound".into(),
            ));
        }
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut scan = self.temporary_scan.lock().await;
        if scan.is_empty() {
            scan.push(tokio::fs::read_dir(self.root().await?).await?);
        }
        let mut deleted = 0;
        // Retain directory iterators across ticks, rather than repeatedly scanning
        // the same prefix or materializing an unbounded list of object paths.
        for _ in 0..limit {
            let Some(directory) = scan.last_mut() else {
                break;
            };
            let entry = match directory.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => {
                    scan.pop();
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    scan.pop();
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let file_type = entry.file_type().await?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                scan.push(tokio::fs::read_dir(entry.path()).await?);
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(id) = name
                .strip_prefix(".aiec-upload.")
                .and_then(|name| name.strip_suffix(".tmp"))
            else {
                continue;
            };
            if Uuid::parse_str(id).is_err() || !file_type.is_file() {
                continue;
            }
            let path = entry.path();
            let removed = tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
                let mut options = std::fs::OpenOptions::new();
                options.read(true).write(true);
                #[cfg(unix)]
                options.custom_flags(libc::O_NOFOLLOW);
                let owner = match options.open(&path) {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(error),
                };
                match lock_temporary_file(&owner) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        return Ok(false);
                    }
                    Err(error) => return Err(error),
                }
                let modified: DateTime<Utc> = owner.metadata()?.modified()?.into();
                if modified >= older_than {
                    return Ok(false);
                }
                match std::fs::remove_file(path) {
                    Ok(()) => Ok(true),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(error) => Err(error),
                }
            })
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))??;
            deleted += u32::from(removed);
        }
        Ok(deleted)
    }
}

#[async_trait]
impl ArtifactStore for FilesystemObjectStore {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<ObjectMetadata, CoreError> {
        Self::put(self, key, bytes).await.map_err(core_error)
    }
    async fn put_stream(
        &self,
        key: &str,
        source: &mut dyn ArtifactSource,
        max_bytes: u64,
    ) -> Result<ObjectMetadata, CoreError> {
        Self::put_stream(self, key, source, max_bytes)
            .await
            .map_err(core_error)
    }
    async fn get_verified(
        &self,
        key: &str,
        options: &GetObjectOptions,
        max_bytes: u64,
    ) -> Result<ArtifactDownload, CoreError> {
        Self::get_verified(self, key, options, max_bytes)
            .await
            .map_err(core_error)
    }
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMetadata>, CoreError> {
        Self::list(self, prefix).await.map_err(core_error)
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, CoreError> {
        Self::get(self, key).await.map_err(core_error)
    }

    async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, CoreError> {
        Self::get_checked(self, key, options)
            .await
            .map_err(core_error)
    }

    async fn delete(&self, key: &str) -> Result<(), CoreError> {
        Self::delete(self, key).await.map_err(core_error)
    }

    async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), CoreError> {
        Self::delete_if_match(self, key, etag)
            .await
            .map_err(core_error)
    }

    async fn cleanup_temporary_uploads(
        &self,
        older_than: DateTime<Utc>,
        limit: u32,
    ) -> Result<u32, CoreError> {
        Self::cleanup_temporary_uploads(self, older_than, limit)
            .await
            .map_err(core_error)
    }
}

fn validate_checksum(expected: &str) -> Result<(), StoreError> {
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StoreError::InvalidObjectKey(
            "expected SHA-256 must be 64 hexadecimal characters".into(),
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub prefix: String,
    pub request_timeout: Duration,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            bucket: "aiec".into(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            prefix: String::new(),
            request_timeout: Duration::from_secs(30),
        }
    }
}

impl S3Config {
    fn validate(&self) -> Result<(), StoreError> {
        let endpoint = Url::parse(&self.endpoint)
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(StoreError::ObjectStore(
                "S3 endpoint must be an HTTP(S) origin without credentials, query, or fragment"
                    .into(),
            ));
        }
        if !(3..=63).contains(&self.bucket.len())
            || self.bucket.starts_with('-')
            || self.bucket.ends_with('-')
            || !self
                .bucket
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(StoreError::ObjectStore("invalid S3 bucket name".into()));
        }
        if self.region.is_empty()
            || self.access_key_id.is_empty()
            || self.secret_access_key.is_empty()
        {
            return Err(StoreError::ObjectStore(
                "S3 region and credentials are required".into(),
            ));
        }
        if !self.prefix.is_empty() {
            validate_object_key(self.prefix.trim_end_matches('/'))?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct S3ObjectStore {
    client: reqwest::Client,
    config: S3Config,
}

struct SignedRequest {
    url: Url,
    headers: header::HeaderMap,
}

impl S3ObjectStore {
    pub fn new(config: S3Config) -> Result<Self, StoreError> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout.min(Duration::from_secs(300)))
            .build()
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        Ok(Self { client, config })
    }

    fn full_key(&self, key: &str) -> Result<String, StoreError> {
        validate_object_key(key)?;
        if self.config.prefix.is_empty() {
            return Ok(key.to_owned());
        }
        Ok(format!(
            "{}/{}",
            self.config.prefix.trim_end_matches('/'),
            key
        ))
    }

    fn object_url(&self, key: &str) -> Result<Url, StoreError> {
        let endpoint = self.config.endpoint.trim_end_matches('/');
        let encoded_key = key.split('/').map(uri_encode).collect::<Vec<_>>().join("/");
        Url::parse(&format!(
            "{endpoint}/{}/{}",
            self.config.bucket, encoded_key
        ))
        .map_err(|error| StoreError::ObjectStore(error.to_string()))
    }

    fn sign(
        &self,
        method: &Method,
        key: &str,
        body_hash: &str,
        extra_headers: &[(&str, String)],
        now: DateTime<Utc>,
    ) -> Result<SignedRequest, StoreError> {
        let url = self.object_url(key)?;
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let host = host_header(&url)?;
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host),
            ("x-amz-content-sha256".into(), body_hash.into()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        headers.extend(
            extra_headers
                .iter()
                .map(|(name, value)| ((*name).to_ascii_lowercase(), value.clone())),
        );
        headers.sort_by(|left, right| left.0.cmp(&right.0));
        let canonical_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", value.trim()))
            .collect::<String>();
        let signed_headers = headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            url.path(),
            canonical_query(&url),
            canonical_headers,
            signed_headers,
            body_hash
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.config.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let date_key = hmac(
            format!("AWS4{}", self.config.secret_access_key).as_bytes(),
            date.as_bytes(),
        );
        let region_key = hmac(&date_key, self.config.region.as_bytes());
        let service_key = hmac(&region_key, b"s3");
        let signing_key = hmac(&service_key, b"aws4_request");
        let signature = hex::encode(hmac(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.config.access_key_id
        );

        let mut request_headers = header::HeaderMap::new();
        for (name, value) in headers {
            request_headers.insert(
                header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|error| StoreError::ObjectStore(error.to_string()))?,
                header::HeaderValue::from_str(&value)
                    .map_err(|error| StoreError::ObjectStore(error.to_string()))?,
            );
        }
        request_headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&authorization)
                .map_err(|error| StoreError::ObjectStore(error.to_string()))?,
        );
        Ok(SignedRequest {
            url,
            headers: request_headers,
        })
    }

    fn signed(
        &self,
        method: Method,
        key: &str,
        body_hash: &str,
        extra_headers: &[(&str, String)],
    ) -> Result<SignedRequest, StoreError> {
        self.sign(&method, key, body_hash, extra_headers, Utc::now())
    }
}

impl S3ObjectStore {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<ObjectMetadata, StoreError> {
        let full_key = self.full_key(key)?;
        let size_bytes = bytes.len() as u64;
        let digest = Sha256::digest(&bytes);
        let body_hash = hex::encode(digest);
        let checksum = BASE64.encode(digest);
        let signed = self.signed(
            Method::PUT,
            &full_key,
            &body_hash,
            &[
                ("content-type", "application/octet-stream".into()),
                ("if-none-match", "*".into()),
                ("x-amz-checksum-sha256", checksum.clone()),
            ],
        )?;
        let response = self
            .client
            .request(Method::PUT, signed.url)
            .headers(signed.headers)
            .body(bytes)
            .send()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        let response = require_success(response).await?;
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        Ok(ObjectMetadata {
            key: key.to_owned(),
            size_bytes,
            checksum_sha256: body_hash,
            etag,
        })
    }

    async fn put_stream(
        &self,
        key: &str,
        source: &mut dyn ArtifactSource,
        max_bytes: u64,
    ) -> Result<ObjectMetadata, StoreError> {
        let full_key = self.full_key(key)?;
        let mut spool = anonymous_spool().await?;
        let (size_bytes, digest) = write_source(source, &mut spool, max_bytes).await?;
        spool.rewind().await?;
        let body_hash = hex::encode(digest);
        let signed = self.signed(
            Method::PUT,
            &full_key,
            &body_hash,
            &[
                ("content-type", "application/octet-stream".into()),
                ("content-length", size_bytes.to_string()),
                ("if-none-match", "*".into()),
                ("x-amz-checksum-sha256", BASE64.encode(digest)),
            ],
        )?;
        let response = self
            .client
            .request(Method::PUT, signed.url)
            .headers(signed.headers)
            .body(reqwest::Body::wrap_stream(ReaderStream::with_capacity(
                spool,
                TRANSFER_CHUNK_BYTES,
            )))
            .send()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        let response = require_success(response).await?;
        let etag = response_header(&response, header::ETAG.as_str())?;
        Ok(ObjectMetadata {
            key: key.to_owned(),
            size_bytes,
            checksum_sha256: body_hash,
            etag,
        })
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        self.get_checked(key, &GetObjectOptions::default()).await
    }

    async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, StoreError> {
        collect_download(
            self.get_verified(key, options, LEGACY_DOWNLOAD_LIMIT)
                .await?,
        )
        .await
    }

    async fn get_verified(
        &self,
        key: &str,
        options: &GetObjectOptions,
        max_bytes: u64,
    ) -> Result<ArtifactDownload, StoreError> {
        let full_key = self.full_key(key)?;
        if let Some(expected) = &options.expected_checksum_sha256 {
            validate_checksum(expected)?;
        }
        let mut signed_headers = vec![("x-amz-checksum-mode", "ENABLED".into())];
        if let Some(etag) = &options.if_match {
            signed_headers.push(("if-match", etag.clone()));
        }
        let signed = self.signed(Method::GET, &full_key, EMPTY_SHA256, &signed_headers)?;
        let response = self
            .client
            .request(Method::GET, signed.url)
            .headers(signed.headers)
            .send()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        let response = require_success(response).await?;
        let declared_size = response.content_length();
        if let Some(size) = declared_size {
            check_size(size, max_bytes)?;
        }
        let remote_checksum = response_header(&response, "x-amz-checksum-sha256")?;
        let etag = response_header(&response, header::ETAG.as_str())?;
        if options.if_match.is_some()
            && etag.as_deref().map(|value| value.trim_matches('"'))
                != options
                    .if_match
                    .as_deref()
                    .map(|value| value.trim_matches('"'))
        {
            return Err(StoreError::ObjectStore(
                "S3 ETag precondition failed".into(),
            ));
        }
        let mut reader = StreamReader::new(response.bytes_stream().map_err(std::io::Error::other));
        let mut spool = anonymous_spool().await?;
        let (size_bytes, actual) = hash_reader(&mut reader, Some(&mut spool), max_bytes).await?;
        if declared_size.is_some_and(|size| size != size_bytes) {
            return Err(StoreError::ObjectStore("S3 object size mismatch".into()));
        }
        if let Some(remote) = remote_checksum {
            let digest = BASE64.decode(remote.trim_matches('"')).map_err(|error| {
                StoreError::ObjectStore(format!("invalid S3 response checksum: {error}"))
            })?;
            if hex::encode(digest) != actual {
                return Err(StoreError::ObjectStore(
                    "S3 response checksum mismatch".into(),
                ));
            }
        }
        verify_digest(&actual, options)?;
        Ok(ArtifactDownload {
            metadata: ObjectMetadata {
                key: key.to_owned(),
                size_bytes,
                checksum_sha256: actual,
                etag,
            },
            body: Box::new(SpoolSource {
                file: spool,
                remaining: size_bytes,
            }),
        })
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let key = self.full_key(key)?;
        let signed = self.signed(Method::DELETE, &key, EMPTY_SHA256, &[])?;
        let response = self
            .client
            .request(Method::DELETE, signed.url)
            .headers(signed.headers)
            .send()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        require_success(response).await?;
        Ok(())
    }

    async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), StoreError> {
        let key = self.full_key(key)?;
        let signed = self.signed(
            Method::DELETE,
            &key,
            EMPTY_SHA256,
            &[("if-match", etag.into())],
        )?;
        let response = self
            .client
            .request(Method::DELETE, signed.url)
            .headers(signed.headers)
            .send()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        require_success(response).await?;
        Ok(())
    }
}

#[async_trait]
impl ArtifactStore for S3ObjectStore {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<ObjectMetadata, CoreError> {
        Self::put(self, key, bytes).await.map_err(core_error)
    }
    async fn put_stream(
        &self,
        key: &str,
        source: &mut dyn ArtifactSource,
        max_bytes: u64,
    ) -> Result<ObjectMetadata, CoreError> {
        Self::put_stream(self, key, source, max_bytes)
            .await
            .map_err(core_error)
    }
    async fn get_verified(
        &self,
        key: &str,
        options: &GetObjectOptions,
        max_bytes: u64,
    ) -> Result<ArtifactDownload, CoreError> {
        Self::get_verified(self, key, options, max_bytes)
            .await
            .map_err(core_error)
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<ObjectMetadata>, CoreError> {
        Err(CoreError::Unsupported(
            "S3 artifact listing is not implemented".into(),
        ))
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, CoreError> {
        Self::get(self, key).await.map_err(core_error)
    }

    async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, CoreError> {
        Self::get_checked(self, key, options)
            .await
            .map_err(core_error)
    }

    async fn delete(&self, key: &str) -> Result<(), CoreError> {
        Self::delete(self, key).await.map_err(core_error)
    }

    async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), CoreError> {
        Self::delete_if_match(self, key, etag)
            .await
            .map_err(core_error)
    }
}

fn hmac(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

fn uri_encode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn canonical_query(url: &Url) -> String {
    let mut pairs = url
        .query_pairs()
        .map(|(name, value)| (uri_encode(&name), uri_encode(&value)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn host_header(url: &Url) -> Result<String, StoreError> {
    let host = url
        .host_str()
        .ok_or_else(|| StoreError::ObjectStore("S3 endpoint has no host".into()))?;
    let host = match url.port() {
        None | Some(443) if url.scheme() == "https" => host.to_owned(),
        Some(80) if url.scheme() == "http" => host.to_owned(),
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok(host)
}

fn response_header(response: &reqwest::Response, name: &str) -> Result<Option<String>, StoreError> {
    response
        .headers()
        .get(name)
        .map(|value| {
            value.to_str().map(str::to_owned).map_err(|error| {
                StoreError::ObjectStore(format!("invalid S3 response header: {error}"))
            })
        })
        .transpose()
}

async fn require_success(mut response: reqwest::Response) -> Result<reqwest::Response, StoreError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let mut body = Vec::with_capacity(1024);
    while body.len() < 1024 {
        let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?
        else {
            break;
        };
        let length = chunk.len().min(1024 - body.len());
        body.extend_from_slice(&chunk[..length]);
    }
    Err(StoreError::ObjectStore(format!(
        "S3 request returned {status}: {}",
        String::from_utf8_lossy(&body)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn filesystem_verified_download_is_bounded_and_refuses_corruption() {
        let root = std::env::temp_dir().join(format!("aiec-verified-{}", Uuid::new_v4()));
        let store = FilesystemObjectStore::new(&root);
        let payload = Bytes::from(vec![0x5a; TRANSFER_CHUNK_BYTES + 17]);
        let metadata = store
            .put_stream(
                "object",
                &mut BytesSource(payload.clone()),
                payload.len() as u64,
            )
            .await
            .unwrap();
        let options = GetObjectOptions {
            if_match: metadata.etag.clone(),
            expected_checksum_sha256: Some(metadata.checksum_sha256.clone()),
        };
        assert!(matches!(
            store
                .get_verified("object", &options, payload.len() as u64 - 1)
                .await,
            Err(StoreError::Core(CoreError::LimitExceeded(_)))
        ));
        let mut download = store
            .get_verified("object", &options, payload.len() as u64)
            .await
            .unwrap();
        // The verified body is isolated from subsequent mutations of the object.
        tokio::fs::write(root.join("object"), b"corrupt")
            .await
            .unwrap();
        assert_eq!(
            download.body.next_chunk().await.unwrap().unwrap(),
            payload.slice(..TRANSFER_CHUNK_BYTES)
        );
        assert_eq!(
            download.body.next_chunk().await.unwrap().unwrap(),
            payload.slice(TRANSFER_CHUNK_BYTES..)
        );
        assert!(download.body.next_chunk().await.unwrap().is_none());
        assert!(
            store
                .get_verified("object", &options, payload.len() as u64)
                .await
                .is_err()
        );
        assert!(
            store
                .get_verified(
                    "object",
                    &GetObjectOptions {
                        if_match: metadata.etag,
                        expected_checksum_sha256: None,
                    },
                    payload.len() as u64
                )
                .await
                .is_err()
        );
        drop(download);
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    /// `list` describes every object under a prefix, and on this backend it
    /// computes a size and a checksum for each by reading the file end to end,
    /// so an unbounded walk costs the bytes of the whole prefix. A tenant can
    /// add objects to a sandbox by name with nothing stopping it from adding
    /// many, which made one `GET` cost whatever the tenant had chosen to store.
    #[tokio::test]
    async fn a_listing_too_large_to_describe_is_refused_rather_than_truncated() {
        let root = std::env::temp_dir().join(format!("aiec-list-{}", Uuid::new_v4()));
        let store = FilesystemObjectStore::new(&root);

        for index in 0..MAX_LISTED_OBJECTS {
            store
                .put(
                    &format!("tenants/t/sandboxes/s/artifacts/artifact-{index:06}"),
                    Bytes::from(vec![b'a'; 8]),
                )
                .await
                .unwrap();
        }
        // Exactly at the bound is a complete listing, not a refusal: the bound
        // is where the walk stops being able to describe everything, not a
        // number the caller has to stay under.
        let at_bound = store
            .list("tenants/t/sandboxes/s/artifacts/")
            .await
            .unwrap();
        assert_eq!(at_bound.len(), MAX_LISTED_OBJECTS);

        store
            .put(
                "tenants/t/sandboxes/s/artifacts/artifact-overflow",
                Bytes::from(vec![b'a'; 8]),
            )
            .await
            .unwrap();
        // One over is refused, and the refusal must not look like a short
        // listing: a caller given fewer objects than exist would read it as a
        // complete answer, which is the failure the bound exists to prevent.
        assert!(matches!(
            store.list("tenants/t/sandboxes/s/artifacts/").await,
            Err(StoreError::ListingLimitExceeded(_))
        ));
        // The bound is on the walk, not on the prefix: a listing small enough
        // to describe still answers normally while the store holds more.
        let other = store
            .list("tenants/t/sandboxes/other/artifacts/")
            .await
            .unwrap();
        assert!(other.is_empty());

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    struct PausedSource {
        first: bool,
        paused: Option<tokio::sync::oneshot::Sender<()>>,
    }

    #[async_trait]
    impl ArtifactSource for PausedSource {
        async fn next_chunk(&mut self) -> Result<Option<Bytes>, CoreError> {
            if self.first {
                self.first = false;
                return Ok(Some(Bytes::from_static(b"incomplete")));
            }
            if let Some(paused) = self.paused.take() {
                let _ = paused.send(());
            }
            std::future::pending().await
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn filesystem_cancelled_upload_cleans_staging_and_releases_ownership() {
        let root = std::env::temp_dir().join(format!("aiec-aborted-{}", Uuid::new_v4()));
        let store = FilesystemObjectStore::new(&root);
        let (paused, wait) = tokio::sync::oneshot::channel();
        let uploader = store.clone();
        let task = tokio::spawn(async move {
            uploader
                .put_stream(
                    "object",
                    &mut PausedSource {
                        first: true,
                        paused: Some(paused),
                    },
                    1024,
                )
                .await
        });
        wait.await.unwrap();
        let mut entries = tokio::fs::read_dir(&root).await.unwrap();
        let temporary = entries.next_entry().await.unwrap().unwrap().path();
        assert!(
            temporary
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(".aiec-upload.")
        );
        let janitor = FilesystemObjectStore::new(&root);
        assert_eq!(
            janitor
                .cleanup_temporary_uploads(Utc::now() + chrono::Duration::hours(1), 100)
                .await
                .unwrap(),
            0
        );
        assert!(temporary.exists());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!temporary.exists());
        assert!(!root.join("object").exists());
        let metadata = store
            .put_stream(
                "object",
                &mut BytesSource(Bytes::from_static(b"complete")),
                8,
            )
            .await
            .unwrap();
        assert_eq!(
            metadata.checksum_sha256,
            hex::encode(Sha256::digest(b"complete"))
        );
        let mut entries = tokio::fs::read_dir(&root).await.unwrap();
        assert_eq!(
            entries.next_entry().await.unwrap().unwrap().file_name(),
            "object"
        );
        assert!(entries.next_entry().await.unwrap().is_none());
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn filesystem_rejected_stream_never_replaces_committed_object() {
        let root = std::env::temp_dir().join(format!("aiec-overflow-{}", Uuid::new_v4()));
        let store = FilesystemObjectStore::new(&root);
        store
            .put("object", Bytes::from_static(b"original"))
            .await
            .unwrap();
        assert!(matches!(
            store
                .put_stream(
                    "object",
                    &mut BytesSource(Bytes::from_static(b"too large")),
                    8
                )
                .await,
            Err(StoreError::Core(CoreError::LimitExceeded(_)))
        ));
        assert_eq!(store.get("object").await.unwrap(), b"original");
        let mut entries = tokio::fs::read_dir(&root).await.unwrap();
        assert_eq!(
            entries.next_entry().await.unwrap().unwrap().file_name(),
            "object"
        );
        assert!(entries.next_entry().await.unwrap().is_none());
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    async fn s3_response(response: Vec<u8>) -> (S3ObjectStore, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let count = socket.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
            }
            // Oversized declared bodies may be refused before the server finishes.
            let _ = socket.write_all(&response).await;
        });
        let store = S3ObjectStore::new(S3Config {
            endpoint,
            region: "us-east-1".into(),
            bucket: "examplebucket".into(),
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            prefix: String::new(),
            request_timeout: Duration::from_secs(5),
        })
        .unwrap();
        (store, server)
    }

    #[tokio::test]
    async fn s3_verified_download_rejects_declared_and_actual_oversize() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n123456789".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n9\r\n123456789\r\n0\r\n\r\n".to_vec(),
        ] {
            let (store, server) = s3_response(response).await;
            assert!(matches!(
                store.get_verified("object", &GetObjectOptions::default(), 8).await,
                Err(StoreError::Core(CoreError::LimitExceeded(_)))
            ));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn s3_verified_download_checks_checksum_version_and_truncation_before_return() {
        let digest = hex::encode(Sha256::digest(b"payload"));
        let options = GetObjectOptions {
            if_match: Some("\"version\"".into()),
            expected_checksum_sha256: Some(digest),
        };
        for headers in [
            "Content-Length: 7\r\nETag: \"other\"\r\n",
            "Content-Length: 7\r\nETag: \"version\"\r\nx-amz-checksum-sha256: aW52YWxpZA==\r\n",
            "Content-Length: 8\r\nETag: \"version\"\r\n",
        ] {
            let (store, server) = s3_response(
                format!("HTTP/1.1 200 OK\r\n{headers}Connection: close\r\n\r\npayload")
                    .into_bytes(),
            )
            .await;
            assert!(store.get_verified("object", &options, 8).await.is_err());
            server.await.unwrap();
        }
        let (store, server) = s3_response(format!(
            "HTTP/1.1 200 OK\r\nETag: \"version\"\r\nx-amz-checksum-sha256: {}\r\nConnection: close\r\n\r\npayload",
            BASE64.encode(Sha256::digest(b"payload"))
        ).into_bytes()).await;
        let download = store.get_verified("object", &options, 7).await.unwrap();
        assert_eq!(collect_download(download).await.unwrap(), b"payload");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn untrusted_download_reads_only_one_sentinel_byte_past_limit() {
        let payload = [0x5a; TRANSFER_CHUNK_BYTES * 2];
        let mut reader = payload.as_slice();
        let mut spool = anonymous_spool().await.unwrap();
        assert!(matches!(
            hash_reader(&mut reader, Some(&mut spool), 8).await,
            Err(StoreError::Core(CoreError::LimitExceeded(_)))
        ));
        assert_eq!(reader.len(), payload.len() - 9);
        // An oversized first read is rejected before any bytes reach the spool.
        assert_eq!(spool.metadata().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn cancelling_s3_verification_closes_unfinished_backend_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (sent, ready) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let count = socket.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")
                .await
                .unwrap();
            sent.send(()).unwrap();
            let count = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                count, 0,
                "cancelled download kept the backend response alive"
            );
        });
        let store = S3ObjectStore::new(S3Config {
            endpoint,
            region: "us-east-1".into(),
            bucket: "examplebucket".into(),
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            prefix: String::new(),
            request_timeout: Duration::from_secs(5),
        })
        .unwrap();
        let task = tokio::spawn(async move {
            store
                .get_verified("object", &GetObjectOptions::default(), 8)
                .await
                .map(|_| ())
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn download_spool_is_unlinked_before_any_body_is_written() {
        use std::os::unix::fs::MetadataExt;
        let mut spool = anonymous_spool().await.unwrap();
        assert_eq!(spool.metadata().await.unwrap().nlink(), 0);
        spool.write_all(b"private verified body").await.unwrap();
        spool.rewind().await.unwrap();
        let mut body = SpoolSource {
            file: spool,
            remaining: 21,
        };
        assert_eq!(
            body.next_chunk().await.unwrap().unwrap(),
            b"private verified body".as_slice()
        );
        drop(body);
    }

    fn store() -> S3ObjectStore {
        S3ObjectStore::new(S3Config {
            endpoint: "https://s3.example.test".into(),
            region: "us-east-1".into(),
            bucket: "examplebucket".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            prefix: "tenant-a".into(),
            request_timeout: Duration::from_secs(5),
        })
        .expect("test configuration")
    }
    #[tokio::test]
    async fn s3_put_get_delete_when_configured() {
        if std::env::var("AIEC_RUN_S3_TESTS").as_deref() != Ok("1") {
            return;
        }
        let endpoint = std::env::var("AIEC_S3_ENDPOINT")
            .expect("AIEC_S3_ENDPOINT is required when S3 tests are enabled");
        let store = S3ObjectStore::new(S3Config {
            endpoint,
            region: std::env::var("AIEC_S3_REGION")
                .expect("AIEC_S3_REGION is required when S3 tests are enabled"),
            bucket: std::env::var("AIEC_S3_BUCKET")
                .expect("AIEC_S3_BUCKET is required when S3 tests are enabled"),
            access_key_id: std::env::var("AIEC_S3_ACCESS_KEY_ID")
                .expect("AIEC_S3_ACCESS_KEY_ID is required when S3 tests are enabled"),
            secret_access_key: std::env::var("AIEC_S3_SECRET_ACCESS_KEY")
                .expect("AIEC_S3_SECRET_ACCESS_KEY is required when S3 tests are enabled"),
            prefix: std::env::var("AIEC_S3_PREFIX").unwrap_or_default(),
            request_timeout: Duration::from_secs(10),
        })
        .expect("valid S3 configuration");
        let key = format!("integration/{}.txt", Uuid::new_v4());
        let payload = b"aiec live S3 artifact";
        let operation = async {
            let metadata = store
                .put_stream(
                    &key,
                    &mut BytesSource(Bytes::from_static(payload)),
                    payload.len() as u64,
                )
                .await
                .map_err(|error| error.to_string())?;
            if metadata.size_bytes != payload.len() as u64 {
                return Err(format!("unexpected object size: {}", metadata.size_bytes));
            }
            let download = store
                .get_verified(
                    &key,
                    &GetObjectOptions {
                        if_match: metadata.etag,
                        expected_checksum_sha256: Some(metadata.checksum_sha256),
                    },
                    payload.len() as u64,
                )
                .await
                .map_err(|error| error.to_string())?;
            let downloaded = collect_download(download)
                .await
                .map_err(|error| error.to_string())?;
            if downloaded != payload {
                return Err("downloaded object bytes differ".into());
            }
            Ok::<(), String>(())
        }
        .await;
        let cleanup = store.delete(&key).await;
        operation.expect("live S3 put/get workflow");
        cleanup.expect("live S3 delete cleanup");
        assert!(
            store.get(&key).await.is_err(),
            "deleted object remains readable"
        );
    }

    #[test]
    fn rejects_unsafe_keys() {
        for key in [
            "",
            "/absolute",
            "../escape",
            "safe/../escape",
            "a//b",
            "a\\b",
        ] {
            assert!(validate_object_key(key).is_err(), "accepted {key:?}");
        }
        assert!(validate_object_key("tenant/sandbox-123/manifest.json").is_ok());
    }
    #[tokio::test]
    async fn filesystem_list_omits_in_progress_temp_files() {
        let root = std::env::temp_dir().join(format!("aiec-list-{}", Uuid::new_v4()));
        let store = FilesystemObjectStore::new(&root);
        store
            .put("prefix/committed", Bytes::from_static(b"payload"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("prefix"))
            .await
            .unwrap();
        tokio::fs::write(root.join("prefix/.upload.uuid.tmp"), b"incomplete")
            .await
            .unwrap();
        let listed = store.list("prefix").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "prefix/committed");
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn temporary_gc_bounds_scanning_and_preserves_fresh_owned_and_nonupload_files() {
        let root = std::env::temp_dir().join(format!("aiec-temp-gc-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(root.join("nested"))
            .await
            .unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(7200);
        let staging = |name: &str| {
            let path = root.join("nested").join(name);
            let file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .unwrap();
            file.set_times(std::fs::FileTimes::new().set_modified(old))
                .unwrap();
            (path, file)
        };
        let (abandoned, abandoned_owner) = staging(&format!(".aiec-upload.{}.tmp", Uuid::new_v4()));
        drop(abandoned_owner);
        let (owned, owner) = staging(&format!(".aiec-upload.{}.tmp", Uuid::new_v4()));
        lock_temporary_file(&owner).unwrap();
        let (nonupload, file) = staging("committed-object");
        drop(file);
        let fresh = root
            .join("nested")
            .join(format!(".aiec-upload.{}.tmp", Uuid::new_v4()));
        tokio::fs::write(&fresh, b"in-progress").await.unwrap();
        // A separately created store tests the cross-instance OS lock, not just
        // the per-instance mutex used by normal uploads.
        let janitor = FilesystemObjectStore::new(&root);
        let cutoff = Utc::now() - chrono::Duration::hours(1);
        let mut removed = 0;
        for _ in 0..20 {
            let count = janitor.cleanup_temporary_uploads(cutoff, 1).await.unwrap();
            assert!(count <= 1);
            removed += count;
        }
        assert_eq!(removed, 1);
        assert!(!abandoned.exists());
        assert!(owned.exists());
        assert!(nonupload.exists());
        assert!(fresh.exists());
        drop(owner);
        for _ in 0..20 {
            removed += janitor.cleanup_temporary_uploads(cutoff, 1).await.unwrap();
        }
        assert_eq!(removed, 2);
        assert!(!owned.exists());
        assert!(nonupload.exists());
        assert!(fresh.exists());
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn filesystem_list_rejects_symlinked_intermediate_directory() {
        let root = std::env::temp_dir().join(format!("aiec-list-root-{}", Uuid::new_v4()));
        let outside = std::env::temp_dir().join(format!("aiec-list-outside-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::create_dir_all(&outside).await.unwrap();
        tokio::fs::create_dir_all(outside.join("nested"))
            .await
            .unwrap();
        std::os::unix::fs::symlink(outside.join("nested"), root.join("linked")).unwrap();
        let store = FilesystemObjectStore::new(&root);
        assert!(store.list("linked").await.is_err());
        let _ = tokio::fs::remove_dir_all(root).await;
        let _ = tokio::fs::remove_dir_all(outside).await;
    }

    #[test]
    fn filesystem_store_rejects_symlink_escape() {
        let root = std::env::temp_dir().join(format!("aiec-store-{}", Uuid::new_v4()));
        let outside = std::env::temp_dir().join(format!("aiec-outside-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let store = FilesystemObjectStore::new(&root);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        assert!(runtime.block_on(store.delete("escape/file")).is_err());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[test]
    fn filesystem_delete_is_idempotent_and_enforces_etag() {
        let root = std::env::temp_dir().join(format!("aiec-store-{}", Uuid::new_v4()));
        let store = FilesystemObjectStore::new(&root);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let metadata = store
                .put("nested/object", Bytes::from_static(b"payload"))
                .await
                .unwrap();
            let etag = metadata.etag.unwrap();
            assert!(store.delete("nested/object").await.is_ok());
            assert!(store.delete("nested/object").await.is_ok());
            assert!(store.delete("missing/nested/object").await.is_ok());
            assert!(!root.join("missing").exists());

            let metadata = store
                .put("conditional/object", Bytes::from_static(b"payload"))
                .await
                .unwrap();
            assert!(
                store
                    .delete_if_match("conditional/object", "wrong-etag")
                    .await
                    .is_err()
            );
            assert_eq!(store.get("conditional/object").await.unwrap(), b"payload");
            store
                .delete_if_match("conditional/object", &etag)
                .await
                .unwrap();
            assert!(store.delete("conditional/object").await.is_ok());
            assert_eq!(metadata.checksum_sha256.len(), 64);
        });
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn signs_the_aws_v4_canonical_request() {
        let signed = store()
            .sign(
                &Method::PUT,
                "tenant-a/sandbox/manifest.json",
                &Sha256::digest(b"payload")
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                &[
                    ("content-type", "application/octet-stream".into()),
                    ("if-none-match", "*".into()),
                    (
                        "x-amz-checksum-sha256",
                        BASE64.encode(Sha256::digest(b"payload")),
                    ),
                ],
                DateTime::parse_from_rfc3339("2015-08-30T12:36:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap();
        assert_eq!(
            signed.url.as_str(),
            "https://s3.example.test/examplebucket/tenant-a/sandbox/manifest.json"
        );
        let authorization = signed
            .headers
            .get(header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, \
             SignedHeaders=content-type;host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date, \
             Signature=28de62bcc0842a5a798456f4bc2b3c80b478c8fe4dbb00fafb97a27894d571b2"
        );
    }
}
