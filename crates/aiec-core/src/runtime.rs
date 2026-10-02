//! Runtime boundary and capability discovery.
//!
//! Runtime implementations translate generic sandbox operations to a backend
//! such as a local jail or a virtual machine. Backend-specific configuration
//! never appears in these contracts.

use crate::{
    DeleteFileRequest, ExecRequest, ExecResult, FileContent, FileEntry, MakeDirectoryRequest,
    PutFileRequest, Sandbox,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::RuntimeKind;
pub use crate::{SandboxId, TenantId};

/// Maximum payload of one artifact range read.
pub const FILE_CHUNK_BYTES: usize = 64 * 1024;
/// How many consecutive chunks one authorized worker read may carry. The
/// authorization pair brackets the whole group, so a lease replaced midway
/// still stops the bytes before they are written; grouping only removes the
/// per-chunk round trip, not the check. Bounded so a group is at most this
/// times `FILE_CHUNK_BYTES` in memory.
pub const FILE_CHUNK_BURST: usize = 32;

/// The request for the `index`-th chunk of a burst starting at this request.
pub fn burst_request(request: &FileChunkRequest, index: usize) -> FileChunkRequest {
    FileChunkRequest {
        path: request.path.clone(),
        offset: request.offset + (index * request.length) as u64,
        length: request.length,
        expected_version: request.expected_version.clone(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileChunkRequest {
    pub path: String,
    pub offset: u64,
    pub length: usize,
    pub expected_version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FileChunk {
    pub bytes: bytes::Bytes,
    pub size_bytes: u64,
    pub version: String,
    pub eof: bool,
}

/// One piece of a file being written into a sandbox.
///
/// The mirror of [`FileChunkRequest`], and it exists for the same reason. A
/// single `WriteFile` has to fit its whole payload into one authenticated frame
/// on the control channel, which is far smaller than `MAX_FILE`, so a file that
/// the API advertises as acceptable could not actually be sent. The total size
/// is declared up front rather than discovered at the end, so an upload that
/// would exceed `MAX_FILE` is refused before any of it is written and a caller
/// that stops early leaves a short file rather than a plausible-looking one.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileWriteChunkRequest {
    pub path: String,
    pub offset: u64,
    pub size_bytes: u64,
    #[serde(default)]
    pub mode: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct FileWriteChunk {
    pub written: usize,
    pub size_bytes: u64,
}

/// Whether this whole write fits in one control-channel frame.
///
/// Small files still travel as a single `WriteFile`, which keeps them to one
/// round trip and keeps guests that predate chunked writes working. The
/// payload is a JSON array of numbers, which costs at most four wire bytes per
/// payload byte, so sizing against that is the conservative estimate; the
/// fixed term covers the path and the request envelope.
pub fn write_fits_one_frame(path: &str, content: &[u8]) -> bool {
    content
        .len()
        .saturating_mul(4)
        .saturating_add(path.len())
        .saturating_add(256)
        < crate::protocol::MAX_FRAME
}

/// A JSON range reply must not allocate an oversized byte vector before validation.
pub fn deserialize_file_chunk_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct ChunkVisitor;
    impl<'de> serde::de::Visitor<'de> for ChunkVisitor {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded file chunk byte array")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Vec<u8>, A::Error> {
            let mut bytes =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(FILE_CHUNK_BYTES));
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() == FILE_CHUNK_BYTES {
                    return Err(serde::de::Error::custom("file chunk exceeds 64 KiB"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(ChunkVisitor)
}

impl FileChunkRequest {
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        crate::safe_path(&self.path)?;
        if self.length == 0 || self.length > FILE_CHUNK_BYTES {
            return Err(crate::CoreError::InvalidRequest(
                "invalid file chunk length".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_chunk(&self, chunk: &FileChunk) -> Result<(), crate::CoreError> {
        self.validate()?;
        if chunk.size_bytes > crate::MAX_FILE as u64 {
            return Err(crate::CoreError::LimitExceeded("file".into()));
        }
        if self.offset > chunk.size_bytes
            || chunk.bytes.len()
                != (chunk.size_bytes - self.offset).min(self.length as u64) as usize
            || chunk.eof != (self.offset + chunk.bytes.len() as u64 == chunk.size_bytes)
            || chunk.version.is_empty()
            || self
                .expected_version
                .as_ref()
                .is_some_and(|v| v != &chunk.version)
        {
            return Err(crate::CoreError::Conflict(
                "file changed or invalid chunk response".into(),
            ));
        }
        Ok(())
    }

    /// Reads relative to an opened workspace, never following a symlink.
    /// Descriptor-relative traversal also prevents rename/symlink races.
    #[cfg(unix)]
    pub fn read_workspace(&self, root: &std::path::Path) -> Result<FileChunk, crate::CoreError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
        self.validate()?;
        let path = crate::safe_path(&self.path)?;
        let relative = path
            .strip_prefix("/workspace")
            .map_err(|_| crate::CoreError::Forbidden("outside workspace".into()))?;
        let open = || -> Result<std::fs::File, crate::CoreError> {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(root)?;
            let mut parts = relative.components().peekable();
            while let Some(part) = parts.next() {
                let name = std::ffi::CString::new(part.as_os_str().as_bytes())
                    .map_err(|_| crate::CoreError::InvalidRequest("invalid path".into()))?;
                let flags = libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | if parts.peek().is_some() {
                        libc::O_DIRECTORY
                    } else {
                        0
                    };
                let fd = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags) };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                file = unsafe { std::fs::File::from_raw_fd(fd) };
            }
            Ok(file)
        };
        let version = |m: &std::fs::Metadata| {
            format!(
                "{}:{}:{}:{}:{}:{}:{}",
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec()
            )
        };
        let file = open()?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(crate::CoreError::InvalidRequest(
                "not a regular file".into(),
            ));
        }
        if before.len() > crate::MAX_FILE as u64 {
            return Err(crate::CoreError::LimitExceeded("file".into()));
        }
        let stamp = version(&before);
        if self.offset > before.len() || self.expected_version.as_ref().is_some_and(|v| v != &stamp)
        {
            return Err(crate::CoreError::Conflict(
                "file changed or invalid offset".into(),
            ));
        }
        let mut bytes = vec![0; (before.len() - self.offset).min(self.length as u64) as usize];
        file.read_exact_at(&mut bytes, self.offset)?;
        if stamp != version(&file.metadata()?) || stamp != version(&open()?.metadata()?) {
            return Err(crate::CoreError::Conflict(
                "file changed while reading".into(),
            ));
        }
        let chunk = FileChunk {
            eof: self.offset + bytes.len() as u64 == before.len(),
            bytes: bytes.into(),
            size_bytes: before.len(),
            version: stamp,
        };
        self.validate_chunk(&chunk)?;
        Ok(chunk)
    }
}

impl FileWriteChunkRequest {
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        crate::safe_path(&self.path)?;
        if self.size_bytes > crate::MAX_FILE as u64 {
            return Err(crate::CoreError::LimitExceeded("file".into()));
        }
        Ok(())
    }

    /// Checks one piece of the upload against the declared total.
    ///
    /// The rule that matters is the last one: a chunk that is shorter than the
    /// transfer unit has to be the final one. Without it a caller could declare
    /// ten megabytes, send three bytes and stop, and the guest would report a
    /// file that looks complete and is not.
    pub fn validate_content(&self, content: &[u8]) -> Result<(), crate::CoreError> {
        self.validate()?;
        let end = self.offset.saturating_add(content.len() as u64);
        if content.is_empty() || content.len() > FILE_CHUNK_BYTES || end > self.size_bytes {
            return Err(crate::CoreError::InvalidRequest(
                "invalid file chunk write".into(),
            ));
        }
        if end < self.size_bytes && content.len() != FILE_CHUNK_BYTES {
            return Err(crate::CoreError::InvalidRequest(
                "only the final chunk of a file may be short".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_chunk(&self, chunk: &FileWriteChunk) -> Result<(), crate::CoreError> {
        self.validate()?;
        if chunk.written == 0
            || chunk.written > FILE_CHUNK_BYTES
            || chunk.size_bytes != self.size_bytes
        {
            return Err(crate::CoreError::Conflict(
                "invalid file chunk write response".into(),
            ));
        }
        Ok(())
    }

    /// Writes one piece relative to an opened workspace, never following a
    /// symlink. Descriptor-relative traversal prevents rename/symlink races in
    /// the same way the read path does.
    #[cfg(unix)]
    pub fn write_workspace(
        &self,
        root: &std::path::Path,
        content: &[u8],
    ) -> Result<FileWriteChunk, crate::CoreError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        self.validate_content(content)?;
        let path = crate::safe_path(&self.path)?;
        let relative = path
            .strip_prefix("/workspace")
            .map_err(|_| crate::CoreError::Forbidden("outside workspace".into()))?;
        // Intermediate directories are created under `root`, not under the
        // logical `/workspace` path. `safe_path` has already proved the parent
        // stays inside the workspace, and the guest's root is where that tree
        // actually lives - creating the logical path instead would escape to
        // the real filesystem root of whatever process is running this.
        if let Some(parent) = std::path::Path::new(relative).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(root.join(parent))?;
        }
        let mut file = std::fs::OpenOptions::new().read(true).open(root)?;
        let mut parts = relative.components().peekable();
        while let Some(part) = parts.next() {
            let name = std::ffi::CString::new(part.as_os_str().as_bytes())
                .map_err(|_| crate::CoreError::InvalidRequest("invalid path".into()))?;
            let final_component = parts.peek().is_none();
            let mut flags = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
            if final_component {
                flags |= libc::O_WRONLY | libc::O_CREAT;
            } else {
                flags |= libc::O_RDONLY | libc::O_DIRECTORY;
            }
            let fd = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags, 0o600) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            file = unsafe { std::fs::File::from_raw_fd(fd) };
        }
        {
            use std::os::unix::fs::FileExt;
            file.write_all_at(content, self.offset)?;
        }
        let end = self.offset + content.len() as u64;
        if end == self.size_bytes {
            // A file that already existed longer than the declared total would
            // otherwise keep its tail, so the upload would appear to succeed and
            // leave a file with bytes nobody sent.
            if file.metadata()?.len() > self.size_bytes {
                file.set_len(self.size_bytes)?;
            }
            if let Some(mode) = self.mode {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            }
        }
        file.sync_all()?;
        let chunk = FileWriteChunk {
            written: content.len(),
            size_bytes: self.size_bytes,
        };
        self.validate_chunk(&chunk)?;
        Ok(chunk)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeIsolation {
    #[default]
    Process,
    Container,
    MicroVm,
    FullVm,
}

impl RuntimeIsolation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Container => "container",
            Self::MicroVm => "microvm",
            Self::FullVm => "full_vm",
        }
    }
}

/// Capabilities advertised by a sandbox runtime implementation.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeCapabilities {
    /// Isolation class advertised by the runtime.
    pub isolation: RuntimeIsolation,
    /// Whether command execution is supported.
    pub exec: bool,
    /// Whether workspace file operations are supported.
    pub files: bool,
    /// Whether exec output can be streamed.
    pub streaming: bool,
    /// Whether pseudo-terminal sessions are supported.
    pub pty: bool,
    /// Whether standard OCI/Docker images are accepted.
    pub docker_image: bool,
    /// Whether a guest control agent is used.
    pub guest_agent: bool,
    /// Whether the boundary is a full hardware-isolated kernel.
    pub full_kernel_isolation: bool,
    /// Whether workspace artifacts are portable across runtime instances.
    pub portable_workspace: bool,
    /// Whether the runtime can snapshot and restore a stopped VM.
    pub vm_snapshot: bool,
    /// Whether execution can resume with memory state intact.
    pub memory_resume: bool,
    /// Whether the runtime enforces a caller-provided network policy.
    pub network_policy: bool,
    /// Whether hardware accelerators can be assigned to a sandbox.
    pub gpu: bool,
    /// Whether the runtime can pause a running sandbox.
    pub pause: bool,
    /// Whether pause releases host runtime resources rather than only suspending execution.
    pub pause_reclaims_resources: bool,
    /// Whether filesystem-only workspace snapshots are available.
    pub workspace_snapshot: bool,
    /// Whether guest communication uses a VSock-like transport.
    pub vsock: bool,
    /// Whether the guest image is a verified coding-capable artifact.
    pub coding_guest: bool,
    /// Minimum writable disk reservation for this runtime's base image, in MiB.
    /// Zero means no floor.
    ///
    /// Excluded from the stored capability document on both sides. It is a
    /// capacity floor, not a capability: a worker advertises the floor of the
    /// image it holds, while a sandbox requires only what it asked for, and
    /// making the two comparable by JSON containment would compare `4096` to
    /// `0` and refuse every placement on a microVM host. The scheduler applies
    /// the floor arithmetically instead - see `RuntimeCapabilities::disk_floor_mb`.
    #[serde(skip)]
    pub minimum_disk_mb: u64,
}

impl RuntimeCapabilities {
    /// The writable disk a sandbox on this runtime must be given, in MiB.
    pub fn disk_floor_mb(&self) -> u64 {
        self.minimum_disk_mb
    }
}

/// Current operational health of a runtime.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeHealth {
    /// Whether the runtime is ready to accept work.
    pub healthy: bool,
    /// Human-readable detail, especially when unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl RuntimeHealth {
    /// Creates a healthy status with no diagnostic message.
    pub fn healthy() -> Self {
        Self {
            healthy: true,
            message: None,
        }
    }

    /// Creates an unhealthy status with a diagnostic message.
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            healthy: false,
            message: Some(message.into()),
        }
    }
}

/// Backend-neutral lifecycle and workload operations for sandboxes.
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    /// Allocates backend resources for a sandbox.
    async fn create(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Starts a previously created sandbox.
    async fn start(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Gracefully stops a running sandbox.
    async fn stop(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Pauses a running sandbox while retaining its runtime state.
    async fn pause(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Resumes a paused sandbox.
    async fn resume(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Configures the durable outside-guest Guard admission authority.
    fn configure_guard_budget_authority(
        &self,
        _authority: Arc<dyn aiec_guard::control::BudgetAuthority>,
    ) -> Result<(), crate::CoreError> {
        Err(crate::CoreError::Unsupported("Guard budgets".into()))
    }
    /// Binds guarded startup to the worker operation's proven current lease.
    async fn guard_set_fence(
        &self,
        _sandbox: &Sandbox,
        _fence: aiec_guard::control::GuardFence,
    ) -> Result<(), crate::CoreError> {
        Err(crate::CoreError::Unsupported("Guard ownership".into()))
    }
    /// Performs an ownership-pinned Guard action; capture must remain paused.
    async fn guard_control(
        &self,
        _sandbox: &Sandbox,
        _fence: aiec_guard::control::GuardFence,
        _command: aiec_guard::control::GuardControlCommand,
    ) -> Result<aiec_guard::control::GuardControlResponse, crate::CoreError> {
        Err(crate::CoreError::Unsupported("Guard control".into()))
    }
    /// Executes a command inside a sandbox.
    async fn exec(
        &self,
        sandbox: &Sandbox,
        request: ExecRequest,
    ) -> Result<ExecResult, crate::CoreError>;
    /// Writes a file into a sandbox.
    async fn put_file(
        &self,
        sandbox: &Sandbox,
        request: PutFileRequest,
    ) -> Result<(), crate::CoreError>;
    /// Reads a file from a sandbox.
    async fn get_file(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<FileContent, crate::CoreError>;
    /// Reads one bounded, version-consistent range without buffering the file.
    async fn get_file_chunk(
        &self,
        sandbox: &Sandbox,
        request: FileChunkRequest,
    ) -> Result<FileChunk, crate::CoreError>;
    /// Reads up to `count` consecutive chunks. The default is the obvious one
    /// — repeated single reads — and a runtime that can serve a whole group
    /// under one authorization overrides it.
    ///
    /// The first chunk read establishes the file the group is of, and every
    /// later read is made against that identity: same version, same size.
    /// A caller's own `expected_version`, when it has one, is what the first
    /// read is checked against and the group then continues under the version
    /// it reported. Without this, a caller's first burst - which arrives with
    /// no version to check, by construction - authorizes each chunk
    /// independently, and a same-size replacement between two completed
    /// chunks produces a group that validates per chunk and carries the first
    /// half of one file and the second half of another.
    async fn get_file_chunks(
        &self,
        sandbox: &Sandbox,
        request: FileChunkRequest,
        count: usize,
    ) -> Result<Vec<FileChunk>, crate::CoreError> {
        let mut chunks: Vec<FileChunk> = Vec::with_capacity(count.min(FILE_CHUNK_BURST));
        for index in 0..count.min(FILE_CHUNK_BURST) {
            let mut step = burst_request(&request, index);
            if let Some(first) = chunks.first() {
                step.expected_version = Some(first.version.clone());
            }
            let chunk = self.get_file_chunk(sandbox, step.clone()).await?;
            step.validate_chunk(&chunk)?;
            if let Some(first) = chunks.first()
                && chunk.size_bytes != first.size_bytes
            {
                return Err(crate::CoreError::Conflict(
                    "file changed within chunk group".into(),
                ));
            }
            let eof = chunk.eof;
            chunks.push(chunk);
            if eof {
                break;
            }
        }
        Ok(chunks)
    }
    /// Lists a directory in a sandbox.
    async fn list_files(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<Vec<FileEntry>, crate::CoreError>;
    /// Removes a file from a sandbox.
    async fn delete_file(
        &self,
        sandbox: &Sandbox,
        request: DeleteFileRequest,
    ) -> Result<(), crate::CoreError>;
    /// Creates a directory in a sandbox.
    async fn make_directory(
        &self,
        sandbox: &Sandbox,
        request: MakeDirectoryRequest,
    ) -> Result<(), crate::CoreError>;
    /// Replaces a sandbox workspace with a portable archive captured elsewhere.
    ///
    /// Recovery assigns a sandbox to a new runtime instance that never held
    /// the captured state, so the archive travels with the snapshot instead of
    /// living in the capturing runtime's local state directory. Implementations
    /// must fail rather than leave the workspace empty when the bytes cannot
    /// be applied.
    async fn import_workspace_archive(
        &self,
        sandbox: &Sandbox,
        archive: &[u8],
    ) -> Result<(), crate::CoreError>;
    /// Releases all resources owned by a sandbox.
    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError>;
    /// Reports current runtime health.
    async fn health(&self) -> RuntimeHealth;
    /// Reports immutable backend capabilities.
    fn capabilities(&self) -> RuntimeCapabilities;
}

/// Result of selecting a runtime from a registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSelection {
    pub runtime: crate::RuntimeKind,
    pub capabilities: RuntimeCapabilities,
    pub reason: String,
}

/// Core-owned registry of runtime implementations.
#[derive(Clone, Default)]
pub struct RuntimeRegistry {
    entries: Vec<(crate::RuntimeKind, Arc<dyn SandboxRuntime>)>,
}

impl RuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, kind: crate::RuntimeKind, runtime: Arc<dyn SandboxRuntime>) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|(existing, _)| *existing == kind)
        {
            entry.1 = runtime;
        } else {
            self.entries.push((kind, runtime));
        }
    }

    pub fn with_runtime(kind: crate::RuntimeKind, runtime: Arc<dyn SandboxRuntime>) -> Self {
        let mut registry = Self::new();
        registry.register(kind, runtime);
        registry
    }

    pub fn lookup(&self, kind: crate::RuntimeKind) -> Option<Arc<dyn SandboxRuntime>> {
        self.entries
            .iter()
            .find(|(existing, _)| *existing == kind)
            .map(|(_, runtime)| runtime.clone())
    }

    pub fn capabilities(&self, kind: crate::RuntimeKind) -> Option<RuntimeCapabilities> {
        self.lookup(kind).map(|runtime| runtime.capabilities())
    }

    pub async fn health(&self, kind: crate::RuntimeKind) -> Option<RuntimeHealth> {
        let runtime = self.lookup(kind)?;
        Some(runtime.health().await)
    }

    pub fn kinds(&self) -> Vec<crate::RuntimeKind> {
        self.entries.iter().map(|(kind, _)| *kind).collect()
    }

    pub async fn select(
        &self,
        requested: Option<crate::RuntimeKind>,
        required: &RuntimeCapabilities,
        minimum_isolation: Option<RuntimeIsolation>,
    ) -> Result<RuntimeSelection, crate::CoreError> {
        if let Some(kind) = requested {
            let runtime = self.lookup(kind).ok_or_else(|| {
                crate::CoreError::Unavailable(format!("runtime {kind:?} is not registered"))
            })?;
            let capabilities = runtime.capabilities();
            if !capabilities_satisfy(&capabilities, required, minimum_isolation) {
                return Err(crate::CoreError::Unsupported(format!(
                    "runtime {kind:?} lacks required capabilities"
                )));
            }
            return Ok(RuntimeSelection {
                runtime: kind,
                capabilities,
                reason: format!("explicit runtime {kind:?} selected"),
            });
        }
        let order = if minimum_isolation.is_some_and(|isolation| {
            matches!(
                isolation,
                RuntimeIsolation::MicroVm | RuntimeIsolation::FullVm
            )
        }) {
            [
                RuntimeKind::Firecracker,
                RuntimeKind::Hosted,
                RuntimeKind::Docker,
                RuntimeKind::BwrapDev,
            ]
        } else {
            [
                RuntimeKind::Docker,
                RuntimeKind::Firecracker,
                RuntimeKind::Hosted,
                RuntimeKind::BwrapDev,
            ]
        };
        for kind in order {
            let Some(runtime) = self.lookup(kind) else {
                continue;
            };
            if !runtime.health().await.healthy {
                continue;
            }
            let capabilities = runtime.capabilities();
            if capabilities_satisfy(&capabilities, required, minimum_isolation) {
                return Ok(RuntimeSelection {
                    runtime: kind,
                    capabilities,
                    reason: format!("policy selected {kind:?} from available capable runtimes"),
                });
            }
        }
        Err(crate::CoreError::Unavailable(
            "no available runtime satisfies requested capabilities".into(),
        ))
    }
}

/// Checks every requested capability and the minimum isolation boundary.
pub fn capabilities_satisfy(
    actual: &RuntimeCapabilities,
    required: &RuntimeCapabilities,
    minimum: Option<RuntimeIsolation>,
) -> bool {
    (!required.exec || actual.exec)
        && (!required.files || actual.files)
        && (!required.streaming || actual.streaming)
        && (!required.pty || actual.pty)
        && (!required.docker_image || actual.docker_image)
        && (!required.guest_agent || actual.guest_agent)
        && (!required.coding_guest || actual.coding_guest)
        && (!required.full_kernel_isolation || actual.full_kernel_isolation)
        && (!required.portable_workspace || actual.portable_workspace)
        && (!required.vm_snapshot || actual.vm_snapshot)
        && (!required.memory_resume || actual.memory_resume)
        && (!required.network_policy || actual.network_policy)
        && (!required.pause || actual.pause)
        && (!required.workspace_snapshot || actual.workspace_snapshot)
        && minimum.is_none_or(|minimum| isolation_rank(actual.isolation) >= isolation_rank(minimum))
}

fn isolation_rank(isolation: RuntimeIsolation) -> u8 {
    match isolation {
        RuntimeIsolation::Process => 0,
        RuntimeIsolation::Container => 1,
        RuntimeIsolation::MicroVm => 2,
        RuntimeIsolation::FullVm => 3,
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;
    use crate::{RuntimeKind, Sandbox};

    struct TestRuntime {
        capabilities: RuntimeCapabilities,
        healthy: bool,
    }

    #[async_trait]
    impl SandboxRuntime for TestRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn start(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, crate::CoreError> {
            Ok(ExecResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: 0,
                timed_out: false,
            })
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn get_file(&self, _: &Sandbox, path: &str) -> Result<FileContent, crate::CoreError> {
            Ok(FileContent {
                path: path.into(),
                content_base64: String::new(),
            })
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            _: FileChunkRequest,
        ) -> Result<FileChunk, crate::CoreError> {
            Err(crate::CoreError::Backend("unused".into()))
        }
        async fn list_files(
            &self,
            _: &Sandbox,
            _: &str,
        ) -> Result<Vec<FileEntry>, crate::CoreError> {
            Ok(Vec::new())
        }
        async fn delete_file(
            &self,
            _: &Sandbox,
            _: DeleteFileRequest,
        ) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn import_workspace_archive(
            &self,
            _: &Sandbox,
            _: &[u8],
        ) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn health(&self) -> RuntimeHealth {
            if self.healthy {
                RuntimeHealth::healthy()
            } else {
                RuntimeHealth::unhealthy("test")
            }
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            self.capabilities.clone()
        }
    }

    #[tokio::test]
    async fn registry_explicit_lookup_and_auto_prefers_available_runtimes() {
        let container = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::Container,
                exec: true,
                files: true,
                ..Default::default()
            },
            healthy: true,
        });
        let microvm = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::MicroVm,
                exec: true,
                files: true,
                full_kernel_isolation: true,
                ..Default::default()
            },
            healthy: true,
        });
        let mut registry = RuntimeRegistry::new();
        registry.register(RuntimeKind::Docker, container);
        registry.register(RuntimeKind::Firecracker, microvm);
        assert!(registry.lookup(RuntimeKind::Docker).is_some());
        assert_eq!(registry.kinds().len(), 2);
        let selected = registry
            .select(
                None,
                &RuntimeCapabilities {
                    exec: true,
                    files: true,
                    ..Default::default()
                },
                Some(RuntimeIsolation::MicroVm),
            )
            .await
            .unwrap();
        assert_eq!(selected.runtime, RuntimeKind::Firecracker);
        assert!(selected.reason.contains("policy selected"));
    }
    #[tokio::test]
    async fn registry_explicit_docker_and_firecracker_capabilities() {
        let docker = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::Container,
                exec: true,
                files: true,
                docker_image: true,
                ..Default::default()
            },
            healthy: true,
        });
        let firecracker = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::MicroVm,
                exec: true,
                files: true,
                full_kernel_isolation: true,
                guest_agent: true,
                ..Default::default()
            },
            healthy: true,
        });
        let mut registry = RuntimeRegistry::new();
        registry.register(RuntimeKind::Docker, docker);
        registry.register(RuntimeKind::Firecracker, firecracker);
        let required = RuntimeCapabilities {
            exec: true,
            files: true,
            ..Default::default()
        };
        let docker_selection = registry
            .select(Some(RuntimeKind::Docker), &required, None)
            .await
            .unwrap();
        assert_eq!(docker_selection.runtime, RuntimeKind::Docker);
        let microvm_selection = registry
            .select(
                Some(RuntimeKind::Firecracker),
                &required,
                Some(RuntimeIsolation::MicroVm),
            )
            .await
            .unwrap();
        assert_eq!(microvm_selection.runtime, RuntimeKind::Firecracker);
    }
    #[tokio::test]
    async fn hosted_is_reachable_by_auto_selection_without_displacing_firecracker() {
        let hosted = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::MicroVm,
                exec: true,
                files: true,
                full_kernel_isolation: true,
                guest_agent: true,
                pause: true,
                ..Default::default()
            },
            healthy: true,
        });
        let required = RuntimeCapabilities {
            exec: true,
            files: true,
            full_kernel_isolation: true,
            ..Default::default()
        };
        let hosted_only = RuntimeRegistry::with_runtime(RuntimeKind::Hosted, hosted.clone());
        let selected = hosted_only
            .select(None, &required, Some(RuntimeIsolation::MicroVm))
            .await
            .unwrap();
        assert_eq!(selected.runtime, RuntimeKind::Hosted);
        let firecracker = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::MicroVm,
                exec: true,
                files: true,
                full_kernel_isolation: true,
                ..Default::default()
            },
            healthy: true,
        });
        let mut registry = RuntimeRegistry::new();
        registry.register(RuntimeKind::Hosted, hosted);
        registry.register(RuntimeKind::Firecracker, firecracker);
        let preferred = registry
            .select(None, &required, Some(RuntimeIsolation::MicroVm))
            .await
            .unwrap();
        assert_eq!(preferred.runtime, RuntimeKind::Firecracker);
    }

    #[tokio::test]
    async fn hosted_outranks_a_container_runtime_when_a_microvm_is_required() {
        // The microVM branch of the preference order is [Firecracker, Hosted,
        // Docker, BwrapDev]. A container runtime cannot satisfy a microVM
        // minimum, so hosted must win here rather than the selection falling
        // through to a runtime that cannot provide the requested boundary.
        let hosted = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::MicroVm,
                exec: true,
                files: true,
                full_kernel_isolation: true,
                guest_agent: true,
                ..Default::default()
            },
            healthy: true,
        });
        let docker = Arc::new(TestRuntime {
            capabilities: RuntimeCapabilities {
                isolation: RuntimeIsolation::Container,
                exec: true,
                files: true,
                ..Default::default()
            },
            healthy: true,
        });
        let mut registry = RuntimeRegistry::new();
        registry.register(RuntimeKind::Docker, docker);
        registry.register(RuntimeKind::Hosted, hosted);
        let selected = registry
            .select(
                None,
                &RuntimeCapabilities {
                    exec: true,
                    files: true,
                    full_kernel_isolation: true,
                    ..Default::default()
                },
                Some(RuntimeIsolation::MicroVm),
            )
            .await
            .expect("a hosted microVM satisfies a microVM requirement");
        assert_eq!(selected.runtime, RuntimeKind::Hosted);
        // Without a microVM requirement the container runtime still wins, so
        // adding a hosted runtime never reorders the unprivileged path.
        let container_first = registry
            .select(
                None,
                &RuntimeCapabilities {
                    exec: true,
                    files: true,
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("docker satisfies a plain exec/files requirement");
        assert_eq!(container_first.runtime, RuntimeKind::Docker);
    }
}

#[cfg(all(test, unix))]
mod file_chunk_tests {
    use super::*;

    struct Workspace(std::path::PathBuf);
    impl Workspace {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("aiec-chunks-{}", uuid::Uuid::now_v7()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn request(&self, offset: u64) -> FileChunkRequest {
            FileChunkRequest {
                path: "/workspace/file".into(),
                offset,
                length: FILE_CHUNK_BYTES,
                expected_version: None,
            }
        }
    }
    fn sandbox() -> Sandbox {
        let now = chrono::Utc::now();
        Sandbox {
            id: uuid::Uuid::now_v7(),
            tenant_id: uuid::Uuid::now_v7(),
            node_id: None,
            image_id: "test".into(),
            state: crate::SandboxState::Running,
            runtime: crate::RuntimeKind::Firecracker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: crate::NetworkPolicy::Disabled,
            environment: crate::EnvironmentSpec::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        }
    }

    /// A runtime that answers every chunk read with the descriptor-relative
    /// read of a real workspace file, so a group read here is the same read a
    /// backend performs rather than a fixture the default loop cannot fail on.
    ///
    /// `replacement`, when set, is written over the file before the first read
    /// that starts past offset zero. That is the window a guest writer has
    /// between two completed chunk reads: the first chunk is already returned
    /// under one version, and the remaining ones are read from whatever the
    /// path resolves to by then.
    struct WorkspaceRuntime {
        root: std::path::PathBuf,
        replacement: Option<Vec<u8>>,
        swapped: std::sync::atomic::AtomicBool,
    }
    impl WorkspaceRuntime {
        fn new(root: &std::path::Path, replacement: Option<Vec<u8>>) -> Self {
            Self {
                root: root.to_path_buf(),
                replacement,
                swapped: std::sync::atomic::AtomicBool::new(false),
            }
        }
        /// Replaces the file's inode with same-length different bytes, the way
        /// an atomic rewrite looks to a reader that holds no descriptor.
        fn swap(&self, bytes: &[u8]) {
            let staged = self.root.join("staged");
            std::fs::write(&staged, bytes).unwrap();
            std::fs::rename(&staged, self.root.join("file")).unwrap();
        }
    }
    #[async_trait]
    impl SandboxRuntime for WorkspaceRuntime {
        async fn create(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn start(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn stop(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn pause(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn resume(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn exec(&self, _: &Sandbox, _: ExecRequest) -> Result<ExecResult, crate::CoreError> {
            Err(crate::CoreError::Backend("unused".into()))
        }
        async fn put_file(&self, _: &Sandbox, _: PutFileRequest) -> Result<(), crate::CoreError> {
            Err(crate::CoreError::Backend("unused".into()))
        }
        async fn get_file(&self, _: &Sandbox, _: &str) -> Result<FileContent, crate::CoreError> {
            Err(crate::CoreError::Backend("unused".into()))
        }
        async fn get_file_chunk(
            &self,
            _: &Sandbox,
            request: FileChunkRequest,
        ) -> Result<FileChunk, crate::CoreError> {
            if request.offset > 0
                && !self.swapped.load(std::sync::atomic::Ordering::SeqCst)
                && let Some(replacement) = &self.replacement
            {
                self.swapped
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                self.swap(replacement);
            }
            request.read_workspace(&self.root)
        }
        async fn list_files(
            &self,
            _: &Sandbox,
            _: &str,
        ) -> Result<Vec<FileEntry>, crate::CoreError> {
            Err(crate::CoreError::Backend("unused".into()))
        }
        async fn delete_file(
            &self,
            _: &Sandbox,
            _: DeleteFileRequest,
        ) -> Result<(), crate::CoreError> {
            Err(crate::CoreError::Backend("unused".into()))
        }
        async fn make_directory(
            &self,
            _: &Sandbox,
            _: MakeDirectoryRequest,
        ) -> Result<(), crate::CoreError> {
            Err(crate::CoreError::Backend("unused".into()))
        }
        async fn import_workspace_archive(
            &self,
            _: &Sandbox,
            _: &[u8],
        ) -> Result<(), crate::CoreError> {
            Err(crate::CoreError::Backend("unused".into()))
        }
        async fn destroy(&self, _: &Sandbox) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn health(&self) -> RuntimeHealth {
            RuntimeHealth::healthy()
        }
        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::default()
        }
    }

    /// The first burst of an artifact read carries no version to check
    /// against, so the file's identity has to be established by the first
    /// chunk and held for the rest of the group. Without that, a same-size
    /// replacement between two completed chunks passes every per-chunk check
    /// and the group returns the first half of one file joined to the second
    /// half of another.
    #[tokio::test]
    async fn a_group_read_refuses_a_file_replaced_between_its_chunks() {
        let workspace = Workspace::new();
        let total = FILE_CHUNK_BYTES * 2;
        std::fs::write(workspace.0.join("file"), vec![b'a'; total]).unwrap();
        let runtime = WorkspaceRuntime::new(&workspace.0, Some(vec![b'b'; total]));
        let read = runtime
            .get_file_chunks(&sandbox(), workspace.request(0), 2)
            .await;
        assert!(
            matches!(&read, Err(crate::CoreError::Conflict(_))),
            "a group read across a replacement must be refused, got {read:?}"
        );
    }

    /// A group read that sees no change serves every chunk of the file, and
    /// the version it reports is what the next burst of the same artifact has
    /// to present. A file swapped after the group, or after a single pinned
    /// read, is refused rather than continued.
    #[tokio::test]
    async fn a_group_read_serves_a_stable_file_and_pins_the_next_burst() {
        let workspace = Workspace::new();
        let total = FILE_CHUNK_BYTES * 3;
        std::fs::write(workspace.0.join("file"), vec![b'x'; total]).unwrap();
        let runtime = WorkspaceRuntime::new(&workspace.0, None);
        let first = runtime
            .get_file_chunks(&sandbox(), workspace.request(0), 2)
            .await
            .expect("an unchanged file must be served");
        assert_eq!(first.len(), 2);
        assert!(!first.iter().any(|chunk| chunk.eof));
        assert!(
            first
                .iter()
                .all(|chunk| chunk.bytes.len() == FILE_CHUNK_BYTES
                    && chunk.bytes.iter().all(|byte| *byte == b'x')
                    && chunk.size_bytes == total as u64
                    && chunk.version == first[0].version)
        );

        // Between bursts: the caller presents the version the group reported
        // and the file is no longer the file it was read from.
        let mut next = workspace.request((FILE_CHUNK_BYTES * 2) as u64);
        next.expected_version = Some(first[0].version.clone());
        runtime.swap(&vec![b'y'; total]);
        assert!(matches!(
            runtime.get_file_chunks(&sandbox(), next, 2).await,
            Err(crate::CoreError::Conflict(_))
        ));

        // Pre-pinned: the same refusal after a single pinned read rather than
        // after a group, which is how a multi-burst artifact resumes.
        runtime.swap(&vec![b'z'; total]);
        let mut pinned = workspace.request(0);
        pinned.expected_version = Some(first[0].version.clone());
        assert!(matches!(
            runtime.get_file_chunks(&sandbox(), pinned, 3).await,
            Err(crate::CoreError::Conflict(_))
        ));
    }

    impl Drop for Workspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn chunks_accept_inclusive_file_limit_and_eof_offsets() {
        use std::os::unix::fs::FileExt;
        let workspace = Workspace::new();
        let file = std::fs::File::create(workspace.0.join("file")).unwrap();
        let empty = workspace.request(0).read_workspace(&workspace.0).unwrap();
        assert_eq!(empty.size_bytes, 0);
        assert!(empty.bytes.is_empty());
        assert!(empty.eof);
        file.set_len(crate::MAX_FILE as u64).unwrap();
        file.write_all_at(b"last", crate::MAX_FILE as u64 - 4)
            .unwrap();
        let first = workspace.request(0).read_workspace(&workspace.0).unwrap();
        assert_eq!(first.bytes, vec![0; FILE_CHUNK_BYTES]);
        assert_eq!(first.size_bytes, crate::MAX_FILE as u64);
        assert!(!first.eof);
        let mut request = workspace.request(crate::MAX_FILE as u64 - 4);
        request.expected_version = Some(first.version);
        let last = request.read_workspace(&workspace.0).unwrap();
        assert_eq!(last.bytes.as_ref(), b"last");
        assert!(last.eof);
        request.offset = crate::MAX_FILE as u64;
        let end = request.read_workspace(&workspace.0).unwrap();
        assert!(end.bytes.is_empty());
        assert!(end.eof);
        request.offset += 1;
        assert!(matches!(
            request.read_workspace(&workspace.0),
            Err(crate::CoreError::Conflict(_))
        ));
        file.set_len(crate::MAX_FILE as u64 + 1).unwrap();
        assert!(matches!(
            workspace.request(0).read_workspace(&workspace.0),
            Err(crate::CoreError::LimitExceeded(_))
        ));
    }

    #[test]
    fn chunks_reject_replacement_and_mutation_between_reads() {
        let workspace = Workspace::new();
        std::fs::write(workspace.0.join("file"), b"before").unwrap();
        let first = workspace.request(0).read_workspace(&workspace.0).unwrap();
        std::fs::write(workspace.0.join("replacement"), b"after!").unwrap();
        std::fs::rename(workspace.0.join("replacement"), workspace.0.join("file")).unwrap();
        let mut request = workspace.request(3);
        request.expected_version = Some(first.version);
        assert!(matches!(
            request.read_workspace(&workspace.0),
            Err(crate::CoreError::Conflict(_))
        ));
        request.expected_version = None;
        let current = request.read_workspace(&workspace.0).unwrap();
        std::fs::write(workspace.0.join("file"), b"x").unwrap();
        request.expected_version = Some(current.version);
        assert!(matches!(
            request.read_workspace(&workspace.0),
            Err(crate::CoreError::Conflict(_))
        ));
    }

    #[test]
    fn chunks_reject_links_traversal_and_invalid_lengths() {
        let workspace = Workspace::new();
        std::os::unix::fs::symlink("/etc/passwd", workspace.0.join("file")).unwrap();
        assert!(workspace.request(0).read_workspace(&workspace.0).is_err());
        for path in [
            "/workspace/../etc/passwd",
            "/workspace-other/file",
            "/etc/passwd",
        ] {
            let mut request = workspace.request(0);
            request.path = path.into();
            assert!(request.validate().is_err());
        }
        for length in [0, FILE_CHUNK_BYTES + 1, usize::MAX] {
            let mut request = workspace.request(0);
            request.length = length;
            assert!(request.validate().is_err());
        }
        let mut request = workspace.request(0);
        request.path = "/workspace/dir/file".into();
        std::os::unix::fs::symlink("/etc", workspace.0.join("dir")).unwrap();
        assert!(request.read_workspace(&workspace.0).is_err());
    }

    #[test]
    fn guest_chunk_arrays_reject_oversize_and_invalid_byte_values() {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(deserialize_with = "deserialize_file_chunk_bytes")]
            content: Vec<u8>,
        }
        let maximum = serde_json::json!({ "content": vec![255u8; FILE_CHUNK_BYTES] });
        let reply: Wire = serde_json::from_value(maximum).unwrap();
        assert_eq!(reply.content, vec![255u8; FILE_CHUNK_BYTES]);
        assert!(
            serde_json::from_value::<Wire>(
                serde_json::json!({ "content": vec![0u8; FILE_CHUNK_BYTES + 1] })
            )
            .is_err()
        );
        assert!(serde_json::from_str::<Wire>(r#"{"content":[256]}"#).is_err());
        assert!(serde_json::from_str::<Wire>(r#"{"content":"AA=="}"#).is_err());
    }
}

#[cfg(all(test, unix))]
mod file_write_chunk_tests {
    use super::*;

    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("aiec-write-{}", uuid::Uuid::now_v7()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn request(path: &str, offset: u64, size_bytes: u64) -> FileWriteChunkRequest {
        FileWriteChunkRequest {
            path: path.into(),
            offset,
            size_bytes,
            mode: Some(0o700),
        }
    }

    /// Writes a whole file the way the runtime does, one bounded chunk at a
    /// time, and returns what ended up on disk.
    fn upload(root: &Root, path: &str, content: &[u8]) -> std::io::Result<Vec<u8>> {
        let size_bytes = content.len() as u64;
        let mut offset = 0usize;
        while offset < content.len() {
            let end = (offset + FILE_CHUNK_BYTES).min(content.len());
            let chunk = &content[offset..end];
            let mut piece = request(path, offset as u64, size_bytes);
            if end != content.len() {
                piece.mode = None;
            }
            piece
                .write_workspace(root.path(), chunk)
                .expect("chunk write");
            offset = end;
        }
        std::fs::read(root.path().join(path.trim_start_matches("/workspace/")))
    }

    /// The reason this path exists. A static binary is larger than one control
    /// channel frame, and before chunked writes it could not be uploaded at
    /// all: the guest rejected the frame on its declared length and the sender
    /// saw a broken pipe instead of an error. Everything above this line is a
    /// larger-than-one-frame file arriving intact.
    #[test]
    fn a_file_larger_than_one_control_frame_arrives_byte_for_byte() {
        let root = Root::new();
        let content: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        assert!(!write_fits_one_frame("/workspace/big", &content));
        assert_eq!(upload(&root, "/workspace/big", &content).unwrap(), content);
        let on_disk = std::fs::metadata(root.path().join("big")).unwrap().len();
        assert_eq!(on_disk, content.len() as u64);
    }

    /// A caller that declares ten megabytes, sends two and stops must not
    /// produce a file that looks complete. The short-chunk rule is what stops
    /// it: only the final piece of a file may be smaller than the transfer
    /// unit, so a truncated stream is refused at the piece that truncated it.
    #[test]
    fn a_truncated_upload_is_refused_rather_than_completed() {
        let root = Root::new();
        let mut piece = request("/workspace/short", 0, 3 * FILE_CHUNK_BYTES as u64);
        piece.mode = None;
        let error = piece
            .write_workspace(root.path(), &[7u8; 16])
            .expect_err("a short first chunk must be refused");
        assert!(
            error.to_string().contains("final chunk"),
            "unexpected error: {error}"
        );
        assert!(!root.path().join("short").exists());
    }

    /// Uploading over a longer file must leave the declared size, not the
    /// longer size. Otherwise a write reports success and the file keeps bytes
    /// from a previous upload that nobody sent this time.
    #[test]
    fn a_shorter_upload_over_a_longer_file_truncates_the_tail() {
        let root = Root::new();
        upload(
            &root,
            "/workspace/reused",
            &vec![b'a'; 5 * FILE_CHUNK_BYTES],
        )
        .unwrap();
        let shorter: Vec<u8> = vec![b'b'; 100];
        assert_eq!(
            upload(&root, "/workspace/reused", &shorter).unwrap(),
            shorter
        );
        let size = std::fs::metadata(root.path().join("reused")).unwrap().len();
        assert_eq!(size, 100);
    }

    #[test]
    fn a_chunk_write_cannot_escape_the_workspace() {
        let root = Root::new();
        for path in ["/etc/passwd", "/workspace/../etc/passwd", "relative"] {
            assert!(
                request(path, 0, 4)
                    .write_workspace(root.path(), b"xxxx")
                    .is_err(),
                "{path} should be refused"
            );
        }
    }

    /// The mode belongs to the piece that finishes the file. Applying it
    /// earlier would make a still-short file executable while it is being
    /// written, which is exactly the window an attacker with a guest foothold
    /// would run something in.
    #[test]
    fn the_mode_is_applied_once_the_file_is_complete() {
        use std::os::unix::fs::PermissionsExt;
        let root = Root::new();
        let first = request("/workspace/script", 0, 2 * FILE_CHUNK_BYTES as u64);
        first
            .write_workspace(root.path(), &vec![1u8; FILE_CHUNK_BYTES])
            .unwrap();
        let during = std::fs::metadata(root.path().join("script"))
            .unwrap()
            .permissions();
        assert_eq!(
            during.mode() & 0o777,
            0o600,
            "not executable while incomplete"
        );
        let mut last = request(
            "/workspace/script",
            FILE_CHUNK_BYTES as u64,
            2 * FILE_CHUNK_BYTES as u64,
        );
        last.mode = Some(0o755);
        last.write_workspace(root.path(), &vec![1u8; FILE_CHUNK_BYTES])
            .unwrap();
        let after = std::fs::metadata(root.path().join("script"))
            .unwrap()
            .permissions();
        assert_eq!(after.mode() & 0o777, 0o755);
    }

    #[test]
    fn the_single_frame_decision_matches_the_frame_limit() {
        assert!(write_fits_one_frame("/workspace/a", &vec![0u8; 64 * 1024]));
        assert!(!write_fits_one_frame(
            "/workspace/a",
            &vec![0u8; 1024 * 1024]
        ));
        // A long path alone cannot tip a small file over.
        let long_path = format!("/workspace/{}", "d".repeat(300));
        assert!(write_fits_one_frame(&long_path, &[0u8; 16]));
        let too_big = request("/workspace/big", 0, crate::MAX_FILE as u64 + 1);
        assert!(
            too_big
                .write_workspace(std::path::Path::new("/"), b"x")
                .is_err()
        );
    }
}
