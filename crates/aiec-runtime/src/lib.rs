use aiec_core::protocol::{self, Operation, Request, RequestPayload, Response, ResponsePayload};
use aiec_core::{
    network::{NetworkAttachment, NetworkBackend},
    runtime::{RuntimeCapabilities, RuntimeHealth},
    snapshots::{
        CapturedSnapshot, MAX_WORKSPACE_ARCHIVE_BYTES, PortableWorkspaceArchive,
        PortableWorkspaceEntry, SnapshotCapabilities, SnapshotKind, SnapshotMetadata,
        SnapshotProvider, SnapshotRequest,
    },
    *,
};
use aiec_network_linux::LinuxNetworkManager;
use async_trait::async_trait;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::{io::AsyncReadExt, process::Command, sync::Mutex};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("core: {0}")]
    Core(#[from] CoreError),
    #[error("runtime unavailable: {0}")]
    Unavailable(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Json(#[from] serde_json::Error),
    #[error("archive: {0}")]
    Archive(String),
    #[error("guest protocol: {0}")]
    Protocol(#[from] protocol::ProtocolError),
    #[error("Firecracker API: {0}")]
    FirecrackerApi(String),
}

pub use aiec_core::runtime::SandboxRuntime;
mod docker;
pub mod e2b;
pub mod guest_artifact;
pub use docker::DockerRuntime;
pub use e2b::{E2bConfig, E2bRuntime, RuntimePathProvider};

fn into_core(error: RuntimeError) -> CoreError {
    match error {
        RuntimeError::Core(error) => error,
        other => CoreError::Io(std::io::Error::other(other.to_string())),
    }
}

fn bwrap_capabilities() -> RuntimeCapabilities {
    RuntimeCapabilities {
        isolation: aiec_core::runtime::RuntimeIsolation::Process,
        exec: true,
        files: true,
        streaming: false,
        network_policy: true,
        workspace_snapshot: true,
        ..RuntimeCapabilities::default()
    }
}

fn firecracker_capabilities(
    _network: &dyn NetworkBackend,
    artifact: Option<&guest_artifact::GuestArtifact>,
) -> RuntimeCapabilities {
    RuntimeCapabilities {
        isolation: aiec_core::runtime::RuntimeIsolation::MicroVm,
        exec: true,
        files: true,
        streaming: false,
        guest_agent: true,
        full_kernel_isolation: true,
        vm_snapshot: true,
        memory_resume: true,
        network_policy: true,
        pause: true,
        pause_reclaims_resources: false,
        vsock: true,
        coding_guest: artifact.is_some_and(guest_artifact::GuestArtifact::is_coding_guest),
        ..RuntimeCapabilities::default()
    }
}

/// Builds the guest kernel command line.
///
/// With a network attachment the guest interface is configured statically from the
/// subnet the network backend allocated, because the guest has no DHCP server and
/// no in-guest agent involvement before the first vsock call.
fn firecracker_boot_args(network: Option<&NetworkAttachment>) -> String {
    const BASE: &str = "console=ttyS0 reboot=k panic=1 pci=off";
    let Some(attachment) = network else {
        return BASE.to_string();
    };
    let (Some(gateway), true) = (
        attachment.addresses.first(),
        !attachment.guest_addresses.is_empty(),
    ) else {
        return BASE.to_string();
    };
    const NETMASK: &str = "255.255.255.252";
    let mut args = String::from(BASE);
    args.push_str(" net.ifnames=0");
    for address in &attachment.guest_addresses {
        args.push_str(&format!(" ip={address}::{gateway}:{NETMASK}:aiec:eth0:off"));
    }
    args
}

/// A validated development workspace archive suitable for handoff between runtimes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceArchive {
    pub key: String,
    pub bytes: Vec<u8>,
    pub checksum_sha256: String,
}

fn validate_archive_key(key: &str) -> Result<(), RuntimeError> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RuntimeError::Archive(
            "invalid workspace archive key".into(),
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub struct BubblewrapRuntime {
    pub root: PathBuf,
    pub bwrap: PathBuf,
}
impl BubblewrapRuntime {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            bwrap: PathBuf::from("/usr/bin/bwrap"),
        }
    }
    fn path_for(&self, sandbox: &Sandbox, raw: &str) -> Result<PathBuf, RuntimeError> {
        let normalized = safe_path(raw)?;
        let relative = normalized
            .strip_prefix("/workspace")
            .map_err(|_| CoreError::Forbidden("outside workspace".into()))?
            .to_string_lossy()
            .trim_start_matches('/')
            .to_owned();
        Ok(self.base(sandbox).join("workspace").join(relative))
    }
    fn base(&self, sandbox: &Sandbox) -> PathBuf {
        self.root.join(sandbox.id.to_string())
    }
    async fn bounded(
        mut child: tokio::process::Child,
        timeout: u64,
        stdin: Option<String>,
    ) -> Result<ExecResult, RuntimeError> {
        if let Some(data) = stdin {
            use tokio::io::AsyncWriteExt;
            child
                .stdin
                .as_mut()
                .ok_or_else(|| RuntimeError::Unavailable("stdin unavailable".into()))?
                .write_all(data.as_bytes())
                .await?;
        }
        drop(child.stdin.take());
        let started = Instant::now();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("stdout unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("stderr unavailable".into()))?;
        let out_task = tokio::spawn(async move {
            let mut pipe = stdout;
            let mut buf = vec![0; 8192];
            while let Ok(n) = pipe.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if out.len() < MAX_STDOUT {
                    let take = n.min(MAX_STDOUT - out.len());
                    out.extend_from_slice(&buf[..take]);
                }
            }
            Ok::<_, std::io::Error>(out)
        });
        let err_task = tokio::spawn(async move {
            let mut pipe = stderr;
            let mut buf = vec![0; 8192];
            while let Ok(n) = pipe.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if err.len() < MAX_STDERR {
                    let take = n.min(MAX_STDERR - err.len());
                    err.extend_from_slice(&buf[..take]);
                }
            }
            Ok::<_, std::io::Error>(err)
        });
        let status = tokio::time::timeout(Duration::from_secs(timeout), child.wait()).await;
        let timed_out = status.is_err();
        if timed_out {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        let status = status
            .ok()
            .transpose()?
            .ok_or_else(|| RuntimeError::Unavailable("process ended without status".into()))?;
        let out = out_task
            .await
            .map_err(|_| RuntimeError::Unavailable("stdout task failed".into()))??;
        let err = err_task
            .await
            .map_err(|_| RuntimeError::Unavailable("stderr task failed".into()))??;
        let code = status.code().unwrap_or(if timed_out { -124 } else { -1 });
        Ok(ExecResult {
            exit_code: code,
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
            duration_ms: started.elapsed().as_millis() as u64,
            timed_out,
        })
    }
}
impl BubblewrapRuntime {
    async fn create(&self, s: &Sandbox) -> Result<(), RuntimeError> {
        let root = self.base(s);
        if root.exists() {
            return Err(CoreError::Conflict("sandbox path exists".into()).into());
        }
        tokio::fs::create_dir_all(root.join("workspace")).await?;
        tokio::fs::write(root.join("metadata.json"), serde_json::to_vec(s)?).await?;
        Ok(())
    }
    async fn start(&self, _: &Sandbox) -> Result<(), RuntimeError> {
        Ok(())
    }
    async fn stop(&self, _: &Sandbox) -> Result<(), RuntimeError> {
        Ok(())
    }
    async fn exec(&self, s: &Sandbox, r: ExecRequest) -> Result<ExecResult, RuntimeError> {
        validate_exec(&r)?;
        let guest_cwd = match &r.working_directory {
            Some(p) => {
                safe_path(p)?;
                p.clone()
            }
            None => "/workspace".into(),
        };
        let mut cmd = Command::new(&self.bwrap);
        cmd.arg("--die-with-parent")
            .arg("--unshare-pid")
            .arg("--unshare-uts")
            .arg("--unshare-ipc")
            .arg("--unshare-cgroup")
            .arg("--ro-bind")
            .arg("/usr")
            .arg("/usr")
            .arg("--symlink")
            .arg("usr/bin")
            .arg("/bin")
            .arg("--symlink")
            .arg("usr/lib")
            .arg("/lib")
            .arg("--symlink")
            .arg("usr/lib64")
            .arg("/lib64")
            .arg("--ro-bind")
            .arg("/etc/ld.so.cache")
            .arg("/etc/ld.so.cache")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--bind")
            .arg(self.base(s).join("workspace"))
            .arg("/workspace")
            .arg("--chdir")
            .arg(guest_cwd)
            .arg("--setenv")
            .arg("PATH")
            .arg("/usr/local/bin:/usr/bin:/bin")
            .arg("--die-with-parent");
        if !s.network.is_enabled() {
            cmd.arg("--unshare-net");
        }
        for (k, v) in &r.environment {
            if !k.is_empty() && !k.contains('=') && v.len() < 4096 {
                cmd.arg("--setenv").arg(k).arg(v);
            }
        }
        cmd.args(&r.command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        Self::bounded(cmd.spawn()?, r.timeout_seconds, r.stdin).await
    }
    async fn put_file(&self, s: &Sandbox, r: PutFileRequest) -> Result<(), RuntimeError> {
        use base64::Engine;
        let path = self.path_for(s, &r.path)?;
        if let Ok(meta) = tokio::fs::metadata(&path).await
            && meta.is_dir()
        {
            return Err(CoreError::Conflict("path is directory".into()).into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(r.content_base64)
            .map_err(|_| CoreError::InvalidRequest("invalid base64".into()))?;
        if bytes.len() > MAX_FILE {
            return Err(CoreError::LimitExceeded("file".into()).into());
        }
        if let Some(p) = path.parent() {
            tokio::fs::create_dir_all(p).await?;
        }
        tokio::fs::write(&path, bytes).await?;
        if let Some(mode) = r.mode {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(libc::mode_t::from(mode)),
            )
            .await?;
        }
        Ok(())
    }
    async fn get_file(&self, s: &Sandbox, path: &str) -> Result<FileContent, RuntimeError> {
        use base64::Engine;
        let p = self.path_for(s, path)?;
        let meta = tokio::fs::metadata(&p).await?;
        if meta.len() > MAX_FILE as u64 {
            return Err(CoreError::LimitExceeded("file".into()).into());
        }
        let bytes = tokio::fs::read(p).await?;
        Ok(FileContent {
            path: path.into(),
            content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        })
    }
    async fn list_files(&self, s: &Sandbox, path: &str) -> Result<Vec<FileEntry>, RuntimeError> {
        let p = self.path_for(s, path)?;
        let mut rd = tokio::fs::read_dir(p).await?;
        let mut out = vec![];
        while let Some(v) = rd.next_entry().await? {
            let m = v.metadata().await?;
            out.push(FileEntry {
                name: v.file_name().to_string_lossy().into_owned(),
                path: format!(
                    "{}/{}",
                    path.trim_end_matches('/'),
                    v.file_name().to_string_lossy()
                ),
                kind: if m.is_dir() {
                    "directory".into()
                } else {
                    "file".into()
                },
                size: m.len(),
            });
        }
        Ok(out)
    }
    async fn delete_file(&self, s: &Sandbox, path: &str) -> Result<(), RuntimeError> {
        let p = self.path_for(s, path)?;
        match tokio::fs::remove_file(p).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    async fn make_directory(&self, s: &Sandbox, path: &str) -> Result<(), RuntimeError> {
        tokio::fs::create_dir_all(self.path_for(s, path)?).await?;
        Ok(())
    }
    pub async fn snapshot(&self, s: &Sandbox, key: &str) -> Result<u64, RuntimeError> {
        let root = self.base(s).join("workspace");
        let out = self.root.join("snapshots").join(format!("{key}.tar"));
        if let Some(p) = out.parent() {
            tokio::fs::create_dir_all(p).await?;
        }
        let output = Command::new("tar")
            .arg("-cf")
            .arg(&out)
            .arg("-C")
            .arg(&root)
            .arg(".")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await?;
        if !output.status.success() {
            return Err(RuntimeError::Archive(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        Ok(tokio::fs::metadata(out).await?.len())
    }
    pub async fn restore(&self, s: &Sandbox, key: &str) -> Result<(), RuntimeError> {
        let archive = self.root.join("snapshots").join(format!("{key}.tar"));
        let root = self.base(s).join("workspace");
        let output = Command::new("tar")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(&root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await?;
        if !output.status.success() {
            return Err(RuntimeError::Archive(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        Ok(())
    }
    pub async fn export_workspace_snapshot(
        &self,
        sandbox: &Sandbox,
        key: &str,
    ) -> Result<WorkspaceArchive, RuntimeError> {
        validate_archive_key(key)?;
        let size = self.snapshot(sandbox, key).await?;
        if size > MAX_WORKSPACE_ARCHIVE_BYTES as u64 {
            return Err(RuntimeError::Archive(
                "workspace archive exceeds 64 MiB".into(),
            ));
        }
        let bytes = tokio::fs::read(self.root.join("snapshots").join(format!("{key}.tar"))).await?;
        Ok(WorkspaceArchive {
            key: key.to_owned(),
            checksum_sha256: hex::encode(Sha256::digest(&bytes)),
            bytes,
        })
    }

    pub async fn import_workspace_snapshot(
        &self,
        sandbox: &Sandbox,
        archive: &WorkspaceArchive,
    ) -> Result<(), RuntimeError> {
        validate_archive_key(&archive.key)?;
        if archive.bytes.len() > MAX_WORKSPACE_ARCHIVE_BYTES {
            return Err(RuntimeError::Archive(
                "workspace archive exceeds 64 MiB".into(),
            ));
        }
        if hex::encode(Sha256::digest(&archive.bytes)) != archive.checksum_sha256 {
            return Err(RuntimeError::Archive(
                "workspace archive checksum mismatch".into(),
            ));
        }
        let directory = self.root.join("snapshots");
        tokio::fs::create_dir_all(&directory).await?;
        let temporary = directory.join(format!(".{}.import", archive.key));
        tokio::fs::write(&temporary, &archive.bytes).await?;
        tokio::fs::rename(temporary, directory.join(format!("{}.tar", archive.key))).await?;
        self.restore(sandbox, &archive.key).await
    }
    async fn destroy(&self, s: &Sandbox) -> Result<(), RuntimeError> {
        match tokio::fs::remove_dir_all(self.base(s)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    fn health(&self) -> bool {
        self.bwrap.exists()
    }
}

#[async_trait]
impl SandboxRuntime for BubblewrapRuntime {
    async fn create(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::create(self, sandbox).await.map_err(into_core)
    }
    async fn start(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::start(self, sandbox).await.map_err(into_core)
    }
    async fn stop(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::stop(self, sandbox).await.map_err(into_core)
    }
    async fn pause(&self, _sandbox: &Sandbox) -> Result<(), CoreError> {
        Err(CoreError::Unsupported(
            "bubblewrap pause is unsupported".into(),
        ))
    }
    async fn resume(&self, _sandbox: &Sandbox) -> Result<(), CoreError> {
        Err(CoreError::Unsupported(
            "bubblewrap resume is unsupported".into(),
        ))
    }
    async fn exec(&self, sandbox: &Sandbox, request: ExecRequest) -> Result<ExecResult, CoreError> {
        Self::exec(self, sandbox, request).await.map_err(into_core)
    }
    async fn put_file(&self, sandbox: &Sandbox, request: PutFileRequest) -> Result<(), CoreError> {
        Self::put_file(self, sandbox, request)
            .await
            .map_err(into_core)
    }
    async fn get_file(&self, sandbox: &Sandbox, path: &str) -> Result<FileContent, CoreError> {
        Self::get_file(self, sandbox, path).await.map_err(into_core)
    }
    async fn list_files(&self, sandbox: &Sandbox, path: &str) -> Result<Vec<FileEntry>, CoreError> {
        Self::list_files(self, sandbox, path)
            .await
            .map_err(into_core)
    }
    async fn delete_file(
        &self,
        sandbox: &Sandbox,
        request: DeleteFileRequest,
    ) -> Result<(), CoreError> {
        Self::delete_file(self, sandbox, &request.path)
            .await
            .map_err(into_core)
    }
    async fn make_directory(
        &self,
        sandbox: &Sandbox,
        request: MakeDirectoryRequest,
    ) -> Result<(), CoreError> {
        Self::make_directory(self, sandbox, &request.path)
            .await
            .map_err(into_core)
    }
    async fn import_workspace_archive(
        &self,
        sandbox: &Sandbox,
        archive: &[u8],
    ) -> Result<(), CoreError> {
        if archive.len() > MAX_WORKSPACE_ARCHIVE_BYTES {
            return Err(CoreError::LimitExceeded(
                "workspace archive exceeds 64 MiB".into(),
            ));
        }
        // The tar payload is the archive; `import_workspace_snapshot`
        // re-verifies the digest it derives here before unpacking.
        Self::import_workspace_snapshot(
            self,
            sandbox,
            &WorkspaceArchive {
                key: format!("import-{}", sandbox.id),
                checksum_sha256: hex::encode(Sha256::digest(archive)),
                bytes: archive.to_vec(),
            },
        )
        .await
        .map_err(into_core)
    }
    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::destroy(self, sandbox).await.map_err(into_core)
    }
    async fn health(&self) -> RuntimeHealth {
        if Self::health(self) {
            RuntimeHealth::healthy()
        } else {
            RuntimeHealth::unhealthy("bubblewrap executable is unavailable")
        }
    }
    fn capabilities(&self) -> RuntimeCapabilities {
        bwrap_capabilities()
    }
}

#[async_trait]
impl SnapshotProvider for BubblewrapRuntime {
    fn capabilities(&self) -> SnapshotCapabilities {
        SnapshotCapabilities {
            workspace: true,
            cross_instance_restore: true,
            ..SnapshotCapabilities::default()
        }
    }
    async fn capture(
        &self,
        sandbox: &Sandbox,
        request: &SnapshotRequest,
    ) -> Result<CapturedSnapshot, CoreError> {
        if request.kind != SnapshotKind::Workspace {
            return Err(CoreError::Unsupported(
                "bubblewrap supports workspace snapshots only".into(),
            ));
        }
        let archive = Self::export_workspace_snapshot(self, sandbox, &request.object_key)
            .await
            .map_err(into_core)?;
        Ok(CapturedSnapshot::from_archive(
            Uuid::now_v7(),
            request.kind,
            request.object_key.clone(),
            archive.bytes,
        ))
    }
    async fn restore(
        &self,
        sandbox: &Sandbox,
        metadata: &SnapshotMetadata,
    ) -> Result<(), CoreError> {
        Self::restore(self, sandbox, &metadata.object_key)
            .await
            .map_err(into_core)
    }
}

#[derive(Clone, Debug)]
pub struct FirecrackerConfig {
    pub binary: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub jailer: Option<PathBuf>,
    pub tap: Option<String>,
    pub state_dir: PathBuf,
    pub guest_secret: Vec<u8>,
    pub guest_cid: u32,
    pub readiness_timeout: Duration,
    /// Directory holding `guest-capabilities.json`, defaulting to the rootfs directory.
    pub guest_artifact_dir: Option<PathBuf>,
    /// Metadata of the configured guest image, when it was built from repository tooling.
    pub guest_artifact: Option<guest_artifact::GuestArtifact>,
    /// Whether the deployment refuses to start without a verified coding guest image.
    pub require_coding_guest: bool,
}

impl FirecrackerConfig {
    pub fn from_env() -> Result<Self, RuntimeError> {
        let required = |name: &str| {
            std::env::var(name)
                .map_err(|_| RuntimeError::Unavailable(format!("{name} is required")))
        };
        let rootfs = PathBuf::from(required("AIEC_ROOTFS")?);
        let guest_artifact_dir = std::env::var("AIEC_GUEST_ARTIFACT_DIR")
            .ok()
            .map(PathBuf::from)
            .or_else(|| rootfs.parent().map(Path::to_path_buf));
        let guest_artifact = guest_artifact_dir.as_deref().and_then(|dir| {
            let path = dir.join(guest_artifact::GUEST_ARTIFACT_FILE);
            let artifact = guest_artifact::load_guest_artifact(&path);
            match &artifact {
                Ok(artifact) => tracing::info!(
                    path = %path.display(),
                    profile = %artifact.profile,
                    version = %artifact.artifact_version,
                    "loaded firecracker guest artifact metadata"
                ),
                Err(error) => {
                    tracing::debug!(path = %path.display(), %error, "no firecracker guest artifact metadata")
                }
            }
            artifact.ok()
        });
        Ok(Self {
            binary: PathBuf::from(required("AIEC_FIRECRACKER_BIN")?),
            kernel: PathBuf::from(required("AIEC_KERNEL")?),
            rootfs,
            jailer: std::env::var("AIEC_JAILER").ok().map(PathBuf::from),
            tap: std::env::var("AIEC_TAP").ok(),
            state_dir: PathBuf::from(
                std::env::var("AIEC_STATE_DIR").unwrap_or_else(|_| ".aiec/firecracker".into()),
            ),
            guest_secret: required("AIEC_GUEST_SECRET")?.into_bytes(),
            guest_cid: 3,
            readiness_timeout: Duration::from_secs(30),
            guest_artifact_dir,
            guest_artifact,
            require_coding_guest: std::env::var("AIEC_REQUIRE_CODING_GUEST")
                .is_ok_and(|value| value == "1"),
        })
    }

    pub fn check(&self) -> Result<(), RuntimeError> {
        let kvm = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm");
        if !self.binary.is_file() {
            return Err(RuntimeError::Unavailable(
                "Firecracker binary is missing or not executable".into(),
            ));
        }
        if !self.kernel.is_file() {
            return Err(RuntimeError::Unavailable(
                "Firecracker kernel image is missing".into(),
            ));
        }
        if !self.rootfs.is_file() {
            return Err(RuntimeError::Unavailable(
                "Firecracker rootfs image is missing".into(),
            ));
        }
        if self.guest_secret.len() < 32 {
            return Err(RuntimeError::Unavailable(
                "AIEC_GUEST_SECRET must contain at least 32 bytes".into(),
            ));
        }
        // Structural validation only. Hashing a multi-gigabyte rootfs is not a
        // boot-time cost: the control plane calls this on every start, and a
        // worker calls [`Self::verify_guest_image`] before it boots a guest.
        self.check_guest_capabilities()?;
        kvm.map_err(|error| {
            RuntimeError::Unavailable(format!("/dev/kvm is not readable and writable: {error}"))
        })?;
        if let Some(jailer) = &self.jailer
            && !jailer.is_file()
        {
            return Err(RuntimeError::Unavailable(
                "configured jailer is missing".into(),
            ));
        }
        if self.tap.is_some()
            && (which("ip").is_none() || which("nft").is_none() || which("sysctl").is_none())
        {
            return Err(RuntimeError::Unavailable(
                "network isolation requires ip(8), nft and sysctl".into(),
            ));
        }
        Ok(())
    }

    /// Verifies the guest image digest, at most once per process.
    ///
    /// A worker calls this before it boots a guest. The result is cached because
    /// the same image is used for every sandbox on the node and the digest of a
    /// multi-gigabyte rootfs is not cheap to recompute per create.
    pub fn verify_guest_image(&self) -> Result<(), RuntimeError> {
        // Keyed on the artifact's identity, not on the process.
        //
        // This was a bare `OnceLock`: one result for the whole process,
        // whatever was being verified. It happens to be correct today because
        // there is exactly one configured guest image, and it would be silently,
        // dangerously wrong the moment there were two - a worker pointed at a
        // second, unverified image would inherit the first one's verdict, which
        // is precisely the failure the specification names when it says never to
        // skip integrity verification because you checked once "sometime
        // earlier".
        //
        // The key is path, size and mtime for each file that takes part, which
        // is the specification's own example. Replacing a rootfs in place, or
        // pointing the runtime at a different one, misses the cache and is
        // verified again. Nothing is trusted because it was trusted before; it
        // is trusted because *these bytes at these paths* were.
        static VERIFIED: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<String, Result<(), String>>>,
        > = std::sync::OnceLock::new();
        let cache =
            VERIFIED.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));

        let key = match artifact_identity(
            &self.rootfs,
            &self.kernel,
            self.guest_artifact.as_ref(),
            self.require_coding_guest,
        ) {
            Ok(key) => key,
            // If the artifacts cannot be stat'd there is nothing to key on, and
            // the honest response is to verify rather than to guess.
            Err(_error) => {
                return self
                    .check_guest_artifact()
                    .map_err(|error| RuntimeError::Unavailable(error.to_string()));
            }
        };

        if let Ok(entries) = cache.lock()
            && let Some(outcome) = entries.get(&key)
        {
            return match outcome {
                Ok(()) => Ok(()),
                Err(error) => Err(RuntimeError::Unavailable(error.clone())),
            };
        }
        let outcome = self
            .check_guest_artifact()
            .map_err(|error| error.to_string());
        if let Ok(mut entries) = cache.lock() {
            entries.insert(key, outcome.clone());
        }
        match outcome {
            Ok(()) => Ok(()),
            Err(error) => Err(RuntimeError::Unavailable(error)),
        }
    }

    /// Hashes the guest image and compares it with the recorded metadata.
    ///
    /// A deployment without artifact metadata keeps running on whatever image it
    /// was pointed at; a deployment with metadata never runs an image that does
    /// not match it, and a deployment that demands a coding guest never runs a
    /// guest that cannot clone over HTTPS.
    pub fn check_guest_artifact(&self) -> Result<(), RuntimeError> {
        if self.guest_artifact.is_some() {
            let dir = self
                .guest_artifact_dir
                .clone()
                .or_else(|| self.rootfs.parent().map(Path::to_path_buf))
                .ok_or_else(|| {
                    RuntimeError::Unavailable(
                        "guest artifact metadata is loaded but no artifact directory is configured"
                            .into(),
                    )
                })?;
            guest_artifact::verify_guest_artifact(&dir, &self.rootfs, &self.kernel).map_err(
                |error| {
                    RuntimeError::Unavailable(format!(
                        "Firecracker guest artifact is unusable: {error}"
                    ))
                },
            )?;
        }
        self.check_guest_capabilities()
    }

    /// Checks the guest capability requirements without hashing the image.
    ///
    /// The control plane calls this at startup: reading the artifact metadata is
    /// cheap, while hashing a multi-gigabyte rootfs is not something to pay on
    /// every API boot. [`Self::check_guest_artifact`] adds the digest
    /// verification and is the check a worker runs before it boots a guest.
    pub fn check_guest_capabilities(&self) -> Result<(), RuntimeError> {
        if self.require_coding_guest {
            let Some(artifact) = &self.guest_artifact else {
                return Err(RuntimeError::Unavailable(
                    "AIEC_REQUIRE_CODING_GUEST=1 requires guest artifact metadata, but none could be loaded"
                        .into(),
                ));
            };
            if artifact.profile != guest_artifact::CODING_PROFILE {
                return Err(RuntimeError::Unavailable(format!(
                    "AIEC_REQUIRE_CODING_GUEST=1 requires the {} profile, artifact {} declares {}",
                    guest_artifact::CODING_PROFILE,
                    artifact.artifact_version,
                    artifact.profile
                )));
            }
            for required in [
                guest_artifact::CAPABILITY_GIT,
                guest_artifact::CAPABILITY_CA_CERTIFICATES,
            ] {
                if !artifact
                    .capabilities
                    .iter()
                    .any(|capability| capability == required)
                {
                    return Err(RuntimeError::Unavailable(format!(
                        "coding guest artifact {} is missing the {required} capability",
                        artifact.artifact_version
                    )));
                }
            }
        }
        Ok(())
    }

    fn socket_root(&self) -> PathBuf {
        let digest = hex::encode(Sha256::digest(self.state_dir.to_string_lossy().as_bytes()));
        std::env::temp_dir().join("aiec-fc").join(&digest[..16])
    }
    fn socket_dir(&self, id: Uuid) -> PathBuf {
        self.socket_root().join(id.to_string())
    }
    fn vm_dir(&self, id: Uuid) -> PathBuf {
        self.state_dir.join("vms").join(id.to_string())
    }
    fn api_socket(&self, id: Uuid) -> PathBuf {
        self.socket_dir(id).join("api.sock")
    }
    fn vsock_socket(&self, id: Uuid) -> PathBuf {
        self.socket_dir(id).join("vsock.sock")
    }
    fn rootfs(&self, id: Uuid) -> PathBuf {
        self.vm_dir(id).join("rootfs.ext4")
    }
    fn snapshot_dir(&self, key: &str) -> PathBuf {
        let digest = hex::encode(Sha256::digest(key.as_bytes()));
        self.state_dir.join("snapshots").join(digest)
    }
}

struct FirecrackerVm {
    child: tokio::process::Child,
    api_socket: PathBuf,
    network: Option<NetworkAttachment>,
    vsock_socket: PathBuf,
    rootfs: PathBuf,
    start_token: Uuid,
}

#[derive(Clone)]
pub struct FirecrackerRuntime {
    pub config: FirecrackerConfig,
    vms: Arc<Mutex<HashMap<Uuid, FirecrackerVm>>>,
    network: Arc<dyn NetworkBackend>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct LocalReconciliationReport {
    /// Worker identity used to establish ownership.
    pub owner_id: Uuid,
    /// Number of VM directories inspected.
    pub scanned: usize,
    /// Number of directories carrying this worker's owner marker.
    pub owned: usize,
    /// Owned directories with no live API socket; reported, never killed.
    pub orphan_candidates: Vec<Uuid>,
}

/// Identity of the artifacts a verification result is valid for.
///
/// Path alone is not enough - a rootfs can be replaced at the same path - and a
/// process-wide result is not enough at all. Size and mtime together catch the
/// replacement that matters: an image swapped for a different one is a
/// different length, and an image rewritten in place moves its mtime.
fn artifact_identity(
    rootfs: &Path,
    kernel: &Path,
    artifact: Option<&guest_artifact::GuestArtifact>,
    require_coding_guest: bool,
) -> std::io::Result<String> {
    let describe = |path: &Path| -> std::io::Result<String> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        Ok(format!(
            "{}:{}:{}",
            path.display(),
            meta.size(),
            meta.mtime()
        ))
    };
    // The whole artifact metadata, serialised, plus the flag derived from it.
    //
    // Listing fields by hand is how the previous version was wrong: a key built
    // from the ones I thought of looked complete and was not, because the check
    // also consults `require_coding_guest`, and a lax configuration's success
    // would satisfy a strict one. Serialising the input means a field added to
    // the check later is in the key the day it is added, rather than on the day
    // somebody remembers.
    let identity = serde_json::to_string(&artifact).unwrap_or_else(|_| "unserialisable".into());
    Ok(format!(
        "{}|{}|coding={require_coding_guest}|{identity}",
        describe(rootfs)?,
        describe(kernel)?,
    ))
}

impl FirecrackerRuntime {
    pub fn new(config: FirecrackerConfig) -> Self {
        Self::with_network_backend(config, Arc::new(LinuxNetworkManager::new()))
    }

    pub fn with_network_backend(
        config: FirecrackerConfig,
        network: Arc<dyn NetworkBackend>,
    ) -> Self {
        Self {
            config,
            vms: Arc::new(Mutex::new(HashMap::new())),
            network,
        }
    }

    /// Records this worker's ownership of a VM directory without touching
    /// another worker's state. Ownership is explicit and durable.
    pub fn claim_local_vm(&self, sandbox_id: Uuid, owner_id: Uuid) -> Result<(), RuntimeError> {
        let dir = self.config.vm_dir(sandbox_id);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("owner.json"), owner_id.to_string())?;
        Ok(())
    }

    /// Reports only VM directories explicitly owned by `owner_id`. Missing API
    /// sockets are candidates for operator review; this method never kills or
    /// deletes a process or directory.
    pub fn reconcile_local(
        &self,
        owner_id: Uuid,
    ) -> Result<LocalReconciliationReport, RuntimeError> {
        let root = self.config.state_dir.join("vms");
        let mut report = LocalReconciliationReport {
            owner_id,
            ..LocalReconciliationReport::default()
        };
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            report.scanned += 1;
            let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|name| Uuid::parse_str(name).ok())
            else {
                continue;
            };
            let owner = std::fs::read_to_string(entry.path().join("owner.json"))
                .ok()
                .and_then(|value| Uuid::parse_str(value.trim()).ok());
            if owner != Some(owner_id) {
                continue;
            }
            report.owned += 1;
            if !self.config.api_socket(id).exists() {
                report.orphan_candidates.push(id);
            }
        }
        report.orphan_candidates.sort_unstable();
        Ok(report)
    }

    async fn api(
        &self,
        socket: &Path,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(), RuntimeError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match tokio::net::UnixStream::connect(socket).await {
                Ok(stream) => break stream,
                Err(error) if tokio::time::Instant::now() < deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => {
                    return Err(RuntimeError::FirecrackerApi(format!(
                        "connect {}: {error}",
                        socket.display()
                    )));
                }
            }
        };
        let body = body.map(|value| serde_json::to_vec(&value)).transpose()?;
        let body = body.unwrap_or_default();
        let request = format!(
            "{method} http://localhost{path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(&body).await?;
        let mut header = Vec::new();
        let mut byte = [0u8; 1];
        while !header.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await? == 0 {
                return Err(RuntimeError::FirecrackerApi(
                    "API closed before response headers".into(),
                ));
            }
            header.push(byte[0]);
            if header.len() > 64 * 1024 {
                return Err(RuntimeError::FirecrackerApi(
                    "API response headers too large".into(),
                ));
            }
        }
        let header_text = String::from_utf8_lossy(&header);
        let status = header_text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| RuntimeError::FirecrackerApi("malformed API response".into()))?;
        let content_length = header_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let mut response_body = vec![0; content_length];
        stream.read_exact(&mut response_body).await?;
        if !(200..300).contains(&status) {
            return Err(RuntimeError::FirecrackerApi(format!(
                "{method} {path} returned {status}: {}",
                String::from_utf8_lossy(&response_body)
            )));
        }
        Ok(())
    }

    async fn connect_guest(&self, id: Uuid) -> Result<tokio::net::UnixStream, RuntimeError> {
        let path = self.config.vsock_socket(id);
        let deadline = tokio::time::Instant::now() + self.config.readiness_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(RuntimeError::Unavailable(
                    "guest vsock readiness timed out".into(),
                ));
            }
            match tokio::time::timeout(remaining, tokio::net::UnixStream::connect(&path)).await {
                Ok(Ok(mut stream)) => {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(RuntimeError::Unavailable(
                            "guest vsock CONNECT timed out".into(),
                        ));
                    }
                    // Firecracker's vsock UDS accepts connections as soon as the
                    // device exists, which is before the guest agent has bound
                    // the control port. An early CONNECT is therefore expected to
                    // fail, so every handshake failure retries against the same
                    // readiness deadline as a failed connect.
                    let connect = format!("CONNECT {}\n", protocol::DEFAULT_CONTROL_PORT);
                    let write =
                        tokio::time::timeout(remaining, stream.write_all(connect.as_bytes()))
                            .await
                            .map_err(|_| {
                                RuntimeError::Unavailable("guest vsock CONNECT timed out".into())
                            });
                    if let Ok(Ok(())) = write {
                        let mut reader = BufReader::new(stream);
                        let mut line = String::new();
                        let reply =
                            tokio::time::timeout(remaining, reader.read_line(&mut line)).await;
                        if let Ok(Ok(_)) = reply
                            && line.starts_with("OK ")
                        {
                            return Ok(reader.into_inner());
                        }
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(RuntimeError::Unavailable(format!(
                            "guest vsock CONNECT was still refused after {:?}",
                            self.config.readiness_timeout
                        )));
                    }
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if !remaining.is_zero() {
                        let _ = tokio::time::timeout(
                            remaining,
                            tokio::time::sleep(Duration::from_millis(50)),
                        )
                        .await;
                    }
                }
                Ok(Err(error)) if tokio::time::Instant::now() < deadline => {
                    let _ = error;
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if !remaining.is_zero() {
                        let _ = tokio::time::timeout(
                            remaining,
                            tokio::time::sleep(Duration::from_millis(50)),
                        )
                        .await;
                    }
                }
                Ok(Err(error)) => {
                    return Err(RuntimeError::Unavailable(format!(
                        "guest vsock readiness failed: {error}"
                    )));
                }
                Err(_) => {
                    return Err(RuntimeError::Unavailable(
                        "guest vsock readiness timed out".into(),
                    ));
                }
            }
        }
    }

    fn guest_call_timeout(&self, request: &Request) -> Duration {
        let timeout = match (&request.operation, &request.payload) {
            (Operation::Exec, RequestPayload::Exec { timeout_ms, .. }) => {
                Duration::from_millis(timeout_ms.saturating_add(5_000))
            }
            _ => self.config.readiness_timeout,
        };
        timeout.max(self.config.readiness_timeout)
    }

    fn fresh_request(operation: Operation, payload: RequestPayload) -> Request {
        Request {
            version: protocol::PROTOCOL_VERSION,
            request_id: Uuid::now_v7(),
            operation,
            payload,
        }
    }

    async fn guest_call_inner(
        &self,
        id: Uuid,
        request: Request,
    ) -> Result<ResponsePayload, RuntimeError> {
        let mut stream = self.connect_guest(id).await?;
        let body = serde_json::to_vec(&request)?;
        let frame = frame_bytes(&self.config.guest_secret, &body);
        let remaining = self.guest_call_timeout(&request);
        match tokio::time::timeout(remaining, stream.write_all(&frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                return Err(RuntimeError::Unavailable(
                    "guest vsock write timed out".into(),
                ));
            }
        }
        let response = match tokio::time::timeout(
            remaining,
            read_frame_async(&mut stream, &self.config.guest_secret),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(RuntimeError::Unavailable(
                    "guest vsock read timed out".into(),
                ));
            }
        };
        let response: Response = serde_json::from_slice(&response)?;
        if response.request_id != request.request_id {
            return Err(RuntimeError::Protocol(protocol::ProtocolError::Malformed(
                "request id mismatch".into(),
            )));
        }
        match response.payload {
            ResponsePayload::Error { message, .. } => Err(RuntimeError::Unavailable(message)),
            payload => Ok(payload),
        }
    }

    async fn guest_call(
        &self,
        id: Uuid,
        operation: Operation,
        payload: RequestPayload,
    ) -> Result<ResponsePayload, RuntimeError> {
        let request = Self::fresh_request(operation, payload);
        match tokio::time::timeout(
            self.guest_call_timeout(&request),
            self.guest_call_inner(id, request),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(RuntimeError::Unavailable(
                "guest vsock call timed out".into(),
            )),
        }
    }

    async fn spawn(&self, id: Uuid) -> Result<FirecrackerVm, RuntimeError> {
        let dir = self.config.vm_dir(id);
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::create_dir_all(self.config.socket_dir(id)).await?;
        let api_socket = self.config.api_socket(id);
        let vsock_socket = self.config.vsock_socket(id);
        let mut command = if let Some(jailer) = &self.config.jailer {
            let mut value = Command::new(jailer);
            value
                .arg("--id")
                .arg(id.to_string())
                .arg("--exec-file")
                .arg(&self.config.binary)
                .arg("--")
                .arg("--api-sock")
                .arg(&api_socket);
            value
        } else {
            let mut value = Command::new(&self.config.binary);
            value.arg("--api-sock").arg(&api_socket);
            value
        };
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("firecracker.log"))?;
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()?;
        Ok(FirecrackerVm {
            child,
            api_socket,
            vsock_socket,
            network: None,
            rootfs: self.config.rootfs(id),
            start_token: Uuid::now_v7(),
        })
    }

    async fn configure_and_start(
        &self,
        sandbox: &Sandbox,
        vm: &mut FirecrackerVm,
    ) -> Result<(), RuntimeError> {
        vm.network = if sandbox.network.is_enabled() {
            Some(self.network.prepare(sandbox, &sandbox.network).await?)
        } else {
            None
        };
        if let Some(network) = &vm.network {
            self.api(&vm.api_socket, "PUT", "/network-interfaces/eth0", Some(serde_json::json!({"iface_id":"eth0", "guest_mac":"06:00:AC:10:00:02", "host_dev_name":network.resource}))).await?;
        }
        self.api(&vm.api_socket, "PUT", "/boot-source", Some(serde_json::json!({"kernel_image_path": self.config.kernel, "boot_args": firecracker_boot_args(vm.network.as_ref())}))).await?;
        self.api(&vm.api_socket, "PUT", "/drives/rootfs", Some(serde_json::json!({"drive_id":"rootfs", "path_on_host":vm.rootfs, "is_root_device":true, "is_read_only":false}))).await?;
        self.api(&vm.api_socket, "PUT", "/machine-config", Some(serde_json::json!({"vcpu_count":sandbox.cpu, "mem_size_mib":sandbox.memory_mb, "smt":false}))).await?;
        self.api(
            &vm.api_socket,
            "PUT",
            "/vsock",
            Some(
                serde_json::json!({"guest_cid":self.config.guest_cid, "uds_path":vm.vsock_socket}),
            ),
        )
        .await?;
        self.api(
            &vm.api_socket,
            "PUT",
            "/actions",
            Some(serde_json::json!({"action_type":"InstanceStart"})),
        )
        .await?;
        let deadline = tokio::time::Instant::now() + self.config.readiness_timeout;
        loop {
            match self
                .guest_call(sandbox.id, Operation::Health, RequestPayload::None)
                .await
            {
                Ok(ResponsePayload::Health { ready: true }) => return Ok(()),
                Ok(_) => {}
                Err(error) if tokio::time::Instant::now() < deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn schedule_lifetime(&self, sandbox: &Sandbox, token: Uuid) {
        let runtime = self.clone();
        let lifetime = sandbox.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(lifetime.timeout_seconds)).await;
            runtime.stop_if_token(&lifetime, token).await;
        });
    }

    async fn terminate_vm(&self, sandbox: &Sandbox, mut vm: FirecrackerVm) {
        let _ = self
            .guest_call(sandbox.id, Operation::Shutdown, RequestPayload::None)
            .await;
        let _ = vm.child.start_kill();
        let _ = vm.child.wait().await;
        if let Some(network) = &vm.network {
            let _ = self.network.release(sandbox, network).await;
        }
    }

    async fn stop_if_token(&self, sandbox: &Sandbox, token: Uuid) {
        let vm = {
            let mut vms = self.vms.lock().await;
            if vms.get(&sandbox.id).map(|vm| vm.start_token) != Some(token) {
                return;
            }
            vms.remove(&sandbox.id)
        };
        if let Some(vm) = vm {
            self.terminate_vm(sandbox, vm).await;
        }
    }
}

fn frame_bytes(secret: &[u8], body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42 + body.len());
    frame.extend_from_slice(b"AFG1");
    frame.extend_from_slice(&protocol::PROTOCOL_VERSION.to_be_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protocol::auth_tag(
        secret,
        protocol::PROTOCOL_VERSION,
        body,
    ));
    frame.extend_from_slice(body);
    frame
}

async fn read_frame_async<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    secret: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let mut header = [0u8; 42];
    reader.read_exact(&mut header).await?;
    if &header[..4] != b"AFG1" {
        return Err(protocol::ProtocolError::Malformed("bad magic".into()).into());
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != protocol::PROTOCOL_VERSION {
        return Err(protocol::ProtocolError::Version(version).into());
    }
    let length = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if length > protocol::MAX_FRAME {
        return Err(protocol::ProtocolError::TooLarge(length).into());
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    let expected = &header[10..42];
    let actual = protocol::auth_tag(secret, version, &body);
    let difference = expected
        .iter()
        .zip(actual.iter())
        .fold(0u8, |sum, (left, right)| sum | (left ^ right));
    if difference != 0 {
        return Err(protocol::ProtocolError::Authentication.into());
    }
    Ok(body)
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|path| path.join(program))
            .find(|path| path.is_file())
    })
}

impl FirecrackerRuntime {
    async fn create(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        let started = Instant::now();
        tracing::info!(sandbox_id = %sandbox.id, runtime = "firecracker", stage = "create_begin", "firecracker create started");
        self.config.check()?;
        // The guest image is verified once at worker startup, not per create:
        // a worker that cannot verify its image must fail to start rather than
        // fail its first sandbox, and hashing the image on the request path
        // would blow the control plane's client timeout.
        let dir = self.config.vm_dir(sandbox.id);
        tokio::fs::create_dir_all(&dir).await?;
        if let Some(owner_id) = sandbox.node_id {
            tokio::fs::write(dir.join("owner.json"), owner_id.to_string()).await?;
        }
        let destination = self.config.rootfs(sandbox.id);
        let copy_started = Instant::now();
        tracing::info!(sandbox_id = %sandbox.id, source = %self.config.rootfs.display(), destination = %destination.display(), stage = "rootfs_copy_begin", "firecracker rootfs copy started");
        let copied = tokio::time::timeout(
            Duration::from_secs(120),
            tokio::fs::copy(&self.config.rootfs, &destination),
        )
        .await
        .map_err(|_| RuntimeError::Unavailable("Firecracker rootfs copy timed out".into()))??;
        tracing::info!(sandbox_id = %sandbox.id, bytes = copied, elapsed_ms = copy_started.elapsed().as_millis() as u64, stage = "rootfs_copy_done", "firecracker rootfs copy completed");
        let requested = (sandbox.disk_mb as u64) * 1024 * 1024;
        let current = tokio::fs::metadata(&self.config.rootfs).await?.len();
        if requested < current {
            let status = Command::new("e2fsck")
                .arg("-f")
                .arg("-y")
                .arg(&destination)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await?;
            if !matches!(status.code(), Some(0) | Some(1)) {
                return Err(RuntimeError::Unavailable(
                    "copied rootfs failed filesystem check before shrink".into(),
                ));
            }
            let output = Command::new("resize2fs")
                .arg(&destination)
                .arg(format!("{}M", sandbox.disk_mb))
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .await?;
            if !output.status.success() {
                return Err(RuntimeError::Unavailable(format!(
                    "rootfs could not be resized to requested disk limit: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        } else if requested > current {
            let file = std::fs::OpenOptions::new().write(true).open(&destination)?;
            file.set_len(requested)?;
            let status = Command::new("resize2fs")
                .arg(&destination)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .status()
                .await?;
            if !status.success() {
                return Err(RuntimeError::Unavailable(
                    "rootfs could not grow to requested disk limit".into(),
                ));
            }
        }
        tracing::info!(sandbox_id = %sandbox.id, elapsed_ms = started.elapsed().as_millis() as u64, stage = "create_done", "firecracker create completed");
        Ok(())
    }

    async fn start(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        self.config.check()?;
        let mut vm = self.spawn(sandbox.id).await?;
        if let Err(error) = self.configure_and_start(sandbox, &mut vm).await {
            if let Some(network) = &vm.network {
                let _ = self.network.release(sandbox, network).await;
            }
            let _ = vm.child.start_kill();
            let _ = vm.child.wait().await;
            return Err(error);
        }
        let token = vm.start_token;
        self.vms.lock().await.insert(sandbox.id, vm);
        self.schedule_lifetime(sandbox, token);
        Ok(())
    }

    async fn stop(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        let vm = self.vms.lock().await.remove(&sandbox.id);
        if let Some(vm) = vm {
            self.terminate_vm(sandbox, vm).await;
        }
        Ok(())
    }
    async fn pause(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        let socket = self
            .vms
            .lock()
            .await
            .get(&sandbox.id)
            .map(|vm| vm.api_socket.clone())
            .ok_or_else(|| RuntimeError::Unavailable("sandbox VM is not running".into()))?;
        self.api(
            &socket,
            "PATCH",
            "/vm",
            Some(serde_json::json!({"state":"Paused"})),
        )
        .await
    }
    async fn resume(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        let socket = self
            .vms
            .lock()
            .await
            .get(&sandbox.id)
            .map(|vm| vm.api_socket.clone())
            .ok_or_else(|| RuntimeError::Unavailable("sandbox VM is not running".into()))?;
        self.api(
            &socket,
            "PATCH",
            "/vm",
            Some(serde_json::json!({"state":"Resumed"})),
        )
        .await
    }

    async fn exec(
        &self,
        sandbox: &Sandbox,
        request: ExecRequest,
    ) -> Result<ExecResult, RuntimeError> {
        validate_exec(&request)?;
        let payload = self
            .guest_call(
                sandbox.id,
                Operation::Exec,
                RequestPayload::Exec {
                    argv: request.command,
                    cwd: request.working_directory,
                    env: request.environment,
                    timeout_ms: request.timeout_seconds.saturating_mul(1000),
                    output_limit: MAX_STDOUT.min(MAX_STDERR),
                    stdin: request.stdin.unwrap_or_default().into_bytes(),
                },
            )
            .await?;
        match payload {
            ResponsePayload::Exec {
                exit_code,
                stdout,
                stderr,
                duration_ms,
                timed_out,
            } => Ok(ExecResult {
                exit_code,
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
                duration_ms,
                timed_out,
            }),
            _ => Err(RuntimeError::Unavailable(
                "guest returned wrong exec response".into(),
            )),
        }
    }

    async fn put_file(
        &self,
        sandbox: &Sandbox,
        request: PutFileRequest,
    ) -> Result<(), RuntimeError> {
        use base64::Engine;
        let content = base64::engine::general_purpose::STANDARD
            .decode(request.content_base64)
            .map_err(|_| CoreError::InvalidRequest("invalid base64".into()))?;
        if content.len() > MAX_FILE {
            return Err(CoreError::LimitExceeded("file".into()).into());
        }
        self.guest_call(
            sandbox.id,
            Operation::WriteFile,
            RequestPayload::WriteFile {
                path: request.path,
                content,
                mode: request.mode,
            },
        )
        .await?;
        Ok(())
    }

    async fn get_file(&self, sandbox: &Sandbox, path: &str) -> Result<FileContent, RuntimeError> {
        match self
            .guest_call(
                sandbox.id,
                Operation::ReadFile,
                RequestPayload::Path { path: path.into() },
            )
            .await?
        {
            ResponsePayload::ReadFile { content } => {
                use base64::Engine;
                Ok(FileContent {
                    path: path.into(),
                    content_base64: base64::engine::general_purpose::STANDARD.encode(content),
                })
            }
            _ => Err(RuntimeError::Unavailable(
                "guest returned wrong file response".into(),
            )),
        }
    }

    async fn list_files(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<Vec<FileEntry>, RuntimeError> {
        match self
            .guest_call(
                sandbox.id,
                Operation::ListDirectory,
                RequestPayload::Path { path: path.into() },
            )
            .await?
        {
            ResponsePayload::ListDirectory { entries } => Ok(entries
                .into_iter()
                .map(|entry| FileEntry {
                    name: entry.name,
                    path: entry.path,
                    kind: match entry.kind {
                        protocol::FileKind::Directory => "directory".into(),
                        protocol::FileKind::File => "file".into(),
                    },
                    size: entry.size,
                })
                .collect()),
            _ => Err(RuntimeError::Unavailable(
                "guest returned wrong directory response".into(),
            )),
        }
    }

    async fn delete_file(&self, sandbox: &Sandbox, path: &str) -> Result<(), RuntimeError> {
        self.guest_call(
            sandbox.id,
            Operation::RemoveFile,
            RequestPayload::Path { path: path.into() },
        )
        .await?;
        Ok(())
    }
    async fn make_directory(&self, sandbox: &Sandbox, path: &str) -> Result<(), RuntimeError> {
        self.guest_call(
            sandbox.id,
            Operation::CreateDirectory,
            RequestPayload::Path { path: path.into() },
        )
        .await?;
        Ok(())
    }

    async fn export_workspace(&self, sandbox: &Sandbox, key: &str) -> Result<u64, RuntimeError> {
        let mut entries = Vec::new();
        let mut pending = vec!["/workspace".to_owned()];
        let mut total = 0_u64;
        while let Some(path) = pending.pop() {
            let response = self
                .guest_call(
                    sandbox.id,
                    Operation::ListDirectory,
                    RequestPayload::Path { path: path.clone() },
                )
                .await?;
            let ResponsePayload::ListDirectory { entries: children } = response else {
                return Err(RuntimeError::Unavailable(
                    "guest returned wrong directory response".into(),
                ));
            };
            for child in children {
                if child.kind == protocol::FileKind::Directory {
                    entries.push(PortableWorkspaceEntry {
                        path: child.path.clone(),
                        directory: true,
                        content_base64: String::new(),
                    });
                    pending.push(child.path);
                } else {
                    let response = self
                        .guest_call(
                            sandbox.id,
                            Operation::ReadFile,
                            RequestPayload::Path {
                                path: child.path.clone(),
                            },
                        )
                        .await?;
                    let ResponsePayload::ReadFile { content } = response else {
                        return Err(RuntimeError::Unavailable(
                            "guest returned wrong file response".into(),
                        ));
                    };
                    total = total.checked_add(content.len() as u64).ok_or_else(|| {
                        RuntimeError::Archive("workspace snapshot size overflow".into())
                    })?;
                    if total > MAX_WORKSPACE_ARCHIVE_BYTES as u64 {
                        return Err(RuntimeError::Archive(
                            "workspace snapshot exceeds 64 MiB".into(),
                        ));
                    }
                    entries.push(PortableWorkspaceEntry {
                        path: child.path,
                        directory: false,
                        content_base64: base64::engine::general_purpose::STANDARD.encode(content),
                    });
                }
                if entries.len() > 10_000 {
                    return Err(RuntimeError::Archive(
                        "workspace snapshot has too many members".into(),
                    ));
                }
            }
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let bytes = serde_json::to_vec(&PortableWorkspaceArchive {
            version: 1,
            entries,
        })?;
        let destination = self.config.snapshot_dir(key);
        tokio::fs::create_dir_all(&destination).await?;
        tokio::fs::write(destination.join("workspace.json"), &bytes).await?;
        Ok(bytes.len() as u64)
    }

    async fn import_workspace(&self, sandbox: &Sandbox, key: &str) -> Result<(), RuntimeError> {
        let source = self.config.snapshot_dir(key).join("workspace.json");
        let bytes = tokio::fs::read(source).await?;
        let archive: PortableWorkspaceArchive = serde_json::from_slice(&bytes)?;
        if archive.version != 1 || archive.entries.len() > 10_000 {
            return Err(RuntimeError::Archive(
                "invalid portable workspace archive".into(),
            ));
        }
        for entry in archive.entries {
            if !entry.path.starts_with("/workspace/")
                || entry.path.split('/').any(|part| part == "..")
            {
                return Err(RuntimeError::Archive(
                    "invalid portable workspace path".into(),
                ));
            }
            if entry.directory {
                self.guest_call(
                    sandbox.id,
                    Operation::CreateDirectory,
                    RequestPayload::Path { path: entry.path },
                )
                .await?;
            } else {
                let content = base64::engine::general_purpose::STANDARD
                    .decode(entry.content_base64)
                    .map_err(|_| {
                        RuntimeError::Archive("invalid portable workspace encoding".into())
                    })?;
                if content.len() > MAX_FILE {
                    return Err(RuntimeError::Archive(
                        "portable workspace file is too large".into(),
                    ));
                }
                self.guest_call(
                    sandbox.id,
                    Operation::WriteFile,
                    RequestPayload::WriteFile {
                        path: entry.path,
                        content,
                        mode: None,
                    },
                )
                .await?;
            }
        }
        Ok(())
    }
    pub async fn export_workspace_archive(
        &self,
        sandbox: &Sandbox,
    ) -> Result<Vec<u8>, RuntimeError> {
        let mut entries = Vec::new();
        let mut pending = vec!["/workspace".to_owned()];
        let mut total = 0_u64;
        while let Some(path) = pending.pop() {
            let response = self
                .guest_call(
                    sandbox.id,
                    Operation::ListDirectory,
                    RequestPayload::Path { path: path.clone() },
                )
                .await?;
            let ResponsePayload::ListDirectory { entries: children } = response else {
                return Err(RuntimeError::Unavailable(
                    "guest returned wrong directory response".into(),
                ));
            };
            for child in children {
                if child.kind == protocol::FileKind::Directory {
                    entries.push(PortableWorkspaceEntry {
                        path: child.path.clone(),
                        directory: true,
                        content_base64: String::new(),
                    });
                    pending.push(child.path);
                } else {
                    let response = self
                        .guest_call(
                            sandbox.id,
                            Operation::ReadFile,
                            RequestPayload::Path {
                                path: child.path.clone(),
                            },
                        )
                        .await?;
                    let ResponsePayload::ReadFile { content } = response else {
                        return Err(RuntimeError::Unavailable(
                            "guest returned wrong file response".into(),
                        ));
                    };
                    total = total.checked_add(content.len() as u64).ok_or_else(|| {
                        RuntimeError::Archive("workspace snapshot size overflow".into())
                    })?;
                    if total > MAX_WORKSPACE_ARCHIVE_BYTES as u64 {
                        return Err(RuntimeError::Archive(
                            "workspace snapshot exceeds 64 MiB".into(),
                        ));
                    }
                    entries.push(PortableWorkspaceEntry {
                        path: child.path,
                        directory: false,
                        content_base64: base64::engine::general_purpose::STANDARD.encode(content),
                    });
                }
                if entries.len() > 10_000 {
                    return Err(RuntimeError::Archive(
                        "workspace snapshot has too many members".into(),
                    ));
                }
            }
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        serde_json::to_vec(&PortableWorkspaceArchive {
            version: 1,
            entries,
        })
        .map_err(RuntimeError::Json)
    }

    pub async fn import_workspace_archive(
        &self,
        sandbox: &Sandbox,
        bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        let archive: PortableWorkspaceArchive = serde_json::from_slice(bytes)?;
        if archive.version != 1 || archive.entries.len() > 10_000 {
            return Err(RuntimeError::Archive(
                "invalid portable workspace archive".into(),
            ));
        }
        let mut total = 0_u64;
        for entry in archive.entries {
            let Some(relative) = entry.path.strip_prefix("/workspace/") else {
                return Err(RuntimeError::Archive(
                    "invalid portable workspace path".into(),
                ));
            };
            if relative.is_empty()
                || Path::new(relative)
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(RuntimeError::Archive(
                    "invalid portable workspace path".into(),
                ));
            }
            if entry.directory {
                self.guest_call(
                    sandbox.id,
                    Operation::CreateDirectory,
                    RequestPayload::Path { path: entry.path },
                )
                .await?;
            } else {
                let content = base64::engine::general_purpose::STANDARD
                    .decode(entry.content_base64)
                    .map_err(|_| {
                        RuntimeError::Archive("invalid portable workspace encoding".into())
                    })?;
                total = total.checked_add(content.len() as u64).ok_or_else(|| {
                    RuntimeError::Archive("workspace snapshot size overflow".into())
                })?;
                if total > MAX_WORKSPACE_ARCHIVE_BYTES as u64 {
                    return Err(RuntimeError::Archive(
                        "workspace snapshot exceeds 64 MiB".into(),
                    ));
                }
                self.guest_call(
                    sandbox.id,
                    Operation::WriteFile,
                    RequestPayload::WriteFile {
                        path: entry.path,
                        content,
                        mode: None,
                    },
                )
                .await?;
            }
        }
        Ok(())
    }

    pub async fn snapshot(&self, sandbox: &Sandbox, key: &str) -> Result<u64, RuntimeError> {
        self.guest_call(sandbox.id, Operation::PrepareSnapshot, RequestPayload::None)
            .await?;
        let vms = self.vms.lock().await;
        let (socket, source_disk) = {
            let vm = vms
                .get(&sandbox.id)
                .ok_or_else(|| RuntimeError::Unavailable("sandbox VM is not running".into()))?;
            (vm.api_socket.clone(), vm.rootfs.clone())
        };
        drop(vms);
        let pause = self
            .api(
                &socket,
                "PATCH",
                "/vm",
                Some(serde_json::json!({"state":"Paused"})),
            )
            .await;
        if let Err(error) = pause {
            let _ = self
                .api(
                    &socket,
                    "PATCH",
                    "/vm",
                    Some(serde_json::json!({"state":"Resumed"})),
                )
                .await;
            return Err(error);
        }
        let snapshot_result: Result<u64, RuntimeError> = async {
            let destination = self.config.snapshot_dir(key);
            tokio::fs::create_dir_all(&destination).await?;
            let state = destination.join("vmstate");
            let memory = destination.join("memory");
            self.api(
                &socket,
                "PUT",
                "/snapshot/create",
                Some(serde_json::json!({"snapshot_type":"Full", "snapshot_path":&state, "mem_file_path":&memory, "sync_snapshot_files":true})),
            )
            .await?;
            let snapshot_disk = destination.join("rootfs.ext4");
            tokio::fs::copy(&source_disk, &snapshot_disk).await?;
            let manifest = serde_json::json!({
                "schema": 1,
                "source_disk": source_disk,
                "rootfs_sha256": hex::encode(Sha256::digest(tokio::fs::read(&snapshot_disk).await?)),
            });
            tokio::fs::write(
                destination.join("manifest.json"),
                serde_json::to_vec(&manifest)?,
            )
            .await?;
            let mut size = 0;
            for file in [state, memory, snapshot_disk] {
                size += tokio::fs::metadata(file).await?.len();
            }
            Ok(size)
        }
        .await;
        let resume = self
            .api(
                &socket,
                "PATCH",
                "/vm",
                Some(serde_json::json!({"state":"Resumed"})),
            )
            .await;
        match (snapshot_result, resume) {
            (Ok(size), Ok(())) => Ok(size),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(resume_error)) => Err(RuntimeError::Unavailable(format!(
                "snapshot failed: {error}; resume failed: {resume_error}"
            ))),
        }
    }

    pub async fn restore(&self, sandbox: &Sandbox, object_key: &str) -> Result<(), RuntimeError> {
        let source = self.config.snapshot_dir(object_key);
        let manifest: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(source.join("manifest.json")).await?)?;
        let restore_disk = PathBuf::from(manifest["source_disk"].as_str().ok_or_else(|| {
            RuntimeError::Unavailable("snapshot manifest has no source disk".into())
        })?);
        let vms_root = self.config.state_dir.join("vms");
        if !restore_disk.starts_with(&vms_root) {
            return Err(RuntimeError::Unavailable(
                "snapshot disk path is outside worker state".into(),
            ));
        }
        let snapshot_disk = source.join("rootfs.ext4");
        let actual = hex::encode(Sha256::digest(tokio::fs::read(&snapshot_disk).await?));
        if actual != manifest["rootfs_sha256"].as_str().unwrap_or_default() {
            return Err(RuntimeError::Unavailable(
                "snapshot disk checksum mismatch".into(),
            ));
        }
        if let Some(parent) = restore_disk.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(&snapshot_disk, &restore_disk).await?;
        let mut vm = self.spawn(sandbox.id).await?;
        vm.rootfs = restore_disk;
        self.api(&vm.api_socket, "PUT", "/snapshot/load", Some(serde_json::json!({"snapshot_path":source.join("vmstate"), "mem_backend":{"backend_type":"File", "backend_path":source.join("memory")}, "resume_vm":false, "vsock_override":{"uds_path":vm.vsock_socket}}))).await?;
        self.api(
            &vm.api_socket,
            "PATCH",
            "/vm",
            Some(serde_json::json!({"state":"Resumed"})),
        )
        .await?;
        let deadline = tokio::time::Instant::now() + self.config.readiness_timeout;
        loop {
            match self
                .guest_call(sandbox.id, Operation::Health, RequestPayload::None)
                .await
            {
                Ok(ResponsePayload::Health { ready: true }) => break,
                Ok(_) => {}
                Err(error) if tokio::time::Instant::now() < deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        }
        let token = vm.start_token;
        self.vms.lock().await.insert(sandbox.id, vm);
        self.schedule_lifetime(sandbox, token);
        Ok(())
    }

    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        self.stop(sandbox).await?;
        let state = self.config.vm_dir(sandbox.id);
        let socket = self.config.socket_dir(sandbox.id);
        match tokio::fs::remove_dir_all(&state).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match tokio::fs::remove_dir_all(&socket).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    fn health(&self) -> bool {
        self.config.check().is_ok()
    }
}

#[async_trait]
impl SandboxRuntime for FirecrackerRuntime {
    async fn create(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::create(self, sandbox).await.map_err(into_core)
    }
    async fn start(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::start(self, sandbox).await.map_err(into_core)
    }
    async fn stop(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::stop(self, sandbox).await.map_err(into_core)
    }
    async fn pause(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::pause(self, sandbox).await.map_err(into_core)
    }
    async fn resume(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::resume(self, sandbox).await.map_err(into_core)
    }
    async fn exec(&self, sandbox: &Sandbox, request: ExecRequest) -> Result<ExecResult, CoreError> {
        Self::exec(self, sandbox, request).await.map_err(into_core)
    }
    async fn put_file(&self, sandbox: &Sandbox, request: PutFileRequest) -> Result<(), CoreError> {
        Self::put_file(self, sandbox, request)
            .await
            .map_err(into_core)
    }
    async fn get_file(&self, sandbox: &Sandbox, path: &str) -> Result<FileContent, CoreError> {
        Self::get_file(self, sandbox, path).await.map_err(into_core)
    }
    async fn list_files(&self, sandbox: &Sandbox, path: &str) -> Result<Vec<FileEntry>, CoreError> {
        Self::list_files(self, sandbox, path)
            .await
            .map_err(into_core)
    }
    async fn delete_file(
        &self,
        sandbox: &Sandbox,
        request: DeleteFileRequest,
    ) -> Result<(), CoreError> {
        Self::delete_file(self, sandbox, &request.path)
            .await
            .map_err(into_core)
    }
    async fn make_directory(
        &self,
        sandbox: &Sandbox,
        request: MakeDirectoryRequest,
    ) -> Result<(), CoreError> {
        Self::make_directory(self, sandbox, &request.path)
            .await
            .map_err(into_core)
    }
    async fn import_workspace_archive(
        &self,
        sandbox: &Sandbox,
        archive: &[u8],
    ) -> Result<(), CoreError> {
        if archive.len() > MAX_WORKSPACE_ARCHIVE_BYTES {
            return Err(CoreError::LimitExceeded(
                "workspace archive exceeds 64 MiB".into(),
            ));
        }
        // The archive is written straight into the guest, so a sandbox adopted
        // from another worker needs no shared state directory.
        Self::import_workspace_archive(self, sandbox, archive)
            .await
            .map_err(into_core)
    }
    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::destroy(self, sandbox).await.map_err(into_core)
    }
    async fn health(&self) -> RuntimeHealth {
        if Self::health(self) {
            RuntimeHealth::healthy()
        } else {
            RuntimeHealth::unhealthy("Firecracker prerequisites unavailable")
        }
    }
    fn capabilities(&self) -> RuntimeCapabilities {
        firecracker_capabilities(self.network.as_ref(), self.config.guest_artifact.as_ref())
    }
}

#[async_trait]
impl SnapshotProvider for FirecrackerRuntime {
    fn capabilities(&self) -> SnapshotCapabilities {
        SnapshotCapabilities {
            virtual_machine: true,
            memory: true,
            workspace: true,
            cross_instance_restore: true,
        }
    }
    async fn capture(
        &self,
        sandbox: &Sandbox,
        request: &SnapshotRequest,
    ) -> Result<CapturedSnapshot, CoreError> {
        if request.kind == SnapshotKind::Workspace {
            self.export_workspace(sandbox, &request.object_key)
                .await
                .map_err(into_core)?;
            let bytes = tokio::fs::read(
                self.config
                    .snapshot_dir(&request.object_key)
                    .join("workspace.json"),
            )
            .await
            .map_err(CoreError::Io)?;
            return Ok(CapturedSnapshot::from_archive(
                Uuid::now_v7(),
                request.kind,
                request.object_key.clone(),
                bytes,
            ));
        }
        let size = Self::snapshot(self, sandbox, &request.object_key)
            .await
            .map_err(into_core)?;
        Ok(CapturedSnapshot {
            id: Uuid::now_v7(),
            kind: request.kind,
            object_key: request.object_key.clone(),
            size_bytes: size,
            checksum_sha256: hex::encode(Sha256::digest(request.object_key.as_bytes())),
            // A full-VM capture stays on the worker's own disk; only a
            // portable workspace archive is handed back for shared storage.
            archive: Vec::new(),
        })
    }
    async fn restore(
        &self,
        sandbox: &Sandbox,
        metadata: &SnapshotMetadata,
    ) -> Result<(), CoreError> {
        if metadata.kind == SnapshotKind::Workspace {
            self.start(sandbox).await.map_err(into_core)?;
            return self
                .import_workspace(sandbox, &metadata.object_key)
                .await
                .map_err(into_core);
        }
        Self::restore(self, sandbox, &metadata.object_key)
            .await
            .map_err(into_core)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> FirecrackerConfig {
        FirecrackerConfig {
            binary: "/fc".into(),
            kernel: "/vmlinux".into(),
            rootfs: "/rootfs".into(),
            jailer: None,
            tap: None,
            state_dir: "/state".into(),
            guest_secret: vec![7; 32],
            guest_cid: 3,
            readiness_timeout: Duration::from_secs(1),
            guest_artifact_dir: None,
            guest_artifact: None,
            require_coding_guest: false,
        }
    }

    #[test]
    fn paths_use_short_socket_root_and_hash_snapshot_keys() {
        let config = config();
        let id = Uuid::now_v7();
        assert!(
            config
                .api_socket(id)
                .starts_with(std::env::temp_dir().join("aiec-fc"))
        );
        assert!(config.api_socket(id).as_os_str().len() < 108);
        assert!(config.vsock_socket(id).as_os_str().len() < 108);
        assert_ne!(
            config.snapshot_dir("tenant/a"),
            config.snapshot_dir("tenant/b")
        );
    }

    fn sandbox(id: Uuid, timeout_seconds: u64) -> Sandbox {
        let now = chrono::Utc::now();
        Sandbox {
            id,
            tenant_id: Uuid::now_v7(),
            node_id: None,
            image_id: "test".into(),
            state: SandboxState::Running,
            runtime: RuntimeKind::Firecracker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 128,
            timeout_seconds,
            network: NetworkPolicy::default(),
            environment: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        }
    }
    #[test]
    fn firecracker_pause_is_not_reported_as_resource_reclamation() {
        let capabilities = firecracker_capabilities(&LinuxNetworkManager::new(), None);
        assert!(capabilities.pause);
        assert!(!capabilities.pause_reclaims_resources);
    }

    #[test]
    fn repeated_non_idempotent_requests_get_fresh_ids() {
        let first = FirecrackerRuntime::fresh_request(
            Operation::WriteFile,
            RequestPayload::Path {
                path: "/workspace/file".into(),
            },
        );
        let second = FirecrackerRuntime::fresh_request(
            Operation::WriteFile,
            RequestPayload::Path {
                path: "/workspace/file".into(),
            },
        );
        assert_ne!(first.request_id, second.request_id);
    }

    #[tokio::test]
    async fn half_open_guest_vsock_read_is_bounded() {
        let mut config = config();
        let state_token = Uuid::now_v7().simple().to_string();
        config.state_dir = std::env::temp_dir().join(format!("af-{}", &state_token[..8]));
        config.readiness_timeout = Duration::from_millis(40);
        let id = Uuid::now_v7();
        let socket = config.vsock_socket(id);
        tokio::fs::create_dir_all(socket.parent().unwrap())
            .await
            .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let runtime = FirecrackerRuntime::new(config);
        let started = Instant::now();
        let result = runtime
            .guest_call(id, Operation::Health, RequestPayload::None)
            .await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        server.abort();
        let _ = tokio::fs::remove_dir_all(runtime.config.state_dir).await;
    }

    #[tokio::test]
    async fn stale_timer_token_cannot_stop_restarted_vm() {
        let mut config = config();
        config.readiness_timeout = Duration::from_millis(5);
        let runtime = FirecrackerRuntime::new(config);
        let sandbox = sandbox(Uuid::now_v7(), 60);
        let token = Uuid::now_v7();
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        runtime.vms.lock().await.insert(
            sandbox.id,
            FirecrackerVm {
                child,
                api_socket: PathBuf::from("/unused/api.sock"),
                network: None,
                vsock_socket: PathBuf::from("/unused/vsock.sock"),
                rootfs: PathBuf::from("/unused/rootfs.ext4"),
                start_token: token,
            },
        );
        runtime.stop_if_token(&sandbox, Uuid::now_v7()).await;
        assert!(runtime.vms.lock().await.contains_key(&sandbox.id));
        let mut vm = runtime.vms.lock().await.remove(&sandbox.id).unwrap();
        let _ = vm.child.start_kill();
        let _ = vm.child.wait().await;
    }

    #[test]
    fn local_reconciliation_only_reports_explicit_owner() {
        let mut config = config();
        let state = std::env::temp_dir().join(format!("af-reconcile-{}", Uuid::now_v7()));
        config.state_dir = state.clone();
        let runtime = FirecrackerRuntime::new(config);
        let owner = Uuid::now_v7();
        let other = Uuid::now_v7();
        let owned = Uuid::now_v7();
        let foreign = Uuid::now_v7();
        runtime.claim_local_vm(owned, owner).unwrap();
        runtime.claim_local_vm(foreign, other).unwrap();
        let report = runtime.reconcile_local(owner).unwrap();
        assert_eq!(report.scanned, 2);
        assert_eq!(report.owned, 1);
        assert_eq!(report.orphan_candidates, vec![owned]);
        let _ = std::fs::remove_dir_all(state);
    }

    #[test]
    fn snapshot_portability_is_explicit_per_provider() {
        let config = config();
        let bwrap = BubblewrapRuntime::new(config.state_dir.clone());
        let bwrap_caps = SnapshotProvider::capabilities(&bwrap);
        let firecracker = FirecrackerRuntime::new(config);
        let firecracker_caps = SnapshotProvider::capabilities(&firecracker);
        assert!(bwrap_caps.workspace && bwrap_caps.cross_instance_restore);
        assert!(!bwrap_caps.virtual_machine && !bwrap_caps.memory);
        assert!(firecracker_caps.workspace && firecracker_caps.cross_instance_restore);
        assert!(firecracker_caps.virtual_machine && firecracker_caps.memory);
    }

    #[tokio::test]
    async fn matching_lifetime_schedule_expires_vm() {
        let mut config = config();
        config.readiness_timeout = Duration::from_millis(5);
        let runtime = FirecrackerRuntime::new(config);
        let sandbox = sandbox(Uuid::now_v7(), 0);
        let token = Uuid::now_v7();
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        runtime.vms.lock().await.insert(
            sandbox.id,
            FirecrackerVm {
                child,
                api_socket: PathBuf::from("/unused/api.sock"),
                network: None,
                vsock_socket: PathBuf::from("/unused/vsock.sock"),
                rootfs: PathBuf::from("/unused/rootfs.ext4"),
                start_token: token,
            },
        );
        runtime.schedule_lifetime(&sandbox, token);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!runtime.vms.lock().await.contains_key(&sandbox.id));
    }

    #[tokio::test]
    async fn workspace_archive_handoffs_between_bubblewrap_runtimes() {
        let first_root = std::env::temp_dir().join(format!("af-export-{}", Uuid::now_v7()));
        let second_root = std::env::temp_dir().join(format!("af-import-{}", Uuid::now_v7()));
        let source = BubblewrapRuntime::new(&first_root);
        let target = BubblewrapRuntime::new(&second_root);
        let source_sandbox = sandbox(Uuid::now_v7(), 60);
        let target_sandbox = sandbox(Uuid::now_v7(), 60);
        source.create(&source_sandbox).await.unwrap();
        source
            .put_file(
                &source_sandbox,
                PutFileRequest {
                    path: "/workspace/proof.txt".into(),
                    content_base64: "cHJvdmVu".into(),
                    mode: None,
                },
            )
            .await
            .unwrap();
        let archive = source
            .export_workspace_snapshot(&source_sandbox, "handoff")
            .await
            .unwrap();
        target.create(&target_sandbox).await.unwrap();
        target
            .import_workspace_snapshot(&target_sandbox, &archive)
            .await
            .unwrap();
        let file = target
            .get_file(&target_sandbox, "/workspace/proof.txt")
            .await
            .unwrap();
        assert_eq!(file.content_base64, "cHJvdmVu");
        let _ = tokio::fs::remove_dir_all(first_root).await;
        let _ = tokio::fs::remove_dir_all(second_root).await;
    }

    #[tokio::test]
    async fn workspace_archive_rejects_checksum_mismatch() {
        let root = std::env::temp_dir().join(format!("af-checksum-{}", Uuid::now_v7()));
        let runtime = BubblewrapRuntime::new(&root);
        let target = sandbox(Uuid::now_v7(), 60);
        let archive = WorkspaceArchive {
            key: "bad".into(),
            bytes: vec![1, 2, 3],
            checksum_sha256: "0".repeat(64),
        };
        assert!(
            runtime
                .import_workspace_snapshot(&target, &archive)
                .await
                .is_err()
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn workspace_archive_rejects_unsafe_key() {
        let root = std::env::temp_dir().join(format!("af-key-{}", Uuid::now_v7()));
        let runtime = BubblewrapRuntime::new(&root);
        let sandbox = sandbox(Uuid::now_v7(), 60);
        assert!(
            runtime
                .export_workspace_snapshot(&sandbox, "../escape")
                .await
                .is_err()
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    fn attachment(host: &str, guest: &str) -> NetworkAttachment {
        NetworkAttachment {
            resource: "af0123456789ab".into(),
            addresses: vec![host.into()],
            guest_addresses: vec![guest.into()],
        }
    }

    #[test]
    fn boot_args_without_network_keep_the_bare_command_line() {
        assert_eq!(
            firecracker_boot_args(None),
            "console=ttyS0 reboot=k panic=1 pci=off"
        );
        // A backend that cannot report in-guest addresses must not produce a
        // command line that would leave the guest with an unusable interface.
        let host_only = NetworkAttachment {
            resource: "af0123456789ab".into(),
            addresses: vec!["172.30.8.1".into()],
            guest_addresses: Vec::new(),
        };
        assert_eq!(
            firecracker_boot_args(Some(&host_only)),
            "console=ttyS0 reboot=k panic=1 pci=off"
        );
    }

    #[test]
    fn boot_args_configure_the_guest_from_the_tap_subnet() {
        let args = firecracker_boot_args(Some(&attachment("172.30.8.1", "172.30.8.2")));
        assert!(args.starts_with("console=ttyS0 reboot=k panic=1 pci=off"));
        assert!(args.contains("net.ifnames=0"));
        assert!(
            args.contains("ip=172.30.8.2::172.30.8.1:255.255.255.252:aiec:eth0:off"),
            "{args}"
        );
    }

    #[test]
    fn coding_guest_capability_follows_the_artifact_profile() {
        let coding = guest_artifact::GuestArtifact {
            artifact_version: "1.0.0".into(),
            base: "debian:bookworm-slim".into(),
            profile: "coding".into(),
            capabilities: vec!["sh".into(), "git".into(), "ca-certificates".into()],
            git_version: Some("git version 2.39.5".into()),
            guest_agent_version: "0.1.0".into(),
            rootfs_sha256: "a".repeat(64),
            kernel_sha256: None,
        };
        let without_git = guest_artifact::GuestArtifact {
            capabilities: vec!["sh".into()],
            ..coding.clone()
        };
        let runtime = FirecrackerRuntime::new(FirecrackerConfig {
            guest_artifact: Some(coding.clone()),
            ..config()
        });
        assert!(SandboxRuntime::capabilities(&runtime).coding_guest);
        let minimal = FirecrackerRuntime::new(FirecrackerConfig {
            guest_artifact: Some(without_git),
            ..config()
        });
        assert!(!SandboxRuntime::capabilities(&minimal).coding_guest);
        let unrecorded = FirecrackerRuntime::new(config());
        assert!(!SandboxRuntime::capabilities(&unrecorded).coding_guest);
        assert!(firecracker_capabilities(&LinuxNetworkManager::new(), Some(&coding)).coding_guest);
    }

    fn artifact_config(dir: &Path, rootfs: &Path) -> FirecrackerConfig {
        FirecrackerConfig {
            kernel: dir.join("vmlinux"),
            rootfs: rootfs.to_path_buf(),
            guest_artifact_dir: Some(dir.to_path_buf()),
            guest_artifact: Some(
                guest_artifact::load_guest_artifact(&dir.join(guest_artifact::GUEST_ARTIFACT_FILE))
                    .expect("artifact metadata"),
            ),
            ..config()
        }
    }

    fn write_artifact_metadata(dir: &Path, rootfs: &Path, capabilities: &str, profile: &str) {
        let digest = hex::encode(Sha256::digest(std::fs::read(rootfs).expect("rootfs")));
        std::fs::write(
            dir.join(guest_artifact::GUEST_ARTIFACT_FILE),
            format!(
                r#"{{"artifact_version":"1.0.0","base":"debian:bookworm-slim","profile":"{profile}","capabilities":{capabilities},"guest_agent_version":"0.1.0","rootfs_sha256":"{digest}"}}"#
            ),
        )
        .expect("artifact metadata");
    }

    #[test]
    fn guest_artifact_check_rejects_a_rootfs_that_does_not_match() {
        let dir = std::env::temp_dir().join(format!("af-guest-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("artifact directory");
        let rootfs = dir.join("aiec-rootfs.ext4");
        std::fs::write(&rootfs, b"root filesystem bytes").expect("rootfs");
        std::fs::write(dir.join("vmlinux"), b"kernel bytes").expect("kernel");
        write_artifact_metadata(&dir, &rootfs, r#"["git","ca-certificates"]"#, "coding");
        artifact_config(&dir, &rootfs)
            .check_guest_artifact()
            .expect("matching artifact must pass");
        std::fs::write(&rootfs, b"tampered root filesystem").expect("rootfs");
        let error = artifact_config(&dir, &rootfs)
            .check_guest_artifact()
            .expect_err("a modified rootfs must fail the check");
        assert!(error.to_string().contains("sha256 mismatch"), "{error}");
        std::fs::remove_file(&rootfs).expect("remove rootfs");
        let error = artifact_config(&dir, &rootfs)
            .check_guest_artifact()
            .expect_err("a missing rootfs must fail the check");
        assert!(error.to_string().contains("is missing"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn required_coding_guest_refuses_images_that_cannot_code() {
        let dir = std::env::temp_dir().join(format!("af-coding-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("artifact directory");
        let rootfs = dir.join("aiec-rootfs.ext4");
        std::fs::write(&rootfs, b"root filesystem bytes").expect("rootfs");
        std::fs::write(dir.join("vmlinux"), b"kernel bytes").expect("kernel");

        let demanded = FirecrackerConfig {
            require_coding_guest: true,
            ..config()
        };
        let error = demanded
            .check_guest_artifact()
            .expect_err("no metadata cannot satisfy a coding guest requirement");
        assert!(
            error
                .to_string()
                .contains("requires guest artifact metadata"),
            "{error}"
        );

        write_artifact_metadata(&dir, &rootfs, r#"["sh"]"#, "minimal");
        artifact_config(&dir, &rootfs)
            .check_guest_artifact()
            .expect("without the requirement flag any recorded image is accepted");
        let error = FirecrackerConfig {
            require_coding_guest: true,
            ..artifact_config(&dir, &rootfs)
        }
        .check_guest_artifact()
        .expect_err("a minimal profile cannot satisfy a coding guest requirement");
        assert!(
            error.to_string().contains("requires the coding profile"),
            "{error}"
        );

        write_artifact_metadata(&dir, &rootfs, r#"["sh","git"]"#, "coding");
        let error = FirecrackerConfig {
            require_coding_guest: true,
            ..artifact_config(&dir, &rootfs)
        }
        .check_guest_artifact()
        .expect_err("git without CA certificates cannot validate HTTPS");
        assert!(error.to_string().contains("ca-certificates"), "{error}");

        write_artifact_metadata(&dir, &rootfs, r#"["sh","git","ca-certificates"]"#, "coding");
        FirecrackerConfig {
            require_coding_guest: true,
            ..artifact_config(&dir, &rootfs)
        }
        .check_guest_artifact()
        .expect("a coding guest with git and CA certificates satisfies the requirement");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod artifact_cache_tests {
    use super::artifact_identity;
    use super::guest_artifact;
    use std::io::Write;

    /// Two different files must not share a verification verdict.
    ///
    /// The cache this replaced was a process-wide `OnceLock`: one result for
    /// everything, correct only while there was exactly one configured image. A
    /// worker pointed at a second, unverified rootfs inherited the first one's
    /// verdict, which is the failure the specification names when it says never
    /// to skip integrity verification because you checked once "sometime
    /// earlier".
    #[test]
    fn a_different_artifact_gets_a_different_key() {
        let dir = std::env::temp_dir().join(format!("af-cache-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let first = dir.join("rootfs-a.img");
        let second = dir.join("rootfs-b.img");
        let kernel = dir.join("vmlinux");
        for path in [&first, &second, &kernel] {
            let mut file = std::fs::File::create(path).expect("create");
            file.write_all(b"contents").expect("write");
        }

        let a = artifact_identity(&first, &kernel, None, false).expect("identity a");
        let b = artifact_identity(&second, &kernel, None, false).expect("identity b");
        assert_ne!(a, b, "two different rootfs must not share a verdict");
        assert_eq!(
            a,
            artifact_identity(&first, &kernel, None, false).expect("identity again"),
            "the same unchanged artifact must still hit the cache"
        );

        // Replacing a file in place must miss: the same path with different
        // bytes is a different artifact, and trusting the old verdict for it is
        // exactly the bug.
        let longer = dir.join("rootfs-longer.img");
        std::fs::write(&longer, b"a considerably longer set of contents").expect("write");
        assert_ne!(
            artifact_identity(&first, &kernel, None, false).expect("identity a"),
            artifact_identity(&longer, &kernel, None, false).expect("identity longer"),
            "a different file at a different path must not reuse a verdict"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The coding-guest requirement is part of the check, so it is part of the key.
    ///
    /// `check_guest_artifact` finishes with `check_guest_capabilities`, which
    /// reads `require_coding_guest`. Two configurations differing only in that
    /// flag share every path and every byte, so a key built from the files alone
    /// would let a lax configuration's success satisfy a strict one - and the
    /// strict one is the one that was supposed to refuse to run an image that
    /// cannot clone.
    #[test]
    fn the_coding_guest_requirement_is_part_of_the_key() {
        let dir = std::env::temp_dir().join(format!("af-coding-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rootfs = dir.join("rootfs.img");
        let kernel = dir.join("vmlinux");
        std::fs::write(&rootfs, b"same bytes").expect("write rootfs");
        std::fs::write(&kernel, b"same kernel").expect("write kernel");

        let lax = artifact_identity(&rootfs, &kernel, None, false).expect("lax");
        let strict = artifact_identity(&rootfs, &kernel, None, true).expect("strict");
        assert_ne!(
            lax, strict,
            "a lax verification must not satisfy a configuration that demands a coding guest"
        );

        // Different metadata is a different verdict too, even at identical paths.
        let artifact = guest_artifact::GuestArtifact {
            artifact_version: "1".into(),
            base: "debian".into(),
            profile: "coding".into(),
            capabilities: vec!["git".into()],
            git_version: Some("2.39.0".into()),
            guest_agent_version: "1".into(),
            rootfs_sha256: "abc123".into(),
            kernel_sha256: Some("def456".into()),
        };
        let with_artifact =
            artifact_identity(&rootfs, &kernel, Some(&artifact), true).expect("with artifact");
        assert_ne!(
            strict, with_artifact,
            "different artifact metadata is a different artifact"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unreadable artifact produces no key rather than a shared one.
    #[test]
    fn an_unstatable_artifact_has_no_key() {
        let missing = std::env::temp_dir().join("af-definitely-not-here-9f2c.img");
        assert!(
            artifact_identity(&missing, &missing, None, false).is_err(),
            "a missing file must not yield a cache key"
        );
    }
}
