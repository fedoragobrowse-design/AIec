use agentforge_core::protocol::{
    self, Operation, Request, RequestPayload, Response, ResponsePayload,
};
use agentforge_core::{
    network::{NetworkAttachment, NetworkBackend},
    runtime::{RuntimeCapabilities, RuntimeHealth},
    snapshots::{
        CapturedSnapshot, SnapshotCapabilities, SnapshotKind, SnapshotMetadata, SnapshotProvider,
        SnapshotRequest,
    },
    *,
};
use agentforge_network_linux::LinuxNetworkManager;
use async_trait::async_trait;
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

pub use agentforge_core::runtime::SandboxRuntime;

fn into_core(error: RuntimeError) -> CoreError {
    match error {
        RuntimeError::Core(error) => error,
        other => CoreError::Io(std::io::Error::other(other.to_string())),
    }
}

fn bwrap_capabilities() -> RuntimeCapabilities {
    RuntimeCapabilities {
        network_policy: true,
        workspace_snapshot: true,
        ..RuntimeCapabilities::default()
    }
}

fn firecracker_capabilities(_network: &dyn NetworkBackend) -> RuntimeCapabilities {
    RuntimeCapabilities {
        vm_snapshot: true,
        memory_resume: true,
        network_policy: true,
        pause: true,
        vsock: true,
        ..RuntimeCapabilities::default()
    }
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
    async fn exec(
        &self,
        sandbox: &Sandbox,
        request: ExecRequest,
    ) -> Result<ExecResult, CoreError> {
        Self::exec(self, sandbox, request).await.map_err(into_core)
    }
    async fn put_file(
        &self,
        sandbox: &Sandbox,
        request: PutFileRequest,
    ) -> Result<(), CoreError> {
        Self::put_file(self, sandbox, request).await.map_err(into_core)
    }
    async fn get_file(&self, sandbox: &Sandbox, path: &str) -> Result<FileContent, CoreError> {
        Self::get_file(self, sandbox, path).await.map_err(into_core)
    }
    async fn list_files(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<Vec<FileEntry>, CoreError> {
        Self::list_files(self, sandbox, path).await.map_err(into_core)
    }
    async fn delete_file(
        &self,
        sandbox: &Sandbox,
        request: DeleteFileRequest,
    ) -> Result<(), CoreError> {
        Self::delete_file(self, sandbox, &request.path).await.map_err(into_core)
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
        SnapshotCapabilities { workspace: true, ..SnapshotCapabilities::default() }
    }
    async fn capture(&self, sandbox: &Sandbox, request: &SnapshotRequest) -> Result<CapturedSnapshot, CoreError> {
        if request.kind != SnapshotKind::Workspace {
            return Err(CoreError::Unsupported("bubblewrap supports workspace snapshots only".into()));
        }
        let size = Self::snapshot(self, sandbox, &request.object_key).await.map_err(into_core)?;
        Ok(CapturedSnapshot {
            id: Uuid::now_v7(), kind: request.kind, object_key: request.object_key.clone(), size_bytes: size,
            checksum_sha256: hex::encode(Sha256::digest(request.object_key.as_bytes())),
        })
    }
    async fn restore(&self, sandbox: &Sandbox, metadata: &SnapshotMetadata) -> Result<(), CoreError> {
        Self::restore(self, sandbox, &metadata.object_key).await.map_err(into_core)
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
}

impl FirecrackerConfig {
    pub fn from_env() -> Result<Self, RuntimeError> {
        let required = |name: &str| {
            std::env::var(name)
                .map_err(|_| RuntimeError::Unavailable(format!("{name} is required")))
        };
        Ok(Self {
            binary: PathBuf::from(required("AGENTFORGE_FIRECRACKER_BIN")?),
            kernel: PathBuf::from(required("AGENTFORGE_KERNEL")?),
            rootfs: PathBuf::from(required("AGENTFORGE_ROOTFS")?),
            jailer: std::env::var("AGENTFORGE_JAILER").ok().map(PathBuf::from),
            tap: std::env::var("AGENTFORGE_TAP").ok(),
            state_dir: PathBuf::from(
                std::env::var("AGENTFORGE_STATE_DIR")
                    .unwrap_or_else(|_| ".agentforge/firecracker".into()),
            ),
            guest_secret: required("AGENTFORGE_GUEST_SECRET")?.into_bytes(),
            guest_cid: 3,
            readiness_timeout: Duration::from_secs(30),
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
                "AGENTFORGE_GUEST_SECRET must contain at least 32 bytes".into(),
            ));
        }
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
        if self.tap.is_some() && (which("ip").is_none() || which("nft").is_none()) {
            return Err(RuntimeError::Unavailable(
                "network isolation requires ip(8) and nft".into(),
            ));
        }
        Ok(())
    }

    fn vm_dir(&self, id: Uuid) -> PathBuf {
        self.state_dir.join("vms").join(id.to_string())
    }
    fn api_socket(&self, id: Uuid) -> PathBuf {
        self.vm_dir(id).join("api.sock")
    }
    fn vsock_socket(&self, id: Uuid) -> PathBuf {
        self.vm_dir(id).join("vsock.sock")
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
                    let connect = format!("CONNECT {}\n", protocol::DEFAULT_CONTROL_PORT);
                    match tokio::time::timeout(remaining, stream.write_all(connect.as_bytes()))
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => return Err(error.into()),
                        Err(_) => {
                            return Err(RuntimeError::Unavailable(
                                "guest vsock CONNECT timed out".into(),
                            ));
                        }
                    }
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    match tokio::time::timeout(remaining, reader.read_line(&mut line)).await {
                        Ok(Ok(_)) if line.starts_with("OK ") => {
                            return Ok(reader.into_inner());
                        }
                        Ok(Ok(_)) => {
                            return Err(RuntimeError::Unavailable(format!(
                                "guest vsock CONNECT rejected: {}",
                                line.trim()
                            )));
                        }
                        Ok(Err(error)) => return Err(error.into()),
                        Err(_) => {
                            return Err(RuntimeError::Unavailable(
                                "guest vsock CONNECT timed out".into(),
                            ));
                        }
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
        self.api(&vm.api_socket, "PUT", "/boot-source", Some(serde_json::json!({"kernel_image_path": self.config.kernel, "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"}))).await?;
        self.api(&vm.api_socket, "PUT", "/drives/rootfs", Some(serde_json::json!({"drive_id":"rootfs", "path_on_host":vm.rootfs, "is_root_device":true, "is_read_only":false}))).await?;
        self.api(&vm.api_socket, "PUT", "/machine-config", Some(serde_json::json!({"vcpu_count":sandbox.cpu, "mem_size_mib":sandbox.memory_mb, "smt":false}))).await?;
        self.api(&vm.api_socket, "PUT", "/vsock", Some(serde_json::json!({"guest_cid":self.config.guest_cid, "uds_path":vm.vsock_socket}))).await?;
        self.api(&vm.api_socket, "PUT", "/actions", Some(serde_json::json!({"action_type":"InstanceStart"}))).await?;
        let deadline = tokio::time::Instant::now() + self.config.readiness_timeout;
        loop {
            match self.guest_call(sandbox.id, Operation::Health, RequestPayload::None).await {
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
        self.config.check()?;
        let dir = self.config.vm_dir(sandbox.id);
        tokio::fs::create_dir_all(&dir).await?;
        let destination = self.config.rootfs(sandbox.id);
        tokio::fs::copy(&self.config.rootfs, &destination).await?;
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
        match tokio::fs::remove_dir_all(self.config.vm_dir(sandbox.id)).await {
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
    async fn exec(&self, sandbox: &Sandbox, request: ExecRequest) -> Result<ExecResult, CoreError> {
        Self::exec(self, sandbox, request).await.map_err(into_core)
    }
    async fn put_file(&self, sandbox: &Sandbox, request: PutFileRequest) -> Result<(), CoreError> {
        Self::put_file(self, sandbox, request).await.map_err(into_core)
    }
    async fn get_file(&self, sandbox: &Sandbox, path: &str) -> Result<FileContent, CoreError> {
        Self::get_file(self, sandbox, path).await.map_err(into_core)
    }
    async fn list_files(&self, sandbox: &Sandbox, path: &str) -> Result<Vec<FileEntry>, CoreError> {
        Self::list_files(self, sandbox, path).await.map_err(into_core)
    }
    async fn delete_file(&self, sandbox: &Sandbox, request: DeleteFileRequest) -> Result<(), CoreError> {
        Self::delete_file(self, sandbox, &request.path).await.map_err(into_core)
    }
    async fn make_directory(&self, sandbox: &Sandbox, request: MakeDirectoryRequest) -> Result<(), CoreError> {
        Self::make_directory(self, sandbox, &request.path).await.map_err(into_core)
    }
    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        Self::destroy(self, sandbox).await.map_err(into_core)
    }
    async fn health(&self) -> RuntimeHealth {
        if Self::health(self) { RuntimeHealth::healthy() } else { RuntimeHealth::unhealthy("Firecracker prerequisites unavailable") }
    }
    fn capabilities(&self) -> RuntimeCapabilities {
        firecracker_capabilities(self.network.as_ref())
    }
}

#[async_trait]
impl SnapshotProvider for FirecrackerRuntime {
    fn capabilities(&self) -> SnapshotCapabilities {
        SnapshotCapabilities { virtual_machine: true, memory: true, workspace: false, cross_instance_restore: true }
    }
    async fn capture(&self, sandbox: &Sandbox, request: &SnapshotRequest) -> Result<CapturedSnapshot, CoreError> {
        if request.kind == SnapshotKind::Workspace {
            return Err(CoreError::Unsupported("Firecracker snapshots include VM state".into()));
        }
        let size = Self::snapshot(self, sandbox, &request.object_key).await.map_err(into_core)?;
        Ok(CapturedSnapshot {
            id: Uuid::now_v7(), kind: request.kind, object_key: request.object_key.clone(), size_bytes: size,
            checksum_sha256: hex::encode(Sha256::digest(request.object_key.as_bytes())),
        })
    }
    async fn restore(&self, sandbox: &Sandbox, metadata: &SnapshotMetadata) -> Result<(), CoreError> {
        Self::restore(self, sandbox, &metadata.object_key).await.map_err(into_core)
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
        }
    }

    #[test]
    fn paths_are_per_vm_and_snapshot_keys_are_hashed() {
        let config = config();
        let id = Uuid::now_v7();
        assert!(
            config
                .api_socket(id)
                .starts_with(config.state_dir.join("vms").join(id.to_string()))
        );
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
            created_at: now,
            updated_at: now,
            runtime_path: None,
        }
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
}
