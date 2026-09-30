use crate::{RuntimeError, SandboxRuntime};
use aiec_core::runtime::{RuntimeCapabilities, RuntimeHealth};
use aiec_core::{
    DeleteFileRequest, ExecRequest, ExecResult, FileContent, FileEntry, MakeDirectoryRequest,
    NetworkPolicy, PutFileRequest, Sandbox,
    snapshots::{
        CapturedSnapshot, PortableWorkspaceArchive, PortableWorkspaceEntry, SnapshotCapabilities,
        SnapshotMetadata, SnapshotProvider, SnapshotRequest,
    },
};
use async_trait::async_trait;
use base64::Engine;
use bollard::{
    Docker,
    container::LogOutput,
    exec::StartExecResults,
    models::{ContainerCreateBody, HostConfig, Mount, MountType},
};
use futures_util::StreamExt;
use sha2::Digest;
use std::io::Read;
use std::{
    collections::HashMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Instant,
};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

fn workspace_path(raw: &str) -> Result<String, aiec_core::CoreError> {
    let normalized = aiec_core::safe_path(raw)?;
    normalized
        .strip_prefix("/workspace")
        .map(|path| {
            format!(
                "/workspace/{}",
                path.to_string_lossy().trim_start_matches('/')
            )
        })
        .map_err(|_| aiec_core::CoreError::Forbidden("outside workspace".into()))
}

const MAX_LIST_ENTRIES: usize = 10_000;

/// Whether a nameserver is one a container can actually reach.
///
/// Loopback is the trap. A host running systemd-resolved lists only
/// `127.0.0.53`, which is a stub listening on the *host's* loopback; hand that
/// to a container and it asks its own loopback, where nothing is listening, so
/// every lookup fails immediately instead of merely being slow. Docker's
/// embedded resolver, `127.0.0.11`, is the same idea and is reachable only
/// inside a container the daemon set up itself.
///
/// Passing such an address through would trade "no resolver configured" for
/// "total, silent DNS failure", which is strictly worse than leaving the
/// daemon's default in place.
fn is_reachable_nameserver(address: &str) -> bool {
    let address = address.trim();
    if address.eq_ignore_ascii_case("::1") {
        return false;
    }
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => !v4.is_loopback(),
        // An IPv6 address that is not loopback is as reachable as its v4 peer.
        Ok(std::net::IpAddr::V6(v6)) => !v6.is_loopback(),
        // Not an address we can judge; let it through rather than silently
        // dropping a resolver the operator configured on purpose.
        Err(_) => !address.is_empty(),
    }
}

/// The nameservers a container can use, or nothing to leave the daemon's own
/// default alone.
///
/// A sandbox that is never told where to ask fails every lookup with "could
/// not resolve host", which reads like a broken image rather than a container
/// that was misconfigured. Inheriting the host's resolvers fixes that on any
/// host with a reachable one; `is_reachable_nameserver` is what keeps it from
/// breaking the hosts that only have a loopback stub.
fn host_resolvers() -> Option<Vec<String>> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let servers: Vec<String> = contents
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .map(str::trim)
        .filter(|address| is_reachable_nameserver(address))
        .map(str::to_owned)
        .collect();
    (!servers.is_empty()).then_some(servers)
}

fn container_network_mode(network: &NetworkPolicy) -> Result<&'static str, aiec_core::CoreError> {
    match network {
        NetworkPolicy::Disabled => Ok("none"),
        NetworkPolicy::Internet => Ok("bridge"),
        NetworkPolicy::Restricted { .. } => Err(aiec_core::CoreError::Unsupported(
            "Docker restricted network allowlists are not implemented".into(),
        )),
    }
}

fn validate_environment(
    environment: &std::collections::BTreeMap<String, String>,
) -> Result<(), RuntimeError> {
    for (key, value) in environment {
        if key.is_empty()
            || key.len() > 256
            || key.contains('=')
            || key.contains('\0')
            || value.len() > 4096
            || value.contains('\0')
        {
            return Err(RuntimeError::Unavailable(
                "invalid Docker environment variable".into(),
            ));
        }
    }
    Ok(())
}

fn decode_file_content(value: &str) -> Result<Vec<u8>, RuntimeError> {
    if value.len() > aiec_core::MAX_FILE.saturating_mul(2) {
        return Err(RuntimeError::Archive(
            "Docker file content exceeds limit".into(),
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| RuntimeError::Archive("invalid base64 file content".into()))?;
    if bytes.len() > aiec_core::MAX_FILE {
        return Err(RuntimeError::Archive(
            "Docker file content exceeds limit".into(),
        ));
    }
    Ok(bytes)
}

fn archive_name(path: &str) -> Result<String, RuntimeError> {
    if path.is_empty()
        || path == "."
        || path == ".."
        || path.contains('/')
        || path.contains('\0')
        || path.bytes().any(|byte| byte < 0x20)
    {
        return Err(RuntimeError::Archive(
            "invalid Docker archive entry name".into(),
        ));
    }
    Ok(path.to_owned())
}

fn validate_archive_path(path: &str) -> Result<(), RuntimeError> {
    if path.split('/').any(|component| component == "..") || path.contains('\0') {
        return Err(RuntimeError::Archive(
            "Docker archive contains an unsafe path".into(),
        ));
    }
    Ok(())
}

fn parent_path(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| parent)
        .filter(|parent| !parent.is_empty())
        .unwrap_or("/")
        .to_owned()
}

fn extract_file_archive(archive: &[u8], expected_name: &str) -> Result<Vec<u8>, RuntimeError> {
    let mut tar = tar::Archive::new(std::io::Cursor::new(archive));
    let mut entries = tar
        .entries()
        .map_err(|error| RuntimeError::Archive(error.to_string()))?;
    let Some(entry) = entries.next() else {
        return Err(RuntimeError::Archive("Docker archive is empty".into()));
    };
    let mut entry = entry.map_err(|error| RuntimeError::Archive(error.to_string()))?;
    let entry_type = entry.header().entry_type();
    if entry_type.is_symlink() || entry_type.is_hard_link() {
        return Err(RuntimeError::Archive(
            "Docker archive contains a link entry".into(),
        ));
    }
    if !entry_type.is_file() {
        return Err(RuntimeError::Archive(
            "Docker file archive contains a non-regular entry".into(),
        ));
    }
    let entry_path = entry
        .path()
        .map_err(|error| RuntimeError::Archive(error.to_string()))?
        .to_string_lossy()
        .into_owned();
    validate_archive_path(&entry_path)?;
    if archive_name(entry_path.rsplit('/').next().unwrap_or_default())? != expected_name {
        return Err(RuntimeError::Archive(
            "Docker archive entry does not match requested file".into(),
        ));
    }
    let mut content = Vec::new();
    entry
        .by_ref()
        .take((aiec_core::MAX_FILE + 1) as u64)
        .read_to_end(&mut content)
        .map_err(|error| RuntimeError::Archive(error.to_string()))?;
    if content.len() > aiec_core::MAX_FILE {
        return Err(RuntimeError::Archive(
            "Docker file content exceeds limit".into(),
        ));
    }
    if entries.next().is_some() {
        return Err(RuntimeError::Archive(
            "Docker file archive contains multiple entries".into(),
        ));
    }
    Ok(content)
}

fn extract_directory_archive(archive: &[u8], root: &str) -> Result<Vec<FileEntry>, RuntimeError> {
    let mut tar = tar::Archive::new(std::io::Cursor::new(archive));
    let entries = tar
        .entries()
        .map_err(|error| RuntimeError::Archive(error.to_string()))?;
    let root = root.trim_matches('/');
    let relative_root = root
        .strip_prefix("workspace")
        .map(|path| path.trim_start_matches('/'))
        .unwrap_or(root);
    let relative_prefix = format!("{relative_root}/");
    let workspace_prefix = if relative_root.is_empty() {
        "workspace/".into()
    } else {
        format!("workspace/{relative_root}/")
    };
    let mut files = Vec::new();
    for entry in entries {
        if files.len() >= MAX_LIST_ENTRIES {
            return Err(RuntimeError::Archive(
                "Docker directory listing limit exceeded".into(),
            ));
        }
        let entry = entry.map_err(|error| RuntimeError::Archive(error.to_string()))?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(RuntimeError::Archive(
                "Docker directory archive contains a link".into(),
            ));
        }
        if !entry_type.is_dir() && !entry_type.is_file() {
            return Err(RuntimeError::Archive(
                "Docker directory archive contains a special entry".into(),
            ));
        }
        let entry_path = entry
            .path()
            .map_err(|error| RuntimeError::Archive(error.to_string()))?
            .to_string_lossy()
            .into_owned();
        validate_archive_path(&entry_path)?;
        let normalized = entry_path.trim_start_matches('/').trim_start_matches("./");
        let relative = if relative_root.is_empty() {
            normalized.strip_prefix(&workspace_prefix)
        } else {
            normalized
                .strip_prefix(&relative_prefix)
                .or_else(|| normalized.strip_prefix(&workspace_prefix))
        };
        let Some(relative) = relative else {
            continue;
        };
        if relative.is_empty() || relative.contains('/') {
            continue;
        }
        let name = archive_name(relative)?;
        let output_path = if relative_root.is_empty() {
            format!("/workspace/{relative}")
        } else {
            format!("/workspace/{relative_root}/{relative}")
        };
        files.push(FileEntry {
            path: output_path,
            name,
            kind: if entry_type.is_dir() {
                "directory".into()
            } else {
                "file".into()
            },
            size: entry.header().size().unwrap_or(0),
        });
    }
    Ok(files)
}

const LABEL_MANAGED: &str = "com.aiec.managed";
const LABEL_SANDBOX: &str = "com.aiec.sandbox";
const LABEL_TENANT: &str = "com.aiec.tenant";

/// Docker Engine API runtime. Docker is a weaker isolation class than Firecracker;
/// callers must select it only through the runtime policy layer.
#[derive(Clone)]
pub struct DockerRuntime {
    docker: Docker,
    root: PathBuf,
}

impl DockerRuntime {
    fn absolute_root(root: impl AsRef<Path>) -> PathBuf {
        let root = root.as_ref();
        if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()
                .map_or_else(|_| root.to_path_buf(), |directory| directory.join(root))
        }
    }

    pub fn new(root: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let docker = Docker::connect_with_unix_defaults().map_err(|error| {
            RuntimeError::Unavailable(format!("Docker daemon unavailable: {error}"))
        })?;
        Ok(Self {
            docker,
            root: Self::absolute_root(root),
        })
    }

    pub fn with_client(docker: Docker, root: impl AsRef<Path>) -> Self {
        Self {
            docker,
            root: Self::absolute_root(root),
        }
    }
    pub async fn export_workspace_archive(
        &self,
        sandbox: &Sandbox,
    ) -> Result<Vec<u8>, RuntimeError> {
        let workspace = self.workspace(sandbox);
        let mut entries = Vec::new();
        let mut total = 0_u64;
        collect_workspace(&workspace, &workspace, &mut entries, &mut total)
            .map_err(RuntimeError::Core)?;
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
        restore_workspace_archive(bytes, &self.workspace(sandbox)).map_err(RuntimeError::Core)
    }

    fn name(sandbox: &Sandbox) -> String {
        format!("aiec-{}", sandbox.id)
    }

    fn workspace(&self, sandbox: &Sandbox) -> PathBuf {
        self.root.join(sandbox.id.to_string()).join("workspace")
    }
    /// Removes containers left running for this sandbox by a superseded owner.
    ///
    /// Recovery hands a sandbox to a new worker while the previous worker's
    /// container may still exist. Only containers carrying this sandbox's
    /// AIec label are touched, so unrelated containers are never affected.
    async fn reclaim_orphaned_containers(&self, sandbox: &Sandbox) {
        // Docker expresses label selection as a `label` filter whose value is
        // `key=value`, not as a filter keyed by the label name.
        let mut filters: HashMap<String, Vec<String>> = HashMap::new();
        filters.insert(
            "label".to_string(),
            vec![
                format!("{LABEL_MANAGED}=true"),
                format!("{LABEL_SANDBOX}={}", sandbox.id),
            ],
        );
        let options = bollard::query_parameters::ListContainersOptionsBuilder::default()
            .all(true)
            .filters(&filters)
            .build();
        let Ok(containers) = self.docker.list_containers(Some(options)).await else {
            return;
        };
        let remove = bollard::query_parameters::RemoveContainerOptionsBuilder::new()
            .v(true)
            .force(true)
            .link(false)
            .build();
        for container in containers {
            let Some(id) = container.id else { continue };
            let _ = self
                .docker
                .remove_container(&id, Some(remove.clone()))
                .await;
        }
    }

    async fn exec_raw(
        &self,
        sandbox: &Sandbox,
        command: Vec<String>,
        working_directory: Option<String>,
        environment: std::collections::BTreeMap<String, String>,
        timeout: u64,
        stdin: Option<Vec<u8>>,
    ) -> Result<ExecResult, RuntimeError> {
        validate_environment(&environment)?;
        let config = bollard::exec::CreateExecOptions {
            attach_stdin: Some(stdin.is_some()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(false),
            cmd: Some(command),
            env: Some(
                environment
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect(),
            ),
            privileged: Some(false),
            user: None,
            working_dir: Some(
                working_directory
                    .map(|path| workspace_path(&path))
                    .transpose()?
                    .unwrap_or_else(|| "/workspace".into()),
            ),
            detach_keys: None,
        };
        let exec = self
            .docker
            .create_exec(&Self::name(sandbox), config)
            .await
            .map_err(|error| {
                RuntimeError::Unavailable(format!("Docker exec create failed: {error}"))
            })?;
        let started = self
            .docker
            .start_exec(&exec.id, None)
            .await
            .map_err(|error| {
                RuntimeError::Unavailable(format!("Docker exec start failed: {error}"))
            })?;
        let start = Instant::now();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        match started {
            StartExecResults::Attached {
                mut output,
                mut input,
            } => {
                if let Some(data) = stdin {
                    let _ = input.write_all(&data).await;
                }
                let _ = input.shutdown().await;
                let deadline =
                    tokio::time::Instant::now() + std::time::Duration::from_secs(timeout.max(1));
                loop {
                    let next = tokio::time::timeout_at(deadline, output.next()).await;
                    let item = match next {
                        Ok(item) => item,
                        Err(_) => {
                            return Ok(ExecResult {
                                exit_code: 124,
                                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                                stderr: format!(
                                    "{}\ncommand timed out",
                                    String::from_utf8_lossy(&stderr)
                                ),
                                duration_ms: start.elapsed().as_millis() as u64,
                                timed_out: true,
                            });
                        }
                    };
                    let Some(item) = item else { break };
                    let message = item.map_err(|error| {
                        RuntimeError::Unavailable(format!("Docker exec stream failed: {error}"))
                    })?;
                    match message {
                        LogOutput::StdOut { message } => stdout.extend_from_slice(&message),
                        LogOutput::Console { message } => stdout.extend_from_slice(&message),
                        LogOutput::StdErr { message } => stderr.extend_from_slice(&message),
                        LogOutput::StdIn { .. } => {}
                    }
                    if stdout.len().saturating_add(stderr.len()) > aiec_core::MAX_STDERR {
                        return Err(RuntimeError::Archive("Docker output limit exceeded".into()));
                    }
                }
            }
            StartExecResults::Detached => {
                return Err(RuntimeError::Unavailable(
                    "Docker exec detached unexpectedly".into(),
                ));
            }
        }
        let inspect = self.docker.inspect_exec(&exec.id).await.map_err(|error| {
            RuntimeError::Unavailable(format!("Docker exec inspect failed: {error}"))
        })?;
        Ok(ExecResult {
            exit_code: inspect.exit_code.unwrap_or(0) as i32,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            duration_ms: start.elapsed().as_millis() as u64,
            timed_out: false,
        })
    }
}

fn ensure_success(result: ExecResult) -> Result<(), aiec_core::CoreError> {
    if result.exit_code == 0 {
        Ok(())
    } else {
        Err(aiec_core::CoreError::Io(std::io::Error::other(
            result.stderr,
        )))
    }
}

#[async_trait]
impl SandboxRuntime for DockerRuntime {
    async fn create(&self, sandbox: &Sandbox) -> Result<(), aiec_core::CoreError> {
        let workspace = self.workspace(sandbox);
        tokio::fs::create_dir_all(&workspace)
            .await
            .map_err(|error| crate::into_core(RuntimeError::Io(error)))?;
        tokio::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o777))
            .await
            .map_err(|error| crate::into_core(RuntimeError::Io(error)))?;
        // Reclaim runtime state left behind by a superseded owner.
        //
        // A worker that dies mid-flight leaves its container running. A new
        // owner cannot place the sandbox while that container still holds the
        // sandbox's container name, and the orphan would keep running forever.
        // Placement is issued by the control plane only after it has reassigned
        // ownership, so anything still labelled with this sandbox id belongs to
        // a superseded owner.
        self.reclaim_orphaned_containers(sandbox).await;
        let mut labels = HashMap::new();
        labels.insert(LABEL_MANAGED.into(), "true".into());
        labels.insert(LABEL_SANDBOX.into(), sandbox.id.to_string());
        labels.insert(LABEL_TENANT.into(), sandbox.tenant_id.to_string());
        let network = container_network_mode(&sandbox.network)?;
        let mount = Mount {
            target: Some("/workspace".into()),
            source: Some(workspace.to_string_lossy().into_owned()),
            typ: Some(MountType::BIND),
            read_only: Some(false),
            ..Default::default()
        };
        if self.docker.inspect_image(&sandbox.image_id).await.is_err() {
            let options = bollard::query_parameters::CreateImageOptionsBuilder::new()
                .from_image(&sandbox.image_id)
                .build();
            let mut pull = self.docker.create_image(Some(options), None, None);
            while let Some(item) = pull.next().await {
                item.map_err(|error| {
                    crate::into_core(RuntimeError::Unavailable(format!(
                        "Docker image pull failed: {error}"
                    )))
                })?;
            }
        }
        let body = ContainerCreateBody {
            image: Some(sandbox.image_id.clone()),
            cmd: Some(vec!["sh".into(), "-c".into(), "sleep 3600".into()]),
            tty: Some(true),
            open_stdin: Some(true),
            labels: Some(labels),
            working_dir: Some("/workspace".into()),
            host_config: Some(HostConfig {
                network_mode: Some(network.into()),
                dns: host_resolvers(),
                cap_drop: Some(vec!["ALL".into()]),
                pids_limit: Some(128),
                memory: Some(i64::from(sandbox.memory_mb) * 1024 * 1024),
                nano_cpus: Some(i64::from(sandbox.cpu) * 1_000_000_000),
                readonly_rootfs: Some(true),
                mounts: Some(vec![mount]),
                security_opt: Some(vec!["no-new-privileges:true".into()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let options = bollard::query_parameters::CreateContainerOptionsBuilder::new()
            .name(&Self::name(sandbox))
            .build();
        self.docker
            .create_container(Some(options), body)
            .await
            .map_err(|error| {
                crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker container create failed: {error}"
                )))
            })?;
        Ok(())
    }
    async fn start(&self, sandbox: &Sandbox) -> Result<(), aiec_core::CoreError> {
        self.docker
            .start_container(&Self::name(sandbox), None)
            .await
            .map_err(|error| {
                crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker container start failed: {error}"
                )))
            })
    }
    async fn stop(&self, sandbox: &Sandbox) -> Result<(), aiec_core::CoreError> {
        let options = bollard::query_parameters::StopContainerOptionsBuilder::new()
            .signal("SIGTERM")
            .t(10)
            .build();
        self.docker
            .stop_container(&Self::name(sandbox), Some(options))
            .await
            .map_err(|error| {
                crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker container stop failed: {error}"
                )))
            })
    }
    async fn pause(&self, sandbox: &Sandbox) -> Result<(), aiec_core::CoreError> {
        self.docker
            .pause_container(&Self::name(sandbox))
            .await
            .map_err(|error| {
                crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker pause failed: {error}"
                )))
            })
    }
    async fn resume(&self, sandbox: &Sandbox) -> Result<(), aiec_core::CoreError> {
        self.docker
            .unpause_container(&Self::name(sandbox))
            .await
            .map_err(|error| {
                crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker unpause failed: {error}"
                )))
            })
    }
    async fn exec(
        &self,
        sandbox: &Sandbox,
        request: ExecRequest,
    ) -> Result<ExecResult, aiec_core::CoreError> {
        self.exec_raw(
            sandbox,
            request.command,
            request.working_directory,
            request.environment,
            request.timeout_seconds,
            request.stdin.map(String::into_bytes),
        )
        .await
        .map_err(crate::into_core)
    }
    async fn put_file(
        &self,
        sandbox: &Sandbox,
        request: PutFileRequest,
    ) -> Result<(), aiec_core::CoreError> {
        let path = workspace_path(&request.path)?;
        let content = decode_file_content(&request.content_base64).map_err(crate::into_core)?;
        let parent = parent_path(&path);
        let mkdir = self
            .exec_raw(
                sandbox,
                vec!["mkdir".into(), "-p".into(), "--".into(), parent],
                None,
                Default::default(),
                30,
                None,
            )
            .await
            .map_err(crate::into_core)?;
        ensure_success(mkdir)?;
        let result = self
            .exec_raw(
                sandbox,
                vec![
                    "sh".into(),
                    "-c".into(),
                    "cat > \"$1\"".into(),
                    "aiec-file".into(),
                    path,
                ],
                None,
                Default::default(),
                30,
                Some(content),
            )
            .await
            .map_err(crate::into_core)?;
        ensure_success(result)?;
        if let Some(mode) = request.mode {
            let mode = mode & 0o7777;
            let chmod = self
                .exec_raw(
                    sandbox,
                    vec![
                        "chmod".into(),
                        format!("{mode:o}"),
                        "--".into(),
                        workspace_path(&request.path)?,
                    ],
                    None,
                    Default::default(),
                    30,
                    None,
                )
                .await
                .map_err(crate::into_core)?;
            ensure_success(chmod)?;
        }
        Ok(())
    }
    async fn get_file(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<FileContent, aiec_core::CoreError> {
        let path = workspace_path(path)?;
        let name =
            archive_name(path.rsplit('/').next().unwrap_or_default()).map_err(crate::into_core)?;
        let options = bollard::query_parameters::DownloadFromContainerOptionsBuilder::new()
            .path(&path)
            .build();
        let mut stream = self
            .docker
            .download_from_container(&Self::name(sandbox), Some(options));
        let mut archive = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker file download failed: {error}"
                )))
            })?;
            if archive.len().saturating_add(chunk.len()) > aiec_core::MAX_FILE.saturating_mul(2) {
                return Err(aiec_core::CoreError::LimitExceeded(
                    "Docker file download".into(),
                ));
            }
            archive.extend_from_slice(&chunk);
        }
        let content = extract_file_archive(&archive, &name).map_err(crate::into_core)?;
        Ok(FileContent {
            path,
            content_base64: base64::engine::general_purpose::STANDARD.encode(content),
        })
    }
    async fn list_files(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<Vec<FileEntry>, aiec_core::CoreError> {
        let path = workspace_path(path)?;
        let options = bollard::query_parameters::DownloadFromContainerOptionsBuilder::new()
            .path(&path)
            .build();
        let mut stream = self
            .docker
            .download_from_container(&Self::name(sandbox), Some(options));
        let mut archive = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker directory download failed: {error}"
                )))
            })?;
            if archive.len().saturating_add(chunk.len()) > aiec_core::MAX_FILE.saturating_mul(2) {
                return Err(aiec_core::CoreError::LimitExceeded(
                    "Docker directory listing".into(),
                ));
            }
            archive.extend_from_slice(&chunk);
        }
        extract_directory_archive(&archive, &path).map_err(crate::into_core)
    }
    async fn delete_file(
        &self,
        sandbox: &Sandbox,
        request: DeleteFileRequest,
    ) -> Result<(), aiec_core::CoreError> {
        let path = workspace_path(&request.path)?;
        let result = self
            .exec_raw(
                sandbox,
                vec!["rm".into(), "--".into(), path],
                None,
                Default::default(),
                30,
                None,
            )
            .await
            .map_err(crate::into_core)?;
        ensure_success(result)
    }
    async fn make_directory(
        &self,
        sandbox: &Sandbox,
        request: MakeDirectoryRequest,
    ) -> Result<(), aiec_core::CoreError> {
        let path = workspace_path(&request.path)?;
        let result = self
            .exec_raw(
                sandbox,
                vec!["mkdir".into(), "-p".into(), "--".into(), path],
                None,
                Default::default(),
                30,
                None,
            )
            .await
            .map_err(crate::into_core)?;
        ensure_success(result)
    }
    async fn import_workspace_archive(
        &self,
        sandbox: &Sandbox,
        archive: &[u8],
    ) -> Result<(), aiec_core::CoreError> {
        // The workspace is materialized on this worker's own disk, so an
        // archive captured by any other worker applies here unchanged.
        Self::import_workspace_archive(self, sandbox, archive)
            .await
            .map_err(crate::into_core)
    }
    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), aiec_core::CoreError> {
        let options = bollard::query_parameters::RemoveContainerOptionsBuilder::new()
            .v(true)
            .force(true)
            .link(false)
            .build();
        match self
            .docker
            .remove_container(&Self::name(sandbox), Some(options))
            .await
        {
            Ok(_) => {}
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(error) => {
                return Err(crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker container destroy failed: {error}"
                ))));
            }
        }
        match tokio::fs::remove_dir_all(self.root.join(sandbox.id.to_string())).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(crate::into_core(RuntimeError::Io(error))),
        }
    }
    async fn health(&self) -> RuntimeHealth {
        match self.docker.ping().await {
            Ok(_) => RuntimeHealth::healthy(),
            Err(error) => RuntimeHealth::unhealthy(format!("Docker daemon unavailable: {error}")),
        }
    }
    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            isolation: aiec_core::runtime::RuntimeIsolation::Container,
            exec: true,
            files: true,
            portable_workspace: true,
            network_policy: false,
            workspace_snapshot: true,
            ..RuntimeCapabilities::default()
        }
    }
}
fn validate_snapshot_key(key: &str) -> Result<(), aiec_core::CoreError> {
    crate::validate_archive_key(key)
        .map_err(|error| aiec_core::CoreError::Io(std::io::Error::other(error.to_string())))
}

fn collect_workspace(
    root: &Path,
    current: &Path,
    entries: &mut Vec<PortableWorkspaceEntry>,
    total: &mut u64,
) -> Result<(), aiec_core::CoreError> {
    for item in std::fs::read_dir(current).map_err(aiec_core::CoreError::Io)? {
        let item = item.map_err(aiec_core::CoreError::Io)?;
        let path = item.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(aiec_core::CoreError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(aiec_core::CoreError::Backend(
                "workspace snapshot contains a link".into(),
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| aiec_core::CoreError::Backend("workspace path escaped root".into()))?;
        let archive_path = format!(
            "/workspace/{}",
            relative.to_string_lossy().replace('\\', "/")
        );
        if metadata.is_dir() {
            entries.push(PortableWorkspaceEntry {
                path: archive_path.clone(),
                directory: true,
                content_base64: String::new(),
            });
            if entries.len() > 10_000 {
                return Err(aiec_core::CoreError::LimitExceeded(
                    "workspace snapshot has too many members".into(),
                ));
            }
            collect_workspace(root, &path, entries, total)?;
        } else if metadata.is_file() {
            let content = std::fs::read(&path).map_err(aiec_core::CoreError::Io)?;
            *total = total.checked_add(content.len() as u64).ok_or_else(|| {
                aiec_core::CoreError::Backend("workspace snapshot size overflow".into())
            })?;
            if *total > crate::MAX_WORKSPACE_ARCHIVE_BYTES as u64 {
                return Err(aiec_core::CoreError::LimitExceeded(
                    "workspace snapshot exceeds 64 MiB".into(),
                ));
            }
            entries.push(PortableWorkspaceEntry {
                path: archive_path,
                directory: false,
                content_base64: base64::engine::general_purpose::STANDARD.encode(content),
            });
            if entries.len() > 10_000 {
                return Err(aiec_core::CoreError::LimitExceeded(
                    "workspace snapshot has too many members".into(),
                ));
            }
        } else {
            return Err(aiec_core::CoreError::Backend(
                "workspace snapshot contains a special entry".into(),
            ));
        }
    }
    Ok(())
}

fn restore_workspace_archive(bytes: &[u8], workspace: &Path) -> Result<(), aiec_core::CoreError> {
    let archive: PortableWorkspaceArchive = serde_json::from_slice(bytes)
        .map_err(|error| aiec_core::CoreError::Backend(error.to_string()))?;
    if archive.version != 1 || archive.entries.len() > 10_000 {
        return Err(aiec_core::CoreError::Backend(
            "invalid portable workspace archive".into(),
        ));
    }

    let mut decoded = Vec::with_capacity(archive.entries.len());
    let mut total = 0_u64;
    for entry in archive.entries {
        let Some(relative) = entry.path.strip_prefix("/workspace/") else {
            return Err(aiec_core::CoreError::Backend(
                "invalid portable workspace path".into(),
            ));
        };
        if relative.is_empty()
            || Path::new(relative)
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(aiec_core::CoreError::Backend(
                "invalid portable workspace path".into(),
            ));
        }
        if entry.directory {
            decoded.push((PathBuf::from(relative), true, Vec::new()));
            continue;
        }
        let content = base64::engine::general_purpose::STANDARD
            .decode(&entry.content_base64)
            .map_err(|_| {
                aiec_core::CoreError::Backend("invalid portable workspace encoding".into())
            })?;
        total = total.checked_add(content.len() as u64).ok_or_else(|| {
            aiec_core::CoreError::Backend("workspace snapshot size overflow".into())
        })?;
        if total > crate::MAX_WORKSPACE_ARCHIVE_BYTES as u64 {
            return Err(aiec_core::CoreError::LimitExceeded(
                "workspace snapshot exceeds 64 MiB".into(),
            ));
        }
        decoded.push((PathBuf::from(relative), false, content));
    }

    let mut paths = std::collections::HashMap::with_capacity(decoded.len());
    for (relative, directory, _) in &decoded {
        if paths.insert(relative.clone(), *directory).is_some() {
            return Err(aiec_core::CoreError::InvalidRequest(
                "workspace snapshot contains duplicate paths".into(),
            ));
        }
    }
    for (relative, directory) in &paths {
        for ancestor in relative.ancestors().skip(1) {
            if paths
                .get(ancestor)
                .is_some_and(|is_directory| !is_directory)
            {
                return Err(aiec_core::CoreError::InvalidRequest(
                    "workspace snapshot contains a file/directory conflict".into(),
                ));
            }
        }
        if !*directory
            && paths
                .keys()
                .any(|other| other != relative && other.starts_with(relative))
        {
            return Err(aiec_core::CoreError::InvalidRequest(
                "workspace snapshot contains a file/directory conflict".into(),
            ));
        }
    }

    let parent = workspace
        .parent()
        .ok_or_else(|| aiec_core::CoreError::Backend("workspace has no parent directory".into()))?;
    std::fs::create_dir_all(parent).map_err(aiec_core::CoreError::Io)?;
    let staging = parent.join(format!(".workspace-restore-{}", Uuid::now_v7()));
    let backup = parent.join(format!(".workspace-backup-{}", Uuid::now_v7()));
    let result = (|| {
        std::fs::create_dir(&staging).map_err(aiec_core::CoreError::Io)?;
        for (relative, directory, content) in decoded {
            let target = staging.join(relative);
            if directory {
                std::fs::create_dir_all(&target).map_err(aiec_core::CoreError::Io)?;
            } else {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(aiec_core::CoreError::Io)?;
                }
                std::fs::write(&target, content).map_err(aiec_core::CoreError::Io)?;
            }
        }
        let had_workspace = workspace.exists();
        if !had_workspace {
            std::fs::create_dir_all(workspace).map_err(aiec_core::CoreError::Io)?;
        }
        if had_workspace {
            std::fs::create_dir(&backup).map_err(aiec_core::CoreError::Io)?;
            for entry in std::fs::read_dir(workspace).map_err(aiec_core::CoreError::Io)? {
                let entry = entry.map_err(aiec_core::CoreError::Io)?;
                std::fs::rename(entry.path(), backup.join(entry.file_name()))
                    .map_err(aiec_core::CoreError::Io)?;
            }
        }
        let remove_path = |path: &Path| -> Result<(), aiec_core::CoreError> {
            let metadata = std::fs::symlink_metadata(path).map_err(aiec_core::CoreError::Io)?;
            if metadata.file_type().is_dir() {
                std::fs::remove_dir_all(path).map_err(aiec_core::CoreError::Io)
            } else {
                std::fs::remove_file(path).map_err(aiec_core::CoreError::Io)
            }
        };
        let mut moved = Vec::new();
        let mut replacement_error = None;
        for entry in std::fs::read_dir(&staging).map_err(aiec_core::CoreError::Io)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    replacement_error = Some(error);
                    break;
                }
            };
            let name = entry.file_name();
            if let Err(error) = std::fs::rename(entry.path(), workspace.join(&name)) {
                replacement_error = Some(error);
                break;
            }
            moved.push(name);
        }
        if let Some(error) = replacement_error {
            let mut rollback_error = None;
            for name in moved.iter().rev() {
                if let Err(cleanup_error) = remove_path(&workspace.join(name))
                    && rollback_error.is_none()
                {
                    rollback_error = Some(cleanup_error);
                }
            }
            if had_workspace {
                let entries = std::fs::read_dir(&backup).map_err(|error| {
                    aiec_core::CoreError::Io(std::io::Error::other(format!(
                        "rollback could not read backup {}: {error}",
                        backup.display()
                    )))
                });
                match entries {
                    Ok(entries) => {
                        for entry in entries {
                            let entry = match entry {
                                Ok(entry) => entry,
                                Err(error) => {
                                    if rollback_error.is_none() {
                                        rollback_error = Some(aiec_core::CoreError::Io(
                                            std::io::Error::other(format!(
                                                "rollback could not read backup entry in {}: {error}",
                                                backup.display()
                                            )),
                                        ));
                                    }
                                    break;
                                }
                            };
                            match std::fs::rename(entry.path(), workspace.join(entry.file_name())) {
                                Ok(()) => {}
                                Err(restore_error) => {
                                    if rollback_error.is_none() {
                                        rollback_error =
                                            Some(aiec_core::CoreError::Io(restore_error));
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    Err(rollback_read_error) => rollback_error = Some(rollback_read_error),
                }
            }
            if let Some(rollback_error) = rollback_error {
                return Err(aiec_core::CoreError::Io(std::io::Error::other(format!(
                    "workspace restore replacement failed: {error}; rollback failed: {rollback_error}; backup preserved at {}",
                    backup.display()
                ))));
            }
            return Err(aiec_core::CoreError::Io(error));
        }
        std::fs::remove_dir_all(&staging).map_err(|error| {
            aiec_core::CoreError::Io(std::io::Error::other(format!(
                "workspace restored but staging cleanup failed at {}: {error}",
                staging.display()
            )))
        })?;
        if had_workspace {
            std::fs::remove_dir_all(&backup).map_err(|error| {
                aiec_core::CoreError::Io(std::io::Error::other(format!(
                    "workspace restored but backup cleanup failed at {}: {error}",
                    backup.display()
                )))
            })?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

#[async_trait]
impl SnapshotProvider for DockerRuntime {
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
    ) -> Result<CapturedSnapshot, aiec_core::CoreError> {
        if request.kind != aiec_core::snapshots::SnapshotKind::Workspace {
            return Err(aiec_core::CoreError::Unsupported(
                "Docker supports portable workspace snapshots only".into(),
            ));
        }
        validate_snapshot_key(&request.object_key)?;
        let workspace = self.workspace(sandbox);
        let mut entries = Vec::new();
        let mut total = 0_u64;
        collect_workspace(&workspace, &workspace, &mut entries, &mut total)?;
        let bytes = serde_json::to_vec(&PortableWorkspaceArchive {
            version: 1,
            entries,
        })
        .map_err(|error| aiec_core::CoreError::Backend(error.to_string()))?;
        if bytes.len() > crate::MAX_WORKSPACE_ARCHIVE_BYTES {
            return Err(aiec_core::CoreError::LimitExceeded(
                "workspace snapshot exceeds 64 MiB".into(),
            ));
        }
        // The bytes travel back to the control plane, which persists them in
        // shared object storage. The local copy only serves this runtime's own
        // `restore`; recovery of a sandbox captured by a dead worker reads the
        // shared object instead.
        let archive = self
            .root
            .join("snapshots")
            .join(format!("{}.json", request.object_key));
        if let Some(parent) = archive.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(aiec_core::CoreError::Io)?;
        }
        tokio::fs::write(&archive, &bytes)
            .await
            .map_err(aiec_core::CoreError::Io)?;
        Ok(CapturedSnapshot::from_archive(
            Uuid::now_v7(),
            request.kind,
            request.object_key.clone(),
            bytes,
        ))
    }

    async fn restore(
        &self,
        sandbox: &Sandbox,
        metadata: &SnapshotMetadata,
    ) -> Result<(), aiec_core::CoreError> {
        if metadata.kind != aiec_core::snapshots::SnapshotKind::Workspace {
            return Err(aiec_core::CoreError::Unsupported(
                "Docker supports portable workspace snapshots only".into(),
            ));
        }
        validate_snapshot_key(&metadata.object_key)?;
        let archive = self
            .root
            .join("snapshots")
            .join(format!("{}.json", metadata.object_key));
        let bytes = tokio::fs::read(&archive)
            .await
            .map_err(aiec_core::CoreError::Io)?;
        if bytes.len() > crate::MAX_WORKSPACE_ARCHIVE_BYTES {
            return Err(aiec_core::CoreError::LimitExceeded(
                "workspace snapshot exceeds 64 MiB".into(),
            ));
        }
        if hex::encode(sha2::Sha256::digest(&bytes)) != metadata.checksum_sha256 {
            return Err(aiec_core::CoreError::Conflict(
                "Docker workspace snapshot checksum mismatch".into(),
            ));
        }
        restore_workspace_archive(&bytes, &self.workspace(sandbox))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn docker_runtime_normalizes_relative_root_without_requiring_existence() {
        let docker = Docker::connect_with_unix_defaults().expect("Docker client");
        let runtime = DockerRuntime::with_client(docker, "relative-root-for-test");
        let now = chrono::Utc::now();
        let sandbox = Sandbox {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            node_id: None,
            image_id: "alpine:3.21".into(),
            state: aiec_core::SandboxState::Creating,
            runtime: aiec_core::RuntimeKind::Docker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: aiec_core::NetworkPolicy::Disabled,
            environment: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        };
        let root = runtime.workspace(&sandbox);
        assert!(root.is_absolute());
        assert!(root.to_string_lossy().contains("relative-root-for-test"));
    }

    #[test]
    fn restricted_network_fails_closed() {
        let policy = NetworkPolicy::Restricted {
            allowed_hosts: vec!["example.com".into()],
        };
        assert!(matches!(
            container_network_mode(&policy),
            Err(aiec_core::CoreError::Unsupported(_))
        ));
    }

    #[test]
    fn environment_rejects_invalid_keys_and_values() {
        let mut environment = std::collections::BTreeMap::new();
        environment.insert("BAD=KEY".into(), "value".into());
        assert!(validate_environment(&environment).is_err());
        environment.clear();
        environment.insert("GOOD".into(), "bad\0value".into());
        assert!(validate_environment(&environment).is_err());
    }

    #[test]
    fn file_content_enforces_decoded_limit() {
        let oversized =
            base64::engine::general_purpose::STANDARD.encode(vec![0; aiec_core::MAX_FILE + 1]);
        assert!(decode_file_content(&oversized).is_err());
    }

    #[test]
    fn archive_rejects_traversal_and_link_entries() {
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("../escape").unwrap();
        header.set_cksum();
        archive.append_data(&mut header, "link", &b"x"[..]).unwrap();
        let bytes = archive.into_inner().unwrap();
        assert!(extract_file_archive(&bytes, "link").is_err());
        assert!(archive_name("../escape").is_err());
    }

    #[test]
    fn directory_archive_lists_regular_file_and_rejects_special_entry() {
        let mut archive = tar::Builder::new(Vec::new());
        let mut file_header = tar::Header::new_gnu();
        file_header.set_size(1);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        archive
            .append_data(&mut file_header, "workspace/proof.txt", &b"x"[..])
            .unwrap();
        let bytes = archive.into_inner().unwrap();
        let mut nested = tar::Builder::new(Vec::new());
        let mut nested_header = tar::Header::new_gnu();
        nested_header.set_size(1);
        nested_header.set_mode(0o644);
        nested_header.set_cksum();
        nested
            .append_data(&mut nested_header, "workspace/nested/proof.txt", &b"x"[..])
            .unwrap();
        let nested_files =
            extract_directory_archive(&nested.into_inner().unwrap(), "/workspace/nested").unwrap();
        assert_eq!(nested_files[0].name, "proof.txt");
        assert_eq!(nested_files[0].path, "/workspace/nested/proof.txt");
        let files = extract_directory_archive(&bytes, "/workspace").unwrap();
        assert_eq!(files[0].name, "proof.txt");
        let mut unrelated = tar::Builder::new(Vec::new());
        let mut unrelated_header = tar::Header::new_gnu();
        unrelated_header.set_size(1);
        unrelated_header.set_mode(0o644);
        unrelated_header.set_cksum();
        unrelated
            .append_data(&mut unrelated_header, "other/proof.txt", &b"x"[..])
            .unwrap();
        assert!(
            extract_directory_archive(&unrelated.into_inner().unwrap(), "/workspace")
                .unwrap()
                .is_empty()
        );
        let mut special = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_size(0);
        header.set_cksum();
        special
            .append_data(&mut header, "workspace/pipe", &b""[..])
            .unwrap();
        assert!(extract_directory_archive(&special.into_inner().unwrap(), "/workspace").is_err());
    }
    #[test]
    fn invalid_archive_does_not_delete_existing_workspace() {
        let root = std::env::temp_dir().join(format!("af-invalid-restore-{}", Uuid::now_v7()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("marker"), b"keep").unwrap();
        let bytes = serde_json::to_vec(&PortableWorkspaceArchive {
            version: 1,
            entries: vec![
                PortableWorkspaceEntry {
                    path: "/workspace/new.txt".into(),
                    directory: false,
                    content_base64: "bmV3".into(),
                },
                PortableWorkspaceEntry {
                    path: "/workspace/../escape".into(),
                    directory: false,
                    content_base64: "ZXNjYXBl".into(),
                },
            ],
        })
        .unwrap();
        assert!(restore_workspace_archive(&bytes, &workspace).is_err());
        assert_eq!(std::fs::read(workspace.join("marker")).unwrap(), b"keep");
        assert!(!workspace.join("new.txt").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn archive_rejects_duplicate_and_file_directory_conflicts() {
        let root = std::env::temp_dir().join(format!("af-conflict-restore-{}", Uuid::now_v7()));
        let workspace = root.join("workspace");
        let duplicate = serde_json::to_vec(&PortableWorkspaceArchive {
            version: 1,
            entries: vec![
                PortableWorkspaceEntry {
                    path: "/workspace/file".into(),
                    directory: false,
                    content_base64: "YQ==".into(),
                },
                PortableWorkspaceEntry {
                    path: "/workspace/file".into(),
                    directory: false,
                    content_base64: "Yg==".into(),
                },
            ],
        })
        .unwrap();
        assert!(restore_workspace_archive(&duplicate, &workspace).is_err());
        let ancestor = serde_json::to_vec(&PortableWorkspaceArchive {
            version: 1,
            entries: vec![
                PortableWorkspaceEntry {
                    path: "/workspace/file".into(),
                    directory: false,
                    content_base64: "YQ==".into(),
                },
                PortableWorkspaceEntry {
                    path: "/workspace/file/child".into(),
                    directory: false,
                    content_base64: "Yg==".into(),
                },
            ],
        })
        .unwrap();
        assert!(restore_workspace_archive(&ancestor, &workspace).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn successful_archive_restore_replaces_workspace_and_cleans_backup() {
        let root = std::env::temp_dir().join(format!("af-successful-restore-{}", Uuid::now_v7()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("old"), b"old").unwrap();
        let bytes = serde_json::to_vec(&PortableWorkspaceArchive {
            version: 1,
            entries: vec![PortableWorkspaceEntry {
                path: "/workspace/new".into(),
                directory: false,
                content_base64: "bmV3".into(),
            }],
        })
        .unwrap();
        restore_workspace_archive(&bytes, &workspace).unwrap();
        assert!(!workspace.join("old").exists());
        assert_eq!(std::fs::read(workspace.join("new")).unwrap(), b"new");
        let leftovers = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".workspace-")
            })
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn empty_directory_archive_is_an_empty_listing() {
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        archive
            .append_data(&mut header, "workspace", &b""[..])
            .unwrap();
        let files =
            extract_directory_archive(&archive.into_inner().unwrap(), "/workspace").unwrap();
        assert!(files.is_empty());
    }

    fn sandbox_fixture() -> Sandbox {
        let now = chrono::Utc::now();
        Sandbox {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            node_id: None,
            image_id: "alpine:3.21".into(),
            state: aiec_core::SandboxState::Running,
            runtime: aiec_core::RuntimeKind::Docker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: aiec_core::NetworkPolicy::Disabled,
            environment: Default::default(),
            created_at: now,
            updated_at: now,
            runtime_path: None,
        }
    }

    /// A worker that dies takes its state directory with it, so the archive a
    /// capture returns has to stand on its own. This exercises the whole
    /// handoff: capture on one runtime, import on another that has never seen
    /// the first one's disk, after the first one's disk is gone.
    #[tokio::test]
    async fn a_captured_workspace_reaches_a_different_worker() {
        let first = std::env::temp_dir().join(format!("af-capture-{}", Uuid::now_v7()));
        let second = std::env::temp_dir().join(format!("af-adopt-{}", Uuid::now_v7()));
        let sandbox = sandbox_fixture();
        let source = DockerRuntime::with_client(
            Docker::connect_with_unix_defaults().expect("Docker client"),
            &first,
        );
        std::fs::create_dir_all(source.workspace(&sandbox)).unwrap();
        std::fs::write(
            source.workspace(&sandbox).join("notes.txt"),
            b"durable state",
        )
        .unwrap();

        let captured = source
            .capture(
                &sandbox,
                &SnapshotRequest {
                    kind: aiec_core::snapshots::SnapshotKind::Workspace,
                    object_key: "capture-1".into(),
                },
            )
            .await
            .expect("capture workspace");
        assert!(!captured.archive.is_empty());
        assert_eq!(captured.size_bytes, captured.archive.len() as u64);
        assert_eq!(
            captured.checksum_sha256,
            hex::encode(sha2::Sha256::digest(&captured.archive))
        );

        // The worker that will own the sandbox has no copy of the capture.
        std::fs::remove_dir_all(&first).unwrap();
        let target = DockerRuntime::with_client(
            Docker::connect_with_unix_defaults().expect("Docker client"),
            &second,
        );
        SandboxRuntime::import_workspace_archive(&target, &sandbox, &captured.archive)
            .await
            .expect("import workspace archive");
        assert_eq!(
            std::fs::read(target.workspace(&sandbox).join("notes.txt")).unwrap(),
            b"durable state"
        );
        let _ = std::fs::remove_dir_all(second);
    }
}

#[cfg(test)]
mod resolver_tests {
    use super::is_reachable_nameserver;

    /// A container handed a loopback resolver resolves against its own
    /// loopback, where nothing listens. Every lookup fails, instantly, with an
    /// error that looks like the workload's fault.
    #[test]
    fn loopback_resolvers_are_never_handed_to_a_container() {
        for stub in [
            "127.0.0.53", // systemd-resolved
            "127.0.0.11", // Docker's embedded resolver
            "127.0.0.1",
            "::1",
        ] {
            assert!(
                !is_reachable_nameserver(stub),
                "{stub} is reachable only from the host's own loopback"
            );
        }
    }

    #[test]
    fn real_resolvers_are_kept() {
        for good in ["1.1.1.1", "8.8.8.8", "192.168.1.1", "2606:4700:4700::1111"] {
            assert!(is_reachable_nameserver(good), "{good} should be kept");
        }
    }
}
