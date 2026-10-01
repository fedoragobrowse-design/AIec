use crate::{RuntimeError, SandboxRuntime};
use aiec_core::runtime::{FileChunk, FileChunkRequest, RuntimeCapabilities, RuntimeHealth};
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
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
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
/// The remaining unreachable addresses are not loopback, so a
/// "not loopback" test passes them, and each was observed on this deployment
/// to turn every lookup in a sandbox into `gaierror(-3)`:
///
/// - `0.0.0.0` and `::` are the unspecified address, which names no host at
///   all. glibc treats it as "this machine", so a container asks itself.
/// - `255.255.255.255` is the limited broadcast address.
/// - `ff02::1` is the all-nodes multicast group, which requires a scope and a
///   route that a container's default namespace does not have.
/// - `fe80::/10` is IPv6 link-local. Unlike its IPv4 peer it carries no
///   embedded scope, so an unzoned `fe80::` address is unroutable, and the
///   daemon rejects a zoned one outright rather than resolving it.
///
/// IPv4 link-local (`169.254.0.0/16`) is deliberately still allowed: it is the
/// only resolvers a rootless podman host can have, and it is reachable from a
/// bridge container there. `169.254.2.1` is not, but a host that lists it has
/// no resolver worth inheriting either way, and dropping the whole range would
/// break the working case.
///
/// Passing any of these through would trade "no resolver configured" for
/// "total, silent DNS failure", which is strictly worse than leaving the
/// daemon's default in place.
fn is_reachable_nameserver(address: &str) -> bool {
    let address = address.trim();
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            !v4.is_loopback() && !v4.is_unspecified() && !v4.is_broadcast() && !v4.is_multicast()
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                // `fe80::/10`: link-local, which needs a scope this address
                // cannot carry.
                && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
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
/// breaking the hosts that only have an unreachable one.
fn host_resolvers() -> Option<Vec<String>> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    parse_resolvers(&contents)
}

/// Every reachable nameserver in a `resolv.conf`, in the order it lists them.
///
/// `resolv.conf` permits several addresses on one `nameserver` line. The
/// container API takes one address per entry and rejects a value containing
/// whitespace outright, so handing it `"1.1.1.1 1.0.0.1"` fails container
/// creation outright. The line is split rather than passed along whole, which
/// also keeps the per-address filter meaningful: dropping the line instead
/// would discard resolvers that are perfectly reachable.
fn parse_resolvers(contents: &str) -> Option<Vec<String>> {
    let servers: Vec<String> = contents
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .flat_map(str::split_whitespace)
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

/// Opens a directory without following a link to it.
///
/// Every workspace walk starts here and reaches everything below it through
/// descriptors, so a name the guest can rewrite can never redirect one
/// outside the workspace it was handed.
fn open_directory(path: &Path) -> Result<std::fs::File, std::io::Error> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// Opens the entry `name` inside `directory`, without following it.
fn open_entry(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
) -> Result<std::fs::File, std::io::Error> {
    let name = entry_name(name)?;
    // `openat` rather than a path: that is the whole point of the walk. The
    // name was classified a moment ago, and the object this reaches is
    // whatever it is *now*, without traversing anything on the way to it.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// What an entry inside an open directory is, without following it.
fn entry_stat(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
) -> Result<libc::stat, std::io::Error> {
    let name = entry_name(name)?;
    let mut raw = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            raw.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { raw.assume_init() })
}

/// What a mode says its entry is, stripped of permissions.
///
/// `libc` exports the `S_IF*` values but not the `S_IS*` predicates, so every
/// type test in this file goes through this mask rather than repeating it.
fn file_type(mode: libc::mode_t) -> libc::mode_t {
    mode & libc::S_IFMT
}

fn entry_name(name: &std::ffi::OsStr) -> Result<std::ffi::CString, std::io::Error> {
    // A directory entry cannot contain a NUL, so this never rejects a name the
    // kernel handed us; it keeps the pointer below well formed.
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
}

/// Owns the directory stream `fdopendir` built, so an early return cannot leak
/// the descriptor it took over.
struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

/// Every name directly inside an open directory, read through its descriptor.
///
/// Read through the descriptor rather than by path, because the names are what
/// the walk then opens: a list gathered from the path describes whatever the
/// path names *now*, which is the very thing the guest is rewriting. `limit`
/// bounds the list, since a directory the guest can fill is also a way to spend
/// the worker's memory before any budget applies.
fn directory_entry_names(
    directory: &std::fs::File,
    limit: usize,
) -> Result<Vec<std::ffi::OsString>, RuntimeError> {
    // `fdopendir` takes ownership of the descriptor it is handed, so it gets
    // its own: the caller's stays open for the entry opens below.
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }
    let handle = unsafe { libc::fdopendir(duplicate) };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(RuntimeError::Io(error));
    }
    let stream = DirectoryStream(handle);
    let mut names = Vec::new();
    loop {
        // `readdir` reports the end of a directory and a failed read the same
        // way - a null pointer - and only errno separates them. A silent
        // truncation here would archive a workspace that is missing files.
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) != 0 {
                return Err(RuntimeError::Io(error));
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() == limit {
            return Err(RuntimeError::Archive(format!(
                "directory holds more than {limit} entries"
            )));
        }
        names.push(std::ffi::OsString::from_vec(name.to_vec()));
    }
    // The archive is checksummed and stored, so one workspace should produce
    // one set of bytes: a directory's own order is not stable, and a snapshot
    // that reshuffles on every capture is not reproducible.
    names.sort_unstable();
    Ok(names)
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
        collect_workspace(&workspace, &mut entries, &mut total).map_err(RuntimeError::Core)?;
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

    /// Opens the workspace directory `path` names, by descriptor.
    ///
    /// The container's `/workspace` is this bind mount, so a directory listing
    /// is a question about this directory and nothing below it - which is why
    /// it is answered from here rather than from the daemon's recursive
    /// archive of the whole tree.
    ///
    /// Each component is opened without following a link. `safe_path` has
    /// already rejected traversal and anything outside the workspace, so the
    /// only way a component could still redirect this walk is a link the guest
    /// put there, and that is refused rather than followed.
    fn open_workspace_directory(
        &self,
        sandbox: &Sandbox,
        path: &str,
    ) -> Result<std::fs::File, aiec_core::CoreError> {
        let relative = path
            .strip_prefix("/workspace")
            .unwrap_or_default()
            .trim_start_matches('/');
        let mut directory =
            open_directory(&self.workspace(sandbox)).map_err(aiec_core::CoreError::Io)?;
        for component in Path::new(relative).components() {
            let std::path::Component::Normal(name) = component else {
                return Err(aiec_core::CoreError::Forbidden("outside workspace".into()));
            };
            match open_entry(
                &directory,
                name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            ) {
                Ok(file) => directory = file,
                // A link answers ENOTDIR, not ELOOP, when O_DIRECTORY is set:
                // the kernel refuses the target type before O_NOFOLLOW is even
                // consulted. So this is the link case, and the refusal has to
                // say so - "Not a directory" tells a caller nothing about a
                // workspace the guest controls.
                Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {
                    return Err(aiec_core::CoreError::InvalidRequest(format!(
                        "workspace path component {name:?} is a link, not a directory"
                    )));
                }
                Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                    return Err(aiec_core::CoreError::InvalidRequest(
                        "workspace path traverses a link".into(),
                    ));
                }
                Err(error) => return Err(aiec_core::CoreError::Io(error)),
            }
        }
        Ok(directory)
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
            // The container runs as the worker's own user, not as root. The
            // workspace is a bind mount this worker owns, and a root process
            // inside it creates root-owned files and directories the worker can
            // neither chmod nor delete - so a guest that made one directory
            // could make its own sandbox impossible to reclaim, on every worker
            // that ever ran it.
            user: Some(format!("{}:{}", unsafe { libc::getuid() }, unsafe {
                libc::getgid()
            })),
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
    async fn get_file_chunk(
        &self,
        sandbox: &Sandbox,
        request: FileChunkRequest,
    ) -> Result<FileChunk, aiec_core::CoreError> {
        let root = self.workspace(sandbox);
        tokio::task::spawn_blocking(move || request.read_workspace(&root))
            .await
            .map_err(|error| aiec_core::CoreError::Backend(error.to_string()))?
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
        let directory = self.open_workspace_directory(sandbox, &path)?;
        let mut files = Vec::new();
        for name in directory_entry_names(&directory, MAX_LIST_ENTRIES).map_err(crate::into_core)? {
            let entry = entry_stat(&directory, &name).map_err(aiec_core::CoreError::Io)?;
            let file_name = name.to_string_lossy().into_owned();
            files.push(FileEntry {
                path: format!("{}/{}", path.trim_end_matches('/'), file_name),
                name: file_name,
                // A link is not a directory: it is listed, and a walker must
                // not descend it. Refusing the whole listing because one entry
                // is a link took out every other entry with it, which is most
                // repositories.
                kind: if file_type(entry.st_mode) == libc::S_IFDIR {
                    "directory".into()
                } else {
                    "file".into()
                },
                size: entry.st_size as u64,
            });
        }
        Ok(files)
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
        // Some Docker-compatible engines still apply a graceful-stop timeout
        // during forced removal. Destroy is immediate, unlike explicit stop.
        let kill = bollard::query_parameters::KillContainerOptionsBuilder::new()
            .signal("SIGKILL")
            .build();
        match self
            .docker
            .kill_container(&Self::name(sandbox), Some(kill))
            .await
        {
            Ok(_) => {}
            // Already absent/stopped/paused: forced removal below is the
            // authoritative cleanup operation and must still succeed.
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404 | 409,
                ..
            }) => {}
            Err(error) => {
                return Err(crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker container kill failed: {error}"
                ))));
            }
        }
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
        reclaim_workspace(&self.root.join(sandbox.id.to_string())).await
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

/// Removes a sandbox's state directory, including what the guest created in it.
///
/// The workspace is bind-mounted `0o777` so a container can write to it, and
/// anything the container creates there is owned by the container's user. A
/// plain `remove_dir_all` therefore fails with EACCES on the first directory the
/// guest made, and the worker's state directory grows by one per sandbox
/// forever - the guest decides when, and whether, this worker can reclaim its
/// own disk. That is a real leak, not a test artifact.
///
/// Access is restored to the owning user first, the tree is walked without
/// following symlinks, and one retry covers a bind mount the daemon has not
/// released yet. Only this sandbox's own directory is touched.
async fn reclaim_workspace(path: &Path) -> Result<(), aiec_core::CoreError> {
    if !path.exists() {
        return Ok(());
    }
    restore_owner_access(path).await;
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            // The container is gone, but its bind mount may not have been
            // released yet; a moment later the same removal usually succeeds.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            restore_owner_access(path).await;
            match tokio::fs::remove_dir_all(path).await {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                // A tree this worker cannot chmod is a tree it cannot reclaim.
                // Saying so names the cause; the bare errno from
                // `remove_dir_all` does not, and an operator reading it has no
                // way to tell a bind mount from a guest-created directory.
                Err(error) => Err(crate::into_core(RuntimeError::Unavailable(format!(
                    "Docker workspace {} could not be reclaimed: {error}; entries the guest \
                     created are owned by a user this worker cannot remove",
                    path.display()
                )))),
            }
        }
    }
}

/// Makes a tree writable and traversable by its owner again.
///
/// This can only succeed for a tree this worker owns, which is now the normal
/// case because the container runs as the worker's own user. It still matters
/// for a directory a previous version left behind. An explicit stack rather
/// than recursion, because the depth of a guest's tree is the guest's to
/// choose; symlinks are never followed, so reclaiming a tree is not a reason
/// to walk wherever the guest pointed one.
async fn restore_owner_access(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let _ =
            tokio::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).await;
        let Ok(mut entries) = tokio::fs::read_dir(&directory).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_type().await.is_ok_and(|kind| kind.is_dir()) {
                pending.push(entry.path());
            }
        }
    }
}
fn validate_snapshot_key(key: &str) -> Result<(), aiec_core::CoreError> {
    // An archive key that cannot be used safely is a caller error, so it is
    // reported as one. Routing it through `Io` made a rejected key surface as
    // an unattributed 500, indistinguishable from a genuine disk failure.
    crate::validate_archive_key(key)
        .map_err(|error| aiec_core::CoreError::InvalidRequest(error.to_string()))
}

/// The local file name a snapshot's object key is stored under.
///
/// Derived from the key rather than equal to it: the control plane names its
/// objects `tenants/<uuid>/snapshots/<uuid>`, and a runtime that required a flat
/// key would be deciding what the control plane is allowed to call an object.
fn local_snapshot_name(key: &str) -> Result<String, aiec_core::CoreError> {
    validate_snapshot_key(key)?;
    crate::local_archive_name(key)
        .map_err(|error| aiec_core::CoreError::InvalidRequest(error.to_string()))
}

/// How many members one workspace capture may hold.
const MAX_SNAPSHOT_MEMBERS: usize = 10_000;

/// Captures the workspace at `root`.
///
/// The guest keeps running while this happens and owns every name in here
/// through the same writable bind mount, so nothing is reached by path: each
/// directory is opened once, and each entry is classified, opened and read
/// through that descriptor. A name the guest replaces between the check and
/// the open is refused rather than followed, because following it would carry
/// worker-host bytes into a tenant snapshot - and from there, through a
/// restore, back out to the tenant.
fn collect_workspace(
    root: &Path,
    entries: &mut Vec<PortableWorkspaceEntry>,
    total: &mut u64,
) -> Result<(), aiec_core::CoreError> {
    let workspace = open_directory(root).map_err(aiec_core::CoreError::Io)?;
    collect_directory(&workspace, root, Path::new(""), entries, total)
}

/// Walks the open `directory`. `logical` is where it lives, for naming and for
/// the test barrier; `relative` is what the archive will call it.
fn collect_directory(
    directory: &std::fs::File,
    logical: &Path,
    relative: &Path,
    entries: &mut Vec<PortableWorkspaceEntry>,
    total: &mut u64,
) -> Result<(), aiec_core::CoreError> {
    let names = directory_entry_names(directory, MAX_SNAPSHOT_MEMBERS).map_err(crate::into_core)?;
    for name in names {
        let path = logical.join(&name);
        let relative = relative.join(&name);
        let archive_path = format!(
            "/workspace/{}",
            relative.to_string_lossy().replace('\\', "/")
        );
        let metadata = entry_stat(directory, &name).map_err(aiec_core::CoreError::Io)?;
        // The type is classified; `checkpoint` is where a test can stand in
        // the window before the entry is opened. Inert unless one armed it.
        #[cfg(test)]
        snapshot_swap::checkpoint(&path);
        if file_type(metadata.st_mode) == libc::S_IFLNK {
            return Err(aiec_core::CoreError::Backend(
                "workspace snapshot contains a link".into(),
            ));
        }
        if file_type(metadata.st_mode) == libc::S_IFDIR {
            entries.push(PortableWorkspaceEntry {
                path: archive_path,
                directory: true,
                content_base64: String::new(),
            });
            if entries.len() > MAX_SNAPSHOT_MEMBERS {
                return Err(aiec_core::CoreError::LimitExceeded(
                    "workspace snapshot has too many members".into(),
                ));
            }
            collect_directory(
                &open_child_directory(directory, &name)?,
                &path,
                &relative,
                entries,
                total,
            )?;
        } else if file_type(metadata.st_mode) == libc::S_IFREG {
            let content = read_child_file(directory, &name, snapshot_budget(*total))?;
            *total += content.len() as u64;
            entries.push(PortableWorkspaceEntry {
                path: archive_path,
                directory: false,
                content_base64: base64::engine::general_purpose::STANDARD.encode(content),
            });
            if entries.len() > MAX_SNAPSHOT_MEMBERS {
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

/// What the archive can still hold.
fn snapshot_budget(total: u64) -> u64 {
    (crate::MAX_WORKSPACE_ARCHIVE_BYTES as u64).saturating_sub(total)
}

/// Opens a directory entry, refusing it if it is no longer the one that was
/// classified.
fn open_child_directory(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, aiec_core::CoreError> {
    let file = open_entry(
        directory,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
    .map_err(|error| match error.raw_os_error() {
        Some(libc::ELOOP) => {
            aiec_core::CoreError::Backend("workspace snapshot contains a link".into())
        }
        // Not a directory any more, and not a link either: the guest replaced
        // it between the check and the open.
        Some(libc::ENOTDIR) => {
            aiec_core::CoreError::Backend("workspace snapshot entry changed during capture".into())
        }
        _ => aiec_core::CoreError::Io(error),
    })?;
    let metadata = file.metadata().map_err(aiec_core::CoreError::Io)?;
    if file_type(metadata.mode()) != libc::S_IFDIR {
        return Err(aiec_core::CoreError::Backend(
            "workspace snapshot entry changed during capture".into(),
        ));
    }
    Ok(file)
}

/// Reads one workspace file, refusing it against what the archive has left.
///
/// The size is read from the descriptor that was opened, before a single byte
/// is allocated: a guest can make a file enormous and sparse for free, and the
/// budget has to bound what the worker *holds* rather than only what it
/// stores. The read then stops one byte past the budget, so a file that grows
/// under the walk is refused instead of being truncated into an archive that
/// claims to be the workspace.
fn read_child_file(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
    remaining: u64,
) -> Result<Vec<u8>, aiec_core::CoreError> {
    let file = open_entry(
        directory,
        name,
        // `O_NONBLOCK` costs a regular file nothing and keeps a name that
        // became a pipe between the check and the open from parking the worker
        // on a reader that never arrives.
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW,
    )
    .map_err(|error| match error.raw_os_error() {
        Some(libc::ELOOP) => {
            aiec_core::CoreError::Backend("workspace snapshot contains a link".into())
        }
        _ => aiec_core::CoreError::Io(error),
    })?;
    let metadata = file.metadata().map_err(aiec_core::CoreError::Io)?;
    if file_type(metadata.mode()) != libc::S_IFREG {
        return Err(aiec_core::CoreError::Backend(
            "workspace snapshot entry changed during capture".into(),
        ));
    }
    if metadata.len() > remaining {
        return Err(aiec_core::CoreError::LimitExceeded(
            "workspace snapshot exceeds 64 MiB".into(),
        ));
    }
    let mut content = Vec::with_capacity(metadata.len() as usize);
    file.take(remaining.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(aiec_core::CoreError::Io)?;
    if content.len() as u64 > remaining {
        return Err(aiec_core::CoreError::LimitExceeded(
            "workspace snapshot exceeds 64 MiB".into(),
        ));
    }
    Ok(content)
}

/// A one-shot barrier a test can arm for exactly one workspace entry.
///
/// The walk reads an entry's type and then opens it, and the guest owns that
/// entry through the same writable bind mount. Reproducing what happens in
/// between needs a place to stop, so the walk calls `checkpoint` there. It is
/// armed per absolute path, fires once, and costs a hash lookup in every other
/// capture; without a test arming it, nothing ever waits.
#[cfg(test)]
mod snapshot_swap {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    struct Armed {
        reached: Sender<()>,
        release: Receiver<()>,
    }

    static ARMED: LazyLock<Mutex<HashMap<PathBuf, Armed>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn armed_lock() -> MutexGuard<'static, HashMap<PathBuf, Armed>> {
        ARMED
            .lock()
            .expect("the swap barrier lock is never held across a panic")
    }

    /// Disarms the barrier when the test ends, however it ends, so a failed
    /// test cannot strand an unrelated capture inside `checkpoint`.
    pub struct Disarm {
        target: PathBuf,
    }

    impl Drop for Disarm {
        fn drop(&mut self) {
            armed_lock().remove(&self.target);
        }
    }

    /// Holds the next capture that reaches `target`. `arrived` fires when the
    /// capture reaches the barrier; send on `release` to let it continue.
    pub fn arm(target: &Path) -> (Disarm, Receiver<()>, Sender<()>) {
        let (arrived_tx, arrived) = std::sync::mpsc::channel();
        let (release_tx, release) = std::sync::mpsc::channel();
        armed_lock().insert(
            target.to_path_buf(),
            Armed {
                reached: arrived_tx,
                release,
            },
        );
        (
            Disarm {
                target: target.to_path_buf(),
            },
            arrived,
            release_tx,
        )
    }

    /// Stops the walk at `path` until the armed test lets it through.
    pub fn checkpoint(path: &Path) {
        let Some(armed) = armed_lock().remove(path) else {
            return;
        };
        let _ = armed.reached.send(());
        let _ = armed
            .release
            .recv_timeout(std::time::Duration::from_secs(30));
    }
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
        collect_workspace(&workspace, &mut entries, &mut total)?;
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
        let archive = self.root.join("snapshots").join(format!(
            "{}.json",
            local_snapshot_name(&request.object_key)?
        ));
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
        let archive = self.root.join("snapshots").join(format!(
            "{}.json",
            local_snapshot_name(&metadata.object_key)?
        ));
        // A missing local archive is not an I/O fault. This runtime only keeps
        // the copy the capturing worker wrote on its own disk, so any restore it
        // cannot serve from there has to be handed the archive bytes; reporting
        // a bare `ENOENT` surfaced as an unattributed 500 that named neither
        // the snapshot nor the reason. It stays a failure either way - a
        // restore that cannot find its archive must never silently produce an
        // empty workspace - but the reason is now attributable.
        let bytes = match tokio::fs::read(&archive).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(aiec_core::CoreError::Conflict(format!(
                    "this runtime holds no workspace archive for {}; restore must supply the \
                     archive bytes captured by the owning worker",
                    metadata.object_key
                )));
            }
            Err(error) => return Err(aiec_core::CoreError::Io(error)),
        };
        if bytes.len() > crate::MAX_WORKSPACE_ARCHIVE_BYTES {
            return Err(aiec_core::CoreError::LimitExceeded(
                "workspace snapshot exceeds 64 MiB".into(),
            ));
        }
        // The shared check, so a stored digest recorded in either case is
        // accepted exactly as object storage accepts it.
        aiec_core::snapshots::verify_archive_checksum(&bytes, &metadata.checksum_sha256)?;
        restore_workspace_archive(&bytes, &self.workspace(sandbox))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
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
        // A path that appears as both a file and a directory, or twice, is a
        // malformed archive. Restoring one would mean guessing which of the
        // two the tenant meant, and the guess decides what lands in the
        // workspace.
        let root = std::env::temp_dir().join(format!("af-conflict-restore-{}", Uuid::now_v7()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let entry = |path: &str, directory: bool| PortableWorkspaceEntry {
            path: path.into(),
            directory,
            content_base64: String::new(),
        };
        for entries in [
            vec![
                entry("/workspace/thing", false),
                entry("/workspace/thing", false),
            ],
            vec![
                entry("/workspace/thing", false),
                entry("/workspace/thing", true),
            ],
        ] {
            let bytes = serde_json::to_vec(&PortableWorkspaceArchive {
                version: 1,
                entries,
            })
            .unwrap();
            assert!(
                restore_workspace_archive(&bytes, &workspace).is_err(),
                "a conflicting archive must be refused"
            );
        }
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

    /// The failure that made a cross-worker restore opaque: the archive was
    /// never on this runtime's disk, and the resulting bare `ENOENT` reached
    /// the caller as an unattributed 500 naming neither the snapshot nor the
    /// reason. It must name the snapshot and say the bytes have to be supplied,
    /// and it must stay a failure - a restore that cannot find its archive may
    /// never quietly hand back an empty workspace.
    #[tokio::test]
    async fn a_restore_without_a_local_archive_says_which_snapshot_and_why() {
        let root = std::env::temp_dir().join(format!("af-absent-restore-{}", Uuid::now_v7()));
        let sandbox = sandbox_fixture();
        let runtime = DockerRuntime::with_client(
            Docker::connect_with_unix_defaults().expect("Docker client"),
            &root,
        );
        let error = runtime
            .restore(
                &sandbox,
                &SnapshotMetadata {
                    id: Uuid::now_v7(),
                    kind: aiec_core::snapshots::SnapshotKind::Workspace,
                    object_key: "never-captured-here".into(),
                    checksum_sha256: aiec_core::snapshots::archive_checksum(b"unused"),
                },
            )
            .await
            .expect_err("a restore with no local archive must fail");
        let message = error.to_string();
        assert!(
            matches!(error, aiec_core::CoreError::Conflict(_)),
            "a missing archive is a routing conflict, not an I/O fault: {message}"
        );
        assert!(
            message.contains("never-captured-here"),
            "the failure must name the snapshot: {message}"
        );
        assert!(
            !runtime.workspace(&sandbox).exists(),
            "a failed restore must not materialize an empty workspace"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A key the runtime cannot turn into a safe path is the caller's mistake,
    /// and has to read as one instead of as an unattributed 500.
    #[tokio::test]
    async fn an_unusable_snapshot_key_is_reported_as_a_caller_error() {
        let root = std::env::temp_dir().join(format!("af-bad-key-{}", Uuid::now_v7()));
        let runtime = DockerRuntime::with_client(
            Docker::connect_with_unix_defaults().expect("Docker client"),
            &root,
        );
        let error = runtime
            .restore(
                &sandbox_fixture(),
                &SnapshotMetadata {
                    id: Uuid::now_v7(),
                    kind: aiec_core::snapshots::SnapshotKind::Workspace,
                    object_key: "../../etc/passwd".into(),
                    checksum_sha256: aiec_core::snapshots::archive_checksum(b"unused"),
                },
            )
            .await
            .expect_err("a traversing key must be rejected");
        assert!(
            matches!(error, aiec_core::CoreError::InvalidRequest(_)),
            "an unusable key is a caller error: {error}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// The digest recorded with a snapshot is compared case-insensitively, so
    /// an archive stored by object storage is not rejected over hex casing.
    #[tokio::test]
    async fn a_local_archive_restores_under_either_digest_casing() {
        let root = std::env::temp_dir().join(format!("af-casing-{}", Uuid::now_v7()));
        let sandbox = sandbox_fixture();
        let runtime = DockerRuntime::with_client(
            Docker::connect_with_unix_defaults().expect("Docker client"),
            &root,
        );
        std::fs::create_dir_all(runtime.workspace(&sandbox)).unwrap();
        std::fs::write(runtime.workspace(&sandbox).join("marker"), b"before").unwrap();
        let captured = runtime
            .capture(
                &sandbox,
                &SnapshotRequest {
                    kind: aiec_core::snapshots::SnapshotKind::Workspace,
                    object_key: "casing-check".into(),
                },
            )
            .await
            .expect("capture workspace");
        std::fs::write(runtime.workspace(&sandbox).join("marker"), b"clobbered").unwrap();

        runtime
            .restore(
                &sandbox,
                &SnapshotMetadata {
                    id: captured.id,
                    kind: aiec_core::snapshots::SnapshotKind::Workspace,
                    object_key: "casing-check".into(),
                    checksum_sha256: captured.checksum_sha256.to_uppercase(),
                },
            )
            .await
            .expect("an uppercase digest names the same archive");
        assert_eq!(
            std::fs::read(runtime.workspace(&sandbox).join("marker")).unwrap(),
            b"before"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A checksum that does not match is still refused, and still a conflict:
    /// the casing tolerance above must not become tolerance of wrong bytes.
    #[tokio::test]
    async fn a_local_archive_whose_bytes_changed_is_refused() {
        let root = std::env::temp_dir().join(format!("af-tampered-{}", Uuid::now_v7()));
        let sandbox = sandbox_fixture();
        let runtime = DockerRuntime::with_client(
            Docker::connect_with_unix_defaults().expect("Docker client"),
            &root,
        );
        std::fs::create_dir_all(runtime.workspace(&sandbox)).unwrap();
        std::fs::write(runtime.workspace(&sandbox).join("honest"), b"original").unwrap();
        let captured = runtime
            .capture(
                &sandbox,
                &SnapshotRequest {
                    kind: aiec_core::snapshots::SnapshotKind::Workspace,
                    object_key: "tamper-check".into(),
                },
            )
            .await
            .expect("capture workspace");
        // Different bytes, same length class and same shape: only the digest
        // separates the two, so this cannot pass by being unparseable. The
        // archive is found rather than named: its local name is derived from
        // the object key, so writing `tamper-check.json` would only create a
        // file the runtime never reads.
        let archive = std::fs::read_dir(root.join("snapshots"))
            .expect("the capture wrote an archive")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .expect("a workspace archive on disk");
        std::fs::write(
            &archive,
            br#"{"version":1,"entries":[{"path":"/workspace/honest","directory":false,"content_base64":"c3doaWZ0ZWQ="}]}"#,
        )
        .unwrap();

        let error = runtime
            .restore(
                &sandbox,
                &SnapshotMetadata {
                    id: captured.id,
                    kind: aiec_core::snapshots::SnapshotKind::Workspace,
                    object_key: "tamper-check".into(),
                    checksum_sha256: captured.checksum_sha256,
                },
            )
            .await
            .expect_err("bytes that no longer match the digest must be refused");
        let message = error.to_string();
        assert!(
            matches!(error, aiec_core::CoreError::Conflict(_)),
            "{message}"
        );
        // An absent archive is also a `Conflict`, so the variant alone cannot
        // tell "the bytes are wrong" from "there are no bytes". The wording is
        // what separates them.
        assert!(
            message.contains("checksum"),
            "changed bytes must be reported as a checksum failure: {message}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Bytes that exist on the worker host and nowhere in the workspace.
    const HOST_SENTINEL: &[u8] = b"host-only-bytes-that-must-never-enter-a-snapshot";

    fn decode_entry(entry: &PortableWorkspaceEntry) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(&entry.content_base64)
            .unwrap_or_default()
    }

    /// A capture must carry no host bytes, and an entry it could not open
    /// safely has to fail the capture rather than quietly go missing: an
    /// archive that silently drops a file restores as a workspace that lost
    /// data, and the digest over it certifies the loss as faithful.
    fn assert_no_host_bytes(
        result: &Result<(), aiec_core::CoreError>,
        entries: &[PortableWorkspaceEntry],
    ) {
        for entry in entries {
            let content = decode_entry(entry);
            assert!(
                !content
                    .windows(HOST_SENTINEL.len())
                    .any(|window| window == HOST_SENTINEL),
                "host bytes were captured at {}",
                entry.path
            );
        }
        assert!(
            result.is_err(),
            "an entry replaced underneath the walk must be refused, not archived"
        );
    }

    /// A guest that keeps running owns the workspace it is being captured
    /// from, through the same writable bind mount. Replacing a file with a
    /// link to a host path in the moment between "this is a regular file" and
    /// "read it" would put host bytes into a tenant snapshot, and from there
    /// back out to the tenant on the next restore. The barrier makes that
    /// window exact instead of a matter of timing.
    #[test]
    fn a_file_swapped_for_a_host_link_after_the_check_is_not_captured() {
        let root = std::env::temp_dir().join(format!("af-swap-file-{}", Uuid::now_v7()));
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let sentinel = outside.join("secret.txt");
        std::fs::write(&sentinel, HOST_SENTINEL).unwrap();
        let probe = workspace.join("probe");
        std::fs::write(&probe, b"guest bytes").unwrap();

        let (disarm, arrived, release) = snapshot_swap::arm(&probe);
        let swap = std::thread::spawn(move || {
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the capture reached the barrier");
            std::fs::remove_file(&probe).unwrap();
            std::os::unix::fs::symlink(&sentinel, &probe).unwrap();
            release.send(()).unwrap();
        });

        let mut entries = Vec::new();
        let mut total = 0_u64;
        let result = collect_workspace(&workspace, &mut entries, &mut total);
        swap.join().expect("the swap thread finished");
        drop(disarm);

        assert_no_host_bytes(&result, &entries);
        let _ = std::fs::remove_dir_all(root);
    }

    /// The same window one level up: a directory accepted as a directory is
    /// descended by path afterwards, so replacing it with a link to a host
    /// directory walks the host instead of the workspace.
    #[test]
    fn a_directory_swapped_for_a_host_link_after_the_check_is_not_captured() {
        let root = std::env::temp_dir().join(format!("af-swap-dir-{}", Uuid::now_v7()));
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        std::fs::create_dir_all(workspace.join("probe")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(workspace.join("probe/inner.txt"), b"guest bytes").unwrap();
        std::fs::write(outside.join("secret.txt"), HOST_SENTINEL).unwrap();
        let probe = workspace.join("probe");

        let (disarm, arrived, release) = snapshot_swap::arm(&probe);
        let swap = std::thread::spawn(move || {
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the capture reached the barrier");
            std::fs::remove_dir_all(&probe).unwrap();
            std::os::unix::fs::symlink(&outside, &probe).unwrap();
            release.send(()).unwrap();
        });

        let mut entries = Vec::new();
        let mut total = 0_u64;
        let result = collect_workspace(&workspace, &mut entries, &mut total);
        swap.join().expect("the swap thread finished");
        drop(disarm);

        assert_no_host_bytes(&result, &entries);
        let _ = std::fs::remove_dir_all(root);
    }

    /// The archive budget has to bound what the worker *holds*, not only what
    /// it hands back. A sparse file is the cheap version of the attack: it
    /// costs the guest almost no disk and the worker a full buffer, in a
    /// process that sits outside the container's memory limit.
    ///
    /// The measurement runs in a child process so that neither the capture's
    /// footprint nor the numbers can be confused with anything else running in
    /// this test binary.
    #[test]
    fn an_oversized_sparse_workspace_file_is_refused_without_buffering_it() {
        const SPARSE_BYTES: u64 = 512 * 1024 * 1024;
        let root = std::env::temp_dir().join(format!("af-sparse-{}", Uuid::now_v7()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::File::create(workspace.join("sparse.bin"))
            .unwrap()
            .set_len(SPARSE_BYTES)
            .unwrap();
        std::fs::write(workspace.join("honest.txt"), b"small").unwrap();

        // Re-run this binary with the measurement child as the only selected
        // test. The filter is positional - the shape libtest documents - and
        // the marker it prints is what makes "ran nothing" distinguishable
        // from "ran and reported nothing".
        let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "docker::tests::oversized_sparse_snapshot_measurement_child",
                // libtest captures a passing test's stdout, so the marker
                // never reaches the pipe unless the child is told not to
                // capture. Without this the parent reads its own child's
                // silence as "the measurement ran and printed nothing".
                "--nocapture",
                "--test-threads=1",
            ])
            .env("AIEC_SPARSE_SNAPSHOT_WORKSPACE", &workspace)
            .output()
            .expect("re-run the measurement child");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        // libtest prints a passing test's name and an ellipsis on the same line
        // as whatever that test wrote. The measurement is therefore located by
        // its marker anywhere in the line, not by position, so this test does
        // not depend on how the harness chooses to format one test's output.
        let report = stdout
            .lines()
            .find_map(|line| {
                let start = line.find("AIEC_SPARSE_SNAPSHOT ")?;
                Some(line[start..].trim_end().to_owned())
            })
            .unwrap_or_else(|| {
                panic!(
                    "the child reported nothing (status {:?})\nstdout: {stdout}\nstderr: {stderr}",
                    output.status
                )
            });
        let field = |key: &str| -> u64 {
            report
                .split_whitespace()
                .find_map(|token| token.strip_prefix(key))
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("{report} does not report {key}"))
        };

        assert!(
            report.contains("outcome=limit-exceeded"),
            "a file larger than the archive budget must be refused, not captured: {report}"
        );
        // `VmHWM` is not readable everywhere this runs - it was absent in the
        // container this was last reproduced in - so the byte counter is what
        // this test stands on, and the peak is a second opinion when the
        // kernel offers one.
        let peak_kib = field("peak_rss_kib=");
        assert!(
            peak_kib == 0 || peak_kib < 192 * 1024,
            "the capture buffered a {} MiB file: peak RSS {peak_kib} KiB, {report}",
            SPARSE_BYTES / (1024 * 1024)
        );
        let read = field("bytes_read=");
        assert!(
            read < crate::MAX_WORKSPACE_ARCHIVE_BYTES as u64,
            "the capture read {read} bytes of a file it had already been told to refuse: {report}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// The measurement itself. Inert unless the test above re-runs this binary
    /// with the workspace to capture named.
    #[test]
    fn oversized_sparse_snapshot_measurement_child() {
        let Some(workspace) = std::env::var_os("AIEC_SPARSE_SNAPSHOT_WORKSPACE") else {
            return;
        };
        let workspace = PathBuf::from(workspace);
        let before = process_footprint().0;
        let mut entries = Vec::new();
        let mut total = 0_u64;
        let outcome = match collect_workspace(&workspace, &mut entries, &mut total) {
            Ok(()) => "captured",
            Err(aiec_core::CoreError::LimitExceeded(_)) => "limit-exceeded",
            Err(_) => "other-error",
        };
        let (after, peak_kib) = process_footprint();
        println!(
            "AIEC_SPARSE_SNAPSHOT outcome={outcome} bytes_read={} peak_rss_kib={peak_kib} entries={} total={total}",
            after.saturating_sub(before),
            entries.len()
        );
    }

    /// Bytes this process has read through `read`, and its resident high-water
    /// mark in KiB. Both are read rather than estimated: the claim under test
    /// is what the capture actually cost, not what it was supposed to cost.
    fn process_footprint() -> (u64, u64) {
        let counter = |file: &str, key: &str| -> u64 {
            std::fs::read_to_string(file)
                .ok()
                .and_then(|contents| {
                    contents.lines().find_map(|line| {
                        let (_, value) = line.split_once(':')?;
                        line.starts_with(key)
                            .then(|| value.trim().parse::<u64>().ok())?
                    })
                })
                .unwrap_or_default()
        };
        (
            counter("/proc/self/io", "rchar"),
            counter("/proc/self/status", "VmHWM"),
        )
    }

    /// The walk is only worth hardening if it still snapshots an ordinary
    /// workspace exactly: every path, every byte, and a refusal for the links
    /// it cannot carry.
    #[test]
    fn a_small_workspace_capture_preserves_paths_and_contents() {
        let root = std::env::temp_dir().join(format!("af-small-capture-{}", Uuid::now_v7()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(workspace.join("nested")).unwrap();
        std::fs::create_dir_all(workspace.join("empty")).unwrap();
        std::fs::write(workspace.join("nested/notes.txt"), b"durable").unwrap();
        std::fs::write(workspace.join("top.bin"), b"top").unwrap();

        let mut entries = Vec::new();
        let mut total = 0_u64;
        collect_workspace(&workspace, &mut entries, &mut total)
            .expect("an ordinary workspace captures");

        let captured: std::collections::BTreeSet<(String, bool)> = entries
            .iter()
            .map(|entry| (entry.path.clone(), entry.directory))
            .collect();
        assert_eq!(
            captured,
            [
                ("/workspace/empty".to_owned(), true),
                ("/workspace/nested".to_owned(), true),
                ("/workspace/nested/notes.txt".to_owned(), false),
                ("/workspace/top.bin".to_owned(), false),
            ]
            .into_iter()
            .collect()
        );
        let notes = entries
            .iter()
            .find(|entry| entry.path == "/workspace/nested/notes.txt")
            .expect("the nested file was captured");
        assert_eq!(decode_entry(notes), b"durable");
        assert_eq!(total, b"durable".len() as u64 + b"top".len() as u64);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_workspace_snapshot_refuses_a_link() {
        let root = std::env::temp_dir().join(format!("af-link-capture-{}", Uuid::now_v7()));
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(workspace.join("real.txt"), b"guest bytes").unwrap();
        std::fs::write(outside.join("secret.txt"), HOST_SENTINEL).unwrap();
        std::os::unix::fs::symlink(&outside, workspace.join("escape")).unwrap();

        let mut entries = Vec::new();
        let mut total = 0_u64;
        let error = collect_workspace(&workspace, &mut entries, &mut total)
            .expect_err("a workspace link must be refused");
        assert!(error.to_string().contains("link"), "{error}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A listing is metadata. Three 12 MiB files are three entries, and a
    /// directory holding a 12 MiB file is one entry: neither may be refused
    /// because of what the descendants weigh.
    #[tokio::test]
    async fn a_listing_reports_metadata_independently_of_descendant_contents() {
        let root = std::env::temp_dir().join(format!("af-listing-{}", Uuid::now_v7()));
        let runtime = DockerRuntime::with_client(
            Docker::connect_with_unix_defaults().expect("Docker client"),
            &root,
        );
        let sandbox = sandbox_fixture();
        let data = runtime.workspace(&sandbox).join("data");
        std::fs::create_dir_all(data.join("sub")).unwrap();
        // Sparse: the listing must not care how the bytes are stored.
        for name in ["a.bin", "b.bin", "c.bin", "sub/deep.bin"] {
            std::fs::File::create(data.join(name))
                .unwrap()
                .set_len(12 * 1024 * 1024)
                .unwrap();
        }

        let entries = runtime
            .list_files(&sandbox, "/workspace/data")
            .await
            .expect("a listing is metadata, not content");
        let listed: std::collections::BTreeMap<&str, (String, u64)> = entries
            .iter()
            .map(|entry| (entry.name.as_str(), (entry.kind.clone(), entry.size)))
            .collect();
        for name in ["a.bin", "b.bin", "c.bin"] {
            assert_eq!(
                listed.get(name),
                Some(&("file".to_owned(), 12 * 1024 * 1024)),
                "{listed:?}"
            );
        }
        assert_eq!(
            listed.get("sub").map(|(kind, _)| kind.as_str()),
            Some("directory"),
            "{listed:?}"
        );
        assert_eq!(entries.len(), 4, "{listed:?}");

        let parent = runtime
            .list_files(&sandbox, "/workspace")
            .await
            .expect("a parent's listing ignores what its children weigh");
        assert_eq!(parent.len(), 1, "{parent:?}");
        assert_eq!(parent[0].name, "data");
        assert_eq!(parent[0].path, "/workspace/data");
        assert_eq!(parent[0].kind, "directory");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A workspace link is listed as an entry and never descended, and it does
    /// not empty the listing around it - most repositories contain one.
    #[tokio::test]
    async fn a_workspace_link_is_listed_without_emptying_its_directory() {
        let root = std::env::temp_dir().join(format!("af-listing-link-{}", Uuid::now_v7()));
        let runtime = DockerRuntime::with_client(
            Docker::connect_with_unix_defaults().expect("Docker client"),
            &root,
        );
        let sandbox = sandbox_fixture();
        let sub = runtime.workspace(&sandbox).join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        for name in ["a.txt", "b.txt"] {
            std::fs::write(sub.join(name), b"x").unwrap();
        }
        std::os::unix::fs::symlink("/etc", sub.join("escape")).unwrap();

        let entries = runtime
            .list_files(&sandbox, "/workspace/sub")
            .await
            .expect("a link must not empty the listing");
        let names: std::collections::BTreeSet<&str> =
            entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["a.txt", "b.txt", "escape"].into_iter().collect());
        let link = entries
            .iter()
            .find(|entry| entry.name == "escape")
            .expect("the link is listed");
        assert_ne!(link.kind, "directory", "a walker must not descend a link");

        // Listing *through* the link is a different request, and one the walk
        // refuses rather than resolving: the daemon used to follow it, which is
        // how a link to `/etc` turned a workspace listing into a host one.
        let through = runtime
            .list_files(&sandbox, "/workspace/sub/escape")
            .await
            .expect_err("a link is not a way into the directory it names");
        assert!(
            through.to_string().contains("link"),
            "the refusal must say why: {through}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A directory is a path, not a prefix of a string.
    ///
    /// Asking for `/workspace/repo` once answered with `repo/`, which also
    /// claimed the sibling `repo-backup/proof.txt` and reported it as a file
    /// inside `repo`. Names come from one opened directory now, so the two can
    /// only be told apart if the walk itself is sound - which is what this
    /// pins down.
    #[tokio::test]
    async fn a_listing_stops_at_a_path_component() {
        let root = std::env::temp_dir().join(format!("af-listing-prefix-{}", Uuid::now_v7()));
        let runtime = DockerRuntime::with_client(
            Docker::connect_with_unix_defaults().expect("Docker client"),
            &root,
        );
        let sandbox = sandbox_fixture();
        let workspace = runtime.workspace(&sandbox);
        std::fs::create_dir_all(workspace.join("repo")).unwrap();
        std::fs::create_dir_all(workspace.join("repo-backup")).unwrap();
        std::fs::write(workspace.join("repo/proof.txt"), b"repo").unwrap();
        std::fs::write(workspace.join("repo-backup/proof.txt"), b"sibling").unwrap();

        let inside = runtime
            .list_files(&sandbox, "/workspace/repo")
            .await
            .expect("listing a directory");
        assert_eq!(
            inside
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["proof.txt"],
            "the sibling shares a prefix, not a directory"
        );
        assert_eq!(inside[0].path, "/workspace/repo/proof.txt");

        let parent = runtime
            .list_files(&sandbox, "/workspace")
            .await
            .expect("listing the workspace");
        let names: std::collections::BTreeSet<&str> =
            parent.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["repo", "repo-backup"].into_iter().collect());
        assert!(parent.iter().all(|entry| entry.kind == "directory"));
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod resolver_tests {
    use super::{is_reachable_nameserver, parse_resolvers};

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

    /// Addresses that are not loopback, so a "not loopback" test admits them,
    /// and that name no reachable resolver. Each was handed to a bridge
    /// container as the only nameserver on this deployment and every lookup
    /// came back `gaierror(-3, 'Temporary failure in name resolution')`.
    #[test]
    fn unreachable_non_loopback_resolvers_are_dropped() {
        for dead in [
            "0.0.0.0",         // unspecified: glibc reads it as "this machine"
            "::",              // the IPv6 unspecified address
            "255.255.255.255", // limited broadcast
            "ff02::1",         // all-nodes multicast, needs a scope the container lacks
            "fe80::1",         // IPv6 link-local, unroutable without a zone id
            "fe80::abcd:1234",
            "febf::1", // top of the fe80::/10 range, still link-local
        ] {
            assert!(
                !is_reachable_nameserver(dead),
                "{dead} is not a resolver a container can answer from"
            );
        }
    }

    /// `fe80::/10` ends at `febf::ffff...`; the next block up is ordinary
    /// global unicast and must survive the link-local check.
    #[test]
    fn the_first_address_above_link_local_is_still_kept() {
        assert!(is_reachable_nameserver("fec0::1"));
        assert!(is_reachable_nameserver("2606:4700:4700::1111"));
    }

    /// A rootless podman host's only resolvers are link-local, and they are
    /// reachable from a bridge container there, so the IPv4 range stays.
    #[test]
    fn ipv4_link_local_resolvers_are_still_kept() {
        assert!(is_reachable_nameserver("169.254.1.1"));
        assert!(is_reachable_nameserver("192.168.1.1"));
    }

    /// `resolv.conf` permits several addresses on one `nameserver` line, and
    /// the container API rejects a value containing whitespace outright - so
    /// that line must be split into separate entries, keeping the reachable
    /// half rather than discarding both.
    #[test]
    fn a_multi_address_nameserver_line_is_split_into_separate_entries() {
        assert_eq!(
            parse_resolvers("nameserver 1.1.1.1 1.0.0.1\n").expect("resolvers"),
            vec!["1.1.1.1".to_owned(), "1.0.0.1".to_owned()]
        );
        // Split first, filter second: the loopback half is dropped and the
        // reachable one still reaches the container.
        assert_eq!(
            parse_resolvers("nameserver 127.0.0.53 8.8.8.8\n").expect("resolvers"),
            vec!["8.8.8.8".to_owned()]
        );
        assert!(parse_resolvers("nameserver 127.0.0.53\n").is_none());
        assert!(parse_resolvers("search example.com\noptions ndots:1\n").is_none());
    }
}
