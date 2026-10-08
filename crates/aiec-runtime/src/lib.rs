use aiec_core::protocol::{self, Operation, Request, RequestPayload, Response, ResponsePayload};
use aiec_core::{
    host_pressure::{HostPressure, HostReserves},
    network::{NetworkAttachment, NetworkBackend},
    runtime::{FileChunk, FileChunkRequest, RuntimeCapabilities, RuntimeHealth},
    snapshots::{
        CapturedSnapshot, MAX_WORKSPACE_ARCHIVE_BYTES, PortableWorkspaceArchive,
        PortableWorkspaceEntry, SnapshotCapabilities, SnapshotKind, SnapshotMetadata,
        SnapshotProvider, SnapshotRequest,
    },
    *,
};
use aiec_network_linux::GuardNetworkManager;
#[cfg(test)]
use aiec_network_linux::LinuxNetworkManager;
use async_trait::async_trait;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex as StdMutex, PoisonError},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    sync::{Mutex, oneshot},
};
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
pub mod control_identity;
mod docker;
pub mod e2b;
pub mod guest_artifact;
pub use docker::DockerRuntime;
pub mod rootfs;
pub use e2b::{E2bConfig, E2bRuntime, RuntimePathProvider};

fn into_core(error: RuntimeError) -> CoreError {
    match error {
        RuntimeError::Core(error) => error,
        // An unavailable backend stays unavailable. Collapsing it into `Io`
        // turned a Guard or Firecracker refusal into "io error: <text>", which
        // loses the class a caller branches on and buries the reason under a
        // category that says nothing about who refused. Everything else still
        // becomes `Io`: `aiec-api` relies on that for destroy, where a
        // vanished backend process has to read as a transport fault rather than
        // a permanent one (see `is_transient_destroy_error`).
        RuntimeError::Unavailable(message) => CoreError::Unavailable(message),
        other => CoreError::Io(std::io::Error::other(other.to_string())),
    }
}

/// How many sandboxes may have a lifecycle operation in flight at once.
///
/// A worker runs a handful of sandboxes, so this is generous for a real node
/// and still a number: past it, a new sandbox is refused rather than allowed to
/// grow a map keyed by a request-supplied id.
pub const MAX_CONCURRENT_LIFECYCLES: usize = 4_096;

/// Most entries one directory listing will describe, for every runtime.
///
/// This lives here rather than per backend because that is how it went wrong:
/// docker, e2b and the guest agent each carried their own copy of the same
/// number, and Bubblewrap's listing, which had none, was missed rather than
/// being a fourth decision. The number is only a defence if it is the same
/// number everywhere.
pub(crate) const MAX_LIST_ENTRIES: usize = 10_000;

/// Largest Firecracker API response header this runtime will read, in bytes.
const HEADER_LIMIT: usize = 64 * 1024;

/// Largest Firecracker API response body this runtime will allocate for, in
/// bytes. Bounded because the size comes off the wire: a `Content-Length` read
/// straight from a response header sized a `Vec` before a byte was read.
const BODY_LIMIT: usize = 8 * 1024 * 1024;

/// One sandbox's lifecycle operations, taken one at a time.
///
/// A sandbox's create, start, stop, restore and destroy all answer the same
/// question - what exists for this sandbox id right now - and they answer it by
/// writing: a create materializes an owner marker and a rootfs into a directory
/// a destroy removes, a start inserts a live VM into the map a stop takes it
/// out of. Run together on one id they interleave. A destroy can report
/// success while a create is still copying, and the copy then recreates the
/// directory the destroy was asked to clear: a machine that a completed destroy
/// already promised nobody would ever boot. The other order is worse, because a
/// start that boots after its sandbox was destroyed leaves a live process
/// behind a successful destroy.
///
/// Serializing by id fixes both orders without serializing the host. Sandboxes
/// are independent, and only two operations on the *same* id can conflict, so
/// every other sandbox boots while one of them is busy.
///
/// Exec is deliberately not one of the operations that queue. A command is the
/// thing an operator interrupts by destroying its sandbox, so a destroy that
/// waited for a long `exec` would be waiting for exactly the work it exists to
/// stop. Exec takes no gate, and a destroy therefore proceeds while a command is
/// running.
///
/// The table is bounded and self-clearing. An entry exists exactly while some
/// caller holds it or is queued behind it, and the last one out removes it, so
/// the map tracks concurrent work rather than every sandbox this worker has
/// ever seen. [`Self::enter`] refuses rather than grows when that bound is
/// reached, because the alternative is an unbounded map.
#[derive(Debug)]
pub struct SandboxLifecycle {
    gates: StdMutex<GateTable>,
}

impl Default for SandboxLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct GateTable {
    gates: HashMap<Uuid, GateState>,
    bound: usize,
}

#[derive(Debug)]
struct GateState {
    lock: Arc<tokio::sync::Mutex<()>>,
    /// Callers that hold this gate or are queued for it.
    users: usize,
}

/// The lifecycle table is already at its bound.
///
/// A distinct error rather than a wait: the callers in flight are all
/// legitimate, and refusing is the only answer that keeps the table finite.
#[derive(Debug, Error)]
#[error("too many sandbox lifecycle operations are already in flight")]
pub struct LifecycleBusy;

/// Exclusive use of one sandbox, released when dropped.
///
/// Holds the token so the table entry lives as long as the work, and the
/// sandbox's own lock so no second caller can be inside it.
#[derive(Debug)]
pub struct SandboxLifecycleGuard {
    /// Dropped first. Releasing the table entry before the sandbox's lock would
    /// let a new caller build a second lock for the same id and enter the
    /// critical section while this one is still inside it.
    _held: tokio::sync::OwnedMutexGuard<()>,
    /// Named for its drop order, not its value: releasing the table entry after
    /// the sandbox lock is what keeps a newcomer out of this critical section.
    _reservation: LifecycleReservation,
}

/// One caller's place in the table, released even if it never gets the lock.
///
/// A caller that is cancelled while queued has already been counted, so the
/// count is released here rather than in the guard that may never be built.
#[derive(Debug)]
struct LifecycleReservation {
    lifecycle: Arc<SandboxLifecycle>,
    sandbox_id: Uuid,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl Drop for LifecycleReservation {
    fn drop(&mut self) {
        // Recovered rather than propagated: this lock is held for a map update
        // and never across an await, and a panic in one sandbox's bookkeeping
        // must not make every other sandbox on the node unreleasable.
        let mut table = self
            .lifecycle
            .gates
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(state) = table.gates.get_mut(&self.sandbox_id) {
            state.users -= 1;
            if state.users == 0 {
                table.gates.remove(&self.sandbox_id);
            }
        }
    }
}

impl SandboxLifecycle {
    pub fn new() -> Self {
        Self {
            gates: StdMutex::new(GateTable {
                gates: HashMap::new(),
                bound: MAX_CONCURRENT_LIFECYCLES,
            }),
        }
    }

    /// Waits for exclusive use of `sandbox_id`, in arrival order.
    ///
    /// The wait is unbounded by design: every holder is itself bounded, and a
    /// caller that gave up here would have to decide what state its abandoned
    /// operation left behind. The guard is returned only once the sandbox is
    /// genuinely free.
    pub async fn enter(
        self: &Arc<Self>,
        sandbox_id: Uuid,
    ) -> Result<SandboxLifecycleGuard, LifecycleBusy> {
        let reservation = self.reserve(sandbox_id)?;
        let held = reservation.lock.clone().lock_owned().await;
        Ok(SandboxLifecycleGuard {
            _held: held,
            _reservation: reservation,
        })
    }

    fn reserve(self: &Arc<Self>, sandbox_id: Uuid) -> Result<LifecycleReservation, LifecycleBusy> {
        let mut table = self.gates.lock().unwrap_or_else(PoisonError::into_inner);
        let existing = table.gates.get(&sandbox_id).map(|state| state.lock.clone());
        let lock = match existing {
            Some(lock) => {
                let state = table
                    .gates
                    .get_mut(&sandbox_id)
                    .expect("the entry was just read under this lock");
                state.users += 1;
                lock
            }
            None => {
                if table.gates.len() >= table.bound {
                    return Err(LifecycleBusy);
                }
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                table.gates.insert(
                    sandbox_id,
                    GateState {
                        lock: Arc::clone(&lock),
                        users: 1,
                    },
                );
                lock
            }
        };
        Ok(LifecycleReservation {
            lifecycle: Arc::clone(self),
            sandbox_id,
            lock,
        })
    }

    /// Sandboxes with a lifecycle operation in flight.
    #[cfg(test)]
    fn held(&self) -> usize {
        self.gates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .gates
            .len()
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
    network: &dyn NetworkBackend,
    artifact: Option<&guest_artifact::GuestArtifact>,
    minimum_disk_mb: u64,
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
        // Asked of the backend rather than assumed. A worker that advertises
        // `network_policy` is a promise the scheduler will place governed work
        // on, and a hardcoded `true` makes that promise empty: the sandbox
        // would then be admitted and would fail at boot instead of being placed
        // somewhere that can actually govern it.
        network_policy: network.capabilities().dns_controls
            && network.capabilities().restricted_allowlists,
        pause: true,
        pause_reclaims_resources: false,
        // A workspace snapshot is captured from this runtime by
        // `SnapshotProvider::capture` and put back by
        // `import_workspace_snapshot`, both verified against the archive
        // checksum, and the archive is portable between machines because it is
        // read out of the guest's workspace rather than off the machine's own
        // disk. Advertising otherwise makes the scheduler's
        // `capabilities @> required` test refuse every placement a restore
        // asks for - `portable_workspace` and `workspace_snapshot` - which is
        // what it did: a workspace restore could not be placed on a microVM
        // host at all, and the refusal was reported as missing capacity.
        portable_workspace: true,
        workspace_snapshot: true,
        vsock: true,
        coding_guest: artifact.is_some_and(guest_artifact::GuestArtifact::is_coding_guest),
        // Reported, not matched: `capabilities_satisfy` compares booleans, so
        // this never narrows worker selection. It is what tells the scheduler
        // that a disk smaller than the base image cannot be honoured here.
        minimum_disk_mb,
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

/// Rejects an object key that must never reach a local path.
///
/// A key names an object in the store; it is not a filename on this host. What
/// is refused here is the shape that would be a problem even after hashing -
/// nothing, empty, control bytes, a traversal component - because a key that
/// says `../../etc/passwd` is a caller bug worth reporting rather than
/// silently absorbing.
fn validate_archive_key(key: &str) -> Result<(), RuntimeError> {
    if key.is_empty() || key.len() > 1024 {
        return Err(RuntimeError::Archive(
            "archive key must be 1 to 1024 bytes".into(),
        ));
    }
    if key.bytes().any(|byte| byte.is_ascii_control()) || key.contains('\\') {
        return Err(RuntimeError::Archive(
            "archive key has an unsafe character".into(),
        ));
    }
    if key
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(RuntimeError::Archive(
            "archive key contains a traversal or an empty component".into(),
        ));
    }
    Ok(())
}

/// The local file name an object key is stored under.
///
/// Derived by digest rather than used verbatim, because keys are
/// tenant-prefixed and contain separators: `tenants/<uuid>/snapshots/<uuid>` is
/// the right shape for an object store and the wrong shape for a filename, and
/// a runtime that insists on a flat key is a runtime that decides what the
/// control plane is allowed to name objects. The Firecracker runtime already
/// hashed its snapshot directory this way; this makes the other two agree.
pub(crate) fn local_archive_name(key: &str) -> Result<String, RuntimeError> {
    validate_archive_key(key)?;
    let digest = hex::encode(Sha256::digest(key.as_bytes()));
    Ok(digest[..32].to_owned())
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

    /// Resolves a request path against the workspace, refusing anything that
    /// leaves it through a symlink.
    ///
    /// [`Self::path_for`] normalizes the request string, which is what stops
    /// `..` in the request itself. It cannot see a symlink the guest planted in
    /// its own workspace, because the host performs the file operation on the
    /// joined path and every one of those follows links. A guest that ran
    /// `ln -s /etc /workspace/etc` then had `put_file("/workspace/etc/passwd")`
    /// write the host's `/etc/passwd`, and `get_file` read back host files the
    /// request never named.
    ///
    /// So the check is on the resolved path, not the requested one: every
    /// component from the workspace down is walked, and a component that is a
    /// symlink pointing outside the workspace is refused. A symlink pointing
    /// *within* the workspace is allowed, because that is a thing a guest
    /// legitimately does with its own files.
    async fn resolve_in_workspace(
        &self,
        sandbox: &Sandbox,
        raw: &str,
    ) -> Result<PathBuf, RuntimeError> {
        let workspace = self.base(sandbox).join("workspace");
        let target = self.path_for(sandbox, raw)?;
        let Ok(relative) = target.strip_prefix(&workspace) else {
            return Err(CoreError::Forbidden("outside workspace".into()).into());
        };
        let mut walked = workspace.clone();
        for component in relative.components() {
            let name = component.as_os_str();
            let next = walked.join(name);
            // `symlink_metadata` does not follow the link, so this reports the
            // link itself rather than whatever it points at.
            if let Ok(metadata) = tokio::fs::symlink_metadata(&next).await
                && metadata.file_type().is_symlink()
            {
                let resolved = tokio::fs::canonicalize(&next).await.map_err(|error| {
                    std::io::Error::other(format!("{error} resolving a workspace symlink"))
                })?;
                // Compared after canonicalization on both sides, so a link out
                // to somewhere else entirely is caught by the prefix check and a link
                // within the workspace is not.
                let canonical_workspace = tokio::fs::canonicalize(&workspace)
                    .await
                    .unwrap_or_else(|_| workspace.clone());
                if !resolved.starts_with(&canonical_workspace) {
                    return Err(CoreError::Forbidden(
                        "path leaves the workspace through a symlink".into(),
                    )
                    .into());
                }
            }
            walked = next;
        }
        Ok(target)
    }
    fn base(&self, sandbox: &Sandbox) -> PathBuf {
        self.root.join(sandbox.id.to_string())
    }
    async fn bounded(
        mut child: tokio::process::Child,
        timeout: u64,
        stdin: Option<String>,
    ) -> Result<ExecResult, RuntimeError> {
        let started = Instant::now();
        // Standard input is delivered by its own task rather than written
        // here. Writing inline blocks until the command either reads or exits,
        // so a command that closes its input without reading it failed the
        // whole exec with `EPIPE` instead of reporting the status it exited
        // with, and a command that never read it at all ran past its own
        // deadline because the wait below never started.
        let stdin_task = match stdin {
            Some(data) => {
                use tokio::io::AsyncWriteExt;
                let mut pipe = child
                    .stdin
                    .take()
                    .ok_or_else(|| RuntimeError::Unavailable("stdin unavailable".into()))?;
                Some(tokio::spawn(async move {
                    // Closing here is what tells a reader that has consumed
                    // everything to see EOF.
                    pipe.write_all(data.as_bytes()).await?;
                    pipe.shutdown().await
                }))
            }
            None => None,
        };
        // The channels are unbounded so a reader is never blocked on a send
        // while its consumer is still waiting for the command to exit. What
        // bounds them is `stream_pipe`: at most one stream limit is ever
        // forwarded, so a bounded channel capacity is not the memory bound,
        // and a full one is not a way to deadlock a writer the caller is still
        // waiting on.
        let (out_tx, mut out_rx) =
            tokio::sync::mpsc::unbounded_channel::<std::io::Result<Vec<u8>>>();
        let (err_tx, mut err_rx) =
            tokio::sync::mpsc::unbounded_channel::<std::io::Result<Vec<u8>>>();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("stdout unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("stderr unavailable".into()))?;
        // Chunks are sent as they arrive rather than accumulated and returned
        // at EOF. A command that exits while a backgrounded descendant still
        // holds its output pipes has finished, and the output it produced
        // before that is real output, not something to withhold until a pipe
        // this exec no longer owns finally closes.
        let out_task = tokio::spawn(stream_pipe(stdout, out_tx, MAX_STDOUT));
        let err_task = tokio::spawn(stream_pipe(stderr, err_tx, MAX_STDERR));
        let status = tokio::time::timeout(Duration::from_secs(timeout), child.wait()).await;
        let timed_out = status.is_err();
        let status = match status {
            Ok(status) => status?,
            Err(_) => {
                let _ = child.start_kill();
                // The post-kill wait is where a killed command's status comes
                // from. Reading it from the elapsed timeout instead made every
                // deadline produce `process ended without status`, so a
                // timed-out exec was reported as an error and never as a
                // timeout.
                child
                    .wait()
                    .await
                    .map_err(|_| RuntimeError::Unavailable("killed process has no status".into()))?
            }
        };
        // A pipe the command has already closed is not an exec failure: the
        // command chose not to read stdin, and `EPIPE` says only that the
        // reader went away. Any other write failure is real and reported.
        if let Some(task) = stdin_task {
            match tokio::time::timeout(DRAIN, task).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    if !matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) {
                        return Err(error.into());
                    }
                }
                // A writer still blocked on a command we just killed cannot
                // report anything, and its pipe is dropped with the task.
                Ok(Err(_)) | Err(_) => {}
            }
        }
        // One shared bound for both pipes, measured from here: a descendant
        // holding a pipe costs this exec one wait, not one per stream, and
        // whatever arrived before it is kept.
        let drains = Instant::now() + DRAIN;
        let out = drain_output(&mut out_rx, MAX_STDOUT, drains).await;
        let err = drain_output(&mut err_rx, MAX_STDERR, drains).await;
        // A stream that ends because its bound ran out is a truncated read of
        // output the caller asked for, not a failed exec. The command's own
        // status and timeout flag are what describe the run.
        if let Some(error) = out.1.or(err.1) {
            tracing::debug!(reason = %error, "exec output collection stopped early");
        }
        let out = out.0;
        let err = err.0;
        // The command has exited or been killed, so anything still holding a
        // pipe is a process this exec has already stopped waiting for. The
        // reader is released rather than awaited, which is what keeps one such
        // descendant from holding the caller's lifecycle gate.
        out_task.abort();
        err_task.abort();
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

/// How long an exec may spend collecting output after its command has ended.
/// A process this exec no longer owns may still hold an output pipe open, and
/// the caller's own deadline has already been spent; this is a second, much
/// smaller bound so one dead descendant cannot hold a sandbox's lifecycle gate.
const DRAIN: Duration = Duration::from_secs(2);

/// Sends each chunk of a pipe as it arrives, forwarding at most `limit` bytes
/// and discarding the rest while still reading to EOF.
///
/// Sending per chunk rather than accumulating and returning at EOF is what lets
/// a caller keep the output a command produced before its pipes stayed open.
/// Discarding is not stopping: a reader that stopped at the limit would close
/// the pipe under a command that is still writing and hand it a `SIGPIPE` for
/// output this side has already decided not to keep.
async fn stream_pipe<R>(
    mut pipe: R,
    sender: tokio::sync::mpsc::UnboundedSender<std::io::Result<Vec<u8>>>,
    limit: usize,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0; 8192];
    let mut forwarded = 0usize;
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                if forwarded >= limit {
                    continue;
                }
                let take = n.min(limit - forwarded);
                forwarded += take;
                if sender.send(Ok(buf[..take].to_vec())).is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.send(Err(error));
                return;
            }
        }
    }
}

/// Collects up to `limit` bytes that arrived before `deadline`. The second
/// element is the reason collection stopped early, if it did: a read failure,
/// or the bound running out with the pipe still open.
async fn drain_output(
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<std::io::Result<Vec<u8>>>,
    limit: usize,
    deadline: Instant,
) -> (Vec<u8>, Option<String>) {
    let mut collected: Vec<u8> = Vec::new();
    loop {
        if collected.len() >= limit {
            return (collected, Some("output limit reached".into()));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return (
                collected,
                Some("output pipe still open at its bound".into()),
            );
        }
        match tokio::time::timeout(remaining, receiver.recv()).await {
            Ok(Some(Ok(chunk))) => {
                let take = chunk.len().min(limit - collected.len());
                collected.extend_from_slice(&chunk[..take]);
            }
            Ok(Some(Err(error))) => {
                return (collected, Some(format!("output stream failed: {error}")));
            }
            // Every sender is gone, so this pipe reached EOF.
            Ok(None) => return (collected, None),
            Err(_) => {
                return (
                    collected,
                    Some("output pipe still open at its bound".into()),
                );
            }
        }
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
        // Intake (`validate_exec_environment`) already refused every entry this
        // filter would drop, so reaching the filter means the gate was bypassed
        // rather than the caller missent. Debug-assert the contract instead of
        // re-deciding: a silent drop here once ran commands with fewer
        // variables than the caller sent, which reads as success with wrong
        // inputs. Release keeps the filter as defence in depth.
        for (k, v) in &r.environment {
            debug_assert!(
                !k.is_empty() && !k.contains('=') && v.len() < 4096,
                "exec environment bypassed intake validation"
            );
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
        let path = self.resolve_in_workspace(s, &r.path).await?;
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
        let p = self.resolve_in_workspace(s, path).await?;
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
        let p = self.resolve_in_workspace(s, path).await?;
        let mut rd = tokio::fs::read_dir(p).await?;
        let mut out = vec![];
        while let Some(v) = rd.next_entry().await? {
            let m = v.metadata().await?;
            // Refused rather than shortened, and for the reason the other
            // runtimes give: a caller that walks a workspace treats a listing
            // as complete, so a truncated one archives a directory that is
            // missing files and reports it as whole. The guest chooses this
            // directory's size - the workspace is the tenant's to fill.
            if out.len() == MAX_LIST_ENTRIES {
                return Err(CoreError::LimitExceeded(format!(
                    "directory holds more than {MAX_LIST_ENTRIES} entries"
                ))
                .into());
            }
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
        let p = self.resolve_in_workspace(s, path).await?;
        match tokio::fs::remove_file(p).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    async fn make_directory(&self, s: &Sandbox, path: &str) -> Result<(), RuntimeError> {
        tokio::fs::create_dir_all(self.resolve_in_workspace(s, path).await?).await?;
        Ok(())
    }
    pub async fn snapshot(&self, s: &Sandbox, key: &str) -> Result<u64, RuntimeError> {
        let root = self.base(s).join("workspace");
        let out = self
            .root
            .join("snapshots")
            .join(format!("{}.tar", local_archive_name(key)?));
        if let Some(p) = out.parent() {
            tokio::fs::create_dir_all(p).await?;
        }
        // tar opens its output with truncate semantics, so pointing it straight
        // at `out` means a capture that fails part way through - an unreadable
        // file, a file deleted while it is being walked, a full disk - replaces
        // the archive already published under this key with a partial one and
        // then reports an error, leaving a snapshot the next restore cannot
        // use. Capture into a sibling temp file and publish it with rename so
        // the previous snapshot survives a failed capture intact.
        let temporary = out.with_extension("tar.partial");
        let output = Command::new("tar")
            .arg("-cf")
            .arg(&temporary)
            .arg("-C")
            .arg(&root)
            .arg(".")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await?;
        if !output.status.success() {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(RuntimeError::Archive(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        if let Err(error) = tokio::fs::rename(&temporary, &out).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error.into());
        }
        Ok(tokio::fs::metadata(out).await?.len())
    }
    pub async fn restore(&self, s: &Sandbox, key: &str) -> Result<(), RuntimeError> {
        let archive = self
            .root
            .join("snapshots")
            .join(format!("{}.tar", local_archive_name(key)?));
        let bytes = tokio::fs::read(&archive).await?;
        self.restore_bytes(s, bytes).await
    }
    /// Unpacks an archive the caller has already read and, where it matters,
    /// already verified.
    ///
    /// Taking the bytes rather than a key is what makes a digest check mean
    /// something: if the provider verified a digest and then re-read the file
    /// by key, a concurrent import publishing under that key in between would
    /// have the extracted archive differ from the verified one.
    pub async fn restore_bytes(&self, s: &Sandbox, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        let base = self.base(s);
        let root = base.join("workspace");
        tokio::fs::create_dir_all(&root).await?;
        // The bytes have to land on disk before tar can read them, and they must
        // land somewhere only this call uses for the duration.
        let unpacked = base.join(format!(".unpacked-{}.tar", Uuid::now_v7()));
        tokio::fs::write(&unpacked, &bytes).await?;
        // Extracting straight into the live workspace means a corrupt or
        // truncated archive leaves it half replaced: tar unpacks every member
        // it can reach and then fails, and the workspace it returns has lost
        // the files that archive did overwrite while never gaining the ones it
        // did not reach. Unpack into a staging directory and swap it in only
        // once tar has confirmed the whole archive landed.
        let staging = base.join(format!(".restore-{}", Uuid::now_v7()));
        let backup = base.join(format!(".previous-{}", Uuid::now_v7()));
        tokio::fs::create_dir_all(&staging).await?;
        let output = Command::new("tar")
            .arg("-xf")
            .arg(&unpacked)
            .arg("-C")
            .arg(&staging)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await;
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                let _ = tokio::fs::remove_dir_all(&staging).await;
                let _ = tokio::fs::remove_file(&unpacked).await;
                return Err(error.into());
            }
        };
        if !output.status.success() {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            let _ = tokio::fs::remove_file(&unpacked).await;
            return Err(RuntimeError::Archive(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        // `workspace` is bind-mounted into the sandbox at create time, so its
        // directory inode has to stay put: swapping the directory itself would
        // leave a running guest reading and writing the backup copy. Move the
        // entries in and out instead, rolling back on any failure so the
        // workspace is either wholly the archive or wholly what it was.
        fn remove(path: &std::path::Path) -> std::io::Result<()> {
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.is_dir() {
                std::fs::remove_dir_all(path)
            } else {
                std::fs::remove_file(path)
            }
        }
        tokio::fs::create_dir_all(&backup).await?;
        let mut displaced = Vec::new();
        let mut entries = tokio::fs::read_dir(&root).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            if let Err(error) = tokio::fs::rename(entry.path(), backup.join(&name)).await {
                // Eviction is not all-or-nothing, so the entries already moved
                // have to come back before returning: otherwise a rename that
                // failed on the third entry leaves the workspace silently
                // missing the first two, which is the half-replaced state the
                // staging above exists to prevent.
                for moved in displaced.iter().rev() {
                    let _ = tokio::fs::rename(backup.join(moved), root.join(moved)).await;
                }
                let _ = tokio::fs::remove_dir_all(&backup).await;
                let _ = tokio::fs::remove_dir_all(&staging).await;
                let _ = tokio::fs::remove_file(&unpacked).await;
                return Err(error.into());
            }
            displaced.push(name);
        }
        let mut moved = Vec::new();
        let mut staged = tokio::fs::read_dir(&staging).await?;
        let mut failure = None;
        while let Some(entry) = staged.next_entry().await? {
            let name = entry.file_name();
            match tokio::fs::rename(entry.path(), root.join(&name)).await {
                Ok(()) => moved.push(name),
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = failure {
            for name in moved.iter().rev() {
                let _ = remove(&root.join(name));
            }
            for name in displaced.iter().rev() {
                let _ = tokio::fs::rename(backup.join(name), root.join(name)).await;
            }
            let _ = tokio::fs::remove_dir_all(&backup).await;
            let _ = tokio::fs::remove_dir_all(&staging).await;
            let _ = tokio::fs::remove_file(&unpacked).await;
            return Err(error.into());
        }
        let _ = tokio::fs::remove_dir_all(&backup).await;
        let _ = tokio::fs::remove_dir_all(&staging).await;
        let _ = tokio::fs::remove_file(&unpacked).await;
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
            // The capture itself succeeded, so the oversized archive is sitting
            // at the key's path on the worker's disk. `destroy` removes the
            // sandbox base directory but not `root/snapshots`, so leaving it
            // there means every rejected capture keeps up to 64 MiB of a file
            // no code path will ever read, for as long as the worker lives.
            let rejected = self
                .root
                .join("snapshots")
                .join(format!("{}.tar", local_archive_name(key)?));
            let _ = tokio::fs::remove_file(&rejected).await;
            return Err(RuntimeError::Archive(
                "workspace archive exceeds 64 MiB".into(),
            ));
        }
        let bytes = tokio::fs::read(
            self.root
                .join("snapshots")
                .join(format!("{}.tar", local_archive_name(key)?)),
        )
        .await?;
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
        let name = local_archive_name(&archive.key)?;
        // The temporary name is per import, not per key. Two imports of the
        // same key - a restore racing a snapshot restore, say - would otherwise
        // write through one shared `.{name}.import` file and interleave their
        // bytes, so the rename that publishes it can land a spliced archive
        // under the key. Only the final rename is shared, and rename replaces
        // the destination atomically, so the published file is always one
        // whole archive.
        let temporary = directory.join(format!(".{name}.{}.import", Uuid::now_v7()));
        tokio::fs::write(&temporary, &archive.bytes).await?;
        if let Err(error) =
            tokio::fs::rename(&temporary, directory.join(format!("{name}.tar"))).await
        {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error.into());
        }
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
    async fn get_file_chunk(
        &self,
        sandbox: &Sandbox,
        request: FileChunkRequest,
    ) -> Result<FileChunk, CoreError> {
        let root = self.base(sandbox).join("workspace");
        tokio::task::spawn_blocking(move || request.read_workspace(&root))
            .await
            .map_err(|error| CoreError::Backend(error.to_string()))?
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
        // A key that cannot be used safely is a caller error, so it is reported
        // as one rather than being stringified into `Io` by `into_core`, where
        // it would be indistinguishable from a genuine disk fault.
        validate_archive_key(&metadata.object_key)
            .map_err(|error| CoreError::InvalidRequest(error.to_string()))?;
        // The archive is re-read from this worker's disk by key, so the key on
        // its own only proves *some* archive exists. The digest recorded next to
        // it is what binds those bytes to the snapshot being restored; without
        // this check a stale local archive left under a reused key is extracted
        // and reported as a successful restore of the wrong snapshot.
        let archive = self.root.join("snapshots").join(format!(
            "{}.tar",
            local_archive_name(&metadata.object_key)
                .map_err(|error| CoreError::InvalidRequest(error.to_string()))?
        ));
        let bytes = match tokio::fs::read(&archive).await {
            Ok(bytes) => bytes,
            // A missing local archive is not an I/O fault: this runtime only
            // holds the copy the capturing worker wrote, so a restore it cannot
            // serve from its own disk has to be handed those bytes. Naming the
            // reason keeps it attributable rather than an unattributed 500.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(CoreError::Conflict(format!(
                    "this runtime holds no workspace archive for {}; restore must supply the \
                     archive bytes captured by the owning worker",
                    metadata.object_key
                )));
            }
            Err(error) => return Err(CoreError::Io(error)),
        };
        if bytes.len() > MAX_WORKSPACE_ARCHIVE_BYTES {
            return Err(CoreError::LimitExceeded(
                "workspace snapshot exceeds 64 MiB".into(),
            ));
        }
        aiec_core::snapshots::verify_archive_checksum(&bytes, &metadata.checksum_sha256)?;
        // Unpack the bytes that were just verified. Handing `restore` the key
        // instead would make it read the file again, and a concurrent import
        // publishing under that key in between would have the archive actually
        // extracted differ from the one the digest was checked against.
        BubblewrapRuntime::restore_bytes(self, sandbox, bytes)
            .await
            .map_err(into_core)
    }
}

/// Where a create re-reads host headroom from before it allocates anything.
///
/// [`HostPressure::measure`] is the only thing that reads a real host. This is
/// the seam that lets a test state a reading instead of inheriting whatever
/// machine it happens to run on, which is the only way an admission decision
/// can be asserted at all.
pub trait HostPressureProbe: Send + Sync {
    fn measure(&self, workspace: &Path, reserves: HostReserves) -> HostPressure;
}

/// Reads the host this worker is running on.
#[derive(Clone, Copy, Debug, Default)]
pub struct MeasuredHostPressure;

impl HostPressureProbe for MeasuredHostPressure {
    fn measure(&self, workspace: &Path, reserves: HostReserves) -> HostPressure {
        HostPressure::measure(workspace, reserves)
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
    /// The build-time secret baked into the base guest image.
    ///
    /// Retained because the image build writes it and the guest image's own
    /// tooling reads it, but it is **no longer the control-channel credential**.
    /// Every sandbox gets its own identity from
    /// [`control_identity`], written into its own disk at create; a secret that
    /// every sandbox an image has ever started shares cannot authenticate any of
    /// them individually. What this value still buys is a placeholder that a
    /// sandbox's own create overwrites, so a disk that escaped the create path
    /// authenticates nothing.
    pub guest_secret: Vec<u8>,
    pub guest_cid: u32,
    pub readiness_timeout: Duration,
    /// Directory holding `guest-capabilities.json`, defaulting to the rootfs directory.
    pub guest_artifact_dir: Option<PathBuf>,
    /// Metadata of the configured guest image, when it was built from repository tooling.
    pub guest_artifact: Option<guest_artifact::GuestArtifact>,
    /// Whether this deployment refuses to boot a guest image that is unsigned or
    /// signed by a key the operator has removed.
    ///
    /// `None` means the deployment has not configured image trust, and the
    /// existing digest verification is the whole of what is checked. `Some` is
    /// the requirement a guarded workload sets, and it is enforced by
    /// [`FirecrackerConfig::check_guest_artifact`] before any boot.
    pub image_trust: Option<aiec_core::image_trust::ImageTrustGate>,
    /// Whether the deployment refuses to start without a verified coding guest image.
    pub require_coding_guest: bool,
    /// Host memory and disk held back before a create is admitted.
    ///
    /// The same reserve the worker's heartbeat publishes, so the reading a
    /// placement was admitted on and the reading a boot re-checks against are
    /// measured against one number. Defaults to [`HostReserves::default`].
    pub host_reserves: HostReserves,
}

/// The guest artifact metadata in `dir`, or `None` when there is no document.
///
/// Three outcomes, and the middle one is the one that used to be lost: no
/// document is a deployment without guest metadata, a document that does not
/// load is a deployment that must not start. Folding the second into the first
/// meant a guest image declaring an older protocol became `None`, every later
/// gate is `Some`-conditional, and the worker started against a guest it cannot
/// speak to - the failure then surfaces as every bounded chunk read erroring at
/// runtime instead of at startup, which is exactly when nobody is watching.
fn load_guest_artifact_metadata(
    dir: &Path,
) -> Result<Option<guest_artifact::GuestArtifact>, RuntimeError> {
    let path = dir.join(guest_artifact::GUEST_ARTIFACT_FILE);
    if !path.is_file() {
        return Ok(None);
    }
    let artifact = guest_artifact::load_guest_artifact(&path)?;
    tracing::info!(
        path = %path.display(),
        profile = %artifact.profile,
        version = %artifact.artifact_version,
        "loaded firecracker guest artifact metadata"
    );
    Ok(Some(artifact))
}

/// Reads the operator's image trust configuration from the environment, or
/// `None` when the deployment has not opted in.
///
/// Two variables, and both are needed before the gate can do anything:
/// `AIEC_REQUIRE_SIGNED_IMAGE` states the requirement, and
/// `AIEC_IMAGE_SIGNING_KEYS` points at a file of `key_id=hex` lines. A
/// requirement with no key file is a gate that admits nothing, so every boot of
/// a guarded workload is refused with "signed by unknown key" - which is the
/// correct answer, and much easier to diagnose than a gate that quietly behaves
/// as though signing were optional.
fn load_image_trust_from_env()
-> Result<Option<aiec_core::image_trust::ImageTrustGate>, RuntimeError> {
    let raw = match std::env::var("AIEC_REQUIRE_SIGNED_IMAGE") {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let requirement = aiec_core::image_trust::ImageTrustRequirement::parse(&raw)
        .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
    let mut gate = aiec_core::image_trust::ImageTrustGate::new(requirement);
    if let Some(path) = std::env::var_os("AIEC_IMAGE_SIGNING_KEYS") {
        let path = PathBuf::from(path);
        let document = std::fs::read_to_string(&path).map_err(|error| {
            RuntimeError::Unavailable(format!(
                "image signing keys {} are unreadable: {error}",
                path.display()
            ))
        })?;
        for (number, line) in document.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key_id, secret)) = line.split_once('=') else {
                return Err(RuntimeError::Unavailable(format!(
                    "image signing keys {} line {} is not key_id=hex",
                    path.display(),
                    number + 1
                )));
            };
            let secret = hex::decode(secret.trim()).map_err(|_| {
                RuntimeError::Unavailable(format!(
                    "image signing keys {} line {} is not hexadecimal",
                    path.display(),
                    number + 1
                ))
            })?;
            gate.insert_key(key_id.trim(), &secret)
                .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        }
    }
    tracing::info!(
        requirement = ?gate.requirement(),
        key_ids = gate.key_ids().len(),
        "loaded image trust configuration"
    );
    Ok(Some(gate))
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
        // A document that is present and rejected is not the same thing as no
        // document. Collapsing the two into `.ok()` meant a guest image
        // declaring an older protocol became "no metadata", every later gate is
        // `Some`-conditional, and the worker started happily against a guest it
        // cannot speak to - the failure then surfaces as every bounded chunk
        // read erroring at runtime instead of at startup, which is exactly the
        // moment an operator is not watching.
        let guest_artifact = match guest_artifact_dir.as_deref() {
            None => None,
            Some(dir) => Some(load_guest_artifact_metadata(dir)?),
        }
        .flatten();
        // The same variables `aiec worker` reads for the reserve it publishes
        // in every heartbeat, so the reading a placement is admitted on and the
        // reading a create re-checks against it are held to one number instead
        // of two that can drift.
        let reserve_mib = |name: &str, default: u64| {
            std::env::var(name)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(default)
        };
        let host_reserves = HostReserves::from_mib(
            reserve_mib("AIEC_WORKER_MEMORY_RESERVE_MIB", 512),
            reserve_mib("AIEC_WORKER_DISK_RESERVE_MIB", 2 * 1024),
        );
        let image_trust = load_image_trust_from_env()?;
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
            image_trust,
            require_coding_guest: std::env::var("AIEC_REQUIRE_CODING_GUEST")
                .is_ok_and(|value| value == "1"),
            host_reserves,
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

    /// Verifies the guest image digest, once per artifact identity.
    ///
    /// A worker calls this before it boots a guest. The result is cached
    /// because the same image is used for every sandbox on the node and the
    /// digest of a multi-gigabyte rootfs is not cheap to recompute per create.
    /// The cache is bounded on every axis it can grow on - entries, image bytes,
    /// how long a verdict is trusted, and how many images are hashed at once -
    /// and it is keyed on the complete identity of the files that were hashed,
    /// so a verdict is only ever reused for the same bytes at the same paths.
    pub fn verify_guest_image(&self) -> Result<(), RuntimeError> {
        let identity = match artifact_identity(
            &self.rootfs,
            &self.kernel,
            self.guest_artifact_dir.as_deref(),
            self.guest_artifact.as_ref(),
            self.require_coding_guest,
        ) {
            Ok(identity) => identity,
            // If the artifacts cannot be stat'd there is nothing to key on, and
            // the honest response is to verify rather than to guess.
            Err(_error) => {
                return self
                    .check_guest_artifact()
                    .map_err(|error| RuntimeError::Unavailable(error.to_string()));
            }
        };
        static VERIFIED: std::sync::LazyLock<VerificationCache> =
            std::sync::LazyLock::new(VerificationCache::default);
        let cache = &*VERIFIED;
        cache
            .verify(&identity.key, identity.bytes, || {
                self.check_guest_artifact()
                    .map_err(|error| error.to_string())
            })
            .map_err(RuntimeError::Unavailable)
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
        self.check_guest_capabilities()?;
        self.check_image_trust()
    }

    /// Refuses to boot a guest image whose signed manifest this deployment does
    /// not admit.
    ///
    /// The digests checked here are of the bytes on disk, streamed, and they are
    /// compared against what the manifest records. That is the whole point: a
    /// manifest that agrees with itself but not with the image is the case
    /// signing exists to catch, and a check that compared the manifest against
    /// itself would wave it through.
    ///
    /// A deployment with no `image_trust` configured keeps the digest
    /// verification it always had and claims nothing beyond it. There is no TPM,
    /// no measured boot and no attestation here, and none is claimed: what this
    /// establishes is that the kernel and rootfs about to be booted are the ones
    /// an operator signed, not that a running guest is unmodified.
    pub fn check_image_trust(&self) -> Result<(), RuntimeError> {
        let Some(gate) = &self.image_trust else {
            return Ok(());
        };
        if !gate.is_required() {
            return Ok(());
        }
        let dir = self
            .guest_artifact_dir
            .clone()
            .or_else(|| self.rootfs.parent().map(Path::to_path_buf));
        let manifest = match dir.as_deref() {
            // No directory means no manifest, and a required gate refuses that.
            None => None,
            Some(dir) => {
                let path = dir.join(aiec_core::image_trust::TRUSTED_IMAGE_FILE);
                if path.is_file() {
                    Some(
                        aiec_core::image_trust::TrustedImageManifest::load(&path)
                            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?,
                    )
                } else {
                    None
                }
            }
        };
        let kernel_sha256 = control_identity::file_digest(&self.kernel)?;
        let rootfs_sha256 = control_identity::file_digest(&self.rootfs)?;
        let image = gate
            .admit(
                manifest.as_ref(),
                &kernel_sha256,
                &rootfs_sha256,
                chrono::Utc::now(),
            )
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        tracing::info!(
            reference = %image.reference(),
            key_id = %image.key_id(),
            kernel_sha256 = %image.kernel_sha256(),
            rootfs_sha256 = %image.rootfs_sha256(),
            "admitted a signed guest image"
        );
        Ok(())
    }

    /// Checks the guest capability requirements without hashing the image.
    ///
    /// The control plane calls this at startup: reading the artifact metadata is
    /// cheap, while hashing a multi-gigabyte rootfs is not something to pay on
    /// every API boot. [`Self::check_guest_artifact`] adds the digest
    /// verification and is the check a worker runs before it boots a guest.
    pub fn check_guest_capabilities(&self) -> Result<(), RuntimeError> {
        if let Some(artifact) = &self.guest_artifact {
            artifact.verify_protocol()?;
        }
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
    /// Host socket directory for the sandbox's real Firecracker control channels.
    pub fn socket_dir(&self, id: Uuid) -> PathBuf {
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

    /// Smallest disk, in MiB, a sandbox on this configuration can hold.
    ///
    /// Every sandbox's disk starts as a copy of the base image, so a request
    /// below the image's own size cannot be honoured: the copy needs the whole
    /// image before the guest writes a byte, and the guest may then fill the
    /// whole filesystem. Reporting the image's own size as a floor is what
    /// keeps a small request from being admitted onto a host that cannot hold
    /// the image it is about to copy. Zero when the image cannot be read, which
    /// [`Self::check`] refuses anyway, so no floor is claimed for it.
    pub fn minimum_disk_mb(&self) -> u64 {
        self.base_image_bytes()
            .div_ceil(aiec_core::host_pressure::MIB)
    }

    /// Logical size of the base image, or zero when it cannot be read.
    ///
    /// A single `stat` of a file this path is about to read in full anyway, and
    /// the answer is used twice on one create: for the disk the host has to
    /// have, and for the comparison that decides whether the copy is resized.
    pub fn base_image_bytes(&self) -> u64 {
        std::fs::metadata(&self.rootfs)
            .map(|metadata| metadata.len())
            .unwrap_or_default()
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

    /// Cancellation handles for the lifetime timers still armed, keyed by the
    /// start token of the VM each timer protects.
    ///
    /// A timer owns a sender here and holds the matching receiver inside the
    /// task it spawned, so taking the entry out ends that task at once. Every
    /// path that takes a VM out of the map takes its entry out first: a stopped
    /// or destroyed sandbox has nothing left to time out, so its timer must not
    /// stay sleeping - holding a runtime and a sandbox alive - for the rest of
    /// a TTL that can no longer act on anything.
    ///
    /// Keyed by start token rather than by sandbox id because one id outlives
    /// its VM: a restarted sandbox is a new token, and a timer may only ever be
    /// able to end its own.
    lifetimes: Arc<Mutex<HashMap<Uuid, oneshot::Sender<()>>>>,
    network: Arc<dyn NetworkBackend>,
    /// One gate per sandbox for the operations that change what exists for it.
    ///
    /// Shared by every clone of this runtime, which is what makes the guarantee
    /// hold for a worker: the clone a lifetime timer stops a VM with is the
    /// clone a request creates one with.
    lifecycle: Arc<SandboxLifecycle>,
    /// The host a create re-measures before it materializes anything.
    pressure: Arc<dyn HostPressureProbe>,
    /// Per-sandbox control identities for the host/guest vsock channel.
    ///
    /// This is what replaced the shared build-time guest secret. The store is
    /// per-worker state under [`control_identity::CONTROL_IDENTITY_DIR`], which
    /// is a sibling of `vms/` and `snapshots/` and inside neither, so an
    /// identity is not carried by a snapshot of either.
    identities: Arc<control_identity::LazyControlIdentityStore>,
    /// The [`Sandbox`] each live VM was published for.
    ///
    /// Every other teardown arrives as a request that already holds one. The
    /// worker's exit does not: a shutdown has to release an attachment and
    /// revoke an identity for machines nobody is asking about, and both of
    /// those are checked against the identity the machine was created under.
    /// Entries are written by [`Self::publish_vm`] and dropped by the teardown
    /// that takes the VM out of [`Self::vms`].
    owners: Arc<Mutex<HashMap<Uuid, Sandbox>>>,
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
/// A path is not enough - a rootfs can be replaced at the same path - and a
/// process-wide result is not enough at all. The identity is everything the
/// check actually reads: for each file, its size, its nanosecond modification
/// time, its nanosecond status-change time, and the inode and device it lives
/// on, plus the artifact metadata document the digest comparison is made
/// against.
///
/// The nanosecond fields are the load-bearing part. `Metadata::mtime` is whole
/// seconds on this platform, so a rootfs that is rewritten in place with the
/// same length inside the same second is a different image with an identical
/// key, and the cached success would be applied to bytes nobody verified. The
/// inode and device catch the other case: a file replaced by an atomic rename
/// can land on a different inode with a new timestamp granularity the caller
/// cannot see, and a `rootfs` moved onto another filesystem is a different
/// object entirely.
///
/// What this cannot see is a rewrite that preserves size, inode, device and
/// every timestamp - which means writing over the image's own blocks without
/// letting the filesystem record it. Re-hashing is the only defence against
/// that, and doing it per create is the cost the cache exists to avoid.
struct ArtifactIdentity {
    /// The key a verification verdict is remembered under.
    key: String,
    /// The bytes the verdict is about, for the cache's byte bound.
    bytes: u64,
}

/// Describes one file in a way that changes when its content does.
fn describe_file(path: &Path) -> std::io::Result<(String, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok((
        format!(
            "{}:dev={}:ino={}:size={}:mtime={}.{}:ctime={}.{}",
            path.display(),
            meta.dev(),
            meta.ino(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        ),
        meta.size(),
    ))
}

/// Builds the identity a verification verdict is valid for.
fn artifact_identity(
    rootfs: &Path,
    kernel: &Path,
    artifact_dir: Option<&Path>,
    artifact: Option<&guest_artifact::GuestArtifact>,
    require_coding_guest: bool,
) -> std::io::Result<ArtifactIdentity> {
    let (rootfs_identity, rootfs_bytes) = describe_file(rootfs)?;
    let (kernel_identity, kernel_bytes) = describe_file(kernel)?;
    // The whole artifact metadata, serialised, plus the flag derived from it.
    //
    // Listing fields by hand is how the previous version was wrong: a key built
    // from the ones I thought of looked complete and was not, because the check
    // also consults `require_coding_guest`, and a lax configuration's success
    // would satisfy a strict one. Serialising the input means a field added to
    // the check later is in the key the day it is added, rather than on the day
    // somebody remembers.
    let metadata = serde_json::to_string(&artifact).unwrap_or_else(|_| "unserialisable".into());
    // `check_guest_artifact` re-reads the document from disk on every call, so
    // the in-memory copy is not what the verdict is about. Keying on the
    // loaded metadata alone would let a manifest edited under a running worker
    // keep the success recorded against the old one, which is the same
    // "verified sometime earlier" failure one level down.
    let manifest = match (artifact, artifact_dir) {
        (Some(_), Some(dir)) => describe_file(&dir.join(guest_artifact::GUEST_ARTIFACT_FILE))?.0,
        _ => "no-manifest".to_string(),
    };
    Ok(ArtifactIdentity {
        key: format!(
            "{rootfs_identity}|{kernel_identity}|{manifest}|coding={require_coding_guest}|{metadata}"
        ),
        bytes: rootfs_bytes + kernel_bytes,
    })
}

/// The bounds a [`VerificationCache`] works within.
///
/// The cache exists so a worker does not re-hash a multi-gigabyte rootfs on
/// every create. It remembers an expensive, immutable fact, so it is bounded on
/// every axis a long-lived process can grow on: how many identities are
/// remembered, how many image bytes those identities account for, how long a
/// verdict is trusted, and how many images are being hashed at the same time.
/// The numbers are deliberately small and conservative - a worker has one
/// image, and a cache that cannot hold two is a bound rather than an outage.
#[derive(Clone, Copy, Debug)]
struct VerificationLimits {
    /// Maximum number of distinct artifact identities remembered.
    max_entries: usize,
    /// Maximum total image bytes the remembered identities may account for.
    max_bytes: u64,
    /// How long a successful verification is trusted without rehashing.
    success_ttl: Duration,
    /// How long a failed verification is remembered.
    ///
    /// Short on purpose. A failure has to stay visible - caching successes and
    /// dropping failures would turn a broken image into a silently booting one -
    /// but a worker that is repaired must not be told "still broken" forever
    /// either. A new artifact is a new identity, so nothing here can make an
    /// old verdict apply to bytes nobody verified; this bound only decides when
    /// the same bytes get a second chance.
    failure_ttl: Duration,
    /// Maximum number of distinct images hashed concurrently.
    max_concurrent: usize,
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self {
            max_entries: 8,
            max_bytes: 8 * 1024 * 1024 * 1024,
            // The image is immutable for the life of a worker, so an hour is
            // generous; it exists so a long-lived process still re-verifies
            // rather than trusting a verdict forever.
            success_ttl: Duration::from_secs(3600),
            failure_ttl: Duration::from_secs(60),
            // Hashing is I/O bound and reads the whole image. Two at a time keeps
            // a worker from saturating its own disk during a restart storm
            // without ever serialising legitimate distinct images.
            max_concurrent: 2,
        }
    }
}

/// One remembered verdict.
struct VerificationEntry {
    outcome: Result<(), String>,
    verified_at: Instant,
    /// The image bytes this verdict is about, for the cache's byte bound.
    bytes: u64,
}

/// The single verification running for one identity, and the result waiters
/// block on.
#[derive(Default)]
struct VerificationSlot {
    outcome: std::sync::Mutex<Option<Result<(), String>>>,
    settled: std::sync::Condvar,
}

impl VerificationSlot {
    /// Publishes the verdict and releases every waiter.
    fn complete(&self, outcome: Result<(), String>) {
        *lock(&self.outcome) = Some(outcome);
        self.settled.notify_all();
    }

    /// Blocks until the one verification this slot stands for has finished.
    fn wait(&self) -> Result<(), String> {
        let mut outcome = lock(&self.outcome);
        loop {
            if let Some(outcome) = outcome.as_ref() {
                return outcome.clone();
            }
            outcome = self
                .settled
                .wait(outcome)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Everything the cache is currently holding.
#[derive(Default)]
struct VerificationState {
    entries: HashMap<String, VerificationEntry>,
    /// The sum of `bytes` over `entries`, so the byte bound is O(1) to enforce.
    accounted_bytes: u64,
    /// Identities currently being verified, each with the slot its waiters use.
    in_flight: HashMap<String, Arc<VerificationSlot>>,
    /// How many verifications are running, for the concurrency bound.
    hashing: usize,
}

impl VerificationState {
    /// Returns a verdict that is still inside its time to live, dropping one
    /// that is not.
    fn fresh(&mut self, key: &str, limits: &VerificationLimits) -> Option<Result<(), String>> {
        let ttl = match self.entries.get(key) {
            Some(entry) if entry.outcome.is_ok() => limits.success_ttl,
            Some(_) => limits.failure_ttl,
            None => return None,
        };
        match self.entries.get(key) {
            Some(entry) if entry.verified_at.elapsed() < ttl => Some(entry.outcome.clone()),
            Some(_) => {
                self.remove(key);
                None
            }
            None => None,
        }
    }

    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.accounted_bytes = self.accounted_bytes.saturating_sub(entry.bytes);
        }
    }

    /// Remembers a verdict, evicting oldest-first until the bounds hold again.
    ///
    /// Eviction is by oldest verification time with the key as the tie-break, so
    /// two processes that reach the same limits drop the same entry rather than
    /// each keeping whichever one it happened to reach first.
    fn record(
        &mut self,
        key: String,
        outcome: Result<(), String>,
        bytes: u64,
        limits: &VerificationLimits,
    ) {
        self.remove(&key);
        self.entries.insert(
            key.clone(),
            VerificationEntry {
                outcome,
                verified_at: Instant::now(),
                bytes,
            },
        );
        self.accounted_bytes += bytes;
        while self.entries.len() > limits.max_entries || self.accounted_bytes > limits.max_bytes {
            let Some(oldest) = self.oldest() else { break };
            self.remove(&oldest);
        }
    }

    fn oldest(&self) -> Option<String> {
        self.entries
            .iter()
            .min_by(|left, right| {
                left.1
                    .verified_at
                    .cmp(&right.1.verified_at)
                    .then_with(|| left.0.cmp(right.0))
            })
            .map(|(key, _)| key.clone())
    }
}

/// A process-wide cache of guest image verification verdicts.
///
/// One entry per artifact identity, and at most one verification running per
/// identity: a worker that restarts twice in a minute would otherwise hash the
/// same multi-gigabyte image twice at once, on the disk the guests are about to
/// share with it.
#[derive(Default)]
struct VerificationCache {
    limits: VerificationLimits,
    state: std::sync::Mutex<VerificationState>,
    /// Signalled when a verification settles or a concurrency slot frees.
    changed: std::sync::Condvar,
}

impl VerificationCache {
    /// A cache with explicit bounds. The process-wide cache uses
    /// [`VerificationLimits::default`]; only the tests need to move the numbers.
    #[cfg(test)]
    fn new(limits: VerificationLimits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Returns the verdict for `key`, verifying it with `work` if there is no
    /// live one.
    fn verify(
        &self,
        key: &str,
        bytes: u64,
        work: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        loop {
            let mut state = lock(&self.state);
            if let Some(outcome) = state.fresh(key, &self.limits) {
                return outcome;
            }
            // Someone is already hashing these exact bytes: wait for their
            // verdict rather than hashing them a second time.
            if let Some(slot) = state.in_flight.get(key).cloned() {
                drop(state);
                return slot.wait();
            }
            if state.hashing >= self.limits.max_concurrent {
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                continue;
            }
            let slot = Arc::new(VerificationSlot::default());
            state.in_flight.insert(key.to_owned(), slot.clone());
            state.hashing += 1;
            drop(state);

            // The guard is what makes a panic safe: without it the identity
            // would stay in flight forever and every later caller for it would
            // block on a slot nobody will ever complete.
            let mut run = InFlight {
                cache: self,
                key: key.to_owned(),
                slot: slot.clone(),
                armed: true,
            };
            let outcome = work();
            run.settle(outcome.clone(), bytes);
            return outcome;
        }
    }

    /// Records a settled verification and releases its waiters.
    fn settle(
        &self,
        key: &str,
        slot: &Arc<VerificationSlot>,
        outcome: Result<(), String>,
        bytes: u64,
    ) {
        let mut state = lock(&self.state);
        state.hashing = state.hashing.saturating_sub(1);
        state.in_flight.remove(key);
        state.record(key.to_owned(), outcome.clone(), bytes, &self.limits);
        drop(state);
        slot.complete(outcome);
        // Woken here rather than at the call site so that a verification that
        // unwound also releases a caller waiting for a concurrency slot.
        self.changed.notify_all();
    }

    /// Releases a verification that unwound, so nobody waits on it forever.
    fn abandon(&self, key: &str, slot: &Arc<VerificationSlot>) {
        self.settle(
            key,
            slot,
            Err("guest image verification did not complete".to_string()),
            0,
        );
    }
}

/// A verification that is in flight, and must be settled or abandoned.
struct InFlight<'a> {
    cache: &'a VerificationCache,
    key: String,
    slot: Arc<VerificationSlot>,
    armed: bool,
}

impl InFlight<'_> {
    fn settle(&mut self, outcome: Result<(), String>, bytes: u64) {
        self.armed = false;
        self.cache.settle(&self.key, &self.slot, outcome, bytes);
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.cache.abandon(&self.key, &self.slot);
        }
    }
}

/// Locks a mutex the crash of an unrelated task must not turn into a
/// permanently broken cache: a poisoned verdict is a wrong answer, not a reason
/// to refuse every later one.
fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl FirecrackerRuntime {
    pub fn new(config: FirecrackerConfig) -> Self {
        let network = GuardNetworkManager::new(config.state_dir.join("guard"));
        Self::with_network_backend(config, Arc::new(network))
    }

    pub fn with_network_backend(
        config: FirecrackerConfig,
        network: Arc<dyn NetworkBackend>,
    ) -> Self {
        let identities = control_identity::LazyControlIdentityStore::new(
            config
                .state_dir
                .join(control_identity::CONTROL_IDENTITY_DIR),
        );
        Self {
            config,
            vms: Arc::new(Mutex::new(HashMap::new())),
            lifetimes: Arc::new(Mutex::new(HashMap::new())),
            network,
            lifecycle: Arc::new(SandboxLifecycle::new()),
            pressure: Arc::new(MeasuredHostPressure),
            owners: Arc::new(Mutex::new(HashMap::new())),
            identities: Arc::new(identities),
        }
    }
    /// Admits the signed image a guarded workload demanded, before any machine
    /// exists for it.
    ///
    /// The deployment-wide setting is read once, at worker start, and cannot
    /// know which sandbox asked. A per-sandbox `require_signed_image` therefore
    /// re-admits here with a required gate: with no operator keys in it, that
    /// gate admits nothing, because an unsigned image is not signed.
    async fn admit_signed_image(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        if !sandbox
            .environment
            .guard
            .as_ref()
            .is_some_and(|guard| guard.require_signed_image)
        {
            return Ok(());
        }
        let mut config = self.config.clone();
        if !config
            .image_trust
            .as_ref()
            .is_some_and(aiec_core::image_trust::ImageTrustGate::is_required)
        {
            config.image_trust = Some(aiec_core::image_trust::ImageTrustGate::new(
                aiec_core::image_trust::ImageTrustRequirement::REQUIRED,
            ));
        }
        tokio::task::spawn_blocking(move || config.check_image_trust())
            .await
            .map_err(|error| {
                RuntimeError::Unavailable(format!("image admission task failed: {error}"))
            })?
    }

    /// The per-sandbox control identity store backing the guest control channel.
    ///
    /// Public so a worker can issue, rotate and revoke an identity without
    /// reaching into the runtime's private state, and so an operator tool can
    /// report whether a sandbox currently has a live identity at all.
    pub fn control_identities(
        &self,
    ) -> Result<&control_identity::ControlIdentityStore, RuntimeError> {
        self.identities.get()
    }

    /// Replaces the store identities are issued from.
    ///
    /// For a deployment that keeps its control identities somewhere other than
    /// the default state directory, and for tests that need a store whose
    /// lifetime they control.
    pub fn with_control_identity_store(
        mut self,
        store: Arc<control_identity::LazyControlIdentityStore>,
    ) -> Self {
        self.identities = store;
        self
    }

    /// Replaces the host a create re-measures its headroom against.
    pub fn with_host_pressure_probe(mut self, pressure: Arc<dyn HostPressureProbe>) -> Self {
        self.pressure = pressure;
        self
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
        self.api_response(socket, method, path, body)
            .await
            .map(|_| ())
    }

    /// The same exchange, returning the response body.
    ///
    /// Exists for the one question `api` cannot answer: what state Firecracker
    /// says this VM is in. Every other caller wants the status only, and
    /// parsing a body nobody reads would be work for its own sake.
    async fn api_response(
        &self,
        socket: &Path,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<Vec<u8>, RuntimeError> {
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
        // The deadline covers the whole exchange, not just the connect. It used
        // to stop at a connected socket, so a Firecracker API that accepted the
        // connection and then stopped responding blocked here forever - and
        // this is called from paths that hold the sandbox's lifecycle gate, so
        // one wedged VM froze every operation on it, including destroy.
        let exchange = async {
            // Every I/O failure on this exchange names the request that
            // produced it. A bare `io: early eof` - which is what a server
            // that closes mid-response looks like - says nothing about which of
            // the six configuration calls it came from, and nothing in the
            // process that receives it can recover the request afterwards.
            let fail = |error: std::io::Error| {
                RuntimeError::FirecrackerApi(format!("{method} {path}: {error}"))
            };
            let body = body.map(|value| serde_json::to_vec(&value)).transpose()?;
            let body = body.unwrap_or_default();
            let request = format!(
                "{method} http://localhost{path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(request.as_bytes()).await.map_err(fail)?;
            stream.write_all(&body).await.map_err(fail)?;
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            while !header.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).await.map_err(fail)? == 0 {
                    return Err(RuntimeError::FirecrackerApi(
                        "API closed before response headers".into(),
                    ));
                }
                header.push(byte[0]);
                if header.len() > HEADER_LIMIT {
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
            // Checked against a bound before it is allocated. A
            // `Content-Length` read straight off the wire sized a `Vec`, so a
            // response that claimed a large body reserved it before a byte had
            // been read.
            if content_length > BODY_LIMIT {
                return Err(RuntimeError::FirecrackerApi(format!(
                    "API response body of {content_length} bytes exceeds the {BODY_LIMIT} byte limit"
                )));
            }
            let mut response_body = vec![0; content_length];
            stream.read_exact(&mut response_body).await.map_err(fail)?;
            if !(200..300).contains(&status) {
                return Err(RuntimeError::FirecrackerApi(format!(
                    "{method} {path} returned {status}: {}",
                    String::from_utf8_lossy(&response_body)
                )));
            }
            Ok(response_body)
        };
        match tokio::time::timeout_at(deadline, exchange).await {
            Ok(result) => result,
            Err(_) => Err(RuntimeError::FirecrackerApi(format!(
                "{method} {path} did not complete within 5s"
            ))),
        }
    }

    /// The state Firecracker reports for this VM, in its own API's words.
    ///
    /// Asked rather than remembered. A guest call issued against a VM that is
    /// already paused has no guest agent left to answer it, and the failure
    /// mode of guessing wrong is a blocked channel rather than an error.
    ///
    /// Read from `GET /`, which is where this Firecracker keeps it: the root
    /// document answers `{"id","state","app_name","vmm_version"}`.
    ///
    /// Neither of the two paths that look right is. `GET /vm` is refused with
    /// `Invalid request method and/or path: GET vm.` because `/vm` accepts
    /// only `PUT` and `PATCH`, and `GET /instance-info` is refused with
    /// `Invalid request method and/or path: GET instance-info.` on 1.17.0.
    /// Both were tried live against this exact binary; the error is the only
    /// thing that distinguishes them from a working call in the source.
    async fn vm_state(&self, socket: &Path) -> Result<String, RuntimeError> {
        let body = self.api_response(socket, "GET", "/", None).await?;
        let value: serde_json::Value = serde_json::from_slice(&body).map_err(|error| {
            RuntimeError::FirecrackerApi(format!("GET / returned malformed JSON: {error}"))
        })?;
        value
            .get("state")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| RuntimeError::FirecrackerApi("GET / did not report a state".into()))
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

    /// The control-channel key for one sandbox.
    ///
    /// Resolved per call rather than cached, because the answer changes: an
    /// identity that has been rotated, has expired, or has been revoked stops
    /// being usable at the moment it stops being current, not at the next
    /// restart.
    fn guest_frame_key(
        &self,
        sandbox_id: Uuid,
    ) -> Result<control_identity::SecretBytes, RuntimeError> {
        self.identities.get()?.frame_key(sandbox_id)
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
        // The per-sandbox identity, not the shared build-time secret. A sandbox
        // with no live identity - never issued, expired, or revoked - has no key
        // here, and the call is refused before a byte is written rather than
        // falling back to a credential every sandbox shares.
        let key = self.guest_frame_key(id)?;
        let mut stream = self.connect_guest(id).await?;
        let body = serde_json::to_vec(&request)?;
        let frame = frame_bytes(key.expose(), &body);
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
        // JSON byte arrays need at most four wire bytes per payload byte.
        let response_limit = if matches!(request.operation, Operation::ReadFileChunk) {
            aiec_core::runtime::FILE_CHUNK_BYTES * 4 + 4096
        } else {
            protocol::MAX_FRAME
        };
        let response = match tokio::time::timeout(
            remaining,
            read_frame_async_bounded(&mut stream, key.expose(), response_limit),
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
        if response.version != protocol::PROTOCOL_VERSION {
            return Err(RuntimeError::Protocol(protocol::ProtocolError::Version(
                response.version,
            )));
        }
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
        let result = match tokio::time::timeout(
            self.guest_call_timeout(&request),
            self.guest_call_inner(id, request),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(RuntimeError::Unavailable(
                "guest vsock call timed out".into(),
            )),
        };
        // A call that fails without a reply - the guest closed the channel, or
        // the framing broke - is otherwise indistinguishable from any other
        // transport failure, and the operation is the one thing that says which
        // request was in flight. The guest's own refusals arrive as an error
        // response and are already specific.
        result.map_err(|error| match error {
            RuntimeError::Io(cause) => RuntimeError::Io(std::io::Error::new(
                cause.kind(),
                format!("guest {operation:?}: {cause}"),
            )),
            other => other,
        })
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
        vm.network = if sandbox.network.is_enabled() || sandbox.environment.guard.is_some() {
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
                Ok(ResponsePayload::Health { ready: true }) => {
                    if sandbox.environment.guard.is_some() {
                        let gateway = vm
                            .network
                            .as_ref()
                            .and_then(|network| network.addresses.first())
                            .ok_or_else(|| {
                                RuntimeError::Unavailable("Guard gateway attachment missing".into())
                            })?
                            .parse::<std::net::Ipv4Addr>()
                            .map_err(|_| {
                                RuntimeError::Unavailable("invalid Guard gateway address".into())
                            })?;
                        // Existing rootfs images contain public resolvers. Configure
                        // the only permitted resolver before accepting workloads.
                        let configured = self.guest_call(
                            sandbox.id,
                            Operation::Exec,
                            RequestPayload::Exec {
                                argv: vec!["/bin/sh".into(), "-c".into(), format!(
                                    "printf 'nameserver {gateway}\\noptions timeout:1 attempts:1\\n' > /etc/resolv.conf"
                                )],
                                cwd: None,
                                env: Default::default(),
                                timeout_ms: 3000,
                                output_limit: 1024,
                                stdin: Vec::new(),
                            },
                        ).await?;
                        if !matches!(
                            configured,
                            ResponsePayload::Exec {
                                exit_code: 0,
                                timed_out: false,
                                ..
                            }
                        ) {
                            return Err(RuntimeError::Unavailable(
                                "Guard guest resolver setup failed".into(),
                            ));
                        }
                    }
                    // Plant the configured file canaries in this sandbox's own
                    // workspace. Only workspace paths: the guest's write path
                    // is confined to the workspace, and the host-side read
                    // observation covers the control channel's file reads, so a
                    // canary outside the workspace could never be both planted
                    // and observed. No base image is ever written.
                    if let Some(guard) = &sandbox.environment.guard {
                        for canary in &guard.canaries.files {
                            if !canary.path.starts_with("/workspace/") {
                                continue;
                            }
                            self.guest_call(
                                sandbox.id,
                                Operation::WriteFile,
                                RequestPayload::WriteFile {
                                    path: canary.path.clone(),
                                    content: canary.value.as_bytes().to_vec(),
                                    mode: Some(0o600),
                                },
                            )
                            .await?;
                        }
                    }
                    return Ok(());
                }
                Ok(_) => {}
                Err(error) if tokio::time::Instant::now() < deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Publishes a booted VM and arms the timeout that stops it later.
    ///
    /// A VM already under this sandbox's id is replaced, and its timer ended
    /// with it: the entry in the map is the authority on what this id is
    /// running, and a second one running beside it has nothing left to time
    /// out.
    async fn publish_vm(&self, sandbox: &Sandbox, vm: FirecrackerVm) {
        let token = vm.start_token;
        let displaced = self.vms.lock().await.insert(sandbox.id, vm);
        // The record of what this VM belongs to, so a teardown that happens
        // without a request in hand - the worker shutting down - can still
        // release an attachment under the identity it was created with.
        self.owners.lock().await.insert(sandbox.id, sandbox.clone());
        if let Some(displaced) = displaced {
            self.lifetimes.lock().await.remove(&displaced.start_token);
        }
        self.schedule_lifetime(sandbox, token).await;
    }

    /// Arms the timeout that ends this sandbox's VM when its TTL runs out.
    ///
    /// The timer waits on its own timeout racing its own cancellation, so it
    /// ends when its entry is taken from [`Self::lifetimes`] without anything
    /// having to reach into the task - and ends when the timeout wins, having
    /// ended the VM that token started.
    ///
    /// A guarded sandbox is contained rather than stopped. Its TTL is the same
    /// deadline as the durable budget's `expires_at`, so stopping it here
    /// destroyed the machine at the exact moment the control plane's reaper
    /// was trying to cut, pause and capture it - the reaper could only lose,
    /// and an expired guarded sandbox was torn down with no quarantine and no
    /// forensics. Containment is the fail-closed terminal action as well: a
    /// guest that cannot be contained is stopped, never left running past its
    /// own allowance.
    async fn schedule_lifetime(&self, sandbox: &Sandbox, token: Uuid) {
        let (cancelled, expiry) = oneshot::channel();
        self.lifetimes.lock().await.insert(token, cancelled);
        let runtime = self.clone();
        let lifetime = sandbox.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(lifetime.timeout_seconds)) => {
                    runtime.expire_lifetime(&lifetime, token).await;
                }
                _ = expiry => {}
            }
            // Spent on either path, and only this timer may drop this entry: a
            // sandbox that has already been restarted is holding a different
            // token's timer under the same id.
            runtime.lifetimes.lock().await.remove(&token);
        });
    }

    /// Ends a sandbox whose own lifetime has run out, by the action its
    /// governance calls for.
    async fn expire_lifetime(&self, sandbox: &Sandbox, token: Uuid) {
        // This timer belongs to one VM, and a restart replaces the VM under the
        // same sandbox id. The identity is checked under the same lock that
        // registers a VM and is held across the containment, so a timer that
        // outlived its own machine can neither contain nor stop the
        // replacement - the invariant the token exists to enforce.
        let vms = self.vms.lock().await;
        if vms.get(&sandbox.id).map(|vm| vm.start_token) != Some(token) {
            return;
        }
        if sandbox.environment.guard.is_some() {
            match self.network.guard_hold_expired(sandbox).await {
                Ok(()) => return,
                Err(error) => tracing::warn!(
                    sandbox_id = %sandbox.id,
                    reason = %error,
                    "expired guarded sandbox could not be contained; stopping it instead"
                ),
            }
        }
        drop(vms);
        self.stop_if_token(sandbox, token).await;
    }

    /// Ends one machine: the process is killed and reaped, the attachment is
    /// released, and the guest is asked to stop first only when a request is
    /// waiting on the answer.
    ///
    /// `owner` is the sandbox the attachment was created for. It can be absent
    /// only on the worker's exit, where nothing is asking about this machine.
    /// The process still goes: a guest left running with no controller is the
    /// worse outcome, and an attachment record that cannot be released is inert
    /// without the guest behind it. Only the release is skipped, and it says so.
    async fn terminate_vm(
        &self,
        id: Uuid,
        owner: Option<&Sandbox>,
        mut vm: FirecrackerVm,
        graceful: Graceful,
    ) {
        // Only a request may wait on a guest that has to answer. On the exit
        // path a machine is often paused - a quarantined one always is - and a
        // paused guest has no agent scheduled to reply, so the write would sit
        // on the vsock until the call timeout, once per machine this process
        // still holds. The disk is deleted either way, so there is nothing for
        // a flushed guest to protect.
        if graceful == Graceful::Yes {
            let _ = self
                .guest_call(id, Operation::Shutdown, RequestPayload::None)
                .await;
        }
        let _ = vm.child.start_kill();
        let _ = vm.child.wait().await;
        if let Some(network) = &vm.network {
            match owner {
                Some(sandbox) => {
                    let _ = self.network.release(sandbox, network).await;
                }
                None => tracing::warn!(
                    sandbox_id = %id,
                    resource = %network.resource,
                    stage = "attachment_release_skipped",
                    "reclaimed a machine with no owner record; its attachment \
                     record is left for operator review"
                ),
            }
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
        // The VM is out of the map, so this timer has nothing left to stop.
        // End it before the teardown rather than after it: a teardown that
        // fails or blocks still leaves no sleeping task behind.
        self.lifetimes.lock().await.remove(&token);
        if let Some(vm) = vm {
            self.terminate_vm(sandbox.id, Some(sandbox), vm, Graceful::Yes)
                .await;
        }
    }
}

/// Whether a teardown may wait on a guest that has to answer before killing it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Graceful {
    /// A request is waiting on the outcome, and a running guest is told to
    /// stop itself first.
    Yes,
    /// The worker is exiting and nothing is waiting: the process is killed
    /// outright.
    No,
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

async fn read_frame_async_bounded<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    secret: &[u8],
    limit: usize,
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
    if length > limit {
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

/// Size of the buffer a disk image is streamed through when it is hashed.
///
/// Snapshot disks are whole sandbox disks, and a worker holds several of them
/// plus the guests that are running. The bound is what keeps hashing one of
/// them from being an allocation the size of the image.
const DISK_DIGEST_CHUNK: usize = 4 * 1024 * 1024;

/// Hex-encoded SHA-256 of `path`, streamed through a bounded buffer.
///
/// The digest is the same one a whole-file read would produce; what it does not
/// do is hold the image in memory to produce it. `guest_artifact.rs` already
/// streams for the same reason, and the snapshot path reading a full disk into
/// RAM to check it was the counter-example next to it.
async fn disk_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buffer = vec![0u8; DISK_DIGEST_CHUNK];
    let mut digest = Sha256::new();
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

impl FirecrackerRuntime {
    /// Takes this sandbox's lifecycle gate.
    ///
    /// Refused rather than queued when the table is full: every holder is real
    /// work, and the alternative to a refusal is an unbounded map keyed by a
    /// request-supplied sandbox id.
    async fn enter_lifecycle(
        &self,
        sandbox_id: Uuid,
    ) -> Result<SandboxLifecycleGuard, RuntimeError> {
        self.lifecycle
            .enter(sandbox_id)
            .await
            .map_err(|busy| RuntimeError::Unavailable(busy.to_string()))
    }

    /// The headroom this host has to have for `sandbox`, measured now.
    ///
    /// Fails closed on both counts: a reading that could not be taken is not a
    /// reading, and a reading with less room than the sandbox needs is the
    /// host's own answer. The demand is the guest's own vCPU count, its
    /// configured memory, and the larger of the requested disk and the base
    /// image's own size, because every sandbox disk starts as a copy of that
    /// image and the guest may then fill the whole filesystem.
    fn admit(
        &self,
        sandbox: &Sandbox,
        base_image_bytes: u64,
    ) -> Result<HostPressure, RuntimeError> {
        let pressure = self
            .pressure
            .measure(&self.config.state_dir, self.config.host_reserves);
        let memory_bytes =
            u64::from(sandbox.memory_mb).saturating_mul(aiec_core::host_pressure::MIB);
        let disk_mb = u64::from(sandbox.disk_mb)
            .max(base_image_bytes.div_ceil(aiec_core::host_pressure::MIB));
        let disk_bytes = disk_mb.saturating_mul(aiec_core::host_pressure::MIB);
        match pressure.admits(sandbox.cpu, memory_bytes, disk_bytes) {
            Ok(()) => Ok(pressure),
            // The reading's own wording, without the `core:` prefix this crate
            // would otherwise wrap it in: the operator reading a refused create
            // needs the numbers, not this crate's error taxonomy.
            Err(CoreError::Unavailable(message)) => Err(RuntimeError::Unavailable(message)),
            Err(error) => Err(RuntimeError::Core(error)),
        }
    }

    async fn create(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        let started = Instant::now();
        tracing::info!(sandbox_id = %sandbox.id, runtime = "firecracker", stage = "create_begin", "firecracker create started");
        // One sandbox's lifecycle at a time, so a destroy cannot report success
        // while this create is still copying into the directory it removes, and
        // so the copy that follows is the only one writing there.
        let _lifecycle = self.enter_lifecycle(sandbox.id).await?;
        self.admit_signed_image(sandbox).await?;
        // Admission is the first thing this asks, before it validates anything
        // and before it writes anything. A host that cannot physically hold the
        // sandbox is refused whether or not its configuration is also wrong,
        // and a refused create has not yet created a directory, copied an
        // image, or reserved a byte. The heartbeat that admitted the placement
        // is already stale by the time a create reaches the runtime: the host
        // fills between the two, and this is the reading taken immediately
        // before the money is spent.
        // One stat of the base image, taken before the copy that reads it, and
        // reused below where the copy is compared against it.
        let base_image_bytes = self.config.base_image_bytes();
        self.admit(sandbox, base_image_bytes)?;
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
        // Copy-on-write clone of the base image where the filesystem supports
        // it, full copy where it does not. The blocking syscall runs on the
        // blocking pool; the existing 120s bound still covers the whole
        // materialization. Timing out drops the future, which is also the
        // cancellation signal: the copy stops at its next chunk boundary and
        // removes the destination, so a create that gave up does not leave a
        // background copy filling a disk nobody is going to boot - or
        // re-creating one after this path's own cleanup removed the directory.
        let materialized = tokio::time::timeout(
            Duration::from_secs(120),
            rootfs::materialize(&self.config.rootfs, &destination),
        )
        .await
        .map_err(|_| RuntimeError::Unavailable("Firecracker rootfs copy timed out".into()))??;
        tracing::info!(sandbox_id = %sandbox.id, bytes = materialized.bytes, method = %materialized.method, elapsed_ms = copy_started.elapsed().as_millis() as u64, stage = "rootfs_copy_done", "firecracker rootfs copy completed");
        let requested = (sandbox.disk_mb as u64) * 1024 * 1024;
        // From here on the disk image exists on this host, so every failure has
        // to take it with it. `materialize` only cleans up after its own errors;
        // once it returns `Ok` the responsibility is the caller's, and a
        // `resize2fs` that fails on a multi-gigabyte image would otherwise leave
        // exactly that behind - on a worker that admits placements against a
        // free-disk reading taken before the copy, so the leak also defeats the
        // pressure check that would otherwise have noticed.
        if let Err(error) = self
            .resize_to_requested_disk(sandbox, &destination, requested, base_image_bytes)
            .await
        {
            rootfs::discard_vm(&dir, &destination);
            return Err(error);
        }
        // The per-sandbox control identity is planted in this sandbox's own disk
        // before it can be booted. It has to be here and not in the base image:
        // a secret baked into an image is the same secret for every sandbox that
        // image has ever started, which is exactly the credential this replaces.
        //
        // A failure here discards the image rather than leaving a disk that
        // boots a guest no worker can authenticate. A sandbox nobody can control
        // is not a sandbox worth keeping, and the alternative - booting it with
        // the shared secret - is the failure this whole path exists to prevent.
        let identity = match self.install_sandbox_identity(sandbox.id, &destination) {
            Ok(identity) => identity,
            Err(error) => {
                rootfs::discard_vm(&dir, &destination);
                return Err(error);
            }
        };
        tracing::info!(
            sandbox_id = %sandbox.id,
            identity_generation = identity.generation(),
            expires_at = %identity.expires_at(),
            stage = "control_identity_issued",
            "issued a per-sandbox control identity"
        );
        tracing::info!(sandbox_id = %sandbox.id, elapsed_ms = started.elapsed().as_millis() as u64, stage = "create_done", "firecracker create completed");
        Ok(())
    }

    /// Issues a control identity for `sandbox_id` and writes it into its disk.
    ///
    /// Issued on every create, so a restarted sandbox gets a fresh secret and
    /// the previous one stops verifying. That is rotation for the ordinary case
    /// and needs no operator action.
    fn install_sandbox_identity(
        &self,
        sandbox_id: Uuid,
        image: &Path,
    ) -> Result<control_identity::ControlIdentity, RuntimeError> {
        let identity = self.identities.get()?.issue(sandbox_id)?;
        control_identity::install_guest_secret(image, identity.secret())?;
        Ok(identity)
    }

    /// Resizes a freshly materialized disk to what the sandbox asked for.
    ///
    /// Split out so the caller can guarantee the single cleanup path: five
    /// failure returns in one function is five chances to leave a multi-
    /// gigabyte image on a worker host, and `kill_on_drop` does not remove
    /// files.
    async fn resize_to_requested_disk(
        &self,
        sandbox: &Sandbox,
        destination: &Path,
        requested: u64,
        current: u64,
    ) -> Result<(), RuntimeError> {
        if requested < current {
            // `kill_on_drop` on every tool this path runs: a create that is
            // cancelled - a client that went away, a request the control plane
            // abandoned - must not leave `resize2fs` writing into a directory
            // a destroy has already been told is gone.
            let status = Command::new("e2fsck")
                .arg("-f")
                .arg("-y")
                .arg(destination)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status()
                .await?;
            if !matches!(status.code(), Some(0) | Some(1)) {
                return Err(RuntimeError::Unavailable(
                    "copied rootfs failed filesystem check before shrink".into(),
                ));
            }
            let output = Command::new("resize2fs")
                .arg(destination)
                .arg(format!("{}M", sandbox.disk_mb))
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output()
                .await?;
            if !output.status.success() {
                return Err(RuntimeError::Unavailable(format!(
                    "rootfs could not be resized to requested disk limit: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        } else if requested > current {
            let file = std::fs::OpenOptions::new().write(true).open(destination)?;
            file.set_len(requested)?;
            let status = Command::new("resize2fs")
                .arg(destination)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
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
        // Held until the VM is in the map. A destroy that ran while this boot
        // was configuring would clear the directory this one is booting from
        // and return success, and the boot would then finish and publish a live
        // process behind it.
        let _lifecycle = self.enter_lifecycle(sandbox.id).await?;
        self.admit_signed_image(sandbox).await?;
        self.config.check()?;
        let mut vm = self.spawn(sandbox.id).await?;
        if let Err(error) = self.configure_and_start(sandbox, &mut vm).await {
            // The guest's console goes to the VMM's log, and it is the only
            // place a boot failure says why: the guest agent logs its own
            // refusals there, and without the tail a refusal reads as "the
            // machine did not come up".
            let boot_log = self.config.vm_dir(sandbox.id).join("firecracker.log");
            if let Ok(text) = std::fs::read_to_string(&boot_log) {
                let tail: Vec<&str> = text.lines().rev().take(60).collect();
                tracing::error!(
                    sandbox_id = %sandbox.id,
                    error = %error,
                    "machine configuration or start failed; last console output follows\n{}",
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                );
            }
            if let Some(network) = &vm.network {
                let _ = self.network.release(sandbox, network).await;
            }
            let _ = vm.child.start_kill();
            let _ = vm.child.wait().await;
            return Err(error);
        }
        self.publish_vm(sandbox, vm).await;
        Ok(())
    }

    async fn stop(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        let _lifecycle = self.enter_lifecycle(sandbox.id).await?;
        self.stop_vm(sandbox.id, Some(sandbox)).await
    }

    /// Takes the running VM out of the map and terminates it.
    ///
    /// Ungated, so the gated operations above can reach it: a destroy stops the
    /// VM it is about to remove the state of, rather than queueing behind a
    /// second gate for the same sandbox.
    async fn stop_vm(&self, id: Uuid, owner: Option<&Sandbox>) -> Result<(), RuntimeError> {
        let vm = self.vms.lock().await.remove(&id);
        if let Some(vm) = vm {
            self.lifetimes.lock().await.remove(&vm.start_token);
            self.terminate_vm(id, owner, vm, Graceful::Yes).await;
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
    /// Captures a guarded sandbox for forensics and leaves it paused.
    ///
    /// Unlike [`Self::snapshot`], this never resumes the guest: the operator is
    /// holding a machine they believe misbehaved, and a resume inside the
    /// capture would hand it a slice of execution back. The guest is asked to
    /// prepare while it still runs - `PrepareSnapshot` fsyncs the workspace
    /// inside the guest and cannot answer from a paused VM - and the network
    /// cut belongs to the attachment, not to the VM, so it stays in force.
    async fn capture_forensics(
        &self,
        sandbox: &Sandbox,
        snapshot_id: &str,
    ) -> Result<u64, RuntimeError> {
        if snapshot_id.is_empty()
            || snapshot_id.len() > 128
            || !snapshot_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(RuntimeError::Unavailable(
                "forensic snapshot id is not a bounded plain identifier".into(),
            ));
        }
        // One gate per sandbox: a destroy issued now would kill the VM halfway
        // through the capture and leave a snapshot object that is not one.
        let _lifecycle = self.enter_lifecycle(sandbox.id).await?;
        let (socket, source_disk) = {
            let vms = self.vms.lock().await;
            let vm = vms
                .get(&sandbox.id)
                .ok_or_else(|| RuntimeError::Unavailable("sandbox VM is not running".into()))?;
            (vm.api_socket.clone(), vm.rootfs.clone())
        };
        // Only a running guest can prepare a snapshot: the operation fsyncs the
        // workspace inside the guest, and a paused VM has no agent scheduled to
        // answer. Asking anyway does not fail fast - the write sits on the
        // vsock until `guest_call_timeout`, which floors every operation at the
        // readiness timeout, so it blocks that whole window while this function
        // holds the lifecycle gate and every other operation on the sandbox
        // queues behind it. Quarantine routinely reaches an already paused
        // machine (an operator pause, or an earlier incident), so this is the
        // ordinary path rather than an edge case.
        if self.vm_state(&socket).await? == "Running" {
            self.guest_call(sandbox.id, Operation::PrepareSnapshot, RequestPayload::None)
                .await?;
        }
        // Final pause and capture are one fenced step: after this returns the
        // only remaining transitions are an operator's, or destruction.
        self.api(
            &socket,
            "PATCH",
            "/vm",
            Some(serde_json::json!({"state":"Paused"})),
        )
        .await?;
        let destination = self
            .config
            .state_dir
            .join("guard-forensics")
            .join(sandbox.id.to_string())
            .join(snapshot_id);
        // A repeated capture of the same incident id replaces nothing: it
        // refuses rather than overwriting evidence an operator may be reading.
        if tokio::fs::try_exists(&destination).await.unwrap_or(false) {
            return Err(RuntimeError::Core(CoreError::Conflict(
                "forensic capture already exists".into(),
            )));
        }
        tokio::fs::create_dir_all(&destination).await?;
        let state = destination.join("vmstate");
        let memory = destination.join("memory");
        self.api(
            &socket,
            "PUT",
            "/snapshot/create",
            Some(serde_json::json!({"snapshot_type":"Full", "snapshot_path":&state, "mem_file_path":&memory, "sync_snapshot_files":true})),
        )
        .await
        .inspect_err(|_| {
            let destination = destination.clone();
            tokio::spawn(async move { let _ = tokio::fs::remove_dir_all(destination).await; });
        })?;
        let disk = destination.join("rootfs.ext4");
        tokio::fs::copy(&source_disk, &disk).await?;
        let manifest = serde_json::json!({
            "schema": 1,
            "sandbox_id": sandbox.id,
            "snapshot_id": snapshot_id,
            "captured_paused": true,
            "source_disk": source_disk,
        });
        tokio::fs::write(
            destination.join("manifest.json"),
            serde_json::to_vec(&manifest)?,
        )
        .await?;
        let mut size = 0;
        for file in [state, memory, disk] {
            size += tokio::fs::metadata(file).await?.len();
        }
        Ok(size)
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
        let mut request = request;
        if let Some(guard) = &sandbox.environment.guard {
            let effective = guard
                .effective_policy()
                .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
            let gateway = self
                .vms
                .lock()
                .await
                .get(&sandbox.id)
                .and_then(|vm| vm.network.as_ref())
                .and_then(|network| network.addresses.first())
                .cloned()
                .ok_or_else(|| RuntimeError::Unavailable("Guard gateway missing".into()))?;
            if let Some(model) = effective.model {
                let base = format!("http://{gateway}:8443/model/{}/v1", model.credential);
                let placeholder = format!("placeholder://{}", model.credential);
                for key in ["AIEC_MODEL_API_KEY", "AIEC_AGENT_API_KEY", "OPENAI_API_KEY"] {
                    request.environment.insert(key.into(), placeholder.clone());
                }
                for key in [
                    "AIEC_MODEL_BASE_URL",
                    "AIEC_AGENT_BASE_URL",
                    "OPENAI_BASE_URL",
                ] {
                    request.environment.insert(key.into(), base.clone());
                }
            }
            // A governed policy with non-model destinations is unusable without
            // this: nft denies all forwarding, so an allowlisted `git clone` or
            // `curl` has no route unless the client is told to send its request
            // to the gateway, which decides whether the destination is
            // permitted. Both spellings are set because the tools disagree -
            // curl reads the lower-case names, git and most of the ecosystem
            // read the upper-case ones.
            //
            // `NO_PROXY` carries the gateway, and only the gateway.
            //
            // Every other destination has to go through the proxy, which
            // decides whether it is permitted, so nothing else may be named
            // here: an address listed in `NO_PROXY` is reached by a direct
            // socket, and the kernel drops those that are not the gateway,
            // which is a refused connection rather than an ungoverned one.
            //
            // The gateway is the exception, and omitting it is not a
            // hardening choice. The model endpoint above is addressed to the
            // gateway itself, and a client that honours `HTTP_PROXY` sends
            // that request to the proxy path as an absolute-form URI - where
            // presenting a credential is forbidden by design, because the
            // proxy has no credential to substitute. Every agent following the
            // documented `AIEC_AGENT_BASE_URL` therefore failed with
            // `403 credentials forbidden on proxy` before it made a single
            // model request. Reaching the enforcement point directly is not
            // bypassing it: the gateway is where enforcement happens.
            let proxy = format!("http://{gateway}:8443");
            for key in [
                "HTTP_PROXY",
                "http_proxy",
                "HTTPS_PROXY",
                "https_proxy",
                "ALL_PROXY",
                "all_proxy",
            ] {
                request.environment.insert(key.into(), proxy.clone());
            }
            for key in ["NO_PROXY", "no_proxy"] {
                request.environment.insert(key.into(), gateway.clone());
            }
        }
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
        // A control-channel frame is much smaller than `MAX_FILE`, so a file
        // that passes the size check above can still be too large to send in
        // one piece. Sending it anyway does not produce a clean error: the
        // guest rejects the frame on its declared length and closes the
        // connection, and this side sees a broken pipe halfway through a write
        // it believed was going to succeed. Split anything that does not fit.
        if aiec_core::runtime::write_fits_one_frame(&request.path, &content) {
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
            return Ok(());
        }
        let size_bytes = content.len() as u64;
        let mut written = 0usize;
        for chunk in content.chunks(aiec_core::runtime::FILE_CHUNK_BYTES) {
            let chunk_request = aiec_core::runtime::FileWriteChunkRequest {
                path: request.path.clone(),
                offset: written as u64,
                size_bytes,
                // The mode belongs to the last piece, which is the one that
                // completes the file; sending it with every chunk would make
                // the file briefly executable while it was still short.
                mode: request
                    .mode
                    .filter(|_| written + chunk.len() == content.len()),
            };
            match self
                .guest_call(
                    sandbox.id,
                    Operation::WriteFileChunk,
                    RequestPayload::WriteFileChunk {
                        request: chunk_request,
                        content: chunk.to_vec(),
                    },
                )
                .await?
            {
                ResponsePayload::WriteFileChunk {
                    written: n,
                    size_bytes: reported,
                } => {
                    if n != chunk.len() || reported != size_bytes {
                        return Err(RuntimeError::Protocol(
                            aiec_core::protocol::ProtocolError::Malformed(
                                "invalid file chunk write response".into(),
                            ),
                        ));
                    }
                }
                _ => {
                    return Err(RuntimeError::Unavailable(
                        "guest returned wrong file chunk write response".into(),
                    ));
                }
            }
            written += chunk.len();
        }
        Ok(())
    }

    /// One step of a multi-chunk file read: validates the chunk against the
    /// request, pins the first chunk's version/size, and refuses a later chunk
    /// that drifts — a same-size replacement landing between two completed chunks
    /// passes per-chunk validation and would otherwise splice halves silently.
    /// Returns the chunk's bytes and whether the read is complete.
    fn assemble_chunk(
        pinned: &mut Option<(String, u64)>,
        request: &aiec_core::runtime::FileChunkRequest,
        chunk: &aiec_core::runtime::FileChunk,
    ) -> Result<(bytes::Bytes, bool), RuntimeError> {
        request.validate_chunk(chunk)?;
        match &pinned {
            None => *pinned = Some((chunk.version.clone(), chunk.size_bytes)),
            Some((version, size)) => {
                if chunk.version != *version || chunk.size_bytes != *size {
                    return Err(aiec_core::CoreError::Conflict(
                        "file changed while reading".into(),
                    )
                    .into());
                }
            }
        }
        Ok((chunk.bytes.clone(), chunk.eof))
    }

    async fn get_file(&self, sandbox: &Sandbox, path: &str) -> Result<FileContent, RuntimeError> {
        use aiec_core::runtime::{FILE_CHUNK_BYTES, FileChunkRequest};
        // Before the read, not after it: a configured canary must be able to
        // refuse the file without its bytes ever crossing the channel.
        self.network.guard_observe_file_read(sandbox, path).await?;
        // Always the chunked read, which is one round trip for a file that fits
        // a frame and several for one that does not. The single-shot `ReadFile`
        // cannot be used here at all: a response has to fit one frame too, so a
        // file large enough to overflow it does not come back as an error - the
        // guest writes a length it then refuses to send, and this side sees the
        // connection end mid-frame. A file the API accepts on the way in has to
        // be readable on the way out.
        let mut content = Vec::new();
        let mut offset = 0u64;
        // The first chunk's version and size pin every later one: without the
        // pin a same-size replacement landing between two completed chunks
        // passes per-chunk validation and splices halves silently — the
        // hazard documented for unpinned bursts in aiec-core. The artifact
        // path pins the same way (RunArtifactSource::accept).
        let mut pinned: Option<(String, u64)> = None;
        loop {
            let request = FileChunkRequest {
                path: path.to_owned(),
                offset,
                length: FILE_CHUNK_BYTES,
                expected_version: pinned.as_ref().map(|(version, _)| version.clone()),
            };
            let eof = match self
                .guest_call(
                    sandbox.id,
                    Operation::ReadFileChunk,
                    RequestPayload::ReadFileChunk {
                        request: request.clone(),
                    },
                )
                .await?
            {
                ResponsePayload::ReadFileChunk {
                    content: chunk,
                    size_bytes,
                    version,
                    eof,
                } => {
                    let chunk = aiec_core::runtime::FileChunk {
                        bytes: bytes::Bytes::from(chunk),
                        size_bytes,
                        version,
                        eof,
                    };
                    let (bytes, done) = Self::assemble_chunk(&mut pinned, &request, &chunk)?;
                    content.extend_from_slice(&bytes);
                    offset += bytes.len() as u64;
                    done
                }
                _ => {
                    return Err(RuntimeError::Unavailable(
                        "guest returned wrong file response".into(),
                    ));
                }
            };
            if eof {
                break;
            }
        }
        use base64::Engine;
        Ok(FileContent {
            path: path.into(),
            content_base64: base64::engine::general_purpose::STANDARD.encode(content),
        })
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
                    // A portable snapshot must not become a way around a
                    // configured file canary: observe each file before its
                    // bytes are read for the archive.
                    self.network
                        .guard_observe_file_read(sandbox, &child.path)
                        .await?;
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
                    // A portable snapshot must not become a way around a
                    // configured file canary: observe each file before its
                    // bytes are read for the archive, exactly as
                    // `export_workspace` does for the same walk.
                    self.network
                        .guard_observe_file_read(sandbox, &child.path)
                        .await?;
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
        // A capture pauses the guest, writes its memory and copies its disk. A
        // destroy issued in the middle would kill the VM halfway through and
        // leave a snapshot object that is not a snapshot, so the destroy waits
        // for the capture to finish and release the guest.
        let _lifecycle = self.enter_lifecycle(sandbox.id).await?;
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
            // Staged, then published. Writing into the destination directly
            // meant two things at once: a failure partway left a directory of
            // half a snapshot with nothing to say it was half a snapshot, and a
            // re-capture overwrote `rootfs.ext4` under the previous
            // `manifest.json`. That pair is the worst of both: the manifest
            // checksum describes a disk that no longer exists, so a restore
            // loads a memory state against a disk it does not belong to. The
            // staging name is unique per attempt, so a concurrent capture
            // cannot share it, and it is removed on every exit below.
            let staging = destination.with_extension(format!("staging-{}", Uuid::now_v7()));
            let staged = async {
                tokio::fs::create_dir_all(&staging).await?;
                let state = staging.join("vmstate");
                let memory = staging.join("memory");
                self.api(
                    &socket,
                    "PUT",
                    "/snapshot/create",
                    Some(serde_json::json!({"snapshot_type":"Full", "snapshot_path":&state, "mem_file_path":&memory, "sync_snapshot_files":true})),
                )
                .await?;
                let snapshot_disk = staging.join("rootfs.ext4");
                tokio::fs::copy(&source_disk, &snapshot_disk).await?;
                let rootfs_sha256 = disk_sha256(&snapshot_disk).await?;
                let manifest = serde_json::json!({
                    "schema": 1,
                    "source_disk": source_disk,
                    "rootfs_sha256": rootfs_sha256,
                });
                tokio::fs::write(
                    staging.join("manifest.json"),
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
            let size = match staged {
                Ok(size) => size,
                Err(error) => {
                    let _ = tokio::fs::remove_dir_all(&staging).await;
                    return Err(error);
                }
            };
            Self::publish_snapshot(&staging, &destination).await?;
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
        // A restore replaces this sandbox's disk and boots from it, so it is a
        // lifecycle operation like any other: a destroy must not clear the
        // directory between the disk copy and the boot.
        let _lifecycle = self.enter_lifecycle(sandbox.id).await?;
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
        let actual = disk_sha256(&snapshot_disk).await?;
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
        self.publish_vm(sandbox, vm).await;
        Ok(())
    }

    /// Moves a fully-written staging directory onto a snapshot key.
    ///
    /// Separate from the capture itself so the property it provides can be stated
    /// directly: the key goes from one complete snapshot to the next, and never
    /// through a state where it is neither. The previous snapshot is moved aside
    /// first and only unlinked once the new one is in place, so a failure here
    /// leaves the key with what it already had.
    ///
    /// The staging directory is removed on every failure path, so a capture that
    /// did not complete leaves nothing behind that a later restore could read.
    async fn publish_snapshot(staging: &Path, destination: &Path) -> Result<(), RuntimeError> {
        let superseded = destination.with_extension(format!("superseded-{}", Uuid::now_v7()));
        if tokio::fs::try_exists(destination).await.unwrap_or(false)
            && tokio::fs::rename(destination, &superseded).await.is_err()
        {
            let _ = tokio::fs::remove_dir_all(staging).await;
            return Err(RuntimeError::Unavailable(
                "the previous snapshot for this key could not be moved aside".into(),
            ));
        }
        if let Err(error) = tokio::fs::rename(staging, destination).await {
            // Put the previous snapshot back before reporting the failure, so the
            // key is left with what it had rather than nothing.
            let _ = tokio::fs::rename(&superseded, destination).await;
            let _ = tokio::fs::remove_dir_all(staging).await;
            return Err(error.into());
        }
        let _ = tokio::fs::remove_dir_all(&superseded).await;
        Ok(())
    }

    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), RuntimeError> {
        self.reclaim(sandbox.id, Some(sandbox), Graceful::Yes).await
    }

    /// Removes everything one machine leaves on this host: the process, the
    /// attachment, the control identity and both of its directories.
    ///
    /// `owner` is absent only on the worker's exit, where the attachment
    /// cannot be released under an identity nobody is holding. The machine is
    /// reclaimed either way.
    async fn reclaim(
        &self,
        id: Uuid,
        owner: Option<&Sandbox>,
        graceful: Graceful,
    ) -> Result<(), RuntimeError> {
        // Held until the state and socket directories are gone. This is the
        // operation the create above has to be behind: a destroy that returned
        // while a create was still copying would be reporting a machine that
        // does not exist and a create that finished afterwards would leave it
        // behind. Neither failure is visible in the response the caller got.
        let _lifecycle = self.enter_lifecycle(id).await?;
        let vm = self.vms.lock().await.remove(&id);
        if let Some(vm) = vm {
            // The VM is out of the map, so its timer has nothing left to stop.
            // End it before the teardown rather than after it: a teardown that
            // fails or blocks still leaves no sleeping task behind.
            self.lifetimes.lock().await.remove(&vm.start_token);
            self.terminate_vm(id, owner, vm, graceful).await;
        }
        self.owners.lock().await.remove(&id);
        // The secret stops being usable before the disk it was planted in is
        // removed. Reversing that order would leave a window where the identity
        // is dead on this host but a copy of the image - a snapshot, a backup -
        // still carries a secret that nothing here would have refused.
        //
        // A store that cannot be opened is not a reason to skip the revocation:
        // the guest is already stopped and the directories still go, so the
        // sandbox is unreachable either way. Failing the whole destroy over it
        // would report a machine that no longer exists as still existing.
        if let Err(error) = self.identities.get().and_then(|store| store.revoke(id)) {
            tracing::warn!(
                sandbox_id = %id,
                error = %error,
                stage = "control_identity_revoke_failed",
                "could not revoke the control identity of a destroyed sandbox"
            );
        }
        let state = self.config.vm_dir(id);
        let socket = self.config.socket_dir(id);
        // Both directories are removed even when the first fails. Returning
        // there left the Firecracker API socket directory behind: `reclaim`
        // runs at the end of destroy, so the machine was already gone and the
        // stale directory was the only thing still on the host — a leftover
        // that no later `destroy` is guaranteed to revisit, because the row it
        // belonged to is destroyed by then. The first error is the one
        // returned, so the caller's retry still sees the real failure.
        let state_result = match tokio::fs::remove_dir_all(&state).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        let socket_result = match tokio::fs::remove_dir_all(&socket).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        state_result?;
        socket_result?;
        Ok(())
    }

    /// Reclaims every machine this runtime still holds, for a worker on its
    /// way out.
    ///
    /// Nothing adopts a VM directory left behind by a process that has exited:
    /// [`Self::reconcile_local`] reports one as an orphan candidate for an
    /// operator, and [`Self::resume`] finds a machine only in this process's
    /// own map. So a rootfs that outlives the worker is not a machine anyone
    /// can return to - it is the disk of a guest still running on the host,
    /// held by a process and a file that no owner will ever reclaim again.
    ///
    /// A forensic capture is a different directory and is deliberately left
    /// alone: it is the evidence an operator investigates, and it is the copy
    /// that survives this call on purpose.
    ///
    /// One machine failing does not strand the others - an exiting worker that
    /// stopped at the first error would leave every machine behind it - and
    /// they are reclaimed together rather than one after another, so the cost
    /// of a host with many machines is one teardown and not one per machine.
    pub async fn shutdown(&self) -> Vec<Uuid> {
        let live: Vec<Uuid> = self.vms.lock().await.keys().copied().collect();
        let owners = self.owners.lock().await.clone();
        let runtime = self.clone();
        let outcomes = futures_util::future::join_all(live.into_iter().map(|id| {
            let runtime = runtime.clone();
            let owner = owners.get(&id).cloned();
            async move {
                // A missing owner record costs the attachment its release and
                // nothing else. The guest still stops and the disk still goes:
                // a machine nobody can identify is still a machine running on
                // the host, and the record left behind is inert without it.
                let outcome = runtime.reclaim(id, owner.as_ref(), Graceful::No).await;
                (id, outcome)
            }
        }))
        .await;
        let mut reclaimed = Vec::with_capacity(outcomes.len());
        for (id, outcome) in outcomes {
            match outcome {
                Ok(()) => reclaimed.push(id),
                Err(error) => tracing::warn!(
                    sandbox_id = %id,
                    %error,
                    stage = "shutdown_reclaim_failed",
                    "could not reclaim a VM while the worker was exiting"
                ),
            }
        }
        reclaimed
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
    fn configure_guard_budget_authority(
        &self,
        authority: Arc<dyn aiec_guard::control::BudgetAuthority>,
    ) -> Result<(), CoreError> {
        self.network.configure_guard_budget_authority(authority)
    }
    async fn guard_set_fence(
        &self,
        sandbox: &Sandbox,
        fence: aiec_guard::control::GuardFence,
    ) -> Result<(), CoreError> {
        self.network.guard_set_fence(sandbox, fence).await
    }
    async fn guard_control(
        &self,
        sandbox: &Sandbox,
        fence: aiec_guard::control::GuardFence,
        command: aiec_guard::control::GuardControlCommand,
    ) -> Result<aiec_guard::control::GuardControlResponse, CoreError> {
        match command {
            aiec_guard::control::GuardControlCommand::CapturePaused { snapshot_id } => {
                let size = Self::capture_forensics(self, sandbox, &snapshot_id)
                    .await
                    .map_err(into_core)?;
                Ok(aiec_guard::control::GuardControlResponse::Forensics {
                    snapshot_id,
                    size_bytes: size,
                })
            }
            other => self.network.guard_control(sandbox, fence, other).await,
        }
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
    async fn get_file_chunk(
        &self,
        sandbox: &Sandbox,
        request: FileChunkRequest,
    ) -> Result<FileChunk, CoreError> {
        request.validate()?;
        // `get_file` observes the read against any configured file canary
        // before the bytes are fetched. The chunked read carries the same bytes
        // in the same workspace and has to be held to the same rule, or a
        // canary is trivially bypassed by reading a large file in chunks.
        self.network
            .guard_observe_file_read(sandbox, &request.path)
            .await?;
        match self
            .guest_call(
                sandbox.id,
                Operation::ReadFileChunk,
                RequestPayload::ReadFileChunk {
                    request: request.clone(),
                },
            )
            .await
            .map_err(into_core)?
        {
            ResponsePayload::ReadFileChunk {
                content,
                size_bytes,
                version,
                eof,
            } => {
                let chunk = FileChunk {
                    bytes: content.into(),
                    size_bytes,
                    version,
                    eof,
                };
                request.validate_chunk(&chunk)?;
                Ok(chunk)
            }
            _ => Err(CoreError::Backend(
                "guest returned invalid chunk response".into(),
            )),
        }
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
    async fn shutdown(&self) -> Vec<Uuid> {
        Self::shutdown(self).await
    }
    async fn health(&self) -> RuntimeHealth {
        if Self::health(self) {
            RuntimeHealth::healthy()
        } else {
            RuntimeHealth::unhealthy("Firecracker prerequisites unavailable")
        }
    }
    fn capabilities(&self) -> RuntimeCapabilities {
        firecracker_capabilities(
            self.network.as_ref(),
            self.config.guest_artifact.as_ref(),
            self.config.minimum_disk_mb(),
        )
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
mod into_core_tests {
    use super::{RuntimeError, into_core};

    /// An unavailable backend must stay unavailable.
    ///
    /// `into_core` used to collapse every non-`Core` error into `CoreError::Io`,
    /// which lost the class a caller branches on and reported "Guard refused"
    /// as a filesystem problem. The live acceptance run was what made that
    /// legible: a permission error arrived wearing a category that had nothing to
    /// do with who refused.
    #[test]
    fn an_unavailable_backend_survives_as_unavailable() {
        let converted = into_core(RuntimeError::Unavailable("guard refused".into()));
        match converted {
            aiec_core::CoreError::Unavailable(message) => assert_eq!(message, "guard refused"),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    /// A core error is already the right type and passes through untouched.
    #[test]
    fn a_core_error_passes_through_unchanged() {
        let converted = into_core(RuntimeError::Core(aiec_core::CoreError::Conflict(
            "already started".into(),
        )));
        match converted {
            aiec_core::CoreError::Conflict(message) => assert_eq!(message, "already started"),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    /// Everything else is still an I/O error, and keeps its text. This is the
    /// part that was correct before and must not regress while the unavailable
    /// case is being fixed.
    #[test]
    fn other_errors_stay_io_errors_with_their_text() {
        let converted = into_core(RuntimeError::FirecrackerApi("boot failed".into()));
        let aiec_core::CoreError::Io(error) = converted else {
            panic!("expected Io, got {converted:?}");
        };
        assert!(
            error.to_string().contains("boot failed"),
            "the reason must survive: {error}",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiec_core::host_pressure::{GIB, MIB};

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
            image_trust: None,
            require_coding_guest: false,
            host_reserves: HostReserves::default(),
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
        let capabilities = firecracker_capabilities(&LinuxNetworkManager::new(), None, 0);
        assert!(capabilities.pause);
        assert!(!capabilities.pause_reclaims_resources);
    }
    #[test]
    fn firecracker_advertises_what_a_workspace_restore_requires() {
        // Exactly what a workspace restore provisions with. If either flag goes
        // back to false the scheduler's containment test stops selecting any
        // microVM host, and the restore fails as missing capacity forever.
        let required = aiec_core::runtime::RuntimeCapabilities {
            portable_workspace: true,
            workspace_snapshot: true,
            ..Default::default()
        };
        let capabilities = firecracker_capabilities(&LinuxNetworkManager::new(), None, 0);
        assert!(aiec_core::runtime::capabilities_satisfy(
            &capabilities,
            &required,
            None
        ));
    }

    #[tokio::test]
    async fn guest_chunk_rejects_oversized_frame_before_reading_body() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let mut header = [0; 42];
        header[..4].copy_from_slice(b"AFG1");
        header[4..6].copy_from_slice(&protocol::PROTOCOL_VERSION.to_be_bytes());
        header[6..10].copy_from_slice(&(300_000u32).to_be_bytes());
        writer.write_all(&header).await.unwrap();
        let result = read_frame_async_bounded(&mut reader, b"secret", 64 * 1024 * 4 + 4096).await;
        assert!(matches!(
            result,
            Err(RuntimeError::Protocol(protocol::ProtocolError::TooLarge(
                300_000
            )))
        ));
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

    /// A VM entry backed by a real process, so a test can observe the process
    /// that a teardown or an expiry is supposed to stop.
    fn running_vm(start_token: Uuid) -> FirecrackerVm {
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        FirecrackerVm {
            child,
            api_socket: PathBuf::from("/unused/api.sock"),
            network: None,
            vsock_socket: PathBuf::from("/unused/vsock.sock"),
            rootfs: PathBuf::from("/unused/rootfs.ext4"),
            start_token,
        }
    }

    fn process_running(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    #[tokio::test]
    async fn stale_timer_token_cannot_stop_restarted_vm() {
        let mut config = config();
        config.readiness_timeout = Duration::from_millis(5);
        let runtime = FirecrackerRuntime::new(config);
        let sandbox = sandbox(Uuid::now_v7(), 60);
        let token = Uuid::now_v7();
        let vm = running_vm(token);
        runtime.vms.lock().await.insert(sandbox.id, vm);
        runtime.stop_if_token(&sandbox, Uuid::now_v7()).await;
        assert!(runtime.vms.lock().await.contains_key(&sandbox.id));
        let mut vm = runtime.vms.lock().await.remove(&sandbox.id).unwrap();
        let _ = vm.child.start_kill();
        let _ = vm.child.wait().await;
    }

    #[tokio::test]
    async fn shutdown_reclaims_the_machines_the_worker_was_running() {
        let mut config = config();
        config.readiness_timeout = Duration::from_millis(5);
        let state = std::env::temp_dir().join(format!("af-shutdown-{}", Uuid::now_v7()));
        config.state_dir = state.clone();
        let runtime = FirecrackerRuntime::new(config);
        let sandbox = sandbox(Uuid::now_v7(), 600);
        let vm = running_vm(Uuid::now_v7());
        let pid = vm.child.id().expect("test VM has a pid");
        runtime.publish_vm(&sandbox, vm).await;
        // The writable disk a create leaves behind is the thing that actually
        // accumulates: the process dies with the worker either way, the file
        // does not.
        let disk = runtime.config.vm_dir(sandbox.id);
        tokio::fs::create_dir_all(&disk).await.unwrap();
        tokio::fs::write(disk.join("rootfs.ext4"), b"guest")
            .await
            .unwrap();
        let reclaimed = runtime.shutdown().await;
        assert_eq!(reclaimed, vec![sandbox.id]);
        assert!(!runtime.vms.lock().await.contains_key(&sandbox.id));
        assert!(!tokio::fs::try_exists(&disk).await.unwrap());
        assert!(!process_running(pid));
        let _ = tokio::fs::remove_dir_all(&state).await;
    }

    #[tokio::test]
    async fn shutdown_reclaims_a_machine_it_cannot_identify() {
        let mut config = config();
        config.readiness_timeout = Duration::from_millis(5);
        let state = std::env::temp_dir().join(format!("af-shutdown-unknown-{}", Uuid::now_v7()));
        config.state_dir = state.clone();
        let runtime = FirecrackerRuntime::new(config);
        let sandbox = sandbox(Uuid::now_v7(), 600);
        let vm = running_vm(Uuid::now_v7());
        let pid = vm.child.id().expect("test VM has a pid");
        runtime.vms.lock().await.insert(sandbox.id, vm);
        let disk = runtime.config.vm_dir(sandbox.id);
        tokio::fs::create_dir_all(&disk).await.unwrap();
        tokio::fs::write(disk.join("rootfs.ext4"), b"guest")
            .await
            .unwrap();
        // Releasing an attachment needs the identity it was created under, and
        // no other identity may be substituted for a missing one. That costs
        // the attachment its release and nothing else: a machine nobody can
        // name is still a guest running on the host, so it is stopped and its
        // disk removed. The record left behind is inert without it.
        assert_eq!(runtime.shutdown().await, vec![sandbox.id]);
        assert!(!runtime.vms.lock().await.contains_key(&sandbox.id));
        assert!(!process_running(pid));
        assert!(!tokio::fs::try_exists(&disk).await.unwrap());
        let _ = tokio::fs::remove_dir_all(&state).await;
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

    /// A command that exits without reading its standard input has reported a
    /// status. `bounded` used to write stdin inline before any deadline poll,
    /// so a pipe the command never read failed the whole exec with the write's
    /// own `EPIPE` instead of the status it exited with.
    #[tokio::test]
    async fn unread_stdin_reports_the_status_rather_than_the_write() {
        let mut command = tokio::process::Command::new("/bin/true");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let result =
            BubblewrapRuntime::bounded(command.spawn().unwrap(), 30, Some("x".repeat(512 * 1024)))
                .await
                .expect("a command that ignores stdin still reports its status");
        assert!(!result.timed_out, "a command that exited was not killed");
        assert_eq!(result.exit_code, 0);
    }

    /// The deadline bounds the whole exec, including delivery that a command
    /// never reads. A command that outlives it while its stdin sits unread
    /// must still be killed and reported as timed out rather than running to
    /// its own completion.
    #[tokio::test]
    async fn the_deadline_bounds_a_command_that_never_reads_its_stdin() {
        let mut command = tokio::process::Command::new("/bin/sleep");
        command.arg("30");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            BubblewrapRuntime::bounded(command.spawn().unwrap(), 1, Some("x".repeat(512 * 1024))),
        )
        .await
        .expect("the deadline is the exec's bound, not the command's")
        .expect("the group kill reaps the command");
        assert!(result.timed_out, "the command outlived its deadline");
        assert_eq!(result.exit_code, -124);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// A command that exits while a backgrounded grandchild still holds its
    /// output pipes has finished. Awaiting those readers with no bound left
    /// the exec waiting for a process it no longer owns, indefinitely, holding
    /// the sandbox's lifecycle gate.
    #[tokio::test]
    async fn a_backgrounded_grandchild_does_not_hold_the_exec_open() {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.arg("-c").arg("sleep 30 2>/dev/null & echo done");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            BubblewrapRuntime::bounded(command.spawn().unwrap(), 30, None),
        )
        .await
        .expect("an open output pipe costs one bounded wait, not an unbounded one")
        .expect("a command that exited reports its status");
        assert!(!result.timed_out, "the command exited inside its deadline");
        assert_eq!(result.exit_code, 0);
        assert_eq!(
            result.stdout, "done\n",
            "output written before the wait is kept"
        );
    }

    /// Output past the limit is dropped, and the writer that produced it is
    /// not killed for producing it.
    ///
    /// The property is the writer's own status, not the shell's: a shell whose
    /// last command is `echo` exits 0 whether or not `dd` was killed, so
    /// asserting the shell's status would pass against a reader that closes
    /// the pipe early. `dd` reports `141` when its stdout is closed under it.
    #[tokio::test]
    async fn output_past_the_limit_is_dropped_without_failing_the_writer() {
        let mut command = tokio::process::Command::new("/bin/sh");
        // Four megabytes, well past the one-megabyte stream bound. The writer's
        // own status goes to stderr, which is below its own limit, and the
        // shell exits with it so the result carries it.
        command.arg("-c").arg(
            "dd if=/dev/zero bs=1024 count=4096 2>/dev/null; \
             status=$?; echo writer_status=$status >&2; exit $status",
        );
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let result = BubblewrapRuntime::bounded(command.spawn().unwrap(), 30, None)
            .await
            .expect("a command whose output exceeds the limit still reports its status");
        assert!(
            !result.timed_out,
            "the command finished inside its deadline"
        );
        assert_eq!(
            result.stdout.len(),
            MAX_STDOUT,
            "output is truncated at the limit"
        );
        assert!(
            result.stderr.contains("writer_status=0"),
            "a writer past the limit is not killed for it, stderr was {:?}",
            result.stderr
        );
        assert_eq!(
            result.exit_code, 0,
            "the writer's own status reaches the caller"
        );
    }

    #[tokio::test]
    async fn a_lifetime_that_runs_out_stops_its_vm_and_ends_its_timer() {
        let mut config = config();
        config.readiness_timeout = Duration::from_millis(5);
        let runtime = FirecrackerRuntime::new(config);
        let metrics = tokio::runtime::Handle::current().metrics();
        let baseline = metrics.num_alive_tasks();
        let sandbox = sandbox(Uuid::now_v7(), 0);
        let token = Uuid::now_v7();
        let vm = running_vm(token);
        let pid = vm.child.id().unwrap();
        runtime.vms.lock().await.insert(sandbox.id, vm);
        runtime.schedule_lifetime(&sandbox, token).await;
        for _ in 0..100 {
            if !process_running(pid) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The timeout won on its own: the VM that token started is out of the
        // map and its process is gone.
        assert!(!runtime.vms.lock().await.contains_key(&sandbox.id));
        assert!(!process_running(pid));
        // And the timer that fired is spent with it, rather than left holding
        // the runtime and the sandbox it just stopped.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(metrics.num_alive_tasks(), baseline);
    }

    #[tokio::test]
    async fn destroying_sandboxes_ends_their_lifetime_timers() {
        let mut config = config();
        config.readiness_timeout = Duration::from_millis(5);
        config.state_dir = std::env::temp_dir().join(format!("af-lifetime-{}", Uuid::now_v7()));
        let runtime = FirecrackerRuntime::new(config);
        let metrics = tokio::runtime::Handle::current().metrics();
        let baseline = metrics.num_alive_tasks();
        // An hour of TTL each: nothing in this test waits one out, so only
        // teardown can end these timers. A timer that outlived its VM would be
        // a task per short-lived Run that nothing ever joins up again.
        let mut armed = Vec::new();
        for _ in 0..8 {
            let sandbox = sandbox(Uuid::now_v7(), 3_600);
            let token = Uuid::now_v7();
            let vm = running_vm(token);
            let pid = vm.child.id().unwrap();
            runtime.vms.lock().await.insert(sandbox.id, vm);
            runtime.schedule_lifetime(&sandbox, token).await;
            armed.push((sandbox, pid));
        }
        assert!(
            metrics.num_alive_tasks() >= baseline + armed.len(),
            "an armed lifetime is a live task for as long as its VM lives"
        );
        for (destroyed, pid) in &armed {
            FirecrackerRuntime::destroy(&runtime, destroyed)
                .await
                .unwrap();
            assert!(!process_running(*pid));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            metrics.num_alive_tasks(),
            baseline,
            "a destroyed sandbox must not leave a lifetime task sleeping"
        );
        assert!(runtime.vms.lock().await.is_empty());
        let _ = tokio::fs::remove_dir_all(&runtime.config.state_dir).await;
    }

    #[tokio::test]
    async fn a_destroyed_sandbox_still_gets_its_restarted_vm_expired() {
        let mut config = config();
        config.readiness_timeout = Duration::from_millis(5);
        let runtime = FirecrackerRuntime::new(config);
        let sandbox = sandbox(Uuid::now_v7(), 0);
        let stale = running_vm(Uuid::now_v7());
        let stale_token = stale.start_token;
        runtime.vms.lock().await.insert(sandbox.id, stale);
        runtime.schedule_lifetime(&sandbox, stale_token).await;
        FirecrackerRuntime::destroy(&runtime, &sandbox)
            .await
            .unwrap();

        // Same sandbox id, new boot. A destroy ends the timer it owned, and the
        // sandbox it left behind must still be able to arm and run its own: a
        // destroy that broke later timers would leave this VM running until
        // something else stopped it.
        let fresh = running_vm(Uuid::now_v7());
        let fresh_token = fresh.start_token;
        let fresh_pid = fresh.child.id().unwrap();
        runtime.vms.lock().await.insert(sandbox.id, fresh);
        runtime.schedule_lifetime(&sandbox, fresh_token).await;
        for _ in 0..100 {
            if !process_running(fresh_pid) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(!runtime.vms.lock().await.contains_key(&sandbox.id));
        assert!(!process_running(fresh_pid));
    }
    /// Counts the containment an expired lifetime asks for.
    #[derive(Default)]
    struct ContainingNetwork {
        contained: std::sync::Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl NetworkBackend for ContainingNetwork {
        fn capabilities(&self) -> aiec_core::network::NetworkCapabilities {
            aiec_core::network::NetworkCapabilities::default()
        }
        async fn prepare(
            &self,
            _: &Sandbox,
            _: &NetworkPolicy,
        ) -> Result<NetworkAttachment, crate::CoreError> {
            Ok(NetworkAttachment::new("unused", Vec::new()))
        }
        async fn release(
            &self,
            _: &Sandbox,
            _: &NetworkAttachment,
        ) -> Result<(), crate::CoreError> {
            Ok(())
        }
        async fn guard_hold_expired(&self, sandbox: &Sandbox) -> Result<(), crate::CoreError> {
            self.contained.lock().unwrap().push(sandbox.id);
            Ok(())
        }
    }

    #[tokio::test]
    async fn an_expired_guarded_sandbox_is_contained_rather_than_destroyed() {
        let mut config = config();
        config.state_dir = std::env::temp_dir().join(format!("af-expire-{}", Uuid::now_v7()));
        let network = Arc::new(ContainingNetwork::default());
        let runtime = FirecrackerRuntime::with_network_backend(config, network.clone());
        let mut guarded = sandbox(Uuid::now_v7(), 0);
        guarded.environment.guard = Some(aiec_guard::policy::GuardConfig::default());
        let token = Uuid::now_v7();
        let vm = running_vm(token);
        let pid = vm.child.id().unwrap();
        runtime.vms.lock().await.insert(guarded.id, vm);

        runtime.expire_lifetime(&guarded, token).await;

        assert_eq!(network.contained.lock().unwrap().as_slice(), &[guarded.id]);
        assert!(
            runtime.vms.lock().await.contains_key(&guarded.id),
            "a contained sandbox is held for the reaper's capture, not torn down"
        );
        assert!(process_running(pid));
        let _ = tokio::fs::remove_dir_all(&runtime.config.state_dir).await;
    }

    #[tokio::test]
    async fn a_stale_lifetime_never_contains_the_vm_that_replaced_it() {
        let mut config = config();
        config.state_dir = std::env::temp_dir().join(format!("af-stale-{}", Uuid::now_v7()));
        let network = Arc::new(ContainingNetwork::default());
        let runtime = FirecrackerRuntime::with_network_backend(config, network.clone());
        let mut guarded = sandbox(Uuid::now_v7(), 0);
        guarded.environment.guard = Some(aiec_guard::policy::GuardConfig::default());
        let fresh_token = Uuid::now_v7();
        let vm = running_vm(fresh_token);
        let pid = vm.child.id().unwrap();
        runtime.vms.lock().await.insert(guarded.id, vm);

        runtime.expire_lifetime(&guarded, Uuid::now_v7()).await;

        assert!(
            network.contained.lock().unwrap().is_empty(),
            "a timer that outlived its own VM must not cut its replacement"
        );
        assert!(process_running(pid));
        let _ = tokio::fs::remove_dir_all(&runtime.config.state_dir).await;
    }

    #[tokio::test]
    async fn an_unguarded_sandbox_is_still_stopped_when_its_lifetime_ends() {
        let mut config = config();
        config.state_dir = std::env::temp_dir().join(format!("af-plain-{}", Uuid::now_v7()));
        let network = Arc::new(ContainingNetwork::default());
        let runtime = FirecrackerRuntime::with_network_backend(config, network.clone());
        let plain = sandbox(Uuid::now_v7(), 0);
        let token = Uuid::now_v7();
        let vm = running_vm(token);
        let pid = vm.child.id().unwrap();
        runtime.vms.lock().await.insert(plain.id, vm);

        runtime.expire_lifetime(&plain, token).await;

        assert!(network.contained.lock().unwrap().is_empty());
        assert!(!runtime.vms.lock().await.contains_key(&plain.id));
        assert!(!process_running(pid));
        let _ = tokio::fs::remove_dir_all(&runtime.config.state_dir).await;
    }

    /// The four files a complete snapshot has, so a test can tell one from a
    /// half-written one.
    fn write_complete_snapshot(dir: &Path, disk: &[u8]) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("vmstate"), b"state").unwrap();
        std::fs::write(dir.join("memory"), b"mem").unwrap();
        std::fs::write(dir.join("rootfs.ext4"), disk).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            format!(
                r#"{{"schema":1,"source_disk":"/vms/x/rootfs.ext4","rootfs_sha256":"{}"}}"#,
                hex::encode(Sha256::digest(disk))
            ),
        )
        .unwrap();
    }

    fn snapshot_manifest_digest(dir: &Path) -> Option<String> {
        let manifest = std::fs::read_to_string(dir.join("manifest.json")).ok()?;
        let value: serde_json::Value = serde_json::from_str(&manifest).ok()?;
        Some(value["rootfs_sha256"].as_str()?.to_string())
    }

    /// A snapshot key moves from one complete snapshot to the next, and a
    /// recapture never leaves the previous manifest describing a disk that has
    /// been overwritten underneath it.
    ///
    /// `snapshot` used to write into the destination directory itself. A
    /// capture that failed partway left half a snapshot there with nothing to
    /// mark it as half, and a recapture overwrote `rootfs.ext4` while the old
    /// `manifest.json` stayed put. The restore path checks that manifest
    /// against the disk, so the second case is a refused restore rather than a
    /// wrong boot - but the key is broken, and the one good snapshot was
    /// destroyed to break it.
    #[tokio::test]
    async fn a_snapshot_key_is_never_left_holding_a_half_written_capture() {
        let root = std::env::temp_dir().join(format!("af-publish-{}", Uuid::now_v7()));
        let destination = root.join("snapshots").join("key");
        write_complete_snapshot(&destination, b"first disk");
        let first = snapshot_manifest_digest(&destination).expect("manifest");

        let staging = destination.with_extension(format!("staging-{}", Uuid::now_v7()));
        write_complete_snapshot(&staging, b"second disk, longer than the first");
        FirecrackerRuntime::publish_snapshot(&staging, &destination)
            .await
            .expect("publish");

        assert_eq!(
            std::fs::read(destination.join("rootfs.ext4")).unwrap(),
            b"second disk, longer than the first",
            "the key must resolve to the new snapshot's disk"
        );
        assert_eq!(
            snapshot_manifest_digest(&destination).unwrap(),
            hex::encode(Sha256::digest(b"second disk, longer than the first")),
            "the manifest must describe the disk that is actually there"
        );
        assert_ne!(snapshot_manifest_digest(&destination).unwrap(), first);
        let entries: Vec<String> = std::fs::read_dir(root.join("snapshots"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec!["key".to_string()],
            "publishing left a staging or superseded directory behind: {entries:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A symlink the guest planted in its own workspace must not become a way
    /// out of it.
    ///
    /// The request path is normalized lexically, which stops `..` in the request
    /// and nothing else. The guest, however, can run a command that creates
    /// links inside its own workspace, and every host-side file operation then
    /// follows them: `put_file("/workspace/escape")` wrote through a planted
    /// link to a file outside the sandbox, and `get_file` read one back. The
    /// request names nothing but `/workspace/escape`.
    ///
    /// A link pointing *within* the workspace is a guest arranging its own
    /// files and is still allowed; only one that leaves is refused.
    #[tokio::test]
    async fn a_symlink_planted_in_the_workspace_cannot_be_used_to_leave_it() {
        let root = std::env::temp_dir().join(format!("af-symlink-{}", Uuid::now_v7()));
        let runtime = BubblewrapRuntime::new(&root);
        let target = sandbox(Uuid::now_v7(), 60);
        runtime.create(&target).await.unwrap();

        let outside = root.join("host-secret.txt");
        std::fs::write(&outside, b"do not read me").unwrap();
        let workspace = root.join(target.id.to_string()).join("workspace");
        // What `exec` lets the guest do to its own directory.
        std::os::unix::fs::symlink(&outside, workspace.join("escape")).unwrap();

        let write = runtime
            .put_file(
                &target,
                PutFileRequest {
                    path: "/workspace/escape".into(),
                    content_base64: "b3ZlcndyaXR0ZW4=".into(),
                    mode: None,
                },
            )
            .await;
        assert!(
            matches!(&write, Err(RuntimeError::Core(CoreError::Forbidden(message))) if message.contains("symlink")),
            "a write through a link out of the workspace was allowed: {write:?}"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"do not read me",
            "the file outside the workspace was modified"
        );

        let read = runtime.get_file(&target, "/workspace/escape").await;
        assert!(
            read.is_err(),
            "a read through a link out of the workspace was allowed: {read:?}"
        );
        assert!(
            runtime
                .list_files(&target, "/workspace/escape")
                .await
                .is_err()
        );
        assert!(
            runtime
                .delete_file(&target, "/workspace/escape")
                .await
                .is_err()
        );
        assert!(
            outside.exists(),
            "a link out of the workspace was followed to delete"
        );

        // A link inside the workspace is still a thing a guest may do.
        std::fs::write(workspace.join("real.txt"), b"content").unwrap();
        std::os::unix::fs::symlink(workspace.join("real.txt"), workspace.join("alias")).unwrap();
        let inside = runtime.get_file(&target, "/workspace/alias").await;
        assert_eq!(
            inside
                .expect("a link within the workspace is the guest's own business")
                .content_base64,
            "Y29udGVudA=="
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// A directory the guest made enormous is refused, not shortened.
    ///
    /// Docker, e2b and the guest agent all bound this and all refuse rather
    /// than truncate, because a caller walking a workspace treats a listing as
    /// complete. Bubblewrap's listing had no ceiling at all, so one tenant
    /// could decide how much of the worker's heap a single `files.list` call
    /// allocates - and the workspace directory is theirs to fill.
    #[tokio::test]
    async fn a_directory_too_large_to_list_is_refused_rather_than_shortened() {
        let root = std::env::temp_dir().join(format!("af-listing-{}", Uuid::now_v7()));
        let runtime = BubblewrapRuntime::new(&root);
        let target = sandbox(Uuid::now_v7(), 60);
        runtime.create(&target).await.unwrap();

        let workspace = root.join(target.id.to_string()).join("workspace");
        for index in 0..=MAX_LIST_ENTRIES {
            std::fs::write(workspace.join(format!("entry-{index}")), b"").unwrap();
        }

        let refused = runtime.list_files(&target, "/workspace").await;
        assert!(
            matches!(&refused, Err(RuntimeError::Core(CoreError::LimitExceeded(message))) if message.contains(&MAX_LIST_ENTRIES.to_string())),
            "one entry past the bound must be a refusal, not a short listing: {refused:?}"
        );

        // One below the bound still lists whole: the bound is where the walk
        // stops being able to describe everything, not a number callers have
        // to stay under.
        std::fs::remove_file(workspace.join(format!("entry-{MAX_LIST_ENTRIES}"))).unwrap();
        let listed = runtime
            .list_files(&target, "/workspace")
            .await
            .expect("a directory at the bound lists");
        assert_eq!(listed.len(), MAX_LIST_ENTRIES);

        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    /// A publish that cannot complete leaves the key with the snapshot it
    /// already had, and leaves nothing of its own behind.
    #[tokio::test]
    async fn a_publish_that_cannot_complete_leaves_the_previous_snapshot_readable() {
        let root = std::env::temp_dir().join(format!("af-publish-{}", Uuid::now_v7()));
        let destination = root.join("snapshots").join("key");
        write_complete_snapshot(&destination, b"first disk");
        let before = snapshot_manifest_digest(&destination).unwrap();

        // No staging directory was ever written, so the final rename cannot
        // succeed. This is what a capture that lost its staging directory to a
        // cleanup looks like at publish time.
        let staging = destination.with_extension(format!("staging-{}", Uuid::now_v7()));
        let outcome = FirecrackerRuntime::publish_snapshot(&staging, &destination).await;

        assert!(outcome.is_err(), "publishing nothing must not succeed");
        assert_eq!(
            snapshot_manifest_digest(&destination).unwrap(),
            before,
            "a failed publish must leave the previous snapshot readable"
        );
        assert_eq!(
            std::fs::read(destination.join("rootfs.ext4")).unwrap(),
            b"first disk"
        );
        let entries: Vec<String> = std::fs::read_dir(root.join("snapshots"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["key".to_string()], "{entries:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// An API socket that accepts the connection and then never answers must
    /// not hold the caller.
    ///
    /// The five-second deadline covered the connect loop only. Everything after
    /// it - writing the request, reading headers, reading the body - was
    /// unbounded, and every caller of this runs while holding the sandbox's
    /// lifecycle gate. One Firecracker that accepted the connection and stopped
    /// responding froze that sandbox entirely, including its destroy.
    #[tokio::test]
    async fn a_firecracker_api_that_stops_responding_is_given_up_on() {
        let mut config = config();
        config.readiness_timeout = Duration::from_millis(50);
        let id = Uuid::now_v7();
        let socket = config.api_socket(id);
        tokio::fs::create_dir_all(socket.parent().unwrap())
            .await
            .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut sink = tokio::io::sink();
            let _ = tokio::io::copy(&mut stream, &mut sink).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let runtime = FirecrackerRuntime::new(config);

        let started = Instant::now();
        let result = runtime.api_response(&socket, "GET", "/", None).await;
        let elapsed = started.elapsed();

        assert!(result.is_err(), "a stalled API must not report success");
        assert!(
            elapsed < Duration::from_secs(6),
            "the exchange took {elapsed:?}; the deadline does not cover the I/O"
        );
        server.abort();
        let _ = tokio::fs::remove_dir_all(runtime.config.state_dir).await;
    }

    /// A `Content-Length` read off the wire sizes a `Vec`, so a response
    /// claiming a large body reserved that memory before a byte of it arrived.
    #[tokio::test]
    async fn a_response_body_larger_than_the_limit_is_refused_before_it_is_allocated() {
        let config = config();
        let id = Uuid::now_v7();
        let socket = config.api_socket(id);
        tokio::fs::create_dir_all(socket.parent().unwrap())
            .await
            .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Headers only, claiming a body that never arrives. The client must
            // refuse on the declared length rather than wait for bytes that are
            // not coming.
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        u64::from(u32::MAX)
                    )
                    .as_bytes(),
                )
                .await
                .ok();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let runtime = FirecrackerRuntime::new(config);

        let result = runtime.api_response(&socket, "GET", "/", None).await;

        let error = result.expect_err("an oversized body must be refused");
        assert!(
            error.to_string().contains("exceeds"),
            "unexpected error: {error}"
        );
        server.abort();
        let _ = tokio::fs::remove_dir_all(runtime.config.state_dir).await;
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

    /// A failed recapture must not destroy the last good archive for the key.
    ///
    /// The published path is `snapshots/<name>.tar`, which is also where the
    /// recovery-from-snapshot path reads from. Writing the tar straight to it
    /// means a capture that fails partway has already truncated or replaced the
    /// only copy, so the key is left with no archive at all rather than with the
    /// previous good one. The failure here is forced by a file tar cannot read;
    /// the assertions are on what survives at the published path.
    #[tokio::test]
    async fn failed_recapture_keeps_the_previously_published_archive() {
        let root = std::env::temp_dir().join(format!("af-recapture-{}", Uuid::now_v7()));
        let runtime = BubblewrapRuntime::new(&root);
        let target = sandbox(Uuid::now_v7(), 60);
        runtime.create(&target).await.unwrap();
        runtime
            .put_file(
                &target,
                PutFileRequest {
                    path: "/workspace/keep.txt".into(),
                    content_base64: "Z29vZA==".into(),
                    mode: None,
                },
            )
            .await
            .unwrap();
        let first = runtime
            .export_workspace_snapshot(&target, "recapture")
            .await
            .unwrap();
        let published = root
            .join("snapshots")
            .join(format!("{}.tar", local_archive_name("recapture").unwrap()));
        let before = tokio::fs::read(&published).await.unwrap();

        // Force the capture to fail in a way that does not depend on the test
        // running unprivileged: `tar -cf -C <path>` cannot change into a path
        // that is not a directory. Replacing the workspace with a regular file
        // makes the second capture fail for every user, including root, while
        // leaving the published archive from the first capture in place.
        let workspace = root.join(target.id.to_string()).join("workspace");
        tokio::fs::remove_dir_all(&workspace).await.unwrap();
        tokio::fs::write(&workspace, b"not a directory")
            .await
            .unwrap();

        let outcome = runtime
            .export_workspace_snapshot(&target, "recapture")
            .await;

        assert!(
            outcome.is_err(),
            "a capture whose workspace is not a directory must fail"
        );
        let after = tokio::fs::read(&published).await.unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&after)),
            first.checksum_sha256,
            "the published archive for the key must still be the last good capture"
        );
        assert_eq!(before, after);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// Restore replaces the workspace rather than merging into it.
    ///
    /// `tar -xf` into the live directory keeps every file the archive does not
    /// mention, so a file deleted in the source workspace reappears after a
    /// restore that is reported as successful. The archive here is a real one
    /// produced by a capture; only the state between capture and restore
    /// differs, which is exactly the sequence a snapshot restore performs.
    #[tokio::test]
    async fn restore_replaces_stale_files_instead_of_merging_them_back() {
        let root = std::env::temp_dir().join(format!("af-replace-{}", Uuid::now_v7()));
        let runtime = BubblewrapRuntime::new(&root);
        let target = sandbox(Uuid::now_v7(), 60);
        runtime.create(&target).await.unwrap();
        for name in ["kept.txt", "deleted.txt"] {
            runtime
                .put_file(
                    &target,
                    PutFileRequest {
                        path: format!("/workspace/{name}"),
                        content_base64: "cHJvdmVu".into(),
                        mode: None,
                    },
                )
                .await
                .unwrap();
        }
        runtime
            .export_workspace_snapshot(&target, "replace")
            .await
            .unwrap();
        let workspace = root.join(target.id.to_string()).join("workspace");
        tokio::fs::remove_file(workspace.join("deleted.txt"))
            .await
            .unwrap();
        tokio::fs::write(workspace.join("added-after-capture.txt"), b"stale")
            .await
            .unwrap();

        runtime.restore(&target, "replace").await.unwrap();

        assert!(
            workspace.join("deleted.txt").exists(),
            "the captured file is restored"
        );
        assert!(
            !workspace.join("added-after-capture.txt").exists(),
            "a file created after the capture must not survive a restore that replaces the workspace"
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// A truncated archive must not replace the live workspace.
    ///
    /// GNU tar does *not* help here: `tar -xf` on an archive cut in half exits 0
    /// with empty stderr and quietly unpacks only the members that were whole,
    /// leaving the workspace holding a partial tree. There is no tar-level gate
    /// that catches this, so the defense has to be the digest - which is
    /// verified before these bytes ever reach the unpack. Without that check a
    /// truncated archive is extracted and reported as a successful restore.
    #[tokio::test]
    async fn a_truncated_archive_is_refused_before_the_workspace_is_touched() {
        let root = std::env::temp_dir().join(format!("af-partial-{}", Uuid::now_v7()));
        let runtime = BubblewrapRuntime::new(&root);
        let target = sandbox(Uuid::now_v7(), 60);
        runtime.create(&target).await.unwrap();
        runtime
            .put_file(
                &target,
                PutFileRequest {
                    path: "/workspace/live.txt".into(),
                    content_base64: "bGl2ZQ==".into(),
                    mode: None,
                },
            )
            .await
            .unwrap();
        let workspace = root.join(target.id.to_string()).join("workspace");
        let good = runtime
            .export_workspace_snapshot(&target, "partial")
            .await
            .unwrap();
        let mut truncated = good.bytes.clone();
        truncated.truncate(truncated.len() / 2);
        assert!(
            truncated.len() < good.bytes.len(),
            "the fixture must actually be shorter than the archive it came from"
        );
        // Published under the key, exactly as a stale or half-uploaded local
        // copy would be.
        let published = root
            .join("snapshots")
            .join(format!("{}.tar", local_archive_name("partial").unwrap()));
        tokio::fs::write(&published, &truncated).await.unwrap();
        let metadata = SnapshotMetadata {
            id: Uuid::now_v7(),
            kind: SnapshotKind::Workspace,
            object_key: "partial".into(),
            checksum_sha256: good.checksum_sha256,
        };

        let outcome = SnapshotProvider::restore(&runtime, &target, &metadata).await;

        assert!(
            outcome.is_err(),
            "a truncated archive must not be reported as a successful restore"
        );
        assert!(
            workspace.join("live.txt").exists(),
            "a refused restore must leave the live workspace intact"
        );
        assert_eq!(
            tokio::fs::read(workspace.join("live.txt")).await.unwrap(),
            b"live"
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// `SnapshotProvider::restore` binds the archive it reads off local disk to
    /// the snapshot it claims to restore.
    ///
    /// The archive is found by object key, so the key alone only proves some
    /// archive exists at that path. Without the digest check a stale archive
    /// left under a reused key is extracted and reported as a successful
    /// restore of the wrong snapshot.
    #[tokio::test]
    async fn snapshot_provider_restore_refuses_an_archive_that_does_not_match_its_digest() {
        let root = std::env::temp_dir().join(format!("af-restore-digest-{}", Uuid::now_v7()));
        let runtime = BubblewrapRuntime::new(&root);
        let target = sandbox(Uuid::now_v7(), 60);
        runtime.create(&target).await.unwrap();
        runtime
            .put_file(
                &target,
                PutFileRequest {
                    path: "/workspace/proof.txt".into(),
                    content_base64: "cHJvdmVu".into(),
                    mode: None,
                },
            )
            .await
            .unwrap();
        let archive = runtime
            .export_workspace_snapshot(&target, "digest")
            .await
            .unwrap();
        // A different archive under the same key: exactly what a stale local
        // copy left by an earlier capture of a reused key looks like.
        let other = WorkspaceArchive {
            key: archive.key.clone(),
            bytes: archive.bytes.clone(),
            checksum_sha256: "0".repeat(64),
        };
        let metadata = SnapshotMetadata {
            id: Uuid::now_v7(),
            kind: SnapshotKind::Workspace,
            object_key: other.key,
            checksum_sha256: other.checksum_sha256,
        };

        let outcome = SnapshotProvider::restore(&runtime, &target, &metadata).await;

        assert!(
            outcome.is_err(),
            "a local archive whose digest disagrees with the snapshot must be refused"
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// Two imports of the same key must not write through one shared temporary
    /// file.
    ///
    /// The temporary name was derived only from the key hash, so concurrent
    /// imports interleaved their bytes through one path and the rename that
    /// publishes the archive could land a spliced tar under the key.
    #[tokio::test]
    async fn concurrent_imports_of_one_key_publish_a_whole_archive() {
        let root = std::env::temp_dir().join(format!("af-import-race-{}", Uuid::now_v7()));
        let runtime = std::sync::Arc::new(BubblewrapRuntime::new(&root));
        let first_sandbox = sandbox(Uuid::now_v7(), 60);
        let second_sandbox = sandbox(Uuid::now_v7(), 60);
        runtime.create(&first_sandbox).await.unwrap();
        runtime.create(&second_sandbox).await.unwrap();
        runtime
            .put_file(
                &first_sandbox,
                PutFileRequest {
                    path: "/workspace/proof.txt".into(),
                    content_base64: "cHJvdmVu".into(),
                    mode: None,
                },
            )
            .await
            .unwrap();
        let archive = runtime
            .export_workspace_snapshot(&first_sandbox, "race")
            .await
            .unwrap();
        let payload = archive.bytes.clone();
        let expected = archive.checksum_sha256.clone();

        // Byte-identical valid archives: the digest gate in
        // `import_workspace_snapshot` passes, so every import really does write
        // its temporary file, and an interleaved write shows up as a published
        // file whose digest is not the one all eight agreed on.
        let imports = (0..8).map(|index| {
            let runtime = std::sync::Arc::clone(&runtime);
            let target = if index % 2 == 0 {
                first_sandbox.clone()
            } else {
                second_sandbox.clone()
            };
            let archive = WorkspaceArchive {
                key: "race".into(),
                bytes: payload.clone(),
                checksum_sha256: expected.clone(),
            };
            tokio::spawn(async move { runtime.import_workspace_snapshot(&target, &archive).await })
        });
        for import in imports {
            import
                .await
                .unwrap()
                .expect("an import of a valid archive must succeed");
        }
        let published = tokio::fs::read(
            root.join("snapshots")
                .join(format!("{}.tar", local_archive_name("race").unwrap())),
        )
        .await
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&published)),
            expected,
            "concurrent imports of one key must publish one whole archive, not a splice"
        );
        assert_eq!(published, payload);
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
            guest_protocol_version: protocol::PROTOCOL_VERSION,
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
        assert!(
            firecracker_capabilities(&LinuxNetworkManager::new(), Some(&coding), 0).coding_guest
        );
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
                r#"{{"artifact_version":"1.0.0","base":"debian:bookworm-slim","profile":"{profile}","capabilities":{capabilities},"guest_agent_version":"0.1.0","guest_protocol_version":2,"rootfs_sha256":"{digest}"}}"#
            ),
        )
        .expect("artifact metadata");
    }

    /// The loader a worker actually uses has to tell "no metadata" apart from
    /// "metadata this worker will not accept".
    ///
    /// The old test built a config by hand with the artifact already in it, so
    /// it exercised the `Some` branch and never the path a real deployment
    /// takes - which is where the protocol check was being swallowed.
    #[test]
    fn a_present_but_unusable_guest_document_is_not_treated_as_absent() {
        let dir = std::env::temp_dir().join(format!("af-guest-meta-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("artifact directory");

        // No document at all: a deployment without guest metadata is fine.
        assert!(
            load_guest_artifact_metadata(&dir)
                .expect("an absent document is not an error")
                .is_none()
        );

        let rootfs = dir.join("aiec-rootfs.ext4");
        std::fs::write(&rootfs, b"root filesystem bytes").expect("rootfs");
        std::fs::write(dir.join("vmlinux"), b"kernel bytes").expect("kernel");
        write_artifact_metadata(&dir, &rootfs, r#"["git","ca-certificates"]"#, "coding");
        assert!(
            load_guest_artifact_metadata(&dir)
                .expect("a good document loads")
                .is_some()
        );

        // A document that is present and wrong must stop the worker.
        let path = dir.join(guest_artifact::GUEST_ARTIFACT_FILE);
        let current = std::fs::read_to_string(&path).expect("metadata");
        let stale = current.replace(
            &format!("\"guest_protocol_version\":{}", protocol::PROTOCOL_VERSION),
            "\"guest_protocol_version\":1",
        );
        assert_ne!(stale, current, "metadata must record the protocol revision");
        std::fs::write(&path, stale).expect("older metadata");
        let error = load_guest_artifact_metadata(&dir)
            .expect_err("an older guest protocol must fail closed, not vanish");
        assert!(error.to_string().contains("protocol 1"), "{error}");

        // And a corrupt document is refused for the same reason.
        std::fs::write(&path, b"{ not json").expect("malformed metadata");
        assert!(
            load_guest_artifact_metadata(&dir).is_err(),
            "malformed metadata must not read as absent"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_older_guest_protocol_is_refused_before_anything_boots() {
        let dir = std::env::temp_dir().join(format!("af-guest-proto-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("artifact directory");
        let rootfs = dir.join("aiec-rootfs.ext4");
        std::fs::write(&rootfs, b"root filesystem bytes").expect("rootfs");
        std::fs::write(dir.join("vmlinux"), b"kernel bytes").expect("kernel");
        write_artifact_metadata(&dir, &rootfs, r#"["git","ca-certificates"]"#, "coding");
        let path = dir.join(guest_artifact::GUEST_ARTIFACT_FILE);
        let current = std::fs::read_to_string(&path).expect("metadata");
        let stale = current.replace(
            &format!("\"guest_protocol_version\":{}", protocol::PROTOCOL_VERSION),
            "\"guest_protocol_version\":1",
        );
        assert_ne!(stale, current, "metadata must record the protocol revision");
        std::fs::write(&path, stale).expect("older metadata");

        // A stale guest cannot answer a bounded range read, so a deployment must
        // not report a usable image at all.
        let error = guest_artifact::load_guest_artifact(&path)
            .expect_err("an older guest protocol must fail closed");
        assert!(error.to_string().contains("protocol 1"), "{error}");
        let config = FirecrackerConfig {
            guest_artifact: Some(
                serde_json::from_str(&std::fs::read_to_string(&path).expect("metadata"))
                    .expect("struct"),
            ),
            ..config()
        };
        let error = config
            .check_guest_capabilities()
            .expect_err("startup must refuse an older guest");
        assert!(error.to_string().contains("protocol 1"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
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

    /// A snapshot disk is hashed in bounded chunks, and the digest is still the
    /// digest of the whole file.
    ///
    /// The image is larger than one chunk and the two copies differ only in
    /// their *last* byte, so a hash that read only the first chunk would call
    /// them equal and accept a snapshot disk nobody verified.
    #[tokio::test]
    async fn a_snapshot_disk_digest_covers_the_whole_image() {
        let dir = std::env::temp_dir().join(format!("af-disk-digest-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let first = dir.join("first.ext4");
        let second = dir.join("second.ext4");
        let mut image = vec![0x5au8; DISK_DIGEST_CHUNK + 4096];
        std::fs::write(&first, &image).expect("image");
        // One byte different, at the very end of the image.
        let last = image.len() - 1;
        image[last] = 0xa5;
        std::fs::write(&second, &image).expect("image");

        let first_digest = disk_sha256(&first).await.expect("digest");
        let second_digest = disk_sha256(&second).await.expect("digest");
        assert_ne!(
            first_digest, second_digest,
            "a difference in the last bytes of a snapshot disk must be detected"
        );
        assert_eq!(first_digest.len(), 64);
        assert_eq!(
            first_digest,
            disk_sha256(&first).await.expect("digest"),
            "hashing the same image twice is the same answer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// A host that reports whatever the test tells it to, so an admission
    /// decision can be asserted without depending on the machine the test runs
    /// on - and, more to the point, without depending on how full it is.
    struct ScriptedPressure {
        reading: HostPressure,
        seen: std::sync::Mutex<Vec<(PathBuf, HostReserves)>>,
    }

    impl HostPressureProbe for ScriptedPressure {
        fn measure(&self, workspace: &Path, reserves: HostReserves) -> HostPressure {
            lock(&self.seen).push((workspace.to_path_buf(), reserves));
            HostPressure {
                reserves,
                ..self.reading.clone()
            }
        }
    }

    fn reading(memory: Option<u64>, disk: Option<u64>, reserves: HostReserves) -> HostPressure {
        HostPressure::from_measurements(
            "test-host",
            chrono::Utc::now(),
            aiec_core::host_pressure::HostMeasurements {
                // A ceiling no sandbox these tests create can reach, so CPU
                // never decides their outcome - the cases that must decide on
                // CPU state state the reading themselves.
                total_vcpus: Some(64),
                available_vcpus: Some(64),
                total_memory_bytes: Some(64 * GIB),
                memory_available_bytes: memory,
                total_disk_bytes: Some(500 * GIB),
                disk_available_bytes: disk,
            },
            reserves,
        )
    }

    /// A configuration whose structural check is irrelevant: admission is
    /// answered before anything is validated, so these tests state a reading
    /// and read the refusal, not the state of this machine.
    fn admission_config(dir: &Path, rootfs: &Path) -> FirecrackerConfig {
        FirecrackerConfig {
            binary: dir.join("missing-firecracker"),
            kernel: dir.join("vmlinux"),
            rootfs: rootfs.to_path_buf(),
            state_dir: dir.join("state"),
            host_reserves: HostReserves::from_mib(0, 0),
            ..config()
        }
    }

    fn admission_sandbox(disk_mb: u32) -> Sandbox {
        Sandbox {
            memory_mb: 128,
            disk_mb,
            runtime: RuntimeKind::Firecracker,
            ..sandbox(Uuid::now_v7(), 60)
        }
    }

    /// A create that cannot be admitted never reaches the image copy, so the
    /// disk is not spent on a sandbox this host cannot hold.
    #[tokio::test]
    async fn a_create_that_the_host_cannot_hold_is_refused_before_anything_is_written() {
        let dir = std::env::temp_dir().join(format!("aiec-admit-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, vec![0u8; 8 * 1024 * 1024]).expect("rootfs");
        let sandbox = admission_sandbox(1024);
        let runtime = FirecrackerRuntime::new(admission_config(&dir, &rootfs))
            .with_host_pressure_probe(Arc::new(ScriptedPressure {
                reading: reading(
                    Some(64 * MIB),
                    Some(400 * GIB),
                    HostReserves::from_mib(0, 0),
                ),
                seen: std::sync::Mutex::new(Vec::new()),
            }));

        let error = runtime
            .create(&sandbox)
            .await
            .expect_err("a host with 64 MiB free cannot take a 128 MiB guest");
        assert!(error.to_string().contains("memory"), "{error}");
        assert!(
            !runtime.config.rootfs(sandbox.id).exists(),
            "the image was materialized for a sandbox the host cannot hold"
        );
        assert!(
            !runtime.config.vm_dir(sandbox.id).exists(),
            "the sandbox directory was created for a refused create"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reading that could not be taken is not a reading of a host with room.
    #[tokio::test]
    async fn an_unmeasurable_host_is_refused_rather_than_guessed() {
        let dir = std::env::temp_dir().join(format!("aiec-admit-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, vec![0u8; 1024 * 1024]).expect("rootfs");
        let sandbox = admission_sandbox(1024);
        let runtime = FirecrackerRuntime::new(admission_config(&dir, &rootfs))
            .with_host_pressure_probe(Arc::new(ScriptedPressure {
                reading: reading(None, None, HostReserves::from_mib(0, 0)),
                seen: std::sync::Mutex::new(Vec::new()),
            }));

        let error = runtime
            .create(&sandbox)
            .await
            .expect_err("an unmeasured host must not be admitted on");
        assert!(
            error.to_string().contains("could not be measured"),
            "{error}"
        );
        assert!(!runtime.config.rootfs(sandbox.id).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The disk a create is admitted on is the larger of what was asked for and
    /// the image every sandbox is copied from. A request below the image's own
    /// size cannot be honoured, so a host that could hold the sandbox is
    /// refused for it unless the image is counted - which is the whole point of
    /// a small request existing on a large-image host.
    #[tokio::test]
    async fn admission_demands_the_base_image_when_the_request_is_smaller() {
        let dir = std::env::temp_dir().join(format!("aiec-admit-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, vec![0u8; 4 * MIB as usize]).expect("rootfs");
        // A 2 MiB request against a 4 MiB image, on a host with 3 MiB free: the
        // request alone would be admitted, and the copy is not.
        let sandbox = admission_sandbox(2);
        let runtime = FirecrackerRuntime::new(admission_config(&dir, &rootfs))
            .with_host_pressure_probe(Arc::new(ScriptedPressure {
                reading: reading(Some(64 * MIB), Some(3 * MIB), HostReserves::from_mib(0, 0)),
                seen: std::sync::Mutex::new(Vec::new()),
            }));
        assert_eq!(runtime.config.minimum_disk_mb(), 4);

        let error = runtime
            .create(&sandbox)
            .await
            .expect_err("3 MiB of disk cannot hold a 4 MiB base image");
        assert!(error.to_string().contains("disk"), "{error}");
        assert!(
            !runtime.config.rootfs(sandbox.id).exists(),
            "an image was copied for a sandbox this host cannot hold"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reserve a create is admitted against is the one the worker is
    /// configured with, and the reading is taken against the directory the
    /// images are written to rather than `/`.
    #[tokio::test]
    async fn admission_uses_the_configured_reserve_and_the_state_directory() {
        let dir = std::env::temp_dir().join(format!("aiec-admit-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, vec![0u8; 1024 * 1024]).expect("rootfs");
        let sandbox = admission_sandbox(1024);
        let reserves = HostReserves::from_mib(1024, 8192);
        let probe = Arc::new(ScriptedPressure {
            // The reading is already net of the reserve - that is what the
            // reserve means - so what admission compares is this figure against
            // the guest's configured memory.
            reading: reading(Some(64 * MIB), Some(2 * GIB), reserves),
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let runtime = FirecrackerRuntime::new(FirecrackerConfig {
            host_reserves: reserves,
            ..admission_config(&dir, &rootfs)
        })
        .with_host_pressure_probe(probe.clone());

        let error = runtime
            .create(&sandbox)
            .await
            .expect_err("a host with 64 MiB above its reserve cannot take a 128 MiB guest");
        assert!(error.to_string().contains("memory"), "{error}");
        let seen = lock(&probe.seen);
        assert_eq!(seen.len(), 1, "the host is measured once per create");
        assert_eq!(seen[0].0, dir.join("state"));
        assert_eq!(seen[0].1, reserves);
        drop(seen);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A host with room is not refused by admission, and the create goes on to
    /// the structural check that fails on this machine's missing Firecracker
    /// binary. That the refusal is about the binary is the evidence that
    /// admission passed.
    #[tokio::test]
    async fn a_host_with_room_is_admitted_and_the_create_continues() {
        let dir = std::env::temp_dir().join(format!("aiec-admit-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, vec![0u8; 1024 * 1024]).expect("rootfs");
        let sandbox = admission_sandbox(1024);
        let runtime = FirecrackerRuntime::new(admission_config(&dir, &rootfs))
            .with_host_pressure_probe(Arc::new(ScriptedPressure {
                reading: reading(
                    Some(64 * GIB),
                    Some(200 * GIB),
                    HostReserves::from_mib(0, 0),
                ),
                seen: std::sync::Mutex::new(Vec::new()),
            }));

        let error = runtime.create(&sandbox).await.expect_err(
            "this machine has no Firecracker binary, so the structural check is the refusal",
        );
        assert!(
            error.to_string().contains("Firecracker binary"),
            "admission refused a host with room: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One gate per sandbox, and nothing left behind when the work is done.
    #[tokio::test]
    async fn a_lifecycle_gate_serves_one_sandbox_at_a_time_and_forgets_it_afterwards() {
        use futures_util::FutureExt;
        let lifecycle = Arc::new(SandboxLifecycle::new());
        let sandbox_id = Uuid::now_v7();
        let held = lifecycle.clone().enter(sandbox_id).await.unwrap();

        // A second caller for the same sandbox queues, and the queue is what
        // keeps the entry alive: polled once, it is pending, and the caller that
        // polled it is gone.
        assert!(lifecycle.clone().enter(sandbox_id).now_or_never().is_none());
        assert_eq!(
            lifecycle.held(),
            1,
            "a caller that gave up while queued is not left counted"
        );
        // A different sandbox is a different machine and does not queue.
        let other = lifecycle.clone().enter(Uuid::now_v7()).await.unwrap();
        assert_eq!(lifecycle.held(), 2);
        drop(other);
        assert_eq!(lifecycle.held(), 1);
        drop(held);
        assert_eq!(
            lifecycle.held(),
            0,
            "the table tracks work in flight, not sandboxes seen"
        );
    }

    /// The table is bounded, and a full table is a refusal rather than growth.
    #[tokio::test]
    async fn a_full_lifecycle_table_refuses_rather_than_growing() {
        let lifecycle = Arc::new(SandboxLifecycle::new());
        let mut held = Vec::with_capacity(MAX_CONCURRENT_LIFECYCLES);
        for _ in 0..MAX_CONCURRENT_LIFECYCLES {
            held.push(lifecycle.clone().enter(Uuid::now_v7()).await.unwrap());
        }
        assert!(
            lifecycle.clone().enter(Uuid::now_v7()).await.is_err(),
            "a table at its bound must refuse, not grow"
        );
        // The sandboxes already in flight keep their gates and finish. A
        // caller queued behind one of them is waiting for that sandbox, not for
        // room in the table, so the bound never queues work it cannot serve.
        held.clear();
        assert_eq!(lifecycle.held(), 0);
        assert!(
            lifecycle.clone().enter(Uuid::now_v7()).await.is_ok(),
            "the table is usable again once the work in flight is done"
        );
    }

    /// A destroy issued while a create is still materializing must not report a
    /// machine that is gone and then let the create finish behind it. The gate
    /// is held here by the test, standing in for that create, so the ordering is
    /// decided rather than raced.
    #[tokio::test]
    async fn a_destroy_waits_for_the_lifecycle_operation_holding_its_sandbox() {
        let dir = std::env::temp_dir().join(format!("aiec-destroy-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, vec![0u8; 1024 * 1024]).expect("rootfs");
        let runtime = FirecrackerRuntime::new(admission_config(&dir, &rootfs));
        let sandbox = admission_sandbox(1024);
        // The state a create that is still copying would be filling.
        std::fs::create_dir_all(runtime.config.vm_dir(sandbox.id)).expect("vm dir");
        std::fs::write(runtime.config.rootfs(sandbox.id), b"half an image").expect("image");

        let held = runtime.lifecycle.clone().enter(sandbox.id).await.unwrap();
        let destroy = tokio::spawn({
            let runtime = runtime.clone();
            let sandbox = sandbox.clone();
            async move { runtime.destroy(&sandbox).await }
        });
        for _ in 0..256 {
            if destroy.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            !destroy.is_finished(),
            "the destroy reported success while a create still held the sandbox"
        );
        assert!(
            runtime.config.vm_dir(sandbox.id).exists(),
            "the state a held create is writing was removed from under it"
        );

        drop(held);
        destroy
            .await
            .expect("the destroy task")
            .expect("the destroy itself");
        assert!(
            !runtime.config.vm_dir(sandbox.id).exists(),
            "the state a completed destroy promised nobody would boot survived it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A forensic capture of a VM that is already paused must not wait for a
    /// guest that will never answer.
    ///
    /// The defect this pins down cost thirty seconds per incident and blocked
    /// every other operation on the sandbox while it did: `PrepareSnapshot`
    /// needs a running guest agent, and against a paused VM the vsock write
    /// simply sits there until `guest_call_timeout` floors it at the readiness
    /// timeout. Quarantine reaches already-paused machines routinely - an
    /// operator pause, or an earlier incident - so this is a live path, and the
    /// capture is held under the sandbox lifecycle gate the whole time.
    ///
    /// A real VM is not needed to prove it. What matters is that the runtime
    /// asks Firecracker for the state and skips the guest call when the answer
    /// is not `Running`, so the fake API below reports `Paused` and the vsock
    /// path is left deliberately absent: a guest call would fail immediately
    /// here rather than hang, so the assertion is that no such call is made and
    /// the capture reaches its snapshot stage at all.
    #[tokio::test]
    async fn a_capture_of_an_already_paused_vm_does_not_call_the_guest() {
        let mut config = config();
        let root = std::env::temp_dir().join(format!("aiec-fc-cap-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("scratch state dir");
        config.state_dir = root.clone();
        let runtime = FirecrackerRuntime::new(config.clone());

        let socket = root.join("api.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("fake api socket");
        let server = tokio::spawn(async move {
            // One connection per Firecracker API exchange this capture makes:
            // the state read, then the pause, then the snapshot creation.
            for _ in 0..3 {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut header = Vec::new();
                let mut byte = [0u8; 1];
                while !header.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    header.push(byte[0]);
                }
                // Answer only what this Firecracker actually serves. State is
                // on `GET /`; `GET /vm` and `GET /instance-info` are both
                // refused by the real API - `Invalid request method and/or
                // path: GET vm.` and `... GET instance-info.` - so a fake that
                // answered any GET would have hidden a wrong endpoint behind a
                // passing test. Both wrong paths were live-confirmed against
                // Firecracker 1.17.0 before being ruled out.
                let request_line = String::from_utf8_lossy(&header);
                let is_root = request_line.starts_with("GET http://localhost/ ");
                // Read the request body so the snapshot request can be
                // answered the way Firecracker answers it: by writing the two
                // files it names. Without them the capture's own size accounting
                // would fail on a missing path, which says nothing about whether
                // the guest was called.
                let length: usize = String::from_utf8_lossy(&header)
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let mut request_body = vec![0u8; length];
                stream.read_exact(&mut request_body).await.ok();
                let (status_line, reply) = if is_root {
                    ("200 OK", r#"{"state":"Paused"}"#.to_owned())
                } else if request_line.starts_with("GET ") {
                    // The real refusal, reproduced - with the path the caller
                    // actually asked for, so a wrong endpoint fails here with
                    // the message Firecracker would have given.
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|target| target.split_once("localhost/"))
                        .map_or_else(String::new, |(_, path)| path.to_owned());
                    (
                        "400 Bad Request",
                        serde_json::json!({
                            "fault_message": format!(
                                "Invalid request method and/or path: GET {path}."
                            )
                        })
                        .to_string(),
                    )
                } else {
                    // Every other request is answered the way Firecracker
                    // answers it: by writing the two files the snapshot request
                    // names. The pause PATCH names none and so writes none.
                    let parsed: serde_json::Value =
                        serde_json::from_slice(&request_body).unwrap_or_default();
                    for key in ["snapshot_path", "mem_file_path"] {
                        if let Some(path) = parsed.get(key).and_then(serde_json::Value::as_str) {
                            let _ = tokio::fs::write(path, b"snapshot").await;
                        }
                    }
                    ("204 No Content", String::new())
                };
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let id = Uuid::now_v7();
        let disk = root.join("rootfs.ext4");
        std::fs::write(&disk, b"disk").expect("disk image");
        runtime.vms.lock().await.insert(
            id,
            FirecrackerVm {
                child: tokio::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .expect("stand-in child"),
                api_socket: socket,
                network: None,
                vsock_socket: root.join("no-such-vsock.sock"),
                rootfs: disk,
                start_token: Uuid::now_v7(),
            },
        );

        let started = std::time::Instant::now();
        let size = runtime
            .capture_forensics(&sandbox(id, 30), "incident-1")
            .await
            .expect("a paused machine is captured without a guest call");
        assert!(size > 0, "the capture produced files");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "capture took {:?}; a paused guest cannot answer PrepareSnapshot, so \
             the call must have been skipped rather than waited on",
            started.elapsed()
        );
        server.abort();
        runtime.vms.lock().await.remove(&id);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A same-size replacement landing between two chunks used to splice
    /// halves silently: per-chunk validation passes on a stable file, so the
    /// pin on the first chunk's version is what refuses the splice.
    #[test]
    fn a_same_size_replacement_mid_read_is_refused_not_spliced() {
        use aiec_core::runtime::{FILE_CHUNK_BYTES, FileChunk, FileChunkRequest};
        let mut pinned = None;
        let first = FileChunkRequest {
            path: "/workspace/data.bin".into(),
            offset: 0,
            length: FILE_CHUNK_BYTES,
            expected_version: None,
        };
        let first_chunk = FileChunk {
            bytes: bytes::Bytes::from(vec![b'a'; FILE_CHUNK_BYTES]),
            size_bytes: FILE_CHUNK_BYTES as u64 * 2,
            version: "v1".into(),
            eof: false,
        };
        let (bytes, done) = FirecrackerRuntime::assemble_chunk(&mut pinned, &first, &first_chunk)
            .expect("the first chunk pins");
        assert_eq!(bytes.len(), FILE_CHUNK_BYTES);
        assert!(!done);
        // The file is replaced with same-size different bytes: the guest
        // reports a new version at the same size and offset.
        let second = FileChunkRequest {
            path: "/workspace/data.bin".into(),
            offset: bytes.len() as u64,
            length: FILE_CHUNK_BYTES,
            expected_version: Some("v1".into()),
        };
        let swapped = FileChunk {
            bytes: bytes::Bytes::from(vec![b'b'; FILE_CHUNK_BYTES]),
            size_bytes: FILE_CHUNK_BYTES as u64 * 2,
            version: "v2".into(),
            eof: true,
        };
        let refused = FirecrackerRuntime::assemble_chunk(&mut pinned, &second, &swapped);
        assert!(
            matches!(
                refused,
                Err(RuntimeError::Core(aiec_core::CoreError::Conflict(_)))
            ),
            "a mid-read replacement must be refused, got {refused:?}"
        );
    }

    /// The steady state still works: identical version and size across chunks
    /// assembles, and the final chunk reports completion.
    #[test]
    fn a_stable_file_assembles_across_chunks() {
        use aiec_core::runtime::{FILE_CHUNK_BYTES, FileChunk, FileChunkRequest};
        let mut pinned = None;
        let first = FileChunkRequest {
            path: "/workspace/data.bin".into(),
            offset: 0,
            length: FILE_CHUNK_BYTES,
            expected_version: None,
        };
        let first_chunk = FileChunk {
            bytes: bytes::Bytes::from(vec![b'a'; FILE_CHUNK_BYTES]),
            size_bytes: FILE_CHUNK_BYTES as u64 + 3,
            version: "v1".into(),
            eof: false,
        };
        let (head, done) = FirecrackerRuntime::assemble_chunk(&mut pinned, &first, &first_chunk)
            .expect("stable first chunk");
        assert!(!done);
        let second = FileChunkRequest {
            path: "/workspace/data.bin".into(),
            offset: head.len() as u64,
            length: FILE_CHUNK_BYTES,
            expected_version: Some("v1".into()),
        };
        let tail = FileChunk {
            bytes: bytes::Bytes::from(vec![b'b'; 3]),
            size_bytes: FILE_CHUNK_BYTES as u64 + 3,
            version: "v1".into(),
            eof: true,
        };
        let (rest, done) = FirecrackerRuntime::assemble_chunk(&mut pinned, &second, &tail)
            .expect("stable second chunk");
        assert!(done);
        assert_eq!(rest.len(), 3);
    }
}
#[cfg(test)]
mod artifact_cache_tests {
    use super::artifact_identity;
    use super::guest_artifact;
    use super::{VerificationCache, VerificationLimits};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

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

        let a = artifact_identity(&first, &kernel, None, None, false)
            .expect("identity a")
            .key;
        let b = artifact_identity(&second, &kernel, None, None, false)
            .expect("identity b")
            .key;
        assert_ne!(a, b, "two different rootfs must not share a verdict");
        assert_eq!(
            a,
            artifact_identity(&first, &kernel, None, None, false)
                .expect("identity again")
                .key,
            "the same unchanged artifact must still hit the cache"
        );

        // Replacing a file in place must miss: the same path with different
        // bytes is a different artifact, and trusting the old verdict for it is
        // exactly the bug.
        let longer = dir.join("rootfs-longer.img");
        std::fs::write(&longer, b"a considerably longer set of contents").expect("write");
        assert_ne!(
            artifact_identity(&first, &kernel, None, None, false)
                .expect("identity a")
                .key,
            artifact_identity(&longer, &kernel, None, None, false)
                .expect("identity longer")
                .key,
            "a different file at a different path must not reuse a verdict"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An image rewritten in place, within the same second and to the same
    /// length, is a different image.
    ///
    /// This is the case a seconds-resolution timestamp cannot see: the key that
    /// used to be built from `Metadata::mtime` was identical before and after
    /// the rewrite, so the success recorded for the old bytes was handed to the
    /// new ones. The test restores the original whole-second modification time
    /// after the rewrite, so it fails for any key that carries neither the
    /// nanoseconds nor the inode.
    #[test]
    fn an_in_place_rewrite_inside_one_second_is_a_different_artifact() {
        let dir = std::env::temp_dir().join(format!("af-same-second-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rootfs = dir.join("rootfs.img");
        let kernel = dir.join("vmlinux");
        std::fs::write(&rootfs, b"first contents").expect("write rootfs");
        std::fs::write(&kernel, b"kernel").expect("write kernel");

        let before = artifact_identity(&rootfs, &kernel, None, None, false)
            .expect("identity before")
            .key;
        let stamp = std::fs::metadata(&rootfs).expect("metadata").mtime();

        // Same length, different bytes, and the timestamp forced back to the
        // same whole second.
        std::fs::write(&rootfs, b"other contents").expect("rewrite");
        restore_mtime(&rootfs, stamp);

        let after = artifact_identity(&rootfs, &kernel, None, None, false)
            .expect("identity after")
            .key;
        assert_ne!(
            before, after,
            "a rootfs rewritten in place must not inherit the verdict of the bytes it replaced"
        );
        let _ = std::fs::remove_dir_all(&dir);
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

        let lax = artifact_identity(&rootfs, &kernel, None, None, false)
            .expect("lax")
            .key;
        let strict = artifact_identity(&rootfs, &kernel, None, None, true)
            .expect("strict")
            .key;
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
            guest_protocol_version: aiec_core::protocol::PROTOCOL_VERSION,
            rootfs_sha256: "abc123".into(),
            kernel_sha256: Some("def456".into()),
        };
        write_manifest(&dir, "abc123");
        let with_artifact = artifact_identity(&rootfs, &kernel, Some(&dir), Some(&artifact), true)
            .expect("with artifact")
            .key;
        assert_ne!(
            strict, with_artifact,
            "different artifact metadata is a different artifact"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The document the digest is compared against is read from disk on every
    /// check, so editing it under a running worker has to invalidate the
    /// verdict.
    ///
    /// Keyed on the loaded copy alone, an operator who replaces the recorded
    /// digest in `guest-capabilities.json` would keep getting the success that
    /// was recorded against the old document - the same "verified sometime
    /// earlier" failure, one level down from the image itself.
    #[test]
    fn editing_the_manifest_on_disk_invalidates_the_verdict() {
        let dir = std::env::temp_dir().join(format!("af-manifest-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rootfs = dir.join("rootfs.img");
        let kernel = dir.join("vmlinux");
        std::fs::write(&rootfs, b"rootfs bytes").expect("write rootfs");
        std::fs::write(&kernel, b"kernel bytes").expect("write kernel");
        let artifact = guest_artifact::GuestArtifact {
            artifact_version: "1".into(),
            base: "debian".into(),
            profile: "coding".into(),
            capabilities: vec!["git".into()],
            git_version: None,
            guest_agent_version: "1".into(),
            guest_protocol_version: aiec_core::protocol::PROTOCOL_VERSION,
            rootfs_sha256: "abc123".into(),
            kernel_sha256: None,
        };
        write_manifest(&dir, "abc123");

        let before = artifact_identity(&rootfs, &kernel, Some(&dir), Some(&artifact), false)
            .expect("identity before")
            .key;
        write_manifest(&dir, "def456");
        let after = artifact_identity(&rootfs, &kernel, Some(&dir), Some(&artifact), false)
            .expect("identity after")
            .key;

        assert_ne!(
            before, after,
            "a manifest edited under a running worker must not reuse the old verdict"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn write_manifest(dir: &std::path::Path, rootfs_sha256: &str) {
        std::fs::write(
            dir.join(guest_artifact::GUEST_ARTIFACT_FILE),
            format!(
                r#"{{"artifact_version":"1.0.0","base":"debian","profile":"coding","capabilities":["git"],"guest_agent_version":"0.1.0","guest_protocol_version":2,"rootfs_sha256":"{rootfs_sha256}"}}"#
            ),
        )
        .expect("manifest");
    }

    /// An unreadable artifact produces no key rather than a shared one.
    #[test]
    fn an_unstatable_artifact_has_no_key() {
        let missing = std::env::temp_dir().join("af-definitely-not-here-9f2c.img");
        assert!(
            artifact_identity(&missing, &missing, None, None, false).is_err(),
            "a missing file must not yield a cache key"
        );
    }

    /// A verdict stops being trusted after its time to live, and a new identity
    /// is verified again immediately.
    ///
    /// The bound that matters is not "the cache works" but "the cache cannot
    /// outlive the fact it recorded": a verdict that is never re-checked is a
    /// permanent exemption from integrity checking.
    #[test]
    fn a_verdict_is_reused_only_inside_its_time_to_live() {
        let cache = VerificationCache::new(VerificationLimits {
            success_ttl: Duration::from_millis(400),
            failure_ttl: Duration::from_millis(400),
            ..VerificationLimits::default()
        });
        let calls = AtomicUsize::new(0);
        let work = || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };

        cache.verify("rootfs-a", 1, work).expect("verified");
        cache.verify("rootfs-a", 1, work).expect("cached verdict");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the second call reused it");
        cache
            .verify("rootfs-b", 1, work)
            .expect("a new identity is verified");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a different artifact is never answered from another one's entry"
        );

        std::thread::sleep(Duration::from_millis(700));
        cache
            .verify("rootfs-a", 1, work)
            .expect("re-verified after the time to live");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "an expired verdict must be earned again"
        );
    }

    /// The number of remembered identities is bounded, and the eviction is
    /// oldest-first rather than arbitrary.
    #[test]
    fn the_cache_holds_a_bounded_number_of_identities() {
        let cache = VerificationCache::new(VerificationLimits {
            max_entries: 2,
            ..VerificationLimits::default()
        });
        let calls = AtomicUsize::new(0);
        let work = || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        for key in ["a", "b", "c"] {
            cache.verify(key, 1, work).expect("verified");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        cache
            .verify("c", 1, work)
            .expect("the newest entry is still held");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "the newest verdict is inside the bound"
        );
        cache
            .verify("a", 1, work)
            .expect("the evicted identity is verified again");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "the oldest entry is what the bound gives up"
        );
    }

    /// The byte bound is enforced as bytes, not as a second entry count: a
    /// worker pointed at a series of large images must not accumulate them.
    #[test]
    fn the_cache_holds_a_bounded_number_of_image_bytes() {
        let cache = VerificationCache::new(VerificationLimits {
            max_entries: 8,
            max_bytes: 10,
            ..VerificationLimits::default()
        });
        let calls = AtomicUsize::new(0);
        let work = || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        cache.verify("a", 6, work).expect("verified");
        cache.verify("b", 6, work).expect("verified");
        cache.verify("b", 6, work).expect("still held");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        cache.verify("a", 6, work).expect("verified again");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "the identity that no longer fits the byte bound is verified again"
        );
    }

    /// Concurrent callers for the same identity share one verification.
    ///
    /// The work here stands in for hashing a multi-gigabyte image. Two of them
    /// at once is not a slower worker, it is two sequential readers of the same
    /// file on the disk the guests are about to share with it.
    #[test]
    fn one_identity_is_never_verified_twice_at_once() {
        let cache = Arc::new(VerificationCache::new(VerificationLimits {
            max_concurrent: 4,
            ..VerificationLimits::default()
        }));
        let calls = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(std::sync::Barrier::new(4));
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let calls = Arc::clone(&calls);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    cache
                        .verify("same", 1, || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(60));
                            Ok(())
                        })
                        .expect("verified")
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "four callers for one identity must share one verification"
        );
    }

    /// Distinct identities are bounded too: a caller waits for a slot rather
    /// than starting another full-image read.
    #[test]
    fn no_more_identities_are_verified_at_once_than_the_limit() {
        let cache = Arc::new(VerificationCache::new(VerificationLimits {
            max_concurrent: 1,
            ..VerificationLimits::default()
        }));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(std::sync::Barrier::new(3));
        let workers: Vec<_> = ["a", "b", "c"]
            .into_iter()
            .map(|key| {
                let cache = Arc::clone(&cache);
                let running = Arc::clone(&running);
                let peak = Arc::clone(&peak);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    cache
                        .verify(key, 1, || {
                            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(40));
                            running.fetch_sub(1, Ordering::SeqCst);
                            Ok(())
                        })
                        .expect("verified")
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker");
        }
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "the concurrency bound is what keeps a restart storm off the disk"
        );
    }

    /// A failure is remembered, reported, and does not follow a worker around
    /// forever - and it never becomes anybody else's answer.
    #[test]
    fn a_failure_stays_visible_without_poisoning_new_artifacts() {
        let cache = VerificationCache::new(VerificationLimits {
            failure_ttl: Duration::from_millis(400),
            ..VerificationLimits::default()
        });
        let calls = AtomicUsize::new(0);
        let broken = || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err("root filesystem sha256 mismatch".to_string())
        };

        let failure = cache
            .verify("broken", 1, broken)
            .expect_err("a mismatching image must fail closed");
        assert!(failure.contains("sha256 mismatch"), "{failure}");
        let repeated = cache
            .verify("broken", 1, broken)
            .expect_err("the failure is still the answer");
        assert_eq!(repeated, failure);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a remembered failure is not re-hashed on every create"
        );

        // A different artifact is a different identity: the broken image's
        // verdict says nothing about it.
        cache
            .verify("replacement", 1, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("a new artifact verifies on its own merits");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // A worker whose image was repaired is not told "still broken" forever.
        std::thread::sleep(Duration::from_millis(700));
        cache
            .verify("broken", 1, broken)
            .expect_err("still failing, but for a fresh look");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "an expired failure is re-checked rather than remembered forever"
        );
    }
}
