use aiec_core::{MAX_FILE, protocol::*};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const AF_VSOCK: i32 = 40;
const SOCK_STREAM: i32 = 1;
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

/// Most entries one directory listing will describe.
///
/// The other runtimes bound this at the same number and refuse rather than
/// shorten. Refusing is the point: the caller walking a workspace treats a
/// listing as complete, so a truncated one archives a directory that is
/// missing files and reports it as whole. The host's own walk bounds total
/// bytes, which a directory of a million empty files never approaches.
const MAX_LIST_ENTRIES: usize = 10_000;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 16],
}

/// Lists one directory, refusing a directory too large to describe whole.
fn list_directory(path: &Path) -> Result<Vec<DirectoryEntry>, String> {
    let mut entries = Vec::new();
    for item in fs::read_dir(path).map_err(|error| error.to_string())? {
        let item = item.map_err(|error| error.to_string())?;
        // `symlink_metadata` rather than `metadata`: a link is described by
        // what it is, not by what it points at, so a link out of the tree is
        // not reported as the directory it targets and a walker does not
        // descend through it.
        let metadata = fs::symlink_metadata(item.path()).map_err(|error| error.to_string())?;
        let kind = if metadata.is_dir() {
            FileKind::Directory
        } else {
            FileKind::File
        };
        // The path reported is the one the caller asked about plus this
        // entry's name, which is inside the workspace by construction.
        // Resolving it is left to the operation that uses it: a link whose
        // target escapes is still listed, so the caller can see that it is
        // there, and still cannot read through it, because every read resolves
        // the path again and refuses. Resolving here instead aborted the whole
        // listing on the first escaping link, which is how a repository
        // containing one lost its entire file list.
        let child = item.path();
        // Checked before the push, so the listing costs no more than the bound
        // allows and the caller is told the directory is too large rather than
        // handed the first MAX_LIST_ENTRIES entries as though they were all of
        // them.
        if entries.len() == MAX_LIST_ENTRIES {
            return Err(format!(
                "directory holds more than {MAX_LIST_ENTRIES} entries"
            ));
        }
        entries.push(DirectoryEntry {
            name: item.file_name().to_string_lossy().into_owned(),
            path: child.to_string_lossy().into_owned(),
            kind,
            size: metadata.len(),
        });
    }
    Ok(entries)
}

fn vsock_listener() -> std::io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let address = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: DEFAULT_CONTROL_PORT,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 16],
    };
    let result = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const SockAddrVm).cast(),
            std::mem::size_of::<SockAddrVm>() as u32,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd.as_raw_fd(), 16) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn accept(listener: &OwnedFd) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn safe_path(raw: &str) -> Result<PathBuf, String> {
    let root = fs::canonicalize("/workspace")
        .map_err(|error| format!("workspace unavailable: {error}"))?;
    let relative = raw
        .strip_prefix("/workspace")
        .ok_or_else(|| "outside workspace".to_owned())?;
    if !relative.is_empty() && !relative.starts_with('/') {
        return Err("outside workspace".into());
    }
    let mut path = root.clone();
    for component in Path::new(relative.trim_start_matches('/')).components() {
        match component {
            std::path::Component::Normal(part) => path.push(part),
            std::path::Component::CurDir => {}
            _ => return Err("path traversal rejected".into()),
        }
    }
    let existing = if path.exists() {
        fs::canonicalize(&path).map_err(|error| error.to_string())?
    } else {
        let parent = path.parent().ok_or_else(|| "missing parent".to_owned())?;
        fs::canonicalize(parent)
            .map_err(|error| error.to_string())?
            .join(path.file_name().unwrap_or_default())
    };
    if !existing.starts_with(&root) {
        return Err("symlink escape rejected".into());
    }
    Ok(existing)
}

/// Traverses to `raw` inside the workspace, creating the intermediate
/// directories it is missing, and opens the leaf with `leaf_flags`.
///
/// `safe_path` resolves a missing leaf by canonicalising its parent, so a path
/// whose parent does not exist yet is refused before a caller can create
/// anything: `WriteFile` and `CreateDirectory` both carried a
/// `create_dir_all` that sat behind a resolution which had already failed, so
/// a nested write or a nested `mkdir` into a fresh workspace could not happen
/// at all.
///
/// Traversal is descriptor-relative and every component is opened with
/// `O_NOFOLLOW`, the same traversal `write_workspace` uses for chunked
/// uploads. It has to be: checking each component by name and then acting
/// through the name afterwards is a check followed by a race, and the process
/// doing the writing is the sandbox's own - it can rename a directory that was
/// just verified and put a link in its place, and a write that went through the
/// path would follow it out of the workspace. Nothing here re-reads the
/// pathname once traversal has started, so there is no window to win. Callers
/// act only through the returned handle, which is also why a file's mode is
/// applied with `fchmod` on it rather than by name.
fn open_in_workspace(
    root: &Path,
    raw: &str,
    leaf_flags: libc::c_int,
    leaf_is_directory: bool,
) -> Result<File, String> {
    use std::os::unix::ffi::OsStrExt;
    let mut components = Vec::new();
    for part in Path::new(raw.trim_start_matches('/')).components() {
        match part {
            std::path::Component::Normal(name) => components
                .push(CString::new(name.as_bytes()).map_err(|_| "invalid path".to_owned())?),
            std::path::Component::CurDir => {}
            _ => return Err("path traversal rejected".into()),
        }
    }
    let directory = fs::File::open(root).map_err(|error| error.to_string())?;
    open_below(&directory, &components, leaf_flags, leaf_is_directory)
}

/// Continues a traversal from an already-open directory, creating what is
/// missing and opening the leaf.
///
/// Taking the directory as a handle rather than as a path is the whole point:
/// once a component has been opened, the rest of the traversal cannot be
/// redirected by renaming it, because the name is never looked up again.
fn open_below(
    directory: &File,
    components: &[CString],
    leaf_flags: libc::c_int,
    leaf_is_directory: bool,
) -> Result<File, String> {
    use std::os::fd::{AsRawFd, FromRawFd};

    fn step(dir: &File, name: &CStr, flags: libc::c_int) -> std::io::Result<File> {
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    /// Creates `name` inside `dir` and re-opens it. A link already at that
    /// name makes `mkdirat` fail with `EEXIST`, and the re-open then refuses
    /// it with `O_NOFOLLOW`; a file planted there is refused the same way.
    fn create(dir: &File, name: &CStr, flags: libc::c_int) -> Result<File, String> {
        if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error.to_string());
            }
        }
        step(dir, name, flags).map_err(|error| error.to_string())
    }
    let (leaf, directories) = components
        .split_last()
        .ok_or_else(|| "path is the workspace root".to_owned())?;
    let mut directory = directory.try_clone().map_err(|error| error.to_string())?;
    for name in directories {
        match step(&directory, name, DIRECTORY_FLAGS) {
            Ok(opened) => directory = opened,
            // Created relative to the directory that was just opened, never
            // through a path, so the name lands inside the workspace even if a
            // component above it is replaced while this call runs.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                directory = create(&directory, name, DIRECTORY_FLAGS)?;
            }
            // `O_NOFOLLOW` on a link reports `ELOOP`, which is not one of the
            // kinds that could be a missing directory. It is refused here as
            // the escape it is rather than reported as absent.
            Err(error) => return Err(error.to_string()),
        }
    }
    match step(&directory, leaf, leaf_flags) {
        Ok(opened) => Ok(opened),
        Err(error) if leaf_is_directory && error.kind() == std::io::ErrorKind::NotFound => {
            create(&directory, leaf, leaf_flags)
        }
        Err(error) => Err(error.to_string()),
    }
}

const DIRECTORY_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Flags for opening a write target. `O_NONBLOCK` is there so a FIFO planted
/// at the target is refused rather than waited on - this is the control
/// channel's only loop, and a blocking open there stalls every later request.
/// `O_TRUNC` is deliberately absent: truncation happens after the handle has
/// been validated, so a refused target is left intact.
const WRITE_FLAGS: libc::c_int =
    libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;

/// The workspace-confined entry point: `raw` is a `/workspace/...` path as the
/// protocol spells it, and everything below is relative to the resolved
/// workspace root.
fn open_in(raw: &str, leaf_flags: libc::c_int, leaf_is_directory: bool) -> Result<File, String> {
    let root = fs::canonicalize("/workspace")
        .map_err(|error| format!("workspace unavailable: {error}"))?;
    open_in_workspace(
        &root,
        workspace_relative(raw)?,
        leaf_flags,
        leaf_is_directory,
    )
}

/// Reduces a `/workspace/...` path to what may be looked up inside the
/// workspace. Anything that is not under `/workspace` is refused here, before
/// a name is resolved against the filesystem at all.
fn workspace_relative(raw: &str) -> Result<&str, String> {
    let relative = raw
        .strip_prefix("/workspace")
        .ok_or_else(|| "outside workspace".to_owned())?;
    if !relative.is_empty() && !relative.starts_with('/') {
        return Err("outside workspace".into());
    }
    Ok(relative)
}

/// Opens a write target and prepares it to be replaced.
///
/// The open deliberately does not truncate: `O_TRUNC` empties whatever the
/// name pointed at *before* anything has decided what it points at, so a
/// refused write - a FIFO, a device, a file that another name also reaches -
/// would still destroy what was there. The open is `O_NONBLOCK` for the same
/// reason in the other direction: opening a FIFO for writing blocks until a
/// reader appears, and this is the control channel's only loop, so a FIFO
/// planted at the target would stall every later request rather than being
/// refused. `O_NONBLOCK` makes that open fail immediately instead.
///
/// Validation is `fstat` on the handle, not a lookup by name, and truncation
/// happens after it on that same handle: what is checked is what is written.
fn open_write_target(raw: &str) -> Result<File, String> {
    let root = fs::canonicalize("/workspace")
        .map_err(|error| format!("workspace unavailable: {error}"))?;
    open_write_target_in(&root, workspace_relative(raw)?)
}

/// `open_write_target` against an already-resolved workspace root.
fn open_write_target_in(root: &Path, relative: &str) -> Result<File, String> {
    use std::os::unix::fs::MetadataExt;

    let file = open_in_workspace(root, relative, WRITE_FLAGS, false)?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("write target is not a regular file".into());
    }
    // A file with a second name is a file something else in the sandbox can
    // still be changing. Refusing is the honest answer to "write this file
    // atomically": there is no atomic answer for a file another process is
    // holding open under a different name.
    if metadata.nlink() != 1 {
        return Err("write target is reachable under another name".into());
    }
    // Only now, with the object known to be an ordinary file, is what was
    // there discarded. Truncating first would have destroyed it even in the
    // cases refused above.
    file.set_len(0).map_err(|error| error.to_string())?;
    Ok(file)
}

/// Opens a directory inside the workspace, creating it and anything missing
/// above it.
fn open_write_directory(raw: &str) -> Result<File, String> {
    open_in(raw, DIRECTORY_FLAGS, true)
}

fn response(id: Uuid, payload: ResponsePayload) -> Response {
    Response {
        version: PROTOCOL_VERSION,
        request_id: id,
        payload,
    }
}
fn error_response(id: Uuid, error: impl ToString) -> Response {
    response(
        id,
        ResponsePayload::Error {
            code: "guest_operation_failed".into(),
            message: error.to_string(),
            retryable: false,
        },
    )
}

fn run_command(payload: RequestPayload) -> Result<ResponsePayload, String> {
    let RequestPayload::Exec {
        argv,
        cwd,
        env,
        timeout_ms,
        output_limit,
        stdin,
    } = payload
    else {
        return Err("exec payload required".into());
    };
    if argv.is_empty() {
        return Err("argv cannot be empty".into());
    }
    if stdin.len() > MAX_FILE {
        return Err("stdin too large".into());
    }
    let limit = output_limit.clamp(1, MAX_FILE.min(MAX_FRAME - 4096));
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/workspace")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    if let Some(path) = cwd {
        command.current_dir(safe_path(&path)?);
    }
    for (key, value) in env.into_iter().filter(|(key, value)| valid_env(key, value)) {
        command.env(key, value);
    }
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    // Standard input is delivered by its own thread rather than written here.
    // Writing inline blocks until the command either reads or exits, so a
    // command that closes its input without reading it fails the whole exec
    // with `EPIPE` instead of reporting the status it exited with, and a
    // command that never reads it at all can run past its own deadline.
    let abort = Arc::new(AtomicBool::new(false));
    let stdin_writer = child.stdin.take().map(|mut pipe| {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(pipe.write_all(&stdin).and_then(|()| pipe.flush()));
            // Closing the pipe here is what tells a reader that has consumed
            // everything to see EOF.
            drop(pipe);
        });
        receiver
    });
    let pid = child.id() as i32;
    let stdout = child.stdout.take().ok_or("stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("stderr unavailable")?;
    let out_rx = bounded_reader(stdout, &abort);
    let err_rx = bounded_reader(stderr, &abort);
    let started = Instant::now();
    let deadline = Duration::from_millis(timeout_ms.clamp(1, 3_600_000));
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= deadline {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            timed_out = true;
            break child.wait().map_err(|error| error.to_string())?;
        }
        thread::sleep(Duration::from_millis(5));
    };
    // The command is gone, so anything still being delivered is undeliverable.
    // Releasing the writer matters more than it looks: a descendant that
    // inherited the read end and never reads it leaves the write blocked
    // forever, and that thread would pin its whole buffer for as long as the
    // guest runs. So the delivery reports what it managed, then the exec stops
    // it rather than waiting on it.
    if let Some(receiver) = stdin_writer {
        // A command that never read its input is still reported as it exited.
        // A pipe the reader has already closed is not an exec failure: the
        // command chose not to read stdin, and `EPIPE`/`ECONNRESET` says only
        // that the reader went away. That verdict does not depend on
        // `timed_out`, because the writer usually fails before the wait loop
        // notices the exit. Every other write failure is real and is reported.
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if !matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) {
                    return Err(error.to_string());
                }
            }
            // A writer that has not finished within the abort window released
            // its pipe on the way out; there is nothing further for it to say.
            Err(_) => {}
        }
    }
    // A pipe held open by a backgrounded grandchild is not an exec failure:
    // the command exited, and its exit status is the answer. Output arrives in
    // chunks, so whatever was produced within the wait is still reported. Both
    // pipes share one bound, so a command that leaves both open costs one
    // wait rather than two.
    let output_deadline = Instant::now() + Duration::from_secs(2);
    let stdout = collect_output(out_rx, limit, output_deadline);
    let stderr = collect_output(err_rx, limit, output_deadline);
    // Only now: before this the collectors have not seen what the command
    // wrote, and stopping the readers early would discard it.
    abort.store(true, Ordering::Relaxed);
    let stdout = stdout?;
    let stderr = stderr?;
    Ok(ResponsePayload::Exec {
        exit_code: status.code().unwrap_or(if timed_out { -124 } else { -1 }),
        stdout,
        stderr,
        duration_ms: started.elapsed().as_millis() as u64,
        timed_out,
    })
}

fn valid_env(key: &str, value: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && !key.contains('=')
        && !key.as_bytes().contains(&0)
        && value.len() <= 4096
        && !value.as_bytes().contains(&0)
}

/// Reads one pipe in bounded chunks, sending each chunk as it arrives so a
/// collector can stop without discarding what the command already wrote.
fn bounded_reader<R: Read + AsRawFd + Send + 'static>(
    mut reader: R,
    abort: &Arc<AtomicBool>,
) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel();
    let abort = Arc::clone(abort);
    // Non-blocking for the same reason the stdin writer is: a descendant that
    // inherited this pipe and never closes it leaves a blocking read parked
    // forever, pinning a thread and its buffer for the life of the guest. The
    // collector's answer does not depend on a stream that is still open.
    unsafe {
        libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
    }
    let mut waiter = libc::pollfd {
        fd: reader.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    thread::spawn(move || {
        let mut buffer = [0; 8192];
        loop {
            if abort.load(Ordering::Relaxed) {
                return;
            }
            waiter.revents = 0;
            let ready = unsafe { libc::poll(&mut waiter, 1, 20) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    let _ = sender.send(Err(error));
                    return;
                }
                continue;
            }
            if ready == 0 {
                continue;
            }
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    // Once the collector is gone the exec has its answer, and
                    // dropping this reader closes our end of the pipe instead
                    // of leaving the command blocked on a full one.
                    if sender.send(Ok(buffer[..count].to_vec())).is_err() {
                        return;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => {
                    let _ = sender.send(Err(error));
                    return;
                }
            }
        }
    });
    receiver
}

/// Drains one pipe up to `limit` bytes, until the command closes it, the reader
/// fails, or `deadline` passes. The bound is what the caller asked for, so
/// output past it is truncated rather than buffered whole.
fn collect_output(
    receiver: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(Ok(chunk)) => {
                if output.len() < limit {
                    let take = chunk.len().min(limit - output.len());
                    output.extend_from_slice(&chunk[..take]);
                }
            }
            Ok(Err(error)) => return Err(error.to_string()),
            // The command closed its output, or it outlived the wait with the
            // pipe still open. What was collected is the answer either way.
            Err(_) => break,
        }
    }
    Ok(output)
}

fn serve_connection(stream: OwnedFd, secret: &[u8]) -> Result<bool, String> {
    let socket = File::from(stream);
    let mut reader = BufReader::new(socket.try_clone().map_err(|error| error.to_string())?);
    let mut writer = BufWriter::new(socket);
    let mut replay = ReplayCache::default();
    loop {
        let request = match read_request(&mut reader, secret, &mut replay) {
            Ok(value) => value,
            Err(ProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(false);
            }
            Err(error) => return Err(error.to_string()),
        };
        // Every refusal has to come back as an answer. `?` inside a match arm
        // propagates out of the *function* the arm is written in, not out of
        // the arm, so with the match inlined in this loop a single refused
        // path - a parent directory that does not exist, a link out of the
        // workspace, a file over the limit - closed the control socket with no
        // response frame at all. The host sees a control channel that went
        // silent and reports the guest as gone, not as a write that was
        // denied; the denial never reaches the operation that caused it.
        // Bounding the match in its own function is what keeps "denied"
        // distinguishable from "gone".
        let request_id = request.request_id;
        let payload = (|| -> Result<ResponsePayload, String> {
            match request.operation {
                Operation::Health => Ok(ResponsePayload::Health {
                    ready: Path::new("/workspace").is_dir(),
                }),
                Operation::Exec => run_command(request.payload),
                Operation::ReadFile => match request.payload {
                    RequestPayload::Path { path } => {
                        let path = safe_path(&path)?;
                        let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
                        if !metadata.is_file() || metadata.len() > MAX_FILE as u64 {
                            return Err("file too large or not regular".into());
                        }
                        fs::read(path)
                            .map(|content| ResponsePayload::ReadFile { content })
                            .map_err(|error| error.to_string())
                    }
                    _ => Err("path payload required".into()),
                },
                Operation::ReadFileChunk => match request.payload {
                    RequestPayload::ReadFileChunk { request } => request
                        .read_workspace(Path::new("/workspace"))
                        .map(|chunk| ResponsePayload::ReadFileChunk {
                            content: chunk.bytes.into(),
                            size_bytes: chunk.size_bytes,
                            version: chunk.version,
                            eof: chunk.eof,
                        })
                        .map_err(|error| error.to_string()),
                    _ => Err("chunk payload required".into()),
                },
                Operation::WriteFile => match request.payload {
                    RequestPayload::WriteFile {
                        path,
                        content,
                        mode,
                    } => {
                        // Checked before anything is created: the limit is a
                        // property of the request, not of what it managed to
                        // leave on disk first.
                        if content.len() > MAX_FILE {
                            return Err("file too large".into());
                        }
                        // Opening the target creates the directories above it,
                        // and returns the only handle the write goes through.
                        let mut file = open_write_target(&path)?;
                        file.write_all(&content)
                            .map_err(|error| error.to_string())?;
                        // Applied to the handle, not to the path: a mode set by
                        // name would be setting it on whatever a rename during
                        // the write put there. `sync_all` on the same handle is
                        // what makes a completed write actually durable - the
                        // previous `fs::write` returned once the bytes were in
                        // the page cache and before any of them reached the
                        // disk.
                        if let Some(mode) = mode {
                            use std::os::unix::fs::PermissionsExt;
                            file.set_permissions(fs::Permissions::from_mode(mode))
                                .map_err(|error| error.to_string())?;
                        }
                        file.sync_all().map_err(|error| error.to_string())?;
                        Ok(ResponsePayload::WriteFile)
                    }
                    _ => Err("write payload required".into()),
                },
                Operation::WriteFileChunk => match request.payload {
                    RequestPayload::WriteFileChunk { request, content } => request
                        .write_workspace(Path::new("/workspace"), &content)
                        .map(|chunk| ResponsePayload::WriteFileChunk {
                            written: chunk.written,
                            size_bytes: chunk.size_bytes,
                        })
                        .map_err(|error| error.to_string()),
                    _ => Err("write chunk payload required".into()),
                },
                Operation::ListDirectory => match request.payload {
                    RequestPayload::Path { path } => list_directory(&safe_path(&path)?)
                        .map(|entries| ResponsePayload::ListDirectory { entries }),
                    _ => Err("path payload required".into()),
                },
                Operation::CreateDirectory => match request.payload {
                    RequestPayload::Path { path } => {
                        // The same traversal a write uses, and for the same
                        // reason: `safe_path` refuses a path whose parent is
                        // missing, so creating a nested directory - which is
                        // what this operation exists to do - failed on the
                        // parent it was meant to create. Opening the leaf as a
                        // directory proves it is one; the handle is dropped.
                        drop(open_write_directory(&path)?);
                        Ok(ResponsePayload::CreateDirectory)
                    }
                    _ => Err("path payload required".into()),
                },
                Operation::RemoveFile => match request.payload {
                    RequestPayload::Path { path } => {
                        let path = safe_path(&path)?;
                        match fs::remove_file(&path) {
                            Ok(()) => Ok(ResponsePayload::RemoveFile),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                Ok(ResponsePayload::RemoveFile)
                            }
                            Err(error) => Err(error.to_string()),
                        }
                    }
                    _ => Err("path payload required".into()),
                },
                Operation::Shutdown => Ok(ResponsePayload::Shutdown),
                Operation::PrepareSnapshot => {
                    let workspace = safe_path("/workspace")?;
                    sync_directory(&workspace)?;
                    Ok(ResponsePayload::PrepareSnapshot)
                }
            }
        })();
        let shutdown = matches!(payload, Ok(ResponsePayload::Shutdown));
        let response = match payload {
            Ok(payload) => response(request_id, payload),
            Err(error) => error_response(request_id, error),
        };
        write_response(&mut writer, secret, &response).map_err(|error| error.to_string())?;
        if shutdown {
            return Ok(true);
        }
    }
}

fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

/// The control secret this guest authenticates with.
///
/// A per-sandbox identity is planted at `/etc/aiec-guest-secret` before the
/// machine boots, and that is what is used when the file is there: the host
/// authenticates with the same per-sandbox value, so the shared
/// `AIEC_GUEST_SECRET` only covers images built before per-sandbox identities
/// existed.
///
/// A planted file that is present but unreadable is a refusal, not a fallback.
/// Falling back there would turn one damaged file into a credential every
/// sandbox shares - and the host would refuse it anyway, because the host holds
/// the per-sandbox key. A fallback buys nothing and hides the damage.
fn control_secret() -> Vec<u8> {
    const PLANTED: &str = "/etc/aiec-guest-secret";
    match std::fs::read_to_string(PLANTED) {
        Ok(text) => {
            let trimmed = text.trim();
            match hex_decode(trimmed) {
                Some(bytes) if !bytes.is_empty() => bytes,
                _ => {
                    eprintln!(
                        "planted control identity at {PLANTED} is unreadable; refusing to start \
                         rather than falling back to a shared secret"
                    );
                    std::process::exit(2);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::env::var("AIEC_GUEST_SECRET") {
                Ok(value) if !value.is_empty() => value.into_bytes(),
                _ => {
                    eprintln!(
                        "no control identity: {PLANTED} is absent and AIEC_GUEST_SECRET is unset"
                    );
                    std::process::exit(2);
                }
            }
        }
        Err(error) => {
            eprintln!("planted control identity at {PLANTED} could not be read: {error}");
            std::process::exit(2);
        }
    }
}

/// Decodes lowercase hex, which is how the host writes the planted identity.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let digit = |value: u8| -> Option<u8> {
            match value {
                b'0'..=b'9' => Some(value - b'0'),
                b'a'..=b'f' => Some(value - b'a' + 10),
                b'A'..=b'F' => Some(value - b'A' + 10),
                _ => None,
            }
        };
        out.push((digit(pair[0])? << 4) | digit(pair[1])?);
    }
    Some(out)
}

fn main() {
    let secret = control_secret();
    fs::create_dir_all("/workspace").ok();
    let listener = vsock_listener().unwrap_or_else(|error| {
        eprintln!("vsock listener failed: {error}");
        std::process::exit(1);
    });
    loop {
        let stream = match accept(&listener) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("accept failed: {error}");
                continue;
            }
        };
        match serve_connection(stream, &secret) {
            Ok(true) => return,
            Ok(false) => continue,
            Err(error) => eprintln!("connection failed: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {

    /// A directory too large to describe is refused, not shortened. The host's
    /// workspace walk treats a listing as complete, so a truncated one archives
    /// a directory that is missing files and reports it as whole. The host's
    /// byte bound does not cover this: a directory of empty files is small.
    #[test]
    fn a_directory_too_large_to_list_is_refused_rather_than_shortened() {
        let root = std::env::temp_dir().join(format!("aiec-guest-listing-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();

        for index in 0..=MAX_LIST_ENTRIES {
            std::fs::write(root.join(format!("entry-{index}")), b"").unwrap();
        }

        let refused = list_directory(&root);
        assert!(
            refused.is_err(),
            "one entry past the bound must be a refusal, not a short listing"
        );
        assert!(
            refused.unwrap_err().contains(&MAX_LIST_ENTRIES.to_string()),
            "and the refusal should say what the bound was"
        );

        // One below the bound still lists whole: the bound is where the walk
        // stops being able to describe everything, not a number the caller has
        // to stay under.
        std::fs::remove_file(root.join(format!("entry-{MAX_LIST_ENTRIES}"))).unwrap();
        let listed = list_directory(&root).expect("a directory at the bound lists");
        assert_eq!(listed.len(), MAX_LIST_ENTRIES);
        assert!(
            listed.iter().all(|entry| entry.kind == FileKind::File),
            "and what it does list is described, not defaulted"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A command that exits without reading its standard input has not failed
    /// the exec. It reported a status, and that status is what the caller gets:
    /// a delivery that dies with `EPIPE` is the command declining to read, not
    /// the guest failing. This also covers the deadline, because the delivery
    /// thread is the only thing that used to be able to outlive it.
    #[test]
    fn stdin_the_command_never_reads_is_not_an_exec_failure() {
        for stdin in [Vec::new(), vec![b'x'; 512 * 1024]] {
            let ResponsePayload::Exec {
                timed_out,
                exit_code,
                ..
            } = run_command(RequestPayload::Exec {
                argv: vec!["/bin/true".into()],
                cwd: None,
                env: Default::default(),
                timeout_ms: 30_000,
                output_limit: 1024,
                stdin,
            })
            .expect("a command that ignores stdin still reports its status")
            else {
                panic!("exec must answer with its exit status");
            };
            assert!(!timed_out, "a command that exited was not killed");
            assert_eq!(exit_code, 0);
        }
    }

    /// The deadline is enforced by the process group, not by delivery
    /// finishing. A command that ignores stdin and outlives its deadline has
    /// to be killed and reported as timed out.
    #[test]
    fn the_deadline_kills_a_command_that_never_reads_its_stdin() {
        let started = Instant::now();
        let ResponsePayload::Exec {
            timed_out,
            exit_code,
            ..
        } = run_command(RequestPayload::Exec {
            argv: vec!["/bin/sleep".into(), "30".into()],
            cwd: None,
            env: Default::default(),
            timeout_ms: 50,
            output_limit: 1024,
            stdin: vec![b'x'; 512 * 1024],
        })
        .expect("the group kill reaps the command")
        else {
            panic!("exec must answer with its exit status");
        };
        assert!(timed_out, "the command outlived its deadline");
        assert_eq!(exit_code, -124);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the deadline is the exec's bound, not the command's"
        );
    }

    /// Moving stdin delivery to a thread must not lose or truncate it, or the
    /// read would silently be short. This is larger than a pipe buffer, so it
    /// only completes if delivery is really concurrent with the child.
    #[test]
    fn stdin_larger_than_a_pipe_buffer_is_delivered_whole() {
        let stdin = vec![b'q'; 256 * 1024];
        let expected = stdin.clone();
        let ResponsePayload::Exec {
            exit_code, stdout, ..
        } = run_command(RequestPayload::Exec {
            argv: vec!["/bin/cat".into()],
            cwd: None,
            env: Default::default(),
            timeout_ms: 30_000,
            // The reader is what bounds the response, so ask for enough to
            // hold every byte being checked.
            output_limit: stdin.len() + 1024,
            stdin,
        })
        .expect("a reader that consumes its input succeeds")
        else {
            panic!("exec must answer with its exit status");
        };
        assert_eq!(exit_code, 0);
        assert_eq!(
            stdout, expected,
            "stdin must arrive whole, and a reader must see EOF"
        );
    }

    /// A command that exits while a backgrounded grandchild still holds its
    /// output pipes has finished. Its exit status and the output it produced
    /// are the answer; the open pipe is not an error and must not cost more
    /// than the one bound both pipes share.
    #[test]
    fn a_backgrounded_grandchild_does_not_fail_or_stall_the_exec() {
        let started = Instant::now();
        let ResponsePayload::Exec {
            timed_out,
            exit_code,
            stdout,
            ..
        } = run_command(RequestPayload::Exec {
            argv: vec!["/bin/sh".into(), "-c".into(), "sleep 30 & echo done".into()],
            cwd: None,
            env: Default::default(),
            timeout_ms: 30_000,
            output_limit: 1024,
            stdin: Vec::new(),
        })
        .expect("a command that exited reports its status, not its descendants")
        else {
            panic!("exec must answer with its exit status");
        };
        assert!(!timed_out, "the command exited inside its deadline");
        assert_eq!(exit_code, 0);
        assert_eq!(stdout, b"done\n", "output written before the wait is kept");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "an open pipe costs one bounded wait, not two unbounded ones"
        );
    }
    use super::*;

    /// A backgrounded descendant inherits its parent's output pipes and keeps
    /// them open after the parent exits, which parks both reader threads in a
    /// blocking read for the life of the guest. The exec still answers; the
    /// threads are the cost.
    ///
    /// Standard input is deliberately not part of this: an asynchronous list
    /// gets `/dev/null` on stdin when job control is off, so the shell exiting
    /// closes that pipe and the writer sees `EPIPE`. Measured — disabling only
    /// the reader abort still leaks two threads per exec, and disabling only a
    /// writer abort leaked none.
    #[test]
    fn a_descendant_holding_output_pipes_does_not_retain_a_thread_per_exec() {
        fn threads() -> usize {
            std::fs::read_dir("/proc/self/task").unwrap().count()
        }
        let baseline = threads();
        // `sleep` never reads its input, and the backgrounded child inherits
        // the pipe, so nothing ever drains it and nothing ever closes it.
        for _ in 0..8 {
            let ResponsePayload::Exec { .. } = run_command(RequestPayload::Exec {
                argv: vec!["/bin/sh".into(), "-c".into(), "sleep 30 & echo done".into()],
                cwd: None,
                env: Default::default(),
                timeout_ms: 30_000,
                output_limit: 1024,
                stdin: vec![b'x'; 256 * 1024],
            })
            .expect("the command itself succeeded") else {
                panic!("exec must answer with its exit status");
            };
        }
        std::thread::sleep(Duration::from_millis(500));
        let leaked = threads().saturating_sub(baseline);
        assert!(
            leaked <= 2,
            "each exec retained a stdin writer thread: {baseline} -> {}",
            threads()
        );
    }

    #[test]
    fn hex_decodes_the_shape_the_host_writes() {
        assert_eq!(hex_decode("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(hex_decode(""), Some(Vec::new()));
        assert_eq!(hex_decode("abc"), None, "an odd length is not a value");
        assert_eq!(hex_decode("zz"), None, "a non-hex byte is not a value");
    }

    #[test]
    fn a_present_but_unusable_identity_is_a_refusal_not_a_fallback() {
        // The decision the code makes: absent falls back (a pre-feature image),
        // present-but-damaged does not. Only the hex path yields bytes.
        for damaged in ["", "   ", "zz", "abc"] {
            assert!(
                hex_decode(damaged.trim())
                    .filter(|bytes| !bytes.is_empty())
                    .is_none(),
                "{damaged:?} must not yield a credential"
            );
        }
        assert!(
            hex_decode("00").is_some(),
            "a well-formed value still works"
        );
    }

    #[test]
    fn a_planted_identity_is_the_bytes_the_host_authenticates_with() {
        // The host writes the secret hex-encoded with a trailing newline, and
        // the guest must recover exactly those bytes.
        let secret = [0xa1u8, 0xb2, 0xc3];
        let encoded = format!(
            "{}\n",
            secret
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(hex_decode(encoded.trim()), Some(secret.to_vec()));
    }

    /// A workspace stand-in for tests, removed when it goes out of scope.
    struct Workspace(PathBuf);

    impl Workspace {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aiec-guest-{name}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).expect("workspace");
            Workspace(fs::canonicalize(&path).expect("canonical workspace"))
        }

        fn write(&self, path: &str, contents: &str) {
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(self.0.join(parent)).expect("parent");
            }
            fs::write(self.0.join(path), contents).expect("seed");
        }

        fn read(&self, path: &str) -> String {
            fs::read_to_string(self.0.join(path)).expect("read")
        }

        fn exists(&self, path: &str) -> bool {
            self.0.join(path).symlink_metadata().is_ok()
        }
    }

    impl Drop for Workspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The production write path, rooted at a test workspace.
    fn write_target(workspace: &Workspace, path: &str) -> Result<File, String> {
        let root = fs::canonicalize(&workspace.0).map_err(|error| error.to_string())?;
        open_write_target_in(&root, path)
    }

    #[test]
    fn a_nested_write_into_a_fresh_workspace_lands_inside_it() {
        // The case the control channel used to die on: the canary path's parent
        // does not exist in a new machine, `safe_path` refused it by
        // canonicalising a parent that was not there, and the refusal closed
        // the connection with no response frame - the host saw a write that
        // became a dead channel rather than a write that was answered.
        let workspace = Workspace::new("nested");
        let mut file = write_target(&workspace, "/secrets/canary.txt").expect("nested write");
        file.write_all(b"canary").expect("write");
        file.sync_all().expect("sync");
        assert_eq!(workspace.read("secrets/canary.txt"), "canary");
    }

    #[test]
    fn a_write_replaces_the_whole_file_and_never_appends() {
        let workspace = Workspace::new("truncate");
        workspace.write("plain/ordinary.txt", "a much longer first version");
        let mut file = write_target(&workspace, "/plain/ordinary.txt").expect("open");
        file.write_all(b"short").expect("write");
        file.sync_all().expect("sync");
        assert_eq!(
            workspace.read("plain/ordinary.txt"),
            "short",
            "a shorter write must not leave the old tail behind"
        );
    }

    #[test]
    fn a_target_that_is_not_an_ordinary_file_is_refused_and_left_alone() {
        let workspace = Workspace::new("special");

        // A FIFO at the target. Two things are being checked: that the write is
        // refused rather than blocking this loop forever waiting for a reader,
        // and that the refusal did not consume the FIFO. `O_TRUNC` at open
        // would have made the open itself wait, with nothing to cancel it.
        let fifo = workspace.0.join("pipe");
        let fifo_path = CString::new(fifo.to_str().expect("utf-8 path")).expect("path has no nul");
        assert_eq!(
            unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) },
            0,
            "mkfifo"
        );
        assert!(
            write_target(&workspace, "/pipe").is_err(),
            "a FIFO is not a file to write"
        );

        // The other reachable case: an ordinary file that also answers to a
        // second name, so something else in the sandbox can still be changing
        // it through that name. Refused, with both names intact.
        workspace.write("plain/data.txt", "original");
        fs::hard_link(
            workspace.0.join("plain/data.txt"),
            workspace.0.join("plain/alias.txt"),
        )
        .expect("hard link");
        assert!(
            write_target(&workspace, "/plain/data.txt").is_err(),
            "a file reachable under another name is refused"
        );
        assert_eq!(workspace.read("plain/data.txt"), "original");
        assert_eq!(workspace.read("plain/alias.txt"), "original");
    }

    #[test]
    fn a_missing_directory_is_created_but_a_leaf_named_like_a_file_is_not() {
        let workspace = Workspace::new("mkdir");
        drop(open_in_workspace(&workspace.0, "/a/b/c", DIRECTORY_FLAGS, true).expect("mkdir"));
        assert!(workspace.exists("a/b/c"));
        workspace.write("a/file", "x");
        assert!(
            open_in_workspace(&workspace.0, "/a/file/c", DIRECTORY_FLAGS, true).is_err(),
            "a file in the middle of the path is refused, not created around"
        );
    }

    #[test]
    fn a_link_anywhere_in_the_path_is_refused_rather_than_followed() {
        let workspace = Workspace::new("escape");
        let outside = Workspace::new("escape-outside");
        outside.write("stolen.txt", "original");

        // A link as an intermediate component: the write must not reach
        // through it, and the target outside the workspace must be untouched.
        std::os::unix::fs::symlink(&outside.0, workspace.0.join("secrets")).expect("link");
        assert!(
            open_in_workspace(&workspace.0, "/secrets/canary.txt", WRITE_FLAGS, false).is_err(),
            "a link in the path must not be followed"
        );
        assert_eq!(outside.read("stolen.txt"), "original");
        assert!(!outside.exists("canary.txt"), "nothing was written outside");

        // A link as the leaf: same answer, and the file it points at keeps its
        // contents instead of being overwritten through the link.
        let other = Workspace::new("escape-leaf");
        other.write("target.txt", "original");
        std::os::unix::fs::symlink(other.0.join("target.txt"), workspace.0.join("link.txt"))
            .expect("link");
        assert!(
            open_in_workspace(&workspace.0, "/link.txt", WRITE_FLAGS, false).is_err(),
            "a leaf that is a link must be refused"
        );
        assert_eq!(other.read("target.txt"), "original");
    }

    #[test]
    fn a_directory_replaced_by_a_link_mid_write_cannot_redirect_the_write() {
        // The race the descriptor-relative traversal exists for, stated without
        // a thread: the attacker renames a directory the guest has already
        // opened and leaves a link to the outside world in its place. A
        // verify-then-write-by-name implementation writes through the link. An
        // implementation holding the opened directory cannot, because after
        // traversal has opened a component the name is never looked up again.
        let workspace = Workspace::new("swap");
        let outside = Workspace::new("swap-outside");
        let held = open_in_workspace(&workspace.0, "/secrets", DIRECTORY_FLAGS, true)
            .expect("create and open the directory");

        let inside = workspace.0.join("secrets");
        let parked = workspace.0.join("parked");
        fs::rename(&inside, &parked).expect("park the real directory");
        std::os::unix::fs::symlink(&outside.0, &inside).expect("leave a link in its place");

        let leaf = CString::new("canary.txt").expect("leaf");
        let mut file = open_below(&held, &[leaf], WRITE_FLAGS, false)
            .expect("the write follows the directory it opened, not the name");
        file.write_all(b"canary").expect("write");
        file.sync_all().expect("sync");

        assert_eq!(
            fs::read_to_string(parked.join("canary.txt")).expect("inside"),
            "canary"
        );
        assert!(
            !outside.exists("canary.txt"),
            "the write followed the link out of the workspace"
        );

        // A fresh traversal refuses the same path, because it has to look the
        // name up again and the name is now a link.
        assert!(open_in_workspace(&workspace.0, "/secrets/other.txt", WRITE_FLAGS, false).is_err());
        assert!(!outside.exists("other.txt"));
    }

    #[test]
    fn traversal_out_of_the_workspace_is_refused_before_any_syscall() {
        let workspace = Workspace::new("traversal");
        for path in ["/../etc/passwd", "/a/../../etc/passwd", "/a/b/.."] {
            assert!(
                open_in_workspace(&workspace.0, path, WRITE_FLAGS, false).is_err(),
                "{path:?} must be refused"
            );
        }
        // The root itself is not a leaf: an operation that resolved to the
        // directory rather than to something inside it is not an operation on
        // a file.
        assert!(open_in_workspace(&workspace.0, "", WRITE_FLAGS, false).is_err());
        assert!(open_in_workspace(&workspace.0, "/", WRITE_FLAGS, false).is_err());
    }

    /// A control channel over a socket pair, answered by `serve_connection`.
    fn serve_over_pair(secret: Vec<u8>) -> (File, thread::JoinHandle<Result<bool, String>>) {
        let mut pair = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) },
            0,
            "socketpair"
        );
        let guest = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        let host = unsafe { File::from_raw_fd(pair[1]) };
        let handle = thread::spawn(move || serve_connection(guest, &secret));
        (host, handle)
    }

    fn write_file_request(path: &str) -> Request {
        Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation: Operation::WriteFile,
            payload: RequestPayload::WriteFile {
                path: path.to_owned(),
                content: b"canary".to_vec(),
                mode: None,
            },
        }
    }

    #[test]
    fn a_refused_operation_is_answered_and_the_connection_survives_it() {
        // The defect was never the refusal itself, it was what the refusal did
        // to the connection: `?` inside a match arm propagated out of the whole
        // connection loop, so the socket closed with nothing written to it. The
        // host read that as a dead control channel - "the guest is gone" -
        // instead of "this write was denied", and the denial never reached the
        // operation that caused it. This runs the real connection loop.
        let secret = b"acceptance-secret".to_vec();
        let (mut host, server) = serve_over_pair(secret.clone());

        // A path that cannot be resolved: the loop must answer rather than
        // hang up.
        write_frame(
            &mut host,
            &secret,
            &write_file_request("/workspace/../etc/passwd"),
        )
        .expect("write the request");
        let answered: Response =
            serde_json::from_slice(&read_frame(&mut host, &secret).expect("a frame, not an eof"))
                .expect("a response");
        assert!(
            matches!(&answered.payload, ResponsePayload::Error { .. }),
            "a denied write is answered as a denial: {:?}",
            answered.payload
        );

        // The channel is still usable: the connection outlived the refusal.
        let mut health = write_file_request("/workspace/../etc/passwd");
        health.operation = Operation::Health;
        health.payload = RequestPayload::None;
        write_frame(&mut host, &secret, &health).expect("write a second request");
        let answered: Response =
            serde_json::from_slice(&read_frame(&mut host, &secret).expect("a second frame"))
                .expect("a second response");
        assert!(matches!(&answered.payload, ResponsePayload::Health { .. }));

        drop(host);
        assert_eq!(
            server.join().expect("the connection closed cleanly"),
            Ok(false)
        );
    }
}
