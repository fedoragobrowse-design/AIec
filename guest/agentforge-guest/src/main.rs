use agentforge_core::{MAX_FILE, protocol::*};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const AF_VSOCK: i32 = 40;
const SOCK_STREAM: i32 = 1;
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 16],
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
    } = payload
    else {
        return Err("exec payload required".into());
    };
    if argv.is_empty() {
        return Err("argv cannot be empty".into());
    }
    let limit = output_limit.clamp(1, MAX_FRAME - 4096);
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = cwd {
        command.current_dir(safe_path(&path)?);
    }
    for (key, value) in env.into_iter().filter(|(key, value)| valid_env(key, value)) {
        command.env(key, value);
    }
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let stdout = child.stdout.take().ok_or("stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("stderr unavailable")?;
    let out_rx = bounded_reader(stdout, limit);
    let err_rx = bounded_reader(stderr, limit);
    let started = Instant::now();
    let deadline = Duration::from_millis(timeout_ms.clamp(1, 3_600_000));
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            timed_out = true;
            break child.wait().map_err(|error| error.to_string())?;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = out_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|error| error.to_string())??;
    let stderr = err_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|error| error.to_string())??;
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

fn bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
) -> mpsc::Receiver<Result<Vec<u8>, String>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if output.len() < limit {
                        let take = count.min(limit - output.len());
                        output.extend_from_slice(&buffer[..take]);
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(error.to_string()));
                    return;
                }
            }
        }
        let _ = sender.send(Ok(output));
    });
    receiver
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
        let payload = match request.operation {
            Operation::Health => Ok(ResponsePayload::Health {
                ready: Path::new("/workspace").is_dir(),
            }),
            Operation::Exec => run_command(request.payload),
            Operation::ReadFile => match request.payload {
                RequestPayload::Path { path } => fs::read(safe_path(&path)?)
                    .map(|content| ResponsePayload::ReadFile { content })
                    .map_err(|error| error.to_string()),
                _ => Err("path payload required".into()),
            },
            Operation::WriteFile => match request.payload {
                RequestPayload::WriteFile {
                    path,
                    content,
                    mode,
                } => {
                    let path = safe_path(&path)?;
                    if content.len() > MAX_FILE {
                        return Err("file too large".into());
                    }
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
                    }
                    fs::write(&path, content).map_err(|error| error.to_string())?;
                    if let Some(mode) = mode {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                            .map_err(|error| error.to_string())?;
                    }
                    Ok(ResponsePayload::WriteFile)
                }
                _ => Err("write payload required".into()),
            },
            Operation::ListDirectory => match request.payload {
                RequestPayload::Path { path } => {
                    let path = safe_path(&path)?;
                    let mut entries = Vec::new();
                    for item in fs::read_dir(path).map_err(|error| error.to_string())? {
                        let item = item.map_err(|error| error.to_string())?;
                        let metadata = item.metadata().map_err(|error| error.to_string())?;
                        let kind = if metadata.is_dir() {
                            FileKind::Directory
                        } else {
                            FileKind::File
                        };
                        let child = safe_path(&item.path().to_string_lossy())
                            .map_err(|error| error.to_string())?;
                        entries.push(DirectoryEntry {
                            name: item.file_name().to_string_lossy().into_owned(),
                            path: child.to_string_lossy().into_owned(),
                            kind,
                            size: metadata.len(),
                        });
                    }
                    Ok(ResponsePayload::ListDirectory { entries })
                }
                _ => Err("path payload required".into()),
            },
            Operation::CreateDirectory => match request.payload {
                RequestPayload::Path { path } => {
                    let path = safe_path(&path)?;
                    fs::create_dir_all(path).map_err(|error| error.to_string())?;
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
        };
        let shutdown = matches!(payload, Ok(ResponsePayload::Shutdown));
        let response = match payload {
            Ok(payload) => response(request.request_id, payload),
            Err(error) => error_response(request.request_id, error),
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

fn main() {
    let secret = std::env::var("AGENTFORGE_GUEST_SECRET").unwrap_or_else(|_| {
        eprintln!("refusing to start without AGENTFORGE_GUEST_SECRET");
        std::process::exit(2);
    });
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
        match serve_connection(stream, secret.as_bytes()) {
            Ok(true) => return,
            Ok(false) => continue,
            Err(error) => eprintln!("connection failed: {error}"),
        }
    }
}
