#![cfg(unix)]

use std::{
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    process::Command,
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
enum StalledPhase {
    RegistrationHeaders,
    RegistrationBody,
    Reconciliation,
    InitialClaim,
    ServingDrain,
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("aiec-startup-signal-{}", Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn worker_stops_at(phase: StalledPhase, signal: i32) {
    let scratch = Scratch::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered, ready) = oneshot::channel();
    let (stopped, maintenance_stopped) = oneshot::channel();
    let reserved = if matches!(phase, StalledPhase::ServingDrain) {
        Some(TcpListener::bind("127.0.0.1:0").await.unwrap())
    } else {
        None
    };
    let worker_address = reserved
        .as_ref()
        .map_or("127.0.0.1:0".parse().unwrap(), |listener| {
            listener.local_addr().unwrap()
        });
    let mut fixture = JoinSet::new();
    fixture.spawn(async move {
        let mut reconciliations = 0;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            let target = line.split_whitespace().nth(1).unwrap();
            let path = target.split_once('?').map_or(target, |(path, _)| path).to_owned();
            let mut content_length = 0;
            loop {
                line.clear();
                assert!(stream.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
            }
            assert!(content_length <= 64 * 1024);
            let mut request = vec![0; content_length];
            stream.read_exact(&mut request).await.unwrap();
            let register = path.ends_with("/register");
            if path.ends_with("/reconcile") {
                reconciliations += 1;
            }
            let stall = match phase {
                StalledPhase::RegistrationHeaders | StalledPhase::RegistrationBody => register,
                StalledPhase::Reconciliation => path.ends_with("/reconcile"),
                StalledPhase::InitialClaim => path.ends_with("/claim"),
                StalledPhase::ServingDrain => reconciliations == 2,
            };
            // A valid assigned-node response lets the real CLI advance to the
            // later startup phases. No sandbox is assigned or executed here.
            let response = if register {
                request
            } else if path.ends_with("/claim") {
                b"[]".to_vec()
            } else {
                b"{}".to_vec()
            };
            let response_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            );
            if stall {
                if matches!(phase, StalledPhase::RegistrationBody) {
                    stream.write_all(response_head.as_bytes()).await.unwrap();
                }
                entered.send(()).unwrap();
                if matches!(phase, StalledPhase::ServingDrain) {
                    let mut byte = [0];
                    assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
                    stopped.send(()).unwrap();
                }
                // Keep the socket and body pending until the test aborts this
                // owned fixture. Sending a signal must not need this response.
                std::future::pending::<()>().await;
                unreachable!();
            }
            stream.write_all(response_head.as_bytes()).await.unwrap();
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_aiec"));
    command
        .args(["--url", &format!("http://{address}"), "worker"])
        .args([
            "--runtime",
            "bwrap-dev",
            "--bind",
            &worker_address.to_string(),
        ])
        .args(["--advertise-url", &format!("http://{worker_address}")])
        .args(["--state-dir"])
        .arg(scratch.path().join("state"))
        .args(["--memory-reserve-mib", "0", "--disk-reserve-mib", "0"])
        .env("AIEC_WORKER_TOKEN", "local-test-token")
        .env("AIEC_ALLOW_LOOPBACK_HTTP", "1")
        .env_remove("AIEC_TLS_CERT_FILE")
        .env_remove("AIEC_TLS_KEY_FILE")
        .env_remove("AIEC_TLS_CA_CERT")
        .env_remove("LD_PRELOAD")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().unwrap();
    drop(reserved);
    if !matches!(timeout(Duration::from_secs(10), ready).await, Ok(Ok(()))) {
        let _ = child.start_kill();
        let output = child.wait_with_output().await.unwrap();
        panic!(
            "{phase:?}: worker did not reach the requested startup phase: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let mut draining_request = None;
    if matches!(phase, StalledPhase::ServingDrain) {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        assert_eq!(
            client
                .get(format!("http://{worker_address}/health"))
                .bearer_auth("local-test-token")
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        let mut request = tokio::net::TcpStream::connect(worker_address)
            .await
            .unwrap();
        // Hold JSON extraction in flight without dispatching any operation.
        request.write_all(
            b"POST /v1/operations HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer local-test-token\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n{"
        ).await.unwrap();
        assert_eq!(
            client
                .get(format!("http://{worker_address}/health"))
                .bearer_auth("local-test-token")
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        draining_request = Some(request);
    }
    // SAFETY: the PID belongs to this still-running, unreaped child. The
    // fixture proves it is awaiting startup I/O, not a reused process ID.
    assert_eq!(unsafe { libc::kill(child.id().unwrap() as i32, signal) }, 0);
    if matches!(phase, StalledPhase::ServingDrain) {
        timeout(Duration::from_secs(1), maintenance_stopped)
            .await
            .expect("maintenance I/O survived shutdown during the listener drain")
            .unwrap();
        assert!(
            child.try_wait().unwrap().is_none(),
            "worker did not drain the in-flight request"
        );
        drop(draining_request);
    }
    let output = timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .expect("worker ignored termination while startup I/O was pending")
        .unwrap();
    assert!(
        output.status.success(),
        "{phase:?}: {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn sigterm_cancels_pending_worker_startup_io() {
    for phase in [
        StalledPhase::RegistrationHeaders,
        StalledPhase::RegistrationBody,
        StalledPhase::Reconciliation,
        StalledPhase::InitialClaim,
    ] {
        worker_stops_at(phase, libc::SIGTERM).await;
    }
}

#[tokio::test]
async fn sigint_cancels_pending_worker_startup_io() {
    for phase in [
        StalledPhase::RegistrationHeaders,
        StalledPhase::RegistrationBody,
        StalledPhase::Reconciliation,
        StalledPhase::InitialClaim,
    ] {
        worker_stops_at(phase, libc::SIGINT).await;
    }
}

#[tokio::test]
async fn sigterm_stops_maintenance_before_draining() {
    worker_stops_at(StalledPhase::ServingDrain, libc::SIGTERM).await;
}

#[tokio::test]
async fn sigint_stops_maintenance_before_draining() {
    worker_stops_at(StalledPhase::ServingDrain, libc::SIGINT).await;
}

#[tokio::test]
async fn occupied_worker_listener_refuses_before_control_requests() {
    let scratch = Scratch::new();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_aiec"));
    command
        .args([
            "--url",
            &format!("http://{}", control.local_addr().unwrap()),
            "worker",
        ])
        .args([
            "--runtime",
            "bwrap-dev",
            "--bind",
            &occupied.local_addr().unwrap().to_string(),
        ])
        .args(["--advertise-url", "http://127.0.0.1:1", "--state-dir"])
        .arg(scratch.path().join("state"))
        .env("AIEC_WORKER_TOKEN", "local-test-token")
        .env("AIEC_ALLOW_LOOPBACK_HTTP", "1")
        .env_remove("AIEC_TLS_CERT_FILE")
        .env_remove("AIEC_TLS_KEY_FILE")
        .env_remove("AIEC_TLS_CA_CERT")
        .env_remove("LD_PRELOAD")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = command.spawn().unwrap();
    let output = timeout(Duration::from_secs(3), async {
        tokio::select! {
            biased;
            request = control.accept() => {
                request.unwrap();
                panic!("worker contacted the control plane before acquiring its listener");
            }
            output = child.wait_with_output() => output.unwrap(),
        }
    })
    .await
    .expect("occupied listener did not refuse startup promptly");
    assert!(!output.status.success());
    assert!(
        !scratch.path().join("state").exists(),
        "failed binding published durable identity"
    );
}
