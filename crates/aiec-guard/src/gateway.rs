//! Outside-guest, destination-bound HTTP broker and explicit allowlist proxy.
mod connect;
use crate::{
    GuardError, Result,
    compiler::CompiledPolicy,
    events::{Category, Decision, EventInput, EventSink},
};
use axum::body::Body;
use bytes::Bytes;
use connect::connect;
use futures_util::{StreamExt, stream};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex as AuditMutex;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const IDLE: Duration = Duration::from_secs(30);
const LIFETIME: Duration = Duration::from_secs(900);
const HEADER_LIMIT: usize = 16 * 1024;
const CHUNK: usize = 16 * 1024;

/// Secrets live only in the operator process. Deliberately has no Debug implementation.
#[derive(Default)]
pub struct CredentialStore {
    secrets: HashMap<String, Zeroizing<String>>,
}
impl CredentialStore {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, name: String, secret: String) -> Result<()> {
        let secret = Zeroizing::new(secret);
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || secret.is_empty()
            || secret.len() > 8192
            || secret.bytes().any(|b| b < 32 || b == 127)
        {
            return Err(GuardError::Policy(
                "invalid credential binding or secret".into(),
            ));
        }
        if self.secrets.contains_key(&name) {
            return Err(GuardError::Policy("duplicate credential binding".into()));
        }
        self.secrets.insert(name, secret);
        Ok(())
    }
    pub fn from_file(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        // Opening first prevents symlink/metadata races; only owner-readable regular files are accepted.
        if !meta.is_file()
            || meta.mode() & 0o777 != 0o600
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.len() > 64 * 1024
        {
            return Err(GuardError::Policy(
                "credential file must be owner-owned regular mode 0600, at most 64KiB".into(),
            ));
        }
        let mut text = Zeroizing::new(String::new());
        file.by_ref().take(65537).read_to_string(&mut text)?;
        if text.len() > 65536 {
            return Err(GuardError::Policy("credential file too large".into()));
        }
        // Custom map visitor rejects duplicate keys rather than keeping the last secret.
        struct SecretsVisitor;
        impl<'de> serde::de::Visitor<'de> for SecretsVisitor {
            type Value = CredentialStore;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("credential map")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut store = CredentialStore::empty();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    store
                        .insert(key, value)
                        .map_err(|_| serde::de::Error::custom("invalid credential map"))?;
                }
                Ok(store)
            }
        }
        use serde::Deserializer;
        let mut de = serde_json::Deserializer::from_str(&text);
        let result = de
            .deserialize_map(SecretsVisitor)
            .map_err(|_| GuardError::Policy("invalid credential file".into()))?;
        de.end()
            .map_err(|_| GuardError::Policy("invalid credential file".into()))?;
        Ok(result)
    }
}

pub struct GatewayConfig {
    pub sandbox_id: Uuid,
    pub tenant_id: Uuid,
    pub compiled: CompiledPolicy,
    pub bind_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub broker_port: u16,
    pub dns_port: u16,
    pub credentials: Arc<CredentialStore>,
    pub events: Arc<dyn EventSink>,
}

struct Budget {
    minute: Instant,
    requests: u32,
    dns: u32,
    out: u64,
    incoming: u64,
}

enum RestoreAck {
    Applied,
    Fenced,
    Failed,
}

/// What a decision cost, kept as one value so it cannot be passed in the wrong
/// order at a call site.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Measured {
    pub(crate) out: u64,
    pub(crate) incoming: u64,
    pub(crate) elapsed: Duration,
}

enum AuditCommand {
    Record(EventInput),
    Restore {
        event: EventInput,
        generation: u64,
        complete: Option<tokio::sync::oneshot::Sender<RestoreAck>>,
    },
}
pub(crate) struct Runtime {
    pub(crate) config: GatewayConfig,
    pub(crate) broker: SocketAddr,
    cut: AtomicBool,
    terminal_failure: AtomicBool,
    pub(crate) stop: watch::Sender<u64>,
    budget: Mutex<Budget>,
    transitions: Mutex<()>,
    requests: Arc<Semaphore>,
    pub(crate) connections: Arc<Semaphore>,
    audit_tx: mpsc::Sender<AuditCommand>,
    tunnels: Mutex<Vec<JoinHandle<()>>>,
}
impl Runtime {
    pub(crate) fn active(&self) -> bool {
        !self.cut.load(Ordering::Acquire) && !self.terminal_failure.load(Ordering::Acquire)
    }
    /// A decision, with the measurements that belong to it.
    ///
    /// The measurements travel as one value so a call site cannot put the byte
    /// counts in the wrong order, and [`Runtime::plain_event`] is the form for
    /// a decision that has none - a lifecycle transition, a policy refusal.
    pub(crate) fn event(
        &self,
        category: Category,
        decision: Decision,
        reason: &str,
        destination: Option<String>,
        measured: Measured,
    ) -> EventInput {
        EventInput {
            sandbox_id: self.config.sandbox_id,
            tenant_id: self.config.tenant_id,
            policy_hash: self.config.compiled.policy_hash().to_owned(),
            category,
            decision,
            reason: reason.into(),
            destination,
            request_bytes: measured.out,
            response_bytes: measured.incoming,
            duration_ms: measured.elapsed.as_millis().min(u64::MAX as u128) as u64,
        }
    }

    /// The measurement-taking form used by the many request and response paths.
    ///
    /// A thin alias kept so the common call reads as one value rather than as
    /// four loose numbers.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn measured_event(
        &self,
        category: Category,
        decision: Decision,
        reason: &str,
        destination: Option<String>,
        out: u64,
        incoming: u64,
        elapsed: Duration,
    ) -> EventInput {
        self.event(
            category,
            decision,
            reason,
            destination,
            Measured {
                out,
                incoming,
                elapsed,
            },
        )
    }
    pub(crate) async fn record(&self, event: EventInput) -> Result<()> {
        match tokio::time::timeout(Duration::from_secs(5), self.config.events.append(event)).await {
            Ok(Ok(_)) => Ok(()),
            _ => {
                self.terminal_failure.store(true, Ordering::Release);
                self.cut.store(true, Ordering::Release);
                self.stop.send_modify(|n| {
                    if *n != u64::MAX {
                        *n = n.wrapping_add(1);
                    }
                });
                Err(GuardError::Unavailable(
                    "guard event sink unavailable".into(),
                ))
            }
        }
    }

    async fn process_audit(&self, command: AuditCommand) -> Result<()> {
        match command {
            AuditCommand::Record(event) => self.record(event).await,
            AuditCommand::Restore {
                event,
                generation,
                complete,
            } => {
                let result = async {
                    self.record(event).await?;
                    let _fence = self.transitions.lock().map_err(|_| {
                        self.terminal_failure.store(true, Ordering::Release);
                        GuardError::Unavailable("gateway transition state is poisoned".into())
                    })?;
                    if self.terminal_failure.load(Ordering::Acquire)
                        || *self.stop.borrow() == u64::MAX
                    {
                        return Err(GuardError::Unavailable("gateway terminal fault".into()));
                    }
                    if *self.stop.borrow() != generation
                        || complete.as_ref().is_some_and(|sender| sender.is_closed())
                    {
                        return Err(GuardError::Denied("gateway release fenced out".into()));
                    }
                    self.cut.store(false, Ordering::Release);
                    Ok(())
                }
                .await;
                match result {
                    Ok(()) => {
                        if let Some(sender) = complete {
                            let _ = sender.send(RestoreAck::Applied);
                        }
                        Ok(())
                    }
                    Err(GuardError::Denied(_)) => {
                        if let Some(sender) = complete {
                            let _ = sender.send(RestoreAck::Fenced);
                        }
                        self.record(self.measured_event(
                            Category::Lifecycle,
                            Decision::Deny,
                            "gateway release fenced out",
                            None,
                            0,
                            0,
                            Duration::ZERO,
                        ))
                        .await
                    }
                    Err(error) => {
                        if let Some(sender) = complete {
                            let _ = sender.send(RestoreAck::Failed);
                        }
                        Err(error)
                    }
                }
            }
        }
    }

    fn close(&self) {
        let fence = self.transitions.lock();
        if fence.is_err() {
            self.terminal_failure.store(true, Ordering::Release);
        }
        self.cut.store(true, Ordering::Release);
        self.stop.send_replace(u64::MAX);
    }
    pub(crate) fn rate(&self, dns: bool) -> Result<()> {
        let mut b = self
            .budget
            .lock()
            .map_err(|_| GuardError::Unavailable("budget unavailable".into()))?;
        if b.minute.elapsed() >= Duration::from_secs(60) {
            b.minute = Instant::now();
            b.requests = 0;
            b.dns = 0;
        }
        let cap = if dns {
            self.config.compiled.policy().limits.dns_queries_per_minute
        } else {
            self.config.compiled.policy().limits.requests_per_minute
        };
        let value = if dns { &mut b.dns } else { &mut b.requests };
        if *value >= cap {
            return Err(GuardError::Denied("rate budget exhausted".into()));
        }
        *value += 1;
        Ok(())
    }
    pub(crate) fn debit(&self, outgoing: bool, amount: u64) -> Result<()> {
        let mut b = self
            .budget
            .lock()
            .map_err(|_| GuardError::Unavailable("budget unavailable".into()))?;
        let cap = if outgoing {
            self.config.compiled.policy().limits.bytes_out
        } else {
            self.config.compiled.policy().limits.bytes_in
        };
        let value = if outgoing {
            &mut b.out
        } else {
            &mut b.incoming
        };
        *value = value
            .checked_add(amount)
            .ok_or_else(|| GuardError::Denied("byte budget exhausted".into()))?;
        if *value > cap {
            return Err(GuardError::Denied("byte budget exhausted".into()));
        }
        Ok(())
    }
    pub(crate) async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let test_addresses = self.config.compiled.boundary().test_addresses(host, port);
        let addresses = if !test_addresses.is_empty() {
            test_addresses
                .iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect::<Vec<_>>()
        } else {
            tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host, port)),
            )
            .await
            .map_err(|_| GuardError::Denied("destination resolution timeout".into()))?
            .map_err(|_| GuardError::Denied("destination resolution failed".into()))?
            .take(17)
            .collect()
        };
        if addresses.is_empty() || addresses.len() > 16 {
            return Err(GuardError::Denied("destination resolution bound".into()));
        }
        for addr in &addresses {
            self.config.compiled.check_destination(host, addr.ip())?;
        }
        Ok(addresses)
    }
}

pub struct GuardGateway {
    state: Arc<Runtime>,
    tasks: Vec<JoinHandle<Result<()>>>,
    audit_task: Option<JoinHandle<Result<()>>>,
    audit_stop: watch::Sender<bool>,
    dns: SocketAddr,
}
impl GuardGateway {
    pub async fn start(config: GatewayConfig) -> Result<Self> {
        config.compiled.verify()?;
        if let Some(model) = &config.compiled.policy().model
            && !config.credentials.secrets.contains_key(&model.credential)
        {
            return Err(GuardError::Unavailable(
                "bound model credential unavailable".into(),
            ));
        }
        let broker = TcpListener::bind((config.bind_ip, config.broker_port)).await?;
        let broker_addr = broker.local_addr()?;
        let dns_tcp = TcpListener::bind((config.bind_ip, config.dns_port)).await?;
        let dns_addr = dns_tcp.local_addr()?;
        let dns_udp = UdpSocket::bind(dns_addr).await?;
        let (stop, _) = watch::channel(0);
        let (audit_tx, mut audit_rx) = mpsc::channel(128);
        let (audit_stop, mut audit_shutdown) = watch::channel(false);
        let request_limit = config.compiled.policy().limits.max_concurrent_requests as usize;
        let state = Arc::new(Runtime {
            config,
            broker: broker_addr,
            cut: AtomicBool::new(false),
            terminal_failure: AtomicBool::new(false),
            stop,
            budget: Mutex::new(Budget {
                minute: Instant::now(),
                requests: 0,
                dns: 0,
                out: 0,
                incoming: 0,
            }),
            transitions: Mutex::new(()),
            requests: Arc::new(Semaphore::new(request_limit)),
            connections: Arc::new(Semaphore::new(request_limit.saturating_mul(2).max(8))),
            audit_tx,
            tunnels: Mutex::new(Vec::new()),
        });
        state
            .record(state.measured_event(
                Category::Lifecycle,
                Decision::Allow,
                "gateway started",
                None,
                0,
                0,
                Duration::ZERO,
            ))
            .await?;
        let audit_state = state.clone();
        let audit_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = audit_shutdown.changed() => {
                        audit_rx.close();
                        while let Some(command) = audit_rx.recv().await {
                            audit_state.process_audit(command).await?;
                        }
                        break;
                    }
                    item = audit_rx.recv() => match item {
                        Some(command) => audit_state.process_audit(command).await?,
                        None => break,
                    }
                }
            }
            Ok(())
        });
        let tasks = vec![
            spawn_service(state.clone(), serve_broker(broker, state.clone())),
            spawn_service(state.clone(), crate::dns::serve_udp(dns_udp, state.clone())),
            spawn_service(state.clone(), crate::dns::serve_tcp(dns_tcp, state.clone())),
        ];
        Ok(Self {
            state,
            tasks,
            audit_task: Some(audit_task),
            audit_stop,
            dns: dns_addr,
        })
    }
    pub fn broker_addr(&self) -> SocketAddr {
        self.state.broker
    }
    pub fn dns_addr(&self) -> SocketAddr {
        self.dns
    }
    pub fn cut(&self) -> Result<()> {
        let _fence = self.state.transitions.lock().map_err(|_| {
            self.state.terminal_failure.store(true, Ordering::Release);
            GuardError::Unavailable("gateway transition state is poisoned".into())
        })?;
        self.state.cut.store(true, Ordering::Release);
        self.state.stop.send_modify(|n| {
            if *n != u64::MAX {
                *n = n.wrapping_add(1);
            }
        });
        self.queue_transition(Decision::Cut, "gateway network cut")
    }
    /// A service/audit fault is terminal. Recovery requires a fresh gateway
    /// after verified journal replay, not an operator's ordinary network release.
    pub fn health(&self) -> Result<()> {
        if self.state.terminal_failure.load(Ordering::Acquire)
            || *self.state.stop.borrow() == u64::MAX
        {
            return Err(GuardError::Unavailable(
                "gateway has a terminal service or audit fault".into(),
            ));
        }
        Ok(())
    }

    /// Accepts a release request; traffic remains cut until its audit record is
    /// durable. A later cut fences out a pending release. Use restore_and_wait
    /// when the caller requires confirmation that release has been applied.
    pub fn restore(&self) -> Result<()> {
        self.enqueue_restore(None)
    }

    pub async fn restore_and_wait(&self) -> Result<()> {
        let (complete, receipt) = tokio::sync::oneshot::channel();
        self.enqueue_restore(Some(complete))?;
        match receipt.await {
            Ok(RestoreAck::Applied) => Ok(()),
            Ok(RestoreAck::Fenced) => Err(GuardError::Denied("gateway release fenced out".into())),
            _ => Err(GuardError::Unavailable("gateway release failed".into())),
        }
    }

    fn enqueue_restore(
        &self,
        complete: Option<tokio::sync::oneshot::Sender<RestoreAck>>,
    ) -> Result<()> {
        self.health()?;
        let _fence = self.state.transitions.lock().map_err(|_| {
            self.state.terminal_failure.store(true, Ordering::Release);
            GuardError::Unavailable("gateway transition state is poisoned".into())
        })?;
        let generation = *self.state.stop.borrow();
        let event = self.state.measured_event(
            Category::Lifecycle,
            Decision::Allow,
            "gateway release authorized",
            None,
            0,
            0,
            Duration::ZERO,
        );
        self.state
            .audit_tx
            .try_send(AuditCommand::Restore {
                event,
                generation,
                complete,
            })
            .map_err(|_| {
                self.state.terminal_failure.store(true, Ordering::Release);
                self.state.cut.store(true, Ordering::Release);
                GuardError::Unavailable("guard audit queue full".into())
            })
    }
    fn queue_transition(&self, decision: Decision, reason: &str) -> Result<()> {
        self.state
            .audit_tx
            .try_send(AuditCommand::Record(self.state.measured_event(
                Category::Lifecycle,
                decision,
                reason,
                None,
                0,
                0,
                Duration::ZERO,
            )))
            .map_err(|_| {
                self.state.terminal_failure.store(true, Ordering::Release);
                self.state.cut.store(true, Ordering::Release);
                GuardError::Unavailable("guard audit queue full".into())
            })
    }
    pub async fn shutdown(mut self) -> Result<()> {
        self.state.close();
        let mut failure = None;
        for task in self.tasks.drain(..) {
            match task.await {
                Ok(Ok(())) => (),
                Ok(Err(e)) => {
                    failure = Some(e);
                }
                Err(_) => {
                    failure = Some(GuardError::Unavailable("gateway task failed".into()));
                }
            }
        }
        let tunnels = self
            .state
            .tunnels
            .lock()
            .map(|mut tasks| std::mem::take(&mut *tasks))
            .unwrap_or_default();
        for task in tunnels {
            let _ = task.await;
        }
        self.audit_stop.send_replace(true);
        if let Some(task) = self.audit_task.take() {
            match task.await {
                Ok(Ok(())) => (),
                Ok(Err(error)) => failure = Some(error),
                Err(_) => {
                    self.state.terminal_failure.store(true, Ordering::Release);
                    failure = Some(GuardError::Unavailable("gateway audit task failed".into()));
                }
            }
        }
        self.state
            .record(self.state.measured_event(
                Category::Lifecycle,
                Decision::Allow,
                "gateway stopped",
                None,
                0,
                0,
                Duration::ZERO,
            ))
            .await?;
        if self.state.terminal_failure.load(Ordering::Acquire) {
            return Err(GuardError::Unavailable(
                "gateway stopped after a terminal service or audit fault".into(),
            ));
        }
        if let Some(e) = failure {
            return Err(e);
        }
        Ok(())
    }
}
impl Drop for GuardGateway {
    fn drop(&mut self) {
        self.state.close();
        for task in &self.tasks {
            task.abort();
        }
        if let Ok(tasks) = self.state.tunnels.lock() {
            for task in tasks.iter() {
                task.abort();
            }
        }
        self.audit_stop.send_replace(true);
    }
}

async fn serve_broker(listener: TcpListener, state: Arc<Runtime>) -> Result<()> {
    let mut stop = state.stop.subscribe();
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => { if *stop.borrow() == u64::MAX { break; } }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                let Ok(permit) = state.connections.clone().try_acquire_owned() else { drop(socket); continue; };
                if peer.ip() != IpAddr::V4(state.config.guest_ip) { state.record(state.measured_event(Category::Network, Decision::Deny, "guest source mismatch", None, 0, 0, Duration::ZERO)).await?; continue; }
                if !state.active() { drop(socket); continue; }
                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut cancel = state.stop.subscribe();
                    let service_state = state.clone();
                    let service = service_fn(move |request: Request<Incoming>| {
                        let state = service_state.clone();
                        async move { Ok::<_, std::convert::Infallible>(handle(request.map(Body::new), state).await) }
                    });
                    let mut http = hyper::server::conn::http1::Builder::new();
                    http.max_buf_size(HEADER_LIMIT).keep_alive(false);
                    let connection = http.serve_connection(TokioIo::new(socket), service).with_upgrades();
                    tokio::select! { _ = cancel.changed() => {}, _ = tokio::time::sleep(LIFETIME) => {}, _ = connection => {} }
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn response(status: StatusCode, text: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Body::from(text))
        .expect("fixed response")
}
async fn deny(state: &Runtime, reason: &'static str, status: StatusCode) -> Response<Body> {
    let _ = state
        .record(state.measured_event(
            Category::Network,
            Decision::Deny,
            reason,
            None,
            0,
            0,
            Duration::ZERO,
        ))
        .await;
    response(status, reason)
}
fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 2048
        && !path.contains('%')
        && !path.contains('\\')
        && !path.split('/').any(|p| p == "." || p == "..")
        && !path.bytes().any(|b| b <= 32 || b == 127)
}
fn path_allowed(path: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|p| {
        path == p
            || (p.ends_with('/') && path.starts_with(p))
            || path
                .strip_prefix(p)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}
fn forbidden_headers(headers: &HeaderMap) -> bool {
    headers.contains_key("upgrade")
        || headers.contains_key("proxy-authorization")
        || headers.get_all("host").iter().count() != 1
        || headers.iter().any(|(name, value)| {
            name.as_str().len() + value.as_bytes().len() > HEADER_LIMIT
                || value.as_bytes().iter().any(|b| *b < 32 || *b == 127)
        })
}
fn sanitized(headers: &HeaderMap) -> HeaderMap {
    let nominated: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    let mut clean = HeaderMap::new();
    for (name, value) in headers {
        if matches!(
            name.as_str(),
            "host"
                | "authorization"
                | "x-api-key"
                | "proxy-authorization"
                | "connection"
                | "proxy-connection"
                | "keep-alive"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
        ) || nominated.iter().any(|n| n == name.as_str())
        {
            continue;
        }
        clean.append(name.clone(), value.clone());
    }
    clean
}

async fn handle(mut request: Request<Body>, state: Arc<Runtime>) -> Response<Body> {
    if !state.active() {
        return deny(&state, "gateway cut", StatusCode::SERVICE_UNAVAILABLE).await;
    }
    if state.rate(false).is_err() {
        return deny(
            &state,
            "request rate exhausted",
            StatusCode::TOO_MANY_REQUESTS,
        )
        .await;
    }
    let permit = match state.requests.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return deny(
                &state,
                "request concurrency exhausted",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .await;
        }
    };
    if forbidden_headers(request.headers()) {
        return deny(&state, "invalid request headers", StatusCode::BAD_REQUEST).await;
    }
    if request.method() == Method::CONNECT {
        return connect(request, state, permit).await;
    }
    let uri = request.uri().clone();
    if uri.query().is_some_and(|q| {
        q.len() > 2048
            || q.bytes().any(|b| b <= 32 || b == 127)
            || q.to_ascii_lowercase().contains("%0")
    }) {
        return deny(&state, "invalid request query", StatusCode::BAD_REQUEST).await;
    }
    let mut headers = sanitized(request.headers());
    let (host, port, scheme, path, category) =
        if uri.scheme().is_none() && uri.authority().is_none() {
            if request.headers().get("host").and_then(|v| v.to_str().ok())
                != Some(state.broker.to_string().as_str())
            {
                return deny(&state, "broker authority mismatch", StatusCode::FORBIDDEN).await;
            }
            let Some(model) = &state.config.compiled.policy().model else {
                return deny(&state, "model route denied", StatusCode::FORBIDDEN).await;
            };
            let prefix = format!("/model/{}", model.credential);
            let Some(path) = uri.path().strip_prefix(&prefix) else {
                return deny(&state, "model binding mismatch", StatusCode::FORBIDDEN).await;
            };
            if !safe_path(path)
                || !model
                    .allowed_methods
                    .iter()
                    .any(|m| m == request.method().as_str())
                || !path_allowed(path, &model.allowed_paths)
            {
                return deny(&state, "model method or path denied", StatusCode::FORBIDDEN).await;
            }
            let Some(binding) = state.config.compiled.policy().credentials.iter().find(|b| {
                b.name == model.credential && b.host == model.host && b.port == model.port
            }) else {
                return deny(
                    &state,
                    "credential destination mismatch",
                    StatusCode::FORBIDDEN,
                )
                .await;
            };
            let expected = if binding.header == "authorization" {
                format!("Bearer placeholder://{}", binding.name)
            } else {
                format!("placeholder://{}", binding.name)
            };
            if request
                .headers()
                .get_all(binding.header.as_str())
                .iter()
                .count()
                != 1
                || request
                    .headers()
                    .get(binding.header.as_str())
                    .and_then(|v| v.to_str().ok())
                    != Some(expected.as_str())
                || request.headers().iter().any(|(n, v)| {
                    n.as_str() != binding.header
                        && (matches!(n.as_str(), "authorization" | "x-api-key")
                            || v.as_bytes().windows(14).any(|w| w == b"placeholder://"))
                })
            {
                return deny(
                    &state,
                    "credential placeholder mismatch",
                    StatusCode::FORBIDDEN,
                )
                .await;
            }
            let Some(secret) = state.config.credentials.secrets.get(&binding.name) else {
                return deny(
                    &state,
                    "credential unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
            };
            let value = if binding.header == "authorization" {
                Zeroizing::new(format!("Bearer {}", **secret))
            } else {
                Zeroizing::new(secret.to_string())
            };
            let Ok(mut value) = HeaderValue::from_str(&value) else {
                return deny(
                    &state,
                    "credential unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
            };
            value.set_sensitive(true);
            headers.insert(
                http::header::HeaderName::from_bytes(binding.header.as_bytes())
                    .expect("validated header"),
                value,
            );
            (
                model.host.clone(),
                model.port,
                model.scheme.clone(),
                path.to_owned(),
                Category::Model,
            )
        } else {
            if !matches!(uri.scheme_str(), Some("http" | "https")) {
                return deny(&state, "proxy scheme denied", StatusCode::FORBIDDEN).await;
            }
            let Some(authority) = uri.authority() else {
                return deny(&state, "proxy authority missing", StatusCode::BAD_REQUEST).await;
            };
            let host = authority.host().to_owned();
            let scheme = uri.scheme_str().expect("validated explicit scheme");
            let port = authority
                .port_u16()
                .unwrap_or(if scheme == "https" { 443 } else { 80 });
            if authority.as_str().contains('@')
                || request.headers().get("host").and_then(|v| v.to_str().ok())
                    != Some(authority.as_str())
            {
                return deny(&state, "proxy authority mismatch", StatusCode::FORBIDDEN).await;
            }
            if request.headers().contains_key("authorization")
                || request.headers().contains_key("x-api-key")
                || request
                    .headers()
                    .iter()
                    .any(|(_, v)| v.as_bytes().windows(14).any(|w| w == b"placeholder://"))
            {
                return deny(
                    &state,
                    "credentials forbidden on proxy",
                    StatusCode::FORBIDDEN,
                )
                .await;
            }
            if state
                .config
                .compiled
                .policy()
                .model
                .as_ref()
                .is_some_and(|m| m.host == host)
            {
                return deny(
                    &state,
                    "model destination requires broker",
                    StatusCode::FORBIDDEN,
                )
                .await;
            }
            let Some(rule) = state.config.compiled.endpoint(&host, port) else {
                return deny(&state, "proxy destination denied", StatusCode::FORBIDDEN).await;
            };
            if !safe_path(uri.path())
                || (!rule.allowed_methods.is_empty()
                    && !rule
                        .allowed_methods
                        .iter()
                        .any(|m| m == request.method().as_str()))
                || (!rule.allowed_paths.is_empty()
                    && !path_allowed(uri.path(), &rule.allowed_paths))
            {
                return deny(&state, "proxy method or path denied", StatusCode::FORBIDDEN).await;
            }
            (
                host,
                port,
                scheme.to_owned(),
                uri.path().to_owned(),
                Category::Network,
            )
        };
    if scheme != "https"
        && state
            .config
            .compiled
            .boundary()
            .test_addresses(&host, port)
            .is_empty()
    {
        return deny(
            &state,
            "plain HTTP requires operator test mapping",
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    let max = state.config.compiled.policy().limits.max_request_bytes;
    if request.headers().get("content-length").is_some_and(|v| {
        v.to_str()
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .is_none_or(|len| len > max)
    }) {
        return deny(
            &state,
            "request body too large",
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
    }
    let addresses = match state.resolve(&host, port).await {
        Ok(a) => a,
        Err(_) => {
            return deny(
                &state,
                "destination resolution denied",
                StatusCode::FORBIDDEN,
            )
            .await;
        }
    };
    if scheme != "https"
        && !addresses.iter().all(|address| {
            state
                .config
                .compiled
                .allows_plain_http_upstream(&host, port, address.ip())
        })
    {
        return deny(
            &state,
            "plain HTTP destination approval mismatch",
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    let client = match reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&host, &addresses)
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(IDLE)
        .timeout(LIFETIME)
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return deny(
                &state,
                "upstream client unavailable",
                StatusCode::BAD_GATEWAY,
            )
            .await;
        }
    };
    let mut url = format!("{scheme}://{host}:{port}{path}");
    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }
    let audit = Arc::new(AuditMutex::new(Audit {
        state: state.clone(),
        category,
        destination: format!("{host}:{port}"),
        start: Instant::now(),
        out: 0,
        incoming: 0,
        allowed: false,
        reason: "request cancelled",
        status: 0,
    }));
    let body = std::mem::replace(request.body_mut(), Body::empty()).into_data_stream();
    let incoming = Upload {
        stream: Box::pin(body),
        state: state.clone(),
        audit: audit.clone(),
        count: 0,
        cancel: state.stop.subscribe(),
        deadline: tokio::time::Instant::now() + LIFETIME,
    };
    let upload = stream::try_unfold(incoming, |mut upload| async move {
        let item = tokio::select! { _ = upload.cancel.changed() => return Err(std::io::Error::other("gateway cancelled")), _ = tokio::time::sleep_until(upload.deadline) => return Err(std::io::Error::other("request lifetime exceeded")), item = tokio::time::timeout(IDLE, upload.stream.next()) => item.map_err(|_| std::io::Error::other("request timeout"))? };
        let Some(item) = item else {
            return Ok(None);
        };
        let chunk = item.map_err(|_| std::io::Error::other("request body failed"))?;
        upload.count = upload.count.saturating_add(chunk.len() as u64);
        upload.audit.lock().out = upload.count;
        upload.state.debit(true, chunk.len() as u64).map_err(|_| {
            upload.audit.lock().reason = "outbound byte budget exhausted";
            std::io::Error::other("request budget exceeded")
        })?;
        if upload.count
            > upload
                .state
                .config
                .compiled
                .policy()
                .limits
                .max_request_bytes
            || !upload.state.active()
        {
            upload.audit.lock().reason = "request body limit exceeded or gateway cut";
            return Err(std::io::Error::other("request budget exceeded"));
        }
        Ok(Some((chunk, upload)))
    });
    if state
        .record(state.measured_event(
            category,
            Decision::Allow,
            "bound upstream request",
            Some(format!("{host}:{port}")),
            0,
            0,
            Duration::ZERO,
        ))
        .await
        .is_err()
    {
        return response(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    let mut cancel = state.stop.subscribe();
    let upstream = tokio::select! { _ = cancel.changed() => return response(StatusCode::SERVICE_UNAVAILABLE, "gateway cancelled"), result = client.request(request.method().clone(), url).headers(headers).body(reqwest::Body::wrap_stream(upload)).send() => result };
    let upstream = match upstream {
        Ok(r) => r,
        Err(_) => return response(StatusCode::BAD_GATEWAY, "upstream request failed"),
    };
    if upstream.status().is_redirection() {
        return deny(&state, "upstream redirect denied", StatusCode::BAD_GATEWAY).await;
    }
    if upstream
        .content_length()
        .is_some_and(|n| n > state.config.compiled.policy().limits.max_response_bytes)
    {
        return deny(&state, "response body too large", StatusCode::BAD_GATEWAY).await;
    }
    let status = upstream.status();
    audit.lock().status = status.as_u16();
    let mut output_headers = sanitized(upstream.headers());
    output_headers.remove("set-cookie");
    let download = Download {
        stream: Box::pin(upstream.bytes_stream()),
        state: state.clone(),
        audit,
        _permit: permit,
        count: 0,
        pending: Bytes::new(),
        cancel: state.stop.subscribe(),
        deadline: tokio::time::Instant::now() + LIFETIME,
    };
    let stream = stream::try_unfold(download, |mut download| async move {
        if download.pending.is_empty() {
            let item = tokio::select! { _ = download.cancel.changed() => return Err(std::io::Error::other("gateway cancelled")), _ = tokio::time::sleep_until(download.deadline) => return Err(std::io::Error::other("response lifetime exceeded")), item = tokio::time::timeout(IDLE, download.stream.next()) => item.map_err(|_| std::io::Error::other("response timeout"))? };
            let Some(item) = item else {
                let mut audit = download.audit.lock();
                audit.allowed = true;
                audit.reason = "upstream response complete";
                drop(audit);
                return Ok(None);
            };
            download.pending =
                item.map_err(|_| std::io::Error::other("upstream response failed"))?;
            download.count = download.count.saturating_add(download.pending.len() as u64);
            download.audit.lock().incoming = download.count;
            download
                .state
                .debit(false, download.pending.len() as u64)
                .map_err(|_| {
                    download.audit.lock().reason = "inbound byte budget exhausted";
                    std::io::Error::other("response budget exceeded")
                })?;
            if download.count
                > download
                    .state
                    .config
                    .compiled
                    .policy()
                    .limits
                    .max_response_bytes
                || !download.state.active()
            {
                download.audit.lock().reason = "response body limit exceeded or gateway cut";
                return Err(std::io::Error::other("response budget exceeded"));
            }
        }
        let size = CHUNK.min(download.pending.len());
        let chunk = download.pending.split_to(size);
        Ok(Some((chunk, download)))
    });
    let mut result = Response::new(Body::from_stream(stream));
    *result.status_mut() = status;
    *result.headers_mut() = output_headers;
    result
}
struct Audit {
    state: Arc<Runtime>,
    category: Category,
    destination: String,
    start: Instant,
    out: u64,
    incoming: u64,
    allowed: bool,
    reason: &'static str,
    status: u16,
}
impl Drop for Audit {
    fn drop(&mut self) {
        let event = self.state.measured_event(
            self.category,
            if self.allowed {
                Decision::Allow
            } else {
                Decision::Deny
            },
            &format!("{}; status={}", self.reason, self.status),
            Some(self.destination.clone()),
            self.out,
            self.incoming,
            self.start.elapsed(),
        );
        if self
            .state
            .audit_tx
            .try_send(AuditCommand::Record(event))
            .is_err()
        {
            self.state.terminal_failure.store(true, Ordering::Release);
            self.state.cut.store(true, Ordering::Release);
            self.state.stop.send_modify(|n| {
                if *n != u64::MAX {
                    *n = n.wrapping_add(1);
                }
            });
        }
    }
}
struct Upload {
    stream: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = std::result::Result<Bytes, axum::Error>> + Send>,
    >,
    state: Arc<Runtime>,
    audit: Arc<AuditMutex<Audit>>,
    count: u64,
    cancel: watch::Receiver<u64>,
    deadline: tokio::time::Instant,
}
struct Download {
    stream: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Send>,
    >,
    state: Arc<Runtime>,
    audit: Arc<AuditMutex<Audit>>,
    _permit: OwnedSemaphorePermit,
    count: u64,
    pending: Bytes,
    cancel: watch::Receiver<u64>,
    deadline: tokio::time::Instant,
}

fn spawn_service<F>(state: Arc<Runtime>, future: F) -> JoinHandle<Result<()>>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        let result = future.await;
        if result.is_err() {
            state.terminal_failure.store(true, Ordering::Release);
            state.cut.store(true, Ordering::Release);
            state.stop.send_replace(u64::MAX);
        }
        result
    })
}
