//! Outside-guest, destination-bound HTTP broker and explicit allowlist proxy.
mod connect;
use crate::{
    GuardError, Result,
    compiler::CompiledPolicy,
    control::{BudgetAuthority, BudgetDebit, GuardFence, GuardIdentity},
    events::{Category, Decision, EventInput, EventSink, GuardEvent},
    l7,
    policy::L7Policy,
    proposals::AtomicPolicy,
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
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const IDLE: Duration = Duration::from_secs(30);
const LIFETIME: Duration = Duration::from_secs(900);
/// The whole shutdown: every service, every tunnel and the final record.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(15);

/// How long a release waits for its audit record to become durable before the
/// gateway latches a fault and stays cut.
///
/// Long enough for an fsync on a slow disk, short enough that a caller is not
/// left waiting on a worker that has stopped answering.
const RESTORE_CONFIRMATION: Duration = Duration::from_secs(10);
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
    /// Whether `candidate` is the stored secret for `name`, without handing the
    /// secret to the caller.
    ///
    /// Used by operator-side authority checks - a human approval, for one -
    /// which need to prove possession of operator credential material that
    /// never leaves this process. Comparison length is not hidden; its value
    /// is not.
    pub fn matches(&self, name: &str, candidate: &str) -> bool {
        let Some(expected) = self.secrets.get(name) else {
            return false;
        };
        let expected = expected.as_bytes();
        let candidate = candidate.as_bytes();
        if expected.len() != candidate.len() {
            return false;
        }
        let mut difference = 0u8;
        for (left, right) in expected.iter().zip(candidate.iter()) {
            difference |= left ^ right;
        }
        difference == 0
    }
    pub fn from_file(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| {
                GuardError::Io(std::io::Error::new(
                    error.kind(),
                    format!("credential store {}: {error}", path.display()),
                ))
            })?;
        let meta = file.metadata().map_err(|error| {
            GuardError::Io(std::io::Error::new(
                error.kind(),
                format!("credential store {} metadata: {error}", path.display()),
            ))
        })?;
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
    pub fence: GuardFence,
    pub compiled: CompiledPolicy,
    pub bind_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub broker_port: u16,
    pub dns_port: u16,
    pub credentials: Arc<CredentialStore>,
    pub events: Arc<dyn EventSink>,
    pub budget_authority: Arc<dyn BudgetAuthority>,
    pub watchdog_timeout: Duration,
}

struct Budget {
    minute: Instant,
    requests: u32,
    dns: u32,
    /// Bytes this process has admitted, against the policy ceilings.
    ///
    /// The durable reservation is the lifetime authority - it survives a
    /// restart - but it is not a substitute for the policy's own ceiling: an
    /// authority that permitted everything must not be able to widen what the
    /// operator wrote. Both are enforced, and each is reset only by its own
    /// scope (this one by the process, the durable one by nothing short of an
    /// operator).
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
        /// True only for the authorized path, which may reopen a latched cut.
        /// An ordinary release is refused outright rather than applied and then
        /// reported as a failure.
        authorized: bool,
        complete: Option<tokio::sync::oneshot::Sender<RestoreAck>>,
    },
}

/// Host-only attachment cut. It runs independently of the event journal.
#[async_trait::async_trait]
pub trait GatewayNetworkCut: Send + Sync {
    async fn cut_network(&self) -> Result<()>;
}

struct WatchdogState {
    deadline: tokio::time::Instant,
    activated: bool,
    /// A cut a containment decision holds: a canary firing, an operator hold.
    ///
    /// It is distinct from a dead-man cut because the watchdog did nothing
    /// wrong, and distinct from an operator cut because it is not the operator's
    /// to undo. A heartbeat must never clear it: the containment is the point,
    /// and the release that ends it is a human one.
    held: Option<&'static str>,
    /// A cut is in force whose delivery to the kernel and the journal is still
    /// owed. Every cut sets this, whoever asked for it.
    pending: bool,
    /// The watchdog is silent past its deadline, or the gateway has a terminal
    /// fault. This is the latch an ordinary release cannot clear, and it is
    /// distinct from an operator's own cut: holding a machine is a decision an
    /// operator can undo, while losing sight of the watcher is not something the
    /// operator's release answers.
    deadman: bool,
}
pub(crate) struct Runtime {
    pub(crate) config: GatewayConfig,
    /// The policy in force. Every decision reads through this cell, so an
    /// approved proposal takes effect without a restart and without a reader
    /// ever seeing a policy that is half of two.
    policy: Arc<AtomicPolicy>,
    pub(crate) broker: SocketAddr,
    identity: std::sync::RwLock<GuardIdentity>,
    fence: std::sync::RwLock<GuardFence>,
    cut: AtomicBool,
    terminal_failure: AtomicBool,
    pub(crate) stop: watch::Sender<u64>,
    budget: Mutex<Budget>,
    /// The canary monitor, when the sandbox configures one.
    canary: parking_lot::Mutex<Option<std::sync::Arc<crate::canaries::CanaryMonitor>>>,
    transitions: Mutex<()>,
    requests: Arc<Semaphore>,
    pub(crate) connections: Arc<Semaphore>,
    audit_tx: mpsc::Sender<AuditCommand>,
    tunnels: Mutex<Vec<JoinHandle<()>>>,
    watchdog: AuditMutex<WatchdogState>,
    watchdog_changed: tokio::sync::Notify,
    network_cut: AuditMutex<Option<Arc<dyn GatewayNetworkCut>>>,
}
impl Runtime {
    /// The policy in force right now.
    pub(crate) fn compiled(&self) -> Arc<CompiledPolicy> {
        self.policy.compiled()
    }

    /// The enforcement identity in force right now.
    ///
    /// A poisoned lock yields an identity nothing can match, so a reader that
    /// cannot learn who it is talking to fails closed instead of guessing.
    pub(crate) fn identity(&self) -> GuardIdentity {
        self.identity
            .read()
            .map(|identity| identity.clone())
            .unwrap_or(GuardIdentity {
                sandbox_id: Uuid::nil(),
                tenant_id: Uuid::nil(),
                policy_hash: String::new(),
            })
    }
    /// Names the enforcement generation installed by an approved proposal.
    ///
    /// Ownership is fixed for the life of the attachment: only the policy hash
    /// moves, only to a hash the live policy cell already reports, and only
    /// from the code path that installs policies. A caller that cannot install
    /// a policy cannot rebind this identity, so the watchdog binding stays as
    /// tight as it was before the first approval.
    pub(crate) fn adopt_policy(&self, policy_hash: &str) -> Result<()> {
        if self.policy.policy_hash() != policy_hash {
            return Err(GuardError::Unavailable(
                "refusing to name a policy that is not in force".into(),
            ));
        }
        let mut identity = self
            .identity
            .write()
            .map_err(|_| GuardError::Unavailable("gateway identity is poisoned".into()))?;
        if identity.policy_hash != policy_hash {
            identity.policy_hash = policy_hash.to_owned();
        }
        Ok(())
    }

    /// The layer 7 rules in force, if the attachment has any.
    pub(crate) fn l7(&self) -> Option<L7Policy> {
        self.policy.l7()
    }

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
            policy_hash: self.compiled().policy_hash().to_owned(),
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
    /// The canary monitor, when the attachment has one.
    pub(crate) fn canaries(&self) -> Option<std::sync::Arc<crate::canaries::CanaryMonitor>> {
        self.canary.lock().clone()
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
                authorized,
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
                    let mut watchdog = self.watchdog.lock();
                    if watchdog.deadman && !authorized {
                        return Err(GuardError::Denied(
                            "watchdog is not reporting; authorized release required".into(),
                        ));
                    }
                    if watchdog.held.is_some() && !authorized {
                        return Err(GuardError::Denied(
                            "the attachment is held cut; authorized release required".into(),
                        ));
                    }
                    watchdog.deadline = tokio::time::Instant::now() + self.config.watchdog_timeout;
                    watchdog.activated = true;
                    watchdog.deadman = false;
                    watchdog.held = None;
                    watchdog.pending = false;
                    self.cut.store(false, Ordering::Release);
                    self.watchdog_changed.notify_one();
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
            self.compiled().policy().limits.dns_queries_per_minute
        } else {
            self.compiled().policy().limits.requests_per_minute
        };
        let value = if dns { &mut b.dns } else { &mut b.requests };
        if *value >= cap {
            return Err(GuardError::Denied("rate budget exhausted".into()));
        }
        *value += 1;
        Ok(())
    }
    pub(crate) async fn reserve(&self, debit: BudgetDebit) -> Result<()> {
        if !self.active() {
            return Err(GuardError::Denied("gateway cut".into()));
        }
        let mut cancel = self.stop.subscribe();
        let identity = self.identity();
        tokio::select! {
            biased;
            _ = cancel.changed() => Err(GuardError::Denied("gateway cut".into())),
            result = self.config.budget_authority.reserve(&identity, *self.fence.read().map_err(|_| GuardError::Unavailable("gateway ownership fence is poisoned".into()))?, debit) => {
                result?;
                if !self.active() {
                    return Err(GuardError::Denied("gateway cut".into()));
                }
                Ok(())
            }
        }
    }
    pub(crate) async fn debit(&self, outgoing: bool, amount: u64) -> Result<()> {
        let cap = if outgoing {
            self.compiled().policy().limits.bytes_out
        } else {
            self.compiled().policy().limits.bytes_in
        };
        {
            let mut b = self
                .budget
                .lock()
                .map_err(|_| GuardError::Unavailable("budget unavailable".into()))?;
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
        }
        self.reserve(BudgetDebit {
            bytes_out: u64::from(outgoing) * amount,
            bytes_in: u64::from(!outgoing) * amount,
            ..Default::default()
        })
        .await
    }

    fn latch_cut(&self, deadman: bool) -> Result<bool> {
        // Even a poisoned transition lock may not prevent the immediate cut.
        let fence = self.transitions.lock();
        let mut watchdog = self.watchdog.lock();
        let first = !watchdog.pending;
        watchdog.pending = true;
        watchdog.deadman |= deadman;
        self.cut.store(true, Ordering::Release);
        if first {
            self.stop.send_modify(|n| {
                if *n != u64::MAX {
                    *n = n.wrapping_add(1);
                }
            });
        }
        if first {
            self.watchdog_changed.notify_one();
        }
        if fence.is_err() {
            self.terminal_failure.store(true, Ordering::Release);
            return Err(GuardError::Unavailable(
                "gateway transition state is poisoned".into(),
            ));
        }
        Ok(first)
    }
    pub(crate) async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let compiled = self.compiled();
        let test_addresses = compiled.boundary().test_addresses(host, port);
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
            self.compiled().check_destination(host, addr.ip())?;
        }
        Ok(addresses)
    }

    fn queue_transition(&self, decision: Decision, reason: &str) -> Result<()> {
        self.audit_tx
            .try_send(AuditCommand::Record(self.measured_event(
                Category::Lifecycle,
                decision,
                reason,
                None,
                0,
                0,
                Duration::ZERO,
            )))
            .map_err(|_| {
                self.terminal_failure.store(true, Ordering::Release);
                self.cut.store(true, Ordering::Release);
                GuardError::Unavailable("guard audit queue full".into())
            })
    }
}

pub struct GuardGateway {
    state: Arc<Runtime>,
    /// Named service tasks, drained by `shutdown`.
    tasks: Vec<(&'static str, JoinHandle<Result<()>>)>,
    audit_task: Option<JoinHandle<Result<()>>>,
    audit_stop: watch::Sender<bool>,
    dns: SocketAddr,
}

/// Read-only attachment state for host cut callbacks; does not own listener tasks.
#[derive(Clone)]
pub struct GatewayControl {
    state: Arc<Runtime>,
}

impl GatewayControl {
    pub fn network_cut(&self) -> bool {
        !self.state.active()
    }
    pub fn cut(&self) -> Result<()> {
        self.state.latch_cut(false).map(|_| ())
    }

    /// Holds the attachment cut until an authorized release.
    ///
    /// A quarantine is a containment decision, not a liveness event: the cut it
    /// makes has to outlive the watchdog that happened to be reporting, because
    /// the release that ends it is an operator's. [`Self::cut`] is the watchdog
    /// dead-man's ordinary cut and the next heartbeat legitimately reopens it.
    pub fn hold_cut(&self, reason: &'static str) -> Result<()> {
        let first = self.state.latch_cut(false)?;
        self.state.watchdog.lock().held = Some(reason);
        if first {
            self.state
                .queue_transition(Decision::Cut, "guard attachment held cut")?;
        }
        Ok(())
    }
    pub fn identity(&self) -> GuardIdentity {
        self.state.identity()
    }

    /// The hash of the policy in force, which changes when an approved
    /// proposal is applied and not before.
    pub fn policy_hash(&self) -> String {
        self.state.policy.policy_hash()
    }
    /// The live policy cell, so a control plane can hand the same instance to
    /// a [`crate::proposals::ProposalStore`] and have an approved proposal take
    /// effect in this gateway.
    pub fn policy(&self) -> Arc<AtomicPolicy> {
        Arc::clone(&self.state.policy)
    }
    /// The canary monitor for this attachment, if one is configured.
    pub fn canaries(&self) -> Option<std::sync::Arc<crate::canaries::CanaryMonitor>> {
        self.state.canary.lock().clone()
    }

    /// Attaches the canary monitor. Only the attachment's owner calls this.
    pub fn set_canaries(&self, monitor: crate::canaries::CanaryMonitor) {
        *self.state.canary.lock() = Some(std::sync::Arc::new(monitor));
    }

    /// Appends one authoritative lifecycle record through the shared journal.
    pub async fn append(&self, event: EventInput) -> Result<GuardEvent> {
        match tokio::time::timeout(
            Duration::from_secs(5),
            self.state.config.events.append(event),
        )
        .await
        {
            Ok(Ok(record)) => Ok(record),
            _ => {
                self.state.terminal_failure.store(true, Ordering::Release);
                self.state.cut.store(true, Ordering::Release);
                self.state.stop.send_modify(|n| {
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
}

/// How many times the DNS UDP bind is re-drawn after the TCP half wins the port
/// and something else takes it. Each attempt is a fresh kernel draw, so this
/// only has to outlast an ordinary scheduling race, not a busy host.
const DNS_UDP_BIND_ATTEMPTS: u32 = 8;
/// Binds a TCP listener, naming which one refused.
async fn labelled_bind(what: &str, bind: (Ipv4Addr, u16)) -> Result<TcpListener, GuardError> {
    TcpListener::bind(bind).await.map_err(|error| {
        GuardError::Io(std::io::Error::new(
            error.kind(),
            format!("{what} listener on {}:{}: {error}", bind.0, bind.1),
        ))
    })
}

/// Binds the DNS listener's TCP and UDP halves onto one port.
///
/// DNS is bound twice and the two binds cannot be atomic. With port 0 the
/// kernel picks the TCP port and hands it back, so the UDP bind of that same
/// port is a separate claim that can lose to anything else on the host taking
/// it in between — and when it does, `AddrInUse` fails the whole gateway at
/// startup even though nothing is actually misconfigured. The retry drops the
/// TCP listener first, so each attempt is a fresh draw rather than a collision
/// with our own.
///
/// The binds are parameters so the collision can be produced on demand rather
/// than waited for: it depends on what else on the host happens to be doing.
pub(crate) async fn bind_dns_pair<T, U, TFut, UFut>(
    bind: (Ipv4Addr, u16),
    tcp_bind: impl Fn((Ipv4Addr, u16)) -> TFut,
    udp_bind: impl Fn(SocketAddr) -> UFut,
) -> Result<(T, U, SocketAddr), GuardError>
where
    TFut: Future<Output = std::io::Result<T>>,
    UFut: Future<Output = std::io::Result<U>>,
    T: BoundSocket,
{
    let mut attempts_left = DNS_UDP_BIND_ATTEMPTS;
    loop {
        let tcp = tcp_bind(bind).await.map_err(|error| {
            GuardError::Io(std::io::Error::new(
                error.kind(),
                format!("DNS over TCP listener on {}:{}: {error}", bind.0, bind.1),
            ))
        })?;
        let addr = tcp.local_addr().map_err(|e| {
            GuardError::Io(std::io::Error::other(format!("DNS listener address: {e}")))
        })?;
        match udp_bind(addr).await {
            Ok(udp) => return Ok((tcp, udp, addr)),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && attempts_left > 1 => {
                // `tcp` drops here, releasing the port before the next draw.
                attempts_left -= 1;
            }
            Err(e) => {
                return Err(GuardError::Io(std::io::Error::new(
                    e.kind(),
                    format!("DNS over UDP listener on {addr}: {e}"),
                )));
            }
        }
    }
}

/// The one thing `bind_dns_pair` needs from a bound TCP listener.
pub(crate) trait BoundSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

impl BoundSocket for TcpListener {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        TcpListener::local_addr(self)
    }
}

impl GuardGateway {
    pub async fn start(config: GatewayConfig) -> Result<Self> {
        Self::start_with_l7(config, None).await
    }

    /// The canary monitor for this attachment, if one is configured.
    ///
    /// Trusted host code observes file reads through this rather than asking
    /// the guest what it read: the guest's answer is exactly the thing under
    /// suspicion.
    pub fn canaries(&self) -> Option<std::sync::Arc<crate::canaries::CanaryMonitor>> {
        self.state.canary.lock().clone()
    }

    /// Names the enforcement generation an approved proposal installed.
    ///
    /// This is the one place a live gateway's identity moves, and it moves
    /// only to a hash the live policy cell is already enforcing.
    pub fn adopt_policy(&self, policy_hash: &str) -> Result<()> {
        self.state.adopt_policy(policy_hash)
    }

    /// Starts a gateway that also governs the traffic it can see.
    ///
    /// The layer 7 policy is an argument rather than a configuration field so
    /// that a deployment which does not use one is unchanged: destination
    /// policy alone remains the default. An L7 policy that asks for TLS
    /// interception without the operator's acknowledgement is refused here
    /// rather than downgraded, and rules that could not be enforced as written
    /// never reach a socket.
    pub async fn start_with_l7(config: GatewayConfig, l7: Option<L7Policy>) -> Result<Self> {
        config.compiled.verify()?;
        if let Some(policy) = &l7 {
            crate::l7::validate(policy)?;
        }
        let policy = Arc::new(AtomicPolicy::new(config.compiled.clone(), l7)?);
        if !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&config.watchdog_timeout) {
            return Err(GuardError::Policy(
                "watchdog timeout must be between 1 and 60 seconds".into(),
            ));
        }
        if let Some(model) = &config.compiled.policy().model
            && !config.credentials.secrets.contains_key(&model.credential)
        {
            return Err(GuardError::Unavailable(
                "bound model credential unavailable".into(),
            ));
        }
        // Each bind names itself. "Guard I/O: Permission denied" from a gateway
        // that opens four sockets says nothing about which one, and the four
        // have genuinely different causes: the broker is a high port, DNS is a
        // privileged one, and all of them are bound to an address that exists
        // only once the sandbox's TAP is up.
        let broker = labelled_bind("broker", (config.bind_ip, config.broker_port)).await?;
        let broker_addr = broker.local_addr().map_err(|e| {
            GuardError::Io(std::io::Error::other(format!(
                "broker listener address: {e}"
            )))
        })?;
        let (dns_tcp, dns_udp, dns_addr) = bind_dns_pair(
            (config.bind_ip, config.dns_port),
            TcpListener::bind,
            UdpSocket::bind,
        )
        .await?;
        let (stop, _) = watch::channel(0);
        let (audit_tx, mut audit_rx) = mpsc::channel(128);
        let (audit_stop, mut audit_shutdown) = watch::channel(false);
        let request_limit = config.compiled.policy().limits.max_concurrent_requests as usize;
        let state = Arc::new(Runtime {
            policy,
            identity: std::sync::RwLock::new(GuardIdentity {
                sandbox_id: config.sandbox_id,
                tenant_id: config.tenant_id,
                policy_hash: config.compiled.policy_hash().to_owned(),
            }),
            fence: std::sync::RwLock::new(config.fence),
            watchdog: AuditMutex::new(WatchdogState {
                deadline: tokio::time::Instant::now() + config.watchdog_timeout,
                activated: false,
                pending: false,
                deadman: false,
                held: None,
            }),
            watchdog_changed: tokio::sync::Notify::new(),
            network_cut: AuditMutex::new(None),
            config,
            broker: broker_addr,
            cut: AtomicBool::new(true),
            terminal_failure: AtomicBool::new(false),
            stop,
            canary: parking_lot::Mutex::new(None),
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
        // Named, because a shutdown that cannot finish has to say which
        // service it was waiting for rather than hanging a build.
        let tasks: Vec<(&'static str, JoinHandle<Result<()>>)> = vec![
            ("watchdog", tokio::spawn(run_watchdog(state.clone()))),
            (
                "broker",
                spawn_service(state.clone(), serve_broker(broker, state.clone())),
            ),
            (
                "dns-udp",
                spawn_service(state.clone(), crate::dns::serve_udp(dns_udp, state.clone())),
            ),
            (
                "dns-tcp",
                spawn_service(state.clone(), crate::dns::serve_tcp(dns_tcp, state.clone())),
            ),
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
    pub fn identity(&self) -> GuardIdentity {
        self.state.identity()
    }

    pub fn control(&self) -> GatewayControl {
        GatewayControl {
            state: self.state.clone(),
        }
    }

    /// Registers the host attachment before bringing its link up.
    pub fn set_network_cut_handler(&self, handler: Arc<dyn GatewayNetworkCut>) {
        *self.state.network_cut.lock() = Some(handler);
        self.state.watchdog_changed.notify_one();
    }

    pub fn network_cut(&self) -> bool {
        !self.state.active()
    }

    /// Host-authenticated first activation is not a release of a latched cut.
    /// Returns true only for the first activation, when the manager must install filters.
    pub fn heartbeat(&self, identity: &GuardIdentity) -> Result<bool> {
        // An approved proposal installs a new generation before the gateway is
        // told about it. A watchdog still reporting under the superseded one
        // is reporting on rules that are no longer in force, so the check is
        // against the policy actually being enforced, not only the last one
        // named.
        if identity.policy_hash != self.state.policy.policy_hash() {
            return Err(GuardError::Denied(
                "watchdog generation is not in force".into(),
            ));
        }
        if identity != &self.state.identity() {
            return Err(GuardError::Denied("watchdog identity mismatch".into()));
        }
        self.health()?;
        let fence =
            self.state.transitions.lock().map_err(|_| {
                GuardError::Unavailable("gateway transition state is poisoned".into())
            })?;
        let mut watchdog = self.state.watchdog.lock();
        if watchdog.deadman {
            return Err(GuardError::Denied(
                "watchdog is not reporting; authorized release required".into(),
            ));
        }
        if tokio::time::Instant::now() >= watchdog.deadline {
            drop(watchdog);
            drop(fence);
            let _ = self.state.latch_cut(true);
            return Err(GuardError::Denied("watchdog deadline expired".into()));
        }
        let first = !watchdog.activated;
        watchdog.activated = true;
        watchdog.deadline = tokio::time::Instant::now() + self.state.config.watchdog_timeout;
        // Liveness is what a heartbeat answers; the cut is not. A cut held by a
        // containment decision - a canary, a quarantine - survives reporting,
        // because the release that ends it is a human one and clearing it here
        // would hand the machine back to a party that only ever proved it was
        // still there.
        if watchdog.held.is_none() {
            self.state.cut.store(false, Ordering::Release);
        }
        drop(watchdog);
        drop(fence);
        self.state.watchdog_changed.notify_one();
        if first {
            self.state.queue_transition(
                Decision::Allow,
                "gateway activated by authenticated watchdog",
            )?;
        }
        Ok(first)
    }

    /// Advances the reservation fence after an authorized lease renewal.
    pub fn set_fence(&self, fence: GuardFence) -> Result<()> {
        let mut bound =
            self.state.fence.write().map_err(|_| {
                GuardError::Unavailable("gateway ownership fence is poisoned".into())
            })?;
        if bound.lease_id == fence.lease_id && fence.generation < bound.generation {
            return Ok(());
        }
        *bound = fence;
        Ok(())
    }
    /// Holds the attachment cut until an authorized release.
    ///
    /// Used by containment decisions the watchdog did not make: a canary
    /// firing, or an operator holding a machine. Unlike an ordinary cut this is
    /// not something the next heartbeat can undo.
    pub fn hold_cut(&self, reason: &'static str) -> Result<()> {
        self.control().hold_cut(reason)
    }

    pub fn cut(&self) -> Result<()> {
        let first = self.state.latch_cut(false)?;
        if !first {
            return Ok(());
        }
        self.state
            .queue_transition(Decision::Cut, "gateway network cut")
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

    /// Releases the network, and returns only once the release is real.
    ///
    /// A release is not a flag write: the audit record has to be durable before
    /// traffic is permitted again, so this awaits the audit worker's
    /// confirmation rather than returning once the request is merely queued.
    /// Returning early would let a caller proceed while the guest was still cut,
    /// and the next request would fail for reasons that look like a policy
    /// problem rather than a release that had not landed yet.
    ///
    /// It is `async` for that reason, not for convenience: a synchronous
    /// function cannot wait on a durable write without blocking a runtime
    /// thread. The wait is bounded, and a release that is not confirmed leaves
    /// the gateway cut rather than assuming the best.
    /// The ordinary release. It cannot reopen a cut the dead-man switch
    /// latched: the refusal is written to the journal rather than answered in
    /// silence, because an operator who sees a denied release should find out
    /// afterwards that the machine is still held.
    pub async fn restore(&self) -> Result<()> {
        self.release(false).await
    }

    /// The authorized release, reserved for a caller that has already proved
    /// the human decision behind it. It clears the latch, but traffic still
    /// waits for the watchdog's next authenticated heartbeat: an operator
    /// releasing a machine is not a substitute for the thing that watches it.
    pub async fn authorized_release(&self) -> Result<()> {
        self.release(true).await
    }

    async fn release(&self, authorized: bool) -> Result<()> {
        let (complete, receipt) = tokio::sync::oneshot::channel();
        self.enqueue_restore(Some(complete), authorized)?;
        match tokio::time::timeout(RESTORE_CONFIRMATION, receipt).await {
            Ok(Ok(RestoreAck::Applied)) => Ok(()),
            Ok(Ok(RestoreAck::Fenced)) => Err(GuardError::Denied(
                "gateway release fenced out by a later cut".into(),
            )),
            Ok(Ok(RestoreAck::Failed)) | Ok(Err(_)) => Err(GuardError::Unavailable(
                "gateway release was not applied".into(),
            )),
            Err(_) => {
                // The worker never answered, so the release is not knowable. The
                // gateway stays cut: a release whose evidence cannot be
                // confirmed is precisely the case the latched fault exists for.
                self.state.terminal_failure.store(true, Ordering::Release);
                Err(GuardError::Unavailable(
                    "gateway release was not confirmed; the gateway remains cut".into(),
                ))
            }
        }
    }

    fn enqueue_restore(
        &self,
        complete: Option<tokio::sync::oneshot::Sender<RestoreAck>>,
        authorized: bool,
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
                authorized,
                complete,
            })
            .map_err(|_| {
                self.state.terminal_failure.store(true, Ordering::Release);
                self.state.cut.store(true, Ordering::Release);
                GuardError::Unavailable("guard audit queue full".into())
            })
    }
    /// Stops the gateway and waits for its services, bounded.
    ///
    /// The whole sequence has a deadline: an operator shutting a gateway down
    /// learns more from a named refusal than from a build that never returns.
    pub async fn shutdown(self) -> Result<()> {
        match tokio::time::timeout(SHUTDOWN_DEADLINE, self.shutdown_inner()).await {
            Ok(result) => result,
            Err(_) => Err(GuardError::Unavailable(
                "gateway did not shut down within its deadline".into(),
            )),
        }
    }

    async fn shutdown_inner(mut self) -> Result<()> {
        self.state.close();
        let mut failure = None;
        // Bounded and aborting: a service that will not stop is aborted and
        // named, because a shutdown that never returns is a defect in its own
        // right - and an operator waiting on it learns nothing from a hang.
        for (name, mut task) in self.tasks.drain(..) {
            let settled = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
            match settled {
                Ok(Ok(Ok(()))) => (),
                Ok(Ok(Err(error))) => failure = Some(error),
                Ok(Err(_)) => {
                    failure = Some(GuardError::Unavailable(format!(
                        "gateway {name} task failed"
                    )));
                }
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    failure = Some(GuardError::Unavailable(format!(
                        "gateway {name} did not stop within its deadline"
                    )));
                }
            }
        }
        let tunnels = self
            .state
            .tunnels
            .lock()
            .map(|mut tasks| std::mem::take(&mut *tasks))
            .unwrap_or_default();
        for mut task in tunnels {
            if tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
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
            task.1.abort();
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
                if !state.active() {
                    // A reset connection is a refusal a client cannot read. The
                    // gateway that is cut, or that has never seen a watchdog,
                    // still answers: 503 says why, and it is the only answer a
                    // guest's proxy can act on.
                    refuse(socket).await;
                    continue;
                }
                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let cancel = state.stop.subscribe();
                    let service_state = state.clone();
                    let service = service_fn(move |request: Request<Incoming>| {
                        let state = service_state.clone();
                        async move { Ok::<_, std::convert::Infallible>(handle(request.map(Body::new), state).await) }
                    });
                    let mut http = hyper::server::conn::http1::Builder::new();
                    http.max_buf_size(HEADER_LIMIT).keep_alive(false);
                    let connection = http.serve_connection(TokioIo::new(socket), service).with_upgrades();
                    // A cut cancels the request, not the connection: the
                    // handler's own select answers 503, or fails the body it
                    // was streaming. Killing the connection here instead would
                    // turn both into a reset the client cannot interpret.
                    tokio::select! { _ = tokio::time::sleep(LIFETIME) => {}, _ = connection => {} }
                    drop(cancel);
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Answers one refused connection with a complete, minimal HTTP response.
async fn refuse(mut socket: tokio::net::TcpStream) {
    let body = b"gateway cut";
    let head = format!(
        "HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = socket.write_all(head.as_bytes()).await;
        let _ = socket.write_all(body).await;
        let _ = socket.flush().await;
    })
    .await;
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
/// One bounded-target definition, shared with the layer 7 rules so a path
/// accepted here is the same path those rules compare against.
fn safe_path(path: &str) -> bool {
    l7::safe_path(path)
}
/// Records and answers a layer 7 refusal.
///
/// The reason is the static text [`crate::l7`] produced: no request content,
/// method name, tool name or document reaches the journal from here.
async fn deny_l7(
    state: &Runtime,
    reason: &'static str,
    refusal: l7::Refusal,
    destination: Option<String>,
) -> Response<Body> {
    let status = match refusal {
        l7::Refusal::Forbidden => StatusCode::FORBIDDEN,
        l7::Refusal::Malformed => StatusCode::BAD_REQUEST,
        l7::Refusal::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
    };
    let _ = state
        .record(state.measured_event(
            Category::Network,
            Decision::Deny,
            reason,
            destination,
            0,
            0,
            Duration::ZERO,
        ))
        .await;
    response(status, reason)
}
/// Whether the policy has anything to say about a request body.
///
/// A `denied_tools` or `allowed_tools` list is a rule about the body even when
/// no method is allowed, and both are independent of the method list: an
/// operator who writes `allowed_methods: []` with a deny list has still named
/// a tool that must not be called. Keying only on `allowed_methods` meant such
/// a policy never buffered the body, so the check that consumes a deny list was
/// unreachable and the explicit deny was silently unenforced - the fail-open
/// direction, from a policy that validated cleanly.
fn governs_bodies(policy: &L7Policy) -> bool {
    !policy.mcp.allowed_methods.is_empty()
        || !policy.mcp.allowed_tools.is_empty()
        || !policy.mcp.denied_tools.is_empty()
        || policy.graphql.allow_mutations
        || !policy.graphql.operations.is_empty()
        || !policy.graphql.root_fields.is_empty()
}
/// Buffers a bounded request body so the body rules can read it.
///
/// A body whose length is not declared is refused rather than partially
/// inspected: the rules would then be applied to a prefix of what the upstream
/// actually receives.
async fn visible_body(
    request: &mut Request<Body>,
    limit: usize,
) -> std::result::Result<Option<Bytes>, (&'static str, l7::Refusal)> {
    let declared = match request.headers().get("content-length") {
        None => {
            return Err((
                "l7: request body length is not declared and cannot be inspected",
                l7::Refusal::Malformed,
            ));
        }
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or((
                "l7: request body length is not declared and cannot be inspected",
                l7::Refusal::Malformed,
            ))?,
    };
    if declared > limit {
        return Err((
            "l7: request body exceeds the inspection bound",
            l7::Refusal::TooLarge,
        ));
    }
    let buffered =
        axum::body::to_bytes(std::mem::replace(request.body_mut(), Body::empty()), limit)
            .await
            .map_err(|_| {
                (
                    "l7: request body could not be read for inspection",
                    l7::Refusal::Malformed,
                )
            })?;
    *request.body_mut() = Body::from(buffered.clone());
    Ok(Some(buffered))
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
    // Observe the credential the client actually presents, even when its route
    // or binding is otherwise invalid. A configured model name is not evidence
    // that the guest exercised a tripwire.
    if let Some(canary) = state.canaries() {
        for value in request.headers().values() {
            let Some(value) = value.to_str().ok() else {
                continue;
            };
            let value = value.strip_prefix("Bearer ").unwrap_or(value);
            if let Some(presented) = value.strip_prefix("placeholder://") {
                match canary.observe_credential(presented).await {
                    Ok(outcome) if outcome.trip.is_none() => {}
                    Ok(_) | Err(_) => {
                        return deny(
                            &state,
                            "presentation of a canary credential refused",
                            StatusCode::FORBIDDEN,
                        )
                        .await;
                    }
                }
            }
        }
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
            let broker = state.compiled();
            let Some(model) = &broker.policy().model else {
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
            let Some(binding) = broker.policy().credentials.iter().find(|b| {
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
                .compiled()
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
            let compiled = state.compiled();
            let Some(rule) = compiled.endpoint(&host, port) else {
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
            .compiled()
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
    let max = state.compiled().policy().limits.max_request_bytes;
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
    // Layer 7. The request line is visible on every proxy request, including an
    // absolute-form HTTPS one, so method and path are governed in both modes.
    // The body is governed only where Guard reads it in the clear: an HTTPS
    // request reaches the upstream inside TLS, and a rule applied to a body
    // Guard never saw would be a rule that was never enforced.
    if let Some(policy) = state.l7() {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let mut body = None;
        let method = request.method().clone();
        let may_carry_body =
            method == Method::POST || method == Method::PUT || method == Method::PATCH;
        if governs_bodies(&policy) && scheme == "http" && may_carry_body {
            match visible_body(&mut request, l7::MAX_INSPECTED_BODY_BYTES).await {
                Ok(buffered) => body = buffered,
                Err((reason, refusal)) => {
                    return deny_l7(&state, reason, refusal, Some(format!("{host}:{port}"))).await;
                }
            }
        }
        let verdict = l7::request_verdict(
            Some(&policy),
            &l7::VisibleRequest {
                host: &host,
                method: method.as_str(),
                path: &path,
                content_type,
                body: body.as_deref(),
            },
        );
        if let l7::Verdict::Deny {
            refusal, reason, ..
        } = verdict
        {
            return deny_l7(&state, reason, refusal, Some(format!("{host}:{port}"))).await;
        }
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
                .compiled()
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
    if state
        .reserve(BudgetDebit {
            model_requests: if matches!(category, Category::Model) {
                1
            } else {
                0
            },
            ..Default::default()
        })
        .await
        .is_err()
    {
        return deny(
            &state,
            "durable admission budget unavailable or exhausted",
            StatusCode::SERVICE_UNAVAILABLE,
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
        upload
            .state
            .debit(true, chunk.len() as u64)
            .await
            .map_err(|_| {
                upload.audit.lock().reason = "outbound byte budget exhausted";
                std::io::Error::other("request budget exceeded")
            })?;
        if upload.count > upload.state.compiled().policy().limits.max_request_bytes
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
        .is_some_and(|n| n > state.compiled().policy().limits.max_response_bytes)
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
            if download.count > download.state.compiled().policy().limits.max_response_bytes
                || !download.state.active()
            {
                download.audit.lock().reason = "response body limit exceeded or gateway cut";
                return Err(std::io::Error::other("response budget exceeded"));
            }
        }
        let size = CHUNK.min(download.pending.len());
        download
            .state
            .debit(false, size as u64)
            .await
            .map_err(|_| {
                download.audit.lock().reason = "inbound byte budget exhausted";
                std::io::Error::other("response budget exceeded")
            })?;
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

async fn run_watchdog(state: Arc<Runtime>) -> Result<()> {
    let mut stop = state.stop.subscribe();
    let mut delivered = None;
    // Keyed by the generation the cut happened under *and* by why it happened.
    // A dead-man latch that follows an ordinary cut leaves the generation
    // untouched - `latch_cut` only bumps it when the cut is new - but it is a
    // separate decision, and a journal that recorded only the ordinary one
    // cannot show that the watchdog was the thing that went wrong.
    let mut audited: Option<(u64, &'static str)> = None;
    // The deadline this loop has already cut for, and why it cut for it.
    // `pending` stays set after an ordinary cut is reclaimed by a heartbeat, and
    // that reclaim must not retire the deadline: the next silence still has to
    // cut. Recording the deadline stops the same deadline being cut twice, and
    // recording the reason keeps a watchdog cut from being filed as a host
    // fault, or the other way round.
    let mut cut_reason: Option<(tokio::time::Instant, &'static str)> = None;
    loop {
        if *stop.borrow() == u64::MAX {
            break;
        }
        let deadline = state.watchdog.lock().deadline;
        let armed = cut_reason.is_none_or(|(cut, _)| cut != deadline);
        if state.terminal_failure.load(Ordering::Acquire) {
            // A host fault cuts whatever the watchdog is doing.
            if armed {
                let _ = state.latch_cut(true);
                cut_reason = Some((deadline, "gateway terminal fault latched network cut"));
            }
        } else if armed && tokio::time::Instant::now() >= deadline {
            // Cancellation happens synchronously, before any attachment I/O or audit.
            let _ = state.latch_cut(true);
            cut_reason = Some((deadline, "watchdog deadline latched network cut"));
        }
        let pending = state.watchdog.lock().pending;
        let generation = *state.stop.borrow();
        if pending && delivered != Some(generation) {
            let handler = state.network_cut.lock().clone();
            if let Some(handler) = handler {
                if let Err(error) = handler.cut_network().await {
                    state.terminal_failure.store(true, Ordering::Release);
                    return Err(error);
                }
                delivered = Some(generation);
            }
        }
        // Whatever cut for *this* deadline is what the journal says. A cut the
        // loop did not make - an operator cut, a host fault elsewhere - keeps
        // the original wording.
        let reason = cut_reason.filter(|(cut, _)| *cut == deadline).map_or(
            "watchdog or host fault latched network cut",
            |(_, reason)| reason,
        );
        if pending && audited != Some((generation, reason)) {
            audited = Some((generation, reason));
            // A failed/full journal cannot gate the network cut.
            if state
                .audit_tx
                .try_send(AuditCommand::Record(state.measured_event(
                    Category::Lifecycle,
                    Decision::Cut,
                    reason,
                    None,
                    0,
                    0,
                    Duration::ZERO,
                )))
                .is_err()
            {
                state.terminal_failure.store(true, Ordering::Release);
            }
        }
        tokio::select! {
            _ = stop.changed() => {},
            _ = state.watchdog_changed.notified() => {},
            _ = tokio::time::sleep_until(deadline), if armed => {},
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A stand-in for the bound TCP listener, so the collision can be produced
    /// on demand. Waiting for the real one means waiting for whatever else on
    /// the host happens to be binding sockets at that instant.
    struct FakeTcp(SocketAddr);

    impl BoundSocket for FakeTcp {
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.0)
        }
    }

    fn taken() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::AddrInUse, "injected collision")
    }

    fn addr_for(draw: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_000 + draw)
    }

    /// The UDP half losing the port is a race with everything else on the host,
    /// and losing it failed gateway startup outright even though nothing was
    /// misconfigured. Losing it once has to be survivable.
    #[tokio::test]
    async fn a_dns_port_taken_between_the_two_binds_is_drawn_again() {
        let draws = Cell::new(0u16);
        let (_, udp, addr) = bind_dns_pair(
            (Ipv4Addr::LOCALHOST, 0),
            |_| {
                let draw = draws.get() + 1;
                draws.set(draw);
                async move { Ok(FakeTcp(addr_for(draw))) }
            },
            |addr| async move {
                if addr.port() == 30_001 {
                    Err(taken())
                } else {
                    Ok(addr.port())
                }
            },
        )
        .await
        .expect("one collision must not fail startup");

        // The first draw was stolen, so the pair must be on the second.
        assert_eq!(draws.get(), 2, "expected exactly one redraw");
        assert_eq!(udp, 30_002, "the halves must land on one port");
        assert_eq!(addr.port(), udp);
    }

    /// The retry is bounded: a port that is genuinely unavailable must still
    /// fail, rather than spinning forever at startup.
    #[tokio::test]
    async fn a_dns_port_that_is_never_free_still_refuses() {
        let draws = Cell::new(0u16);
        let result = bind_dns_pair(
            (Ipv4Addr::LOCALHOST, 0),
            |_| {
                let draw = draws.get() + 1;
                draws.set(draw);
                async move { Ok(FakeTcp(addr_for(draw))) }
            },
            |_addr| async { Err::<(), _>(taken()) },
        )
        .await;

        let error = match result {
            Ok(_) => panic!("an unavailable DNS UDP port must not succeed"),
            Err(e) => e,
        };
        assert!(
            matches!(error, GuardError::Io(ref e) if e.kind() == std::io::ErrorKind::AddrInUse),
            "an unavailable DNS UDP port returned {error:?} instead of AddrInUse"
        );
        assert_eq!(
            u32::from(draws.get()),
            DNS_UDP_BIND_ATTEMPTS,
            "the retry must be bounded"
        );
    }
}
