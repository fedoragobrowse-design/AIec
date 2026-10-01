//! Optional remote event delivery.
//!
//! The local journal is always the authoritative copy. Remote delivery is a
//! second, explicitly configured copy: it is ordered, bounded, retry-bounded,
//! and it never rewrites or rolls back the local chain. Guard does not require
//! any particular service here; [`HttpEventSink`] is one real implementation
//! against an operator's own HTTPS endpoint.
//!
//! Delivery integrity semantics, stated plainly:
//!
//! * Records leave in journal order, because they are enqueued while the
//!   journal lock is held.
//! * Each batch must be acknowledged by `accepted` plus the `head_hash` of the
//!   batch's last record. Anything else - a non-2xx status, an unparsable
//!   body, a wrong count, a wrong or malformed head hash, an oversized body - is
//!   a failure, and a failed batch is never recorded as delivered.
//! * Batches are retried up to a configured bound. A batch that exhausts it is
//!   counted in [`RemoteStatsSnapshot::undelivered_events`] and dropped: the
//!   documented loss boundary is the local journal plus the operator, not this
//!   worker.
//! * [`RemoteStatsSnapshot::last_acknowledged_hash`] is the anchor that makes
//!   removal of trailing local records detectable. Read it from somewhere the
//!   guest cannot reach.
//! * [`RemoteQueue::enqueue`] never fails. A record the queue refuses is
//!   counted in [`RemoteStatsSnapshot::unqueued_events`] instead, so a stalled
//!   remote can never make a durable local append look unrecorded.
//!
//! Memory is bounded everywhere: a fixed-capacity queue, a capped batch, a
//! capped acknowledgement body, and a request timeout. Nothing is logged except
//! counters and fixed refusal reasons; the token is held in a zeroizing
//! buffer, redacted from `Debug`, and is only ever sent as one header value.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use url::Url;
use zeroize::Zeroizing;

use super::GuardEvent;
use crate::{GuardError, Result};

/// Largest acknowledgement body accepted from a remote endpoint.
pub const MAX_ACK_BYTES: usize = 4096;
/// Largest endpoint URL accepted.
const MAX_ENDPOINT_BYTES: usize = 2048;
/// Largest bearer token or API key accepted.
const MAX_TOKEN_BYTES: usize = 4096;

/// A remote endpoint's acknowledgement of one delivered batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteAck {
    /// How many records the remote durably stored; must equal the batch size.
    pub accepted: usize,
    /// `current_hash` of the last record in the batch.
    pub head_hash: String,
    /// Endpoint-assigned request identifier, for operator correlation.
    pub request_id: Option<String>,
}

impl RemoteAck {
    /// The acknowledgement a correct remote must return for `batch`.
    pub fn for_batch(batch: &[GuardEvent]) -> Option<Self> {
        let last = batch.last()?;
        Some(Self {
            accepted: batch.len(),
            head_hash: last.current_hash.clone(),
            request_id: None,
        })
    }
}

/// A remote destination for Guard records.
///
/// Implementations must not claim durability they did not achieve: `Ok` means
/// the remote confirmed this exact batch, head hash included.
#[async_trait]
pub trait RemoteEventSink: Send + Sync {
    /// Delivers one contiguous, in-order batch.
    async fn deliver(&self, batch: &[GuardEvent]) -> Result<RemoteAck>;

    /// Secret-free description for operator output.
    fn describe(&self) -> String;
}

/// Configuration of the HTTPS event sink.
pub struct HttpEventSinkConfig {
    /// Absolute `https://` endpoint that accepts NDJSON batches.
    pub endpoint: String,
    /// Header the token is sent in; only `authorization` or `x-api-key`.
    pub header_name: String,
    /// Bearer token or API key. Never logged, never in `Debug`, zeroized on drop.
    pub token: Zeroizing<String>,
    /// Largest batch sent in one request.
    pub max_batch_events: usize,
    /// Whole-request deadline.
    pub request_timeout: Duration,
}

impl Default for HttpEventSinkConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            header_name: "authorization".to_string(),
            token: Zeroizing::new(String::new()),
            max_batch_events: 64,
            request_timeout: Duration::from_secs(10),
        }
    }
}

// A derived `Debug` would print the token.
impl std::fmt::Debug for HttpEventSinkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpEventSinkConfig")
            .field("endpoint", &self.endpoint)
            .field("header_name", &self.header_name)
            .field("token", &"<redacted>")
            .field("max_batch_events", &self.max_batch_events)
            .finish()
    }
}

/// [`RemoteEventSink`] over operator-configured HTTPS.
///
/// TLS certificate and hostname verification are left at their secure
/// defaults, proxies are disabled so that no environment variable can redirect
/// evidence, and redirects are refused so that a 302 cannot move a batch to an
/// unvalidated destination.
pub struct HttpEventSink {
    client: reqwest::Client,
    endpoint: Url,
    host: String,
    header_name: HeaderName,
    token: Zeroizing<Vec<u8>>,
    max_batch_events: usize,
}

impl HttpEventSink {
    /// Builds a sink against an `https://` endpoint.
    pub fn new(config: HttpEventSinkConfig) -> Result<Self> {
        Self::build(config, false)
    }

    /// Builds a sink against a plain-HTTP loopback endpoint.
    ///
    /// Only for a local mock or collector: the endpoint host must be a loopback
    /// IP literal, so this cannot be pointed at a remote plaintext service.
    pub fn new_insecure_loopback_for_tests(config: HttpEventSinkConfig) -> Result<Self> {
        Self::build(config, true)
    }

    fn build(config: HttpEventSinkConfig, allow_loopback_http: bool) -> Result<Self> {
        let header_name = validated_header_name(&config.header_name)?;
        let token = validated_token(&config.token)?;
        if config.max_batch_events == 0 || config.max_batch_events > 1024 {
            return Err(GuardError::Denied(format!(
                "remote event max_batch_events must be between 1 and 1024, got {}",
                config.max_batch_events
            )));
        }
        if config.request_timeout.is_zero() {
            return Err(GuardError::Denied(
                "remote event request_timeout must be greater than zero".to_string(),
            ));
        }
        let endpoint = validated_endpoint(&config.endpoint, allow_loopback_http)?;
        let host = endpoint
            .host_str()
            .ok_or_else(|| GuardError::Policy("remote event endpoint has no host".to_string()))?
            .to_string();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.request_timeout)
            .user_agent(concat!("aiec-guard-events/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| {
                GuardError::Unavailable(
                    "remote event HTTP client could not be configured".to_string(),
                )
            })?;
        Ok(Self {
            client,
            endpoint,
            host,
            header_name,
            token: Zeroizing::new(token),
            max_batch_events: config.max_batch_events,
        })
    }
}

#[async_trait]
impl RemoteEventSink for HttpEventSink {
    async fn deliver(&self, batch: &[GuardEvent]) -> Result<RemoteAck> {
        if batch.is_empty() || batch.len() > self.max_batch_events {
            return Err(GuardError::Denied(format!(
                "remote event batch size {} is outside the configured bound",
                batch.len()
            )));
        }
        // A batch that does not chain is a caller bug, not something to send.
        for pair in batch.windows(2) {
            if pair[0].current_hash != pair[1].previous_hash {
                return Err(GuardError::Integrity(
                    "refusing to deliver a batch whose records do not chain".to_string(),
                ));
            }
        }
        let mut body = Vec::new();
        for event in batch {
            let line = serde_json::to_vec(event)?;
            if line.len() + 1 > super::MAX_LINE_BYTES {
                return Err(GuardError::Denied(
                    "record exceeds the remote record bound".to_string(),
                ));
            }
            body.extend_from_slice(&line);
            body.push(b'\n');
        }
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/x-ndjson")
            .header(
                self.header_name.clone(),
                HeaderValue::from_bytes(&self.token).map_err(|_| {
                    GuardError::Denied("remote event token contains illegal bytes".to_string())
                })?,
            )
            .body(body)
            .send()
            .await
            .map_err(|err| transport_error(&self.host, &err))?;
        let status = response.status();
        if !status.is_success() {
            return Err(GuardError::Unavailable(format!(
                "remote event endpoint {} answered HTTP {}",
                self.host,
                status.as_u16()
            )));
        }
        let body = read_bounded(response, self.host.clone()).await?;
        parse_ack(&body, batch)
    }

    fn describe(&self) -> String {
        format!("{} event sink at {}", self.endpoint.scheme(), self.endpoint)
    }
}

/// Reports only transport failures and status codes, never response bodies.
fn transport_error(host: &str, err: &reqwest::Error) -> GuardError {
    match err.status() {
        Some(status) => GuardError::Unavailable(format!(
            "remote event endpoint {host} answered HTTP {}",
            status.as_u16()
        )),
        None => GuardError::Unavailable(format!("remote event endpoint {host} is unreachable")),
    }
}

async fn read_bounded(response: reqwest::Response, host: String) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| transport_error(&host, &err))?;
        if body.len() + chunk.len() > MAX_ACK_BYTES {
            return Err(GuardError::Unavailable(format!(
                "remote event endpoint {host} answered more than {MAX_ACK_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AckWire {
    accepted: usize,
    head_hash: String,
    #[serde(default)]
    request_id: Option<String>,
}

/// Accepts only an acknowledgement that names this exact batch.
fn parse_ack(body: &[u8], batch: &[GuardEvent]) -> Result<RemoteAck> {
    // The serde error text may echo an offending value, so only its class and
    // position are reported.
    let wire: AckWire = serde_json::from_slice(body).map_err(|err| {
        GuardError::Integrity(format!(
            "remote event acknowledgement is not valid ({:?} at line {} column {})",
            err.classify(),
            err.line(),
            err.column()
        ))
    })?;
    let expected = batch
        .last()
        .map(|event| event.current_hash.as_str())
        .ok_or_else(|| GuardError::Denied("refusing to deliver an empty batch".to_string()))?;
    if !super::is_sha256_hex(&wire.head_hash) {
        return Err(GuardError::Integrity(
            "remote event acknowledgement head_hash is not a sha-256 hex digest".to_string(),
        ));
    }
    if wire.accepted != batch.len() {
        return Err(GuardError::Integrity(format!(
            "remote event endpoint acknowledged {} of {} records",
            wire.accepted,
            batch.len()
        )));
    }
    if wire.head_hash != expected {
        return Err(GuardError::Integrity(
            "remote event endpoint acknowledged a different chain head".to_string(),
        ));
    }
    Ok(RemoteAck {
        accepted: wire.accepted,
        head_hash: wire.head_hash,
        request_id: wire.request_id,
    })
}

fn validated_endpoint(endpoint: &str, allow_loopback_http: bool) -> Result<Url> {
    if endpoint.is_empty() {
        return Err(GuardError::Policy(
            "remote event endpoint is required".to_string(),
        ));
    }
    if endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(GuardError::Denied(format!(
            "remote event endpoint exceeds {MAX_ENDPOINT_BYTES} bytes"
        )));
    }
    let url = Url::parse(endpoint)
        .map_err(|_| GuardError::Policy("remote event endpoint is not a URL".to_string()))?;
    match url.scheme() {
        "https" => {}
        "http" => {
            let loopback = url
                .host_str()
                .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback());
            if !(allow_loopback_http && loopback) {
                return Err(GuardError::Policy(
                    "remote event endpoint must use https".to_string(),
                ));
            }
        }
        _ => {
            return Err(GuardError::Policy(
                "remote event endpoint must use https".to_string(),
            ));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(GuardError::Policy(
            "remote event endpoint must not carry credentials in the URL".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(GuardError::Policy(
            "remote event endpoint must not carry a query or fragment".to_string(),
        ));
    }
    if url.host_str().is_none() {
        return Err(GuardError::Policy(
            "remote event endpoint has no host".to_string(),
        ));
    }
    Ok(url)
}

fn validated_header_name(name: &str) -> Result<HeaderName> {
    let lowered = name.to_ascii_lowercase();
    if lowered != "authorization" && lowered != "x-api-key" {
        return Err(GuardError::Policy(
            "remote event credential header must be authorization or x-api-key".to_string(),
        ));
    }
    HeaderName::from_bytes(lowered.as_bytes())
        .map_err(|_| GuardError::Policy("remote event credential header is invalid".to_string()))
}

/// Validates the token and returns the bytes the sink keeps in a zeroizing
/// buffer, so no copy of the secret outlives the sink without being wiped.
fn validated_token(token: &str) -> Result<Vec<u8>> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(GuardError::Denied(format!(
            "remote event token must be between 1 and {MAX_TOKEN_BYTES} bytes"
        )));
    }
    if HeaderValue::from_str(token).is_err() {
        return Err(GuardError::Denied(
            "remote event token contains illegal bytes".to_string(),
        ));
    }
    Ok(token.as_bytes().to_vec())
}

/// Bounds of the delivery worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteQueueConfig {
    /// Records that may wait for delivery. Further records are refused.
    pub capacity: usize,
    /// Largest batch handed to the remote sink in one call.
    pub max_batch_events: usize,
    /// Attempts per batch.
    pub max_attempts: u32,
}

impl Default for RemoteQueueConfig {
    fn default() -> Self {
        Self {
            capacity: 1024,
            max_batch_events: 64,
            max_attempts: 3,
        }
    }
}

/// Counters an operator can read; the last-error text is a fixed refusal
/// reason produced by this module and never a credential or response body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemoteStatsSnapshot {
    /// Records accepted into the queue.
    pub queued: u64,
    /// Records the remote acknowledged.
    pub delivered_events: u64,
    /// Batches the remote acknowledged.
    pub delivered_batches: u64,
    /// Failed delivery attempts, including ones later retried.
    pub failed_attempts: u64,
    /// Records dropped after exhausting their attempts.
    pub undelivered_events: u64,
    /// Records the local journal kept but the queue would not take.
    pub unqueued_events: u64,
    /// Consecutive batches that ended undelivered.
    pub consecutive_failures: u64,
    /// Head hash the remote last acknowledged; the anchor for tail truncation.
    pub last_acknowledged_hash: Option<String>,
    /// Last delivery failure.
    pub last_error: Option<String>,
}

#[derive(Default)]
struct RemoteStats {
    queued: AtomicU64,
    delivered_events: AtomicU64,
    delivered_batches: AtomicU64,
    failed_attempts: AtomicU64,
    undelivered_events: AtomicU64,
    unqueued_events: AtomicU64,
    consecutive_failures: AtomicU64,
    last_acknowledged_hash: Mutex<Option<String>>,
    last_error: Mutex<Option<String>>,
}

impl RemoteStats {
    fn snapshot(&self) -> RemoteStatsSnapshot {
        RemoteStatsSnapshot {
            queued: self.queued.load(Ordering::Relaxed),
            delivered_events: self.delivered_events.load(Ordering::Relaxed),
            delivered_batches: self.delivered_batches.load(Ordering::Relaxed),
            failed_attempts: self.failed_attempts.load(Ordering::Relaxed),
            undelivered_events: self.undelivered_events.load(Ordering::Relaxed),
            unqueued_events: self.unqueued_events.load(Ordering::Relaxed),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            last_acknowledged_hash: read_lock(&self.last_acknowledged_hash),
            last_error: read_lock(&self.last_error),
        }
    }
}

fn read_lock<T>(slot: &Mutex<Option<T>>) -> Option<T>
where
    T: Clone,
{
    slot.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// Bounded, ordered delivery worker for one remote sink.
///
/// The queue holds at most `capacity` records, so a slow or absent remote
/// cannot make Guard's memory grow. A record the queue will not take is
/// counted, never silently dropped, and never fails the local append.
pub struct RemoteQueue {
    tx: mpsc::Sender<GuardEvent>,
    stats: Arc<RemoteStats>,
    worker: JoinHandle<()>,
}

impl RemoteQueue {
    /// Starts the delivery worker on the current Tokio runtime.
    pub fn start(sink: Arc<dyn RemoteEventSink>, config: RemoteQueueConfig) -> Result<Self> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(GuardError::Unavailable(
                "remote event delivery requires a Tokio runtime".to_string(),
            ));
        }
        if config.capacity == 0 || config.capacity > 65_536 {
            return Err(GuardError::Denied(format!(
                "remote event queue capacity must be between 1 and 65536, got {}",
                config.capacity
            )));
        }
        if config.max_batch_events == 0 || config.max_batch_events > 1024 {
            return Err(GuardError::Denied(format!(
                "remote event max_batch_events must be between 1 and 1024, got {}",
                config.max_batch_events
            )));
        }
        if config.max_attempts == 0 || config.max_attempts > 10 {
            return Err(GuardError::Denied(format!(
                "remote event max_attempts must be between 1 and 10, got {}",
                config.max_attempts
            )));
        }
        let (tx, rx) = mpsc::channel(config.capacity);
        let stats = Arc::new(RemoteStats::default());
        let worker = tokio::spawn(run_worker(
            sink,
            rx,
            config.max_batch_events,
            config.max_attempts,
            Arc::clone(&stats),
        ));
        Ok(Self { tx, stats, worker })
    }

    /// Queues one record without waiting, and always records the outcome.
    ///
    /// This cannot fail: the record is already durable in the local journal,
    /// and a secondary delivery copy must never make the local append look
    /// unrecorded. A record the queue refuses is counted in
    /// [`RemoteStatsSnapshot::unqueued_events`] and leaves
    /// `last_acknowledged_hash` behind the journal head, which is the signal an
    /// operator or the phase-2 watchdog acts on.
    pub fn enqueue(&self, event: &GuardEvent) {
        match self.tx.try_send(event.clone()) {
            Ok(()) => {
                self.stats.queued.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.unqueued_events.fetch_add(1, Ordering::Relaxed);
                let mut last_error = self
                    .stats
                    .last_error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *last_error =
                    Some("remote event queue refused a record that is durable locally".to_string());
            }
        }
    }

    /// Current delivery counters.
    pub fn stats(&self) -> RemoteStatsSnapshot {
        self.stats.snapshot()
    }

    /// Stops the worker after the queued records have been attempted, and
    /// returns the final delivery counters.
    pub async fn shutdown(self) -> Result<RemoteStatsSnapshot> {
        let Self { tx, worker, stats } = self;
        drop(tx);
        worker
            .await
            .map_err(|err| GuardError::Unavailable(format!("remote event worker failed: {err}")))?;
        Ok(stats.snapshot())
    }
}

async fn run_worker(
    sink: Arc<dyn RemoteEventSink>,
    mut rx: mpsc::Receiver<GuardEvent>,
    max_batch_events: usize,
    max_attempts: u32,
    stats: Arc<RemoteStats>,
) {
    while let Some(first) = rx.recv().await {
        let mut batch = Vec::with_capacity(max_batch_events);
        batch.push(first);
        // Opportunistic batching: take what is already queued, never wait for more.
        while batch.len() < max_batch_events {
            match rx.try_recv() {
                Ok(next) => batch.push(next),
                Err(_) => break,
            }
        }
        deliver_batch(&sink, &batch, max_attempts, &stats).await;
    }
}

async fn deliver_batch(
    sink: &Arc<dyn RemoteEventSink>,
    batch: &[GuardEvent],
    max_attempts: u32,
    stats: &Arc<RemoteStats>,
) {
    for attempt in 0..max_attempts {
        match sink.deliver(batch).await {
            Ok(ack) => {
                stats
                    .delivered_events
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                stats.delivered_batches.fetch_add(1, Ordering::Relaxed);
                stats.consecutive_failures.store(0, Ordering::Relaxed);
                let mut head = stats
                    .last_acknowledged_hash
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *head = Some(ack.head_hash);
                let mut last_error = stats
                    .last_error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *last_error = None;
                return;
            }
            Err(err) => {
                stats.failed_attempts.fetch_add(1, Ordering::Relaxed);
                {
                    let mut last_error = stats
                        .last_error
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    *last_error = Some(err.to_string());
                }
                if attempt + 1 < max_attempts {
                    tokio::time::sleep(backoff(attempt)).await;
                }
            }
        }
    }
    stats.consecutive_failures.fetch_add(1, Ordering::Relaxed);
    stats
        .undelivered_events
        .fetch_add(batch.len() as u64, Ordering::Relaxed);
}

fn backoff(attempt: u32) -> Duration {
    let millis = 50u64.saturating_mul(1u64 << attempt.min(5));
    Duration::from_millis(millis.min(2000))
}
