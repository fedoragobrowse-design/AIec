use aiec_core::run::{
    CapabilityRequirements, ResourceRequirements, RetentionPolicy, Run, RunArtifactRef, RunEvent,
    RunState, WorkloadSpec,
};
use aiec_core::*;
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

/// The run vocabulary, re-exported so a caller does not have to depend on
/// `aiec-core` to describe a run.
pub use aiec_core::run::{
    BatchOptions, CommandOutcome, Placement, RepoSpec, RunResults, RunSandbox,
};

/// The ceiling on a client-side batch, matching the control plane's own limit
/// so a client cannot be the thing that makes a batch unbounded.
const MAX_CLIENT_BATCH_PARALLEL: usize = 64;

/// Everything a caller supplies to start a run.
///
/// Mirrors the API's `RunRequest` field for field: the names here are the wire
/// names, so a body built from this type deserialises into the server's own
/// struct without translation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreateRunRequest {
    #[serde(default)]
    pub workload: WorkloadSpec,
    #[serde(default)]
    pub resources: ResourceRequirements,
    #[serde(default)]
    pub requirements: CapabilityRequirements,
    #[serde(default)]
    pub retention: RetentionPolicy,
    /// Reusing a key returns the run that already exists instead of executing
    /// the work twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_run_id: Option<Uuid>,
    /// Groups the cells of a matrix so the set is addressable as a whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matrix_id: Option<Uuid>,
    /// Advanced use only. Stating requirements does not mean picking a runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_runtime: Option<String>,
    /// How long a machine kept for debugging is kept, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_seconds: Option<i64>,
}

/// One collected artifact, with the path its bytes are served from.
#[derive(Clone, Debug, Deserialize)]
pub struct RunArtifact {
    /// The record itself, flattened because that is how the API emits it.
    #[serde(flatten)]
    pub artifact: RunArtifactRef,
    /// Absolute within the API, so it can be handed to anything that speaks
    /// HTTP rather than reassembled by the caller.
    pub download_url: String,
}

/// One cell of a batch, and what happened to it.
///
/// A batch reports the runs it managed to start, so a cell that could not be
/// scheduled carries the reason rather than disappearing: a matrix indexed by
/// axis value cannot be summarised if half its cells silently vanished.
#[derive(Clone, Debug)]
pub struct RunCell {
    /// The cell's position in the request list, so a caller can line the
    /// outcome up with what it asked for.
    pub index: usize,
    pub run: Option<Run>,
    /// Why this cell produced no run.
    pub error: Option<String>,
}

/// How long the control plane gives a run that states no timeout of its own.
const DEFAULT_RUN_TIMEOUT_SECONDS: u64 = 600;

/// The ceiling on a run timeout, matching what the control plane clamps to.
const MAX_RUN_TIMEOUT_SECONDS: u64 = 86_400;

/// Slack added to a run's own timeout before the client stops waiting.
///
/// The API drives a run to a terminal state before it answers, so the wait for
/// `POST /v1/runs` *is* the run. A 60-second client timeout would abandon a
/// perfectly healthy ten-minute workload and report it as a transport failure.
///
/// It must also be *longer* than the server's own budget, by enough that the
/// server always gives up first. The control plane adds a grace period on top of
/// the stated timeout for placement and teardown; a client that waits less than
/// that drops the connection while the server is still working, which cancels
/// the run's future mid-flight, leaves the row non-terminal with no terminal
/// event, and leaks the machine. Those are the runs that hold a machine longest,
/// so the slack is what the failure costs most.
const RUN_RESPONSE_SLACK_SECONDS: u64 = 300;

/// How long a cancel may take: it transitions the run, then waits for each
/// machine it was holding to be destroyed.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(300);

/// The wait allowed for one run, taken from the timeout the workload states.
fn run_response_timeout(workload: &WorkloadSpec) -> Duration {
    let stated = workload
        .timeout_seconds
        .unwrap_or(DEFAULT_RUN_TIMEOUT_SECONDS)
        .clamp(30, MAX_RUN_TIMEOUT_SECONDS);
    Duration::from_secs(stated + RUN_RESPONSE_SLACK_SECONDS)
}

/// Checks a caller-stated batch limit against the bound the control plane puts
/// on one, so a client cannot be the thing that makes a batch unbounded.
fn check_batch_parallelism(max_parallel: usize) -> Result<usize, ClientError> {
    if max_parallel == 0 || max_parallel > MAX_CLIENT_BATCH_PARALLEL {
        return Err(ClientError::Configuration(format!(
            "max_parallel must be between 1 and {MAX_CLIENT_BATCH_PARALLEL}"
        )));
    }
    Ok(max_parallel)
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("client configuration: {0}")]
    Configuration(String),
    #[error("API error {status}: {message} (request {request_id})")]
    Api {
        status: StatusCode,
        code: String,
        message: String,
        request_id: Uuid,
    },
    #[error("invalid response: {0}")]
    Decode(String),
}
#[derive(Debug, Deserialize)]
struct ErrorDocument {
    error: ApiErrorBody,
}

#[derive(Clone)]
pub struct AIecClient {
    http: Client,
    base_url: String,
    api_key: String,
}
impl AIecClient {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let mut builder = Client::builder().timeout(Duration::from_secs(60));
        if let Ok(path) = std::env::var("AIEC_TLS_CA_CERT") {
            let pem = std::fs::read(&path)
                .map_err(|error| ClientError::Configuration(format!("read {path}: {error}")))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|error| ClientError::Configuration(format!("parse {path}: {error}")))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build()?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            api_key: api_key.into(),
        })
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(&self.api_key)
    }
    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, ClientError> {
        let response = request.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            let document: ErrorDocument = serde_json::from_slice(&bytes)
                .map_err(|_| ClientError::Decode("malformed API error".into()))?;
            return Err(ClientError::Api {
                status,
                code: document.error.code,
                message: document.error.message,
                request_id: document.error.request_id,
            });
        }
        serde_json::from_slice(&bytes).map_err(|error| ClientError::Decode(error.to_string()))
    }
    pub async fn health(&self) -> Result<serde_json::Value, ClientError> {
        self.send(self.request(reqwest::Method::GET, "/health"))
            .await
    }
    pub async fn ready(&self) -> Result<serde_json::Value, ClientError> {
        self.send(self.request(reqwest::Method::GET, "/ready"))
            .await
    }
    pub async fn create_sandbox(
        &self,
        request: &CreateSandboxRequest,
    ) -> Result<Sandbox, ClientError> {
        self.send(
            self.request(reqwest::Method::POST, "/v1/sandboxes")
                .json(request),
        )
        .await
    }

    /// Creates a sandbox, pinning the runtime rather than letting policy choose.
    ///
    /// The control plane flattens `runtime` alongside the request fields, so it
    /// is merged in here. A caller that requires a specific isolation level
    /// needs to be able to ask for one and to see which runtime it got.
    pub async fn create_sandbox_with_runtime(
        &self,
        request: &CreateSandboxRequest,
        runtime: &str,
    ) -> Result<Sandbox, ClientError> {
        let mut body = serde_json::to_value(request)
            .map_err(|error| ClientError::Decode(error.to_string()))?;
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "runtime".to_owned(),
                serde_json::Value::String(runtime.to_owned()),
            );
        }
        self.send(
            self.request(reqwest::Method::POST, "/v1/sandboxes")
                .json(&body),
        )
        .await
    }
    pub async fn list_sandboxes(&self) -> Result<Vec<Sandbox>, ClientError> {
        self.send(self.request(reqwest::Method::GET, "/v1/sandboxes"))
            .await
    }
    pub async fn get_sandbox(&self, id: Uuid) -> Result<Sandbox, ClientError> {
        self.send(self.request(reqwest::Method::GET, &format!("/v1/sandboxes/{id}")))
            .await
    }
    pub async fn delete_sandbox(&self, id: Uuid) -> Result<(), ClientError> {
        self.send_empty(self.request(reqwest::Method::DELETE, &format!("/v1/sandboxes/{id}")))
            .await
    }
    pub async fn start(&self, id: Uuid) -> Result<Sandbox, ClientError> {
        self.send(self.request(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/start")))
            .await
    }
    pub async fn stop(&self, id: Uuid) -> Result<Sandbox, ClientError> {
        self.send(self.request(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/stop")))
            .await
    }
    pub async fn resume(&self, id: Uuid) -> Result<Sandbox, ClientError> {
        self.send(self.request(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/resume")))
            .await
    }
    pub async fn pause(&self, id: Uuid) -> Result<Sandbox, ClientError> {
        self.send(self.request(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/pause")))
            .await
    }
    pub async fn exec(&self, id: Uuid, request: &ExecRequest) -> Result<ExecResult, ClientError> {
        self.send(
            self.request(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/exec"))
                .json(request),
        )
        .await
    }
    pub async fn git_diff(&self, id: Uuid) -> Result<serde_json::Value, ClientError> {
        self.send(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{id}/git/diff"),
            )
            .json(&serde_json::json!({})),
        )
        .await
    }
    pub async fn put_file(&self, id: Uuid, request: &PutFileRequest) -> Result<(), ClientError> {
        self.send_empty(
            self.request(reqwest::Method::PUT, &format!("/v1/sandboxes/{id}/files"))
                .json(request),
        )
        .await
    }
    pub async fn get_file(&self, id: Uuid, path: &str) -> Result<FileContent, ClientError> {
        let url = format!("/v1/sandboxes/{id}/files/content?path={}", urlencode(path));
        self.send(self.request(reqwest::Method::GET, &url)).await
    }
    pub async fn list_files(&self, id: Uuid, path: &str) -> Result<Vec<FileEntry>, ClientError> {
        let url = format!("/v1/sandboxes/{id}/files?path={}", urlencode(path));
        self.send(self.request(reqwest::Method::GET, &url)).await
    }
    pub async fn delete_file(&self, id: Uuid, path: &str) -> Result<(), ClientError> {
        self.send_empty(self.request(
            reqwest::Method::DELETE,
            &format!("/v1/sandboxes/{id}/files?path={}", urlencode(path)),
        ))
        .await
    }
    pub async fn make_directory(&self, id: Uuid, path: &str) -> Result<(), ClientError> {
        self.send_empty(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{id}/files/mkdir"),
            )
            .json(&MakeDirectoryRequest { path: path.into() }),
        )
        .await
    }
    pub async fn create_snapshot(&self, id: Uuid) -> Result<Snapshot, ClientError> {
        self.send(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{id}/snapshots"),
            )
            .json(&serde_json::json!({})),
        )
        .await
    }
    pub async fn list_snapshots(&self, id: Uuid) -> Result<Vec<Snapshot>, ClientError> {
        self.send(self.request(
            reqwest::Method::GET,
            &format!("/v1/sandboxes/{id}/snapshots"),
        ))
        .await
    }
    pub async fn restore_snapshot(
        &self,
        id: Uuid,
        request: &RestoreSnapshotRequest,
    ) -> Result<Sandbox, ClientError> {
        self.send(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/snapshots/{id}/restore"),
            )
            .json(request),
        )
        .await
    }
    pub async fn delete_snapshot(&self, id: Uuid) -> Result<(), ClientError> {
        self.send_empty(self.request(reqwest::Method::DELETE, &format!("/v1/snapshots/{id}")))
            .await
    }
    pub async fn usage(&self) -> Result<Vec<UsageSummary>, ClientError> {
        self.send(self.request(reqwest::Method::GET, "/v1/usage"))
            .await
    }

    /// Starts a run and returns it settled.
    ///
    /// The API drives the run to a terminal state before answering, so the run
    /// that comes back is the record of what happened. A workload that failed
    /// is reported through that document rather than as an error, because "the
    /// work failed" is the outcome the caller asked for.
    pub async fn create_run(&self, request: &CreateRunRequest) -> Result<Run, ClientError> {
        self.send(
            self.request(reqwest::Method::POST, "/v1/runs")
                .timeout(run_response_timeout(&request.workload))
                .json(request),
        )
        .await
    }

    /// Lists this tenant's runs, newest first.
    pub async fn list_runs(
        &self,
        state: Option<RunState>,
        limit: Option<u32>,
    ) -> Result<Vec<Run>, ClientError> {
        let mut query = Vec::new();
        if let Some(state) = state {
            query.push(format!("state={}", urlencode(state.as_str())));
        }
        if let Some(limit) = limit {
            query.push(format!("limit={limit}"));
        }
        let path = if query.is_empty() {
            "/v1/runs".to_owned()
        } else {
            format!("/v1/runs?{}", query.join("&"))
        };
        self.send(self.request(reqwest::Method::GET, &path)).await
    }

    /// Reads one of this tenant's runs.
    pub async fn get_run(&self, id: Uuid) -> Result<Run, ClientError> {
        self.send(self.request(reqwest::Method::GET, &format!("/v1/runs/{id}")))
            .await
    }

    /// A run's history, in the order it happened.
    pub async fn run_events(&self, id: Uuid) -> Result<Vec<RunEvent>, ClientError> {
        self.send(self.request(reqwest::Method::GET, &format!("/v1/runs/{id}/events")))
            .await
    }

    /// The artifacts a run collected, each with the path its bytes are served
    /// from.
    pub async fn run_artifacts(&self, id: Uuid) -> Result<Vec<RunArtifact>, ClientError> {
        self.send(self.request(reqwest::Method::GET, &format!("/v1/runs/{id}/artifacts")))
            .await
    }

    /// Stops a run and reclaims the machine it was holding.
    ///
    /// Cancelling a run that already finished is a success, not a failure: the
    /// caller's intent is already true and a second cancel must not look like a
    /// mistake.
    pub async fn cancel_run(&self, id: Uuid) -> Result<Run, ClientError> {
        self.send(
            self.request(reqwest::Method::POST, &format!("/v1/runs/{id}/cancel"))
                .timeout(CANCEL_TIMEOUT),
        )
        .await
    }

    /// Runs several workloads with bounded concurrency, reporting every cell.
    ///
    /// The requests are chunked rather than all fired at once, so a slow run
    /// does not hold the whole batch behind it and the control plane never sees
    /// more simultaneous submissions than this asked for. One workload that
    /// could not be scheduled does not abandon the others: the point of a
    /// batch is that fifty tasks do not need fifty separate submissions.
    pub async fn run_cells(
        &self,
        requests: &[CreateRunRequest],
        max_parallel: usize,
    ) -> Result<Vec<RunCell>, ClientError> {
        let limit = check_batch_parallelism(max_parallel)?;
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        let limit = limit.min(requests.len());
        let mut cells = Vec::with_capacity(requests.len());
        let mut queued = requests.iter().enumerate();

        // A sliding window, built from concrete futures rather than a stream.
        //
        // Chunks bound the concurrency correctly and then waste most of it: a
        // chunk ends only when its slowest member does, so one cell that takes
        // a minute holds the rest of its group idle while slots sit free. On a
        // heterogeneous batch that is most of the wall time spent waiting on
        // whichever slow cell a slot happened to be grouped with.
        //
        // `FuturesUnordered` over an explicit refill keeps the same bound and
        // starts the next cell the moment one finishes. It is written this way
        // rather than as `buffer_unordered` because a closure there infers a
        // higher-ranked future the MCP `#[tool]` wrapper will not accept - the
        // same change written this way compiles for both.
        let mut in_flight = FuturesUnordered::new();
        for _ in 0..limit {
            if let Some((index, request)) = queued.next() {
                in_flight.push(self.run_one_cell(index, request));
            }
        }
        while let Some(cell) = in_flight.next().await {
            cells.push(cell);
            if let Some((index, request)) = queued.next() {
                in_flight.push(self.run_one_cell(index, request));
            }
        }
        // The window completes out of order; callers identify a failed cell by
        // its position in what they submitted, so it is restored here.
        cells.sort_by_key(|cell| cell.index);
        Ok(cells)
    }

    /// One cell of a batch, reduced to the shape every cell has.
    async fn run_one_cell(&self, index: usize, request: &CreateRunRequest) -> RunCell {
        match self.create_run(request).await {
            Ok(run) => RunCell {
                index,
                run: Some(run),
                error: None,
            },
            Err(error) => RunCell {
                index,
                run: None,
                error: Some(error.to_string()),
            },
        }
    }

    /// Runs several workloads with bounded concurrency.
    ///
    /// The runs that started, in submission order. A caller that needs to know
    /// which cell failed wants [`Self::run_cells`], which reports every cell
    /// rather than only the ones that worked.
    pub async fn run_batch(
        &self,
        requests: &[CreateRunRequest],
        max_parallel: usize,
    ) -> Result<Vec<Run>, ClientError> {
        Ok(self
            .run_cells(requests, max_parallel)
            .await?
            .into_iter()
            .filter_map(|cell| cell.run)
            .collect())
    }
    async fn send_empty(&self, request: reqwest::RequestBuilder) -> Result<(), ClientError> {
        let response = request.send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let bytes = response.bytes().await?;
        let document: ErrorDocument = serde_json::from_slice(&bytes)
            .map_err(|_| ClientError::Decode("malformed API error".into()))?;
        Err(ClientError::Api {
            status,
            code: document.error.code,
            message: document.error.message,
            request_id: document.error.request_id,
        })
    }
}
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    /// The client's patience must exceed the server's budget.
    ///
    /// A client that gives up first does not merely fail: it drops the
    /// connection, the server's `execute` future is cancelled mid-flight, and
    /// the run is left non-terminal holding a machine. Because that happens
    /// exactly when a run uses its whole budget, it takes down the runs that
    /// hold compute longest - the opposite of what a shorter timeout buys.
    #[test]
    fn the_client_outlasts_the_servers_own_budget() {
        // Mirrors the control plane's PLACEMENT_GRACE_SECONDS. Duplicated on
        // purpose rather than imported: if the server ever changes its grace,
        // this assertion should fail loudly here instead of both sides moving
        // together and nobody noticing the relationship.
        const SERVER_PLACEMENT_GRACE_SECONDS: u64 = 120;
        const _: () = assert!(
            RUN_RESPONSE_SLACK_SECONDS > SERVER_PLACEMENT_GRACE_SECONDS,
            "the client gives up before the server does: a client that drops the \
             connection mid-run cancels the server's future and leaks the machine"
        );
        let workload = WorkloadSpec {
            timeout_seconds: Some(600),
            ..WorkloadSpec::default()
        };
        assert_eq!(run_response_timeout(&workload).as_secs(), 900);
    }

    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::extract::{Request, State};
    use axum::http::StatusCode as AxumStatus;
    use axum::response::Response;
    use axum::routing::any;
    use chrono::Utc;
    use serde_json::Value;
    use tokio::net::TcpListener;

    use tokio::sync::Mutex;

    /// A run id the stub control plane treats as absent, so the error mapping
    /// has something real to map.
    const MISSING_RUN_ID: &str = "0192f2c1-6f0a-7b1e-8a1c-2f9a4d0e5b31";

    /// One request the stub control plane saw, so a test can assert on what
    /// the client actually put on the wire rather than on what it meant to.
    #[derive(Clone, Debug)]
    struct Seen {
        method: String,
        path: String,
        query: String,
        authorization: Option<String>,
        body: Value,
    }

    #[derive(Clone)]
    struct Stub {
        seen: Arc<Mutex<Vec<Seen>>>,
        in_flight: Arc<AtomicUsize>,
        peak_in_flight: Arc<AtomicUsize>,
        slow: bool,
    }

    impl Stub {
        fn new() -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
                in_flight: Arc::new(AtomicUsize::new(0)),
                peak_in_flight: Arc::new(AtomicUsize::new(0)),
                slow: false,
            }
        }

        async fn requests(&self) -> Vec<Seen> {
            self.seen.lock().await.clone()
        }
    }

    /// A settled run, built from the real type so the stub cannot drift from
    /// what the API actually serialises.
    fn settled_run(state: RunState) -> Run {
        Run {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            state,
            requested_at: Utc::now(),
            queued_at: Some(Utc::now()),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            workload: WorkloadSpec {
                command: vec!["pytest".to_owned(), "-q".to_owned()],
                ..Default::default()
            },
            resources: ResourceRequirements::default(),
            requirements: CapabilityRequirements::default(),
            placement: Placement {
                runtime: Some("firecracker".to_owned()),
                worker: None,
                reasons: vec![],
            },
            results: RunResults::default(),
            failure_reason: None,
            retention: RetentionPolicy::Destroy,
            retained_sandbox_id: None,
            retained_until: None,
            idempotency_key: None,
            parent_run_id: None,
            matrix_id: None,
        }
    }

    /// A settled run carrying a specific id, so a test that read `/v1/runs/{id}`
    /// gets that run back rather than one of the stub's own.
    fn run_document_for(id: &str, state: RunState) -> Value {
        let mut document = run_document(state);
        if let Some(object) = document.as_object_mut() {
            object.insert("id".to_owned(), Value::String(id.to_owned()));
        }
        document
    }

    /// The run id inside a `/v1/runs/...` path.
    fn run_id_in(path: &str) -> &str {
        path.strip_prefix("/v1/runs/")
            .unwrap_or_default()
            .split('/')
            .next()
            .unwrap_or_default()
    }

    fn run_document(state: RunState) -> Value {
        serde_json::to_value(settled_run(state)).expect("a run serialises")
    }

    /// A control plane that records what it was asked and answers with the
    /// document the API would answer with.
    async fn stub_control_plane(stub: Stub) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().fallback(any(handle)).with_state(stub.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let url = format!("http://{}", listener.local_addr().expect("a bound address"));
        let serving = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (url, serving)
    }

    async fn handle(State(stub): State<Stub>, request: Request) -> Response {
        let method = request.method().to_string();
        let path = request.uri().path().to_owned();
        let query = request.uri().query().unwrap_or_default().to_owned();
        let authorization = request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let raw = axum::body::to_bytes(request.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap_or_default();
        let body = serde_json::from_slice::<Value>(&raw).unwrap_or(Value::Null);
        stub.seen.lock().await.push(Seen {
            method,
            path: path.clone(),
            query,
            authorization,
            body: body.clone(),
        });

        // Batch submissions overlap on purpose so the test can see how many
        // the client is willing to have in flight at once.
        if stub.slow {
            let now = stub.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            stub.peak_in_flight.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            stub.in_flight.fetch_sub(1, Ordering::SeqCst);
        }

        // One run id is reserved as "does not exist", so the error mapping can
        // be exercised without a second stub route.
        let missing_path = format!("/v1/runs/{MISSING_RUN_ID}");
        let (status, payload) = match path.as_str() {
            p if p == missing_path => (
                AxumStatus::NOT_FOUND,
                serde_json::json!({
                    "error": {
                        "code": "not_found",
                        "message": "run not found",
                        "request_id": MISSING_RUN_ID,
                    }
                }),
            ),
            "/v1/runs" if body.get("workload").is_some() => {
                (AxumStatus::CREATED, run_document(RunState::Succeeded))
            }
            "/v1/runs" => (
                AxumStatus::OK,
                serde_json::json!([run_document(RunState::Running)]),
            ),
            other if other.ends_with("/events") => (AxumStatus::OK, serde_json::json!([])),
            other if other.ends_with("/artifacts") => (
                AxumStatus::OK,
                serde_json::json!([{
                    "name": "report.txt",
                    "object_key": format!("tenants/t/runs/{}/report.txt", "0192f2c1-6f0a-7b1e-8a1c-2f9a4d0e5b31"),
                    "size_bytes": 11,
                    "checksum_sha256": null,
                    "content_type": "text/plain",
                    "download_url": "/v1/runs/0192f2c1-6f0a-7b1e-8a1c-2f9a4d0e5b31/artifacts/report.txt",
                }]),
            ),
            other if other.ends_with("/cancel") => (
                AxumStatus::OK,
                run_document_for(run_id_in(other), RunState::Cancelled),
            ),
            other if other.starts_with("/v1/runs/") => (
                AxumStatus::OK,
                run_document_for(run_id_in(other), RunState::Succeeded),
            ),
            _ => (AxumStatus::NOT_FOUND, Value::Null),
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }

    fn request(command: &[&str]) -> CreateRunRequest {
        CreateRunRequest {
            workload: WorkloadSpec {
                command: command.iter().map(|part| (*part).to_owned()).collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_run_is_posted_with_the_shape_the_api_deserialises() {
        let stub = Stub::new();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");

        let mut wanted = request(&["pytest", "-q"]);
        wanted.workload.image = Some("aiec-coding:latest".to_owned());
        wanted.workload.repo = Some(aiec_core::run::RepoSpec {
            url: "https://github.com/example/project.git".to_owned(),
            reference: Some("main".to_owned()),
            ..Default::default()
        });
        wanted.workload.setup = vec![vec![
            "pip".to_owned(),
            "install".to_owned(),
            "-e".to_owned(),
            ".".to_owned(),
        ]];
        wanted.workload.validations = vec![vec!["pytest".to_owned(), "-q".to_owned()]];
        wanted.workload.artifacts = vec!["report.txt".to_owned()];
        wanted.workload.timeout_seconds = Some(900);
        wanted.workload.git_evidence = true;
        wanted.resources = ResourceRequirements {
            cpu: 2,
            memory_mb: 2048,
            disk_mb: 4096,
            network: NetworkPolicy::Internet,
        };
        wanted.requirements.full_kernel_isolation = true;
        wanted.retention = RetentionPolicy::KeepOnFailure;
        wanted.idempotency_key = Some("nightly-42".to_owned());
        wanted.requested_runtime = Some("firecracker".to_owned());

        let run = client.create_run(&wanted).await.expect("a settled run");
        assert_eq!(run.state, RunState::Succeeded);

        let seen = stub.requests().await;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, "/v1/runs");
        assert_eq!(
            seen[0].authorization.as_deref(),
            Some("Bearer af_live_key"),
            "the run routes are authenticated like every other route"
        );
        let body = &seen[0].body;
        assert_eq!(
            body["workload"]["command"],
            serde_json::json!(["pytest", "-q"])
        );
        assert_eq!(body["workload"]["image"], "aiec-coding:latest");
        assert_eq!(
            body["workload"]["repo"],
            serde_json::json!({
                "url": "https://github.com/example/project.git",
                "reference": "main",
                "path": "/workspace/repository",
            })
        );
        assert_eq!(
            body["workload"]["setup"][0],
            serde_json::json!(["pip", "install", "-e", "."])
        );
        assert_eq!(
            body["workload"]["validations"][0],
            serde_json::json!(["pytest", "-q"])
        );
        assert_eq!(
            body["workload"]["artifacts"],
            serde_json::json!(["report.txt"])
        );
        assert_eq!(body["workload"]["timeout_seconds"], 900);
        assert_eq!(body["workload"]["git_evidence"], true);
        assert_eq!(
            body["resources"],
            serde_json::json!({
                "cpu": 2,
                "memory_mb": 2048,
                "disk_mb": 4096,
                "network": { "enabled": true },
            })
        );
        assert_eq!(body["requirements"]["full_kernel_isolation"], true);
        assert_eq!(body["retention"], "keep_on_failure");
        assert_eq!(body["idempotency_key"], "nightly-42");
        assert_eq!(body["requested_runtime"], "firecracker");
        serving.abort();
    }

    /// The key set is the contract: a field the API does not have is silently
    /// dropped on the floor, and a field renamed is silently ignored, so a
    /// typo here would be a request that quietly does less than the caller
    /// asked for.
    #[test]
    fn a_run_request_only_sends_fields_the_api_accepts() {
        let keys = |value: CreateRunRequest| {
            let body = serde_json::to_value(value).expect("a request serialises");
            let mut keys: Vec<String> = body
                .as_object()
                .expect("an object")
                .keys()
                .cloned()
                .collect();
            keys.sort();
            keys
        };

        // Nothing optional is invented: a request that states no options says
        // only what the API needs, and the API fills in the rest.
        let plain = serde_json::to_value(request(&["true"])).expect("a request serialises");
        assert_eq!(
            keys(request(&["true"])),
            ["requirements", "resources", "retention", "workload"]
        );
        assert_eq!(plain["retention"], "destroy");
        assert_eq!(
            plain["resources"]["network"],
            serde_json::json!({ "enabled": false })
        );

        assert_eq!(
            keys(CreateRunRequest {
                idempotency_key: Some("k".to_owned()),
                parent_run_id: Some(Uuid::now_v7()),
                matrix_id: Some(Uuid::now_v7()),
                requested_runtime: Some("firecracker".to_owned()),
                retained_seconds: Some(600),
                ..request(&["true"])
            }),
            [
                "idempotency_key",
                "matrix_id",
                "parent_run_id",
                "requested_runtime",
                "requirements",
                "resources",
                "retained_seconds",
                "retention",
                "workload",
            ]
        );
    }

    #[tokio::test]
    async fn a_run_page_carries_the_state_and_limit_filters() {
        let stub = Stub::new();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");

        let runs = client
            .list_runs(Some(RunState::Running), Some(5))
            .await
            .expect("a run page");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].state, RunState::Running);

        let seen = stub.requests().await;
        assert_eq!(seen[0].path, "/v1/runs");
        assert_eq!(seen[0].query, "state=running&limit=5");
        assert_eq!(seen[0].method, "GET");
        serving.abort();
    }

    #[tokio::test]
    async fn a_run_is_read_by_id_and_can_be_cancelled() {
        let stub = Stub::new();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");
        let id = Uuid::now_v7();

        let run = client.get_run(id).await.expect("a run");
        assert_eq!(run.id, id);

        let cancelled = client.cancel_run(id).await.expect("a cancelled run");
        assert_eq!(cancelled.state, RunState::Cancelled);

        let paths: Vec<String> = stub
            .requests()
            .await
            .into_iter()
            .map(|seen| seen.path)
            .collect();
        assert_eq!(
            paths,
            vec![format!("/v1/runs/{id}"), format!("/v1/runs/{id}/cancel")]
        );
        serving.abort();
    }

    #[tokio::test]
    async fn run_events_and_artifacts_use_the_documented_routes() {
        let stub = Stub::new();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");
        let id = Uuid::now_v7();

        assert!(client.run_events(id).await.expect("events").is_empty());
        let artifacts = client.run_artifacts(id).await.expect("artifacts");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact.name, "report.txt");
        assert_eq!(artifacts[0].artifact.size_bytes, 11);
        assert!(artifacts[0].download_url.ends_with("/artifacts/report.txt"));

        let paths: Vec<String> = stub
            .requests()
            .await
            .into_iter()
            .map(|seen| seen.path)
            .collect();
        assert_eq!(
            paths,
            vec![
                format!("/v1/runs/{id}/events"),
                format!("/v1/runs/{id}/artifacts")
            ]
        );
        serving.abort();
    }

    #[tokio::test]
    async fn an_api_failure_keeps_its_code_and_request_id() {
        let stub = Stub::new();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");

        let error = client
            .get_run(Uuid::parse_str(MISSING_RUN_ID).expect("a run id"))
            .await
            .expect_err("the stub refuses this one");
        let ClientError::Api {
            status,
            code,
            message,
            request_id,
        } = &error
        else {
            panic!("a run that does not exist is an API error, got {error:?}");
        };
        assert_eq!(*status, AxumStatus::NOT_FOUND);
        assert_eq!(code, "not_found");
        assert_eq!(message, "run not found");
        assert_eq!(request_id.to_string(), MISSING_RUN_ID);
        serving.abort();
    }

    /// A batch that fires everything at once is how a caller takes the whole
    /// cluster, so the limit the caller gave is the limit actually used.
    #[tokio::test]
    async fn a_batch_never_exceeds_its_parallel_limit() {
        let stub = Stub {
            slow: true,
            ..Stub::new()
        };
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");
        let requests = vec![
            request(&["one"]),
            request(&["two"]),
            request(&["three"]),
            request(&["four"]),
        ];

        let runs = client.run_batch(&requests, 2).await.expect("a batch");
        assert_eq!(runs.len(), 4);
        assert!(
            stub.peak_in_flight.load(Ordering::SeqCst) <= 2,
            "the client had {} submissions in flight at once",
            stub.peak_in_flight.load(Ordering::SeqCst)
        );
        assert_eq!(stub.requests().await.len(), 4);
        serving.abort();
    }

    #[tokio::test]
    async fn a_batch_of_nothing_costs_nothing() {
        let stub = Stub::new();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");

        assert!(
            client
                .run_batch(&[], 2)
                .await
                .expect("an empty batch")
                .is_empty()
        );
        assert!(stub.requests().await.is_empty());
        assert!(
            client.run_batch(&[request(&["true"])], 0).await.is_err(),
            "a batch with no parallelism cannot run anything"
        );
        serving.abort();
    }
}
