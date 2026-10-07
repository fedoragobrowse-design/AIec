use aiec_core::run::{
    CapabilityRequirements, ResourceRequirements, RetentionPolicy, Run, RunArtifactRef, RunEvent,
    RunState, WorkloadSpec,
};
use aiec_core::*;
use chrono::{DateTime, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

/// The run vocabulary, re-exported so a caller does not have to depend on
/// `aiec-core` to describe a run.
pub use aiec_core::run::{
    BatchOptions, CommandOutcome, Placement, RepoSpec, RunResults, RunSandbox,
};
pub use aiec_core::storage::{MatrixCell, MatrixCursor, PageCursor, SandboxPage, SnapshotPage};

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
#[derive(Clone, Debug, Deserialize, Serialize)]
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

/// A list of runs to execute under one concurrency bound.
///
/// The list, not the client's own scheduling: the control plane holds the
/// window, so every cell is a run the platform knows about and a client that
/// gives up cannot silently strand the rest.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvalBatchRequest {
    #[serde(default)]
    pub requests: Vec<CreateRunRequest>,
    #[serde(default)]
    pub options: BatchOptions,
}

/// The same workload, run several times.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvalRepetitionRequest {
    pub request: CreateRunRequest,
    #[serde(default = "one_repetition")]
    pub repetitions: u32,
    #[serde(default)]
    pub options: BatchOptions,
}

fn one_repetition() -> u32 {
    1
}

/// One matrix cell: a named combination of variables.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvalMatrixCell {
    /// The variable name and value, e.g. `{"model": "opus"}`.
    pub axis: BTreeMap<String, String>,
    pub request: CreateRunRequest,
}

/// A set of combinations to run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvalMatrixSpec {
    #[serde(default)]
    pub cells: Vec<EvalMatrixCell>,
    #[serde(default)]
    pub options: BatchOptions,
}

/// One matrix cell's outcome, kept whole.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalCellResult {
    pub axis: BTreeMap<String, String>,
    /// The run itself, not a summary of it: the task, setup and validation
    /// outcomes, the placement, the timings and the cleanup report are the
    /// evidence, and an evaluation that kept only a pass/fail would discard
    /// the part a reader needs.
    ///
    /// Absent when the cell was refused before it ran. The control plane
    /// reports such a cell beside the ones that did run rather than failing the
    /// whole request, so a client that insisted on a run for every cell would
    /// turn a partial result back into the error the server was avoiding.
    #[serde(default)]
    pub run: Option<Run>,
    /// Why this cell produced no run.
    #[serde(default)]
    pub error: Option<String>,
}

/// What a matrix produced.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalMatrixResult {
    pub matrix_id: Uuid,
    pub requested_at: DateTime<Utc>,
    pub max_parallel: usize,
    pub effective_parallel: usize,
    pub results: Vec<EvalCellResult>,
}

/// A tenant-scoped bounded page; aggregates describe this page, not the matrix.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalMatrixPage {
    pub matrix_id: Uuid,
    pub cells: Vec<MatrixCell>,
    pub successes: usize,
    pub by_axis: BTreeMap<String, (usize, usize)>,
    pub next: Option<MatrixCursor>,
}

/// How long the control plane gives a run that states no timeout of its own.
const DEFAULT_RUN_TIMEOUT_SECONDS: u64 = 600;

/// The ceiling on a run timeout, matching what the control plane clamps to.
const MAX_RUN_TIMEOUT_SECONDS: u64 = 86_400;

/// How long the control plane can hold a run in its durable queue before it
/// stops trying to claim one.
///
/// `POST /v1/runs` admits to the queue *before* it answers
/// (`run_queue::enqueue_and_wait`), and an unclaimed run stays `queued` until
/// `queue_deadline = now() + queue_timeout_seconds` before it even gets an
/// execution deadline (`crates/aiec-storage/src/run_queue.rs`). The queue
/// timeout is server configuration, so a client cannot read it from the task it
/// was handed: it takes the validated ceiling rather than the 300 s default,
/// because a deployment that raised `AIEC_RUN_QUEUE_TIMEOUT_SECONDS` would
/// otherwise still time out this client.
const MAX_RUN_QUEUE_WAIT_SECONDS: u64 = 86_400;

/// Slack added on top of the queue deadline and a run's own timeout before the
/// client stops waiting.
///
/// The API drives a run to a terminal state before it answers, so the wait for
/// `POST /v1/runs` *is* the run. A 60-second client timeout would abandon a
/// perfectly healthy ten-minute workload and report it as a transport failure.
///
/// It must also be *longer* than the server's own remaining budget, by enough
/// that the server always gives up first. The control plane adds a grace period
/// on top of the stated timeout for placement and teardown; a client that waits
/// less than that drops the connection while the server is still working, which
/// cancels the run's future mid-flight, leaves the row non-terminal with no
/// terminal event, and leaks the machine. Those are the runs that hold a machine
/// longest, so the slack is what the failure costs most.
///
/// With the queue ceiling above, the whole wait is checkable against
/// `crates/aiec-storage/src/run_queue.rs`:
///
/// ```text
/// queue_deadline  = now() + queue_timeout_seconds  (<= MAX_RUN_QUEUE_WAIT_SECONDS)
/// execution_secs  = timeout_seconds + 120          (PLACEMENT_GRACE_SECONDS)
/// answer         <= queue_deadline + execution_secs + the round trip
/// ```
///
/// The queue allowance is per run, so `eval_timeout` and `longest_run_budget`
/// multiply it by the cell count - which is what that wait has to cover anyway,
/// since each cell is queued and executed separately.
const RUN_RESPONSE_SLACK_SECONDS: u64 = 300;

/// The wait allowed for one run: the queue it may sit in, the execution it may
/// take, and the slack between them and the answer.
fn run_response_timeout(workload: &WorkloadSpec) -> Duration {
    let stated = workload
        .timeout_seconds
        .unwrap_or(DEFAULT_RUN_TIMEOUT_SECONDS)
        .clamp(30, MAX_RUN_TIMEOUT_SECONDS);
    Duration::from_secs(MAX_RUN_QUEUE_WAIT_SECONDS + stated + RUN_RESPONSE_SLACK_SECONDS)
}

/// How long a cancel may take: it transitions the run, then waits for each
/// machine it was holding to be destroyed.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(300);

/// Slack above a server-side bound, so the control plane always gives up first
/// and the client is the last thing to decide a call has failed.
const SERVER_OPERATION_SLACK_SECONDS: u64 = 120;

/// The longest exec the API accepts (`aiec_core::MAX_EXEC_SECONDS`).
const MAX_EXEC_SECONDS: u64 = 3_600;

/// The exec the API runs for `git_diff`, which it fixes at 60 seconds.
const GIT_DIFF_EXEC_SECONDS: u64 = 60;

/// The upload allowance the API gives an artifact write
/// (`artifact_gc::MAX_ARTIFACT_UPLOAD_SECONDS`).
const ARTIFACT_UPLOAD_SECONDS: u64 = 300;

/// Provisioning has no small server-side deadline: it clones the workload's
/// repository, pulls layers and runs setup commands inside the machine, all
/// before the control plane answers. A clone of a large repository alone is
/// minutes, so this is an allowance rather than a bound the API enforces.
const PROVISION_SECONDS: u64 = 900;

/// The wait an exec is given: the command's own stated timeout, which the API
/// accepts up to `MAX_EXEC_SECONDS`, plus slack.
///
/// The client's default is 60 seconds, which is the right size for the
/// control-plane verbs and wrong for anything that runs inside a machine. An
/// `exec` the API happily ran for an hour used to be abandoned at 60 seconds
/// by the caller, with the command still running in a sandbox the caller had
/// been told was broken.
fn exec_timeout(request: &ExecRequest) -> Duration {
    Duration::from_secs(
        request.timeout_seconds.clamp(1, MAX_EXEC_SECONDS) + SERVER_OPERATION_SLACK_SECONDS,
    )
}

/// The wait provisioning is given. `POST /v1/sandboxes` answers only after the
/// machine exists, its repository is cloned and its setup commands have run, so
/// it is bounded by the deployment's own work rather than by the 60 seconds the
/// client defaults to for control-plane verbs.
fn provision_timeout() -> Duration {
    Duration::from_secs(PROVISION_SECONDS + SERVER_OPERATION_SLACK_SECONDS)
}

/// The wait a snapshot capture is given: a capture is the work the runtime does
/// to freeze the machine plus the artifact upload allowance on top of it.
fn snapshot_timeout() -> Duration {
    Duration::from_secs(ARTIFACT_UPLOAD_SECONDS * 2 + SERVER_OPERATION_SLACK_SECONDS)
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

/// The wait allowed for a whole evaluation.
///
/// The server can lower concurrency after admission. Until it advertises that
/// window before the blocking response, only the serial bound covers every cell.
///
/// The queue allowance inside `per_run` is per run, so this multiplies it by the
/// cell count - which is what the evaluation has to cover anyway, since each cell
/// is queued and executed on its own.
fn eval_timeout(per_run: Duration, cells: usize) -> Duration {
    per_run.saturating_mul(u32::try_from(cells.max(1)).unwrap_or(u32::MAX))
}

/// The longest single-run wait in a set, which is the one the evaluation as a
/// whole has to accommodate. An empty set falls back to the default budget
/// rather than to a wait of nothing.
fn longest_run_budget<'a>(workloads: impl Iterator<Item = &'a WorkloadSpec>) -> Duration {
    workloads
        .map(run_response_timeout)
        .max()
        .unwrap_or_else(|| run_response_timeout(&WorkloadSpec::default()))
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

/// The fencing sentences the store emits when a sandbox's worker resynced its
/// lease between a request being issued and applied.
///
/// These live here rather than in each client because they are a wire contract
/// between the storage layer and every consumer of it. Duplicated as string
/// literals per crate, a wording change in the store silently stops every
/// destroy retry firing again - a machine left running to its TTL, reported to
/// the caller as a cleanup failure. One list, matched by every consumer.
pub const LEASE_RESYNC_MESSAGES: [&str; 3] = [
    "worker lease generation or status changed",
    "sandbox lease generation does not match the control plane",
    "stale sandbox lease generation",
];

/// Whether a conflict message is the lease resync race rather than a refusal.
///
/// The race clears by itself: the identical call a moment later succeeds. A
/// refusal does not, and retrying one reports the same refusal repeatedly
/// while achieving nothing.
pub fn is_lease_resync_conflict(message: &str) -> bool {
    LEASE_RESYNC_MESSAGES.contains(&message)
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
    /// Builds a client bound to one control plane.
    ///
    /// Redirects are returned as errors rather than followed: even when reqwest
    /// strips cross-origin Authorization, a 307/308 can disclose the request
    /// body and substitute an unrelated server's response.
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none());
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
                .json(request)
                .timeout(provision_timeout()),
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
                .json(&body)
                .timeout(provision_timeout()),
        )
        .await
    }
    /// Reads one page of the caller's sandboxes, newest first.
    ///
    /// The response is a page rather than the tenant's whole list, so the
    /// result carries the cursor its successor starts at. A caller that wants
    /// every sandbox follows `next` until it is `None`; a caller that ignores
    /// it has stopped at a page boundary it chose, not had its list silently
    /// truncated.
    pub async fn list_sandboxes_page(&self, limit: u32) -> Result<SandboxPage, ClientError> {
        self.send(
            self.request(reqwest::Method::GET, "/v1/sandboxes")
                .query(&[("limit", limit.to_string())]),
        )
        .await
    }

    /// Reads the page that starts where `after` says.
    ///
    /// The cursor goes through `.query` rather than into a formatted path: an
    /// RFC 3339 instant ends in `+00:00`, and an unencoded `+` in a query
    /// string decodes as a space. Built by hand the timestamp arrives as
    /// `2026-10-03T12:00:00 00:00`, which the route cannot parse, so every
    /// page past the first would be refused for a cursor the caller never got
    /// wrong.
    pub async fn list_sandboxes_after(
        &self,
        limit: u32,
        after: &PageCursor,
    ) -> Result<SandboxPage, ClientError> {
        self.send(self.request(reqwest::Method::GET, "/v1/sandboxes").query(&[
            ("limit", limit.to_string()),
            ("after_created_at", after.created_at.to_rfc3339()),
            ("after_id", after.id.to_string()),
        ]))
        .await
    }

    /// Reads every page of the caller's sandboxes, newest first.
    ///
    /// This is the call that wants the whole list and is prepared to hold it.
    /// Each request is bounded, so the cost is the history the caller asked for
    /// rather than one response the control plane had to build in full.
    pub async fn list_all_sandboxes(&self, limit: u32) -> Result<Vec<Sandbox>, ClientError> {
        let mut all = Vec::new();
        let mut after: Option<PageCursor> = None;
        let mut seen: Vec<(DateTime<Utc>, Uuid)> = Vec::new();
        loop {
            let page = match &after {
                Some(cursor) => self.list_sandboxes_after(limit, cursor).await?,
                None => self.list_sandboxes_page(limit).await?,
            };
            // The walk is bounded by the server saying it is done, so it needs
            // its own termination guarantee. A control plane that keeps
            // offering a cursor without advancing past it turns this into an
            // unbounded fetch loop -- the same defect the paging was added to
            // stop, one layer down, and it never ends on its own.
            let next = page.next;
            if let Some(cursor) = next {
                let position = (cursor.created_at, cursor.id);
                if seen.contains(&position) {
                    return Err(ClientError::Decode(format!(
                        "GET /v1/sandboxes returned the cursor {} twice; \
                         the page walk was stopped rather than repeated",
                        cursor.id
                    )));
                }
                if page.sandboxes.is_empty() {
                    return Err(ClientError::Decode(format!(
                        "GET /v1/sandboxes returned an empty page and a cursor ({}); \
                         there is nothing to advance past",
                        cursor.id
                    )));
                }
                seen.push(position);
            }
            all.extend(page.sandboxes);
            match next {
                Some(cursor) => after = Some(cursor),
                None => return Ok(all),
            }
        }
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
                .json(request)
                .timeout(exec_timeout(request)),
        )
        .await
    }
    pub async fn git_diff(&self, id: Uuid) -> Result<serde_json::Value, ClientError> {
        self.send(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{id}/git/diff"),
            )
            .json(&serde_json::json!({}))
            .timeout(Duration::from_secs(
                GIT_DIFF_EXEC_SECONDS + SERVER_OPERATION_SLACK_SECONDS,
            )),
        )
        .await
    }
    /// Asks the control plane whether a high-risk operation may proceed.
    ///
    /// The answer is the control plane's; the caller treats an unreachable
    /// service as no answer rather than as a yes.
    pub async fn guard_approval(
        &self,
        sandbox_id: Uuid,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        self.send(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{sandbox_id}/guard/approval"),
            )
            .json(body),
        )
        .await
    }
    pub async fn put_file(&self, id: Uuid, request: &PutFileRequest) -> Result<(), ClientError> {
        self.send_empty(
            self.request(reqwest::Method::PUT, &format!("/v1/sandboxes/{id}/files"))
                .json(request)
                .timeout(Duration::from_secs(
                    ARTIFACT_UPLOAD_SECONDS + SERVER_OPERATION_SLACK_SECONDS,
                )),
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
            .json(&serde_json::json!({}))
            .timeout(snapshot_timeout()),
        )
        .await
    }
    /// Reads one bounded page of a sandbox's snapshots, newest first.
    pub async fn list_snapshots_page(
        &self,
        id: Uuid,
        limit: u32,
    ) -> Result<SnapshotPage, ClientError> {
        self.send(
            self.request(
                reqwest::Method::GET,
                &format!("/v1/sandboxes/{id}/snapshots"),
            )
            .query(&[("limit", limit.to_string())]),
        )
        .await
    }

    /// Reads the snapshot page that starts where `after` says.
    ///
    /// Structured query encoding for the same reason as the sandbox cursor: an
    /// RFC 3339 instant ends in `+00:00` and an unencoded `+` decodes as a
    /// space, so a hand-built query string would be refused as unparseable on
    /// every page after the first.
    pub async fn list_snapshots_after(
        &self,
        id: Uuid,
        limit: u32,
        after: &PageCursor,
    ) -> Result<SnapshotPage, ClientError> {
        self.send(
            self.request(
                reqwest::Method::GET,
                &format!("/v1/sandboxes/{id}/snapshots"),
            )
            .query(&[
                ("limit", limit.to_string()),
                ("after_created_at", after.created_at.to_rfc3339()),
                ("after_id", after.id.to_string()),
            ]),
        )
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
            .json(request)
            .timeout(provision_timeout()),
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
    ///
    /// One page. `after` is the last run of the previous page and pages
    /// strictly past it on `(requested_at, id)`, so a caller that stops at a
    /// page limit can say which run it stopped after rather than discovering
    /// the ceiling by counting. `None` is the first page.
    pub async fn list_runs(
        &self,
        state: Option<RunState>,
        limit: Option<u32>,
        after: Option<MatrixCursor>,
    ) -> Result<Vec<Run>, ClientError> {
        let mut query = Vec::new();
        if let Some(state) = state {
            query.push(format!("state={}", urlencode(state.as_str())));
        }
        if let Some(limit) = limit {
            query.push(format!("limit={limit}"));
        }
        if let Some(after) = after {
            query.push(format!(
                "after_requested_at={}",
                urlencode(&after.requested_at.to_rfc3339())
            ));
            query.push(format!("after_id={}", urlencode(&after.id.to_string())));
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

    /// Runs a list of workloads under one concurrency bound, on the control
    /// plane.
    ///
    /// The window is the server's, not the client's: every cell is a run the
    /// platform knows about, and the answer comes back once they have all
    /// settled, which is why the wait is sized for the whole batch.
    pub async fn eval_batch(&self, request: &EvalBatchRequest) -> Result<Vec<Run>, ClientError> {
        check_batch_parallelism(request.options.max_parallel)?;
        let timeout = eval_timeout(
            longest_run_budget(request.requests.iter().map(|cell| &cell.workload)),
            request.requests.len(),
        );
        self.send(
            self.request(reqwest::Method::POST, "/v1/eval/batch")
                .timeout(timeout)
                .json(request),
        )
        .await
    }

    /// Runs one workload several times, each repetition on its own machine.
    pub async fn eval_repetitions(
        &self,
        request: &EvalRepetitionRequest,
    ) -> Result<Vec<Run>, ClientError> {
        check_batch_parallelism(request.options.max_parallel)?;
        if request.repetitions == 0 {
            return Err(ClientError::Configuration(
                "repetitions must be at least 1".into(),
            ));
        }
        let timeout = eval_timeout(
            run_response_timeout(&request.request.workload),
            request.repetitions as usize,
        );
        self.send(
            self.request(reqwest::Method::POST, "/v1/eval/repetitions")
                .timeout(timeout)
                .json(request),
        )
        .await
    }

    /// Expands and runs a matrix, reporting every cell with its own run.
    pub async fn eval_matrix(
        &self,
        spec: &EvalMatrixSpec,
    ) -> Result<EvalMatrixResult, ClientError> {
        check_batch_parallelism(spec.options.max_parallel)?;
        let timeout = eval_timeout(
            longest_run_budget(spec.cells.iter().map(|cell| &cell.request.workload)),
            spec.cells.len(),
        );
        self.send(
            self.request(reqwest::Method::POST, "/v1/eval/matrix")
                .timeout(timeout)
                .json(spec),
        )
        .await
    }

    /// Recovers one bounded page without loading every run in the matrix.
    pub async fn eval_matrix_page(
        &self,
        matrix: Uuid,
        limit: u32,
        after: Option<MatrixCursor>,
    ) -> Result<EvalMatrixPage, ClientError> {
        let mut query = vec![("limit", limit.to_string())];
        if let Some(after) = after {
            query.push(("after_requested_at", after.requested_at.to_rfc3339()));
            query.push(("after_id", after.id.to_string()));
        }
        self.send(
            self.request(reqwest::Method::GET, &format!("/v1/eval/matrix/{matrix}"))
                .query(&query),
        )
        .await
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
/// Percent-encodes everything outside the unreserved set, for a single path
/// segment.
///
/// The old version mapped each byte to its own `String`, so a path cost one
/// allocation per character plus a `format!` per reserved one - and artifact
/// names are absolute sandbox paths like `/workspace/report.tar.gz`, so nearly
/// every byte paid twice. One pass counts the bytes that need escaping, which
/// sizes the result exactly (they are known to be three bytes each) and means
/// the `String` is built once.
fn urlencode(value: &str) -> String {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";
    let escaped = value
        .bytes()
        .filter(
            |b| !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~'),
        )
        .count();
    let mut out = String::with_capacity(value.len() + 2 * escaped);
    for byte in value.bytes() {
        if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    /// The client's patience must exceed the server's budget, queue included.
    ///
    /// A client that gives up first does not merely fail: it drops the
    /// connection, the server's `execute` future is cancelled mid-flight, and
    /// the run is left non-terminal holding a machine. Because that happens
    /// exactly when a run uses its whole budget, it takes down the runs that
    /// hold compute longest - the opposite of what a shorter timeout buys.
    #[test]
    fn the_client_outlasts_the_servers_own_budget() {
        // Mirrors the control plane's PLACEMENT_GRACE_SECONDS and the
        // `1..=86_400` check on RunQueueLimits::queue_timeout_seconds.
        // Duplicated on purpose rather than imported: if the server ever
        // changes either bound, this assertion should fail loudly here instead
        // of both sides moving together and nobody noticing the relationship.
        const SERVER_PLACEMENT_GRACE_SECONDS: u64 = 120;
        const SERVER_MAX_QUEUE_WAIT_SECONDS: u64 = 86_400;
        const _: () = assert!(
            RUN_RESPONSE_SLACK_SECONDS > SERVER_PLACEMENT_GRACE_SECONDS,
            "the client gives up before the server does: a client that drops the \
             connection mid-run cancels the server's future and leaks the machine"
        );
        const _: () = assert!(
            MAX_RUN_QUEUE_WAIT_SECONDS >= SERVER_MAX_QUEUE_WAIT_SECONDS,
            "the client waits less than the queue can hold a run, so a run that \
             waits its whole queue deadline times out with no run id while the \
             server keeps executing it"
        );
        let workload = WorkloadSpec {
            timeout_seconds: Some(600),
            ..WorkloadSpec::default()
        };
        let wait = run_response_timeout(&workload).as_secs();
        assert_eq!(
            wait,
            SERVER_MAX_QUEUE_WAIT_SECONDS + 600 + RUN_RESPONSE_SLACK_SECONDS
        );
        // The queue is spent before execution begins, so the whole server
        // budget - the deadline it may sit queued for, then the execution it
        // may take once claimed - has to fit inside the wait.
        assert!(
            wait > SERVER_MAX_QUEUE_WAIT_SECONDS + 600 + SERVER_PLACEMENT_GRACE_SECONDS,
            "a run queued for {SERVER_MAX_QUEUE_WAIT_SECONDS}s then executed for \
            600s would still be running when the client gives up"
        );
    }

    /// The same failure on the sandbox verbs.
    ///
    /// The client default of 60 seconds is sized for the control-plane verbs
    /// and is shorter than work the API explicitly accepts: an exec may state
    /// 3600 seconds, `git_diff` runs a 60-second exec server-side, and
    /// provisioning answers only after the machine is built. Every one of those
    /// used to inherit the 60-second default, so the client gave up while the
    /// command kept running inside a sandbox the caller had been told was
    /// broken.
    #[test]
    fn a_machine_bound_verb_outlasts_the_clients_default() {
        // Mirrors `aiec_core::MAX_EXEC_SECONDS`, the API's own `validate_exec`
        // ceiling. Duplicated on purpose, as in the run timeout above.
        const SERVER_MAX_EXEC_SECONDS: u64 = 3_600;
        const CLIENT_DEFAULT_SECONDS: u64 = 60;

        let longest = ExecRequest {
            command: vec!["pytest".into()],
            working_directory: Some("/workspace".into()),
            environment: BTreeMap::new(),
            timeout_seconds: SERVER_MAX_EXEC_SECONDS,
            stdin: None,
        };
        assert!(
            exec_timeout(&longest).as_secs() > SERVER_MAX_EXEC_SECONDS,
            "the client abandons an exec the API is still running"
        );

        // A caller that states its own budget gets that budget, not the
        // client's default and not the API's ceiling.
        let short = ExecRequest {
            timeout_seconds: CLIENT_DEFAULT_SECONDS,
            ..longest.clone()
        };
        assert_eq!(
            exec_timeout(&short).as_secs(),
            CLIENT_DEFAULT_SECONDS + SERVER_OPERATION_SLACK_SECONDS
        );
        assert!(
            exec_timeout(&short) < exec_timeout(&longest),
            "the exec budget no longer follows the timeout the caller stated"
        );

        // A zero timeout is not a budget at all: `aiec-core` refuses the
        // request outright rather than substituting a default, so the wait is
        // the clamped minimum plus slack. Anything derived from zero itself
        // would be a zero-length budget for a request that is answered in
        // microseconds by the refusal.
        let zero = ExecRequest {
            timeout_seconds: 0,
            ..longest.clone()
        };
        assert_eq!(
            exec_timeout(&zero).as_secs(),
            1 + SERVER_OPERATION_SLACK_SECONDS,
            "a refused request must still leave room for the refusal to arrive"
        );

        for (what, wait) in [
            (
                "git_diff",
                Duration::from_secs(GIT_DIFF_EXEC_SECONDS + SERVER_OPERATION_SLACK_SECONDS),
            ),
            (
                "put_file",
                Duration::from_secs(ARTIFACT_UPLOAD_SECONDS + SERVER_OPERATION_SLACK_SECONDS),
            ),
            ("create_snapshot", snapshot_timeout()),
            ("create_sandbox", provision_timeout()),
            ("restore_snapshot", provision_timeout()),
        ] {
            assert!(
                wait.as_secs() > CLIENT_DEFAULT_SECONDS,
                "{what} inherits the 60s client default, which is shorter than \
                 the work the API accepts for it"
            );
        }
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

    /// A permanent redirect this stub answers with instead of a result.
    ///
    /// `location` names a different listener, so a client that follows it is
    /// talking to an origin the control plane never vouched for.
    #[derive(Clone)]
    struct Redirect {
        status: u16,
        location: String,
    }

    /// The path a redirecting stub points its `Location` at. No other stub
    /// route answers it, so a request arriving there is unambiguously the
    /// client having followed a redirect.
    const REDIRECT_PATH: &str = "/v1/sandboxes/redirect";

    /// The error document the redirect carries: the envelope the API puts on
    /// an unsuccessful status, so a refused redirect is reported through the
    /// ordinary `ClientError::Api` path instead of as a decode failure.
    fn redirect_error_body() -> Value {
        serde_json::json!({
            "error": {
                "code": "redirect_refused",
                "message": "this origin does not redirect",
                "request_id": MISSING_RUN_ID,
            }
        })
    }

    #[derive(Clone)]
    struct Stub {
        seen: Arc<Mutex<Vec<Seen>>>,
        in_flight: Arc<AtomicUsize>,
        peak_in_flight: Arc<AtomicUsize>,
        slow: bool,
        paging: SandboxPaging,
        redirect: Option<Redirect>,
    }

    /// How `/v1/sandboxes` behaves when the client keeps walking. A well
    /// behaved control plane stops handing out cursors; these are the two ways
    /// it can fail to, and each is a loop a client without a termination guard
    /// never leaves.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SandboxPaging {
        /// Two distinct pages, the second terminal.
        Finite,
        /// The same cursor on every page, forever.
        RepeatsCursor,
        /// No rows at all, but still a successor to follow.
        EmptyWithCursor,
    }

    impl Stub {
        fn new() -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
                in_flight: Arc::new(AtomicUsize::new(0)),
                peak_in_flight: Arc::new(AtomicUsize::new(0)),
                slow: false,
                paging: SandboxPaging::Finite,
                redirect: None,
            }
        }

        /// A stub whose sandbox list misbehaves the way a broken control plane
        /// would, for the tests that exercise the client's own guard.
        fn paging(mode: SandboxPaging) -> Self {
            Self {
                paging: mode,
                ..Self::new()
            }
        }

        /// A stub whose answers are a permanent redirect to `location`.
        fn redirecting(status: u16, location: impl Into<String>) -> Self {
            Self {
                redirect: Some(Redirect {
                    status,
                    location: location.into(),
                }),
                ..Self::new()
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
            matrix_cell: None,
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

    /// One sandbox page: `page` is 1-based, and only the first names a
    /// successor.
    fn sandbox_page(page: usize) -> Value {
        let ids = [
            "0192f2c1-6f0a-7b1e-8a1c-2f9a4d0e5b31",
            "0192f2c1-6f0a-7b1e-8a1c-2f9a4d0e5b32",
        ];
        let sandbox = |id: &str, created_at: &str| {
            serde_json::json!({
                "id": id,
                "tenant_id": "0192f2c1-6f0a-7b1e-8a1c-2f9a4d0e5b33",
                "image_id": "alpine:3.21",
                "state": "destroyed",
                "runtime": "docker",
                "cpu": 1,
                "memory_mb": 128,
                "disk_mb": 512,
                "timeout_seconds": 60,
                "network": { "enabled": false },
                "created_at": created_at,
                "updated_at": created_at,
            })
        };
        match page {
            1 => serde_json::json!({
                "sandboxes": [sandbox(ids[0], "2026-10-03T12:00:00Z")],
                "next": { "created_at": "2026-10-03T12:00:00Z", "id": ids[0] },
            }),
            _ => serde_json::json!({
                "sandboxes": [sandbox(ids[1], "2026-10-02T12:00:00Z")],
                "next": null,
            }),
        }
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

        // Answered before the routes below, so a redirecting stub redirects
        // whatever it is asked rather than only one path. The request is
        // recorded first, so a test can still see exactly what the origin was
        // asked and what it refused to forward.
        if let Some(redirect) = &stub.redirect {
            return Response::builder()
                .status(redirect.status)
                .header("location", redirect.location.as_str())
                .header("content-type", "application/json")
                .body(Body::from(redirect_error_body().to_string()))
                .unwrap_or_else(|_| Response::new(Body::empty()));
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
            // The evaluation routes answer with the runs and nothing else: one
            // per cell that was asked for, exactly as the API returns them.
            "/v1/eval/batch" | "/v1/eval/repetitions" => {
                let cells = if path == "/v1/eval/batch" {
                    body.get("requests")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len)
                } else {
                    body.get("repetitions").and_then(Value::as_u64).unwrap_or(0) as usize
                };
                let runs: Vec<Value> = (0..cells)
                    .map(|_| run_document(RunState::Succeeded))
                    .collect();
                (AxumStatus::OK, serde_json::json!(runs))
            }
            "/v1/eval/matrix" => {
                let results: Vec<Value> = body["cells"]
                    .as_array()
                    .map(|cells| {
                        cells
                            .iter()
                            .map(|cell| {
                                serde_json::json!({
                                    "axis": cell["axis"],
                                    "run": run_document(RunState::Succeeded),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                (
                    AxumStatus::OK,
                    serde_json::json!({
                        "matrix_id": Uuid::now_v7(),
                        "requested_at": Utc::now().to_rfc3339(),
                        "max_parallel": body["options"]["max_parallel"],
                        "results": results,
                    }),
                )
            }
            // Two pages, newest first, the second carrying no successor. A
            // fixed sequence rather than one page repeated: a client that
            // trusted its own count instead of the page's `next` would then be
            // visible, and so would one that returns only the first page.
            "/v1/sandboxes" => {
                let served = stub
                    .seen
                    .lock()
                    .await
                    .iter()
                    .filter(|entry| entry.path == "/v1/sandboxes")
                    .count();
                let page = match stub.paging {
                    SandboxPaging::Finite => sandbox_page(served),
                    SandboxPaging::RepeatsCursor => sandbox_page(1),
                    SandboxPaging::EmptyWithCursor => serde_json::json!({
                        "sandboxes": [],
                        "next": sandbox_page(1)["next"],
                    }),
                };
                (AxumStatus::OK, page)
            }
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

    /// A cursor's timestamp carries a `+`, and `+` in a query string decodes as
    /// a space. A client that interpolates the instant into the path therefore
    /// asks for a timestamp the route cannot parse, and every page after the
    /// first fails for a cursor the caller never got wrong.
    ///
    /// This reads the raw query the way a server does rather than trusting the
    /// client meant to encode it: `+` and `:` are decoded back and the instant is
    /// parsed. A hand-built path fails here; `.query` passes.
    #[tokio::test]
    async fn a_sandbox_cursor_put_on_the_wire_survives_the_round_trip() {
        let stub = Stub::new();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");

        let cursor = PageCursor {
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0)
                .expect("a valid instant")
                .with_timezone(&Utc),
            id: Uuid::from_u128(0x0192_f2c1_6f0a_7b1e_8a1c_2f9a_4d0e_5b31),
        };
        client
            .list_sandboxes_after(25, &cursor)
            .await
            .expect("a page");

        let seen = stub.seen.lock().await;
        let query = seen.last().expect("a request was recorded").query.clone();
        drop(seen);
        assert!(
            !query.contains('+'),
            "a bare + in a query string decodes as a space: {query}"
        );
        let decoded: Vec<(String, String)> = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(key, value)| {
                (
                    key.to_owned(),
                    value
                        .replace("%3A", ":")
                        .replace("%2B", "+")
                        .replace("%3D", "="),
                )
            })
            .collect();
        let value_of = |key: &str| {
            decoded
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| panic!("{key} is missing from {query}"))
        };
        assert_eq!(value_of("limit"), "25");
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(&value_of("after_created_at"))
                .expect("the cursor instant survives the wire")
                .timestamp(),
            cursor.created_at.timestamp(),
            "the instant the server decodes must be the instant the client meant"
        );
        assert_eq!(value_of("after_id"), cursor.id.to_string());
        drop(serving);
    }

    /// Walking the whole history has to actually walk: one page at a time, each
    /// one starting where the last stopped, until the page says there is no
    /// next. A client that returns the first page regardless would look
    /// identical to one that works whenever the tenant's history fits in a
    /// single page.
    #[tokio::test]
    async fn reading_every_sandbox_follows_the_cursor_until_the_page_says_it_is_the_last() {
        let stub = Stub::new();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");

        // Two pages are on offer and the second says it is the last, so a
        // client that asks a third time has not believed the page.
        let walked = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.list_all_sandboxes(50),
        )
        .await
        .expect("the walk terminates")
        .expect("a page");
        assert_eq!(
            walked
                .iter()
                .map(|sandbox| sandbox.id.to_string())
                .collect::<Vec<_>>(),
            vec![
                "0192f2c1-6f0a-7b1e-8a1c-2f9a4d0e5b31".to_owned(),
                "0192f2c1-6f0a-7b1e-8a1c-2f9a4d0e5b32".to_owned(),
            ],
            "the whole history, newest first"
        );

        let seen = stub.seen.lock().await;
        let pages: Vec<String> = seen
            .iter()
            .filter(|entry| entry.path == "/v1/sandboxes")
            .map(|entry| entry.query.clone())
            .collect();
        drop(seen);
        assert_eq!(
            pages.len(),
            2,
            "one request per page, and it stops at the last"
        );
        assert!(
            !pages[0].contains("after_created_at"),
            "the first page has no cursor to follow"
        );
        assert!(
            pages[1].contains("after_created_at") && pages[1].contains("after_id"),
            "the second page must carry the cursor the first one named: {}",
            pages[1]
        );
        drop(serving);
    }

    /// The walk ends when the server says it has ended. A control plane that
    /// keeps naming a successor must not be able to keep this call running
    /// forever: the paging exists to bound the work, and a client with no
    /// termination guarantee reintroduces the unbounded read one layer down.
    #[tokio::test]
    async fn a_control_plane_that_repeats_a_sandbox_cursor_cannot_walk_forever() {
        let stub = Stub::paging(SandboxPaging::RepeatsCursor);
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.list_all_sandboxes(50),
        )
        .await
        .expect("the walk stops instead of running until the timeout");
        let message = outcome
            .expect_err("a repeated cursor is not a result")
            .to_string();
        assert!(
            message.contains("twice"),
            "the refusal must name the cause: {message}"
        );
        drop(serving);
    }

    /// An empty page carrying a cursor is the other way round the same loop:
    /// there is no row to advance past, so following it again returns the same
    /// emptiness. A page that is empty and still claims a successor is a
    /// contradiction, and repeating it is how a walk hangs.
    #[tokio::test]
    async fn an_empty_sandbox_page_with_a_cursor_is_refused_not_repeated() {
        let stub = Stub::paging(SandboxPaging::EmptyWithCursor);
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.list_all_sandboxes(50),
        )
        .await
        .expect("the walk stops instead of running until the timeout");
        let message = outcome
            .expect_err("an empty page is not a result")
            .to_string();
        assert!(
            message.contains("empty page"),
            "the refusal must name the cause: {message}"
        );
        let pages = stub
            .seen
            .lock()
            .await
            .iter()
            .filter(|entry| entry.path == "/v1/sandboxes")
            .count();
        assert_eq!(pages, 1, "the contradiction is caught on the first page");
        drop(serving);
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
            guard: None,
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

    /// A repetition count of zero and a bound of zero are both ways of
    /// evaluating nothing, and both are refused here rather than being sent
    /// and answered with an empty success.
    #[tokio::test]
    async fn an_evaluation_that_would_run_nothing_is_refused_before_it_is_sent() {
        let stub = Stub::new();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let client = AIecClient::new(&url, "af_live_key").expect("a client");
        let base = EvalRepetitionRequest {
            request: request(&["true"]),
            repetitions: 0,
            options: BatchOptions { max_parallel: 2 },
        };

        assert!(client.eval_repetitions(&base).await.is_err());
        assert!(
            client
                .eval_repetitions(&EvalRepetitionRequest {
                    repetitions: 3,
                    ..base.clone()
                })
                .await
                .is_ok(),
            "three repetitions of the same workload is the ordinary case"
        );
        assert!(
            client
                .eval_batch(&EvalBatchRequest {
                    requests: vec![request(&["true"])],
                    options: BatchOptions { max_parallel: 0 },
                })
                .await
                .is_err(),
            "a bound of zero cannot run anything"
        );
        let paths: Vec<String> = stub
            .requests()
            .await
            .into_iter()
            .map(|seen| seen.path)
            .collect();
        assert_eq!(
            paths,
            vec!["/v1/eval/repetitions"],
            "only the request that could run something was sent"
        );
        serving.abort();
    }

    /// The slowest cell is the one the whole evaluation has to accommodate.
    #[test]
    fn an_evaluation_waits_for_its_slowest_cell() {
        let short = WorkloadSpec {
            timeout_seconds: Some(60),
            ..Default::default()
        };
        let long = WorkloadSpec {
            timeout_seconds: Some(3600),
            ..Default::default()
        };
        // Literal seconds, not the constants the implementation adds: this is
        // where the arithmetic is pinned, so a reader can check 86_400 (queue
        // ceiling) + stated timeout + 300 (slack) against run_queue.rs. The
        // queue allowance is per run, so it appears in every cell's share of an
        // evaluation's wait.
        assert_eq!(
            longest_run_budget([&short, &long].into_iter()).as_secs(),
            90_300,
            "a fast cell does not shorten the wait for a slow one"
        );
        assert_eq!(
            longest_run_budget([&short].into_iter()).as_secs(),
            86_760,
            "a cell's own budget is waited out, after the queue it may sit in, \
             plus the slack the server needs"
        );
    }

    // Exercise reqwest's real redirect decision, including writes with
    // confidential environment/stdin bytes, without contacting the target.
    #[tokio::test]
    async fn redirects_preserve_origin_errors_without_contacting_target() {
        let exec = ExecRequest {
            command: vec!["pytest".into(), "-q".into()],
            working_directory: Some("/workspace".into()),
            environment: BTreeMap::from([(
                "AIEC_TEST_TOKEN".to_owned(),
                "synthetic-secret-value".to_owned(),
            )]),
            timeout_seconds: 60,
            stdin: Some("synthetic-stdin-bytes".to_owned()),
        };

        for status in [301u16, 302, 303, 307, 308] {
            // Distinct loopback ports are distinct origins.
            let elsewhere = Stub::new();
            let (elsewhere_url, elsewhere_serving) = stub_control_plane(elsewhere.clone()).await;
            let origin = Stub::redirecting(status, format!("{elsewhere_url}{REDIRECT_PATH}"));
            let (origin_url, origin_serving) = stub_control_plane(origin.clone()).await;
            let client = AIecClient::new(&origin_url, "af_live_key").expect("a client");
            let sandbox = Uuid::now_v7();

            let read = client
                .get_sandbox(sandbox)
                .await
                .expect_err("a redirect is not a sandbox");
            let write = client
                .exec(sandbox, &exec)
                .await
                .expect_err("a redirect is not an exec result");

            for (verb, error) in [("GET", read), ("POST", write)] {
                let ClientError::Api {
                    status: reported,
                    code,
                    ..
                } = &error
                else {
                    panic!("{verb} {status} must reach the caller as an API error, got {error:?}");
                };
                assert_eq!(
                    reported.as_u16(),
                    status,
                    "{verb} {status} is reported as the status it was, not as the \
                     result of wherever it pointed"
                );
                assert_eq!(
                    code, "redirect_refused",
                    "{verb} {status} must keep the API error the origin returned"
                );
            }

            assert!(
                elsewhere.requests().await.is_empty(),
                "{status}: the redirect target was contacted"
            );

            origin_serving.abort();
            elsewhere_serving.abort();
        }
    }
}
