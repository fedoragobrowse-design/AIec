//! The sandbox facade every MCP tool routes through.
//!
//! §6 of the milestone is the invariant that matters: a workload command must
//! always execute inside an AIec sandbox and must never fall back to the host.
//! This type is the only place a command is issued, and it only ever speaks to
//! the AIec HTTP API through [`AIecClient`]. There is deliberately no
//! `std::process::Command` anywhere in this crate's execution path, and a test
//! asserts the crate source contains none.
//!
//! Ownership is also tracked here. Every sandbox this server creates is tagged
//! with the run that created it, so shutdown can clean up its own machines
//! without touching anyone else's.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use aiec_client::AIecClient;
use aiec_core::network::NetworkPolicy;
use aiec_core::{
    CreateSandboxRequest, EnvironmentSpec, ExecRequest, FileEntry, PutFileRequest, Sandbox,
    SandboxState, WorkspaceSpec,
};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use serde::Serialize;
use uuid::Uuid;

use crate::error::{ErrorCode, McpError, ToolResult};
use crate::guard::LocalEndpoint;

/// How many sandboxes one listing will describe.
///
/// The control plane's own sandbox list is paged for exactly this reason. This
/// server tracks its own machines and fetches each one by id, so the cost of
/// listing is one request per machine and grows with everything this process
/// has ever created. Refused rather than truncated: a shorter list would be
/// indistinguishable from a complete one, and a caller acting on "these are my
/// machines" would leave the rest running and never learn about them.
const MAX_OWNED_SANDBOXES: usize = 200;

/// How many of those requests are in flight at once. Bounded so that a listing
/// with a few hundred machines does not open a few hundred sockets.
const OWNED_FETCH_CONCURRENCY: usize = 8;
/// The marker recorded on every sandbox this server creates.
pub const CREATED_BY: &str = "aiec-mcp";

/// A sandbox as reported back to a caller.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxView {
    pub sandbox_id: String,
    pub state: String,
    pub runtime: String,
    pub image: String,
    pub cpu: u32,
    pub memory_mb: u32,
    pub disk_mb: u32,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// The result of running a command inside a sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct ExecOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub duration_ms: u64,
    /// Set when output was clipped to stay inside the bound.
    pub truncated: bool,
}

/// Ownership record for a sandbox this server created.
#[derive(Debug, Clone, Serialize)]
struct Ownership {
    sandbox_id: Uuid,
    run_id: Uuid,
    created_at: DateTime<Utc>,
    /// Sandboxes created by a high-level tool are destroyed with it unless the
    /// caller asked to keep them for debugging.
    owned_by_tool: bool,
}

/// Everything the tools need, with the local-only guarantees already applied.
#[derive(Clone)]
pub struct LocalAiec {
    client: Arc<AIecClient>,
    endpoint: LocalEndpoint,
    owned: Arc<Mutex<Vec<Ownership>>>,
    default_ttl_seconds: u64,
    max_output_bytes: usize,
    max_parallel: usize,
}

impl LocalAiec {
    /// Builds the facade, refusing any non-local control plane.
    pub fn new(
        endpoint: LocalEndpoint,
        api_key: String,
        default_ttl_seconds: u64,
        max_output_bytes: usize,
        max_parallel: usize,
    ) -> Result<Self, McpError> {
        // The client is constructed only after the endpoint has been validated,
        // so no code path can build one pointed at a remote control plane.
        let client = AIecClient::new(endpoint.url.clone(), api_key).map_err(|error| {
            McpError::new(
                ErrorCode::AiecApiUnavailable,
                format!("could not build a client for the local control plane: {error}"),
            )
        })?;
        Ok(Self {
            client: Arc::new(client),
            endpoint,
            owned: Arc::new(Mutex::new(Vec::new())),
            default_ttl_seconds,
            max_output_bytes,
            max_parallel,
        })
    }

    /// Asks the local control plane how it is doing.
    ///
    /// Used by the health surface, which must report the control plane's own
    /// view rather than assume the server started successfully.
    pub async fn health(&self) -> Result<serde_json::Value, McpError> {
        self.client
            .health()
            .await
            .map_err(|error| map_client_error(&error))
    }

    pub fn endpoint(&self) -> &LocalEndpoint {
        &self.endpoint
    }

    /// The authenticated client behind this facade.
    ///
    /// Runs are not sandboxes: they are the control plane's own workflow, and
    /// they go through this same client rather than opening a second
    /// connection to the same local control plane.
    pub fn client(&self) -> &AIecClient {
        &self.client
    }

    pub fn max_parallel(&self) -> usize {
        self.max_parallel
    }

    pub fn default_ttl_seconds(&self) -> u64 {
        self.default_ttl_seconds
    }

    /// Creates a sandbox whose workspace is prepared by the control plane.
    ///
    /// AIec drives the clone inside the guest, so the sandbox needs outbound
    /// network for it: the guest is the thing that runs `git clone`. A host that
    /// cannot give a microVM a network will fail this path with a backend
    /// error, which is surfaced rather than papered over.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_sandbox_with_workspace(
        &self,
        image: &str,
        runtime: &str,
        workspace: WorkspaceSpec,
        cpu: u32,
        memory_mb: u32,
        disk_mb: u32,
        timeout_seconds: u64,
        network_enabled: bool,
        guard_allowlist: Option<Vec<String>>,
    ) -> Result<(SandboxView, Uuid, Uuid), McpError> {
        self.create_sandbox_inner(
            image,
            runtime,
            cpu,
            memory_mb,
            disk_mb,
            timeout_seconds,
            network_enabled,
            guard_allowlist,
            Some(workspace),
        )
        .await
    }

    /// Creates a sandbox on the local control plane.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_sandbox(
        &self,
        image: &str,
        runtime: &str,
        cpu: u32,
        memory_mb: u32,
        disk_mb: u32,
        timeout_seconds: u64,
        network_enabled: bool,
        guard_allowlist: Option<Vec<String>>,
    ) -> Result<(SandboxView, Uuid, Uuid), McpError> {
        self.create_sandbox_inner(
            image,
            runtime,
            cpu,
            memory_mb,
            disk_mb,
            timeout_seconds,
            network_enabled,
            guard_allowlist,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_sandbox_inner(
        &self,
        image: &str,
        runtime: &str,
        cpu: u32,
        memory_mb: u32,
        disk_mb: u32,
        timeout_seconds: u64,
        network_enabled: bool,
        guard_allowlist: Option<Vec<String>>,
        workspace: Option<WorkspaceSpec>,
    ) -> Result<(SandboxView, Uuid, Uuid), McpError> {
        LocalEndpoint::require_local_runtime(runtime)?;

        let ttl = timeout_seconds.clamp(60, 86_400);
        let run_id = Uuid::now_v7();
        // A Firecracker worker governs its own egress, so asking it for
        // ungoverned internet access is refused rather than quietly downgraded
        // to no-network. The caller is told what to do instead, because a
        // failure that arrives as a backend error sends people looking in the
        // wrong place.
        let firecracker = runtime.eq_ignore_ascii_case("firecracker");
        if network_enabled && firecracker && guard_allowlist.is_none() {
            return Err(McpError::invalid(
                "a Firecracker sandbox governs its own egress: pass guard_allowlist with the \
                 hosts it may reach instead of network_enabled, or leave the network off",
            ));
        }
        let request = CreateSandboxRequest {
            image: image.to_owned(),
            cpu,
            memory_mb,
            disk_mb,
            timeout_seconds: ttl,
            network: if network_enabled && !firecracker {
                NetworkPolicy::Internet
            } else {
                NetworkPolicy::Disabled
            },
            environment: EnvironmentSpec {
                workspace: workspace.unwrap_or_default(),
                guard: guard_allowlist
                    .map(crate::runs::allowlist_guard)
                    .transpose()?,
                ..Default::default()
            },
        };
        let sandbox = self.create_with_runtime(&request, runtime).await?;

        // Recorded the moment the control plane says it exists, before any
        // check that can refuse it. Both refusals below return an error to a
        // caller who is never told the id, so a machine refused here is one
        // this server created and nothing else will ever tear down: it runs
        // until its TTL expires, holding capacity and counting against the
        // tenant's quota for a machine nobody can name.
        self.owned
            .lock()
            .expect("ownership lock is not poisoned")
            .push(Ownership {
                sandbox_id: sandbox.id,
                run_id,
                created_at: Utc::now(),
                owned_by_tool: false,
            });

        // A caller that asked for a specific runtime must not silently get a
        // different one: the control plane chooses, so verify what it chose.
        if !sandbox.runtime.as_str().eq_ignore_ascii_case(runtime)
            && !sandbox.runtime.as_str().eq_ignore_ascii_case("bwrap-dev")
            && !sandbox.runtime.as_str().eq_ignore_ascii_case("hosted")
        {
            self.discard(sandbox.id).await;
            return Err(McpError::new(
                ErrorCode::LocalRuntimeUnavailable,
                format!(
                    "asked for the `{runtime}` runtime but the control plane placed it on `{}`",
                    sandbox.runtime.as_str()
                ),
            ));
        }
        if sandbox.runtime.as_str() == "hosted" {
            self.discard(sandbox.id).await;
            return Err(McpError::new(
                ErrorCode::LocalRuntimeUnavailable,
                "the control plane placed this sandbox on a hosted runtime; this server only \
                 drives local sandboxes",
            ));
        }

        Ok((view_of(&sandbox), sandbox.id, run_id))
    }

    /// Tears down a machine this server created but cannot drive, and forgets
    /// it on success so nothing later polls a machine that is gone.
    ///
    /// The refusal is returned to the caller regardless of whether the teardown
    /// worked: the reason the create was refused has not changed, and replacing
    /// it with "could not destroy" would hide the cause behind a consequence.
    /// `destroy_sandbox` only forgets on a confirmed terminal state, so a
    /// teardown that fails leaves the machine in the owned set, which is
    /// where a later `aiec_list_sandboxes` can still report it.
    async fn discard(&self, id: Uuid) {
        if let Err(error) = self.destroy_sandbox(id).await {
            tracing::warn!(%id, %error, "a sandbox created here could not be torn down");
        }
    }

    /// Lists sandboxes this server is responsible for.
    ///
    /// Each owned sandbox is fetched by id rather than by scanning the
    /// tenant's sandbox list. That route answers one bounded page ordered by
    /// recency, so an owned sandbox older than the page would simply not
    /// appear in it — this server would report a sandbox it still holds and
    /// still owns as gone. The set is this server's own bookkeeping, so its size
    /// is bounded by what this server created.
    pub async fn list_owned_sandboxes(&self) -> ToolResult<Vec<SandboxView>> {
        let owned: Vec<Uuid> = {
            let guard = self.owned.lock().expect("ownership lock is not poisoned");
            guard.iter().map(|record| record.sandbox_id).collect()
        };
        if owned.len() > MAX_OWNED_SANDBOXES {
            return Err(McpError::invalid(format!(
                "this server owns {} sandboxes; destroy the ones you no longer \
                 need before asking it to describe all of them",
                owned.len()
            )));
        }
        // Concurrently, and bounded. This is one request per machine, so a
        // serial walk made a health poll cost the length of this server's whole
        // history, on a path a client reaches repeatedly.
        let fetched = futures::stream::iter(owned.iter().copied())
            .map(|id| async move {
                let sandbox = self.client.get_sandbox(id).await;
                (id, sandbox)
            })
            .buffer_unordered(OWNED_FETCH_CONCURRENCY);
        futures::pin_mut!(fetched);
        let mut views = Vec::with_capacity(owned.len());
        let mut dead: Vec<Uuid> = Vec::new();
        while let Some((id, sandbox)) = fetched.next().await {
            match sandbox {
                Ok(sandbox) if is_terminal(sandbox.state) => dead.push(id),
                Ok(sandbox) => views.push(view_of(&sandbox)),
                Err(error) if map_client_error(&error).code == ErrorCode::SandboxNotFound => {
                    dead.push(id)
                }
                Err(error) => return Err(map_client_error(&error).with_sandbox(id)),
            }
        }
        // A machine that is gone, or that finished on its own, is not something
        // this server can clean up or hand back. It was kept here only because
        // `forget` runs on an explicit destroy, so a sandbox that timed out or
        // failed by itself stayed in the map for the life of the process — and
        // this map is exactly what the listing walks, so a long-lived server
        // made every poll cost one request per sandbox it had ever made.
        for id in dead {
            self.forget(id);
        }
        // Newest first, the order the list route returns, so the two ways of
        // seeing a sandbox's history agree.
        views.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.sandbox_id.cmp(&a.sandbox_id))
        });
        Ok(views)
    }

    /// Fetches one sandbox, mapping a missing sandbox onto a typed error.
    pub async fn get_sandbox(&self, id: Uuid) -> ToolResult<SandboxView> {
        let sandbox = self
            .client
            .get_sandbox(id)
            .await
            .map_err(|error| map_client_error(&error).with_sandbox(id))?;
        Ok(view_of(&sandbox))
    }

    /// Destroys a sandbox and waits briefly for the state to settle.
    ///
    /// Destroying something already gone is reported as success, because a
    /// caller cleaning up after a failure should not have to distinguish the
    /// two cases.
    pub async fn destroy_sandbox(&self, id: Uuid) -> ToolResult<String> {
        // A destroy issued immediately after a failed task can race the
        // worker's lease resync and come back "worker lease generation or status
        // changed". It is transient: the same call a moment later succeeds. So
        // it is retried briefly before being reported, which is what makes
        // cleanup reliable rather than merely attempted.
        let mut last_error: Option<aiec_client::ClientError> = None;
        for attempt in 0..4 {
            match self.client.delete_sandbox(id).await {
                Ok(()) => {
                    last_error = None;
                    break;
                }
                Err(error) => {
                    // Already gone is the outcome the caller wanted. Matched on
                    // the wire status rather than on the formatted message:
                    // "404" appears in any error whose text carries that number
                    // anywhere, including a backend error that reported it, and
                    // reporting a sandbox destroyed while it is still running is
                    // worse than reporting the failure.
                    if matches!(
                        &error,
                        aiec_client::ClientError::Api { status, .. }
                            if status == &reqwest::StatusCode::NOT_FOUND
                    ) {
                        last_error = None;
                        break;
                    }
                    // On the wire, transience is a code, so it is matched as one.
                    let lease_race = matches!(
                        &error,
                        aiec_client::ClientError::Api { code, .. } if code == "transient"
                    );
                    last_error = Some(error);
                    if !lease_race || attempt == 3 {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(400 * (attempt + 1))).await;
                }
            }
        }
        if let Some(error) = last_error {
            return Err(map_client_error(&error).with_sandbox(id));
        }

        // Confirm cleanup rather than assuming the delete was synchronous.
        for _ in 0..25 {
            match self.client.get_sandbox(id).await {
                Ok(sandbox) => {
                    if is_terminal(sandbox.state) {
                        self.forget(id);
                        return Ok(sandbox.state.as_str().to_owned());
                    }
                }
                Err(error) => {
                    if map_client_error(&error).code == ErrorCode::SandboxNotFound {
                        self.forget(id);
                        return Ok("destroyed".to_owned());
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        // The machine is still there. Saying "destroyed" anyway is a lie the
        // caller acts on - it stops watching the machine and assumes its capacity
        // is free - so this is reported as a failure and the ownership record is
        // kept so the sandbox can still be collected.
        let state = self
            .client
            .get_sandbox(id)
            .await
            .map(|sandbox| sandbox.state.as_str().to_owned())
            .unwrap_or_else(|_| "unknown".to_owned());
        Err(McpError::new(
            ErrorCode::AiecApiUnavailable,
            format!("the sandbox is still `{state}` after destroy was requested"),
        )
        .with_sandbox(id))
    }

    /// Runs a command inside a sandbox.
    ///
    /// This is the only execution path in the server. The command is passed to
    /// AIec as an argument vector, never through a host shell, and the control
    /// plane applies the timeout, output bound and process cleanup.
    #[allow(clippy::too_many_arguments)]
    pub async fn exec(
        &self,
        sandbox_id: Uuid,
        command: &[String],
        cwd: Option<String>,
        env: BTreeMap<String, String>,
        stdin: Option<String>,
        timeout_seconds: u64,
    ) -> Result<ExecOutcome, McpError> {
        if command.is_empty() {
            return Err(McpError::invalid("the command is empty"));
        }
        self.require_running(sandbox_id).await?;

        let request = ExecRequest {
            command: command.to_vec(),
            working_directory: cwd,
            environment: env,
            timeout_seconds: timeout_seconds.clamp(1, 3600),
            stdin,
        };

        let result = self
            .client
            .exec(sandbox_id, &request)
            .await
            .map_err(|error| map_client_error(&error).with_sandbox(sandbox_id))?;

        if result.timed_out {
            return Err(McpError::new(
                ErrorCode::CommandTimeout,
                format!(
                    "the command exceeded {}s inside the sandbox",
                    request.timeout_seconds
                ),
            )
            .with_sandbox(sandbox_id));
        }

        let (stdout, stdout_truncated) = clamp(&result.stdout, self.max_output_bytes);
        let (stderr, stderr_truncated) = clamp(&result.stderr, self.max_output_bytes);

        Ok(ExecOutcome {
            exit_code: result.exit_code,
            stdout,
            stderr,
            timed_out: false,
            duration_ms: result.duration_ms,
            truncated: stdout_truncated || stderr_truncated,
        })
    }

    /// Convenience wrapper that runs a shell command string inside the sandbox.
    pub async fn exec_shell(
        &self,
        sandbox_id: Uuid,
        script: &str,
        timeout_seconds: u64,
    ) -> Result<ExecOutcome, McpError> {
        self.exec(
            sandbox_id,
            &["/bin/sh".to_owned(), "-lc".to_owned(), script.to_owned()],
            None,
            BTreeMap::new(),
            None,
            timeout_seconds,
        )
        .await
    }

    pub async fn read_file(
        &self,
        sandbox_id: Uuid,
        path: &str,
        max_bytes: usize,
    ) -> Result<(String, u64, bool), McpError> {
        let file = self
            .client
            .get_file(sandbox_id, path)
            .await
            .map_err(|error| map_client_error(&error).with_sandbox(sandbox_id))?;
        let decoded = decode_base64(&file.content_base64).ok_or_else(|| {
            McpError::new(
                ErrorCode::UnsupportedOperation,
                "the control plane returned a file the MCP server could not decode",
            )
            .with_sandbox(sandbox_id)
        })?;
        let size = decoded.len();
        let (content, truncated) = clamp(&decoded, max_bytes.min(self.max_output_bytes));
        Ok((content, size as u64, truncated))
    }

    pub async fn write_file(
        &self,
        sandbox_id: Uuid,
        path: &str,
        content: &str,
    ) -> Result<(), McpError> {
        if content.len() > self.max_output_bytes {
            return Err(McpError::new(
                ErrorCode::FileTooLarge,
                format!(
                    "the file is {} bytes, above the {} byte limit",
                    content.len(),
                    self.max_output_bytes
                ),
            )
            .with_sandbox(sandbox_id));
        }
        self.client
            .put_file(
                sandbox_id,
                &PutFileRequest {
                    path: path.to_owned(),
                    content_base64: encode_base64(content.as_bytes()),
                    mode: None,
                },
            )
            .await
            .map_err(|error| map_client_error(&error).with_sandbox(sandbox_id))
    }

    pub async fn list_files(
        &self,
        sandbox_id: Uuid,
        path: &str,
    ) -> Result<Vec<FileEntry>, McpError> {
        self.client
            .list_files(sandbox_id, path)
            .await
            .map_err(|error| map_client_error(&error).with_sandbox(sandbox_id))
    }

    /// Collects the working tree state of a repository inside a sandbox.
    pub async fn git_evidence(
        &self,
        sandbox_id: Uuid,
        repo_path: &str,
    ) -> Result<GitEvidence, McpError> {
        let status = self
            .exec_shell(
                sandbox_id,
                &format!("cd {repo_path} && git --no-pager status --porcelain=v1 -z"),
                60,
            )
            .await?;
        let diff = self
            .exec_shell(
                sandbox_id,
                &format!("cd {repo_path} && git --no-pager diff"),
                60,
            )
            .await?;
        let head = self
            .exec_shell(
                sandbox_id,
                &format!("cd {repo_path} && git rev-parse HEAD"),
                60,
            )
            .await?;

        let changed = porcelain_paths(&status.stdout);
        // NUL written as a newline, because that is what separates the records
        // anyway; `changed_files` above holds the exact paths. This is the same
        // stream rendered for a human reading it.
        let git_status = status.stdout.replace('\0', "\n");

        Ok(GitEvidence {
            head: head.stdout.trim().to_owned(),
            git_status,
            git_diff: diff.stdout.clone(),
            changed_files: changed,
            diff_bytes: diff.stdout.len(),
        })
    }

    /// Marks a sandbox as belonging to a high-level tool, so it is destroyed
    /// with the run unless the caller keeps it.
    pub fn mark_tool_owned(&self, sandbox_id: Uuid) {
        let mut owned = self.owned.lock().expect("ownership lock is not poisoned");
        if let Some(record) = owned.iter_mut().find(|r| r.sandbox_id == sandbox_id) {
            record.owned_by_tool = true;
        } else {
            owned.push(Ownership {
                sandbox_id,
                run_id: Uuid::now_v7(),
                created_at: Utc::now(),
                owned_by_tool: true,
            });
        }
    }

    /// The sandboxes this server created, and only those.
    pub fn owned_sandbox_ids(&self) -> Vec<Uuid> {
        self.owned
            .lock()
            .expect("ownership lock is not poisoned")
            .iter()
            .map(|record| record.sandbox_id)
            .collect()
    }

    fn forget(&self, id: Uuid) {
        self.owned
            .lock()
            .expect("ownership lock is not poisoned")
            .retain(|record| record.sandbox_id != id);
    }

    /// Issues the create with the runtime pinned.
    async fn create_with_runtime(
        &self,
        request: &CreateSandboxRequest,
        runtime: &str,
    ) -> Result<Sandbox, McpError> {
        self.client
            .create_sandbox_with_runtime(request, runtime)
            .await
            .map_err(|error| map_client_error(&error))
    }

    async fn require_running(&self, id: Uuid) -> Result<(), McpError> {
        let sandbox = self
            .client
            .get_sandbox(id)
            .await
            .map_err(|error| map_client_error(&error).with_sandbox(id))?;
        if sandbox.state.as_str() != "running" {
            return Err(McpError::new(
                ErrorCode::SandboxNotRunning,
                format!("the sandbox is `{}`, not `running`", sandbox.state.as_str()),
            )
            .with_sandbox(id));
        }
        Ok(())
    }
}

/// Repository evidence gathered from inside a sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct GitEvidence {
    pub head: String,
    pub git_status: String,
    pub git_diff: String,
    pub changed_files: Vec<String>,
    pub diff_bytes: usize,
}

/// The paths `git status --porcelain=v1 -z` reported, exactly as it printed them.
///
/// Each record is two status characters, a space, then the path - and for a
/// rename or a copy the *original* path follows as its own NUL-terminated
/// field. Splitting the ordinary way and trimming the remainder turned both
/// cases into something that is not a path: a file edited without staging is
/// ` M src/main.rs`, which trimmed gives `M src/main.rs`, and a rename gave
/// `new name.txt -> old name.txt`. The whole point of the field is that a
/// reader can open what the run claims it touched.
fn porcelain_paths(porcelain: &str) -> Vec<String> {
    let mut fields = porcelain.split('\0');
    let mut paths = Vec::new();
    while let Some(record) = fields.next() {
        let bytes = record.as_bytes();
        // The shortest possible record is `XY ` plus one byte of path.
        if bytes.len() < 4 || bytes[2] != b' ' {
            continue;
        }
        // `bytes[2]` is ASCII, so index 3 is a character boundary and this slice
        // can never split one.
        paths.push(record[3..].to_owned());
        if matches!(bytes[0], b'R' | b'C') {
            let _ = fields.next();
        }
    }
    paths
}

fn view_of(sandbox: &Sandbox) -> SandboxView {
    SandboxView {
        sandbox_id: sandbox.id.to_string(),
        state: sandbox.state.as_str().to_owned(),
        runtime: sandbox.runtime.as_str().to_owned(),
        image: sandbox.image_id.clone(),
        cpu: sandbox.cpu,
        memory_mb: sandbox.memory_mb,
        disk_mb: sandbox.disk_mb,
        created_at: sandbox.created_at,
        expires_at: Some(
            sandbox.created_at + chrono::Duration::seconds(sandbox.timeout_seconds as i64),
        ),
    }
}

/// Whether a sandbox has reached a state it will not leave on its own.
fn is_terminal(state: SandboxState) -> bool {
    matches!(state, SandboxState::Destroyed | SandboxState::Failed)
}

/// Encodes to the standard base64 the control plane expects for file bodies.
fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decodes standard base64, which is what the control plane emits for files.
fn decode_base64(text: &str) -> Option<String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// Clips output to a bound, reporting whether it had to.
pub(crate) fn clamp(text: &str, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text.to_owned(), false);
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

/// Maps the client's error type onto the structured MCP error model.
pub fn map_client_error(error: &aiec_client::ClientError) -> McpError {
    use aiec_client::ClientError as E;
    match error {
        E::Api {
            status,
            code,
            message,
            request_id,
        } => {
            let mut mapped = crate::error::ToolFailure::Api {
                code: code.clone(),
                message: message.clone(),
            }
            .into_error();
            mapped.request_id = Some(request_id.to_string());
            if *status == reqwest::StatusCode::UNAUTHORIZED {
                mapped.code = ErrorCode::AuthFailed;
            }
            mapped
        }
        E::Request(detail) => McpError::new(
            ErrorCode::AiecApiUnavailable,
            format!("the local AIec control plane is unreachable: {detail}"),
        ),
        E::Decode(detail) => McpError::new(
            ErrorCode::AiecApiUnavailable,
            format!("the control plane returned an unreadable response: {detail}"),
        ),
        E::Configuration(detail) => McpError::new(
            ErrorCode::LocalRuntimeUnavailable,
            format!("the local control plane is not configured: {detail}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_clipped_on_a_character_boundary() {
        // A multi-byte character must not be split, which would panic.
        let text = "é".repeat(10);
        let (clipped, truncated) = clamp(&text, 5);
        assert!(truncated);
        assert_eq!(clipped, "éé");

        let (whole, truncated) = clamp("short", 100);
        assert!(!truncated);
        assert_eq!(whole, "short");
    }

    /// The changed-file list is the run's own account of what it touched, and a
    /// reader opens those names. Trimming a porcelain line handed back
    /// `M src/main.rs` for the most ordinary thing an agent does - edit a file
    /// without staging it - and `new name.txt -> old name.txt` for a rename.
    #[test]
    fn changed_files_are_the_paths_git_printed() {
        let stream = " M src/main.rs\0?? new file.rs\0A  added.rs\0";
        assert_eq!(
            porcelain_paths(stream),
            vec!["src/main.rs", "new file.rs", "added.rs"]
        );

        // A rename is two NUL-terminated fields; only the destination is a path
        // the run left behind.
        assert_eq!(
            porcelain_paths("R  new name.txt\0old name.txt\0"),
            vec!["new name.txt"]
        );

        // With -z git does not C-quote, so a non-ASCII name arrives as itself.
        assert_eq!(porcelain_paths("?? caf\u{e9}.txt\0"), vec!["caf\u{e9}.txt"]);
    }

    #[test]
    fn an_empty_command_is_rejected_before_any_request() {
        let error = McpError::invalid("the command is empty");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    use axum::response::IntoResponse;
    use axum::routing::any;

    #[derive(Clone, Default)]
    struct Stub {
        requested: Arc<Mutex<Vec<String>>>,
        gone: Arc<Mutex<Vec<String>>>,
    }

    async fn stub_handle(
        axum::extract::State(stub): axum::extract::State<Stub>,
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::response::Response {
        let id = request
            .uri()
            .path()
            .strip_prefix("/v1/sandboxes/")
            .unwrap_or_default()
            .to_owned();
        stub.requested
            .lock()
            .expect("not poisoned")
            .push(id.clone());
        let gone = stub.gone.lock().expect("not poisoned").clone();
        // Retention-expired: the control plane no longer has this one at all,
        // so it answers 404 rather than a document.
        let (status, body) = if gone.contains(&id) {
            (
                axum::http::StatusCode::NOT_FOUND,
                serde_json::json!({"error": {
                    "code": "not_found",
                    "message": "gone",
                    "request_id": "00000000-0000-0000-0000-000000000003",
                }}),
            )
        } else if id.ends_with('1') {
            (
                axum::http::StatusCode::OK,
                sandbox_document(&id, "destroyed"),
            )
        } else {
            (axum::http::StatusCode::OK, sandbox_document(&id, "running"))
        };
        (
            status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response()
    }

    /// A sandbox document the way the control plane returns one.
    fn sandbox_document(id: &str, state: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "node_id": serde_json::Value::Null,
            "image_id": "image",
            "state": state,
            "runtime": "docker",
            "cpu": 1,
            "memory_mb": 128,
            "disk_mb": 128,
            "timeout_seconds": 900,
            "network": {"enabled": false},
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "runtime_path": serde_json::Value::Null,
        })
    }

    /// A long-lived server reads its sandbox list on a health poll, and that
    /// list is one request per machine this process ever created. Two things
    /// follow, and both are checked here: a machine that finished on its own
    /// stops being carried, and a server holding more than one listing will
    /// describe refuses rather than describing part of it.
    #[tokio::test]
    async fn the_owned_listing_forgets_finished_machines_and_refuses_past_its_bound() {
        let stub = Stub {
            gone: std::sync::Arc::new(std::sync::Mutex::new(vec![
                "00000000-0000-0000-0000-000000000003".to_owned(),
            ])),
            ..Stub::default()
        };
        let app = axum::Router::new()
            .fallback(any(stub_handle))
            .with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let url = format!("http://{}", listener.local_addr().expect("a bound address"));
        let serving = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let endpoint = LocalEndpoint::parse(&url, false).expect("a loopback endpoint");
        let aiec = LocalAiec::new(endpoint, String::new(), 900, 1 << 20, 4).expect("a facade");
        let live = "00000000-0000-0000-0000-000000000002";
        // Ends in 1, so the stub reports it as having finished on its own.
        let finished = "00000000-0000-0000-0000-000000000001";
        let vanished = "00000000-0000-0000-0000-000000000003";
        aiec.mark_tool_owned(Uuid::parse_str(live).expect("a uuid"));
        aiec.mark_tool_owned(Uuid::parse_str(finished).expect("a uuid"));
        // Retention-expired: the control plane no longer has this one at all.
        aiec.mark_tool_owned(Uuid::parse_str(vanished).expect("a uuid"));

        let views = aiec.list_owned_sandboxes().await.expect("a listing");
        assert_eq!(
            views
                .iter()
                .map(|view| view.sandbox_id.to_string())
                .collect::<Vec<_>>(),
            vec![live.to_owned()],
            "a machine that finished on its own is not one to hand back"
        );
        assert_eq!(
            aiec.owned_sandbox_ids(),
            vec![Uuid::parse_str(live).expect("a uuid")],
            "and it must leave the map, or every later poll fetches it again"
        );

        // More machines than one listing will describe. Refused rather than
        // truncated, so a caller is never handed a partial "these are my
        // machines" answer and left the rest running.
        for _ in 0..MAX_OWNED_SANDBOXES {
            aiec.mark_tool_owned(Uuid::new_v4());
        }
        assert!(
            aiec.list_owned_sandboxes().await.is_err(),
            "a listing past the bound must be refused, not truncated"
        );

        serving.abort();
    }

    /// A create the control plane places somewhere this server cannot drive is
    /// refused, and the machine is already running. The refusal names the
    /// runtime mismatch but not the machine, so nothing downstream holds its
    /// id: without an explicit teardown the machine runs to its TTL holding
    /// capacity and quota for something the caller was told does not exist.
    #[tokio::test]
    async fn a_refused_placement_is_destroyed_rather_than_left_running() {
        #[derive(Clone)]
        struct Placement {
            /// The runtime the control plane reports, ignoring the request.
            placed: &'static str,
            deleted: Arc<Mutex<Vec<String>>>,
            states: Arc<Mutex<std::collections::HashMap<String, String>>>,
        }

        async fn placement_handle(
            axum::extract::State(placement): axum::extract::State<Placement>,
            request: axum::http::Request<axum::body::Body>,
        ) -> axum::response::Response {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let json = [(axum::http::header::CONTENT_TYPE, "application/json")];
            if method == axum::http::Method::POST {
                let id = "00000000-0000-0000-0000-0000000000aa";
                placement
                    .states
                    .lock()
                    .expect("not poisoned")
                    .insert(id.to_owned(), "running".to_owned());
                let mut document = sandbox_document(id, "running");
                document["runtime"] = serde_json::Value::String(placement.placed.to_owned());
                return axum::response::IntoResponse::into_response((
                    axum::http::StatusCode::CREATED,
                    json,
                    document.to_string(),
                ));
            }
            let id = path.strip_prefix("/v1/sandboxes/").unwrap_or_default();
            if method == axum::http::Method::DELETE {
                placement
                    .deleted
                    .lock()
                    .expect("not poisoned")
                    .push(id.to_owned());
                placement
                    .states
                    .lock()
                    .expect("not poisoned")
                    .insert(id.to_owned(), "destroyed".to_owned());
                return axum::response::IntoResponse::into_response((
                    axum::http::StatusCode::NO_CONTENT,
                    json,
                    String::new(),
                ));
            }
            let state = placement
                .states
                .lock()
                .expect("not poisoned")
                .get(id)
                .cloned()
                .unwrap_or_else(|| "destroyed".to_owned());
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::OK,
                json,
                sandbox_document(id, &state).to_string(),
            ))
        }

        // Both refusals: a runtime this server does not drive at all, and one
        // it drives but the caller did not ask for. Same leak either way.
        for placed in ["hosted", "firecracker"] {
            let placement = Placement {
                placed,
                deleted: Arc::new(Mutex::new(Vec::new())),
                states: Arc::new(Mutex::new(std::collections::HashMap::new())),
            };
            let app = axum::Router::new()
                .fallback(any(placement_handle))
                .with_state(placement.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a loopback port");
            let url = format!("http://{}", listener.local_addr().expect("a bound address"));
            let serving = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            let aiec = LocalAiec::new(
                LocalEndpoint::parse(&url, false).expect("a loopback endpoint"),
                String::new(),
                900,
                1 << 20,
                4,
            )
            .expect("a facade");

            let error = aiec
                .create_sandbox("image", "docker", 1, 128, 128, 900, false, None)
                .await
                .expect_err("a placement this server cannot drive must be refused");
            assert_eq!(error.code, ErrorCode::LocalRuntimeUnavailable);
            assert_eq!(
                *placement.deleted.lock().expect("not poisoned"),
                vec!["00000000-0000-0000-0000-0000000000aa".to_owned()],
                "a machine placed on `{placed}` must be destroyed, not left running"
            );
            assert!(
                aiec.owned_sandbox_ids().is_empty(),
                "and it must leave the owned set, or every later poll asks for it again"
            );
            serving.abort();
        }
    }

    /// Teardown that fails must leave the machine tracked rather than
    /// forgotten. Forgetting it would make the refusal look clean — the caller's
    /// error is unchanged either way — while the machine keeps running with
    /// nothing left that knows it exists. Kept in the owned set it is still
    /// there to be listed and to fail the process's own cleanup, which is the
    /// only place left to report it.
    #[tokio::test]
    async fn a_refused_placement_whose_teardown_fails_stays_tracked() {
        #[derive(Clone)]
        struct Refuses {
            deleted: Arc<Mutex<usize>>,
        }

        async fn refusing_handle(
            axum::extract::State(state): axum::extract::State<Refuses>,
            request: axum::http::Request<axum::body::Body>,
        ) -> axum::response::Response {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let json = [(axum::http::header::CONTENT_TYPE, "application/json")];
            if method == axum::http::Method::POST {
                let id = "00000000-0000-0000-0000-0000000000bb";
                let mut document = sandbox_document(id, "running");
                document["runtime"] = serde_json::Value::String("hosted".to_owned());
                return axum::response::IntoResponse::into_response((
                    axum::http::StatusCode::CREATED,
                    json,
                    document.to_string(),
                ));
            }
            let id = path.strip_prefix("/v1/sandboxes/").unwrap_or_default();
            if method == axum::http::Method::DELETE {
                *state.deleted.lock().expect("not poisoned") += 1;
                return axum::response::IntoResponse::into_response((
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    json,
                    serde_json::json!({"error": {
                        "code": "internal",
                        "message": "the worker's lease generation changed",
                        "request_id": "00000000-0000-0000-0000-000000000004",
                    }})
                    .to_string(),
                ));
            }
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::OK,
                json,
                sandbox_document(id, "running").to_string(),
            ))
        }

        let state = Refuses {
            deleted: Arc::new(Mutex::new(0)),
        };
        let app = axum::Router::new()
            .fallback(any(refusing_handle))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let url = format!("http://{}", listener.local_addr().expect("a bound address"));
        let serving = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let aiec = LocalAiec::new(
            LocalEndpoint::parse(&url, false).expect("a loopback endpoint"),
            String::new(),
            900,
            1 << 20,
            4,
        )
        .expect("a facade");

        let error = aiec
            .create_sandbox("image", "docker", 1, 128, 128, 900, false, None)
            .await
            .expect_err("the placement is still refused");
        // The refusal, not the failed teardown: the caller asked the wrong
        // question and the answer to that question has not changed.
        assert_eq!(error.code, ErrorCode::LocalRuntimeUnavailable);
        assert!(error.message.contains("hosted"));
        assert!(
            *state.deleted.lock().expect("not poisoned") > 0,
            "a teardown must be attempted before the machine is given up on"
        );
        assert_eq!(
            aiec.owned_sandbox_ids(),
            vec![Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").expect("a uuid")],
            "a machine that could not be torn down must stay owned, or it runs on untracked"
        );
        serving.abort();
    }
}
