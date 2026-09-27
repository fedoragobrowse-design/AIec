//! The MCP server: tools, resources and prompts over Streamable HTTP.
//!
//! Every workload tool here delegates to [`LocalAiec`], which is the only
//! component that talks to a sandbox. There is deliberately no host execution
//! path in this file: `aiec_exec` takes an argument vector and sends it to
//! AIec, and nothing in this server can run a command on the machine it runs
//! on.

use std::collections::BTreeMap;
use std::sync::Arc;

use rmcp::ErrorData as McpErrorData;
use rmcp::RoleServer;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, ListPromptsResult, ListResourceTemplatesResult,
    ListResourcesResult, PaginatedRequestParams, Prompt, ReadResourceRequestParams,
    ReadResourceResponse, ReadResourceResult, Resource, ResourceTemplate, ServerCapabilities,
    ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::tool;
use rmcp::tool_handler;
use rmcp::tool_router;
use rmcp::{ServerHandler, schemars};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{ErrorCode, McpError, ToolResult};
use crate::sandbox::{ExecOutcome, LocalAiec, SandboxView};

/// Server state shared by every request.
#[derive(Clone)]
pub struct AiecMcp {
    pub aiec: LocalAiec,
    pub default_image: String,
    pub default_runtime: String,
    pub default_ttl_seconds: u64,
    pub max_parallel: usize,
    /// Sandboxes this server created, used by the ownership resources.
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl AiecMcp {
    pub fn new(config: &Config) -> Result<Self, McpError> {
        let aiec = LocalAiec::new(
            config.endpoint.clone(),
            config.api_key.clone(),
            config.default_ttl_seconds,
            config.max_output_bytes,
            config.max_parallel,
        )?;
        Ok(Self {
            aiec,
            default_image: "python:3.13".to_owned(),
            // Firecracker is the local microVM runtime; it is preferred whenever
            // the worker offers it.
            default_runtime: "firecracker".to_owned(),
            default_ttl_seconds: config.default_ttl_seconds,
            max_parallel: config.max_parallel,
            started_at: chrono::Utc::now(),
        })
    }

    /// Resolves a sandbox id, reporting a typed error for a malformed one.
    fn sandbox_id(&self, raw: &str) -> ToolResult<Uuid> {
        Uuid::parse_str(raw.trim()).map_err(|_| {
            McpError::invalid(format!("`{raw}` is not a sandbox id"))
                .with_details(json!({ "sandbox_id": raw }))
        })
    }
}

// ---------------------------------------------------------------------------
// Tool parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateSandboxArgs {
    /// Image to boot. Defaults to the standard Python image.
    #[serde(default)]
    pub image: Option<String>,
    /// `firecracker` (microVM) or `docker`. Hosted providers are refused.
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub cpu: Option<u32>,
    #[serde(default)]
    pub memory_mb: Option<u32>,
    #[serde(default)]
    pub disk_mb: Option<u32>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub network_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SandboxIdArgs {
    pub sandbox_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecArgs {
    pub sandbox_id: String,
    /// The command and its arguments. Never interpreted by a host shell.
    pub command: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadFileArgs {
    pub sandbox_id: String,
    pub path: String,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteFileArgs {
    pub sandbox_id: String,
    pub path: String,
    pub content: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListFilesArgs {
    pub sandbox_id: String,
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PrepareRepoArgs {
    pub repo_url: String,
    /// Runtime for the sandbox. Defaults to a local microVM.
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunRepoTaskArgs {
    pub repo_url: String,
    /// Runtime for the sandbox. Defaults to a local microVM.
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    /// Commands run in order before the task, each as an argument vector.
    #[serde(default)]
    pub setup_commands: Option<Vec<Vec<String>>>,
    pub task_command: Vec<String>,
    #[serde(default)]
    pub validation_commands: Option<Vec<Vec<String>>>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Keep the sandbox after the run so it can be inspected.
    #[serde(default)]
    pub keep_sandbox: Option<bool>,
    #[serde(default)]
    pub image: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TestOmpArgs {
    pub omp_repo: String,
    /// Runtime for the sandbox. Defaults to a local microVM.
    #[serde(default)]
    pub runtime: Option<String>,
    pub omp_ref: String,
    pub target_repo: String,
    #[serde(default)]
    pub target_ref: Option<String>,
    pub task: String,
    #[serde(default)]
    pub setup_command: Option<Vec<String>>,
    #[serde(default)]
    pub omp_command: Option<Vec<String>>,
    #[serde(default)]
    pub validation_commands: Option<Vec<Vec<String>>>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub keep_sandbox: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CompareOmpArgs {
    pub omp_repo: String,
    /// Runtime for every sandbox the comparison creates.
    #[serde(default)]
    pub runtime: Option<String>,
    pub baseline_ref: String,
    pub candidate_ref: String,
    pub target_repo: String,
    #[serde(default)]
    pub target_ref: Option<String>,
    pub task: String,
    #[serde(default)]
    pub validation_commands: Option<Vec<Vec<String>>>,
    #[serde(default)]
    pub repetitions: Option<u32>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub max_parallel: Option<usize>,
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[tool_router]
impl AiecMcp {
    /// Creates a disposable local sandbox and returns its id.
    #[tool(
        name = "aiec_create_sandbox",
        description = "Create a disposable sandbox on the LOCAL AIec cluster and return its id. \
Runs on a local microVM (Firecracker) or Docker; never on AIec Cloud and never on a \
third-party provider.",
        annotations(
            title = "Create sandbox",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn create_sandbox(
        &self,
        Parameters(args): Parameters<CreateSandboxArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let image = args.image.unwrap_or_else(|| self.default_image.clone());
        let runtime = args.runtime.unwrap_or_else(|| self.default_runtime.clone());
        self.report("aiec_create_sandbox", async {
            let (view, _id, _run) = self
                .aiec
                .create_sandbox(
                    &image,
                    &runtime,
                    args.cpu.unwrap_or(1),
                    args.memory_mb.unwrap_or(1024),
                    args.disk_mb.unwrap_or(2048),
                    args.timeout_seconds.unwrap_or(self.default_ttl_seconds),
                    args.network_enabled.unwrap_or(false),
                )
                .await?;
            Ok(view)
        })
        .await
    }

    /// Lists the sandboxes this MCP server created.
    #[tool(
        name = "aiec_list_sandboxes",
        description = "List sandboxes created by this MCP server, with their state, runtime, \
image and resource allocation.",
        annotations(title = "List sandboxes", read_only_hint = true)
    )]
    async fn list_sandboxes(&self) -> Result<CallToolResult, McpErrorData> {
        self.report("aiec_list_sandboxes", async {
            self.aiec.list_owned_sandboxes().await
        })
        .await
    }

    /// Fetches one sandbox's authoritative state.
    #[tool(
        name = "aiec_get_sandbox",
        description = "Get the current authoritative state of one sandbox.",
        annotations(title = "Get sandbox", read_only_hint = true)
    )]
    async fn get_sandbox(
        &self,
        Parameters(args): Parameters<SandboxIdArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let id = self.sandbox_id(&args.sandbox_id)?;
        self.report("aiec_get_sandbox", async {
            self.aiec.get_sandbox(id).await
        })
        .await
    }

    /// Destroys a sandbox and waits for cleanup to be confirmed.
    #[tool(
        name = "aiec_destroy_sandbox",
        description = "Destroy a sandbox on the local cluster and wait for cleanup to be \
confirmed. Safe to call on an already-destroyed sandbox.",
        annotations(
            title = "Destroy sandbox",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true
        )
    )]
    async fn destroy_sandbox(
        &self,
        Parameters(args): Parameters<SandboxIdArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let id = self.sandbox_id(&args.sandbox_id)?;
        self.report("aiec_destroy_sandbox", async {
            Ok(json!({ "sandbox_id": id.to_string(), "state": self.aiec.destroy_sandbox(id).await? }))
        })
        .await
    }

    /// Runs a command inside a sandbox.
    #[tool(
        name = "aiec_exec",
        description = "Run a command INSIDE a local sandbox and return exit code, stdout and \
stderr. The command is executed by the sandbox, never by the MCP host. Output is bounded \
and the command is subject to a timeout.",
        annotations(
            title = "Exec in sandbox",
            read_only_hint = false,
            // Honest, and deliberately not "destructive": a command runs in a
            // disposable sandbox the caller asked for. Marking this destructive
            // makes clients prompt to confirm every clone, test run and diff.
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let id = self.sandbox_id(&args.sandbox_id)?;
        self.report("aiec_exec", async {
            self.aiec
                .exec(
                    id,
                    &args.command,
                    args.cwd.clone(),
                    args.env.clone().unwrap_or_default(),
                    args.stdin.clone(),
                    args.timeout_seconds.unwrap_or(120),
                )
                .await
        })
        .await
    }

    /// Reads a file from inside a sandbox.
    #[tool(
        name = "aiec_read_file",
        description = "Read a file from inside a local sandbox, bounded to max_bytes.",
        annotations(title = "Read sandbox file", read_only_hint = true)
    )]
    async fn read_file(
        &self,
        Parameters(args): Parameters<ReadFileArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let id = self.sandbox_id(&args.sandbox_id)?;
        self.report("aiec_read_file", async {
            let (content, size, truncated) = self
                .aiec
                .read_file(id, &args.path, args.max_bytes.unwrap_or(1_048_576))
                .await?;
            Ok(json!({ "path": args.path, "content": content, "size": size, "truncated": truncated }))
        })
        .await
    }

    /// Writes a file inside a sandbox.
    #[tool(
        name = "aiec_write_file",
        description = "Write a file inside a local sandbox, creating parent directories as \
needed. Paths are confined to the sandbox filesystem.",
        annotations(
            title = "Write sandbox file",
            read_only_hint = false,
            destructive_hint = true
        )
    )]
    async fn write_file(
        &self,
        Parameters(args): Parameters<WriteFileArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let id = self.sandbox_id(&args.sandbox_id)?;
        self.report("aiec_write_file", async {
            self.aiec.write_file(id, &args.path, &args.content).await?;
            Ok(json!({ "path": args.path, "written": true }))
        })
        .await
    }

    /// Lists a directory inside a sandbox.
    #[tool(
        name = "aiec_list_files",
        description = "List a directory inside a local sandbox.",
        annotations(title = "List sandbox files", read_only_hint = true)
    )]
    async fn list_files(
        &self,
        Parameters(args): Parameters<ListFilesArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let id = self.sandbox_id(&args.sandbox_id)?;
        self.report("aiec_list_files", async {
            self.aiec.list_files(id, &args.path).await
        })
        .await
    }

    /// Clones a repository into a fresh local sandbox.
    #[tool(
        name = "aiec_prepare_repo",
        description = "Create a local sandbox, clone a git repository INSIDE it over HTTPS and \
check out a revision. The host filesystem is never touched.",
        annotations(
            title = "Prepare repository",
            read_only_hint = false,
            destructive_hint = false
        )
    )]
    async fn prepare_repo(
        &self,
        Parameters(args): Parameters<PrepareRepoArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        self.report("aiec_prepare_repo", async {
            crate::eval::prepare_repo(
                &self.aiec,
                crate::eval::PrepareRepoRequest {
                    repo_url: args.repo_url,
                    runtime: args.runtime,
                    reference: args.reference,
                    image: args.image.or_else(|| Some(self.default_image.clone())),
                },
            )
            .await
        })
        .await
    }

    /// Runs a coding task against a repository in a clean sandbox.
    #[tool(
        name = "aiec_run_repo_task",
        description = "Create a local sandbox, clone a repository inside it, run setup commands, \
run a task, run validations, collect git status and diff, then destroy the sandbox unless \
keep_sandbox is set.",
        annotations(
            title = "Run repository task",
            read_only_hint = false,
            destructive_hint = false
        )
    )]
    async fn run_repo_task(
        &self,
        Parameters(args): Parameters<RunRepoTaskArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        self.report("aiec_run_repo_task", async {
            crate::eval::run_repo_task(
                &self.aiec,
                crate::eval::RunRepoTaskRequest {
                    repo_url: args.repo_url,
                    runtime: args.runtime,
                    reference: args.reference,
                    setup_commands: args.setup_commands.unwrap_or_default(),
                    task_command: args.task_command,
                    validation_commands: args.validation_commands.unwrap_or_default(),
                    timeout_seconds: args.timeout_seconds,
                    keep_sandbox: args.keep_sandbox.unwrap_or(false),
                    image: args.image.or_else(|| Some(self.default_image.clone())),
                },
            )
            .await
        })
        .await
    }

    /// Builds one OMP revision in a clean sandbox and runs it against a target repo.
    #[tool(
        name = "aiec_test_omp",
        description = "In a fresh local sandbox, clone a given OMP revision, build it, clone a \
target repository, run OMP against a task, run validations and return structured evidence. \
Set keep_sandbox to leave the machine for debugging.",
        annotations(
            title = "Test OMP revision",
            read_only_hint = false,
            destructive_hint = false
        )
    )]
    async fn test_omp(
        &self,
        Parameters(args): Parameters<TestOmpArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        self.report("aiec_test_omp", async {
            crate::eval::run_omp_once(
                &self.aiec,
                &crate::eval::OmpRunRequest {
                    runtime: args.runtime,
                    omp_repo: args.omp_repo,
                    omp_ref: args.omp_ref,
                    target_repo: args.target_repo,
                    target_ref: args.target_ref,
                    task: args.task,
                    setup_command: args.setup_command,
                    omp_command: args.omp_command,
                    validation_commands: args.validation_commands.unwrap_or_default(),
                    timeout_seconds: args.timeout_seconds,
                    keep_sandbox: args.keep_sandbox.unwrap_or(false),
                    repetitions: 1,
                },
            )
            .await
        })
        .await
    }

    /// Compares two OMP revisions across isolated repetitions.
    #[tool(
        name = "aiec_compare_omp",
        description = "Run a baseline and a candidate OMP revision against the same target \
repository, task, validations and resources, each in its OWN clean sandbox, and return \
measurements. Returns measurements only, never a judgement about which is better.",
        annotations(
            title = "Compare OMP revisions",
            read_only_hint = false,
            destructive_hint = false
        )
    )]
    async fn compare_omp(
        &self,
        Parameters(args): Parameters<CompareOmpArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let max_parallel = args.max_parallel.unwrap_or(self.max_parallel);
        self.report("aiec_compare_omp", async {
            crate::eval::compare_omp(
                &self.aiec,
                crate::eval::CompareOmpRequest {
                    runtime: args.runtime,
                    omp_repo: args.omp_repo,
                    baseline_ref: args.baseline_ref,
                    candidate_ref: args.candidate_ref,
                    target_repo: args.target_repo,
                    target_ref: args.target_ref,
                    task: args.task,
                    validation_commands: args.validation_commands.unwrap_or_default(),
                    repetitions: args.repetitions,
                    timeout_seconds: args.timeout_seconds,
                    max_parallel: Some(max_parallel),
                },
            )
            .await
        })
        .await
    }

    /// Local health, reachable without a sandbox.
    #[tool(
        name = "aiec_health",
        description = "Report whether the local AIec control plane is reachable, whether a local \
worker has capacity, and whether Firecracker is available.",
        annotations(title = "Local health", read_only_hint = true)
    )]
    async fn health(&self) -> Result<CallToolResult, McpErrorData> {
        self.report("aiec_health", async { Ok(self.health_report().await) })
            .await
    }
}

impl AiecMcp {
    /// Gathers local health without creating anything.
    pub async fn health_report(&self) -> serde_json::Value {
        let mut control_plane = serde_json::Value::Null;
        let mut workers: Vec<serde_json::Value> = Vec::new();
        let mut ready = false;

        // Readiness means a local worker could actually take a sandbox, not just
        // that the process answers /health.
        if let Ok(value) = self.aiec.health().await {
            control_plane = value.clone();
            ready = value
                .get("status")
                .and_then(|status| status.as_str())
                .is_some_and(|status| status.eq_ignore_ascii_case("ok"));
        }

        if let Ok(list) = self.aiec.list_owned_sandboxes().await {
            workers = list
                .iter()
                .map(|sandbox| json!({ "sandbox_id": sandbox.sandbox_id, "state": sandbox.state }))
                .collect();
        }

        json!({
            "status": if ready { "ok" } else { "degraded" },
            "mcp_server": "alive",
            "local_aiec_api": self.aiec.endpoint().url,
            "local_only": true,
            "control_plane": control_plane,
            "sandboxes": workers,
            "ready": ready,
        })
    }

    /// Runs a tool body, logging it and converting a failure into an MCP error.
    async fn report<T, F>(&self, tool: &str, body: F) -> Result<CallToolResult, McpErrorData>
    where
        T: Serialize,
        F: Future<Output = Result<T, McpError>>,
    {
        let started = std::time::Instant::now();
        let request_id = Uuid::now_v7();
        match body.await {
            Ok(value) => {
                tracing::info!(
                    request_id = %request_id,
                    tool,
                    duration_ms = started.elapsed().as_millis() as u64,
                    result = "ok",
                    "mcp tool call"
                );
                Ok(structured(&value))
            }
            Err(error) => {
                // The message is safe to log: it never carries a credential.
                tracing::warn!(
                    request_id = %request_id,
                    tool,
                    code = %error.code,
                    duration_ms = started.elapsed().as_millis() as u64,
                    result = "error",
                    "mcp tool call failed"
                );
                Err(McpErrorData::invalid_params(
                    error.message.clone(),
                    Some(
                        json!({ "code": error.code.as_str(), "request_id": request_id.to_string() }),
                    ),
                ))
            }
        }
    }
}

/// Renders a value as a structured tool result with JSON text.
fn structured<T: Serialize>(value: &T) -> CallToolResult {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned());
    CallToolResult::success(vec![ContentBlock::text(text)])
}

// ---------------------------------------------------------------------------
// Handler, resources and prompts
// ---------------------------------------------------------------------------

#[tool_handler]
impl ServerHandler for AiecMcp {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        );
        info.instructions = Some(
            "Drives LOCAL AIec sandboxes. Every command runs inside an isolated sandbox on \
             the user's own AIec cluster. This server never executes on the host and never \
             calls AIec Cloud or an external provider."
                .to_owned(),
        );
        info
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new("aiec://sandboxes", "sandboxes")
                .with_description("Sandboxes created by this MCP server")
                .with_mime_type("application/json"),
            Resource::new("aiec://local-capacity", "local-capacity")
                .with_description("Local AIec health and capacity")
                .with_mime_type("application/json"),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpErrorData> {
        let uri = request.uri.to_string();
        let body = if uri == "aiec://sandboxes" {
            serde_json::to_string_pretty(&self.aiec.list_owned_sandboxes().await.map_err(to_error)?)
        } else if uri == "aiec://local-capacity" {
            serde_json::to_string_pretty(&self.health_report().await)
        } else if let Some(id) = uri.strip_prefix("aiec://sandboxes/") {
            // A per-sandbox resource, addressed as aiec://sandboxes/{id}.
            let parsed = Uuid::parse_str(id)
                .map_err(|_| McpError::invalid(format!("`{id}` is not a sandbox id")))?;
            let view: SandboxView = self.aiec.get_sandbox(parsed).await.map_err(to_error)?;
            serde_json::to_string_pretty(&view)
        } else {
            return Err(McpErrorData::invalid_params(
                format!("unknown resource `{uri}`"),
                None,
            ));
        }
        .map_err(|error| McpErrorData::internal_error(error.to_string(), None))?;

        Ok(ReadResourceResult::new(vec![rmcp::model::ResourceContents::text(body, uri)]).into())
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(vec![
            ResourceTemplate::new("aiec://sandboxes/{id}", "sandbox")
                .with_description("State of one sandbox")
                .with_mime_type("application/json"),
        ]))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpErrorData> {
        Ok(ListPromptsResult::with_all_items(vec![
            Prompt::new(
                "test-repo-in-clean-sandbox",
                Some(
                    "Clone the repository into a fresh local sandbox, run the task and \
                      validations, and report the diff",
                ),
                None,
            ),
            Prompt::new(
                "reproduce-bug-in-clean-machine",
                Some(
                    "Create a sandbox and reproduce a failure, keeping the machine for \
                      inspection",
                ),
                None,
            ),
        ]))
    }
}

/// A tool failure becomes an MCP error carrying the machine-readable code, so
/// a calling agent can branch on the cause instead of reading prose.
impl From<McpError> for McpErrorData {
    fn from(error: McpError) -> Self {
        let mut details = error.details;
        if !details.is_object() {
            details = json!({});
        }
        if let Some(object) = details.as_object_mut() {
            object.insert("code".to_owned(), json!(error.code.as_str()));
            if let Some(id) = &error.sandbox_id {
                object.insert("sandbox_id".to_owned(), json!(id));
            }
            if let Some(id) = &error.request_id {
                object.insert("request_id".to_owned(), json!(id));
            }
        }
        McpErrorData::invalid_params(error.message, Some(details))
    }
}

fn to_error(error: McpError) -> McpErrorData {
    error.into()
}

/// Re-exported so the binary can build the router.
pub fn router() -> ToolRouter<AiecMcp> {
    AiecMcp::tool_router()
}

/// A convenience view used by the health tool and tests.
pub type HealthReport = serde_json::Value;

/// Marker for the structured result types tools return.
pub type ToolOutput = Result<CallToolResult, McpErrorData>;

/// Errors that the facade can raise, re-exported for the binary's error mapping.
pub use crate::error::ErrorCode as Code;

/// The default runtime preference, exposed for the health report.
pub const PREFERRED_RUNTIME: &str = "firecracker";

/// Ensures `ExecOutcome` stays serialisable for structured tool output.
const _: fn() = || {
    fn assert_serializable<T: Serialize>() {}
    assert_serializable::<ExecOutcome>();
};

/// Shared state type used by the axum wiring.
pub type Shared = Arc<AiecMcp>;

/// Error code for an unreachable control plane, re-exported for callers.
pub const UNAVAILABLE: ErrorCode = ErrorCode::AiecApiUnavailable;
