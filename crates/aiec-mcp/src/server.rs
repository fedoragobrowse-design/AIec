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
    pub approval: Option<Arc<crate::approval::ApprovalGate>>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Destroy owned sandboxes on shutdown. Parsed for a while but never
    /// read: without it a restarted server orphaned every machine it made.
    pub cleanup_on_shutdown: bool,
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
        let approval = config.approval_required.then(|| {
            // The approver talks to the same control plane, on the same key,
            // as everything else this server does. It has no way to answer
            // for itself, so it can only relay a decision.
            Arc::new(crate::approval::ApprovalGate::new(
                std::sync::Arc::new(crate::approval::ControlPlaneApprover::new(
                    aiec.client().clone(),
                    // The default policy is the fail-closed one: the
                    // operations an operator would not want done to them
                    // without asking.
                    crate::approval::ApprovalPolicy::default(),
                )),
                true,
            ))
        });
        Ok(Self {
            aiec,
            default_image: "python:3.13".to_owned(),
            // Firecracker is the local microVM runtime; it is preferred
            // whenever the worker offers it.
            default_runtime: "firecracker".to_owned(),
            default_ttl_seconds: config.default_ttl_seconds,
            max_parallel: config.max_parallel,
            started_at: chrono::Utc::now(),
            approval,
            cleanup_on_shutdown: config.cleanup_on_shutdown,
        })
    }

    /// Resolves a sandbox id, reporting a typed error for a malformed one.
    fn sandbox_id(&self, raw: &str) -> ToolResult<Uuid> {
        Uuid::parse_str(raw.trim()).map_err(|_| {
            McpError::invalid(format!("`{raw}` is not a sandbox id"))
                .with_details(json!({ "sandbox_id": raw }))
        })
    }

    /// Asks the control plane for permission before a high-risk tool runs.
    ///
    /// The tool is named in the policy's own vocabulary (`sandbox.destroy`,
    /// not `aiec_destroy_sandbox`) because that is what the control plane
    /// compares against. A deployment with no gate is unaffected; a
    /// deployment with one gets a refusal, not a retry, when the service
    /// cannot answer.
    async fn approve(
        &self,
        tool: &str,
        sandbox: Uuid,
        arguments: &serde_json::Value,
    ) -> ToolResult<()> {
        let Some(gate) = self.approval.as_ref() else {
            return Ok(());
        };
        // The digest is taken from the complete call, here, immediately before
        // dispatch — not from whatever summary the caller passed in. A summary
        // is a lossy thing to authorise: approving `write_file("/etc/rc")` says
        // nothing about the bytes written there, so a grant bound to it would
        // carry over to any content written next.
        let digest = aiec_core::approval_request_digest(tool, arguments);
        let detail = arguments_summary(tool, arguments);
        gate.check(sandbox, tool, &digest, detail.as_deref())
            .await
            .map(|_| ())
            .map_err(|refusal| {
                McpError::new(
                    ErrorCode::ApprovalRefused,
                    format!("{tool} was not approved: {refusal}"),
                )
                .with_sandbox(sandbox)
                .with_details(json!({
                    "tool": tool,
                    // `Unavailable` means nobody answered. That is the case an
                    // operator needs to see distinguished from a decision.
                    "unreachable": matches!(
                        refusal,
                        crate::approval::ApprovalRefusal::Unavailable
                    ),
                }))
            })
    }
}

/// A short, human-readable description of one call, for the operator's queue.
///
/// Only what an operator needs to recognise the call, and bounded: this is
/// shown to a person deciding, not an audit record, and the durable record is
/// the row this request produces. File content is deliberately reduced to a
/// length rather than quoted — an operator needs to know a large body is about
/// to be written, not to read it here, and content can be anything at all.
fn arguments_summary(tool: &str, arguments: &serde_json::Value) -> Option<String> {
    let object = arguments.as_object()?;
    match tool {
        "sandbox.write_file"
        | "sandbox.delete_file"
        | "sandbox.make_directory"
        | "sandbox.import_workspace_archive" => {
            let path = object.get("path").and_then(|p| p.as_str())?;
            match object.get("content").and_then(|c| c.as_str()) {
                Some(content) => Some(format!("{path} ({} bytes)", content.len())),
                None => Some(path.to_string()),
            }
        }
        "sandbox.exec" => {
            let command = object.get("command").and_then(|c| c.as_str())?;
            Some(format!("exec {command}"))
        }
        "sandbox.destroy" => Some("destroy sandbox".to_string()),
        _ => None,
    }
    .map(|summary| summary.chars().take(256).collect())
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
    /// Allow the sandbox to reach the internet.
    ///
    /// Still the right flag on a Docker worker, which does not enforce Guard
    /// and therefore still has the ordinary NAT path. On a Firecracker worker
    /// it is refused without `guard_allowlist`, because a microVM there has no
    /// ungoverned egress to grant.
    #[serde(default)]
    pub network_enabled: Option<bool>,
    /// Govern egress with a Guard policy naming the hosts the sandbox may
    /// reach. Required instead of `network_enabled` on a Firecracker worker.
    #[serde(default)]
    pub guard_allowlist: Option<Vec<String>>,
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
    /// Builds the OMP checkout. Defaults to Bun install and build.
    #[serde(default)]
    pub build_command: Option<Vec<String>>,
    #[serde(default)]
    pub omp_command: Option<Vec<String>>,
    #[serde(default)]
    pub validation_commands: Option<Vec<Vec<String>>>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub keep_sandbox: Option<bool>,
    #[serde(default)]
    pub cpu: Option<u32>,
    #[serde(default)]
    pub memory_mb: Option<u32>,
    #[serde(default)]
    pub disk_mb: Option<u32>,
    /// Extra hosts the run may reach beyond the two it clones: a model endpoint,
    /// a package registry. Without these the governed policy covers only the
    /// clones and the run fails at its first call to anything else.
    #[serde(default)]
    pub network_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub requirements: Option<crate::runs::RunRequirements>,
    /// Non-secret environment only. Use `secrets` for tenant credential references.
    #[serde(default)]
    pub environment: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub secrets: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CompareOmpArgs {
    pub omp_repo: String,
    /// Prepares the target repository before the agent runs.
    #[serde(default)]
    pub setup_command: Option<Vec<String>>,
    /// Builds the OMP checkout. Defaults to Bun install and build.
    #[serde(default)]
    pub build_command: Option<Vec<String>>,
    /// Override invocation, with the task on stdin and in OMP_TASK.
    #[serde(default)]
    pub omp_command: Option<Vec<String>>,
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
    #[serde(default)]
    pub cpu: Option<u32>,
    #[serde(default)]
    pub memory_mb: Option<u32>,
    #[serde(default)]
    pub disk_mb: Option<u32>,
    /// Extra hosts the run may reach beyond the two it clones: a model endpoint,
    /// a package registry. Without these the governed policy covers only the
    /// clones and the run fails at its first call to anything else.
    #[serde(default)]
    pub network_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub requirements: Option<crate::runs::RunRequirements>,
    /// Non-secret environment only. Use `secrets` for tenant credential references.
    #[serde(default)]
    pub environment: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub secrets: Option<Vec<String>>,
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
                    args.guard_allowlist,
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
        // Asked before anything is torn down, not after.
        self.approve("sandbox.destroy", id, &json!({})).await?;
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
            // A command can overwrite or delete anything in the sandbox, so
            // this stays destructive. The MCP default is already conservative
            // and downgrading it for fewer confirmation prompts would trade a
            // safety signal for convenience; a client that wants to allow-list
            // this tool can do so on its own side.
            destructive_hint = true,
            idempotent_hint = false,
            // It reaches the network from inside the sandbox.
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
        // The path is the detail an operator needs to judge the call, and it is
        // a path inside a disposable sandbox, not a credential.
        // Both the target and the bytes are in the digest. The operator judges
        // the path; the control plane binds the content, so an approval cannot
        // be carried over to different bytes at the same path.
        self.approve(
            "sandbox.write_file",
            id,
            &json!({ "path": args.path, "content": args.content }),
        )
        .await?;
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
        description = "Submit an ordinary durable Run on the local AIec control plane, clone \
and build a given OMP revision, run its Bun checkout launcher against a target task, and \
return real setup, task, validation, git and cleanup evidence. Set keep_sandbox for debugging.",
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
                    build_command: args.build_command,
                    omp_command: args.omp_command,
                    validation_commands: args.validation_commands.unwrap_or_default(),
                    timeout_seconds: args.timeout_seconds,
                    keep_sandbox: args.keep_sandbox.unwrap_or(false),
                    repetitions: 1,
                    // Left as `None` on purpose: the derived default governs
                    // egress with the repositories this run clones plus any
                    // `network_hosts` the caller named. A bare `Internet`
                    // here would both widen the policy past what the run needs
                    // and be refused outright by a Guard worker.
                    resources: None,
                    network_hosts: args.network_hosts.unwrap_or_default(),
                    requirements: args.requirements.unwrap_or_default().into(),
                    environment: args.environment.unwrap_or_default(),
                    secrets: args.secrets.unwrap_or_default(),
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
                    setup_command: args.setup_command,
                    build_command: args.build_command,
                    omp_command: args.omp_command,
                    validation_commands: args.validation_commands.unwrap_or_default(),
                    repetitions: args.repetitions,
                    timeout_seconds: args.timeout_seconds,
                    max_parallel: Some(max_parallel),
                    // As in `aiec_test_omp`: the derived policy governs, and a
                    // bare `Internet` here would widen it and be refused by a
                    // Guard worker.
                    resources: None,
                    network_hosts: args.network_hosts.unwrap_or_default(),
                    requirements: args.requirements.unwrap_or_default().into(),
                    environment: args.environment.unwrap_or_default(),
                    secrets: args.secrets.unwrap_or_default(),
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
    pub(crate) async fn report<T, F>(
        &self,
        tool: &str,
        body: F,
    ) -> Result<CallToolResult, McpErrorData>
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
                // Built from the error's own details rather than replaced by a
                // fresh object: a tool that could not clean up attaches that
                // fact to the error, and dropping it here would leave the caller
                // holding a dead sandbox id and no idea.
                let mut details = if error.details.is_object() {
                    error.details.clone()
                } else {
                    json!({})
                };
                if let Some(object) = details.as_object_mut() {
                    object.insert("code".to_owned(), json!(error.code.as_str()));
                    // The sandbox id travels with the failure. A destroy that
                    // leaves a machine behind is the case that matters: the
                    // caller has to be able to name the machine it still holds,
                    // and the resource path already reports it this way.
                    if let Some(id) = &error.sandbox_id {
                        object.insert("sandbox_id".to_owned(), json!(id));
                    }
                    object.insert("request_id".to_owned(), json!(request_id.to_string()));
                }
                Err(McpErrorData::invalid_params(
                    error.message.clone(),
                    Some(details),
                ))
            }
        }
    }
}

/// Renders a value as a structured tool result with JSON text.
pub(crate) fn structured<T: Serialize>(value: &T) -> CallToolResult {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned());
    CallToolResult::success(vec![ContentBlock::text(text)])
}

// ---------------------------------------------------------------------------
// Handler, resources and prompts
// ---------------------------------------------------------------------------

#[tool_handler(router = crate::server::router())]
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

/// Every tool this server serves, sandbox tools and run tools together.
///
/// The handler dispatches through this router rather than through the
/// macro-generated one, so a tool defined in another module is reachable
/// without a second `ServerHandler` impl.
pub fn router() -> ToolRouter<AiecMcp> {
    AiecMcp::tool_router() + AiecMcp::run_tool_router()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A server pointed at an address nothing answers on: `report` never
    /// reaches the control plane in these tests, so the endpoint is only there
    /// to satisfy the local-only check.
    fn server() -> AiecMcp {
        let config = Config {
            bind: "127.0.0.1:0".parse().expect("a socket address"),
            endpoint: crate::guard::LocalEndpoint::parse("http://127.0.0.1:1", false)
                .expect("loopback is local"),
            api_key: "test-key".to_owned(),
            token: Arc::new(zeroize::Zeroizing::new("test-token".to_owned())),
            max_parallel: 1,
            default_ttl_seconds: 1800,
            max_output_bytes: 1_048_576,
            cleanup_on_shutdown: false,
            approval_required: false,
        };
        AiecMcp::new(&config).expect("a local endpoint builds a client")
    }

    /// The shutdown flag reaches the server: it was parsed for a while while
    // nothing read it, so a `true` config building a `false` server would
    // silently orphan every owned machine on restart.
    #[test]
    fn the_cleanup_flag_reaches_the_server() {
        let mut config = Config {
            bind: "127.0.0.1:0".parse().expect("a socket address"),
            endpoint: crate::guard::LocalEndpoint::parse("http://127.0.0.1:1", false)
                .expect("loopback is local"),
            api_key: "test-key".to_owned(),
            token: Arc::new(zeroize::Zeroizing::new("test-token".to_owned())),
            max_parallel: 1,
            default_ttl_seconds: 1800,
            max_output_bytes: 1_048_576,
            cleanup_on_shutdown: true,
            approval_required: false,
        };
        assert!(AiecMcp::new(&config).expect("a server").cleanup_on_shutdown);
        config.cleanup_on_shutdown = false;
        assert!(!AiecMcp::new(&config).expect("a server").cleanup_on_shutdown);
    }

    /// The machine a destroy could not clean up is still the caller's to
    /// dispose of, so the id has to arrive with the error. Without it the
    /// caller is left holding a sandbox it can neither identify nor clean up.
    #[tokio::test]
    async fn a_tool_error_names_the_sandbox_it_could_not_clean_up() {
        let id = Uuid::now_v7();
        let failure = server()
            .report("aiec_destroy_sandbox", async {
                Err::<serde_json::Value, McpError>(
                    McpError::new(
                        ErrorCode::AiecApiUnavailable,
                        "the sandbox is still `running` after destroy was requested",
                    )
                    .with_sandbox(id),
                )
            })
            .await
            .expect_err("the tool failed");

        let details = failure.data.expect("the error carries details");
        assert_eq!(
            details["sandbox_id"].as_str(),
            Some(id.to_string().as_str()),
            "the tool error dropped the sandbox id: {details}"
        );
    }

    /// The id is added to whatever the tool already attached, not in place of
    /// it: the reason for the failure is what the caller acts on first.
    #[tokio::test]
    async fn a_tool_error_keeps_its_own_details_alongside_the_sandbox_id() {
        let id = Uuid::now_v7();
        let failure = server()
            .report("aiec_destroy_sandbox", async {
                Err::<serde_json::Value, McpError>(
                    McpError::new(
                        ErrorCode::AiecApiUnavailable,
                        "the sandbox is still `running`",
                    )
                    .with_sandbox(id)
                    .with_details(json!({ "state": "running" })),
                )
            })
            .await
            .expect_err("the tool failed");

        let details = failure.data.expect("the error carries details");
        assert_eq!(
            details["sandbox_id"].as_str(),
            Some(id.to_string().as_str())
        );
        assert_eq!(details["state"].as_str(), Some("running"));
        assert_eq!(
            details["code"].as_str(),
            Some(ErrorCode::AiecApiUnavailable.as_str())
        );
    }

    /// A failure with no sandbox to name says so by omission rather than
    /// reporting an empty id the caller might try to act on.
    #[tokio::test]
    async fn a_tool_error_without_a_sandbox_carries_no_sandbox_id() {
        let failure = server()
            .report("aiec_list_sandboxes", async {
                Err::<serde_json::Value, McpError>(McpError::new(
                    ErrorCode::AiecApiUnavailable,
                    "the local AIec control plane is unreachable",
                ))
            })
            .await
            .expect_err("the tool failed");

        let details = failure.data.expect("the error carries details");
        assert!(
            details.get("sandbox_id").is_none(),
            "an empty sandbox id was invented: {details}"
        );
    }

    /// A server with the gate on, pointed at a control plane that is not
    /// there. This is the case that matters: the approval service is
    /// unavailable, and the high-risk tool must not run anyway.
    fn gated_server() -> AiecMcp {
        let mut server = server();
        server.approval = Some(Arc::new(crate::approval::ApprovalGate::new(
            std::sync::Arc::new(Unreachable),
            true,
        )));
        server
    }

    /// Refuses when nothing can answer, before the tool body runs at all.
    /// The endpoint is a dead port, so a body that ran would fail with
    /// `AiecApiUnavailable` instead - a different code, and the whole point.
    #[tokio::test]
    async fn a_destructive_tool_is_refused_when_approval_is_unavailable() {
        let id = Uuid::now_v7();
        let error = gated_server()
            .destroy_sandbox(Parameters(SandboxIdArgs {
                sandbox_id: id.to_string(),
            }))
            .await
            .expect_err("an unreachable approval service is not an approval");

        let details = error.data.expect("the refusal carries details");
        assert_eq!(
            details["code"].as_str(),
            Some(ErrorCode::ApprovalRefused.as_str()),
            "a refusal must be its own code, not the generic unavailable one: {details}"
        );
        assert_eq!(
            details["unreachable"].as_bool(),
            Some(true),
            "an unanswered approval must be distinguishable from a decision: {details}"
        );
    }

    /// A read is not high risk, so it is never asked about. If it were, a
    /// deployment with the gate on would be unusable - the test is that the
    /// gate does not fire for tools the policy does not list.
    #[tokio::test]
    async fn a_tool_the_policy_does_not_list_is_never_asked_about() {
        // The control plane is unreachable, so an ask would surface as a
        // refusal. Not getting one proves the ask did not happen.
        let outcome = gated_server()
            .approve("sandbox.get", Uuid::now_v7(), &json!({}))
            .await;
        assert!(
            outcome.is_ok(),
            "a read should not need approval: {outcome:?}"
        );
    }

    /// The tools the default policy names are exactly the destructive ones
    /// this server exposes, and the two names agree.
    #[test]
    fn the_gate_covers_the_destructive_tools_this_server_exposes() {
        let policy = crate::approval::ApprovalPolicy::default();
        for tool in ["sandbox.destroy", "sandbox.write_file"] {
            assert!(
                policy.requires_approval(tool),
                "{tool} is exposed as destructive and is not gated"
            );
        }
        for tool in ["sandbox.get", "sandbox.list_owned", "sandbox.read_file"] {
            assert!(
                !policy.requires_approval(tool),
                "{tool} is a read and would be escalated by mistake"
            );
        }
    }

    /// An approver that never answers, standing in for a control plane that
    /// is not reachable.
    struct Unreachable;

    #[async_trait::async_trait]
    impl crate::approval::Approver for Unreachable {
        // The real policy, so which tools are asked about is not decided by
        // the test double.
        fn requires_approval(&self, tool: &str) -> bool {
            crate::approval::ApprovalPolicy::default().requires_approval(tool)
        }
        async fn approve(
            &self,
            _sandbox: Uuid,
            _tool: &str,
            _request_digest: &str,
            _detail: Option<&str>,
        ) -> Option<crate::approval::ApprovalDecision> {
            None
        }
    }
}
