//! Run tools: durable work, driven by the control plane.
//!
//! A run is not a sandbox this server creates and destroys itself. It is the
//! control plane's own workflow: it reserves durable state, places a machine
//! through the same registry the sandbox API uses, runs the command, collects
//! artifacts and reclaims the machine before it answers. So these tools call
//! the API and report what it settled, rather than re-implementing the
//! workflow here.
//!
//! `crate::eval` still holds the older sandbox-by-sandbox workflow, which is
//! the right thing for the multi-step agent harnesses it drives. The difference
//! is deliberate: a run is the control plane's record of the work, and a tool
//! that rebuilt it locally would have no record, no history and no idempotency.

use std::collections::BTreeMap;

use aiec_client::{CreateRunRequest, RunCell};
use aiec_core::network::NetworkPolicy;
use aiec_core::run::{
    CapabilityRequirements, RepoSpec, ResourceRequirements, RetentionPolicy, Run, RunEvent,
    WorkloadSpec,
};
use rmcp::ErrorData as McpErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{schemars, tool, tool_router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::error::{McpError, ToolResult};
use crate::guard::LocalEndpoint;
use crate::sandbox::{clamp, map_client_error};
use crate::server::AiecMcp;

/// How much of a command's output a tool result carries.
///
/// A run's stdout is evidence, not a document to be read in full: the rest is
/// one fetch away, and a tool result that is megabytes of log is a tool result
/// the calling agent will not read.
const MAX_TOOL_OUTPUT_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Tool parameter types
// ---------------------------------------------------------------------------

/// What a run needs from its *runtime*, as a one-way demand.
///
/// A caller states requirements, not providers: asking for full kernel
/// isolation and letting the scheduler choose is what stops every caller
/// hardcoding a runtime.
#[derive(Clone, Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct RunRequirements {
    #[serde(default)]
    pub full_kernel_isolation: Option<bool>,
    #[serde(default)]
    pub coding_guest: Option<bool>,
    #[serde(default)]
    pub network_policy: Option<bool>,
    #[serde(default)]
    pub workspace_snapshot: Option<bool>,
    #[serde(default)]
    pub portable_workspace: Option<bool>,
    #[serde(default)]
    pub memory_resume: Option<bool>,
    #[serde(default)]
    pub pty: Option<bool>,
    #[serde(default)]
    pub pause: Option<bool>,
}

impl From<RunRequirements> for CapabilityRequirements {
    fn from(value: RunRequirements) -> Self {
        let demand = |asked: Option<bool>| asked.unwrap_or(false);
        Self {
            full_kernel_isolation: demand(value.full_kernel_isolation),
            coding_guest: demand(value.coding_guest),
            network_policy: demand(value.network_policy),
            workspace_snapshot: demand(value.workspace_snapshot),
            portable_workspace: demand(value.portable_workspace),
            memory_resume: demand(value.memory_resume),
            pty: demand(value.pty),
            pause: demand(value.pause),
        }
    }
}

/// Parses a Guard template name into the selection the API deserialises.
///
/// A closed set rather than a free string, so a template that does not exist is
/// refused here with a message naming the ones that do, rather than becoming a
/// policy error after a machine has been placed.
fn guard_config(name: &str) -> Result<aiec_guard::policy::GuardConfig, McpError> {
    use aiec_guard::policy::{GuardConfig, PolicyTemplate, Topology};
    let policy_template = match name.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "no-network" => PolicyTemplate::NoNetwork,
        "model-only" => PolicyTemplate::ModelOnly,
        "model-plus-allowlist" => PolicyTemplate::ModelPlusAllowlist,
        "read-only-api" => PolicyTemplate::ReadOnlyApi,
        other => {
            return Err(McpError::invalid(format!(
                "unknown Guard template `{other}`; use no-network, model-only, \
                 model-plus-allowlist or read-only-api"
            )));
        }
    };
    Ok(GuardConfig {
        topology: Topology::default(),
        policy_template,
        policy: None,
        model_endpoint: None,
        allowlist: Vec::new(),
        ..Default::default()
    })
}

/// A Guard policy permitting exactly the named hosts, and the methods a clone
/// needs.
///
/// Shared by the run and sandbox tools: both need "these hosts, and nothing
/// else", and two spellings of that is how a client and a control plane drift.
///
/// An explicit document rather than a template, because neither shipped
/// template can express a governed clone. `read-only-api` refuses a rule
/// carrying `POST` by design; `model-plus-allowlist` accepts per-rule methods
/// but demands a model endpoint, and a clone has none.
pub fn allowlist_guard(hosts: Vec<String>) -> Result<aiec_guard::policy::GuardConfig, McpError> {
    use aiec_guard::policy::{
        DnsPolicy, EgressRule, GuardConfig, GuardPolicy, NetworkPolicy, PolicyTemplate, Topology,
    };
    if hosts.is_empty() {
        return Err(McpError::invalid(
            "a Guard allowlist must name at least one host, or leave the network off",
        ));
    }
    if hosts.len() > 16 {
        return Err(McpError::invalid(
            "a Guard allowlist may name at most 16 hosts",
        ));
    }
    // Deduplicated once, and the same vector feeds both the zones and the rules.
    // Two names that resolve to one host - a caller naming it twice, or a fork
    // and its upstream - are one destination, and Guard refuses a policy that
    // names the same destination or zone twice. Deriving the two from
    // different lists is how one of them ends up duplicated and the other not.
    let mut unique: Vec<String> = Vec::new();
    for host in hosts {
        if !unique.contains(&host) {
            unique.push(host);
        }
    }
    let egress = unique
        .iter()
        .cloned()
        .map(|host| EgressRule {
            host,
            port: 443,
            protocol: "tcp".to_string(),
            // POST because a clone is a read that uses POST as its transport
            // verb; read-only is carried by the host and the path, not by the
            // verb.
            allowed_methods: vec!["GET".into(), "HEAD".into(), "POST".into()],
            allowed_paths: Vec::new(),
        })
        .collect();
    Ok(GuardConfig {
        topology: Topology::Inside,
        policy_template: PolicyTemplate::NoNetwork,
        policy: Some(GuardPolicy {
            version: 1,
            network: NetworkPolicy {
                dns: DnsPolicy {
                    allowed_zones: unique,
                    allowed_record_types: vec!["A".into(), "AAAA".into()],
                },
                egress,
            },
            model: None,
            credentials: Vec::new(),
            limits: Default::default(),
        }),
        model_endpoint: None,
        allowlist: Vec::new(),
        ..Default::default()
    })
}

/// One workload, as a calling agent states it.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunArgs {
    /// The work, as an argument vector. Never a shell string, so a task cannot
    /// be a command injection by construction.
    pub command: Vec<String>,
    /// Image to boot. Defaults to the control plane's own default image.
    #[serde(default)]
    pub image: Option<String>,
    /// Repository to start from, cloned inside the sandbox by the control
    /// plane over https, git@ or ssh.
    #[serde(default)]
    pub repo_url: Option<String>,
    /// Branch, tag or commit to check out.
    #[serde(default)]
    pub repo_ref: Option<String>,
    /// Commands run in order before the task, each an argument vector.
    #[serde(default)]
    pub setup_commands: Option<Vec<Vec<String>>>,
    /// Run after the task; all of them run even if one fails.
    #[serde(default)]
    pub validation_commands: Option<Vec<Vec<String>>>,
    /// Paths to collect once the task is done.
    #[serde(default)]
    pub artifacts: Option<Vec<String>>,
    /// Non-secret environment for the task. Secrets are named, not inlined.
    #[serde(default)]
    pub environment: Option<BTreeMap<String, String>>,
    /// Names of tenant secrets to inject, resolved at execution time.
    #[serde(default)]
    pub secrets: Option<Vec<String>>,
    /// Collect git status, git diff and the changed-file list.
    #[serde(default)]
    pub git_evidence: Option<bool>,
    /// How long the task may run, in seconds.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub cpu: Option<u32>,
    #[serde(default)]
    pub memory_mb: Option<u32>,
    #[serde(default)]
    pub disk_mb: Option<u32>,
    /// General outbound network access. Needed for a repository clone, since
    /// the guest is the thing that runs `git clone`.
    #[serde(default)]
    pub network: Option<bool>,
    /// Govern egress from outside the guest with a Guard policy template:
    /// `no-network`, `model-only`, `model-plus-allowlist` or `read-only-api`.
    ///
    /// This replaces `network` rather than accompanying it. A governed run is
    /// not an ungoverned one that happens to be filtered, and a caller that set
    /// both would otherwise have asked for two different egress policies and
    /// got whichever was wider.
    #[serde(default)]
    pub guard: Option<String>,
    /// `destroy`, `keep_on_failure` or `keep_always`. Keeping a machine is
    /// time-limited whatever the outcome, because a failure is not a licence to
    /// hold compute forever.
    #[serde(default)]
    pub retention: Option<String>,
    /// Advanced use only: pin the local runtime instead of letting the
    /// scheduler choose. `hosted` and external providers are refused.
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub requirements: Option<RunRequirements>,
    /// Reuse a key to get the run that already exists instead of executing the
    /// work twice.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub matrix_id: Option<String>,
    #[serde(default)]
    pub parent_run_id: Option<String>,
}

/// Several workloads, run with bounded concurrency.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunBatchArgs {
    pub tasks: Vec<RunArgs>,
    /// How many machines the batch may hold at once. Defaults to this
    /// server's configured limit.
    #[serde(default)]
    pub max_parallel: Option<usize>,
}

/// One cell of a matrix: a workload plus the axis values that name it.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MatrixCellArgs {
    /// What this cell varies, e.g. `{"model": "opus"}`. Reported back so a
    /// reader can see which variable moved the number.
    #[serde(default)]
    pub axis: BTreeMap<String, String>,
    #[serde(flatten)]
    pub run: RunArgs,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunMatrixArgs {
    pub cells: Vec<MatrixCellArgs>,
    #[serde(default)]
    pub max_parallel: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunIdArgs {
    pub run_id: String,
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// A run as reported back to a calling agent.
///
/// The settled document is the record; this is the part of it an agent acts
/// on, with output bounded so a chatty workload cannot bury the result.
#[derive(Debug, Clone, Serialize)]
pub struct RunView {
    pub run_id: String,
    pub state: String,
    pub failure_reason: Option<String>,
    /// The task's exit code, when the run got as far as running it.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// Set when the sandbox clipped the output, so a missing tail is reported
    /// rather than mistaken for a clean run.
    pub truncated: bool,
    pub output_preview_truncated: bool,
    pub git_evidence_truncated: bool,
    /// Which validations failed, as `command -> exit code`.
    pub failed_validations: Vec<String>,
    pub changed_files: Vec<String>,
    pub commit: Option<String>,
    pub artifacts: Vec<RunArtifactView>,
    /// Where the run was placed and why, so a refused placement is
    /// answerable without re-running the scheduler by hand.
    pub placement: Value,
    /// Set when a machine outlived its run: the caller is never left with a
    /// live sandbox it believes was released.
    pub retained_sandbox_id: Option<String>,
    pub cleanup_failed: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunArtifactView {
    pub name: String,
    pub size_bytes: i64,
    /// Absolute within the API, so the bytes are one GET away.
    pub download_url: String,
}

impl RunView {
    fn of(run: &Run) -> Self {
        let task = run.results.task.as_ref();
        let (stdout, stdout_clipped) = clamp(
            task.map(|outcome| outcome.stdout.as_str())
                .unwrap_or_default(),
            MAX_TOOL_OUTPUT_BYTES,
        );
        let (stderr, stderr_clipped) = clamp(
            task.map(|outcome| outcome.stderr.as_str())
                .unwrap_or_default(),
            MAX_TOOL_OUTPUT_BYTES,
        );
        Self {
            run_id: run.id.to_string(),
            state: run.state.as_str().to_owned(),
            failure_reason: run.failure_reason.clone(),
            exit_code: task.map(|outcome| outcome.exit_code),
            stdout,
            stderr,
            truncated: task.is_some_and(|outcome| outcome.truncated),
            output_preview_truncated: stdout_clipped
                || stderr_clipped
                || task.is_some_and(|outcome| outcome.output_preview_truncated),
            git_evidence_truncated: run.results.git_evidence_truncated,
            failed_validations: run
                .results
                .validations
                .iter()
                .filter(|outcome| outcome.exit_code != 0)
                .map(|outcome| format!("{} -> {}", outcome.command.join(" "), outcome.exit_code))
                .collect(),
            changed_files: run.results.changed_files.clone(),
            commit: run.results.commit.clone(),
            artifacts: run
                .results
                .artifacts
                .iter()
                .map(|artifact| RunArtifactView {
                    name: artifact.name.clone(),
                    size_bytes: artifact.size_bytes,
                    download_url: format!("/v1/runs/{}/artifacts/{}", run.id, artifact.name),
                })
                .collect(),
            placement: serde_json::to_value(&run.placement).unwrap_or_else(|_| json!({})),
            retained_sandbox_id: run.retained_sandbox_id.map(|id| id.to_string()),
            cleanup_failed: run
                .results
                .cleanup_failed
                .as_ref()
                .and_then(|report| serde_json::to_value(report).ok()),
        }
    }
}

/// One cell of a batch or a matrix, and what became of it.
#[derive(Debug, Clone, Serialize)]
pub struct RunCellView {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axis: Option<BTreeMap<String, String>>,
    pub run: Option<RunView>,
    /// Why this cell produced no run. The control plane refused it.
    pub error: Option<String>,
}

impl RunCellView {
    fn of(cell: &RunCell) -> Self {
        Self {
            index: cell.index,
            axis: None,
            run: cell.run.as_ref().map(RunView::of),
            error: cell.error.clone(),
        }
    }

    fn succeeded(&self) -> bool {
        self.run
            .as_ref()
            .is_some_and(|run| run.state == "succeeded")
    }
}

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

/// Parses a run id, reporting a typed error for a malformed one.
fn run_id(raw: &str) -> ToolResult<Uuid> {
    Uuid::parse_str(raw.trim()).map_err(|_| {
        McpError::invalid(format!("`{raw}` is not a run id")).with_details(json!({ "run_id": raw }))
    })
}

/// The workload, resources and policy one tool call asked for.
///
/// Refused here rather than by the API, because a workload with no command is a
/// request the caller can fix without waiting for a machine to be placed first.
fn run_request(args: &RunArgs, default_image: Option<&str>) -> ToolResult<CreateRunRequest> {
    if args.command.is_empty() {
        return Err(McpError::invalid("the workload has no command"));
    }

    let repo = match (&args.repo_url, &args.repo_ref) {
        (Some(url), reference) => {
            let spec = RepoSpec {
                url: url.clone(),
                reference: reference.clone(),
                ..Default::default()
            };
            // A URL carrying a credential would end up in the run document and
            // in every error message that renders it, so it is refused here.
            spec.validate()
                .map_err(|error| McpError::invalid(error.to_string()))?;
            Some(spec)
        }
        (None, Some(_)) => {
            return Err(McpError::invalid(
                "repo_ref was given without repo_url, so there is nothing to check out",
            ));
        }
        (None, None) => None,
    };

    let runtime = match args.runtime.as_deref() {
        Some(runtime) => {
            // The local-only guarantee is this server's whole reason for
            // existing, so a named runtime is checked here rather than trusted.
            LocalEndpoint::require_local_runtime(runtime)?;
            Some(runtime.to_owned())
        }
        None => None,
    };

    let retention = match args.retention.as_deref() {
        Some(raw) => RetentionPolicy::parse(raw.trim()).ok_or_else(|| {
            McpError::invalid(format!(
                "unknown retention `{raw}`; use destroy, keep_on_failure or keep_always"
            ))
        })?,
        None => RetentionPolicy::Destroy,
    };

    let request = CreateRunRequest {
        workload: WorkloadSpec {
            image: args
                .image
                .clone()
                .or_else(|| default_image.map(str::to_owned)),
            repo,
            setup: args.setup_commands.clone().unwrap_or_default(),
            command: args.command.clone(),
            validations: args.validation_commands.clone().unwrap_or_default(),
            artifacts: args.artifacts.clone().unwrap_or_default(),
            environment: args.environment.clone().unwrap_or_default(),
            secrets: args.secrets.clone().unwrap_or_default(),
            timeout_seconds: args.timeout_seconds,
            git_evidence: args.git_evidence.unwrap_or(false),
        },
        resources: ResourceRequirements {
            cpu: args.cpu.unwrap_or(1),
            memory_mb: args.memory_mb.unwrap_or(1024),
            disk_mb: args.disk_mb.unwrap_or(2048),
            // A Guard selection replaces the network policy rather than
            // sitting beside it: two descriptions of one egress would be two
            // paths to the internet, and the wider one would be the one that
            // applied. A caller who set both gets the governed one, and the
            // control plane refuses the combination anyway.
            network: if args.guard.is_some() {
                NetworkPolicy::Disabled
            } else if args.network.unwrap_or(false) {
                NetworkPolicy::Internet
            } else {
                NetworkPolicy::Disabled
            },
            guard: args.guard.as_deref().map(guard_config).transpose()?,
        },
        requirements: args.requirements.clone().unwrap_or_default().into(),
        retention,
        idempotency_key: args.idempotency_key.clone(),
        parent_run_id: optional_id(args.parent_run_id.as_deref(), "parent_run_id")?,
        matrix_id: optional_id(args.matrix_id.as_deref(), "matrix_id")?,
        requested_runtime: runtime,
        retained_seconds: None,
    };
    request
        .workload
        .validate()
        .map_err(|error| McpError::invalid(error.to_string()))?;
    Ok(request)
}

fn optional_id(raw: Option<&str>, field: &str) -> ToolResult<Option<Uuid>> {
    raw.map(run_id).transpose().map_err(|error| {
        McpError::invalid(error.message.clone()).with_details(json!({ "field": field }))
    })
}

/// The matrix summary: what ran, what passed, and which axis value moved it.
///
/// Measurements only, never a judgement: what "better" means depends on the
/// metric the caller cares about, and picking one for them would be inventing a
/// conclusion the data does not support.
fn summarise(cells: &[RunCellView]) -> Value {
    let mut by_axis: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut successes = 0;
    for cell in cells {
        let succeeded = cell.succeeded();
        successes += usize::from(succeeded);
        if let Some(axis) = &cell.axis {
            for (key, value) in axis {
                let tally = by_axis.entry(format!("{key}={value}")).or_insert((0, 0));
                tally.0 += usize::from(succeeded);
                tally.1 += 1;
            }
        }
    }
    json!({
        "cells": cells.len(),
        "successes": successes,
        "by_axis": by_axis
            .into_iter()
            .map(|(key, (successes, cells))| (key, json!({ "successes": successes, "cells": cells })))
            .collect::<serde_json::Map<String, Value>>(),
    })
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/// The run tools, merged into the server's router by [`crate::server::router`].
#[tool_router(router = run_tool_router, vis = "pub")]
impl AiecMcp {
    /// Runs one workload on the local control plane and reports the outcome.
    #[tool(
        name = "aiec_run",
        title = "Run workload",
        description = "Run one workload on the LOCAL AIec control plane: the control plane \
places a machine, runs setup commands, the task, then validations, collects artifacts and \
reclaims the machine, and returns the settled result with the task's exit code, output, \
changed files and artifact URLs. Prefer this over aiec_exec when the work is a self-contained \
task: a run is durable, keeps its own history, and never leaves a machine behind. The \
command is an argument vector, never a shell string.",
        annotations(
            title = "Run workload",
            read_only_hint = false,
            // It runs a command and destroys the machine it used, so it is
            // destructive in the same sense aiec_exec is.
            destructive_hint = true,
            idempotent_hint = false,
            // A repository clone or a dependency install reaches the network.
            open_world_hint = true
        )
    )]
    async fn run(
        &self,
        Parameters(args): Parameters<RunArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        self.report("aiec_run", async {
            let request = run_request(&args, Some(self.default_image.as_str()))?;
            let run = self
                .aiec
                .client()
                .create_run(&request)
                .await
                .map_err(|error| map_client_error(&error))?;
            Ok(RunView::of(&run))
        })
        .await
    }

    /// Runs several workloads with bounded concurrency.
    #[tool(
        name = "aiec_run_batch",
        title = "Run workload batch",
        description = "Run several workloads on the LOCAL AIec control plane, at most \
max_parallel machines at a time. Returns one entry per task in the order given, each with \
either its settled run or the reason the control plane refused it, so one task that cannot \
be scheduled does not abandon the rest.",
        annotations(
            title = "Run workload batch",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_batch(
        &self,
        Parameters(args): Parameters<RunBatchArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        self.report("aiec_run_batch", async {
            if args.tasks.is_empty() {
                return Ok(json!({ "max_parallel": self.max_parallel, "results": [] }));
            }
            let max_parallel = args.max_parallel.unwrap_or(self.max_parallel);
            let requests: Vec<CreateRunRequest> = args
                .tasks
                .iter()
                .map(|task| run_request(task, Some(self.default_image.as_str())))
                .collect::<ToolResult<_>>()?;
            let cells = self
                .aiec
                .client()
                .run_cells(&requests, max_parallel)
                .await
                .map_err(|error| map_client_error(&error))?;
            let results: Vec<RunCellView> = cells.iter().map(RunCellView::of).collect();
            Ok(json!({
                "max_parallel": max_parallel,
                "summary": summarise(&results),
                "results": results,
            }))
        })
        .await
    }

    /// Runs a matrix of cells, each in its own machine.
    #[tool(
        name = "aiec_run_matrix",
        title = "Run workload matrix",
        description = "Run a matrix of workloads on the LOCAL AIec control plane, each cell in \
its own machine, and report measurements per axis value. Every cell carries the same \
matrix_id and its own idempotency key, so the set is addressable as a group and re-running it \
returns the runs that already exist. Returns measurements only, never a judgement about which \
cell is better.",
        annotations(
            title = "Run workload matrix",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_matrix(
        &self,
        Parameters(args): Parameters<RunMatrixArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        self.report("aiec_run_matrix", async {
            if args.cells.is_empty() {
                return Ok(
                    json!({ "matrix_id": Value::Null, "results": [], "summary": summarise(&[]) }),
                );
            }
            let max_parallel = args.max_parallel.unwrap_or(self.max_parallel);
            // One id for the set, one key per cell: without both, a re-run would
            // either lose the grouping or hand every cell the first one's run.
            let matrix_id = Uuid::now_v7();
            let mut requests = Vec::with_capacity(args.cells.len());
            for cell in &args.cells {
                let mut request = run_request(&cell.run, Some(self.default_image.as_str()))?;
                request.matrix_id = Some(matrix_id);
                if request.idempotency_key.is_none() {
                    request.idempotency_key =
                        Some(format!("matrix-{matrix_id}-{}", requests.len()));
                }
                requests.push(request);
            }
            let cells = self
                .aiec
                .client()
                .run_cells(&requests, max_parallel)
                .await
                .map_err(|error| map_client_error(&error))?;
            let results: Vec<RunCellView> = cells
                .iter()
                .zip(args.cells.iter())
                .map(|(cell, requested)| RunCellView {
                    index: cell.index,
                    axis: Some(requested.axis.clone()),
                    run: cell.run.as_ref().map(RunView::of),
                    error: cell.error.clone(),
                })
                .collect();
            Ok(json!({
                "matrix_id": matrix_id.to_string(),
                "max_parallel": max_parallel,
                "summary": summarise(&results),
                "results": results,
            }))
        })
        .await
    }

    /// Reads one run's authoritative state.
    #[tool(
        name = "aiec_run_status",
        title = "Get run status",
        description = "Get the current authoritative state of one run on the LOCAL AIec \
control plane, with its exit code, output, changed files and any machine that outlived it.",
        annotations(
            title = "Get run status",
            read_only_hint = true,
            // Stated rather than left to the protocol default, which is not
            // the same value: a tool list a client has to interpret is a tool
            // list a client can misread.
            destructive_hint = false
        )
    )]
    async fn run_status(
        &self,
        Parameters(args): Parameters<RunIdArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let id = run_id(&args.run_id)?;
        self.report("aiec_run_status", async {
            let run = self.aiec.client().get_run(id).await.map_err(|error| {
                map_client_error(&error).with_details(json!({ "run_id": id.to_string() }))
            })?;
            Ok(RunView::of(&run))
        })
        .await
    }

    /// Reads a run's history, in the order it happened.
    #[tool(
        name = "aiec_run_events",
        title = "List run events",
        description = "List the events of one run on the LOCAL AIec control plane, in the order \
they happened: machine placement, task start, artifact collection, failure, cancellation. \
Event detail carries shapes and names, never a credential.",
        annotations(
            title = "List run events",
            read_only_hint = true,
            // Stated rather than left to the protocol default, which is not
            // the same value: a tool list a client has to interpret is a tool
            // list a client can misread.
            destructive_hint = false
        )
    )]
    async fn run_events(
        &self,
        Parameters(args): Parameters<RunIdArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let id = run_id(&args.run_id)?;
        self.report("aiec_run_events", async {
            let events: Vec<RunEvent> =
                self.aiec.client().run_events(id).await.map_err(|error| {
                    map_client_error(&error).with_details(json!({ "run_id": id.to_string() }))
                })?;
            Ok(events
                .into_iter()
                .map(|event| {
                    json!({
                        "event_type": event.event_type,
                        "occurred_at": event.occurred_at,
                        "sandbox_id": event.sandbox_id,
                        "detail": event.detail,
                    })
                })
                .collect::<Vec<Value>>())
        })
        .await
    }

    /// Stops a run and reclaims the machine it was holding.
    #[tool(
        name = "aiec_run_cancel",
        title = "Cancel run",
        description = "Cancel a run on the LOCAL AIec control plane and destroy the machines it \
was holding, reporting any machine that would not go. Cancelling a run that already finished \
succeeds and returns the run as it stands.",
        annotations(
            title = "Cancel run",
            read_only_hint = false,
            // It destroys machines, so it is destructive even though it is
            // also the tool a caller reaches for to stop work.
            destructive_hint = true,
            // Cancelling twice is defined to succeed, so it is safe to repeat.
            idempotent_hint = true
        )
    )]
    async fn run_cancel(
        &self,
        Parameters(args): Parameters<RunIdArgs>,
    ) -> Result<CallToolResult, McpErrorData> {
        let id = run_id(&args.run_id)?;
        self.report("aiec_run_cancel", async {
            let run = self.aiec.client().cancel_run(id).await.map_err(|error| {
                map_client_error(&error).with_details(json!({ "run_id": id.to_string() }))
            })?;
            Ok(RunView::of(&run))
        })
        .await
    }
}

/// Ensures the JSON views stay serialisable for structured tool output.
const _: fn() = || {
    fn assert_serialize<T: Serialize>() {}
    assert_serialize::<RunView>();
    assert_serialize::<RunCellView>();
    assert_serialize::<RunArtifactView>();
};

#[cfg(test)]
mod tests {
    use super::*;

    use aiec_core::run::RunState;
    use axum::Router as AxumRouter;
    use axum::body::Body;
    use axum::extract::{Request, State};
    use axum::http::StatusCode;
    use axum::response::Response;
    use axum::routing::any;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    /// `network_hosts` is caller input that flows straight into DNS zones and
    /// egress rules, and nothing else checks that what comes out is a policy
    /// Guard will accept. The compiler is the same check the API performs at
    /// admission, so running it here is the same check.
    #[test]
    fn the_allowlist_the_tool_builds_is_a_policy_guard_accepts() {
        let config = allowlist_guard(vec!["github.com".into()]).expect("an allowlist builds");
        let effective = config
            .effective_policy()
            .expect("the derived policy compiles");
        assert_eq!(effective.network.dns.allowed_zones, vec!["github.com"]);
        assert_eq!(effective.network.egress.len(), 1);
        // A governed clone fetches its pack with POST, so a rule without it
        // would compile and then break the clone it exists to permit.
        assert!(
            effective.network.egress[0]
                .allowed_methods
                .iter()
                .any(|method| method == "POST")
        );
    }

    /// The same host named twice is one destination, and Guard refuses a
    /// document that names a destination or a zone twice. Zones and rules are
    /// derived from one deduplicated vector so they cannot disagree about it.
    #[test]
    fn a_repeated_host_is_one_destination() {
        let config = allowlist_guard(vec!["github.com".into(), "github.com".into()])
            .expect("a repeated host is not an error by itself");
        let effective = config
            .effective_policy()
            .expect("the derived policy still compiles");
        assert_eq!(effective.network.dns.allowed_zones.len(), 1);
        assert_eq!(effective.network.egress.len(), 1);
    }

    #[test]
    fn an_empty_allowlist_is_refused_rather_than_denying_everything_silently() {
        assert!(allowlist_guard(Vec::new()).is_err());
    }

    /// A server pointed at a stub control plane, with no token file involved.
    fn server_for(url: &str, max_parallel: usize) -> AiecMcp {
        let config = crate::config::Config {
            bind: "127.0.0.1:0".parse().expect("a socket address"),
            endpoint: LocalEndpoint::parse(url, false).expect("a loopback control plane"),
            api_key: "af_live_key".to_owned(),
            token: Arc::new(zeroize::Zeroizing::new("token".to_owned())),
            max_parallel,
            default_ttl_seconds: 1800,
            max_output_bytes: 1_048_576,
            cleanup_on_shutdown: false,
            approval_required: false,
        };
        AiecMcp::new(&config).expect("a server")
    }

    /// A settled run, built from the real type so the stub cannot drift from
    /// what the control plane actually serialises.
    fn settled_run(state: RunState) -> Value {
        serde_json::to_value(Run {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            state,
            requested_at: chrono::Utc::now(),
            queued_at: None,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            workload: WorkloadSpec {
                command: vec!["pytest".to_owned(), "-q".to_owned()],
                ..Default::default()
            },
            resources: ResourceRequirements::default(),
            requirements: CapabilityRequirements::default(),
            placement: Default::default(),
            results: Default::default(),
            failure_reason: None,
            retention: RetentionPolicy::Destroy,
            retained_sandbox_id: None,
            retained_until: None,
            idempotency_key: None,
            parent_run_id: None,
            matrix_id: None,
            matrix_cell: None,
        })
        .expect("a run serialises")
    }

    #[derive(Clone, Default)]
    struct Stub {
        bodies: Arc<Mutex<Vec<Value>>>,
        paths: Arc<Mutex<Vec<String>>>,
        in_flight: Arc<AtomicUsize>,
        peak_in_flight: Arc<AtomicUsize>,
    }

    async fn stub_control_plane(stub: Stub) -> (String, tokio::task::JoinHandle<()>) {
        let app = AxumRouter::new()
            .fallback(any(handle))
            .with_state(stub.clone());
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
        let path = request.uri().path().to_owned();
        stub.paths.lock().await.push(path.clone());
        let raw = axum::body::to_bytes(request.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        stub.bodies.lock().await.push(body.clone());

        // Overlap on purpose, so a test can see how many submissions the tool
        // was willing to have in flight at once.
        let now = stub.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        stub.peak_in_flight.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        stub.in_flight.fetch_sub(1, Ordering::SeqCst);

        // The id that was asked about comes back, so a test can tell a tool
        // that read the named run from one that read any run.
        let asked_for = path
            .strip_prefix("/v1/runs/")
            .and_then(|rest| rest.split('/').next())
            .unwrap_or_default()
            .to_owned();
        let run = |state: RunState| {
            let mut document = settled_run(state);
            if let Some(object) = document.as_object_mut() {
                object.insert("id".to_owned(), Value::String(asked_for.clone()));
            }
            document
        };

        let payload = if path == "/v1/runs" {
            if body.get("workload").is_some() {
                settled_run(RunState::Succeeded)
            } else {
                json!([settled_run(RunState::Running)])
            }
        } else if path.ends_with("/events") {
            json!([{
                "id": Uuid::now_v7().to_string(),
                "run_id": asked_for,
                "sandbox_id": Value::Null,
                "event_type": "run.created",
                "occurred_at": chrono::Utc::now(),
                "detail": { "state": "queued" },
            }])
        } else if path.ends_with("/cancel") {
            run(RunState::Cancelled)
        } else {
            run(RunState::Succeeded)
        };
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }

    /// The JSON a tool result carries, which is what a calling agent reads.
    fn result_json(result: &CallToolResult) -> Value {
        let serialised = serde_json::to_value(result).expect("a tool result serialises");
        let text = serialised["content"][0]["text"]
            .as_str()
            .expect("a text block")
            .to_owned();
        serde_json::from_str(&text).expect("a tool result is JSON")
    }

    fn args(command: &[&str]) -> RunArgs {
        RunArgs {
            command: command.iter().map(|part| (*part).to_owned()).collect(),
            image: None,
            repo_url: None,
            repo_ref: None,
            setup_commands: None,
            validation_commands: None,
            artifacts: None,
            environment: None,
            secrets: None,
            git_evidence: None,
            timeout_seconds: None,
            cpu: None,
            memory_mb: None,
            disk_mb: None,
            network: None,
            guard: None,
            retention: None,
            runtime: None,
            requirements: None,
            idempotency_key: None,
            matrix_id: None,
            parent_run_id: None,
        }
    }

    // -- registration ---------------------------------------------------

    /// A tool a client cannot describe is a tool it will not call, and a tool
    /// whose safety hints are wrong is a tool it will call without asking.
    #[test]
    fn every_run_tool_is_registered_with_a_title_and_honest_hints() {
        let router = crate::server::router();
        // (name, read_only, destructive)
        let expected: [(&str, bool, bool); 6] = [
            ("aiec_run", false, true),
            ("aiec_run_batch", false, true),
            ("aiec_run_matrix", false, true),
            ("aiec_run_status", true, false),
            ("aiec_run_events", true, false),
            ("aiec_run_cancel", false, true),
        ];

        for (name, read_only, destructive) in expected {
            let tool = router
                .get(name)
                .unwrap_or_else(|| panic!("{name} is not registered"));
            assert!(name.starts_with("aiec_"), "{name} is not prefixed");
            assert!(name.len() < 64, "{name} is too long for a client to accept");
            assert!(
                tool.title
                    .as_deref()
                    .is_some_and(|title| !title.trim().is_empty()),
                "{name} has no title"
            );
            let annotations = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("{name} carries no annotations"));
            assert!(
                annotations
                    .title
                    .as_ref()
                    .is_some_and(|title| !title.trim().is_empty()),
                "{name} has no annotation title"
            );
            assert_eq!(
                annotations.read_only_hint,
                Some(read_only),
                "{name} has the wrong read-only hint"
            );
            assert_eq!(
                annotations.destructive_hint,
                Some(destructive),
                "{name} has the wrong destructive hint"
            );
        }

        // The sandbox tools are still there: the router is a merge, not a
        // replacement.
        assert!(router.has_route("aiec_create_sandbox"));
        assert!(router.has_route("aiec_exec"));
    }

    // -- request building -----------------------------------------------

    #[test]
    fn a_run_request_carries_exactly_what_the_caller_asked_for() {
        let mut asked = args(&["pytest", "-q"]);
        asked.image = Some("aiec-coding:latest".to_owned());
        asked.repo_url = Some("https://github.com/example/project.git".to_owned());
        asked.repo_ref = Some("main".to_owned());
        asked.setup_commands = Some(vec![vec!["pip".to_owned(), "install".to_owned()]]);
        asked.validation_commands = Some(vec![vec!["pytest".to_owned(), "-q".to_owned()]]);
        asked.artifacts = Some(vec!["report.txt".to_owned()]);
        asked.environment = Some(BTreeMap::from([("CI".to_owned(), "1".to_owned())]));
        asked.secrets = Some(vec!["NPM_TOKEN".to_owned()]);
        asked.git_evidence = Some(true);
        asked.timeout_seconds = Some(900);
        asked.cpu = Some(2);
        asked.memory_mb = Some(2048);
        asked.disk_mb = Some(4096);
        asked.network = Some(true);
        asked.retention = Some("keep_on_failure".to_owned());
        asked.runtime = Some("firecracker".to_owned());
        asked.idempotency_key = Some("nightly-42".to_owned());
        asked.requirements = Some(RunRequirements {
            full_kernel_isolation: Some(true),
            ..RunRequirements::default()
        });

        let request = run_request(&asked, Some("aiec-coding:latest")).expect("a request");
        assert_eq!(request.workload.command, vec!["pytest", "-q"]);
        assert_eq!(
            request.workload.image.as_deref(),
            Some("aiec-coding:latest")
        );
        let repo = request.workload.repo.expect("a repository");
        assert_eq!(repo.url, "https://github.com/example/project.git");
        assert_eq!(repo.reference.as_deref(), Some("main"));
        assert_eq!(request.workload.artifacts, vec!["report.txt"]);
        assert!(request.workload.git_evidence);
        assert_eq!(
            request.workload.environment.get("CI").map(String::as_str),
            Some("1")
        );
        assert_eq!(request.resources.cpu, 2);
        assert!(request.resources.network.is_enabled());
        assert_eq!(request.retention, RetentionPolicy::KeepOnFailure);
        assert!(request.requirements.full_kernel_isolation);
        assert_eq!(request.idempotency_key.as_deref(), Some("nightly-42"));
        assert_eq!(request.requested_runtime.as_deref(), Some("firecracker"));
    }

    #[test]
    fn a_workload_with_no_command_is_refused_before_a_machine_is_placed() {
        let error = run_request(&args(&[]), Some("aiec-coding:latest"))
            .expect_err("there is nothing to run");
        assert_eq!(error.code, crate::error::ErrorCode::InvalidArgument);
    }

    /// A runtime that executes off this machine would end the local-only
    /// guarantee the whole server exists to provide.
    #[test]
    fn a_runtime_outside_this_machine_is_refused() {
        let mut asked = args(&["true"]);
        asked.runtime = Some("hosted".to_owned());
        let error = run_request(&asked, None).expect_err("hosted is not local");
        assert_eq!(error.code, crate::error::ErrorCode::LocalRuntimeUnavailable);

        let mut unknown = args(&["true"]);
        unknown.runtime = Some("time-machine".to_owned());
        let error = run_request(&unknown, None).expect_err("there is no such runtime");
        assert_eq!(error.code, crate::error::ErrorCode::InvalidArgument);
    }

    /// A URL with a token in it would end up in the run document, in the event
    /// log, and in every error message that renders the request.
    #[test]
    fn a_repository_url_carrying_a_credential_is_refused() {
        let mut asked = args(&["true"]);
        asked.repo_url = Some("https://token@example.com/project.git".to_owned());
        let error = run_request(&asked, None).expect_err("credentials are refused");
        assert_eq!(error.code, crate::error::ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_reference_without_a_repository_names_nothing_to_check_out() {
        let mut asked = args(&["true"]);
        asked.repo_ref = Some("main".to_owned());
        let error = run_request(&asked, None).expect_err("a ref needs a repo");
        assert_eq!(error.code, crate::error::ErrorCode::InvalidArgument);
    }

    // -- end to end against a stub control plane -------------------------

    #[tokio::test]
    async fn a_run_reaches_the_control_plane_and_comes_back_settled() {
        let stub = Stub::default();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let server = server_for(&url, 2);

        let result = server
            .run(Parameters(args(&["pytest", "-q"])))
            .await
            .expect("a tool result");
        let view = result_json(&result);
        assert_eq!(view["state"], "succeeded");
        assert!(Uuid::parse_str(view["run_id"].as_str().expect("a run id")).is_ok());

        let bodies = stub.bodies.lock().await;
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0]["workload"]["command"], json!(["pytest", "-q"]));
        // This server's own default image, the same one its sandbox tools use,
        // rather than a name invented here.
        assert_eq!(bodies[0]["workload"]["image"], "python:3.13");
        assert_eq!(stub.paths.lock().await[0], "/v1/runs");
        serving.abort();
    }

    #[tokio::test]
    async fn a_batch_reports_every_cell_and_respects_its_bound() {
        let stub = Stub::default();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let server = server_for(&url, 2);

        let result = server
            .run_batch(Parameters(RunBatchArgs {
                tasks: vec![args(&["one"]), args(&["two"]), args(&["three"])],
                max_parallel: Some(2),
            }))
            .await
            .expect("a tool result");
        let view = result_json(&result);
        assert_eq!(view["results"].as_array().map(Vec::len), Some(3));
        assert_eq!(view["summary"]["cells"], 3);
        assert_eq!(view["summary"]["successes"], 3);
        assert!(
            stub.peak_in_flight.load(Ordering::SeqCst) <= 2,
            "the batch had {} runs in flight at once",
            stub.peak_in_flight.load(Ordering::SeqCst)
        );
        serving.abort();
    }

    #[tokio::test]
    async fn a_matrix_groups_its_cells_under_one_id() {
        let stub = Stub::default();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let server = server_for(&url, 2);

        let result = server
            .run_matrix(Parameters(RunMatrixArgs {
                cells: vec![
                    MatrixCellArgs {
                        axis: BTreeMap::from([("model".to_owned(), "a".to_owned())]),
                        run: args(&["one"]),
                    },
                    MatrixCellArgs {
                        axis: BTreeMap::from([("model".to_owned(), "b".to_owned())]),
                        run: args(&["two"]),
                    },
                ],
                max_parallel: None,
            }))
            .await
            .expect("a tool result");
        let view = result_json(&result);
        let matrix_id = view["matrix_id"].as_str().expect("a matrix id").to_owned();
        assert!(Uuid::parse_str(&matrix_id).is_ok());
        assert_eq!(view["summary"]["by_axis"]["model=a"]["successes"], 1);
        assert_eq!(view["summary"]["by_axis"]["model=b"]["cells"], 1);

        let bodies = stub.bodies.lock().await;
        assert_eq!(bodies.len(), 2);
        assert!(bodies.iter().all(|body| body["matrix_id"] == matrix_id));
        let keys: BTreeSet<&str> = bodies
            .iter()
            .filter_map(|body| body["idempotency_key"].as_str())
            .collect();
        assert_eq!(keys.len(), 2, "each cell needs its own idempotency scope");
        serving.abort();
    }

    #[tokio::test]
    async fn status_events_and_cancel_use_the_runs_routes() {
        let stub = Stub::default();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let server = server_for(&url, 2);
        let id = Uuid::now_v7().to_string();

        let status = result_json(
            &server
                .run_status(Parameters(RunIdArgs { run_id: id.clone() }))
                .await
                .expect("a tool result"),
        );
        assert_eq!(status["state"], "succeeded");
        // The stub echoes whatever it was asked about, so the id proves the
        // status tool actually read the run that was named.
        assert_eq!(status["run_id"], id);

        let events = result_json(
            &server
                .run_events(Parameters(RunIdArgs { run_id: id.clone() }))
                .await
                .expect("a tool result"),
        );
        assert_eq!(events[0]["event_type"], "run.created");

        let cancelled = result_json(
            &server
                .run_cancel(Parameters(RunIdArgs { run_id: id.clone() }))
                .await
                .expect("a tool result"),
        );
        assert_eq!(cancelled["state"], "cancelled");

        assert_eq!(
            *stub.paths.lock().await,
            vec![
                format!("/v1/runs/{id}"),
                format!("/v1/runs/{id}/events"),
                format!("/v1/runs/{id}/cancel"),
            ]
        );
        serving.abort();
    }

    #[tokio::test]
    async fn a_malformed_run_id_is_refused_without_a_request() {
        let stub = Stub::default();
        let (url, serving) = stub_control_plane(stub.clone()).await;
        let server = server_for(&url, 2);

        let error = server
            .run_status(Parameters(RunIdArgs {
                run_id: "not-a-run".to_owned(),
            }))
            .await
            .expect_err("there is no such run");
        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(stub.paths.lock().await.is_empty());
        serving.abort();
    }
}
