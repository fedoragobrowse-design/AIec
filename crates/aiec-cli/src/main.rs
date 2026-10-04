mod guard;
mod image;
use guard::{GuardCommand, guard_command};
use image::{ImageCommand, image_command};

use aiec_api::{
    HttpOwnershipVerifier, WorkerGuestProfile, WorkerHeartbeat, WorkerListener, WorkerRegistration,
    WorkerService, WorkerStatus,
};
use aiec_client::{
    AIecClient, BatchOptions, CreateRunRequest, EvalBatchRequest, EvalMatrixSpec,
    EvalRepetitionRequest,
};
use aiec_core::*;
use aiec_core::{
    host_pressure::{HostPressure, HostReserves},
    platform::Platform,
    run::{RepoSpec, RetentionPolicy, RunState},
    runtime::SandboxRuntime,
    snapshots::SnapshotProvider,
    storage::{MatrixCursor, MetadataStore, WorkerAssignment},
};
use aiec_guard::budget_client::HttpBudgetAuthority;
use aiec_guard::policy::PolicyTemplate;
use aiec_runtime::DockerRuntime;
use aiec_runtime::{BubblewrapRuntime, FirecrackerConfig, FirecrackerRuntime};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "aiec", version, about = "AIec sandbox cloud CLI")]
struct Cli {
    #[arg(long, env = "AIEC_URL", default_value = "http://127.0.0.1:8080")]
    url: String,
    /// The tenant API key. A credential on a command line is in every process
    /// listing on the host for as long as the process lives, so prefer the
    /// environment variable or `--api-key-file`.
    #[arg(long, env = "AIEC_API_KEY")]
    api_key: Option<String>,
    /// Reads the key from a file, trimming the trailing newline. The benchmark
    /// harness has taken `--api-key-file` since it was written; the CLI had no
    /// way to keep a key out of `ps` output at all.
    #[arg(long, env = "AIEC_API_KEY_FILE")]
    api_key_file: Option<std::path::PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Server(ServerArgs),
    Worker(WorkerArgs),
    Doctor,
    Migrate,
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
    File {
        #[command(subcommand)]
        command: FileCommand,
    },
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommand,
    },
    /// Guard: policy, proposals, incidents and quarantine for a sandbox.
    Guard {
        #[command(subcommand)]
        command: GuardCommand,
    },
    /// A run: a workload the control plane places, drives and reclaims.
    Run {
        #[command(subcommand)]
        command: RunCommand,
    },
    /// An evaluation: many runs of the same shapes, at a bound the caller sets.
    Eval {
        #[command(subcommand)]
        command: EvalCommand,
    },
    /// The signed manifest a deployment's image trust gate checks.
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    Benchmark(BenchmarkArgs),
}
#[derive(Args)]
struct ServerArgs {
    #[arg(long, env = "AIEC_BIND", default_value = "127.0.0.1:8080")]
    bind: String,
    #[arg(long, env = "AIEC_RUNTIME", default_value = "bwrap-dev")]
    runtime: String,
    #[arg(long, default_value = ".aiec")]
    state_dir: PathBuf,
}

#[derive(Args)]
struct WorkerArgs {
    #[arg(long, env = "AIEC_RUNTIME", default_value = "bwrap-dev")]
    runtime: String,
    #[arg(long, default_value = ".aiec")]
    state_dir: PathBuf,
    #[arg(long, env = "AIEC_WORKER_ADVERTISE_URL")]
    advertise_url: String,
    #[arg(long, env = "AIEC_WORKER_BIND", default_value = "127.0.0.1:9090")]
    bind: String,
    #[arg(long, env = "AIEC_WORKER_NAME", default_value = "worker")]
    name: String,
    #[arg(long, env = "AIEC_WORKER_CAPACITY", default_value_t = 1)]
    capacity: u32,
    /// Host memory held back from sandbox admission, in MiB.
    ///
    /// Never spent on work: this is the operating system, the page cache and
    /// this worker's own processes. Lowering it to zero hands the host's last
    /// bytes to tenants, which is refused at admission rather than corrected
    /// later.
    #[arg(long, env = "AIEC_WORKER_MEMORY_RESERVE_MIB", default_value_t = 512)]
    memory_reserve_mib: u64,
    /// Host disk held back from sandbox admission, in MiB.
    ///
    /// Room for logs, images and the workspace archives a snapshot writes.
    #[arg(long, env = "AIEC_WORKER_DISK_RESERVE_MIB", default_value_t = 2 * 1024)]
    disk_reserve_mib: u64,
    #[arg(long, env = "AIEC_WORKER_TOKEN")]
    token: Option<String>,
    #[arg(long, env = "AIEC_WORKER_NODE_ID")]
    node_id: Option<Uuid>,
}
#[derive(Args)]
struct BenchmarkArgs {
    #[arg(long, default_value_t = 10)]
    sandboxes: usize,
    #[arg(long, default_value_t = 1)]
    concurrency: usize,
}
#[derive(Subcommand)]
enum KeyCommand {
    Create {
        #[arg(long, default_value = "default")]
        name: String,
    },
    Revoke {
        key_id: Uuid,
    },
    Rotate {
        key_id: Uuid,
    },
}
#[derive(Subcommand)]
enum SandboxCommand {
    Create {
        #[arg(long, default_value = "python:3.13")]
        image: String,
        #[arg(long, default_value_t = 1)]
        cpu: u32,
        #[arg(long, default_value_t = 512)]
        memory_mb: u32,
        #[arg(long, default_value = "bwrap-dev")]
        runtime: String,
        #[arg(long, default_value_t = 2048)]
        disk_mb: u32,
        #[arg(long, default_value_t = 900)]
        timeout_seconds: u64,
        #[arg(long)]
        network: bool,
    },
    /// Lists sandboxes, newest first.
    ///
    /// The control plane answers one bounded page, so this follows the page
    /// cursor until the history is exhausted by default: a truncated history
    /// printed as though it were the whole thing is worse than a few more
    /// requests. `--page` prints one page and stops where that page ended.
    List {
        /// Print exactly one page, and say where the next one starts.
        #[arg(long)]
        page: bool,
        /// Sandboxes to ask for per page request.
        #[arg(long, default_value_t = 200)]
        limit: u32,
    },
    Show {
        id: Uuid,
    },
    Exec {
        id: Uuid,
        #[arg(last = true)]
        command: Vec<String>,
    },
    Destroy {
        id: Uuid,
    },
    Stop {
        id: Uuid,
    },
    Start {
        id: Uuid,
    },
    Resume {
        id: Uuid,
    },
}
#[derive(Subcommand)]
enum FileCommand {
    Put {
        id: Uuid,
        path: String,
        file: PathBuf,
    },
    Get {
        id: Uuid,
        path: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    List {
        id: Uuid,
        #[arg(default_value = "/workspace")]
        path: String,
    },
    Delete {
        id: Uuid,
        path: String,
    },
    Mkdir {
        id: Uuid,
        path: String,
    },
}
#[derive(Subcommand)]
enum SnapshotCommand {
    Create { sandbox_id: Uuid },
    List { sandbox_id: Uuid },
    Restore { snapshot_id: Uuid },
    Delete { snapshot_id: Uuid },
}

#[derive(Subcommand)]
enum RunCommand {
    /// Submits a run and prints the settled record.
    ///
    /// The request is a JSON document so it can be reviewed in a pull request
    /// and re-run unchanged; the flags are a shorthand for the same request and
    /// override whatever the document said.
    Submit(Box<RunSubmitArgs>),
    /// One run, in full.
    Show { run_id: Uuid },
    /// This tenant's runs, newest first.
    ///
    /// One page. `--after-requested-at` with `--after-id` resumes past the last
    /// run of the previous page; both are required together, because half a
    /// cursor names no row to start after.
    List {
        #[arg(long)]
        state: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// `requested_at` of the last run of the previous page.
        #[arg(long, value_name = "TIMESTAMP")]
        after_requested_at: Option<String>,
        /// Id of that run, which breaks a `requested_at` tie.
        #[arg(long, value_name = "RUN_ID")]
        after_id: Option<Uuid>,
    },
    /// Stops a run and reclaims the machine it was holding.
    Cancel { run_id: Uuid },
    /// What a run produced: the command outcomes, the diff and the timings.
    Results { run_id: Uuid },
    /// A run's history, in the order it happened.
    Events { run_id: Uuid },
    /// The artifacts a run collected, with a URL for each one's bytes.
    Artifacts { run_id: Uuid },
}

#[derive(Args)]
struct RunSubmitArgs {
    /// A RunRequest JSON document. Flags below override the fields it states.
    #[arg(value_name = "REQUEST_JSON")]
    file: Option<PathBuf>,
    #[arg(long)]
    image: Option<String>,
    /// A repository to clone inside the machine before the command runs.
    #[arg(long)]
    repo: Option<String>,
    #[arg(long = "ref")]
    git_ref: Option<String>,
    /// A setup command, as a JSON argument vector. Repeatable.
    #[arg(long, value_parser = parse_argv)]
    setup: Vec<Vec<String>>,
    /// A validation command, as a JSON argument vector. Repeatable.
    #[arg(long, value_parser = parse_argv)]
    validate: Vec<Vec<String>>,
    /// A path to collect once the run is done. Repeatable.
    #[arg(long = "artifact")]
    artifact: Vec<String>,
    /// A non-secret environment entry, as KEY=VALUE. Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE", value_parser = parse_env)]
    env: Vec<(String, String)>,
    /// The name of a tenant secret to inject. Repeatable.
    #[arg(long = "secret")]
    secret: Vec<String>,
    #[arg(long)]
    timeout_seconds: Option<u64>,
    #[arg(long)]
    cpu: Option<u32>,
    #[arg(long)]
    memory_mb: Option<u32>,
    #[arg(long)]
    disk_mb: Option<u32>,
    /// Allow the run to reach the internet.
    #[arg(long)]
    network: bool,
    /// Govern egress from outside the guest with a Guard policy template.
    /// This replaces `--network`: a governed run is not an ungoverned one that
    /// happens to be filtered.
    #[arg(long, value_enum)]
    guard: Option<GuardTemplateArg>,
    /// Insist on a full hardware-isolated kernel.
    #[arg(long)]
    full_kernel_isolation: bool,
    #[arg(long, value_enum)]
    retention: Option<RetentionArg>,
    /// Advanced: ask for a specific runtime rather than letting policy choose.
    #[arg(long)]
    requested_runtime: Option<String>,
    /// Reusing a key returns the run that already exists instead of running the
    /// work twice.
    #[arg(long)]
    idempotency_key: Option<String>,
    /// Print the request that would be sent, and send nothing.
    #[arg(long)]
    dry_run: bool,
    /// The command to run, as arguments, after `--`.
    #[arg(last = true)]
    command: Vec<String>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum RetentionArg {
    Destroy,
    KeepOnFailure,
    KeepAlways,
}

impl From<RetentionArg> for RetentionPolicy {
    fn from(value: RetentionArg) -> Self {
        match value {
            RetentionArg::Destroy => Self::Destroy,
            RetentionArg::KeepOnFailure => Self::KeepOnFailure,
            RetentionArg::KeepAlways => Self::KeepAlways,
        }
    }
}

/// The shipped Guard policy templates, as a closed set on the command line.
///
/// A closed enum rather than a free string: a template name that does not exist
/// should be refused by the shell that completed the word, not by a policy
/// parser after a machine has been placed.
#[derive(Clone, Copy, clap::ValueEnum)]
enum GuardTemplateArg {
    NoNetwork,
    ModelOnly,
    ModelPlusAllowlist,
    ReadOnlyApi,
}

impl From<GuardTemplateArg> for PolicyTemplate {
    fn from(value: GuardTemplateArg) -> Self {
        match value {
            GuardTemplateArg::NoNetwork => PolicyTemplate::NoNetwork,
            GuardTemplateArg::ModelOnly => PolicyTemplate::ModelOnly,
            GuardTemplateArg::ModelPlusAllowlist => PolicyTemplate::ModelPlusAllowlist,
            GuardTemplateArg::ReadOnlyApi => PolicyTemplate::ReadOnlyApi,
        }
    }
}

/// An argument vector, written the way the wire writes it.
///
/// JSON rather than a quoted string, because a command is a vector and not a
/// line: `["sh", "-c", "pytest -q && echo done"]` is one argument, and a
/// splitter that turned it into three would be a shell injection the platform
/// exists to make impossible.
fn parse_argv(value: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(value).map_err(|error| format!("not a JSON argument vector: {error}"))
}

fn parse_env(value: &str) -> Result<(String, String), String> {
    value
        .split_once('=')
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .filter(|(key, _)| !key.is_empty())
        .ok_or_else(|| format!("{value} is not KEY=VALUE"))
}

#[derive(Subcommand)]
enum EvalCommand {
    /// Runs a list of run documents, at most `--max-parallel` machines at once.
    Batch {
        /// One RunRequest JSON document per cell. Repeatable, in order.
        #[arg(long = "request", value_name = "REQUEST_JSON", required = true)]
        request: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        max_parallel: usize,
        #[arg(long)]
        dry_run: bool,
    },
    /// Runs one document several times, each repetition on its own machine.
    Repetitions {
        #[arg(long = "request", value_name = "REQUEST_JSON", required = true)]
        request: PathBuf,
        #[arg(long, default_value_t = 1)]
        repetitions: u32,
        #[arg(long, default_value_t = 2)]
        max_parallel: usize,
        #[arg(long)]
        dry_run: bool,
    },
    /// Runs a matrix: named combinations, each cell on its own machine.
    Matrix {
        /// A document of `{"cells": [{"axis": {...}, "request": {...}}]}`.
        #[arg(long = "spec", value_name = "MATRIX_JSON", required = true)]
        spec: PathBuf,
        /// Overrides the bound the document states.
        #[arg(long)]
        max_parallel: Option<usize>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Runs a suite: named tasks against repositories, expanded into a matrix.
    Suite {
        #[arg(long = "suite", value_name = "SUITE_JSON", required = true)]
        suite: PathBuf,
        /// The image every task boots. Unset leaves the default in place.
        #[arg(long)]
        image: Option<String>,
        #[arg(long, default_value_t = 2)]
        max_parallel: usize,
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let url = cli.url.clone();
    let api_key = resolve_api_key(cli.api_key.clone(), cli.api_key_file.clone())?;
    match cli.command {
        Command::Server(args) => server(args).await,
        Command::Worker(args) => worker(&url, args).await,
        Command::Doctor => doctor().await,
        Command::Migrate => migrate().await,
        Command::Key { command } => key_command(command),
        Command::Sandbox { command } => sandbox_command(&url, api_key.clone(), command).await,
        Command::File { command } => file_command(&url, api_key.clone(), command).await,
        Command::Snapshot { command } => snapshot_command(&url, api_key.clone(), command).await,
        Command::Guard { command } => guard_command(&url, api_key.clone(), command).await,
        Command::Image { command } => image_command(command).await,
        Command::Run { command } => run_command(&url, api_key.clone(), command).await,
        Command::Eval { command } => eval_command(&url, api_key.clone(), command).await,
        Command::Benchmark(args) => benchmark(&url, api_key, args).await,
    }
}

async fn server(args: ServerArgs) -> Result<()> {
    if !matches!(args.runtime.as_str(), "bwrap-dev" | "docker") {
        anyhow::bail!("server supports bwrap-dev or docker; production uses a server launcher")
    }
    std::fs::create_dir_all(&args.state_dir)?;
    let artifacts: Arc<dyn aiec_core::storage::ArtifactStore> = Arc::new(
        aiec_storage::FilesystemObjectStore::new(args.state_dir.join("artifacts")),
    );
    let (runtime, snapshots, runtime_kind): (
        Arc<dyn SandboxRuntime>,
        Arc<dyn SnapshotProvider>,
        RuntimeKind,
    ) = match args.runtime.as_str() {
        "bwrap-dev" => {
            let backend = Arc::new(BubblewrapRuntime::new(&args.state_dir));
            (backend.clone(), backend, RuntimeKind::BwrapDev)
        }
        "docker" => {
            let backend = Arc::new(
                DockerRuntime::new(&args.state_dir)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            );
            (backend.clone(), backend, RuntimeKind::Docker)
        }
        other => anyhow::bail!("unsupported server runtime {other}"),
    };
    let metadata_store: Arc<dyn MetadataStore> = aiec_storage::MemoryRepository::new();
    let scheduler: Arc<dyn aiec_core::scheduler::Scheduler> =
        Arc::new(aiec_api::DevelopmentScheduler);
    let registry = Arc::new(aiec_core::runtime::RuntimeRegistry::with_runtime(
        runtime_kind,
        runtime.clone(),
    ));
    let platform = Platform::builder()
        .runtime(runtime)
        .runtime_registry(registry)
        .metadata_store(metadata_store)
        .scheduler(scheduler)
        .snapshots(snapshots)
        .artifact_store(artifacts)
        .policy(Arc::new(aiec_api::DefaultPolicy))
        .build()?;
    let worker_token = ServerSecret::from_env("AIEC_WORKER_TOKEN");
    let state = aiec_api::AppState::development(platform)
        .with_runtime_kind(runtime_kind)
        .with_worker_token(worker_token.value().to_owned());
    let addr = args.bind.parse().context("invalid bind address")?;
    let key = ServerSecret::from_env("AIEC_API_KEY");
    aiec_api::bootstrap_api_key(
        state.repository().as_ref(),
        key.value(),
        Uuid::nil(),
        &[Scope::Admin],
    )
    .await?;
    println!(
        "aiec server listening on {addr}\nbootstrap API key: {}\nworker token: {}",
        key.report(),
        worker_token.report()
    );
    aiec_api::serve(state, addr).await.context("serve API")
}

/// Where a server credential came from.
#[derive(Clone, Copy)]
enum SecretOrigin {
    /// This process invented it, so nobody else has ever seen it.
    Generated,
    /// The operator exported it in the named environment variable.
    Supplied(&'static str),
}

/// A server credential plus the provenance that decides whether it may be
/// printed.
///
/// A generated key has to reach the operator somehow: it is written to no file
/// and nobody else can derive it. A key the operator exported must not be
/// echoed. Everything a process prints lands in terminal scrollback, in the
/// systemd or container journal, and in whatever CI job captured stdout - and
/// an operator who put a secret in an environment variable did that precisely
/// to keep it out of those places. Printing it again undoes the precaution and
/// the echo looks exactly like the "here is your new key" line beside it.
struct ServerSecret {
    value: String,
    origin: SecretOrigin,
}

impl ServerSecret {
    /// Reads the credential from the environment, generating one when the
    /// variable is unset or blank.
    ///
    /// A blank variable counts as unset: it would otherwise bootstrap an
    /// unusable empty credential, and reporting that as "supplied" would leave
    /// the operator with a server nobody can authenticate to.
    fn from_env(name: &'static str) -> Self {
        match std::env::var(name) {
            Ok(value) if !value.trim().is_empty() => Self {
                value,
                origin: SecretOrigin::Supplied(name),
            },
            _ => Self {
                value: generate_api_key(),
                origin: SecretOrigin::Generated,
            },
        }
    }

    fn value(&self) -> &str {
        &self.value
    }

    /// The line the operator reads: the secret itself when this process made
    /// it up, its origin when the operator supplied it.
    fn report(&self) -> String {
        match self.origin {
            SecretOrigin::Generated => format!(
                "{} (generated by this process; nothing else has it, store it now)",
                self.value
            ),
            SecretOrigin::Supplied(name) => {
                format!("read from ${name}; not echoed, the operator supplied it")
            }
        }
    }
}

/// The key from the flag, the file, or the environment, in that order.
///
/// The file is trimmed: a key written with `echo` carries a newline, and a
/// trailing newline inside an `Authorization` header is a key that does not
/// authenticate.
fn resolve_api_key(
    flag: Option<String>,
    file: Option<std::path::PathBuf>,
) -> Result<Option<String>> {
    if let Some(key) = flag {
        return Ok(Some(key));
    }
    let Some(path) = file else {
        return Ok(None);
    };
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let key = raw.trim().to_owned();
    if key.is_empty() {
        return Err(anyhow::anyhow!("{} is empty", path.display()));
    }
    Ok(Some(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key read from a file has to arrive without the newline `echo` adds:
    /// a trailing newline inside an Authorization header does not authenticate,
    /// and the failure looks like a wrong key rather than a dirty file.
    #[test]
    fn a_key_file_is_trimmed_and_an_empty_one_is_an_error() {
        let path = std::env::temp_dir().join(format!("aiec-key-{}", uuid::Uuid::now_v7()));
        std::fs::write(&path, "af_live_abc123\n").unwrap();
        assert_eq!(
            resolve_api_key(None, Some(path.clone())).unwrap(),
            Some("af_live_abc123".to_owned())
        );
        std::fs::write(&path, "   \n").unwrap();
        assert!(resolve_api_key(None, Some(path.clone())).is_err());
        let _ = std::fs::remove_file(&path);
        // The flag still wins, and no file is consulted when it is absent.
        assert_eq!(
            resolve_api_key(Some("af_live_flag".to_owned()), None).unwrap(),
            Some("af_live_flag".to_owned())
        );
        assert_eq!(resolve_api_key(None, None).unwrap(), None);
    }

    /// A secret the operator exported must not be echoed back at them.
    ///
    /// `aiec server` prints its two credentials on startup, and that line is
    /// what ends up in scrollback, in the systemd journal and in whatever CI
    /// job captured stdout. A key this process invented has to be printed -
    /// nobody else can derive it - but a key the operator put in the
    /// environment was kept out of the logs on purpose, and re-printing it
    /// looks identical to the "here is your new key" line beside it.
    #[test]
    fn a_supplied_secret_is_named_but_never_echoed() {
        let supplied = ServerSecret {
            value: "af_live_operatorsownkey".to_owned(),
            origin: SecretOrigin::Supplied("AIEC_API_KEY"),
        };
        let line = supplied.report();
        assert!(
            !line.contains("af_live_operatorsownkey"),
            "a key the operator supplied was echoed: {line}"
        );
        assert!(line.contains("AIEC_API_KEY"), "{line}");
        // The secret still has to reach the call that bootstraps it.
        assert_eq!(supplied.value(), "af_live_operatorsownkey");

        let token = ServerSecret {
            value: "worker-token-value".to_owned(),
            origin: SecretOrigin::Supplied("AIEC_WORKER_TOKEN"),
        };
        assert!(!token.report().contains("worker-token-value"));
    }

    /// A generated secret is printed, because it exists nowhere else.
    #[test]
    fn a_generated_secret_is_printed_once_with_a_warning() {
        let generated = ServerSecret {
            value: "af_live_generated".to_owned(),
            origin: SecretOrigin::Generated,
        };
        let line = generated.report();
        assert!(line.contains("af_live_generated"), "{line}");
        assert!(line.contains("store it now"), "{line}");
    }

    /// A sandbox that was created and never torn down is a failed sample.
    ///
    /// The benchmark used to discard the delete result and record
    /// `created = true`, printing `success_rate=1.000` and exiting 0 while N
    /// machines kept running and holding capacity. A transient teardown
    /// failure - the same `worker lease generation or status changed` race the
    /// MCP server retries - has to show up in the counts and in the exit code.
    #[test]
    fn a_failed_teardown_is_a_failed_sample_and_a_non_zero_exit() {
        let samples = vec![
            BenchmarkSample {
                create_micros: 120_000,
                teardown_micros: Some(80_000),
                outcome: SampleOutcome::Destroyed,
            },
            BenchmarkSample {
                create_micros: 130_000,
                teardown_micros: Some(90_000),
                outcome: SampleOutcome::TeardownFailed,
            },
            BenchmarkSample {
                create_micros: 90_000,
                teardown_micros: Some(70_000),
                outcome: SampleOutcome::TeardownFailed,
            },
        ];
        let report = BenchmarkReport::summarise(&samples, 500.0);

        assert_eq!(report.success, 1);
        assert_eq!(report.created, 3, "all three sandboxes were created");
        assert_eq!(report.teardown_failed, 2);
        assert!(!report.is_clean(), "a failed teardown must not exit 0");

        let line = report.summary_line(2);
        assert!(line.contains("success_rate=0.333"), "{line}");
        assert!(line.contains("teardown_failed=2"), "{line}");
        assert!(report.failure_reason().contains("may still be running"));
    }

    /// A run whose every sandbox was created and destroyed passes; a run with
    /// nothing to measure does not get to report a perfect score either.
    #[test]
    fn only_a_fully_clean_run_reports_success() {
        let clean = vec![BenchmarkSample {
            create_micros: 1_000,
            teardown_micros: Some(1_000),
            outcome: SampleOutcome::Destroyed,
        }];
        assert!(BenchmarkReport::summarise(&clean, 5.0).is_clean());

        let create_failed = vec![BenchmarkSample {
            create_micros: 1_000,
            teardown_micros: None,
            outcome: SampleOutcome::CreateFailed,
        }];
        let report = BenchmarkReport::summarise(&create_failed, 5.0);
        assert!(!report.is_clean());
        assert!(report.summary_line(1).contains("success_rate=0.000"));
        assert!(!BenchmarkReport::summarise(&[], 0.0).is_clean());
    }

    /// Creation and teardown are two measurements, not one.
    ///
    /// The old code evaluated `started.elapsed()` after the delete, so every
    /// percentile it printed was a create+destroy sum presented as creation
    /// latency.
    #[test]
    fn creation_and_teardown_latency_are_reported_separately() {
        let mut samples = Vec::new();
        for index in 0..MIN_SAMPLES_FOR_PERCENTILE {
            samples.push(BenchmarkSample {
                create_micros: 100_000 + index as u64,
                teardown_micros: Some(900_000 + index as u64),
                outcome: SampleOutcome::Destroyed,
            });
        }
        let report = BenchmarkReport::summarise(&samples, 1_000.0);
        let line = report.summary_line(4);

        // Create p95 sits in the 100ms band, teardown p95 in the 900ms band:
        // they cannot be the same number.
        let create_p95 = line
            .split_whitespace()
            .find_map(|field| field.strip_prefix("create_p95_ms="))
            .unwrap();
        let teardown_p95 = line
            .split_whitespace()
            .find_map(|field| field.strip_prefix("teardown_p95_ms="))
            .unwrap();
        assert_ne!(create_p95, teardown_p95, "{line}");
        // Create ran at ~100ms and teardown at ~900ms per sample. A percentile
        // that spanned both would land somewhere the two never were.
        assert!(
            (create_p95.parse::<f64>().unwrap() - 100.018).abs() < 0.001,
            "create p95 {create_p95} should be near 100.018ms in {line}"
        );
        assert!(
            (teardown_p95.parse::<f64>().unwrap() - 900.018).abs() < 0.001,
            "teardown p95 {teardown_p95} should be near 900.018ms in {line}"
        );
    }

    /// Percentiles the sample cannot carry are withheld, not printed as a
    /// number - and an empty sample is not a zero.
    ///
    /// This is the rule `benchmarks/aiecbench/stats.py` enforces with
    /// `MIN_SAMPLES_FOR_PERCENTILE = 20`. With the default `--sandboxes 1` the
    /// old helper printed the same observation as p50, p95 and p99, and
    /// returned `0` for no samples at all.
    #[test]
    fn percentiles_are_withheld_below_the_minimum_sample_count() {
        let one = vec![BenchmarkSample {
            create_micros: 100_000,
            teardown_micros: Some(100_000),
            outcome: SampleOutcome::Destroyed,
        }];
        let line = BenchmarkReport::summarise(&one, 5.0).summary_line(1);
        assert!(line.contains("create_p50_ms=unavailable"), "{line}");
        assert!(line.contains("create_p95_ms=unavailable"), "{line}");
        assert!(line.contains("create_p99_ms=unavailable"), "{line}");
        assert!(
            line.contains("1 samples is below the 20 needed for a p50/p95/p99"),
            "{line}"
        );

        let empty = Latencies::from_micros(&[]);
        assert_eq!(empty.samples, 0);
        assert!(empty.p50_ms.is_none());
        assert!(empty.p95_ms.is_none());
        assert!(empty.p99_ms.is_none());
        let fields = empty.fields("create");
        assert!(fields.contains("create_p50_ms=unavailable"), "{fields}");
        assert!(
            fields.contains("no samples were observed"),
            "no samples is not a zero: {fields}"
        );
    }

    /// The nearest-rank percentile agrees with the Python harness, so a number
    /// copied between the two reports is the same number.
    #[test]
    fn percentiles_are_nearest_rank_over_the_sorted_sample() {
        let values: Vec<u64> = (1..=MIN_SAMPLES_FOR_PERCENTILE)
            .map(|value| value as u64 * 1_000)
            .collect();
        let latencies = Latencies::from_micros(&values);
        assert_eq!(latencies.p50_ms, Some(10.0));
        assert_eq!(latencies.p95_ms, Some(19.0));
        assert_eq!(latencies.p99_ms, Some(20.0));
        assert!(latencies.withheld.is_none());
        assert!(!latencies.fields("create").contains("withheld"));
    }

    /// A half-stated cursor is refused before a request is made. Sending it
    /// would page from a query the caller did not ask for - an instant with no
    /// identity orders nothing, and an id alone cannot order a page that has
    /// not been read - and the control plane's own rejection would arrive only
    /// after the credentials were spent on a request that was always wrong.
    #[test]
    fn a_run_page_cursor_is_either_the_pair_or_neither() {
        assert!(
            run_page_cursor(None, None)
                .expect("the first page")
                .is_none()
        );

        let id = Uuid::now_v7();
        let cursor = run_page_cursor(Some("2024-01-02T03:04:05Z"), Some(id))
            .expect("a paired cursor")
            .expect("a cursor");
        assert_eq!(cursor.id, id);
        assert_eq!(
            cursor.requested_at.to_rfc3339(),
            "2024-01-02T03:04:05+00:00"
        );

        assert!(run_page_cursor(Some("2024-01-02T03:04:05Z"), None).is_err());
        assert!(run_page_cursor(None, Some(id)).is_err());
        // A timestamp that is not one is a message, not a page that comes
        // back wrong.
        assert!(run_page_cursor(Some("yesterday"), Some(id)).is_err());
    }
}

async fn client(url: &str, api_key: Option<String>) -> Result<AIecClient> {
    let key = api_key
        .or_else(|| std::env::var("AIEC_API_KEY").ok())
        .context("set --api-key, --api-key-file or AIEC_API_KEY")?;
    AIecClient::new(url, key).context("create API client")
}
async fn worker(control_url: &str, mut args: WorkerArgs) -> Result<()> {
    // The worker emits structured logs all over - rejected operations, lease
    // renewals, capacity decisions, sandbox teardown - and without a subscriber
    // every one of them was discarded, so a worker that refused an operation or
    // lost a lease produced no output at all. That is the same black box the
    // control plane fixed for itself: a host whose worker fails silently looks
    // exactly like a host with no work. `RUST_LOG` still overrides the default.
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        "info,aiec_api=info,aiec_core=info,aiec_runtime=info,aiec_storage=info,sqlx=warn".to_owned()
    });
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    let token = args
        .token
        .take()
        .or_else(|| std::env::var("AIEC_WORKER_TOKEN").ok())
        .context("set --token or AIEC_WORKER_TOKEN")?;
    if args.capacity == 0 {
        anyhow::bail!("--capacity must be greater than zero");
    }
    let advertised = reqwest::Url::parse(&args.advertise_url)
        .context("--advertise-url must be an absolute HTTP(S) URL")?;
    if args.runtime == "firecracker" && advertised.scheme() != "https" {
        anyhow::bail!("Firecracker worker --advertise-url must use HTTPS")
    }
    if !matches!(advertised.scheme(), "http" | "https")
        || advertised.host_str().is_none()
        || !advertised.username().is_empty()
        || advertised.password().is_some()
        || advertised.query().is_some()
        || advertised.fragment().is_some()
        || !matches!(advertised.path(), "" | "/")
    {
        anyhow::bail!(
            "--advertise-url must be an HTTP(S) origin without credentials, path, query, or fragment"
        );
    }
    let advertise_url = advertised.as_str().trim_end_matches('/').to_owned();
    let tls_config = match (
        std::env::var("AIEC_TLS_CERT_FILE"),
        std::env::var("AIEC_TLS_KEY_FILE"),
    ) {
        (Ok(cert), Ok(key)) => Some((cert, key)),
        _ if args.runtime == "bwrap-dev" => None,
        _ => anyhow::bail!("TLS certificate and key are required for non-development workers"),
    };
    if args.runtime != "bwrap-dev" && advertised.scheme() != "https" {
        anyhow::bail!("non-development workers must advertise HTTPS");
    }
    let bind = args.bind.parse().context("invalid worker bind address")?;
    // Handler installation is fallible. Do it before registration, local
    // reconciliation or lease claims, not inside the spawned shutdown future:
    // a panic there is otherwise mistaken for a clean server shutdown.
    let mut shutdown = termination_signal()?;
    let listener = tokio::select! {
        biased;
        _ = &mut shutdown => {
            tracing::info!("worker shutdown requested during startup");
            return Ok(());
        }
        listener = WorkerListener::bind(
            bind,
            tls_config.as_ref().map(|(cert, key)| (Path::new(cert), Path::new(key))),
        ) => listener.context("prepare worker listener")?,
    };
    // Keep the runtime outside the cancellable startup future so termination
    // or a startup error can still reclaim anything this process owns.
    let mut startup_runtime = None;
    let started = tokio::select! {
        // If both become ready together, do not publish a listener after the
        // user has already requested termination.
        biased;
        _ = &mut shutdown => {
            tracing::info!("worker shutdown requested during startup");
            Ok(None)
        }
        started = start_worker(
            control_url, args, token, advertise_url, &mut startup_runtime
        ) => started.map(Some),
    };
    if !matches!(&started, Ok(Some(_)))
        && let Some(runtime) = startup_runtime.as_ref()
    {
        let reclaimed = runtime.shutdown().await;
        tracing::info!(
            reclaimed = reclaimed.len(),
            "reclaimed worker startup runtime"
        );
    }
    let Some(WorkerStartup {
        service,
        runtime: shutdown_runtime,
        mut maintenance,
    }) = started?
    else {
        return Ok(());
    };
    drop(startup_runtime);
    let (drain, drained) = tokio::sync::oneshot::channel();
    let listener_shutdown = async move {
        let _ = drained.await;
    };
    let serving_context = if tls_config.is_some() {
        "serve TLS worker"
    } else {
        "serve worker"
    };
    let serving = async move {
        listener
            .serve_until(service, listener_shutdown)
            .await
            .context(serving_context)
    };
    tokio::pin!(serving);
    let mut serving_started = false;
    let serving = tokio::select! {
        biased;
        _ = &mut shutdown => {
            // Stop claims and renewals before beginning the listener drain.
            // Keep serving in-flight operations until the drain completes.
            maintenance.shutdown().await;
            let _ = drain.send(());
            if serving_started {
                serving.await
            } else {
                Ok(())
            }
        }
        result = std::future::poll_fn(|cx| {
            serving_started = true;
            serving.as_mut().poll(cx)
        }) => {
            maintenance.shutdown().await;
            drop(drain);
            result
        }
    };
    // Reclaim after the listener drains, even if serving returned an error.
    let reclaimed = shutdown_runtime.shutdown().await;
    tracing::info!(
        reclaimed = reclaimed.len(),
        "reclaimed the machines this worker was still running"
    );
    serving
}

struct WorkerStartup {
    service: WorkerService,
    runtime: Arc<dyn SandboxRuntime>,
    maintenance: JoinSet<()>,
}

async fn start_worker(
    control_url: &str,
    args: WorkerArgs,
    token: String,
    advertise_url: String,
    startup_runtime: &mut Option<Arc<dyn SandboxRuntime>>,
) -> Result<WorkerStartup> {
    let control = control_url.trim_end_matches('/').to_owned();
    let node_id = match args.node_id {
        Some(id) => id,
        None => durable_node_id(&args.state_dir)?,
    };
    let mut startup_report = None;
    // The runtime places work against the same reserve the worker advertises,
    // so a sandbox cannot be admitted into space the host held back.
    let reserves = HostReserves::from_mib(args.memory_reserve_mib, args.disk_reserve_mib);
    let mut guest_profile = None;
    let (runtime, snapshots, runtime_kind): (
        Arc<dyn SandboxRuntime>,
        Arc<dyn SnapshotProvider>,
        RuntimeKind,
    ) = match args.runtime.as_str() {
        "bwrap-dev" => {
            let backend = Arc::new(BubblewrapRuntime::new(&args.state_dir));
            (backend.clone(), backend, RuntimeKind::BwrapDev)
        }
        "docker" => {
            let backend = Arc::new(
                DockerRuntime::new(&args.state_dir)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            );
            (backend.clone(), backend, RuntimeKind::Docker)
        }
        "firecracker" => {
            let mut config = FirecrackerConfig::from_env()
                .map_err(|error| anyhow::anyhow!("invalid Firecracker configuration: {error}"))?;
            config.host_reserves = reserves;
            // The runtime already verified the artifact against the rootfs, so
            // the profile it resolved is what /health reports.
            guest_profile = config
                .guest_artifact
                .as_ref()
                .map(guest_profile_from)
                .or_else(|| {
                    tracing::warn!("no Firecracker guest artifact metadata is configured");
                    None
                });
            // Verify the guest image before this worker serves anything. A
            // worker that cannot verify its image must fail to start, not fail
            // its first sandbox on the control plane's request timeout.
            config.verify_guest_image()?;
            let backend = Arc::new(FirecrackerRuntime::new(config));
            // Runs before registration because its report is part of the
            // registration metadata. On a restart the persisted id is already
            // the adopted one, so this is owner-scoped correctly.
            let report = backend.reconcile_local(node_id)?;
            startup_report = Some(report.clone());
            if !report.orphan_candidates.is_empty() {
                tracing::warn!(owner_id = %report.owner_id, orphan_candidates = ?report.orphan_candidates, "owner-scoped Firecracker reconciliation found VM directories for operator review");
            }
            (backend.clone(), backend, RuntimeKind::Firecracker)
        }
        other => anyhow::bail!(
            "unsupported worker runtime {other}; use bwrap-dev, docker, or firecracker"
        ),
    };
    *startup_runtime = Some(runtime.clone());
    let capabilities = runtime.capabilities();
    let mut client_builder =
        reqwest::Client::builder().connect_timeout(std::time::Duration::from_secs(5));
    let ca_cert = std::env::var("AIEC_TLS_CA_CERT").ok();
    if let Some(path) = ca_cert.as_deref() {
        let pem = std::fs::read(path).with_context(|| format!("read {path}"))?;
        let certificate =
            reqwest::Certificate::from_pem(&pem).with_context(|| format!("parse {path}"))?;
        client_builder = client_builder.add_root_certificate(certificate);
    }
    // Whether an unmeasurable host is allowed to take work anyway. Only the
    // development runtime gets that latitude: it runs the developer's own
    // shell, not a tenant's job, and a worker that silently never claims
    // anything is a worse failure than one that claims without a reading.
    let production = runtime_kind != RuntimeKind::BwrapDev;
    let client = client_builder.build().context("build worker API client")?;
    let now = chrono::Utc::now();
    // One version base for this process, shared by the registration and every
    // heartbeat it sends. The control plane rejects a re-registration that does
    // not outrank the stored version, so registration and heartbeat must never
    // derive their versions separately.
    let version_base = worker_version_base();
    // The ledger declares the allocation, and only the allocation.
    //
    // `total_*` used to be `min(measurement, capacity x GiB)`, which made a
    // momentary host reading rewrite a durable declaration: a worker that
    // measured a busy host declared less than its operator allocated, the
    // `available_*` seeded from it were smaller than the allocations they came
    // from, and the shortfall could never be given back - the scheduler's
    // debit and release are the only writers of those columns, and they were
    // working from totals that had moved under them. A measurement that is not
    // a declaration belongs somewhere else.
    //
    // So the totals stay exactly what the operator allocated, and the
    // measurement is published alongside them as pressure. Pressure is what
    // answers "may this host take another sandbox", it moves every heartbeat,
    // and it recovers: a host that was full yesterday can admit today without
    // any ledger row having been rewritten to say so.
    let allocated_memory = u64::from(args.capacity) * GIB;
    let allocated_disk = u64::from(args.capacity) * 10 * GIB;
    let reserves = HostReserves::from_mib(args.memory_reserve_mib, args.disk_reserve_mib);
    let pressure = HostPressure::measure(&args.state_dir, reserves);
    report_pressure(&pressure, "registration");
    let short = |measured: Option<u64>, allocated: u64| {
        measured.is_some_and(|available| available < allocated)
    };
    if short(pressure.memory_available_bytes, allocated_memory)
        || short(pressure.disk_available_bytes, allocated_disk)
    {
        tracing::warn!(
            host_id = %pressure.host_id,
            allocated_memory_bytes = allocated_memory,
            allocated_disk_bytes = allocated_disk,
            "the host has less headroom than this node was allocated; admission will refuse \
             placements that do not fit until it recovers"
        );
    }
    // A worker that cannot measure its host must not claim that the host has
    // room. It says so in the metadata it registers, publishes on every
    // heartbeat, and stops claiming new work until a reading succeeds - rather
    // than falling back to the arithmetic allocation, which is how an
    // unmeasured machine ends up scheduled to zero.
    if !pressure.complete() {
        tracing::error!(
            host_id = %pressure.host_id,
            state_dir = %args.state_dir.display(),
            "host pressure could not be measured; this worker takes no new work until a \
             reading succeeds"
        );
    }
    // The metadata this worker registers with, kept so every heartbeat can
    // republish it. `heartbeat_worker` replaces the stored object wholesale
    // rather than merging, so a heartbeat carrying only its own fields would
    // delete `state_dir` and the startup reconciliation report within five
    // seconds of the worker starting - which is exactly the record an operator
    // wants when a host starts refusing work.
    let registration_metadata = serde_json::json!({
        "state_dir": args.state_dir,
        "startup_reconciliation": startup_report,
        "pressure": pressure.to_metadata(),
    });
    let registration = WorkerRegistration {
        node_id,
        name: args.name,
        runtime: runtime_kind,
        capabilities: capabilities.clone(),
        control_endpoint: advertise_url.clone(),
        total_vcpus: args.capacity,
        total_memory_bytes: allocated_memory,
        total_disk_bytes: allocated_disk,
        available_vcpus: args.capacity,
        available_memory_bytes: allocated_memory,
        available_disk_bytes: allocated_disk,
        // The worker's own health, never its host's. Pressure gates new work;
        // health means the worker is serving what it already holds.
        healthy: true,
        version: version_base,
        metadata: registration_metadata.clone(),
        started_at: now,
        last_heartbeat: now,
    };
    let registration_response = client
        .post(format!("{control}/v1/workers/register"))
        .bearer_auth(&token)
        .json(&registration)
        .send()
        .await
        .context("register worker")?;
    if !registration_response.status().is_success() {
        // Surface the control plane's reason: a version conflict and a bad
        // endpoint look identical in a bare 409.
        let status = registration_response.status();
        let body = registration_response.text().await.unwrap_or_default();
        anyhow::bail!("worker registration rejected ({status}): {body}");
    }
    // The control plane is authoritative about a worker's identity: if the name
    // was already registered it hands back the id it holds, and this worker
    // adopts it. Persisting it keeps the two in step across later restarts.
    let assigned: WorkerRegistration = registration_response
        .json()
        .await
        .context("worker registration response")?;
    let node_id = assigned.node_id;
    persist_node_id(&args.state_dir, node_id).context("persist the assigned node id")?;

    // Built only after the id is settled: the ownership verifier and the service
    // both capture it, and a worker that adopted a different id than it proposed
    // would otherwise authorize every operation against an id the control plane
    // does not use.
    let verifier = HttpOwnershipVerifier::new(control.clone(), token.clone(), node_id)
        .map_err(|error| anyhow::anyhow!("build worker ownership verifier: {error}"))?;
    // Guard reservations are committed by the control plane before any byte is
    // admitted, so the worker needs a real authority before it may serve a
    // guarded sandbox. A worker that cannot reach the authority still starts,
    // because an unguarded deployment has nothing to reserve.
    let guard_budget_authority = HttpBudgetAuthority::new(
        &control,
        Zeroizing::new(token.clone()),
        node_id,
        ca_cert.as_deref().map(std::path::Path::new),
        std::env::var("AIEC_ALLOW_LOOPBACK_HTTP").as_deref() == Ok("1"),
    );
    let budget_target = runtime.clone();
    // The service takes ownership of the runtime, but the shutdown path needs
    // its own handle: reclaiming the machines left running is the last thing
    // this process does, and it is not a request the service could carry.
    let shutdown_runtime = runtime.clone();
    let mut service = WorkerService::new(
        runtime,
        runtime_kind,
        capabilities.clone(),
        Some(snapshots),
        token.clone(),
        node_id,
        args.capacity,
    )
    .with_state_dir(&args.state_dir)
    .context("load durable worker generation ledger")?
    .with_ownership_verifier(Arc::new(verifier));
    match &guard_budget_authority {
        Ok(authority) => {
            // A guarded attachment refuses to prepare without this, so a
            // failure here is reported rather than left to a sandbox's own
            // refusal much later.
            if let Err(error) =
                budget_target.configure_guard_budget_authority(Arc::new(authority.clone()))
            {
                tracing::warn!(%error, "this worker's runtime does not accept a Guard budget authority");
            }
        }
        Err(error) => tracing::warn!(
            %error,
            "no Guard budget authority is configured; guarded sandboxes will refuse to start"
        ),
    }
    if let Some(profile) = guest_profile {
        service = service.with_guest_profile(profile);
    }
    client
        .post(format!("{control}/v1/workers/reconcile"))
        .bearer_auth(&token)
        .send()
        .await
        .context("initial worker reconciliation")?
        .error_for_status()
        .context("initial worker reconciliation rejected")?;
    let owned_leases: Arc<Mutex<HashMap<Uuid, OwnedLease>>> = Arc::new(Mutex::new(HashMap::new()));
    // The same gate the maintenance loop applies: this is the first chance to
    // take on new work, and a host that could not be measured has not earned
    // it. The maintenance loop retries, so declining here costs nothing but
    // one cycle.
    if admits_new_work(&args.state_dir, reserves, production) {
        match claim_assignments(&client, &control, &token, node_id, args.capacity).await {
            Ok(leases) => {
                tracing::info!(leases = leases.len(), "claimed worker assignments");
                owned_leases.lock().await.extend(leases);
            }
            Err(error) => {
                tracing::warn!(%error, "worker assignment claim failed; retrying with the heartbeat")
            }
        }
    }
    let loop_leases = owned_leases.clone();
    let loop_capacity = args.capacity;
    // Heartbeats continue the version sequence the registration started, so a
    // worker that restarts outranks the version it last reported.
    let heartbeat_version = Arc::new(AtomicU64::new(version_base));
    let heartbeat_token = token.clone();
    let heartbeat_client = client.clone();
    let heartbeat_url = control.clone();
    // Liveness and maintenance run on separate tasks on purpose. The control
    // plane treats a node as dead once its heartbeat is older than
    // NODE_HEARTBEAT_TTL_SECONDS, so a slow reconcile, claim, or renewal must
    // never delay the heartbeat that keeps this node schedulable.
    let liveness_node = node_id;
    let liveness_version = heartbeat_version.clone();
    let liveness_token = token.clone();
    let liveness_client = client.clone();
    let liveness_url = control.clone();
    let liveness_health_url = format!("{}/health", advertise_url);
    let liveness_state_dir = args.state_dir.clone();
    let liveness_reserves = reserves;
    // Moved into the liveness task, which republishes it with a fresh reading
    // on every beat rather than sending a partial object.
    let liveness_metadata = registration_metadata;
    let mut maintenance = JoinSet::new();
    maintenance.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        // Carried across beats because a failed probe does not tell the worker
        // how many sandboxes it holds, and guessing zero would have the control
        // plane believe a machine is unassigned.
        let mut last_reported_sandbox_count: Option<u32> = None;
        loop {
            interval.tick().await;
            // The control plane declares a node dead once its heartbeat is
            // older than `NODE_HEARTBEAT_TTL_SECONDS`, and the only cure is a
            // heartbeat. So a worker that could not answer its own `/health`
            // probe still has to beat: skipping the beat on a failed probe is
            // what made a running worker get reaped for a fault in the probe.
            // The probe's failure is reported as `healthy: false` with the
            // reason in `last_error`, which is exactly what those two fields
            // are for. What a worker cannot know is its own sandbox count, so
            // the last one it reported is carried rather than invented.
            let probe = async {
                let status = liveness_client
                    .get(&liveness_health_url)
                    .bearer_auth(&liveness_token)
                    .send()
                    .await
                    .map_err(|error| error.to_string())?;
                let status = status
                    .error_for_status()
                    .map_err(|error| error.to_string())?;
                status
                    .json::<WorkerStatus>()
                    .await
                    .map_err(|error| error.to_string())
            }
            .await;
            let (active, healthy, probe_error) = match probe {
                Ok(status) => (status.sandbox_count as u32, status.healthy, None),
                Err(error) => {
                    tracing::warn!(%error, "worker health probe failed");
                    (
                        last_reported_sandbox_count.unwrap_or(0),
                        false,
                        Some(format!("health probe failed: {error}")),
                    )
                }
            };
            last_reported_sandbox_count = Some(active);
            // Measured again on every beat, because the answer that mattered
            // when this worker registered is the answer now: a host that filled
            // up in the last five seconds has to be able to say so, and one
            // that emptied has to be able to say that too.
            //
            // The reading replaces the `pressure` key of the metadata this
            // worker registered with, and nothing else. The store assigns the
            // whole object rather than merging it, so sending only the reading
            // would delete the state directory and the startup reconciliation
            // report from the node record five seconds after startup.
            //
            // The reading still goes nowhere near `available_*`. That is the
            // scheduler's ledger, maintained only by debit and release;
            // writing a measurement over it would erase the per-placement
            // accounting and make two writers of one column disagree.
            let pressure = HostPressure::measure(&liveness_state_dir, liveness_reserves);
            report_pressure(&pressure, "heartbeat");
            let mut metadata = liveness_metadata.clone();
            metadata["pressure"] = pressure.to_metadata();
            let heartbeat = WorkerHeartbeat {
                node_id: liveness_node,
                sandbox_count: active,
                // Health is the worker's own answer about itself, and pressure
                // is not allowed to overwrite it. A host that cannot be
                // measured is not a broken worker, and reporting it as one
                // conflates two conditions an operator treats differently: one
                // needs a reboot, the other needs a bigger disk.
                //
                // What an unmeasured or full host does is decline *new* work,
                // through the pressure in this metadata and the claim gate
                // below. The sandboxes already running are untouched.
                healthy,
                version: liveness_version.fetch_add(1, Ordering::Relaxed) + 1,
                metadata,
                last_error: probe_error,
            };
            if let Err(error) = liveness_client
                .post(format!(
                    "{liveness_url}/v1/workers/{liveness_node}/heartbeat"
                ))
                .bearer_auth(&liveness_token)
                .json(&heartbeat)
                .send()
                .await
                .and_then(|response| response.error_for_status())
            {
                tracing::warn!(%error, "worker heartbeat failed");
            }
        }
    });

    let loop_state_dir = args.state_dir.clone();
    let loop_reserves = reserves;
    let loop_production = production;
    maintenance.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let _ = heartbeat_client
                .post(format!("{heartbeat_url}/v1/workers/reconcile"))
                .bearer_auth(&heartbeat_token)
                .send()
                .await;
            // Claiming is taking on *new* work, so it is what pressure gets to
            // refuse. The renewal below is deliberately outside this gate: a
            // full or unmeasurable host must keep the leases on the sandboxes
            // it is already running. Dropping them would hand running work
            // back for reassignment on a host that is still perfectly able to
            // finish it.
            //
            // No warning is logged here. `report_pressure` already logs a
            // reading when it changes, which covers the transition in and out
            // of a blocked state; a line every ten seconds for as long as a
            // host stays full is noise on precisely the incident where the log
            // needs to stay readable.
            if admits_new_work(&loop_state_dir, loop_reserves, loop_production) {
                match claim_assignments(
                    &heartbeat_client,
                    &heartbeat_url,
                    &heartbeat_token,
                    node_id,
                    loop_capacity,
                )
                .await
                {
                    Ok(leases) if !leases.is_empty() => {
                        tracing::info!(leases = leases.len(), "claimed worker assignments");
                        loop_leases.lock().await.extend(leases);
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "worker assignment claim failed"),
                }
            }
            let leases: Vec<OwnedLease> = loop_leases.lock().await.values().cloned().collect();
            let renewal = renew_leases(
                &heartbeat_client,
                &heartbeat_url,
                &heartbeat_token,
                node_id,
                &leases,
            )
            .await;
            let mut owned = loop_leases.lock().await;
            // Write the generation the control plane just assigned back into the
            // tracked lease. Renewal bumps the generation server-side, so
            // replaying the old one would fence this worker out of its own
            // sandbox and abandon a lease it still legitimately holds.
            for (sandbox_id, generation) in &renewal.renewed {
                if let Some(lease) = owned.get_mut(sandbox_id) {
                    lease.generation = *generation;
                }
            }
            if !renewal.superseded.is_empty() {
                for sandbox_id in &renewal.superseded {
                    owned.remove(sandbox_id);
                }
                tracing::info!(
                    released = renewal.superseded.len(),
                    "dropped leases the control plane no longer owns"
                );
            }
            let tracked = owned.len();
            drop(owned);
            if let Some(error) = renewal.failure {
                tracing::warn!(%error, leases = leases.len(), tracked, "worker lease renewal failed");
            }
        }
    });
    Ok(WorkerStartup {
        service,
        runtime: shutdown_runtime,
        maintenance,
    })
}

/// Installs both handlers immediately, then resolves on `SIGTERM` or `SIGINT`.
///
/// Installation errors must fail worker startup before it registers or takes
/// ownership of machines. The default signal disposition skips destructors;
/// the returned future gives the running worker a chance to reclaim them.
fn termination_signal() -> Result<impl Future<Output = ()> + Unpin> {
    use std::{future::poll_fn, task::Poll};
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    // Signal streams are Unpin. An allocation-free poll_fn keeps the waiter
    // movable from startup's select into the server's owned shutdown task.
    Ok(poll_fn(move |cx| {
        if terminate.poll_recv(cx).is_ready() || interrupt.poll_recv(cx).is_ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }))
}

/// Lease lifetime requested when this worker claims assignments.
const WORKER_LEASE_TTL_SECONDS: u64 = 300;

/// A lease this worker currently holds for a sandbox.
#[derive(Clone)]
struct OwnedLease {
    sandbox_id: Uuid,
    lease_id: Uuid,
    tenant_id: Uuid,
    generation: i64,
}

/// Claims the assignments reserved for this worker.
async fn claim_assignments(
    client: &reqwest::Client,
    control: &str,
    token: &str,
    node_id: Uuid,
    capacity: u32,
) -> Result<Vec<(Uuid, OwnedLease)>, reqwest::Error> {
    let assignments: Vec<WorkerAssignment> = client
        .post(format!(
            "{control}/v1/workers/{node_id}/assignments/claim?limit={}&lease_ttl_seconds={}",
            capacity.clamp(1, 128),
            WORKER_LEASE_TTL_SECONDS
        ))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(assignments
        .into_iter()
        .map(|assignment| {
            (
                assignment.sandbox.id,
                OwnedLease {
                    sandbox_id: assignment.sandbox.id,
                    lease_id: assignment.lease.id,
                    tenant_id: assignment.lease.tenant_id,
                    generation: assignment.lease.generation,
                },
            )
        })
        .collect())
}

/// Renews every owned lease, reporting the first transport failure without
/// skipping the remaining leases, and collecting the sandboxes whose lease the
/// control plane no longer recognizes.
#[derive(Default)]
struct RenewalOutcome {
    superseded: Vec<Uuid>,
    /// The generation each successfully renewed lease now holds. Renewal bumps
    /// the server-side generation, so a client that kept the old one would be
    /// fenced out on the very next cycle and would drop the lease it still owns.
    renewed: Vec<(Uuid, i64)>,
    failure: Option<reqwest::Error>,
}

async fn renew_leases(
    client: &reqwest::Client,
    control: &str,
    token: &str,
    node_id: Uuid,
    leases: &[OwnedLease],
) -> RenewalOutcome {
    let mut outcome = RenewalOutcome::default();
    for lease in leases {
        let response = match client
            .post(format!(
                "{control}/v1/workers/{node_id}/leases/{}/renew",
                lease.lease_id
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "tenant_id": lease.tenant_id,
                "generation": lease.generation,
            }))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                if outcome.failure.is_none() {
                    outcome.failure = Some(error);
                }
                continue;
            }
        };
        if response.status() == reqwest::StatusCode::CONFLICT {
            // The sandbox was destroyed, reassigned, or fenced: stop tracking it
            // instead of failing every later cycle.
            outcome.superseded.push(lease.sandbox_id);
            continue;
        }
        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                if outcome.failure.is_none() {
                    outcome.failure = Some(error);
                }
                continue;
            }
        };
        match response.json::<aiec_core::storage::WorkerLease>().await {
            Ok(lease) => outcome.renewed.push((lease.sandbox_id, lease.generation)),
            // The lease is extended; only the reported generation is unknown, so
            // keep the lease rather than dropping a sandbox we still own.
            Err(error) if outcome.failure.is_none() => {
                outcome.failure = Some(error);
            }
            Err(_) => {}
        }
    }
    outcome
}

/// Whether this host will take on another sandbox right now.
///
/// The demand tested is one vCPU, one byte of memory and one byte of disk, not
/// the size of a particular sandbox. This is the local half of admission: it
/// answers "is there any headroom at all", and the scheduler's aggregate answers
/// the per-sandbox question with the real demand and every sibling worker's
/// reservations. Testing a real size here would refuse small work on a host
/// that has plenty of room for it, and the error would name this worker rather
/// than the placement that did not fit.
///
/// `production` decides what an unmeasurable host does. It is true for the
/// runtimes that hold a tenant's job and must never claim capacity they did
/// not measure, and false for `bwrap-dev`, where refusing every claim on a
/// host that will not expose `/proc/meminfo` would leave a developer with a
/// worker that starts, registers, and silently never runs anything.
fn admits_new_work(state_dir: &Path, reserves: HostReserves, production: bool) -> bool {
    let pressure = HostPressure::measure(state_dir, reserves);
    if !pressure.complete() {
        // Unmeasured. Production refuses; development proceeds, because a dev
        // sandbox is the developer's own shell and blocking it on a kernel
        // interface that happens to be unavailable helps nobody.
        return !production;
    }
    // Measured, so this is arithmetic either way: a full host takes nothing,
    // whatever it happens to be running.
    pressure.admits(1, 1, 1).is_ok()
}

/// Bytes in a gibibyte, shared with the host-pressure measurement so the
/// allocation arithmetic and the measured headroom are in the same unit.
const GIB: u64 = aiec_core::host_pressure::GIB;

/// Logs one host reading, so an operator can see pressure move without
/// burying every other worker log under a heartbeat that repeats itself.
///
/// A reading whose figures changed since the last one is worth a line; a host
/// sitting at the same numbers five seconds apart is not.
fn report_pressure(pressure: &HostPressure, phase: &'static str) {
    static LAST: std::sync::Mutex<Option<PressureReading>> = std::sync::Mutex::new(None);
    let reading = (
        pressure.host_id.clone(),
        pressure.memory_available_bytes,
        pressure.disk_available_bytes,
    );
    let changed = match LAST.lock() {
        Ok(last) if *last == Some(reading.clone()) => false,
        Ok(mut last) => {
            *last = Some(reading.clone());
            true
        }
        Err(_) => true,
    };
    if !changed {
        return;
    }
    if pressure.complete() {
        tracing::info!(
            host_id = %pressure.host_id,
            memory_available_bytes = pressure.memory_available_bytes.unwrap_or_default(),
            disk_available_bytes = pressure.disk_available_bytes.unwrap_or_default(),
            memory_reserve_bytes = pressure.reserves.memory_bytes,
            disk_reserve_bytes = pressure.reserves.disk_bytes,
            phase,
            "host pressure measured"
        );
    } else {
        tracing::warn!(
            host_id = %pressure.host_id,
            total_memory_bytes = ?pressure.total_memory_bytes,
            memory_available_bytes = ?pressure.memory_available_bytes,
            total_disk_bytes = ?pressure.total_disk_bytes,
            disk_available_bytes = ?pressure.disk_available_bytes,
            phase,
            "host pressure is incomplete; new placements are refused until a reading succeeds"
        );
    }
}

/// The three figures worth comparing between readings.
type PressureReading = (String, Option<u64>, Option<u64>);

/// Base value for this process's node version.
///
/// Derived from the process start time so a restarted worker always outranks
/// the version it last reported, which the control plane requires before it
/// will accept the re-registration.
fn worker_version_base() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or_default();
    // Leave headroom above the millisecond clock so the counter can never
    // overflow a u64 through normal operation.
    u64::try_from(millis).unwrap_or(u64::MAX / 2)
}
async fn doctor() -> Result<()> {
    println!("os: {}", std::env::consts::OS);
    println!(
        "runtime: {}",
        std::env::var("AIEC_RUNTIME").unwrap_or_else(|_| "bwrap-dev".into())
    );
    println!(
        "bwrap: {}",
        if std::path::Path::new("/usr/bin/bwrap").exists() {
            "available"
        } else {
            "missing (install bubblewrap)"
        }
    );
    println!(
        "docker: {}",
        match aiec_runtime::DockerRuntime::new(std::env::temp_dir()) {
            Ok(runtime) => match runtime.health().await {
                health if health.healthy => "ready".to_owned(),
                health => health.message.unwrap_or_else(|| "not ready".into()),
            },
            Err(error) => format!("not ready ({error})"),
        }
    );
    println!(
        "kvm: {}",
        if std::path::Path::new("/dev/kvm").exists() {
            "available"
        } else {
            "unavailable"
        }
    );
    println!(
        "database: {}",
        if std::env::var("DATABASE_URL").is_ok() {
            "configured"
        } else {
            "not configured (in-memory API)"
        }
    );
    let require_coding_guest = std::env::var("AIEC_REQUIRE_CODING_GUEST").as_deref() == Ok("1");
    let mut coding_guest = false;
    match FirecrackerConfig::from_env() {
        Ok(config) => {
            match config.check() {
                Ok(()) => println!(
                    "firecracker: ready (binary {}, kernel {})",
                    config.binary.display(),
                    config.kernel.display()
                ),
                Err(error) => println!("firecracker: {error}"),
            }
            match config.guest_artifact.as_ref() {
                Some(artifact) => {
                    coding_guest = artifact.is_coding_guest();
                    println!(
                        "firecracker guest: base {} profile {} (artifact {})",
                        artifact.base, artifact.profile, artifact.artifact_version
                    );
                    println!(
                        "firecracker guest capabilities: {}",
                        artifact.capabilities.join(", ")
                    );
                    println!(
                        "firecracker guest git: {}",
                        artifact
                            .git_version
                            .clone()
                            .unwrap_or_else(|| "missing".into())
                    );
                    println!("firecracker guest agent: {}", artifact.guest_agent_version);
                    println!(
                        "firecracker guest wire protocol: {}",
                        artifact.guest_protocol_version
                    );
                }
                None => println!(
                    "firecracker guest image: no guest artifact metadata (set AIEC_GUEST_ARTIFACT_DIR)"
                ),
            }
        }
        Err(error) => println!(
            "firecracker: {error} (set AIEC_FIRECRACKER_BIN, AIEC_KERNEL, AIEC_ROOTFS, AIEC_GUEST_SECRET)"
        ),
    }
    if require_coding_guest && !coding_guest {
        anyhow::bail!(
            "AIEC_REQUIRE_CODING_GUEST=1 requires a verified Firecracker guest image that provides git"
        );
    }
    Ok(())
}

fn guest_profile_from(
    artifact: &aiec_runtime::guest_artifact::GuestArtifact,
) -> WorkerGuestProfile {
    WorkerGuestProfile {
        artifact_version: artifact.artifact_version.clone(),
        base: artifact.base.clone(),
        profile: artifact.profile.clone(),
        capabilities: artifact.capabilities.clone(),
        git_version: artifact.git_version.clone(),
        guest_agent_version: artifact.guest_agent_version.clone(),
        guest_protocol_version: artifact.guest_protocol_version,
    }
}
async fn migrate() -> Result<()> {
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL is required for `aiec migrate`")?;
    let repository = aiec_storage::PostgresRepository::connect(&database_url)
        .await
        .context("connect to PostgreSQL")?;
    repository
        .migrate()
        .await
        .context("apply AIec database migrations")?;
    println!("AIec database migrations are current.");
    Ok(())
}
fn key_command(command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Create { name } => {
            let key = generate_api_key();
            println!("{name}: {key}");
            println!(
                "Store only a SHA-256 digest in production; this local CLI cannot revoke an unpersisted key."
            );
        }
        KeyCommand::Revoke { key_id } => {
            println!("revoked {key_id} (persist this operation in your key store)")
        }
        KeyCommand::Rotate { key_id } => {
            let key = generate_api_key();
            println!("rotated {key_id}: {key}");
        }
    }
    Ok(())
}
async fn sandbox_command(url: &str, key: Option<String>, command: SandboxCommand) -> Result<()> {
    let c = client(url, key).await?;
    match command {
        SandboxCommand::Create {
            image,
            cpu,
            memory_mb,
            runtime,
            disk_mb,
            timeout_seconds,
            network,
        } => {
            if !matches!(runtime.as_str(), "bwrap-dev" | "docker" | "firecracker") {
                anyhow::bail!(
                    "unsupported sandbox runtime {runtime}; use bwrap-dev, docker, or firecracker"
                )
            }
            let request = CreateSandboxRequest {
                image,
                cpu,
                memory_mb,
                disk_mb,
                timeout_seconds,
                network: if network {
                    NetworkPolicy::Internet
                } else {
                    NetworkPolicy::Disabled
                },
                environment: Default::default(),
            };
            let sandbox = if matches!(runtime.as_str(), "firecracker" | "docker") {
                // Through `c`, which carries `AIEC_TLS_CA_CERT` and the request
                // timeout. A bare `reqwest::Client::new()` here reached a
                // deployment with a private certificate authority through no
                // trust anchor at all, and waited forever when it did not.
                c.create_sandbox_with_runtime(&request, &runtime).await?
            } else {
                c.create_sandbox(&request).await?
            };
            println!("{}", serde_json::to_string_pretty(&sandbox)?)
        }
        SandboxCommand::List { page, limit } => {
            if page {
                // One page, with the cursor printed alongside it. Stopping
                // here is the caller's choice, so the response has to carry
                // enough to resume: the cursor is the last sandbox shown, not
                // an offset a reader would have to keep in step with the data.
                let response = c.list_sandboxes_page(limit).await?;
                println!("{}", serde_json::to_string_pretty(&response)?);
                if let Some(next) = &response.next {
                    eprintln!(
                        "more sandboxes remain; resume after {} {}",
                        next.created_at.to_rfc3339(),
                        next.id
                    );
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&c.list_all_sandboxes(limit).await?)?
                );
            }
        }
        SandboxCommand::Show { id } => println!(
            "{}",
            serde_json::to_string_pretty(&c.get_sandbox(id).await?)?
        ),
        SandboxCommand::Exec { id, command } => {
            let result = c
                .exec(
                    id,
                    &ExecRequest {
                        command,
                        working_directory: None,
                        environment: BTreeMap::new(),
                        timeout_seconds: 60,
                        stdin: None,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        SandboxCommand::Destroy { id } => {
            c.delete_sandbox(id).await?;
            println!("destroyed")
        }
        SandboxCommand::Stop { id } => {
            println!("{}", serde_json::to_string_pretty(&c.stop(id).await?)?)
        }
        SandboxCommand::Start { id } => {
            println!("{}", serde_json::to_string_pretty(&c.start(id).await?)?)
        }
        SandboxCommand::Resume { id } => {
            println!("{}", serde_json::to_string_pretty(&c.resume(id).await?)?)
        }
    }
    Ok(())
}
async fn file_command(url: &str, key: Option<String>, command: FileCommand) -> Result<()> {
    let c = client(url, key).await?;
    match command {
        FileCommand::Put { id, path, file } => {
            let bytes = std::fs::read(file)?;
            c.put_file(
                id,
                &PutFileRequest {
                    path,
                    content_base64: base64_encode(&bytes),
                    mode: None,
                },
            )
            .await?;
            println!("written")
        }
        FileCommand::Get { id, path, output } => {
            let value = c.get_file(id, &path).await?;
            let bytes = base64_decode(&value.content_base64)?;
            match output {
                Some(path) => std::fs::write(path, bytes)?,
                None => print!("{}", String::from_utf8_lossy(&bytes)),
            }
        }
        FileCommand::List { id, path } => println!(
            "{}",
            serde_json::to_string_pretty(&c.list_files(id, &path).await?)?
        ),
        FileCommand::Delete { id, path } => {
            c.delete_file(id, &path).await?;
            println!("deleted")
        }
        FileCommand::Mkdir { id, path } => {
            c.make_directory(id, &path).await?;
            println!("created")
        }
    }
    Ok(())
}
async fn snapshot_command(url: &str, key: Option<String>, command: SnapshotCommand) -> Result<()> {
    let c = client(url, key).await?;
    match command {
        SnapshotCommand::Create { sandbox_id } => println!(
            "{}",
            serde_json::to_string_pretty(&c.create_snapshot(sandbox_id).await?)?
        ),
        SnapshotCommand::List { sandbox_id } => println!(
            "{}",
            serde_json::to_string_pretty(&c.list_snapshots_page(sandbox_id, 50).await?)?
        ),
        SnapshotCommand::Restore { snapshot_id } => println!(
            "{}",
            serde_json::to_string_pretty(
                &c.restore_snapshot(
                    snapshot_id,
                    &RestoreSnapshotRequest {
                        image: None,
                        cpu: None,
                        memory_mb: None,
                        disk_mb: None,
                        runtime: None,
                    }
                )
                .await?
            )?
        ),
        SnapshotCommand::Delete { snapshot_id } => {
            c.delete_snapshot(snapshot_id).await?;
            println!("deleted")
        }
    }
    Ok(())
}

/// Reads a run request from a file, then applies whatever flags were stated.
///
/// A document is the reviewable form and the flags are the shorthand, so the
/// two compose: a checked-in request with a different timeout is the same
/// request, and `--dry-run` prints exactly what would have gone out.
fn run_request_from(args: &RunSubmitArgs) -> Result<CreateRunRequest> {
    let mut request = match &args.file {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("read run request {}", path.display()))?;
            serde_json::from_str(&raw)
                .with_context(|| format!("parse run request {}", path.display()))?
        }
        None => CreateRunRequest::default(),
    };
    if let Some(image) = &args.image {
        request.workload.image = Some(image.clone());
    }
    if let Some(repo) = &args.repo {
        request.workload.repo = Some(RepoSpec {
            url: repo.clone(),
            reference: args.git_ref.clone(),
            ..Default::default()
        });
    }
    if let Some(git_ref) = &args.git_ref {
        // The repository may have come from the document rather than the flag,
        // so this is resolved against the request rather than against the flag.
        let repo = request.workload.repo.as_mut().ok_or_else(|| {
            anyhow::anyhow!("--ref needs a repository: pass --repo, or state one in the request")
        })?;
        repo.reference = Some(git_ref.clone());
    }
    if !args.setup.is_empty() {
        request.workload.setup = args.setup.clone();
    }
    if !args.validate.is_empty() {
        request.workload.validations = args.validate.clone();
    }
    if !args.artifact.is_empty() {
        request.workload.artifacts = args.artifact.clone();
    }
    for (key, value) in &args.env {
        request
            .workload
            .environment
            .insert(key.clone(), value.clone());
    }
    if !args.secret.is_empty() {
        request.workload.secrets = args.secret.clone();
    }
    if !args.command.is_empty() {
        request.workload.command = args.command.clone();
    }
    if let Some(timeout) = args.timeout_seconds {
        request.workload.timeout_seconds = Some(timeout);
    }
    if let Some(cpu) = args.cpu {
        request.resources.cpu = cpu;
    }
    if let Some(memory_mb) = args.memory_mb {
        request.resources.memory_mb = memory_mb;
    }
    if let Some(disk_mb) = args.disk_mb {
        request.resources.disk_mb = disk_mb;
    }
    if args.network {
        request.resources.network = NetworkPolicy::Internet;
    }
    if let Some(template) = args.guard {
        // Silently dropping `--network` would let a script believe it asked
        // for open egress and silently get a governed policy instead, which is
        // the opposite of what the flag said. Two descriptions of one egress
        // are refused, not resolved in favour of the narrower one.
        if args.network {
            anyhow::bail!(
                "--guard and --network ask for two different egress policies; \
                 pass --guard with a template that names the destinations you want"
            );
        }
        request.resources.guard = Some(aiec_guard::policy::GuardConfig {
            topology: aiec_guard::policy::Topology::default(),
            policy_template: PolicyTemplate::from(template),
            policy: None,
            model_endpoint: None,
            allowlist: Vec::new(),
            ..Default::default()
        });
        request.resources.network = NetworkPolicy::Disabled;
    }
    if args.full_kernel_isolation {
        request.requirements.full_kernel_isolation = true;
    }
    if let Some(retention) = args.retention {
        request.retention = retention.into();
    }
    if let Some(runtime) = &args.requested_runtime {
        request.requested_runtime = Some(runtime.clone());
    }
    if let Some(key) = &args.idempotency_key {
        request.idempotency_key = Some(key.clone());
    }
    // Checked here so a caller is told what is missing before a machine is
    // placed, rather than after one is.
    request
        .workload
        .validate()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(request)
}

/// The run listing's page cursor, or the first page when neither flag was given.
///
/// A half-stated cursor names no row to start after: the timestamp alone orders
/// nothing without an identity, and the id alone cannot order a page that has
/// not been read. Passing one through would page from a different query than
/// the caller asked for, so the halves are refused here rather than sent.
fn run_page_cursor(requested_at: Option<&str>, id: Option<Uuid>) -> Result<Option<MatrixCursor>> {
    match (requested_at, id) {
        (None, None) => Ok(None),
        (Some(raw), Some(id)) => {
            let requested_at = DateTime::parse_from_rfc3339(raw.trim())
                .with_context(|| format!("not an RFC 3339 timestamp: {raw}"))?
                .with_timezone(&Utc);
            Ok(Some(MatrixCursor { requested_at, id }))
        }
        _ => anyhow::bail!("--after-requested-at and --after-id must be given together"),
    }
}

async fn run_command(url: &str, key: Option<String>, command: RunCommand) -> Result<()> {
    // The request is built before the client so a `--dry-run` review needs no
    // credentials: being able to read what you are about to submit without
    // holding a key is the point of the document form.
    let submit = match &command {
        RunCommand::Submit(args) => Some((run_request_from(args)?, args.dry_run)),
        _ => None,
    };
    if let Some((request, true)) = &submit {
        println!("{}", serde_json::to_string_pretty(request)?);
        return Ok(());
    }
    let c = client(url, key).await?;
    match (command, submit) {
        (RunCommand::Submit(_), submit) => {
            let (request, _) =
                submit.ok_or_else(|| anyhow::anyhow!("missing Run submission request"))?;
            let run = c.create_run(&request).await?;
            println!("{}", serde_json::to_string_pretty(&run)?);
        }
        (RunCommand::Show { run_id }, _) => {
            let run = c.get_run(run_id).await?;
            println!("{}", serde_json::to_string_pretty(&run)?);
        }
        (
            RunCommand::List {
                state,
                limit,
                after_requested_at,
                after_id,
            },
            _,
        ) => {
            // Parsed here so a typo is a message rather than a query the
            // control plane answers with an empty page.
            let state = state
                .map(|raw| {
                    RunState::parse(raw.trim())
                        .ok_or_else(|| anyhow::anyhow!("unknown run state `{raw}`"))
                })
                .transpose()?;
            let after = run_page_cursor(after_requested_at.as_deref(), after_id)?;
            let runs = c.list_runs(state, Some(limit), after).await?;
            println!("{}", serde_json::to_string_pretty(&runs)?);
        }
        (RunCommand::Cancel { run_id }, _) => {
            let run = c.cancel_run(run_id).await?;
            println!("{}", serde_json::to_string_pretty(&run)?);
        }
        (RunCommand::Results { run_id }, _) => {
            // The run's own results, not the whole record: this is what a
            // caller pipes into something that reads command outcomes.
            let run = c.get_run(run_id).await?;
            println!("{}", serde_json::to_string_pretty(&run.results)?);
        }
        (RunCommand::Events { run_id }, _) => {
            let events = c.run_events(run_id).await?;
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        (RunCommand::Artifacts { run_id }, _) => {
            let artifacts = c.run_artifacts(run_id).await?;
            println!("{}", serde_json::to_string_pretty(&artifacts)?);
        }
    }
    Ok(())
}

fn read_run_request(path: &Path) -> Result<CreateRunRequest> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read run request {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse run request {}", path.display()))
}

/// Expands a suite into the matrix the generic route already runs.
///
/// The expansion is the control plane's, so a suite means the same thing here
/// as it does to every other caller; only the submission crosses the wire.
fn suite_to_spec(
    path: &Path,
    image: Option<String>,
    max_parallel: usize,
) -> Result<EvalMatrixSpec> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("read suite {}", path.display()))?;
    let suite =
        aiec_api::eval_matrix::Suite::parse(&raw).map_err(|error| anyhow::anyhow!("{error}"))?;
    let spec = suite.to_matrix(image, max_parallel);
    // The two types are the same document with the same field names, so this
    // is a re-typing rather than a translation: nothing is renamed, defaulted
    // or dropped on the way.
    serde_json::from_value(serde_json::to_value(spec)?)
        .context("the suite expanded into a matrix the client cannot express")
}

/// The body one of the evaluation routes takes.
///
/// Held as one type so `--dry-run` prints exactly what would have been sent,
/// rather than a second rendering of the same flags that could disagree with
/// it.
enum EvalSubmission {
    Batch(Box<EvalBatchRequest>),
    Repetitions(Box<EvalRepetitionRequest>),
    Matrix(Box<EvalMatrixSpec>),
}

impl EvalSubmission {
    fn body(&self) -> Result<String> {
        Ok(match self {
            Self::Batch(request) => serde_json::to_string_pretty(request)?,
            Self::Repetitions(request) => serde_json::to_string_pretty(request)?,
            Self::Matrix(spec) => serde_json::to_string_pretty(spec)?,
        })
    }
}

async fn eval_command(url: &str, key: Option<String>, command: EvalCommand) -> Result<()> {
    let (submission, dry_run) = match &command {
        EvalCommand::Batch {
            request,
            max_parallel,
            dry_run,
        } => (
            EvalSubmission::Batch(Box::new(EvalBatchRequest {
                requests: request
                    .iter()
                    .map(|path| read_run_request(path))
                    .collect::<Result<Vec<_>>>()?,
                options: BatchOptions {
                    max_parallel: *max_parallel,
                },
            })),
            *dry_run,
        ),
        EvalCommand::Repetitions {
            request,
            repetitions,
            max_parallel,
            dry_run,
        } => (
            EvalSubmission::Repetitions(Box::new(EvalRepetitionRequest {
                request: read_run_request(request)?,
                repetitions: *repetitions,
                options: BatchOptions {
                    max_parallel: *max_parallel,
                },
            })),
            *dry_run,
        ),
        EvalCommand::Matrix {
            spec,
            max_parallel,
            dry_run,
        } => (
            EvalSubmission::Matrix(Box::new(matrix_spec(spec, *max_parallel)?)),
            *dry_run,
        ),
        EvalCommand::Suite {
            suite,
            image,
            max_parallel,
            dry_run,
        } => (
            EvalSubmission::Matrix(Box::new(suite_to_spec(
                suite,
                image.clone(),
                *max_parallel,
            )?)),
            *dry_run,
        ),
    };
    if dry_run {
        println!("{}", submission.body()?);
        return Ok(());
    }

    let c = client(url, key).await?;
    let printed = match submission {
        EvalSubmission::Batch(request) => {
            let result = c.eval_batch(&request).await?;
            serde_json::to_string_pretty(&result)?
        }
        EvalSubmission::Repetitions(request) => {
            let result = c.eval_repetitions(&request).await?;
            serde_json::to_string_pretty(&result)?
        }
        EvalSubmission::Matrix(spec) => {
            let result = c.eval_matrix(&spec).await?;
            serde_json::to_string_pretty(&result)?
        }
    };
    println!("{printed}");
    Ok(())
}

/// Reads a matrix document, applying `--max-parallel` only when it was stated.
fn matrix_spec(path: &Path, max_parallel: Option<usize>) -> Result<EvalMatrixSpec> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("read matrix {}", path.display()))?;
    let mut spec: EvalMatrixSpec =
        serde_json::from_str(&raw).with_context(|| format!("parse matrix {}", path.display()))?;
    if let Some(max_parallel) = max_parallel {
        spec.options.max_parallel = max_parallel;
    }
    Ok(spec)
}

/// Below this many samples a p95 or p99 is noise, so the CLI withholds it and
/// says why rather than printing a number the sample cannot carry.
///
/// This is the same threshold the Python harness enforces in
/// `benchmarks/aiecbench/stats.py` (`MIN_SAMPLES_FOR_PERCENTILE`). With the
/// default `--sandboxes 1`, every percentile would otherwise collapse onto one
/// observation and be presented as three independent measurements.
const MIN_SAMPLES_FOR_PERCENTILE: usize = 20;

/// How one sandbox attempt ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SampleOutcome {
    /// Created and then torn down cleanly.
    Destroyed,
    /// Created, but the teardown failed. The machine may still be running and
    /// still holding capacity, so this is a failed sample.
    TeardownFailed,
    /// Never created.
    CreateFailed,
}

impl SampleOutcome {
    /// Only a sandbox that was both created and torn down is a success.
    ///
    /// A discarded `delete_sandbox` error used to report `success_rate=1.000`
    /// while N machines kept running; that is the number an operator watching a
    /// cluster fill up is reading.
    fn is_success(self) -> bool {
        matches!(self, Self::Destroyed)
    }
}

/// One attempt: how long each half of it took, and how it ended.
#[derive(Clone, Copy)]
struct BenchmarkSample {
    create_micros: u64,
    teardown_micros: Option<u64>,
    outcome: SampleOutcome,
}

/// A distribution that may be too small to carry percentiles.
#[derive(Debug)]
struct Latencies {
    samples: usize,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
    /// Why the percentiles are absent, in the operator's words.
    withheld: Option<String>,
}

impl Latencies {
    fn from_micros(values: &[u64]) -> Self {
        let samples = values.len();
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        // Nearest-rank, matching `aiecbench.stats.percentile`: an interpolated
        // percentile is a number between two observations that nobody measured.
        let at = |fraction: f64| -> Option<f64> {
            if sorted.is_empty() {
                return None;
            }
            let rank = (fraction * samples as f64)
                .ceil()
                .clamp(1.0, samples as f64) as usize;
            Some(sorted[rank - 1] as f64 / 1000.0)
        };
        let withheld = if samples == 0 {
            Some("no samples were observed".to_owned())
        } else if samples < MIN_SAMPLES_FOR_PERCENTILE {
            Some(format!(
                "{samples} samples is below the {MIN_SAMPLES_FOR_PERCENTILE} needed for a p50/p95/p99"
            ))
        } else {
            None
        };
        // Withheld means withheld: the number is not computed at all, so there
        // is no path by which it reaches the output.
        let percentile =
            |fraction: f64| withheld.is_none().then(|| at(fraction).unwrap_or_default());
        Self {
            samples,
            p50_ms: percentile(0.50),
            p95_ms: percentile(0.95),
            p99_ms: percentile(0.99),
            withheld,
        }
    }

    /// The percentile keys, always present. A withheld percentile prints
    /// `unavailable` - not `0.000`, which is a measurement.
    fn fields(&self, prefix: &str) -> String {
        let render = |value: Option<f64>| {
            value.map_or_else(|| "unavailable".to_owned(), |value| format!("{value:.3}"))
        };
        let mut fields = format!(
            "{prefix}_samples={} {prefix}_p50_ms={} {prefix}_p95_ms={} {prefix}_p99_ms={}",
            self.samples,
            render(self.p50_ms),
            render(self.p95_ms),
            render(self.p99_ms),
        );
        if let Some(reason) = &self.withheld {
            fields.push_str(&format!(" {prefix}_percentiles_withheld={reason}"));
        }
        fields
    }
}

/// What a benchmark run did, and whether that counts as a pass.
#[derive(Debug)]
struct BenchmarkReport {
    samples: usize,
    success: usize,
    created: usize,
    teardown_failed: usize,
    create_failed: usize,
    create: Latencies,
    teardown: Latencies,
    total_ms: f64,
}

impl BenchmarkReport {
    fn summarise(samples: &[BenchmarkSample], total_ms: f64) -> Self {
        let created = samples
            .iter()
            .filter(|sample| !matches!(sample.outcome, SampleOutcome::CreateFailed))
            .count();
        Self {
            samples: samples.len(),
            success: samples
                .iter()
                .filter(|sample| sample.outcome.is_success())
                .count(),
            created,
            teardown_failed: samples
                .iter()
                .filter(|sample| sample.outcome == SampleOutcome::TeardownFailed)
                .count(),
            create_failed: samples
                .iter()
                .filter(|sample| sample.outcome == SampleOutcome::CreateFailed)
                .count(),
            create: Latencies::from_micros(
                &samples.iter().map(|s| s.create_micros).collect::<Vec<_>>(),
            ),
            teardown: Latencies::from_micros(
                &samples
                    .iter()
                    .filter_map(|s| s.teardown_micros)
                    .collect::<Vec<_>>(),
            ),
            total_ms,
        }
    }

    /// Whether the run deserves exit code 0.
    ///
    /// A teardown that failed leaves a machine running and holding capacity
    /// until its lease expires, so a run that leaves sandboxes behind has not
    /// passed, whatever the create rate says.
    fn is_clean(&self) -> bool {
        self.samples > 0 && self.success == self.samples
    }

    fn summary_line(&self, concurrency: usize) -> String {
        format!(
            "samples={} concurrency={} success={} success_rate={:.3} created={} create_failed={} teardown_failed={} {} {} total_ms={:.3}",
            self.samples,
            concurrency,
            self.success,
            self.success as f64 / self.samples.max(1) as f64,
            self.created,
            self.create_failed,
            self.teardown_failed,
            self.create.fields("create"),
            self.teardown.fields("teardown"),
            self.total_ms,
        )
    }

    /// The non-zero-exit message, naming the sandboxes this run may have left
    /// running.
    fn failure_reason(&self) -> String {
        format!(
            "{} of {} benchmark samples failed: {} never created, {} whose teardown failed and may still be running",
            self.samples - self.success,
            self.samples,
            self.create_failed,
            self.teardown_failed,
        )
    }
}

async fn benchmark(url: &str, key: Option<String>, args: BenchmarkArgs) -> Result<()> {
    if args.sandboxes == 0 || args.concurrency == 0 {
        anyhow::bail!("sandboxes and concurrency must be positive")
    }
    if args.sandboxes > 10_000 || args.concurrency > 1_000 {
        anyhow::bail!("benchmark limits: sandboxes <= 10000 and concurrency <= 1000")
    }
    let client = client(url, key).await?;
    let started = Instant::now();
    let permits = Arc::new(Semaphore::new(args.concurrency));
    let mut tasks: JoinSet<Result<BenchmarkSample>> = JoinSet::new();
    for _ in 0..args.sandboxes {
        let client = client.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits
                .acquire_owned()
                .await
                .map_err(|error| anyhow::Error::msg(error.to_string()))?;
            let request = CreateSandboxRequest {
                image: "ubuntu:24.04".into(),
                cpu: 1,
                memory_mb: 512,
                disk_mb: 2048,
                timeout_seconds: 300,
                network: NetworkPolicy::default(),
                environment: Default::default(),
            };
            // Creation and teardown are timed separately: the caller's
            // `started` used to span both, so every percentile it printed was a
            // create+destroy sum reported as if it were creation latency.
            let create_started = Instant::now();
            let sandbox = match client.create_sandbox(&request).await {
                Ok(sandbox) => sandbox,
                Err(_) => {
                    return Ok(BenchmarkSample {
                        create_micros: create_started.elapsed().as_micros() as u64,
                        teardown_micros: None,
                        outcome: SampleOutcome::CreateFailed,
                    });
                }
            };
            let create_micros = create_started.elapsed().as_micros() as u64;
            let teardown_started = Instant::now();
            let outcome = match client.delete_sandbox(sandbox.id).await {
                Ok(_) => SampleOutcome::Destroyed,
                Err(_) => SampleOutcome::TeardownFailed,
            };
            let teardown_micros = teardown_started.elapsed().as_micros() as u64;
            Ok(BenchmarkSample {
                create_micros,
                teardown_micros: Some(teardown_micros),
                outcome,
            })
        });
    }
    let mut samples = Vec::with_capacity(args.sandboxes);
    while let Some(result) = tasks.join_next().await {
        samples.push(result??);
    }
    let report = BenchmarkReport::summarise(&samples, started.elapsed().as_secs_f64() * 1000.0);
    println!("{}", report.summary_line(args.concurrency));
    if !report.is_clean() {
        anyhow::bail!(report.failure_reason())
    }
    Ok(())
}
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn base64_decode(value: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(anyhow::Error::from)
}

/// Records the node id the control plane assigned to this worker.
fn persist_node_id(state_dir: &std::path::Path, node_id: Uuid) -> anyhow::Result<()> {
    publish_node_id(state_dir, node_id, true)
}

/// Publishes a complete, synced identity without truncating the previous one.
fn publish_node_id(
    state_dir: &std::path::Path,
    node_id: Uuid,
    replace: bool,
) -> anyhow::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let mut directory = std::fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    directory.mode(0o700);
    directory.create(state_dir)?;
    let path = state_dir.join("node-id");
    let temporary = state_dir.join(format!(".node-id-{}.tmp", Uuid::now_v7()));
    let mut temporary_created = false;
    let result = (|| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        temporary_created = true;
        let mut bytes = [0u8; 37];
        node_id.hyphenated().encode_lower(&mut bytes[..36]);
        bytes[36] = b'\n';
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if replace {
            std::fs::rename(&temporary, &path)?;
        } else {
            // A simultaneous first start must adopt the winning identity.
            std::fs::hard_link(&temporary, &path)?;
            std::fs::remove_file(&temporary)?;
        }
        #[cfg(unix)]
        sync_node_id_directory(state_dir)?;
        Ok(())
    })();
    if result.is_err() && temporary_created {
        let _ = std::fs::remove_file(&temporary);
    }
    result.context("persist worker node identity")
}

/// Sync the directory that received the identity entry, then the directories
/// above it on a best-effort basis.
///
/// The entry just written lives in `state_dir`, so syncing that directory is
/// what makes the identity durable, and it is the one directory this code
/// creates and owns. Ancestors are synced because `create_dir_all` may have
/// just created `state_dir` — a new directory's own entry lives in its parent,
/// so the parent's directory needs syncing too — but those ancestors are
/// pre-existing system directories (`/var`, `/home`, `/`) that belong to
/// someone else.
///
/// Their failures are therefore logged rather than propagated. Two reasons:
/// `fsync` on a directory is not universally supported and can report
/// `EINVAL`, and a directory can be perfectly usable for its purpose while
/// refusing to be opened for reading — mode `0300` permits creating files
/// inside it but not opening it. Either case would otherwise turn node
/// identity publication, and with it worker startup, into a failure caused by
/// a directory this process never needed to touch.
#[cfg(unix)]
fn sync_node_id_directory(state_dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(state_dir)?.sync_all()?;
    for ancestor in state_dir.ancestors().skip(1) {
        let path = if ancestor.as_os_str().is_empty() {
            std::path::Path::new(".")
        } else {
            ancestor
        };
        let synced = std::fs::File::open(path).and_then(|directory| directory.sync_all());
        if let Err(error) = synced {
            tracing::warn!(
                directory = %path.display(),
                error = %error,
                "could not sync a parent of the node identity directory; the \
                 identity itself is durable, only the parent entry may not survive a crash"
            );
        }
    }
    Ok(())
}

fn read_node_id(path: &std::path::Path) -> anyhow::Result<Uuid> {
    let text = std::fs::read_to_string(path).context("read stored worker node identity")?;
    Uuid::parse_str(text.trim()).context("stored worker node identity is malformed")
}

/// Only a genuinely missing identity permits automatic first-start minting.
fn durable_node_id(state_dir: &std::path::Path) -> anyhow::Result<Uuid> {
    let path = state_dir.join("node-id");
    match read_node_id(&path) {
        Ok(existing) => return Ok(existing),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    let minted = Uuid::now_v7();
    match publish_node_id(state_dir, minted, false) {
        Ok(()) => Ok(minted),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            #[cfg(unix)]
            sync_node_id_directory(state_dir)?;
            read_node_id(&path)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod node_identity_tests {
    use super::{durable_node_id, persist_node_id};

    /// A worker that invents a fresh id on every start collides with the
    /// control plane's unique name and can never re-register, so the id has to
    /// outlive the process.
    #[test]
    fn a_restarted_worker_keeps_its_node_id() {
        let dir = std::env::temp_dir().join(format!("aiec-node-id-{}", uuid::Uuid::now_v7()));
        let first = durable_node_id(&dir).expect("first start mints an id");
        let second = durable_node_id(&dir).expect("second start reads it back");
        assert_eq!(first, second, "the node id must survive a restart");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn separate_state_dirs_get_separate_identities() {
        let suffix = uuid::Uuid::now_v7();
        let a_dir = std::env::temp_dir().join(format!("aiec-a-{suffix}"));
        let b_dir = std::env::temp_dir().join(format!("aiec-b-{suffix}"));
        let a = durable_node_id(&a_dir).unwrap();
        let b = durable_node_id(&b_dir).unwrap();
        assert_ne!(a, b, "two workers must not share an identity");
        std::fs::remove_dir_all(a_dir).unwrap();
        std::fs::remove_dir_all(b_dir).unwrap();
    }

    #[test]
    fn corrupt_identity_is_refused_and_preserved() {
        for content in [b"".as_slice(), b"interrupted-node-id", b"\xff"] {
            let dir = std::env::temp_dir().join(format!("aiec-node-id-{}", uuid::Uuid::now_v7()));
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("node-id");
            std::fs::write(&path, content).unwrap();
            assert!(
                durable_node_id(&dir).is_err(),
                "corruption must not mint a new identity"
            );
            assert_eq!(std::fs::read(&path).unwrap(), content);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    /// An ancestor directory can be fully usable for creating and writing the
    /// identity while refusing to be opened for reading — mode `0300` is
    /// write-and-traverse, no read. Sync hardening that walks past the
    /// directory it actually wrote into would refuse to mint an identity
    /// because of a directory the worker never needed to touch, and worker
    /// startup fails with it.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_ancestor_does_not_block_identity_publication() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("aiec-ancestor-{}", uuid::Uuid::now_v7()));
        let outer = root.join("outer");
        std::fs::create_dir_all(&outer).unwrap();
        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o300)).unwrap();
        let state_dir = outer.join("inner");
        std::fs::create_dir_all(&state_dir).unwrap();

        // The precondition: usable for its purpose, not openable for reading.
        assert!(
            std::fs::File::open(&outer).is_err(),
            "the fixture must be an ancestor that cannot be opened"
        );

        let minted = durable_node_id(&state_dir)
            .expect("an unreadable ancestor must not stop the worker minting an identity");
        assert_eq!(durable_node_id(&state_dir).unwrap(), minted);

        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_directory_at_the_identity_path_is_refused_and_preserved() {
        let dir = std::env::temp_dir().join(format!("aiec-node-id-{}", uuid::Uuid::now_v7()));
        let path = dir.join("node-id");
        std::fs::create_dir_all(&path).unwrap();
        let marker = path.join("preserve");
        std::fs::write(&marker, b"existing directory").unwrap();
        assert!(durable_node_id(&dir).is_err());
        assert!(path.is_dir());
        assert_eq!(std::fs::read(marker).unwrap(), b"existing directory");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_identity_is_not_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aiec-node-id-{}", uuid::Uuid::now_v7()));
        let original = durable_node_id(&dir).unwrap();
        let path = dir.join("node-id");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200)).unwrap();
        if std::fs::read_to_string(&path).is_ok() {
            eprintln!(
                "this process bypasses file read permissions; unreadable-file case not exercised"
            );
            std::fs::remove_dir_all(dir).unwrap();
            return;
        }
        assert!(durable_node_id(&dir).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(durable_node_id(&dir).unwrap(), original);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn simultaneous_first_starts_adopt_one_identity() {
        let dir = std::env::temp_dir().join(format!("aiec-node-id-{}", uuid::Uuid::now_v7()));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    durable_node_id(&dir).unwrap()
                })
            })
            .collect();
        let identities: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(identities.iter().all(|id| *id == identities[0]));
        assert_eq!(durable_node_id(&dir).unwrap(), identities[0]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_assigned_identity_survives_the_next_start() {
        let dir = std::env::temp_dir().join(format!("aiec-node-id-{}", uuid::Uuid::now_v7()));
        let first = durable_node_id(&dir).unwrap();
        let assigned = uuid::Uuid::now_v7();
        assert_ne!(assigned, first);
        persist_node_id(&dir, assigned).unwrap();
        assert_eq!(durable_node_id(&dir).unwrap(), assigned);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.join("node-id"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replacing_an_identity_never_exposes_partial_or_missing_content() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = std::env::temp_dir().join(format!("aiec-node-id-{}", uuid::Uuid::now_v7()));
        let first = durable_node_id(&dir).unwrap();
        let assigned = uuid::Uuid::now_v7();
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let writer_dir = dir.clone();
        let writer_done = done.clone();
        let writer = std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<()> {
                for index in 0..200 {
                    persist_node_id(&writer_dir, if index % 2 == 0 { first } else { assigned })?;
                }
                Ok(())
            })();
            writer_done.store(true, Ordering::Release);
            result
        });
        let mut failure = None;
        loop {
            match durable_node_id(&dir) {
                Ok(id) if id == first || id == assigned => {}
                other => {
                    failure = Some(other);
                }
            }
            if failure.is_some() || done.load(Ordering::Acquire) {
                break;
            }
        }
        writer.join().unwrap().unwrap();
        assert!(
            failure.is_none(),
            "a replacement exposed invalid identity: {failure:?}"
        );
        assert_eq!(durable_node_id(&dir).unwrap(), assigned);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
