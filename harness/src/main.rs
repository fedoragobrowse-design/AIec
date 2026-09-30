//! The binary. One task, one process, one exit.
//!
//! `run` is the path everything else exists to serve, so it stays the shortest
//! possible invocation: no config file to find, no daemon to reach, no warm-up.

use clap::Parser;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use aiec_harness::agent::Agent;
use aiec_harness::events::{EventLog, Stderr};
use aiec_harness::model::{ModelConfig, Provider, Reasoning};
use aiec_harness::result::{Provenance, Result as RunResult, Status};
use aiec_harness::session::SessionState;
use aiec_harness::task::Task;
use aiec_harness::{HarnessError, model};

#[derive(clap::Subcommand)]
enum Command {
    /// Run one task to completion. The normal, and intended, mode.
    Run {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        result: PathBuf,
        /// JSONL event stream. Defaults to `<workspace>/.aiec-agent/events.jsonl`.
        #[arg(long)]
        events: Option<PathBuf>,
        /// Resume state. Defaults to `<workspace>/.aiec-agent/session.json`.
        #[arg(long)]
        state: Option<PathBuf>,
        /// Provider override. Otherwise taken from the environment.
        #[arg(long, env = "AIEC_AGENT_PROVIDER")]
        provider: Option<String>,
        #[arg(long, env = "AIEC_AGENT_MODEL")]
        model: Option<String>,
        #[arg(long, env = "AIEC_AGENT_BASE_URL")]
        base_url: Option<String>,
        /// Resume a previous incomplete session if one matches this task.
        #[arg(long)]
        resume: bool,
    },
    /// Machine-readable capability handshake, so a host can decide whether
    /// this guest is usable before it starts a run.
    Capabilities,
    /// Measure the harness's own overhead, with no model and no network.
    ///
    /// This is the number that makes two harnesses comparable: a task's wall
    /// time is mostly a provider waiting, and that total hides everything the
    /// harness itself does.
    Bench {
        #[arg(long, default_value_t = 50)]
        iterations: usize,
    },
    #[command(version)]
    Version,
}

#[derive(clap::Parser)]
#[command(
    name = "aiec-agent",
    about = "A small coding-agent runtime for disposable AIec VMs.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            task,
            result,
            events,
            state,
            provider,
            model: model_name,
            base_url,
            resume,
        } => run(RunArgs {
            task,
            result,
            events,
            state,
            provider,
            model: model_name,
            base_url,
            resume,
        }),
        Command::Capabilities => capabilities(),
        Command::Bench { iterations } => {
            let report = aiec_harness::bench::run(iterations);
            let (peak, current) = aiec_harness::bench::rss();
            print!("{}", report.render());
            let mib = |b: Option<u64>| match b {
                Some(v) => format!("{:.1} MiB", v as f64 / (1024.0 * 1024.0)),
                None => "unavailable".to_owned(),
            };
            println!(
                "\nrss after the suite: current {} peak {}",
                mib(current),
                mib(peak)
            );
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("{} {}", aiec_harness::VERSION, env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}

struct RunArgs {
    task: PathBuf,
    result: PathBuf,
    events: Option<PathBuf>,
    state: Option<PathBuf>,
    provider: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
    resume: bool,
}

fn run(args: RunArgs) -> ExitCode {
    let started = Instant::now();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[error] could not start a runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(run_async(args, started))
}

async fn run_async(args: RunArgs, started: Instant) -> ExitCode {
    let ui = Stderr::from_env();

    // The task is read first and on its own: if it is malformed there is no
    // session, no result worth much, and no reason to start anything.
    let task = match Task::load(&args.task) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[error] {e}");
            return ExitCode::FAILURE;
        }
    };

    let root = match task.workspace_root() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[error] {e}");
            return ExitCode::FAILURE;
        }
    };

    // The overrides are read out first, so `args` stays whole for `model_config`.
    let event_path = args
        .events
        .clone()
        .unwrap_or_else(|| aiec_harness::events::default_event_path(&root));
    let state_path = args
        .state
        .clone()
        .unwrap_or_else(|| aiec_harness::events::default_state_path(&root));

    let log = match EventLog::open(Some(&event_path)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[error] could not open the event log at {event_path:?}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let config = match model_config(&args, task.limits.wall_seconds) {
        Ok(c) => c,
        Err(e) => {
            let provenance = fallback_provenance();
            let document = RunResult::for_error(&task.task_id, provenance, e.to_string());
            let _ = document.write_to(&args.result);
            eprintln!("[error] {e}");
            return ExitCode::FAILURE;
        }
    };

    let resumed = if args.resume {
        SessionState::load(&state_path).ok().flatten()
    } else {
        None
    };
    if resumed.is_some() {
        ui.say(&format!(
            "[agent] resuming task {} from {}",
            task.task_id,
            state_path.display()
        ));
    }

    let client = match model::http_client() {
        Ok(c) => c,
        Err(e) => {
            let document =
                RunResult::for_error(&task.task_id, fallback_provenance(), e.to_string());
            let _ = document.write_to(&args.result);
            eprintln!("[error] {e}");
            return ExitCode::FAILURE;
        }
    };

    let provider: Box<dyn model::ModelProvider> = match config.provider {
        Provider::Anthropic => Box::new(model::anthropic::AnthropicProvider::new(config, client)),
        _ => Box::new(model::openai::OpenAiProvider::new(config, client)),
    };

    let mut agent = match Agent::new(&task, provider.as_ref(), &log, resumed) {
        Ok(a) => a,
        Err(e) => {
            let document =
                RunResult::for_error(&task.task_id, fallback_provenance(), e.to_string());
            let _ = document.write_to(&args.result);
            eprintln!("[error] {e}");
            return ExitCode::FAILURE;
        }
    };

    for artifact in [&event_path, &args.result, &state_path, &args.task] {
        agent.note_artifact(artifact);
    }
    let mut document = agent.run(&state_path).await;

    // The agent already ran the caller's validation and folded its verdict into
    // the document; this only restamps the total wall time across the whole
    // process, which is what the caller experiences.
    document.metrics.wall_ms = started.elapsed().as_millis() as u64;

    provider.shutdown();

    if let Err(e) = document.write_to(&args.result) {
        eprintln!("[error] could not write the result: {e}");
        return ExitCode::FAILURE;
    }
    ui.say(&document.summary_line());

    match document.status {
        Status::Success => ExitCode::SUCCESS,
        Status::Failed | Status::Error => ExitCode::from(1),
    }
}

/// Reads the model configuration from the environment.
///
/// There is deliberately no config file: a repository is untrusted, and a file
/// inside the workspace must never be able to decide where credentials go.
fn model_config(
    args: &RunArgs,
    wall_seconds: u64,
) -> std::result::Result<ModelConfig, HarnessError> {
    let provider_name = args
        .provider
        .as_deref()
        .ok_or_else(|| HarnessError::MissingCredential("AIEC_AGENT_PROVIDER".into()))?;
    let provider = Provider::parse(provider_name).ok_or_else(|| {
        HarnessError::invalid(
            "provider",
            format!("`{provider_name}` is not a known provider"),
        )
    })?;
    let model = args
        .model
        .clone()
        .ok_or_else(|| HarnessError::MissingCredential("AIEC_AGENT_MODEL".into()))?;

    let reasoning = std::env::var("AIEC_AGENT_REASONING")
        .ok()
        .and_then(|r| match r.to_ascii_lowercase().as_str() {
            "off" | "none" => Some(Reasoning::Off),
            "low" => Some(Reasoning::Low),
            "medium" => Some(Reasoning::Medium),
            "high" => Some(Reasoning::High),
            _ => None,
        })
        .unwrap_or_default();

    let context_window = std::env::var("AIEC_AGENT_CONTEXT_WINDOW")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);

    Ok(ModelConfig {
        provider,
        model,
        base_url: args
            .base_url
            .clone()
            .or_else(|| std::env::var("AIEC_AGENT_BASE_URL").ok())
            .or_else(|| Some(provider.default_base_url().to_owned())),
        reasoning,
        context_window,
        // A single request may not outlive the session that asked for it. From
        // the task, not the environment: the task is what the caller actually
        // bounded, and the provider is downstream of that decision.
        deadline_ms: Some(wall_seconds.saturating_mul(1000)),
    })
}

/// Used when the run fails before a provider exists, so the result still records
/// enough to be attributable. The model is simply unknown.
fn fallback_provenance() -> Provenance {
    Provenance {
        harness_version: aiec_harness::VERSION.to_owned(),
        protocol: aiec_harness::PROTOCOL_VERSION,
        provider: "none".to_owned(),
        model: "none".to_owned(),
        task_digest: String::new(),
        config_digest: String::new(),
        repository_start_commit: None,
    }
}

fn capabilities() -> ExitCode {
    let document = serde_json::json!({
        "protocol": aiec_harness::PROTOCOL_VERSION,
        "version": aiec_harness::VERSION,
        "features": [
            "tool_calling",
            "structured_result",
            "jsonl_events",
            "session_resume",
            "task_budget",
            "context_compaction",
            "loop_detection",
            "steering"
        ],
        "tools": aiec_harness::tools::list_tools(),
        "providers": ["openai-compatible", "openrouter", "anthropic"],
    });
    match serde_json::to_string_pretty(&document) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[error] {e}");
            ExitCode::FAILURE
        }
    }
}

/// Kept so a path helper is available to future subcommands without a second
/// import block.
#[allow(dead_code)]
fn state_dir(root: &Path) -> PathBuf {
    root.join(".aiec-agent")
}
