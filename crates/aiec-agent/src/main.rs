//! Entry point.
//!
//! The normal shape of a run is a task document in, a result document out. No
//! configuration file, no daemon, no state that outlives the process: the VM
//! will be destroyed and this binary with it.
//!
//! Anything expensive - the HTTP client, the TLS session, the tool table - is
//! built after the task is read and only if it is actually needed, so a malformed
//! task costs a file read rather than a connection pool.

use std::path::PathBuf;

use aiec_agent::agent;
use aiec_agent::task::{HarnessError, Result_, StopReason, Task};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aiec-agent",
    about = "A very small coding-agent harness for AIec sandboxes",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one task to completion and write a result document.
    Run {
        /// Task specification.
        #[arg(long)]
        task: PathBuf,
        /// Where the result document is written.
        #[arg(long)]
        result: PathBuf,
        /// Append a human-readable trace to stderr as well as the event stream.
        #[arg(long, default_value_t = false)]
        verbose: bool,
    },
    /// Print the harness version and exit. Used by the version handshake.
    Version,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("aiec-agent {}", aiec_agent::HARNESS_VERSION);
        }
        Command::Run {
            task: task_path,
            result: result_path,
            verbose,
        } => {
            if verbose {
                tracing_subscriber::fmt()
                    .with_writer(std::io::stderr)
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
                    )
                    .init();
            }
            let task = match Task::load(&task_path) {
                Ok(task) => task,
                Err(error) => {
                    // A task that cannot be read is still a result: the caller
                    // must not have to infer a crash from a missing file.
                    let result = Result_ {
                        stop_reason: StopReason::Error,
                        error: Some(error.to_string()),
                        ..Default::default()
                    };
                    let _ = result.save(&result_path);
                    eprintln!("aiec-agent: {error}");
                    std::process::exit(2);
                }
            };
            std::process::exit(run(task, &result_path).await);
        }
    }
}

/// Runs one task. Returns the process exit code.
async fn run(task: Task, result_path: &std::path::Path) -> i32 {
    let mut outcome = Result_ {
        harness_version: aiec_agent::HARNESS_VERSION.to_owned(),
        ..Default::default()
    };

    match agent::execute(task, &mut outcome).await {
        Ok(()) => {
            let _ = outcome.save(result_path);
            if outcome.ok { 0 } else { 1 }
        }
        Err(error) => {
            outcome.stop_reason = StopReason::Error;
            outcome.error = Some(describe(&error));
            let _ = outcome.save(result_path);
            eprintln!("aiec-agent: {error}");
            2
        }
    }
}

/// A message safe to write to a result document.
///
/// A harness error can quote a model response, and a model response can quote a
/// tool result, and a tool result can quote a file. This keeps the first two
/// links in the chain from becoming a way to write arbitrary bytes into the
/// document a program is going to parse.
fn describe(error: &HarnessError) -> String {
    let text = error.to_string();
    const LIMIT: usize = 500;
    if text.chars().count() <= LIMIT {
        return text;
    }
    let truncated: String = text.chars().take(LIMIT).collect();
    format!("{truncated}…")
}
