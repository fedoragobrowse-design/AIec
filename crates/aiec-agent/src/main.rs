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
                    // The task's own failure is reported first, so that a result
                    // directory which cannot be written does not replace it
                    // with the only complaint the operator gets to read.
                    eprintln!("aiec-agent: {error}");
                    std::process::exit(publish(&result, &result_path, 2));
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
            let earned = if outcome.ok { 0 } else { 1 };
            publish(&outcome, result_path, earned)
        }
        Err(error) => {
            outcome.stop_reason = StopReason::Error;
            outcome.error = Some(describe(&error));
            // Reported before the attempt to write it down, so that a result
            // directory which cannot be written does not replace the only
            // thing the operator had to read with a complaint about the disk.
            eprintln!("aiec-agent: {error}");
            publish(&outcome, result_path, 2)
        }
    }
}

/// Writes the result document and turns the outcome into an exit code.
///
/// The document is the only channel this harness has. A caller that reads exit
/// 0 expects a file, and the save used to be discarded - so a read-only result
/// directory or a full disk produced exit 0 with nothing on disk, which is the
/// one outcome that cannot be told apart from a good run. A save that fails is
/// the harness failing, whatever the model did, and it is reported on stderr
/// because the document it belongs in is the thing that could not be written.
///
/// `earned` is the code the outcome earns on its own, returned untouched when
/// the document lands where it was asked to.
fn publish(outcome: &Result_, result_path: &std::path::Path, earned: i32) -> i32 {
    match outcome.save(result_path) {
        Ok(()) => earned,
        Err(error) => {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A result nobody can read is not a result.
    ///
    /// The save was discarded at every call site, so a read-only directory or a
    /// full disk produced exit 0 and no file - and a caller reading exit 0 has
    /// nothing to parse and no way to know the run never reached it.
    #[test]
    fn a_result_that_cannot_be_written_is_not_a_successful_run() {
        let outcome = Result_ {
            ok: true,
            stop_reason: StopReason::TaskComplete,
            ..Default::default()
        };
        // A directory that does not exist, so the temporary file the save goes
        // through cannot be created either.
        let unwritable = std::path::Path::new("/nonexistent-aiec-result-dir/result.json");
        assert_eq!(
            publish(&outcome, unwritable, 0),
            2,
            "exit 0 with no result file on disk"
        );
        // The same outcome, written where it can be written, earns the code it
        // earned - so what the assertion above caught is the save and nothing
        // about the outcome itself.
        let path = std::env::temp_dir().join(format!("aiec-publish-{}.json", std::process::id()));
        assert_eq!(publish(&outcome, &path, 0), 0, "{path:?}");
        assert!(path.exists(), "the document was not written: {path:?}");
        let _ = std::fs::remove_file(&path);
    }

    /// A failed run whose result cannot be written down is still a failure.
    #[test]
    fn an_unwritable_failure_is_still_reported_as_a_failure() {
        let outcome = Result_ {
            ok: false,
            stop_reason: StopReason::Error,
            error: Some("the model refused the request: provider returned 401".to_owned()),
            ..Default::default()
        };
        let unwritable = std::path::Path::new("/nonexistent-aiec-result-dir/result.json");
        assert_ne!(publish(&outcome, unwritable, 1), 0);
    }
}
