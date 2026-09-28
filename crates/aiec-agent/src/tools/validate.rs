//! Running the caller's own definition of done.
//!
//! The model saying "finished" is not evidence. The commands the task author
//! wrote are: validation runs after the agent stops, and the result is their
//! exit codes. This is deliberately not advisory - a run that reports success
//! with failing validations would be worse than useless to whoever scheduled it.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::task::ValidationOutcome;

/// How long one validation may take before it is treated as failed.
const MAX_SECONDS: u64 = 600;

/// Only the tail of a validation's output is kept: its job is its exit code, and
/// a failing build's last lines are the useful ones, not its first.
const OUTPUT_TAIL: usize = 2000;

/// Runs every validation, in order, and reports each one.
///
/// Every validation runs even if an earlier one failed. Stopping at the first
/// would hide whether the failure is one problem or several, and that
/// distinction is usually the whole point of running them.
pub async fn run_all(root: &Path, commands: &[Vec<String>]) -> Vec<ValidationOutcome> {
    let mut results = Vec::with_capacity(commands.len());
    for command in commands {
        results.push(run_one(root, command).await);
    }
    results
}

async fn run_one(root: &Path, command: &[String]) -> ValidationOutcome {
    if command.is_empty() {
        return ValidationOutcome {
            command: command.to_vec(),
            exit_code: -1,
            ok: false,
            duration_ms: 0,
            output_tail: "the validation command is empty".to_owned(),
        };
    }
    let started = Instant::now();
    let child = tokio::process::Command::new(&command[0])
        .args(&command[1..])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(error) => {
            return ValidationOutcome {
                command: command.to_vec(),
                exit_code: -1,
                ok: false,
                duration_ms: started.elapsed().as_millis() as u64,
                output_tail: format!("could not start: {error}"),
            };
        }
    };

    let output =
        tokio::time::timeout(Duration::from_secs(MAX_SECONDS), child.wait_with_output()).await;
    match output {
        Ok(Ok(output)) => ValidationOutcome {
            command: command.to_vec(),
            exit_code: output.status.code().unwrap_or(-1),
            ok: output.status.success(),
            duration_ms: started.elapsed().as_millis() as u64,
            output_tail: tail(&format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )),
        },
        Ok(Err(error)) => ValidationOutcome {
            command: command.to_vec(),
            exit_code: -1,
            ok: false,
            duration_ms: started.elapsed().as_millis() as u64,
            output_tail: format!("{error}"),
        },
        Err(_) => {
            // `wait_with_output` consumed the child, and `kill_on_drop` fired
            // when the future was dropped: a validation that hangs is a failure,
            // not something to wait out for a VM whose lifetime is finite.
            ValidationOutcome {
                command: command.to_vec(),
                exit_code: -1,
                ok: false,
                duration_ms: started.elapsed().as_millis() as u64,
                output_tail: format!("timed out after {MAX_SECONDS}s"),
            }
        }
    }
}

fn tail(text: &str) -> String {
    if text.len() <= OUTPUT_TAIL {
        return text.trim().to_owned();
    }
    let start = text.len() - OUTPUT_TAIL;
    let mut at = start;
    while at < text.len() && !text.is_char_boundary(at) {
        at += 1;
    }
    format!("…{}\n{}", &text[at..], text[..start].is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_passing_validation_passes() {
        let root = std::env::temp_dir();
        let results = run_one(&root, &["/bin/sh".into(), "-c".into(), "exit 0".into()]).await;
        assert!(results.ok);
        assert_eq!(results.exit_code, 0);
    }

    #[tokio::test]
    async fn a_failing_validation_fails_with_its_output() {
        let root = std::env::temp_dir();
        let results = run_one(
            &root,
            &[
                "/bin/sh".into(),
                "-c".into(),
                "echo 'the actual problem'; exit 3".into(),
            ],
        )
        .await;
        assert!(!results.ok);
        assert_eq!(results.exit_code, 3);
        assert!(
            results.output_tail.contains("the actual problem"),
            "{}",
            results.output_tail
        );
    }

    #[tokio::test]
    async fn a_command_that_cannot_start_fails_rather_than_panicking() {
        let root = std::env::temp_dir();
        let results = run_one(&root, &["/nonexistent/binary-xyz".into()]).await;
        assert!(!results.ok);
        assert!(results.output_tail.contains("could not start"));
    }

    #[tokio::test]
    async fn an_empty_command_is_a_failure_not_a_crash() {
        let root = std::env::temp_dir();
        let results = run_one(&root, &[]).await;
        assert!(!results.ok);
    }
}
