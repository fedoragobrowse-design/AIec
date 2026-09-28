//! `bash`: run one command, with a timeout, and report what it printed.
//!
//! It is called `bash` and it is not bash. The `command` argument is an argv
//! array, executed directly, because a tool that takes a shell string hands
//! the model `;`, `&&`, `>`, and `$()` — at which point the model's judgement
//! about what is inside the workspace is the only thing between a read and a
//! `curl | sh`. If a model wants a pipeline it can run `sh -c` as an argument,
//! visibly, in one argv entry, rather than have one interposed invisibly.
//!
//! The other half of the job is bounding a process that prints forever. Two
//! pipes are drained concurrently into capped buffers, so a command that
//! emits a gigabyte of output costs a fixed amount of memory and says so.

use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::AsyncRead;
use tokio::process::Command;

use super::read::{Call, clamp, display_path};
use super::{Tool, ToolContext, ToolOutput, field_or, field_usize, resolve, tool_error};
use crate::ToolFailure;
use crate::model::ToolSpec;

/// Hard ceiling on the bytes kept from one stream, whatever the task allows.
const STREAM_CAP: usize = 256 * 1024;
/// Smallest per-stream cap, so a tiny `max_tool_output_bytes` still returns
/// something rather than nothing.
const MIN_STREAM_CAP: usize = 1024;

pub struct Bash;

impl Tool for Bash {
    fn name(&self) -> &'static str {
        "bash"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "bash".into(),
            description: "Run a command in the workspace. `command` is an argv array executed \
                          directly, never through a shell, so `;`, `&&` and `>` are literal. Output \
                          is capped and the command is killed on timeout."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "description": "Argument vector, e.g. [\"cargo\", \"test\", \"-p\", \"core\"]."
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory relative to the workspace root."
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Wall clock limit; capped at the task's command limit."
                    }
                },
                "required": ["command"],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Bash::run(args, ctx))
    }
}

impl Bash {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        let argv = argv(args)?;
        let program = argv[0].clone();

        let cwd = {
            let raw = field_or(args, "cwd", ".");
            let path = resolve(&ctx.root, raw)?;
            // `resolve` refuses `..` as text; this refuses a `cwd` that is a
            // symlink pointing at `/`.
            let real = super::read::canonical_inside(&ctx.root, &path)?;
            if !real.is_dir() {
                return Err(tool_error("cwd", format!("{raw} is not a directory")));
            }
            real
        };

        let requested = field_usize(args, "timeout_seconds", 0) as u64;
        let ceiling = ctx.limits.command_timeout_seconds.max(1);
        let seconds = if requested == 0 {
            ceiling
        } else {
            requested.min(ceiling)
        };

        let mut command = Command::new(&program);
        command
            .args(&argv[1..])
            .current_dir(&cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own process group, so the timeout can take the whole tree
            // down rather than orphaning whatever it started.
            .process_group(0)
            .kill_on_drop(true);

        let started = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|e| tool_error("command", format!("could not start `{program}`: {e}")))?;
        let pid = child.id();

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        // Each stream gets half the ceiling so that both, plus the markers
        // naming what was dropped, still fit inside `max_tool_output_bytes`.
        let stream_cap = (ctx.limits.max_tool_output_bytes / 2).clamp(MIN_STREAM_CAP, STREAM_CAP);
        let out_task = tokio::spawn(drain(stdout, stream_cap));
        let err_task = tokio::spawn(drain(stderr, stream_cap));

        let mut timed_out = false;
        let status = match tokio::time::timeout(Duration::from_secs(seconds), child.wait()).await {
            Ok(result) => {
                Some(result.map_err(|e| tool_error("command", format!("`{program}`: {e}")))?)
            }
            Err(_) => {
                timed_out = true;
                kill_tree(pid, &mut child);
                // The pipes close once it is dead, which is what lets the
                // readers finish; the wait is bounded because SIGKILL is not.
                let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                None
            }
        };
        let elapsed = started.elapsed();

        let (out_bytes, out_truncated) = join_bounded(out_task).await;
        let (err_bytes, err_truncated) = join_bounded(err_task).await;

        let exit = match status {
            Some(s) => s
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into()),
            None if timed_out => "timed out".to_owned(),
            None => "unknown".to_owned(),
        };

        let mut report = String::new();
        if timed_out {
            report.push_str(&format!(
                "[timed out after {seconds}s and the process tree was killed]\n"
            ));
        }
        report.push_str(&format!(
            "$ {}   [exit {exit}, {:.2}s, in {}]\n",
            display_argv(&argv),
            elapsed.as_secs_f64(),
            display_path(&ctx.root, &cwd),
        ));
        if !out_bytes.is_empty() || out_truncated {
            report.push_str("--- stdout ---\n");
            report.push_str(&String::from_utf8_lossy(&out_bytes));
            if out_truncated {
                report.push_str(&format!(
                    "\n[truncated: stdout incomplete at {stream_cap} bytes; the command printed more]\n"
                ));
            }
        }
        if !err_bytes.is_empty() || err_truncated {
            report.push_str("--- stderr ---\n");
            report.push_str(&String::from_utf8_lossy(&err_bytes));
            if err_truncated {
                report.push_str(&format!(
                    "\n[truncated: stderr incomplete at {stream_cap} bytes; the command printed more]\n"
                ));
            }
        }
        if out_bytes.is_empty() && err_bytes.is_empty() {
            report.push_str("(no output)\n");
        }

        let moved = (out_bytes.len() + err_bytes.len()) as u64;
        Ok(ToolOutput::sized(
            clamp(report, ctx.limits.max_tool_output_bytes),
            moved,
        ))
    }
}

/// The argv, as strings. A shell string here would be a shell.
fn argv(args: &Value) -> Result<Vec<String>, ToolFailure> {
    let Some(list) = args.get("command").and_then(Value::as_array) else {
        return Err(tool_error(
            "command",
            "`command` is required and must be an array of strings, e.g. [\"ls\", \"-la\"]. No shell \
             is interposed, so quoting and ; do not work.",
        ));
    };
    if list.is_empty() {
        return Err(tool_error("command", "`command` is empty"));
    }
    let mut out = Vec::with_capacity(list.len());
    for (i, value) in list.iter().enumerate() {
        let Some(s) = value.as_str() else {
            return Err(tool_error(
                "command",
                format!("`command[{i}]` is not a string"),
            ));
        };
        if s.contains('\0') {
            return Err(tool_error(
                "command",
                format!("`command[{i}]` contains a null byte"),
            ));
        }
        out.push(s.to_owned());
    }
    Ok(out)
}

/// The command as the model should read it back: one line, shell-quoted, so an
/// argument containing a space is not silently two arguments.
fn display_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty() || a.contains([' ', '\t', '\'', '"', '\n']) {
                format!("'{}'", a.replace('\'', r"'\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Reads a pipe to EOF or to `cap` bytes, whichever comes first. The `cap + 1`
/// is what makes "there was more" provable without reading all of it.
pub(crate) async fn drain<R>(reader: Option<R>, cap: usize) -> (Vec<u8>, bool)
where
    R: AsyncRead + Unpin,
{
    let Some(mut reader) = reader else {
        return (Vec::new(), false);
    };
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let limit = cap.saturating_add(1);
    while buf.len() < limit {
        let want = (limit - buf.len()).min(chunk.len());
        match tokio::io::AsyncReadExt::read(&mut reader, &mut chunk[..want]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    if buf.len() > cap {
        buf.truncate(cap);
        return (buf, true);
    }
    (buf, false)
}

/// How long to wait for a pipe reader once the process is accounted for.
const JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Waits for a reader, but not forever.
///
/// The process group kill takes down anything that stayed in the group; a
/// descendant that put *itself* in another group and kept the write end open
/// would otherwise leave this join pending forever, and a tool that has
/// already killed its command must still return. The bytes read so far are
/// lost with the task, so the caller is told the stream was cut rather than
/// shown a half-read pipe as if it were complete.
pub(crate) async fn join_bounded(
    handle: tokio::task::JoinHandle<(Vec<u8>, bool)>,
) -> (Vec<u8>, bool) {
    match tokio::time::timeout(JOIN_TIMEOUT, handle).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(_)) => (Vec::new(), false),
        Err(_) => (Vec::new(), true),
    }
}

/// SIGKILL to the child's process group, falling back to the child itself.
pub(crate) fn kill_tree(pid: Option<u32>, child: &mut tokio::process::Child) {
    if let Some(pid) = pid {
        // SAFETY: `kill` is a syscall wrapper; a signal to a group id this
        // process created as its own leader cannot affect the harness.
        let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    }
    let _ = child.start_kill();
}
