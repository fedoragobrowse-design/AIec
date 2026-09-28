//! `git_status` and `git_diff`: git's own answer, bounded.
//!
//! Both shell out to `git` rather than reading `.git` or walking the tree.
//! Git already knows about merges, renames, submodules, index state, and
//! `.gitignore`, and a reimplementation of that is a worse answer delivered
//! faster. What this module owns is the part git does not do for us: bounding
//! the output. A diff of a vendored dependency is a hundred megabytes, and the
//! model's context is not.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::process::Command;

use super::bash::{drain, join_bounded, kill_tree};
use super::read::{Call, clamp};
use super::{Tool, ToolContext, ToolOutput, tool_error};
use crate::ToolFailure;
use crate::model::ToolSpec;

/// Status lines shown before the rest are counted rather than listed.
const MAX_STATUS_LINES: usize = 200;
/// Bytes of diff kept. Diff is capped separately from the tool ceiling because
/// a truncated diff with no diffstat is not much use to a model.
const DIFF_CAP: usize = 128 * 1024;
/// Bytes of porcelain status kept; a status listing past this is pathological.
const STATUS_CAP: usize = 64 * 1024;
/// Never wait longer than this for git, whatever the task's command limit says.
const GIT_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Status;
pub struct Diff;

impl Tool for Status {
    fn name(&self) -> &'static str {
        "git_status"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "git_status".into(),
            description:
                "Working tree status: branch, HEAD, and porcelain entries. Reports plainly \
                          when the workspace is not a git repository."
                    .into(),
            parameters: json!({
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, _args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Status::run(ctx))
    }
}

impl Status {
    async fn run(ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        if !is_repo(ctx).await {
            return Ok(ToolOutput::text(format!(
                "{} is not a git repository, so there is no status to report.",
                ctx.root.display()
            )));
        }

        let porcelain = run(ctx, &["status", "--porcelain=v1", "--branch"], STATUS_CAP).await?;
        let head = run(ctx, &["rev-parse", "--short", "HEAD"], 4096)
            .await
            .ok()
            .map(|r| String::from_utf8_lossy(&r.stdout).trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unborn (no commits yet)".to_owned());

        let text = String::from_utf8_lossy(&porcelain.stdout);
        let mut branch = "unknown".to_owned();
        let mut entries: Vec<&str> = Vec::new();
        for line in text.lines() {
            // `--branch` prefixes a `## branch...tracking` line; the rest are
            // one entry per changed path.
            if let Some(rest) = line.strip_prefix("## ") {
                branch = rest.split("...").next().unwrap_or(rest).trim().to_owned();
            } else if !line.trim().is_empty() {
                entries.push(line);
            }
        }

        let mut out = format!("branch: {branch}\nhead: {head}\n");
        if entries.is_empty() {
            out.push_str("clean: no changes to tracked or untracked files\n");
        } else {
            out.push_str(&format!("{} changed path(s):\n", entries.len()));
            let shown = entries.len().min(MAX_STATUS_LINES);
            for entry in &entries[..shown] {
                out.push_str(entry);
                out.push('\n');
            }
            if shown < entries.len() {
                out.push_str(&format!(
                    "[truncated: {}-more changed paths not listed]\n",
                    entries.len() - shown
                ));
            }
        }
        if porcelain.truncated {
            out.push_str(&format!(
                "[truncated: git status cut at {STATUS_CAP} bytes]\n"
            ));
        }

        Ok(ToolOutput::sized(
            clamp(out, ctx.limits.max_tool_output_bytes),
            porcelain.stdout.len() as u64,
        ))
    }
}

impl Tool for Diff {
    fn name(&self) -> &'static str {
        "git_diff"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "git_diff".into(),
            description: "Unified diff of the working tree, or of the index against HEAD with \
                          staged=true. Bounded, and says so when it was cut."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "staged": {
                        "type": "boolean",
                        "description": "Diff the index against HEAD instead of the working tree."
                    }
                },
                "required": [],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Diff::run(args, ctx))
    }
}

impl Diff {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        if !is_repo(ctx).await {
            return Ok(ToolOutput::text(format!(
                "{} is not a git repository, so there is no diff.",
                ctx.root.display()
            )));
        }

        let staged = args.get("staged").and_then(Value::as_bool).unwrap_or(false);
        let scope = if staged { "staged" } else { "working tree" };
        let mut argv: Vec<&str> = vec!["diff", "--no-color", "--no-ext-diff"];
        if staged {
            argv.push("--staged");
        }
        let diff = run(ctx, &argv, DIFF_CAP).await?;
        let stat = run(ctx, &["diff", "--no-color", "--shortstat"], 4096)
            .await
            .ok()
            .map(|r| String::from_utf8_lossy(&r.stdout).trim().to_owned())
            .filter(|s| !s.is_empty());

        if diff.stdout.is_empty() {
            return Ok(ToolOutput::text(format!("no changes in the {scope}")));
        }

        let mut out = match &stat {
            Some(stat) => format!("diff ({scope}): {stat}\n"),
            None => format!("diff ({scope})\n"),
        };
        out.push_str(&String::from_utf8_lossy(&diff.stdout));
        if diff.truncated {
            out.push_str(&format!(
                "\n[truncated: diff incomplete at {DIFF_CAP} bytes; narrow it, e.g. `git diff -- \
                 <path>` through bash]\n"
            ));
        }

        Ok(ToolOutput::sized(
            clamp(out, ctx.limits.max_tool_output_bytes),
            diff.stdout.len() as u64,
        ))
    }
}

/// One git subprocess, with its output capped.
struct Output {
    stdout: Vec<u8>,
    truncated: bool,
}

/// Whether the workspace root is inside a work tree. Not an error: plenty of
/// tasks are "here is a directory, no repository", and the model should be told
/// that rather than shown a failure.
async fn is_repo(ctx: &ToolContext) -> bool {
    match run(ctx, &["rev-parse", "--is-inside-work-tree"], 4096).await {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim() == "true",
        Err(_) => false,
    }
}

/// Runs `git` in the workspace and reads its output through a cap, so a
/// repository whose diff is a hundred megabytes costs a fixed amount of memory.
async fn run(ctx: &ToolContext, args: &[&str], cap: usize) -> Result<Output, ToolFailure> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(&ctx.root)
        .args(args)
        .current_dir(&ctx.root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // No terminal, no credential prompt, no pager: a git that blocks
        // waiting for input would hang the whole session.
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .kill_on_drop(true);

    let mut child = command
        .spawn()
        .map_err(|e| tool_error("git", format!("could not run git: {e}")))?;
    let pid = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_task = tokio::spawn(drain(stdout, cap));
    let err_task = tokio::spawn(drain(stderr, 8 * 1024));

    let limit = GIT_TIMEOUT.min(Duration::from_secs(
        ctx.limits.command_timeout_seconds.max(1),
    ));
    let status = match tokio::time::timeout(limit, child.wait()).await {
        Ok(result) => {
            Some(result.map_err(|e| tool_error("git", format!("git {}: {e}", args.join(" "))))?)
        }
        Err(_) => {
            kill_tree(pid, &mut child);
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            return Err(tool_error(
                "git",
                format!(
                    "git {} did not finish in {:.0}s",
                    args.join(" "),
                    limit.as_secs_f64()
                ),
            ));
        }
    };

    let (out_bytes, out_truncated) = join_bounded(out_task).await;
    let (err_bytes, _) = join_bounded(err_task).await;

    if let Some(status) = status
        && !status.success()
    {
        let detail = String::from_utf8_lossy(&err_bytes);
        let detail = detail.trim();
        if !detail.is_empty() {
            return Err(tool_error(
                "git",
                format!("git {}: {detail}", args.join(" ")),
            ));
        }
    }

    Ok(Output {
        stdout: out_bytes,
        truncated: out_truncated,
    })
}
