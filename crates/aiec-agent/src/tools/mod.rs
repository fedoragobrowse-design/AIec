//! The tools, and the small amount of policy around them.
//!
//! Nine tools, deliberately. Every one of them costs schema tokens on every
//! request and adds a way for a model to be confused, so the set is the smallest
//! that can read, change, search and verify a repository. A harness that ships
//! seventy tools to match a competitor is charging the user for all of them on
//! every turn.
//!
//! The search tools go through the repository's own index where one exists, and
//! everything they return is bounded. A tool that returns 40,000 lines of
//! matches has not helped the model; it has charged it.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::model::{ToolCall, ToolSchema};
use crate::task::HarnessError;

pub mod git;
pub mod validate;

/// The tools this harness offers, with the schema each advertises.
///
/// The descriptions are the reference manual, which is why the system prompt can
/// be small: everything a model needs to know about a tool is here, sent once.
pub fn schemas() -> Vec<ToolSchema> {
    fn schema(
        name: &'static str,
        description: &'static str,
        parameters: serde_json::Value,
    ) -> ToolSchema {
        ToolSchema {
            name,
            description,
            parameters,
        }
    }

    vec![
        schema(
            "read",
            "Read a file. Returns numbered lines; pass offset/limit for part of a file.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path, relative to the repository root."},
                    "offset": {"type": "integer", "description": "First line to return, 1-based."},
                    "limit": {"type": "integer", "description": "Maximum number of lines."},
                },
                "required": ["path"],
                "additionalProperties": false,
            }),
        ),
        schema(
            "write",
            "Create or replace a whole file. Prefer edit for changes to an existing file.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path, relative to the repository root."},
                    "content": {"type": "string", "description": "Complete new contents."},
                },
                "required": ["path", "content"],
                "additionalProperties": false,
            }),
        ),
        schema(
            "edit",
            "Replace an exact string in a file. Fails if the string is absent or ambiguous.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path, relative to the repository root."},
                    "old": {"type": "string", "description": "Exact text to replace, including indentation."},
                    "new": {"type": "string", "description": "Replacement text."},
                    "replace_all": {"type": "boolean", "description": "Replace every occurrence rather than requiring uniqueness."},
                },
                "required": ["path", "old", "new"],
                "additionalProperties": false,
            }),
        ),
        schema(
            "find",
            "Find files by name pattern under the repository.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob pattern such as src/**/*.rs"},
                    "limit": {"type": "integer", "description": "Maximum matches to return."},
                },
                "required": ["pattern"],
                "additionalProperties": false,
            }),
        ),
        schema(
            "grep",
            "Search file contents for a regular expression.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regular expression."},
                    "glob": {"type": "string", "description": "Restrict to files matching this glob."},
                    "limit": {"type": "integer", "description": "Maximum matching lines to return."},
                },
                "required": ["pattern"],
                "additionalProperties": false,
            }),
        ),
        schema(
            "glob",
            "List repository files matching a glob, from the git index when possible.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob pattern such as **/*.toml"},
                    "limit": {"type": "integer", "description": "Maximum paths to return."},
                },
                "required": ["pattern"],
                "additionalProperties": false,
            }),
        ),
        schema(
            "bash",
            "Run a shell command. Returns exit code, stdout and stderr, each bounded.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The command line to run."},
                    "timeout_seconds": {"type": "integer", "description": "Kill the command after this long."},
                },
                "required": ["command"],
                "additionalProperties": false,
            }),
        ),
        schema(
            "git_status",
            "Working tree status, from git.",
            serde_json::json!({"type": "object", "properties": {}, "additionalProperties": false}),
        ),
        schema(
            "git_diff",
            "Uncommitted diff, from git.",
            serde_json::json!({"type": "object", "properties": {}, "additionalProperties": false}),
        ),
    ]
}

/// Dispatches tool calls for one repository.
pub struct Registry {
    root: PathBuf,
}

impl Registry {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    pub fn schemas(&self) -> Vec<ToolSchema> {
        schemas()
    }

    /// Runs one call and returns the text the model will see.
    pub async fn execute(&self, call: &ToolCall, root: &Path) -> Result<String, HarnessError> {
        let args: Value = serde_json::from_str(&call.arguments).map_err(|error| {
            HarnessError::Tool(format!("{}: arguments are not json: {error}", call.name))
        })?;
        let _ = &self.root;
        match call.name.as_str() {
            "read" => read(root, &args),
            "write" => write(root, &args),
            "edit" => edit(root, &args),
            "find" | "glob" => find(root, &args),
            "grep" => grep(root, &args),
            "bash" => bash(root, &args).await,
            "git_status" => git::status(root),
            "git_diff" => git::diff(root),
            other => Err(HarnessError::Tool(format!(
                "no such tool `{other}`; available: {}",
                schemas()
                    .iter()
                    .map(|t| t.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }
}

fn arg_str(args: &Value, name: &str) -> Result<String, HarnessError> {
    args.get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| HarnessError::Tool(format!("`{name}` is required")))
}

fn arg_usize(args: &Value, name: &str, fallback: usize) -> usize {
    args.get(name)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(fallback)
}

/// Resolves a path inside the repository, refusing to escape it.
///
/// The harness runs inside a sandbox, so this is not about hostile tenants. It
/// is about the model accidentally writing to `/etc` because it guessed a path,
/// which is a very common failure and a very annoying one - and every tool
/// schema here already says the path is "relative to the repository root", so
/// an absolute path is the model guessing rather than the caller asking.
///
/// Refusing `..` and absolute paths is not enough on its own: those are lexical
/// rules, and a repository can hold a symlink pointing anywhere -
/// `ln -s /etc link` makes `link/hosts` a path inside the repository whose
/// contents are not. So the answer is resolved through the real tree. Every
/// component that exists is canonicalized and must stay under the root, and a
/// component that does not exist yet is simply appended, which is what lets
/// `write` create `src/deep/new.rs` without having to special-case creation.
/// A path that exists but cannot be resolved - a dangling symlink, above all -
/// is refused rather than guessed at: opening one for write follows the link
/// and creates whatever it points at.
///
/// The check is on the tree as it is now. A link swapped between this call and
/// the write is still a way out; that is the price of not being the kernel, and
/// it is out of scope here because the caller is the model, not an attacker.
fn resolve(root: &Path, raw: &str) -> Result<PathBuf, HarnessError> {
    let candidate = Path::new(raw);
    if candidate.is_absolute() {
        return Err(HarnessError::Tool(format!(
            "`{raw}` is absolute; paths are relative to the repository root"
        )));
    }
    // The prefix checks below are lexical, so `a/../b` would slip through
    // them: the path has to be walked first, rejecting any `..` outright.
    if candidate
        .components()
        .any(|part| part == std::path::Component::ParentDir)
    {
        return Err(HarnessError::Tool(format!("`{raw}` leaves the repository")));
    }
    let base = std::fs::canonicalize(root).map_err(|error| {
        HarnessError::Tool(format!(
            "the repository root {} is unusable: {error}",
            root.display()
        ))
    })?;
    let parts: Vec<&std::ffi::OsStr> = candidate
        .components()
        .filter_map(|part| match part {
            std::path::Component::Normal(name) => Some(name),
            // `.` is noise the join would keep; root and prefix cannot appear
            // in a relative path, and `..` was refused above.
            _ => None,
        })
        .collect();
    let mut current = base.clone();
    for (index, name) in parts.iter().enumerate() {
        let probe = current.join(name);
        match std::fs::symlink_metadata(&probe) {
            Ok(_) => match std::fs::canonicalize(&probe) {
                Ok(real) => {
                    if !real.starts_with(&base) {
                        return Err(HarnessError::Tool(format!(
                            "`{raw}` is outside the repository"
                        )));
                    }
                    current = real;
                }
                // It exists, so something is there to be opened, and it cannot
                // be resolved. Creating the file would follow the link.
                Err(_) => {
                    return Err(HarnessError::Tool(format!(
                        "`{raw}` does not resolve; it may be a broken link"
                    )));
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Nothing here yet, and nothing below it can exist either. The
                // rest of the path is the caller's to create, but it hangs off
                // what was walked, not off the root: `current` may be several
                // resolved components down, and joining to the root would drop
                // the directories that do exist.
                for name in &parts[index..] {
                    current.push(*name);
                }
                break;
            }
            Err(error) => {
                return Err(HarnessError::Tool(format!(
                    "cannot resolve `{raw}`: {error}"
                )));
            }
        }
    }
    Ok(current)
}

fn read(root: &Path, args: &Value) -> Result<String, HarnessError> {
    let path = resolve(root, &arg_str(args, "path")?)?;
    let text = std::fs::read_to_string(&path)
        .map_err(|error| HarnessError::Tool(format!("{}: {error}", path.display())))?;
    let offset = arg_usize(args, "offset", 1).max(1);
    let limit = arg_usize(args, "limit", 2000);
    let mut out = String::new();
    for (index, line) in text.lines().enumerate().skip(offset - 1).take(limit) {
        out.push_str(&format!("{}\t{}\n", index + 1, line));
    }
    if out.len() > crate::DEFAULT_READ_BYTES {
        out.truncate(crate::head_bytes(&out, crate::DEFAULT_READ_BYTES).len());
        out.push_str("… truncated\n");
    }
    Ok(out)
}

fn write(root: &Path, args: &Value) -> Result<String, HarnessError> {
    let path = resolve(root, &arg_str(args, "path")?)?;
    let content = arg_str(args, "content")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            HarnessError::Tool(format!("creating {}: {error}", parent.display()))
        })?;
    }
    std::fs::write(&path, &content)
        .map_err(|error| HarnessError::Tool(format!("{}: {error}", path.display())))?;
    Ok(format!(
        "wrote {} bytes to {}",
        content.len(),
        path.display()
    ))
}

fn edit(root: &Path, args: &Value) -> Result<String, HarnessError> {
    let path = resolve(root, &arg_str(args, "path")?)?;
    let old = arg_str(args, "old")?;
    let new = arg_str(args, "new")?;
    let replace_all = args
        .get("replace_all")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let text = std::fs::read_to_string(&path)
        .map_err(|error| HarnessError::Tool(format!("{}: {error}", path.display())))?;
    let occurrences = text.matches(&old).count();
    if occurrences == 0 {
        return Err(HarnessError::Tool(format!(
            "`{}` does not appear in {}; read the file and copy the text exactly",
            crate::clip(&old, 60),
            path.display()
        )));
    }
    if occurrences > 1 && !replace_all {
        // Guessing which occurrence was meant is how an agent corrupts a file.
        return Err(HarnessError::Tool(format!(
            "`{}` appears {occurrences} times in {}; include more context or pass replace_all",
            crate::clip(&old, 60),
            path.display()
        )));
    }
    let updated = if replace_all {
        text.replace(&old, &new)
    } else {
        text.replacen(&old, &new, 1)
    };
    std::fs::write(&path, &updated)
        .map_err(|error| HarnessError::Tool(format!("{}: {error}", path.display())))?;
    Ok(format!("replaced in {}", path.display()))
}

fn find(root: &Path, args: &Value) -> Result<String, HarnessError> {
    let pattern = arg_str(args, "pattern")?;
    let limit = arg_usize(args, "limit", 200);
    // git ls-files is the cheap path: the index already knows what is tracked,
    // so this is one command rather than a filesystem walk.
    if let Ok(output) = std::process::Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(root)
        .output()
        && output.status.success()
    {
        let listed = String::from_utf8_lossy(&output.stdout);
        let matches: Vec<&str> = listed
            .lines()
            .filter(|line| glob_match(pattern.as_str(), line))
            .take(limit)
            .collect();
        return Ok(matches.join("\n"));
    }
    Ok(walk(root, &pattern, limit, MAX_WALK_DIRECTORIES)?.join("\n"))
}

fn grep(root: &Path, args: &Value) -> Result<String, HarnessError> {
    let pattern = arg_str(args, "pattern")?;
    let limit = arg_usize(args, "limit", 100);
    let glob = args.get("glob").and_then(Value::as_str);
    let output = std::process::Command::new("git")
        .args(["grep", "-n", "-I", "--no-color"])
        .arg(&pattern)
        .current_dir(root)
        .output();
    let text = match output {
        Ok(result) if result.status.success() || result.status.code() == Some(1) => {
            String::from_utf8_lossy(&result.stdout).to_string()
        }
        Ok(result) => {
            return Err(HarnessError::Tool(format!(
                "git grep failed: {}",
                crate::clip(&String::from_utf8_lossy(&result.stderr), 200)
            )));
        }
        Err(_) => return Err(HarnessError::Tool("git is not available".to_owned())),
    };
    let mut kept: Vec<&str> = text
        .lines()
        .filter(|line| glob.is_none_or(|pattern| glob_match(pattern, line)))
        .take(limit)
        .collect();
    if kept.is_empty() {
        return Ok("no matches".to_owned());
    }
    kept.shrink_to_fit();
    Ok(kept.join("\n"))
}

/// Runs a shell command, keeping its output bounded and leaving nothing behind.
///
/// Three properties this has to have, each of which was missing:
///
/// * The output is read incrementally and capped. Collecting the whole stream
///   and clipping it afterwards bounds what the *model* sees and nothing else,
///   so a command printing without end takes the sandbox down with it.
/// * The command runs in its own process group and a timeout kills the group.
///   Killing the shell leaves a backgrounded grandchild running for the rest of
///   the run, holding CPU and any pipe the next command is waiting on.
/// * What was dropped is counted. A model handed a silently clipped result
///   assumes the output ended there and concludes from a partial answer.
async fn bash(root: &Path, args: &Value) -> Result<String, HarnessError> {
    const STDOUT_CAP: usize = 8000;
    const STDERR_CAP: usize = 4000;
    let command = arg_str(args, "command")?;
    let timeout = arg_usize(args, "timeout_seconds", 120).clamp(1, 3600);
    let mut child = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .current_dir(root)
        // Explicit, because the default is to inherit: an inherited pipe means
        // the command's output goes to the harness's own stdout instead of to
        // the model, which is both invisible and unbounded.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Its own group, so the timeout below reaches everything it started.
        .process_group(0)
        // `kill_on_drop` so the child cannot outlive this function on any path
        // that returns early. `bash` runs a model-supplied command, and the
        // group above is only killed on the timeout arm; without this, an error
        // from `wait` returns with the shell and every backgrounded grandchild
        // it started still running for the rest of the run.
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| HarnessError::Tool(format!("spawning: {error}")))?;
    let group = child.id().map(|pid| pid as i32);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| HarnessError::Tool("stdout unavailable".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| HarnessError::Tool("stderr unavailable".to_owned()))?;
    let out_task = tokio::spawn(drain(stdout, STDOUT_CAP));
    let err_task = tokio::spawn(drain(stderr, STDERR_CAP));

    let status =
        match tokio::time::timeout(std::time::Duration::from_secs(timeout as u64), child.wait())
            .await
        {
            Ok(Ok(status)) => Some(status),
            Ok(Err(error)) => {
                // A `wait` error says nothing about whether the child is still
                // running, so this arm gets the same teardown as the timeout.
                // Returning straight out of here detached both reader tasks —
                // dropping a `JoinHandle` detaches rather than cancels — so the
                // bounded read above stopped being bounded exactly when the
                // tool failed, and the whole process group outlived the call.
                kill_group(&mut child, group).await;
                let _ = out_task.await;
                let _ = err_task.await;
                return Err(HarnessError::Tool(format!("{error}")));
            }
            Err(_) => {
                kill_group(&mut child, group).await;
                None
            }
        };

    // The pipes close when the group is gone, so these finish promptly even on
    // the timeout path. Awaiting them is what makes the bound hold: a detached
    // reader would still be accumulating after the tool call returned.
    let (stdout, stdout_total) = out_task.await.unwrap_or_default();
    let (stderr, stderr_total) = err_task.await.unwrap_or_default();
    let mut rendered = String::new();
    match status {
        Some(status) => rendered.push_str(&format!("exit={}\n", status.code().unwrap_or(-1))),
        None => rendered.push_str("timed out\n"),
    }
    rendered.push_str("--- stdout\n");
    push_stream(&mut rendered, &stdout, stdout_total, STDOUT_CAP);
    rendered.push_str("--- stderr\n");
    push_stream(&mut rendered, &stderr, stderr_total, STDERR_CAP);
    Ok(rendered)
}

/// Kills a spawned command's entire process group and reaps the shell.
///
/// The negative pid is what reaches a backgrounded grandchild: signalling only
/// the shell leaves whatever it started running for the rest of the run, which
/// is what the doc comment on [`bash`] is about. Reaping the shell is just as
/// necessary — an unreaped child is a zombie for the life of the harness,
/// holding its pid and the pipes the drain tasks are still reading.
async fn kill_group(child: &mut tokio::process::Child, group: Option<i32>) {
    if let Some(group) = group {
        // Negative pid: the signal goes to the process group.
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Reads a pipe to end of file, keeping at most `cap` bytes and counting the
/// rest. The pipe is always drained: a reader that stops early leaves the
/// writer blocked on a full pipe forever.
async fn drain<R>(mut reader: R, cap: usize) -> (Vec<u8>, u64)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut kept = Vec::with_capacity(cap.min(8192));
    let mut total: u64 = 0;
    let mut buffer = [0; 8192];
    loop {
        match tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                total += count as u64;
                if kept.len() < cap {
                    let take = count.min(cap - kept.len());
                    kept.extend_from_slice(&buffer[..take]);
                }
            }
        }
    }
    (kept, total)
}

/// Appends one stream, saying how much of it was not shown.
fn push_stream(out: &mut String, kept: &[u8], total: u64, cap: usize) {
    out.push_str(&String::from_utf8_lossy(kept));
    if total > cap as u64 {
        out.push_str(&format!(
            "\n… [{} more bytes not shown; rerun with a narrower command] …\n",
            total - cap as u64
        ));
    } else {
        out.push('\n');
    }
}

/// Shrinks a large tool result so it is cheap to send again.
///
/// A truncation marker says what was dropped: a model that knows its output was
/// clipped can ask for the rest, whereas one handed a silent truncation assumes
/// that was all of it.
///
/// The marker is counted *against* `limit` rather than added on top of it. Every
/// caller here treats the limit as a ceiling - `Task::max_tool_output_bytes` is
/// documented as one - and a bound the marker can push past is not the bound
/// that was asked for.
pub fn compress(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let marker = |head: usize, tail: usize| {
        format!(
            "\n… [{} bytes elided; re-read the file or narrow the query] …\n",
            text.len().saturating_sub(head).saturating_sub(tail)
        )
    };
    // Reserve the longest possible marker before splitting the remaining
    // bytes. Keeping text can only reduce the elided count's digit width.
    let marker_bytes = marker(0, 0).len();
    if marker_bytes > limit {
        // A compact ASCII truncation notice fits any nonzero ceiling. Zero
        // explicitly requests no output, including no notice.
        if limit == 0 {
            return String::new();
        }
        let head = crate::head_bytes(text, limit - 1);
        let mut kept = String::with_capacity(head.len() + 1);
        kept.push_str(head);
        kept.push('~');
        return kept;
    }
    let budget = limit - marker_bytes;
    let head = crate::head_bytes(text, budget.saturating_mul(3) / 4).len();
    let tail = crate::tail_bytes(text, budget / 4).len();
    let text_marker = marker(head, tail);
    let mut kept = String::with_capacity(head + text_marker.len() + tail);
    kept.push_str(&text[..head]);
    kept.push_str(&text_marker);
    kept.push_str(&text[text.len() - tail..]);
    kept
}

/// A small glob matcher: `*` within a segment, `**` across segments.
///
/// Written out rather than pulled from a crate because matching a pattern
/// against a few hundred paths is not worth a dependency in something judged on
/// its binary size.
fn glob_match(pattern: &str, path: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').collect();
    let s: Vec<&str> = path.split('/').collect();
    match_segments(&p, &s)
}

fn match_segments(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.first() {
        None => path.is_empty(),
        Some(&"**") => {
            // `**` may consume any number of segments, including none.
            for index in 0..=path.len() {
                if match_segments(&pattern[1..], &path[index..]) {
                    return true;
                }
            }
            false
        }
        Some(segment) => match path.first() {
            None => false,
            Some(name) if segment == name => match_segments(&pattern[1..], &path[1..]),
            // A single `*` consumes exactly one segment: `src/*` must not match
            // `src/a/b.rs`. Only `**` crosses a separator.
            Some(name) => path.len() == 1 && wildcard(segment, name, false),
        },
    }
}

fn wildcard(pattern: &str, text: &str, _crosses: bool) -> bool {
    // A single star never matches a separator, so a path is matched whole.
    if text.contains('/') {
        return false;
    }
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return pattern == text;
    };
    if !text.starts_with(prefix) {
        return false;
    }
    let rest = &text[prefix.len()..];
    if suffix.is_empty() {
        return true;
    }
    if !rest.ends_with(suffix) {
        return false;
    }
    rest.len() >= suffix.len()
}

/// Most directories one `find` call will open.
///
/// The walk has to stay bounded even when nothing matches: `out` only grows on
/// a glob hit, so the caller's result limit cannot bound a walk that is
/// descending. This is the unconditional bound that does.
const MAX_WALK_DIRECTORIES: usize = 50_000;

fn walk(
    root: &Path,
    pattern: &str,
    limit: usize,
    max_directories: usize,
) -> Result<Vec<String>, HarnessError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut inspected = 0usize;
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".git" || name == "node_modules" || name == "target" {
                continue;
            }
            // `entry.file_type` reads the directory entry itself and does not
            // follow, where `Path::is_dir` resolves the link. A link that
            // points back into the tree (`loop -> .`) therefore produced
            // `root/loop`, `root/loop/loop`, ... with no visited set and no
            // depth cap, re-enumerating the same subtree once per path depth
            // the stack reached. A pattern matching nothing never grew `out`
            // at all, so it ignored `limit` entirely and stopped only once
            // `read_dir` hit the OS path-length bound; a pattern that did
            // match reported the same file once per depth reached. The damage
            // is to the worker process rather than to one sandbox, and the
            // repository this walks is attacker-supplied in the eval flow, so
            // the link is planted long before it is walked.
            //
            // A symlink to a file is still a file to a glob, so it is left to
            // match below; only descending through one is refused.
            if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                inspected += 1;
                // Reaching the cap is an error, not a short answer. Returning
                // the partial list would present it as the complete set of
                // matches, which is the one thing a `find` result cannot be:
                // the caller has no way to tell that the tree was bigger than
                // the bound and that something it asked for is missing. The
                // cap is not expected to fire - refusing to descend through a
                // symlink is what stops the loop - so when it does, the honest
                // answer is that the search did not finish.
                if inspected > max_directories {
                    return Err(HarnessError::Tool(format!(
                        "find stopped after {max_directories} directories: \
                         the tree is larger than this search will walk"
                    )));
                }
                stack.push(path);
                continue;
            }
            if path.is_dir() {
                continue;
            }
            if let Ok(relative) = path.strip_prefix(root) {
                let text = relative.to_string_lossy();
                if glob_match(pattern, &text) {
                    out.push(text.to_string());
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("aiec-tools-{label}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn glob_matching_handles_stars_and_greedy_segments() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(!glob_match("*.rs", "src/main.rs"));
        assert!(glob_match("src/**/*.rs", "src/a/b/main.rs"));
        assert!(glob_match("**/*.toml", "Cargo.toml"));
        assert!(glob_match("**/*.toml", "a/b/Cargo.toml"));
        assert!(glob_match("src/*", "src/main.rs"));
        assert!(!glob_match("src/*", "src/a/b.rs"));
    }

    /// A symlink pointing back at its own directory must not make `find`
    /// re-walk its own tree.
    ///
    /// The walk pushed a path whenever `Path::is_dir` resolved true, and
    /// `is_dir` follows links, so `loop -> .` produced `root/loop`,
    /// `root/loop/loop`, ... The result limit could not catch it: `out` only
    /// grows when a glob matches, so a pattern matching nothing kept
    /// descending until the kernel refused the too-long path, and a pattern
    /// that did match reported the same file once per depth reached. The
    /// damage is to the worker process rather than to one sandbox, and the
    /// repository this walks is attacker-supplied in the eval flow.
    ///
    /// The walk runs on its own thread and is waited for with a timeout, so a
    /// walk that never returns fails this assertion instead of hanging the
    /// suite.
    // The whole test is Unix-gated, not just the `symlink` call: without the
    // link there is no loop, the walk trivially terminates, and the test would
    // report this regression covered while asserting nothing about it.
    #[cfg(unix)]
    #[test]
    fn a_symlink_pointing_back_at_its_own_directory_terminates_the_find_walk() {
        let root = scratch("find-loop");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/keep.txt"), "keep").unwrap();
        std::os::unix::fs::symlink(&root, root.join("loop")).unwrap();

        // The walk runs on its own thread and is waited on with a timeout, so
        // the pre-fix behaviour is this assertion rather than a hung suite.
        let (tx, rx) = std::sync::mpsc::channel();
        let walked = std::thread::spawn({
            let root = root.clone();
            move || {
                let _ = tx.send(walk(&root, "**/*.missing", 10, MAX_WALK_DIRECTORIES));
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(30))
            .expect("the walk over a self-referential symlink must terminate")
            .expect("walk");
        walked.join().expect("walker thread");

        // Refusing to descend through a link is not the same as refusing to
        // walk: the files that are really there are still found.
        let found = walk(&root, "**/keep.txt", 10, MAX_WALK_DIRECTORIES).expect("walk");
        assert_eq!(found, vec!["nested/keep.txt".to_owned()]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A tree larger than the directory bound must say so, not answer with the
    /// part of it that was searched.
    ///
    /// Returning the partial list is the one answer a `find` result cannot
    /// give: the caller cannot tell it apart from a complete search, so a file
    /// they asked for and did not get looks like a file that does not exist.
    /// The bound exists so a walk terminates on a hostile tree; when it fires,
    /// the search genuinely did not finish and the error is the true result.
    #[test]
    fn a_tree_larger_than_the_directory_bound_is_an_error_not_a_short_list() {
        let root = scratch("find-cap");
        for index in 0..8 {
            let directory = root.join(format!("d{index}"));
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("hit.txt"), "hit").unwrap();
        }

        let refused = walk(&root, "**/hit.txt", 100, 3)
            .expect_err("a bounded walk must not pass a partial list off as complete");
        assert!(
            refused.to_string().contains("3 directories"),
            "the error must state the bound that stopped it: {refused}"
        );

        // Under the bound the same tree answers completely.
        let found = walk(&root, "**/hit.txt", 100, 8).expect("walk");
        assert_eq!(found.len(), 8, "a tree inside the bound is searched fully");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compression_keeps_both_ends_and_says_what_was_dropped() {
        let text = "a".repeat(1000) + "TAIL";
        let squeezed = compress(&text, 200);
        assert!(squeezed.len() < text.len());
        assert!(squeezed.contains("TAIL"), "the end must survive");
        assert!(squeezed.contains("elided"), "the drop must be visible");
    }

    /// A string of `n` ASCII bytes, then a three-byte character, then a tail, so
    /// that a byte limit of `n + 1` lands inside that character.
    fn straddling(n: usize) -> String {
        let mut text = String::new();
        while text.len() < n {
            text.push('a');
        }
        text.push('€');
        text.push_str("tail");
        text
    }

    #[test]
    fn clipping_a_limit_inside_a_character_does_not_panic() {
        // The limit is a byte count and the text is UTF-8, so a limit that lands
        // mid-character is the normal case for any non-ASCII output, not an
        // edge case. Slicing there used to abort the whole harness, losing the
        // run's result document with it.
        let text = straddling(8000);
        let clipped = crate::clip(&text, 8001);
        assert!(clipped.ends_with('…'));
        assert!(!clipped.is_empty());
    }

    #[test]
    fn compression_survives_a_boundary_inside_a_character() {
        let limit = 8000;
        let head = limit * 3 / 4;
        // Long enough past the limit to be compressed at all, with the
        // character straddling the byte the head is cut at.
        let text = format!("{}{}", straddling(head - 1), "b".repeat(limit));
        let squeezed = compress(&text, limit);
        assert!(squeezed.contains("elided"), "the drop must be visible");
        assert!(squeezed.ends_with('b'), "the end must survive");
    }

    #[test]
    fn a_read_truncated_mid_character_does_not_panic() {
        let root = scratch("read-utf8");
        // `read` prefixes every line with its number and a tab, so the file's
        // first byte lands two bytes into the rendered output. The character
        // goes where the truncation actually cuts.
        let mut content = String::new();
        while content.len() < crate::DEFAULT_READ_BYTES - 3 {
            content.push('a');
        }
        content.push('€');
        content.push_str("tail\n");
        std::fs::write(root.join("big.txt"), &content).unwrap();
        let out = read(&root, &serde_json::json!({"path": "big.txt"})).unwrap();
        assert!(out.contains("truncated"), "the cut must be visible");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_short_result_is_untouched() {
        assert_eq!(compress("short", 100), "short");
    }

    #[test]
    fn compression_honors_even_a_sub_marker_byte_ceiling() {
        for text in ["a".repeat(1000), "🦀".repeat(1000)] {
            for limit in 0..=128 {
                let rendered = compress(&text, limit);
                assert!(
                    rendered.len() <= limit,
                    "limit {limit} produced {} bytes: {rendered:?}",
                    rendered.len()
                );
                if limit > 0 {
                    assert!(
                        rendered.contains("elided") || rendered.ends_with('~'),
                        "truncation must remain visible at limit {limit}: {rendered:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn paths_cannot_escape_the_repository() {
        let root = scratch("escape");
        std::fs::create_dir_all(root.join("inside")).unwrap();
        assert!(resolve(&root, "inside/file.rs").is_ok());
        let escape = resolve(&root, "../outside").unwrap_err();
        assert!(escape.to_string().contains("outside"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_absolute_path_is_refused_rather_than_taken_as_given() {
        // Every path schema says "relative to the repository root", and the
        // whole point of `resolve` is that the model does not get to write
        // wherever it guessed. An absolute path used to be returned untouched,
        // so `/etc/cron.d/x` or `/root/.ssh/authorized_keys` reached straight
        // through every file tool.
        let root = scratch("absolute");
        for outside in ["/etc/hostname", "/root/.ssh/authorized_keys", "/tmp"] {
            let failure = resolve(&root, outside);
            assert!(
                matches!(&failure, Err(error) if error
                    .to_string()
                    .contains("relative to the repository root")),
                "{outside} resolved to {:?}, which is outside {root:?}",
                failure.map(|path| path.display().to_string())
            );
        }
        assert!(
            resolve(&root, "inside/file.rs").is_ok(),
            "relative paths still work"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Refusing `..` and absolute paths is a rule about the *string*, and a
    /// repository can hold a symlink. `ln -s /etc link` makes `link/hostname` a
    /// perfectly relative path with no `..` anywhere in it whose bytes are
    /// `/etc/hostname`, so both the read tools and `write` walked straight out.
    #[test]
    fn a_link_out_of_the_repository_is_refused_rather_than_followed() {
        let root = scratch("symlink-out");
        // A directory outside the repository, standing in for /etc: the same
        // shape, without a failing test reaching into a real system directory.
        let outside_root = scratch("symlink-outside");
        std::fs::write(root.join("inside.txt"), "inside\n").unwrap();
        // The target has to hold a file, or `out/hostname` is simply a path
        // that does not exist and the walk would treat it as a new one.
        std::fs::write(outside_root.join("hostname"), "outside\n").unwrap();
        std::os::unix::fs::symlink(&outside_root, root.join("out")).expect("symlink out");

        for outside in ["out/hostname", "out"] {
            let failure = resolve(&root, outside);
            assert!(
                matches!(&failure, Err(error) if error
                    .to_string()
                    .contains("outside the repository")),
                "{outside} resolved to {:?}",
                failure.map(|path| path.display().to_string())
            );
        }
        // And it is the tools, not just the helper, that have to refuse.
        let read_error = read(&root, &serde_json::json!({"path": "out/hostname"}))
            .expect_err("a read through a link out of the repository must fail");
        assert!(read_error.to_string().contains("outside"), "{read_error}");
        let write_error = write(
            &root,
            &serde_json::json!({"path": "out/pwned", "content": "x"}),
        )
        .expect_err("a write through a link out of the repository must fail");
        assert!(write_error.to_string().contains("outside"), "{write_error}");
        assert!(
            !outside_root.join("pwned").exists(),
            "the write landed outside the repository anyway"
        );
        let _ = std::fs::remove_dir_all(&outside_root);

        // A link back inside is ordinary, and must keep working: refusing every
        // symlink would break every repository that has one.
        std::os::unix::fs::symlink(root.join("inside.txt"), root.join("link")).expect("symlink");
        let through = resolve(&root, "link").expect("a link inside the repository resolves");
        assert_eq!(
            std::fs::read_to_string(&through).unwrap(),
            "inside\n",
            "a link that stays inside is followed, not refused"
        );

        // Creating a file several directories deep still works: a component
        // that does not exist yet is not an escape.
        assert!(resolve(&root, "new/deeper/file.txt").is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Creating a file is the one case where the path legitimately does not
    /// exist yet, so the walk stops early and hands back a path. It has to hand
    /// back the right one: joining the missing tail to the repository root
    /// instead of to what was walked silently dropped the directories that do
    /// exist, so `src/deep/new.txt` landed in `src/`, or in neither.
    #[test]
    fn a_new_file_is_created_where_it_was_asked_for() {
        let root = scratch("new-file");
        std::fs::create_dir_all(root.join("src/deep")).unwrap();

        // The first component is missing entirely.
        assert!(
            write(
                &root,
                &serde_json::json!({"path": "brand/new.txt", "content": "a"})
            )
            .is_ok()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("brand/new.txt")).unwrap(),
            "a"
        );
        // Several levels are missing at once.
        assert!(
            write(
                &root,
                &serde_json::json!({"path": "one/two/three.txt", "content": "b"})
            )
            .is_ok()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("one/two/three.txt")).unwrap(),
            "b"
        );
        // The tail is missing but the head exists, which is the case a
        // root-relative join gets wrong: `new.txt` belongs in `src/deep`.
        assert!(
            write(
                &root,
                &serde_json::json!({"path": "src/deep/new.txt", "content": "c"})
            )
            .is_ok()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("src/deep/new.txt")).unwrap(),
            "c"
        );
        assert!(
            !root.join("src/new.txt").exists() && !root.join("new.txt").exists(),
            "the new file was written somewhere it was not asked for"
        );
        // Overwriting an existing file still finds it.
        assert!(
            write(
                &root,
                &serde_json::json!({"path": "src/deep/new.txt", "content": "d"})
            )
            .is_ok()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("src/deep/new.txt")).unwrap(),
            "d"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Opening a broken link for writing creates whatever it points at, so a
    /// link to nothing has to be refused rather than resolved to a guess.
    #[test]
    fn a_broken_link_is_refused_rather_than_created_through() {
        let root = scratch("symlink-dangling");
        std::os::unix::fs::symlink("/tmp/aiec-never-created", root.join("dangling"))
            .expect("symlink");
        let failure = resolve(&root, "dangling");
        assert!(
            matches!(&failure, Err(error) if error.to_string().contains("does not resolve")),
            "a dangling link resolved to {:?}",
            failure.map(|path| path.display().to_string())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_ambiguous_edit_is_refused_rather_than_guessed() {
        let root = scratch("edit");
        let file = root.join("dup.rs");
        std::fs::write(&file, "let x = 1;\nlet x = 1;\n").unwrap();
        let args = serde_json::json!({"path": "dup.rs", "old": "let x = 1;", "new": "let x = 2;"});
        let error = edit(&root, &args).unwrap_err();
        assert!(error.to_string().contains("appears 2 times"), "{error}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_missing_edit_target_explains_itself() {
        let root = scratch("edit-missing");
        std::fs::write(root.join("a.rs"), "fn main() {}\n").unwrap();
        let args = serde_json::json!({"path": "a.rs", "old": "nowhere", "new": "x"});
        let error = edit(&root, &args).unwrap_err();
        assert!(error.to_string().contains("does not appear"), "{error}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn read_numbers_lines_and_honours_offset() {
        let root = scratch("read");
        std::fs::write(root.join("lines.txt"), "one\ntwo\nthree\n").unwrap();
        let all = read(&root, &serde_json::json!({"path": "lines.txt"})).unwrap();
        assert!(all.contains("1\tone"));
        let tail = read(
            &root,
            &serde_json::json!({"path": "lines.txt", "offset": 2, "limit": 1}),
        )
        .unwrap();
        assert!(tail.contains("2\ttwo"));
        assert!(!tail.contains("three"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn the_model_actually_sees_what_the_command_printed() {
        let root = scratch("bash-visible");
        // A tool that returns an exit code and no output is not a shell. This
        // pins the property itself rather than the clipping: whatever else the
        // bounds become, what a command printed has to reach the model.
        let out = bash(
            &root,
            &serde_json::json!({"command": "echo to-stdout; echo to-stderr >&2; exit 3"}),
        )
        .await
        .unwrap();
        assert!(out.contains("exit=3"), "the exit code: {out}");
        assert!(out.contains("to-stdout"), "stdout must be visible: {out}");
        assert!(out.contains("to-stderr"), "stderr must be visible: {out}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_command_printing_without_end_is_bounded_and_says_so() {
        let root = scratch("bash-bound");
        // Twenty megabytes on a pipe. Collecting the whole thing first and
        // clipping afterwards is what this test exists to prevent: the model
        // gets a bounded string either way, but the harness's own memory does
        // not, and the elided count is what tells the model to narrow the
        // command rather than assume the output ended.
        let args = serde_json::json!({
            "command": "head -c 20000000 /dev/zero | tr '\\0' 'a'",
            "timeout_seconds": 60,
        });
        let out = bash(&root, &args).await.unwrap();
        assert!(
            out.len() < 20_000,
            "the result must be bounded: {}",
            out.len()
        );
        assert!(out.contains("not shown"), "the drop must be counted: {out}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_timed_out_command_leaves_nothing_running() {
        let root = scratch("bash-orphan");
        let pid_file = root.join("grandchild.pid");
        // The shell backgrounds a long sleep and then waits. Timing out kills
        // the shell; without killing the process group the sleep keeps running
        // in the sandbox for the rest of the run, holding CPU and, if the
        // command had opened one, a pipe the next command is waiting on.
        let args = serde_json::json!({
            "command": format!("sleep 120 & echo $! > {} ; sleep 120", pid_file.display()),
            "timeout_seconds": 1,
        });
        let out = bash(&root, &args).await.unwrap();
        assert!(out.contains("timed out"), "{out}");
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .expect("the shell should have recorded its child")
            .trim()
            .parse()
            .expect("a pid");
        // The kill lands asynchronously relative to the shell's exit, so this
        // polls briefly rather than asserting on the first look.
        let mut alive = true;
        for _ in 0..50 {
            alive = unsafe { libc::kill(pid, 0) } == 0;
            if !alive {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(!alive, "process {pid} outlived the tool call");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn tearing_down_a_command_kills_what_it_backgrounded() {
        let root = scratch("bash-teardown");
        let pid_file = root.join("bg.pid");
        // `bash` reaches this on the timeout arm and on a `wait` failure, and
        // the second one used to return without any teardown at all. Signalling
        // only the shell is enough to make the tool call look finished while
        // the sleep is still running: `start_kill` sends SIGKILL to one pid, so
        // the group kill is the only thing that reaches a backgrounded child.
        let mut child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "sleep 120 & echo $! > {} ; sleep 120",
                pid_file.display()
            ))
            .current_dir(&root)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .expect("spawning");
        let group = child.id().map(|pid| pid as i32);

        // Wait for the shell to record its child before tearing anything down,
        // or this asserts on a pid that was never written.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !pid_file.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .expect("the shell should have recorded its child")
            .trim()
            .parse()
            .expect("a pid");
        assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "the sleep should be up");

        kill_group(&mut child, group).await;

        let mut alive = true;
        for _ in 0..50 {
            alive = unsafe { libc::kill(pid, 0) } == 0;
            if !alive {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(!alive, "process {pid} outlived the teardown");
        let _ = std::fs::remove_dir_all(root);
    }
}
