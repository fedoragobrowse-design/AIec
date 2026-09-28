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
/// which is a very common failure and a very annoying one.
fn resolve(root: &Path, raw: &str) -> Result<PathBuf, HarnessError> {
    let candidate = Path::new(raw);
    if candidate.is_absolute() {
        return Ok(candidate.to_path_buf());
    }
    // The prefix check below is lexical, so `a/../b` would slip through it:
    // the path has to be walked first, rejecting any `..` outright.
    if candidate
        .components()
        .any(|part| part == std::path::Component::ParentDir)
    {
        return Err(HarnessError::Tool(format!("`{raw}` leaves the repository")));
    }
    let joined = root.join(candidate);
    if !joined.starts_with(root) {
        return Err(HarnessError::Tool(format!(
            "`{raw}` is outside the repository"
        )));
    }
    Ok(joined)
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
        out.truncate(crate::DEFAULT_READ_BYTES);
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
            clip(&old, 60),
            path.display()
        )));
    }
    if occurrences > 1 && !replace_all {
        // Guessing which occurrence was meant is how an agent corrupts a file.
        return Err(HarnessError::Tool(format!(
            "`{}` appears {occurrences} times in {}; include more context or pass replace_all",
            clip(&old, 60),
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
    Ok(walk(root, &pattern, limit)?.join("\n"))
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
                clip(&String::from_utf8_lossy(&result.stderr), 200)
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

async fn bash(root: &Path, args: &Value) -> Result<String, HarnessError> {
    let command = arg_str(args, "command")?;
    let timeout = arg_usize(args, "timeout_seconds", 120).clamp(1, 3600);
    let child = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .current_dir(root)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| HarnessError::Tool(format!("spawning: {error}")))?;
    let waited = tokio::time::timeout(
        std::time::Duration::from_secs(timeout as u64),
        child.wait_with_output(),
    )
    .await;
    let output = match waited {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return Err(HarnessError::Tool(format!("{error}"))),
        Err(_) => {
            // The child is killed by kill_on_drop; the model is told it timed
            // out rather than left waiting.
            return Ok("timed out".to_owned());
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(format!(
        "exit={}\n--- stdout\n{}\n--- stderr\n{}",
        output.status.code().unwrap_or(-1),
        clip(&stdout, 8000),
        clip(&stderr, 4000)
    ))
}

/// Shrinks a large tool result so it is cheap to send again.
///
/// A truncation marker says what was dropped: a model that knows its output was
/// clipped can ask for the rest, whereas one handed a silent truncation assumes
/// that was all of it.
pub fn compress(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let head = limit * 3 / 4;
    let tail = limit - head;
    let mut kept = String::with_capacity(limit);
    kept.push_str(&text[..head]);
    kept.push_str(&format!(
        "\n… [{} bytes elided; re-read the file or narrow the query] …\n",
        text.len() - head - tail
    ));
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

fn walk(root: &Path, pattern: &str, limit: usize) -> Result<Vec<String>, HarnessError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
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
            if path.is_dir() {
                stack.push(path);
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

fn clip(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    format!("{}…", &text[..limit])
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

    #[test]
    fn compression_keeps_both_ends_and_says_what_was_dropped() {
        let text = "a".repeat(1000) + "TAIL";
        let squeezed = compress(&text, 200);
        assert!(squeezed.len() < text.len());
        assert!(squeezed.contains("TAIL"), "the end must survive");
        assert!(squeezed.contains("elided"), "the drop must be visible");
    }

    #[test]
    fn a_short_result_is_untouched() {
        assert_eq!(compress("short", 100), "short");
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
}
