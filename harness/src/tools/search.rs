//! `grep`, `find`, `glob`: the three ways of asking a repository a question.
//!
//! All of them walk the tree, which is the one operation in this harness that
//! is not obviously bounded. A repository is not a tidy directory: it has a
//! million files, a `target/` with a hundred thousand more, and one file that
//! is four gigabytes of base64. So the walk has a budget of entries it may
//! visit, the three tools cap how much they will report, and every cap that
//! bites says so in the output — an answer that silently stops halfway is
//! worse than no answer, because the model cannot tell the difference.

use globset::{GlobBuilder, GlobMatcher};
use regex::Regex;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

use super::read::{Call, clamp, display_path, looks_binary};
use super::{Tool, ToolContext, ToolOutput, field, field_or, resolve, tool_error};
use crate::ToolFailure;
use crate::model::ToolSpec;

/// Directories no one wants listed and no one wants searched.
const SKIP_DIRS: [&str; 3] = [".git", "node_modules", "target"];
/// Directory entries one call may visit before it gives up on the whole tree.
const MAX_ENTRIES: usize = 200_000;
/// How deep the walk will go. A symlink is never followed, so this is about
/// pathological depth rather than loops.
const MAX_DEPTH: usize = 64;
/// Bytes read from any one file when searching it.
const SCAN_CAP: usize = 256 * 1024;
/// Matches one `grep` call reports.
const MAX_MATCHES: usize = 200;
/// Files one `grep` call reports matches from.
const MAX_MATCH_FILES: usize = 200;
/// Matches one file may contribute, so one generated file cannot eat the cap.
const MAX_MATCHES_PER_FILE: usize = 50;
/// Names one `find` or `glob` call reports.
const MAX_NAMES: usize = 500;

pub struct Grep;
pub struct Find;
pub struct Glob;

// ---------------------------------------------------------------- grep

impl Tool for Grep {
    fn name(&self) -> &'static str {
        "grep"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "grep".into(),
            description: "Search file contents with a regular expression. Returns \
                          `path:line:text`. Skips .git, node_modules, and target."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Rust/PCRE-style regular expression."
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory to search, relative to the workspace root (default .)."
                    },
                    "glob": {
                        "type": "string",
                        "description": "Only search files matching this glob, e.g. `*.rs` or `src/**`."
                    }
                },
                "required": ["pattern"],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Grep::run(args, ctx))
    }
}

impl Grep {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        let pattern = field(args, "pattern")?;
        let regex = Regex::new(pattern)
            .map_err(|e| tool_error("pattern", format!("`{pattern}` is not a valid regex: {e}")))?;
        let start = start_dir(args, ctx)?;
        let filter = match field_or(args, "glob", "") {
            "" => None,
            glob => Some(compile_glob(glob)?),
        };

        let walk = walk(&ctx.root, &start);
        let mut hits: Vec<(String, usize, String)> = Vec::new();
        let mut files_with_hits = 0usize;
        let mut scanned = 0usize;
        let mut scanned_bytes = 0usize;
        let mut skipped_binary = 0usize;
        let mut per_file_dropped = 0usize;
        let mut stopped = walk.truncated;

        'outer: for entry in &walk.files {
            if let Some(m) = &filter
                && !m.is_match(&entry.rel)
                && !m.is_match(&entry.name)
            {
                continue;
            }
            scanned += 1;
            let bytes = match read_capped(&entry.path, SCAN_CAP).await {
                Ok(b) => b,
                Err(_) => continue,
            };
            scanned_bytes += bytes.len();
            if looks_binary(&bytes) {
                skipped_binary += 1;
                continue;
            }
            // The scan cap can cut a large file mid-character. Dropping the
            // whole file for that would report "no matches" for a file full of
            // them, so the partial tail becomes U+FFFD and the rest is searched.
            let text = String::from_utf8_lossy(&bytes);

            let mut in_this_file = 0usize;
            for (i, line) in text.lines().enumerate() {
                if !regex.is_match(line) {
                    continue;
                }
                if in_this_file >= MAX_MATCHES_PER_FILE {
                    per_file_dropped += 1;
                    continue;
                }
                if hits.len() >= MAX_MATCHES || files_with_hits >= MAX_MATCH_FILES {
                    stopped = true;
                    break 'outer;
                }
                hits.push((entry.rel.clone(), i + 1, line.trim_end().to_owned()));
                in_this_file += 1;
            }
            if in_this_file > 0 {
                files_with_hits += 1;
            }
        }

        hits.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        let mut out = String::new();
        for (rel, line, text) in &hits {
            out.push_str(&format!("{rel}:{line}:{text}\n"));
        }
        out.insert_str(
            0,
            &format!(
                "{} match{} in {files_with_hits} file{}; scanned {scanned} file{} under {}\n",
                hits.len(),
                plural(hits.len()),
                plural(files_with_hits),
                plural(scanned),
                display_path(&ctx.root, &start)
            ),
        );
        let mut notes: Vec<String> = Vec::new();
        if stopped {
            notes.push(format!(
                "search stopped early; narrow it with `path` or `glob` ({} entries visited)",
                walk.entries_seen
            ));
        }
        if per_file_dropped > 0 {
            notes.push(format!(
                "{per_file_dropped} further match(es) in the same file(s) not shown"
            ));
        }
        if skipped_binary > 0 {
            notes.push(format!(
                "{skipped_binary} file(s) skipped as binary or not utf-8"
            ));
        }
        push_notes(&mut out, &notes);

        Ok(ToolOutput::sized(
            clamp(out, ctx.limits.max_tool_output_bytes),
            scanned_bytes as u64,
        ))
    }
}

// ---------------------------------------------------------------- find

impl Tool for Find {
    fn name(&self) -> &'static str {
        "find"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "find".into(),
            description:
                "List file paths under a directory, optionally filtered by a name (substring, \
                          or a glob if it contains * ? [). Skips .git, node_modules, and target."
                    .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Case-insensitive substring, or a glob such as `*.toml`."
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory to list, relative to the workspace root (default .)."
                    }
                },
                "required": [],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Find::run(args, ctx))
    }
}

impl Find {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        let name = field_or(args, "name", "");
        let start = start_dir(args, ctx)?;
        let walk = walk(&ctx.root, &start);
        let matcher = name_matcher(name)?;

        let mut shown = 0usize;
        let mut matched = 0usize;
        let mut out = String::new();
        for entry in &walk.files {
            if !name_matches(&matcher, entry) {
                continue;
            }
            matched += 1;
            if shown < MAX_NAMES {
                out.push_str(&entry.rel);
                out.push('\n');
                shown += 1;
            }
        }
        out.insert_str(
            0,
            &format!(
                "{matched} file{} under {}{}\n",
                plural(matched),
                display_path(&ctx.root, &start),
                if name.is_empty() {
                    String::new()
                } else {
                    format!(" matching {name}")
                }
            ),
        );
        let mut notes = Vec::new();
        if matched > shown {
            notes.push(format!(
                "{}-more matching files not listed; narrow with `path` or `name`",
                matched - shown
            ));
        }
        if walk.truncated {
            notes.push(format!(
                "stopped after {} directory entries; narrow with `path`",
                walk.entries_seen
            ));
        }
        push_notes(&mut out, &notes);

        Ok(ToolOutput::sized(
            clamp(out, ctx.limits.max_tool_output_bytes),
            matched as u64,
        ))
    }
}

// ---------------------------------------------------------------- glob

impl Tool for Glob {
    fn name(&self) -> &'static str {
        "glob"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "glob".into(),
            description: "List paths matching a glob (`**` crosses directories, `*` does not). \
                          Skips .git, node_modules, and target."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob such as `src/**/*.rs` or `**/Cargo.toml`."
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory to match under, relative to the workspace root (default .)."
                    }
                },
                "required": ["pattern"],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Glob::run(args, ctx))
    }
}

impl Glob {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        let pattern = field(args, "pattern")?;
        let matcher = compile_glob(pattern)?;
        let start = start_dir(args, ctx)?;
        let walk = walk(&ctx.root, &start);

        let mut shown = 0usize;
        let mut matched = 0usize;
        let mut out = String::new();
        for entry in &walk.files {
            if !matcher.is_match(&entry.rel) {
                continue;
            }
            matched += 1;
            if shown < MAX_NAMES {
                out.push_str(&entry.rel);
                out.push('\n');
                shown += 1;
            }
        }
        out.insert_str(
            0,
            &format!(
                "{matched} path{} under {} matching {pattern}\n",
                plural(matched),
                display_path(&ctx.root, &start)
            ),
        );
        let mut notes = Vec::new();
        if matched > shown {
            notes.push(format!(
                "{}-more matches not listed; narrow the pattern or `path`",
                matched - shown
            ));
        }
        if walk.truncated {
            notes.push(format!(
                "stopped after {} directory entries; narrow with `path`",
                walk.entries_seen
            ));
        }
        push_notes(&mut out, &notes);

        Ok(ToolOutput::sized(
            clamp(out, ctx.limits.max_tool_output_bytes),
            matched as u64,
        ))
    }
}

// ---------------------------------------------------------------- shared

struct Entry {
    path: PathBuf,
    rel: String,
    name: String,
}

struct Walked {
    files: Vec<Entry>,
    entries_seen: usize,
    truncated: bool,
}

/// Resolves the optional `path` argument to a directory inside the workspace.
fn start_dir(args: &Value, ctx: &ToolContext) -> Result<PathBuf, ToolFailure> {
    let raw = field_or(args, "path", ".");
    let path = resolve(&ctx.root, raw)?;
    if !path.is_dir() {
        return Err(tool_error(
            "path",
            format!("{} is not a directory", path.display()),
        ));
    }
    Ok(path)
}

/// `literal_separator` is the difference between `src/*.rs` meaning "the
/// sources directly in src" and "every rust file in the tree". Models mean
/// the first one, and `**` is how they ask for the second.
fn compile_glob(pattern: &str) -> Result<GlobMatcher, ToolFailure> {
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map_err(|e| tool_error("glob", format!("{pattern}: {e}")))?;
    Ok(glob.compile_matcher())
}

fn is_globish(name: &str) -> bool {
    name.contains(['*', '?', '['])
}

/// A substring match, or a glob when the name looks like one. Case
/// insensitive either way: a model asking for `Cargo.toml` has found it.
enum NameFilter {
    All,
    Substring(String),
    Glob(GlobMatcher),
}

fn name_matcher(name: &str) -> Result<NameFilter, ToolFailure> {
    if name.is_empty() {
        Ok(NameFilter::All)
    } else if is_globish(name) {
        Ok(NameFilter::Glob(compile_glob(name)?))
    } else {
        Ok(NameFilter::Substring(name.to_lowercase()))
    }
}

fn name_matches(filter: &NameFilter, entry: &Entry) -> bool {
    match filter {
        NameFilter::All => true,
        NameFilter::Substring(needle) => entry.name.to_lowercase().contains(needle),
        // A bare `*.rs` should find `src/a.rs`, and `*` is told not to cross a
        // separator, so the bare file name is matched as well as the path.
        NameFilter::Glob(m) => m.is_match(&entry.rel) || m.is_match(&entry.name),
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn push_notes(out: &mut String, notes: &[String]) {
    for note in notes {
        out.push_str(&format!("[truncated: {note}]\n"));
    }
}

/// Walks `start` without following symlinks, bounded in entries, depth, and
/// by refusing to leave the workspace through one.
fn walk(root: &Path, start: &Path) -> Walked {
    let mut files = Vec::new();
    let mut entries_seen = 0usize;
    let mut truncated = false;

    if !start.is_dir() {
        return Walked {
            files,
            entries_seen,
            truncated,
        };
    }

    let mut stack: Vec<(PathBuf, String, usize)> = vec![(start.to_path_buf(), String::new(), 0)];

    'walk: while let Some((dir, prefix, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            truncated = true;
            continue;
        }
        let Ok(reader) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in reader {
            if entries_seen >= MAX_ENTRIES {
                truncated = true;
                break 'walk;
            }
            let Ok(entry) = entry else { continue };
            entries_seen += 1;

            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "." || name == ".." {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let path = entry.path();

            // A link is never followed into another directory: that is both a
            // loop risk and a way out of the workspace.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                match std::fs::metadata(&path) {
                    Ok(target) if target.is_dir() => continue,
                    Ok(_) => {
                        if super::read::canonical_inside(root, &path).is_err() {
                            continue;
                        }
                    }
                    Err(_) => continue,
                }
            }
            if meta.is_dir() {
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                stack.push((path, rel, depth + 1));
                continue;
            }

            files.push(Entry { path, rel, name });
        }
    }

    // Sorted so two identical queries produce identical output.
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Walked {
        files,
        entries_seen,
        truncated,
    }
}

/// Reads at most `cap` bytes from a file, without ever loading the rest.
async fn read_capped(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await?;
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    let mut limited = file.take(cap as u64);
    limited.read_to_end(&mut buf).await?;
    Ok(buf)
}
