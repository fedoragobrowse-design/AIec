//! `read`: one file, one window, numbered.
//!
//! Numbering is the whole point. `edit` takes line numbers, so a read that
//! returns a bare blob makes the model count lines in its head, and a model
//! that counts badly rewrites the wrong three lines of a five thousand line
//! file. Everything here serves that: numbering, a header that says how much of
//! the file is on screen, and a footer that says how to get the rest.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tokio::io::AsyncReadExt;

use super::{
    Tool, ToolContext, ToolOutput, field, field_usize, resolve, tool_error, truncation_note,
};
use crate::ToolFailure;
use crate::model::ToolSpec;

/// The most bytes taken off disk in one call, whatever the caller's limit says.
/// `max_tool_output_bytes` is a request; a four gigabyte file is a fact.
pub(crate) const HARD_BYTE_CAP: usize = 512 * 1024;
/// Lines returned when the model does not say.
const DEFAULT_LINES: usize = 2_000;
/// The most lines any single call may ask for, however it asks.
const MAX_LINES: usize = 20_000;
/// How much of the head is sniffed for a NUL byte before calling a file binary.
pub(crate) const BINARY_SNIFF: usize = 8_192;
/// The largest file `edit` will load into memory to rewrite a few lines.
pub(crate) const MAX_EDIT_BYTES: u64 = 8 * 1024 * 1024;

/// The boxed future the object-safe `Tool` trait returns. Every tool in this
/// module implements `call` as `Box::pin(Self::run(..))` and keeps its body in
/// an ordinary `async fn`.
pub(crate) type Call<'a> = std::pin::Pin<
    Box<dyn Future<Output = std::result::Result<ToolOutput, ToolFailure>> + Send + 'a>,
>;

pub struct Read;

impl Tool for Read {
    fn name(&self) -> &'static str {
        "read"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "read".into(),
            description: "Read a file in the workspace. Returns 1-based numbered lines plus a \
                          header saying how large the file is."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path relative to the workspace root."
                    },
                    "offset": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "0-based index of the first line to return. Displayed line numbers are 1-based."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Maximum number of lines to return (default 2000)."
                    }
                },
                "required": ["path"],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Read::run(args, ctx))
    }
}

impl Read {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        let raw = field(args, "path")?;
        let joined = resolve(&ctx.root, raw)?;
        // `resolve` checks the text; this checks what the text points at, which
        // is the half a model can otherwise walk straight through with a symlink.
        let path = canonical_inside(&ctx.root, &joined)?;
        let rel = display_path(&ctx.root, &path);

        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| tool_error("path", format!("{rel}: {e}")))?;
        if meta.is_dir() {
            return Err(tool_error(
                "path",
                format!("{rel} is a directory; use find or glob"),
            ));
        }
        let file_len = meta.len();

        let offset = field_usize(args, "offset", 0);
        let limit = field_usize(args, "limit", DEFAULT_LINES).clamp(1, MAX_LINES);
        let ceiling = ctx.limits.max_tool_output_bytes;
        let cap = ceiling.min(HARD_BYTE_CAP);

        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|e| tool_error("path", format!("{rel}: {e}")))?;
        let mut buf = Vec::with_capacity(cap.min(64 * 1024));
        let read = file
            .take(cap as u64)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| tool_error("path", format!("{rel}: {e}")))?;

        if let Some(nul) = buf.iter().position(|&b| b == 0)
            && nul < BINARY_SNIFF
        {
            return Ok(ToolOutput::sized(
                format!(
                    "{rel} is binary: NUL byte at offset {nul} of {file_len} bytes. Its text is \
                     not line oriented, so it was not read; use bash (`head -c 4096 {rel} | xxd`) \
                     if you need to look at it."
                ),
                read as u64,
            ));
        }
        let body = match std::str::from_utf8(&buf) {
            Ok(s) => Cow::Borrowed(s),
            Err(e) if e.error_len().is_none() => {
                // The read stopped mid-character rather than the file being bad.
                Cow::Borrowed(std::str::from_utf8(&buf[..e.valid_up_to()]).unwrap_or(""))
            }
            Err(e) => {
                return Ok(ToolOutput::sized(
                    format!(
                        "{rel} is not valid utf-8 (first bad byte at offset {}, file is {file_len} \
                         bytes), so it was not read; use bash (`head -c 4096 {rel} | xxd`) if you need \
                         to look at it.",
                        e.valid_up_to()
                    ),
                    read as u64,
                ));
            }
        };

        let total = body.lines().count();
        let mut out = String::with_capacity(cap.min(16 * 1024));
        let mut shown = 0usize;
        let mut last = 0usize;
        // The header and the truncation notes are the part that tells the model
        // the file is bigger than what it is holding, so room is kept for them
        // rather than spent on the last line of the window.
        let reserve = 320.min(ceiling / 2);
        let line_budget = ceiling.saturating_sub(reserve);
        for line in body.lines().skip(offset).take(limit) {
            if out.len() + line.len() + 16 > line_budget {
                break;
            }
            out.push_str(&format!("{:>6}\t{}\n", offset + shown + 1, line));
            shown += 1;
            last = offset + shown;
        }

        let whole = (read as u64) == file_len;
        let first = if shown == 0 { 0 } else { offset + 1 };
        // A partial read cannot know the file's line count, and saying it can
        // would be a lie the model then reasons from.
        let header = if whole {
            format!("{rel}: {total} lines, {file_len} bytes; showing lines {first}-{last}\n")
        } else {
            format!(
                "{rel}: {file_len} bytes on disk; read the first {read} bytes \
                 ({total} line{}), showing lines {first}-{last}\n",
                plural(total)
            )
        };
        out.insert_str(0, &header);

        let mut notes: Vec<String> = Vec::new();
        if last < total || !whole {
            notes.push(format!("more lines not shown; re-read with offset={last}"));
        }
        if !whole {
            notes.push(format!(
                "{}-more bytes not read (read cap {read} bytes)",
                file_len - read as u64
            ));
        }
        for note in &notes {
            out.push_str(&format!("[truncated: {note}]\n"));
        }

        Ok(ToolOutput::sized(clamp(out, ceiling), read as u64))
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The canonical path, refused if it lands outside the workspace.
///
/// A prefix comparison on strings is not enough and is not what this does:
/// `root.join("link").canonicalize()` may resolve anywhere, so the resolved
/// path is what gets compared, component by component, against the root.
pub(crate) fn canonical_inside(root: &Path, path: &Path) -> Result<PathBuf, ToolFailure> {
    let resolved = path
        .canonicalize()
        .map_err(|e| tool_error("path", format!("{}: {e}", path.display())))?;
    let base = match root.canonicalize() {
        Ok(p) => p,
        Err(_) => root.to_path_buf(),
    };
    if !resolved.starts_with(&base) {
        return Err(tool_error(
            "path",
            format!(
                "{} resolves to {}, which is outside the workspace",
                path.display(),
                resolved.display()
            ),
        ));
    }
    Ok(resolved)
}

/// The nearest existing ancestor of `path`, canonicalised and checked. For a
/// file about to be created, whose parent may not exist yet.
pub(crate) fn parent_inside(root: &Path, path: &Path) -> Result<PathBuf, ToolFailure> {
    let base = match root.canonicalize() {
        Ok(p) => p,
        Err(_) => root.to_path_buf(),
    };
    let parent = path.parent().ok_or_else(|| {
        tool_error(
            "path",
            format!("{} has no parent directory", path.display()),
        )
    })?;
    let resolved = parent
        .canonicalize()
        .map_err(|e| tool_error("path", format!("{}: {e}", parent.display())))?;
    if !resolved.starts_with(&base) {
        return Err(tool_error(
            "path",
            format!(
                "{} resolves to {}, which is outside the workspace",
                parent.display(),
                resolved.display()
            ),
        ));
    }
    Ok(resolved)
}

/// The path as the model should see it: workspace relative, never absolute.
pub(crate) fn display_path(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => ".".to_owned(),
        Ok(rel) => rel.to_string_lossy().into_owned(),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

/// Forces a rendered message under the caller's ceiling, with a marker naming
/// what was dropped, and never cuts a character in half.
pub(crate) fn clamp(mut content: String, ceiling: usize) -> String {
    if content.len() <= ceiling {
        return content;
    }
    let note = truncation_note(ceiling);
    let keep = ceiling.saturating_sub(note.len());
    let mut end = keep;
    while end > 0 && !content.is_char_boundary(end) {
        end -= 1;
    }
    content.truncate(end);
    content.push_str(&note);
    content
}

/// The same rule for anything that is not utf-8 text, used by `grep`.
pub(crate) fn looks_binary(sample: &[u8]) -> bool {
    let window = &sample[..sample.len().min(BINARY_SNIFF)];
    window.contains(&0)
}
