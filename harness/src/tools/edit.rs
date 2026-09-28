//! `edit`: replace a line range, not a file.
//!
//! This is the tool the whole harness is shaped around. A model that has to
//! resend a five thousand line file to change three of them will eventually
//! truncate it, and a truncated file is a failed task with a plausible-looking
//! diff. So the unit of work here is a range of 1-based line numbers, the
//! surrounding text is read from disk rather than from the model, and every
//! way the range can be wrong is refused rather than guessed at.

use serde_json::{Value, json};

use super::read::{Call, MAX_EDIT_BYTES, canonical_inside, clamp, display_path, looks_binary};
use super::{Tool, ToolContext, ToolOutput, field, field_usize, tool_error};
use crate::ToolFailure;
use crate::model::ToolSpec;

/// Replacement lines echoed back, so the model can check the edit landed
/// without reading the file back.
const PREVIEW_LINES: usize = 10;

pub struct Edit;

impl Tool for Edit {
    fn name(&self) -> &'static str {
        "edit"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "edit".into(),
            description: "Replace a 1-based inclusive line range of a file. `content` empty deletes \
                          the range; `start` > `end` inserts before `start` without deleting anything."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path relative to the workspace root."
                    },
                    "start": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "First line to replace, 1-based, as numbered by read."
                    },
                    "end": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Last line to replace, inclusive (defaults to start)."
                    },
                    "content": {
                        "type": "string",
                        "description": "Replacement text. Empty string deletes the range."
                    }
                },
                "required": ["path", "start", "content"],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Edit::run(args, ctx))
    }
}

impl Edit {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        let raw = field(args, "path")?;
        let content = field(args, "content")?;
        if args.get("start").and_then(Value::as_u64).is_none() {
            return Err(tool_error(
                "start",
                "`start` is required and must be a 1-based line number",
            ));
        }
        let start = field_usize(args, "start", 0);
        let end = field_usize(args, "end", start);

        let joined = super::resolve(&ctx.root, raw)?;
        // Resolving the target is what refuses a symlink that leaves the
        // workspace, before a single byte is read or written.
        let path = canonical_inside(&ctx.root, &joined)?;
        let rel = display_path(&ctx.root, &path);

        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| tool_error("path", format!("{rel}: {e}")))?;
        if meta.is_dir() {
            return Err(tool_error("path", format!("{rel} is a directory")));
        }
        if meta.len() > MAX_EDIT_BYTES {
            return Err(tool_error(
                "path",
                format!(
                    "{rel} is {} bytes, over the {MAX_EDIT_BYTES}-byte limit for a line edit; \
                     edit a smaller file or use write",
                    meta.len()
                ),
            ));
        }

        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(|e| tool_error("path", format!("{rel}: {e}")))?;
        let mut bytes = Vec::with_capacity(meta.len() as usize + 1);
        tokio::io::AsyncReadExt::read_to_end(&mut file, &mut bytes)
            .await
            .map_err(|e| tool_error("path", format!("{rel}: {e}")))?;

        if looks_binary(&bytes) {
            return Err(tool_error(
                "path",
                format!("{rel} is binary; a line range means nothing in it"),
            ));
        }
        let text = String::from_utf8(bytes).map_err(|e| {
            tool_error(
                "path",
                format!(
                    "{rel} is not valid utf-8 (first bad byte at offset {}); a line edit would \
                     corrupt it",
                    e.utf8_error().valid_up_to()
                ),
            )
        })?;

        // `split_inclusive` rather than `lines`: whether the file ended with a
        // newline is a fact about the file, and reserialising must not change it.
        let segments: Vec<&str> = text.split_inclusive('\n').collect();
        let line_count = segments.len();

        if start == 0 {
            return Err(tool_error(
                "start",
                "line numbers are 1-based; `start` must be >= 1",
            ));
        }

        let (prefix, suffix, removed) = if start > end {
            // Insert: the gap [end, start) contains nothing, so the text goes
            // in before line `start`.
            if start > line_count + 1 {
                return Err(tool_error(
                    "start",
                    format!(
                        "cannot insert at line {start}: {rel} has {line_count} line{}",
                        plural(line_count)
                    ),
                ));
            }
            let at = start - 1;
            (&segments[..at], &segments[at..], 0usize)
        } else {
            if end > line_count {
                return Err(tool_error(
                    "end",
                    format!(
                        "line range {start}-{end} is past the end of {rel}, which has {line_count} \
                         line{}",
                        plural(line_count)
                    ),
                ));
            }
            (&segments[..start - 1], &segments[end..], end - start + 1)
        };

        let mut result = String::with_capacity(text.len() + content.len());
        for part in prefix {
            result.push_str(part);
        }
        if !content.is_empty() {
            result.push_str(content);
            // The replacement has to be terminated or it will run into the line
            // that follows it; and if the file ended with a newline, it still
            // should.
            let needs_newline = !suffix.is_empty() || text.ends_with('\n');
            if needs_newline && !content.ends_with('\n') {
                result.push('\n');
            }
        }
        for part in suffix {
            result.push_str(part);
        }

        tokio::fs::write(&path, result.as_bytes())
            .await
            .map_err(|e| tool_error("edit", format!("{rel}: {e}")))?;

        let new_lines = result.split_inclusive('\n').count();
        let added = content.lines().count();
        let verb = if !content.is_empty() {
            format!(
                "replaced line{} {start}-{end} with {added} line{}",
                plural(removed),
                plural(added)
            )
        } else if removed == 0 {
            // An insert of nothing: say so rather than "deleted lines 3-2".
            format!("inserted nothing before line {start}; no lines changed")
        } else {
            format!(
                "deleted line{} {}-{}",
                plural(removed),
                start,
                start + removed - 1
            )
        };

        let mut out = format!(
            "{rel}: {verb}; now {new_lines} line{}, {} bytes\n",
            plural(new_lines),
            result.len()
        );
        for (i, line) in content.lines().take(PREVIEW_LINES).enumerate() {
            out.push_str(&format!("{:>6}\t{}\n", start + i, line));
        }
        if added > PREVIEW_LINES {
            out.push_str(&format!(
                "[preview shows {PREVIEW_LINES} of {added} replacement lines]\n"
            ));
        }
        Ok(ToolOutput::sized(
            clamp(out, ctx.limits.max_tool_output_bytes),
            result.len() as u64,
        ))
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}
