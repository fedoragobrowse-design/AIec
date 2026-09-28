//! `write`: create or replace one file.
//!
//! Whole-file by design, and the only tool that is: `edit` is the one for
//! changing three lines of a large file without resending it. What this has to
//! get right is containment, because a path that is safe as text can still be
//! a symlink pointing at `/etc`, and because `create_dir_all` will happily
//! build a whole directory tree through one.

use std::path::Path;

use serde_json::{Value, json};

use super::read::{Call, canonical_inside, display_path, parent_inside};
use super::{Tool, ToolContext, ToolOutput, field, resolve, tool_error};
use crate::ToolFailure;
use crate::model::ToolSpec;

pub struct Write;

impl Tool for Write {
    fn name(&self) -> &'static str {
        "write"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "write".into(),
            description: "Create or overwrite a file with `content`, creating parent directories. \
                          To change part of an existing file use edit, which does not resend it."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path relative to the workspace root."
                    },
                    "content": {
                        "type": "string",
                        "description": "The complete new contents of the file."
                    }
                },
                "required": ["path", "content"],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Write::run(args, ctx))
    }
}

impl Write {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        let raw = field(args, "path")?;
        let content = field(args, "content")?;
        let joined = resolve(&ctx.root, raw)?;
        let rel = display_path(&ctx.root, &joined);

        // Check the deepest directory that already exists before creating
        // anything: if a component is a symlink out of the workspace,
        // `create_dir_all` would write through it.
        nearest_existing_inside(&ctx.root, &joined)?;

        let Some(parent) = joined.parent() else {
            return Err(tool_error("path", format!("{rel} has no parent directory")));
        };
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| tool_error("path", format!("{rel}: {e}")))?;

        // Re-checked after creation, and the file is written through the
        // resolved parent rather than the textual one.
        let real_parent = parent_inside(&ctx.root, &joined)?;
        let name = joined
            .file_name()
            .ok_or_else(|| tool_error("path", format!("{rel} is not a file path")))?;
        let target = real_parent.join(name);

        match tokio::fs::symlink_metadata(&target).await {
            Ok(meta) if meta.is_dir() => {
                return Err(tool_error("path", format!("{rel} is a directory")));
            }
            Ok(_) => {
                // Exists: a link is fine only if it stays inside.
                canonical_inside(&ctx.root, &target)?;
            }
            Err(_) => {}
        }

        let existed = target.exists();
        tokio::fs::write(&target, content.as_bytes())
            .await
            .map_err(|e| tool_error("write", format!("{rel}: {e}")))?;

        let lines = content.lines().count();
        let verb = if existed { "overwrote" } else { "wrote" };
        Ok(ToolOutput::sized(
            format!(
                "{verb} {rel}: {} bytes, {lines} line{}",
                content.len(),
                if lines == 1 { "" } else { "s" }
            ),
            content.len() as u64,
        ))
    }
}

/// The nearest existing ancestor directory of `path`, canonicalised and
/// required to be inside the workspace.
fn nearest_existing_inside(root: &Path, path: &Path) -> Result<(), ToolFailure> {
    let base = match root.canonicalize() {
        Ok(p) => p,
        Err(_) => root.to_path_buf(),
    };
    let mut cursor: Option<&Path> = path.parent();
    while let Some(dir) = cursor {
        if let Ok(real) = dir.canonicalize() {
            if !real.starts_with(&base) {
                return Err(tool_error(
                    "path",
                    format!(
                        "{} resolves to {}, which is outside the workspace",
                        dir.display(),
                        real.display()
                    ),
                ));
            }
            return Ok(());
        }
        cursor = dir.parent();
    }
    Ok(())
}
