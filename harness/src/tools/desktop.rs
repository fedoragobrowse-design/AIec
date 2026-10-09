//! `desktop`: keyboard, mouse, and screen inside the guest's X display.
//!
//! The guest runs Xvfb on `:99` (desktop image profile); this tool shells the
//! standard utilities — `xdotool` for input, `scrot` (falling back to
//! `import` from ImageMagick) for pixels — with `std::process::Command`, the
//! same pattern `bash.rs` uses. No new dependency: the harness binary stays
//! static musl and every pixel moves through files, not a framebuffer socket.
//!
//! Coordinates are absolute display pixels. The tool refuses to run without a
//! `DISPLAY` in its environment and refuses to act during validation, for the
//! same reason `browser` does: a validation turn that moves a mouse proves
//! nothing about the task.

use std::process::Stdio;

use serde_json::{Value, json};
use tokio::process::Command;

use super::read::Call;
use super::{Tool, ToolContext, ToolImage, ToolOutput, field, field_usize, tool_error};
use crate::ToolFailure;
use crate::context::MAX_SCREENSHOT_BASE64;
use crate::model::ToolSpec;

pub struct Desktop;

impl Tool for Desktop {
    fn name(&self) -> &'static str {
        "desktop"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "desktop".into(),
            description: "Keyboard, mouse, and screen on the guest X display (Xvfb :99 in desktop \
                          images). Actions: key, click, move, type, screenshot. Coordinates are \
                          absolute display pixels."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["key", "click", "move", "type", "screenshot"],
                    },
                    "keys": {"type": "string", "description": "For key: xdotool key sequence, e.g. \"ctrl+l\"."},
                    "x": {"type": "integer", "minimum": 0},
                    "y": {"type": "integer", "minimum": 0},
                    "button": {"type": "integer", "minimum": 1, "maximum": 3},
                    "text": {"type": "string", "description": "For type: text to type."},
                },
                "required": ["action"],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Desktop::run(args, ctx))
    }
}

impl Desktop {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        if ctx.phase == super::Phase::Validation {
            return Err(tool_error(
                "desktop",
                "desktop use is refused during validation",
            ));
        }
        let display = std::env::var("DISPLAY").map_err(|_| {
            tool_error(
                "desktop",
                "no DISPLAY in the environment; this sandbox has no desktop profile",
            )
        })?;
        let action = field(args, "action")?;
        match action {
            "key" => {
                let keys = field(args, "keys")?;
                // One sequence, no shell: xdotool parses `+`-separated keys
                // itself, so `;` and `$()` stay literal arguments.
                let out = run_xdotool(&["key", keys]).await?;
                Ok(ToolOutput::text(format!("pressed {keys}: {}", out.trim())))
            }
            "click" => {
                let x = field_usize(args, "x", usize::MAX);
                let y = field_usize(args, "y", usize::MAX);
                if x == usize::MAX || y == usize::MAX {
                    return Err(tool_error("desktop", "`x` and `y` are required for click"));
                }
                let button = field_usize(args, "button", 1).clamp(1, 3).to_string();
                run_xdotool(&["mousemove", &x.to_string(), &y.to_string()]).await?;
                let out = run_xdotool(&["click", &button]).await?;
                Ok(ToolOutput::text(format!(
                    "clicked {x},{y} button {button}: {}",
                    out.trim()
                )))
            }
            "move" => {
                let x = field_usize(args, "x", usize::MAX);
                let y = field_usize(args, "y", usize::MAX);
                if x == usize::MAX || y == usize::MAX {
                    return Err(tool_error("desktop", "`x` and `y` are required for move"));
                }
                run_xdotool(&["mousemove", &x.to_string(), &y.to_string()]).await?;
                Ok(ToolOutput::text(format!("moved to {x},{y} on {display}")))
            }
            "type" => {
                let text = field(args, "text")?;
                if text.len() > 4096 {
                    return Err(tool_error(
                        "desktop",
                        "text is capped at 4096 chars per call",
                    ));
                }
                let out = run_xdotool(&["type", "--", text]).await?;
                Ok(ToolOutput::text(format!(
                    "typed {} chars: {}",
                    text.len(),
                    out.trim()
                )))
            }
            "screenshot" => Self::shot().await,
            other => Err(tool_error(
                "desktop",
                format!("unknown action `{other}`; key, click, move, type, screenshot"),
            )),
        }
    }

    async fn shot() -> Result<ToolOutput, ToolFailure> {
        // scrot first, ImageMagick import second: the desktop image ships
        // scrot, but a hand-built guest may only have one of the two.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("aiec-shot-{}.png", std::process::id()));
        let tried = match run_capture(&path, &["scrot", "--silent"]).await {
            Ok(()) => None,
            Err(first) => match run_capture(&path, &["import", "-window", "root"]).await {
                Ok(()) => None,
                Err(_) => Some(first),
            },
        };
        if let Some(message) = tried {
            return Err(tool_error(
                "desktop",
                format!("no screenshot utility worked: {message}"),
            ));
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| tool_error("desktop", format!("screenshot unreadable: {e}")))?;
        let _ = std::fs::remove_file(&path);
        // PNG magic, not an extension: a zero-byte or HTML error page from a
        // confused capture utility is refused before it reaches the model.
        if bytes.len() < 8 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" {
            return Err(tool_error(
                "desktop",
                "capture produced no PNG; the X display may be empty",
            ));
        }
        let encoded = base64_encode(&bytes);
        if encoded.len() > MAX_SCREENSHOT_BASE64 {
            return Err(tool_error(
                "desktop",
                format!(
                    "screenshot is {} bytes, over the {} cap; the display is larger than the model can see",
                    encoded.len(),
                    MAX_SCREENSHOT_BASE64
                ),
            ));
        }
        let len = bytes.len();
        let image = ToolImage::new("image/png", encoded).expect("png is always allowed");
        Ok(
            ToolOutput::sized(format!("screenshot taken ({len} bytes of PNG)"), len as u64)
                .with_images(vec![image]),
        )
    }
}

async fn run_xdotool(args: &[&str]) -> Result<String, ToolFailure> {
    let child = Command::new("xdotool")
        .args(args)
        .stdin(Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| tool_error("desktop", format!("xdotool would not start: {e}")))?;
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| tool_error("desktop", format!("xdotool failed: {e}")))?;
    if !output.status.success() {
        return Err(tool_error(
            "desktop",
            format!(
                "xdotool refused: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn run_capture(path: &std::path::Path, argv: &[&str]) -> Result<(), String> {
    let (program, rest) = argv.split_first().expect("capture argv is never empty");
    let mut full: Vec<std::ffi::OsString> = rest.iter().map(|s| s.into()).collect();
    full.push(path.into());
    Command::new(program)
        .args(&full)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| e.to_string())
        .and_then(|status| {
            if status.success() && path.is_file() {
                Ok(())
            } else {
                Err(format!("{program} exited {status}"))
            }
        })
}

/// Base64 without a crate: the standard alphabet, `=` padding, nothing else.
/// Screenshots are the only user, and pulling a dependency for 30 lines would
/// grow every guest harness build for one tool.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (chunk.get(1).copied().unwrap_or(0) as u32) << 8
            | (chunk.get(2).copied().unwrap_or(0) as u32);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
