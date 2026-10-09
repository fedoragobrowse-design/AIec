//! Tools: the whole set the model can reach, and the boundary that keeps it
//! inside the repository.
//!
//! Nine text tools always, plus two GUI tools when the guest can back them:
//! usefulness per token of schema is still the selection criterion, and a
//! schema for a binary that is not installed is pure waste.

pub mod bash;
pub mod browser;
pub mod desktop;
pub mod edit;
pub mod git;
pub mod read;
pub mod search;
pub mod write;

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;

use crate::ToolFailure;
use crate::model::ToolCall;

/// One screenshot, base64-encoded. Kept beside the text it accompanies rather
/// than inside it: base64 must never pass through `compress_output`, which
/// would corrupt the bytes, so images ride in their own field end to end.
#[derive(Debug, Clone, Default)]
pub struct ToolImage {
    /// Only `image/png` or `image/jpeg`; anything else is refused at
    /// construction because a provider wire format has no third shape.
    pub media_type: &'static str,
    pub data_base64: String,
}

impl ToolImage {
    pub fn new(media_type: &'static str, data_base64: String) -> Option<Self> {
        match media_type {
            "image/png" | "image/jpeg" => Some(Self {
                media_type,
                data_base64,
            }),
            _ => None,
        }
    }
}

/// What a tool hands back to the loop.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    /// What the model sees. Always bounded.
    pub content: String,
    /// Bytes the tool actually moved, for the metrics in the result.
    pub bytes: u64,
    /// Screenshots the model sees. Never compressed: truncating base64
    /// corrupts the image, so the size cap is enforced as a refusal instead.
    pub images: Vec<ToolImage>,
}

impl ToolOutput {
    pub fn text(content: impl Into<String>) -> Self {
        let content = content.into();
        Self {
            bytes: content.len() as u64,
            content,
            images: Vec::new(),
        }
    }

    pub fn sized(content: impl Into<String>, bytes: u64) -> Self {
        Self {
            content: content.into(),
            bytes,
            images: Vec::new(),
        }
    }

    /// Attaches screenshots. A tool returning more than the cap is a tool
    /// error at the call site, not a silent crop here: this only records.
    pub fn with_images(mut self, images: Vec<ToolImage>) -> Self {
        self.images = images;
        self
    }
}

/// One tool. Tools never fail the session: an error is an observation the model
/// should see and react to, which is why the return type is a failure value
/// rather than a `Result`.
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    fn spec(&self) -> crate::model::ToolSpec;
    /// Boxed rather than `async fn` so the trait stays object safe: the
    /// registry holds `Box<dyn Tool>`, so a new tool is a new file and not a
    /// change here.
    fn call<'a>(
        &'a self,
        args: &'a Value,
        ctx: &'a ToolContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<ToolOutput, ToolFailure>>
                + Send
                + 'a,
        >,
    >;
}

/// Everything a tool is allowed to know about the world.
pub struct ToolContext {
    /// Canonicalised once. Every path is resolved against this and checked.
    pub root: PathBuf,
    pub limits: crate::task::Limits,
    /// Set by the loop so a tool can refuse to act during validation.
    pub phase: Phase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Working,
    Validation,
}

/// A name, so a model can be told what exists without a second round trip.
pub fn list_tools() -> Vec<&'static str> {
    vec![
        "read",
        "write",
        "edit",
        "grep",
        "find",
        "glob",
        "bash",
        "git_status",
        "git_diff",
    ]
}

/// Resolves a model-supplied path against the workspace root.
///
/// This is the harness's most important line of defence. `root.join("../x")`
/// still textually starts with `root`, so a prefix comparison would pass and
/// the read would escape; instead every component is resolved and any parent
/// reference or absolute path is refused.
pub fn resolve(root: &Path, raw: &str) -> std::result::Result<PathBuf, ToolFailure> {
    if raw.is_empty() {
        return Err(ToolFailure {
            name: "path".into(),
            message: "path is empty".into(),
        });
    }
    // A NUL byte truncates the path in every syscall that takes one, which
    // would make a validated path a different path.
    if raw.contains('\0') {
        return Err(ToolFailure {
            name: "path".into(),
            message: "path contains a null byte".into(),
        });
    }

    let candidate = Path::new(raw);
    if candidate.is_absolute() {
        return Err(ToolFailure {
            name: "path".into(),
            message: format!("`{raw}` is absolute; paths are relative to the workspace"),
        });
    }

    let mut resolved = root.to_path_buf();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            // Parent references and roots are refused outright rather than
            // normalised, so a path cannot leave and re-enter.
            Component::ParentDir => {
                return Err(ToolFailure {
                    name: "path".into(),
                    message: format!("`{raw}` leaves the workspace"),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ToolFailure {
                    name: "path".into(),
                    message: format!("`{raw}` is not a workspace-relative path"),
                });
            }
        }
    }
    Ok(resolved)
}

/// The dispatcher's front door: everything a model sends is checked here before
/// any tool sees it.
pub struct Registry {
    tools: Vec<Box<dyn Tool>>,
    by_name: std::collections::HashMap<String, usize>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            tools: Vec::new(),
            by_name: std::collections::HashMap::new(),
        }
    }

    pub fn register(&mut self, tool: Box<dyn Tool>) {
        let name = tool.name().to_owned();
        self.by_name.insert(name, self.tools.len());
        self.tools.push(tool);
    }

    pub fn specs(&self) -> Vec<crate::model::ToolSpec> {
        self.tools.iter().map(|t| t.spec()).collect()
    }

    pub async fn dispatch(
        &self,
        call: &ToolCall,
        ctx: &ToolContext,
    ) -> std::result::Result<ToolOutput, ToolFailure> {
        let Some(&index) = self.by_name.get(&call.name) else {
            let mut names: Vec<&str> = self.by_name.keys().map(String::as_str).collect();
            names.sort_unstable();
            return Err(ToolFailure {
                name: call.name.clone(),
                message: format!("no such tool; available: {}", names.join(", ")),
            });
        };

        // Arguments are the model's. `[]` and `42` are valid JSON, and letting
        // them through turns a confused model into a confusing "missing field".
        let args: Value = serde_json::from_str(&call.arguments).map_err(|e| ToolFailure {
            name: call.name.clone(),
            message: format!("arguments are not json: {e}"),
        })?;
        if !args.is_object() {
            return Err(ToolFailure {
                name: call.name.clone(),
                message: "arguments must be a json object".into(),
            });
        }

        self.tools[index].call(&args, ctx).await
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads a required string field.
pub fn field<'a>(args: &'a Value, name: &str) -> std::result::Result<&'a str, ToolFailure> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ToolFailure {
            name: name.to_owned(),
            message: format!("`{name}` is required and must be a string"),
        })
}

/// Reads an optional field with a default.
pub fn field_or<'a>(args: &'a Value, name: &str, default: &'a str) -> &'a str {
    args.get(name).and_then(Value::as_str).unwrap_or(default)
}

/// Reads an optional non-negative integer, refusing negatives rather than
/// wrapping them into an enormous allocation.
pub fn field_usize(args: &Value, name: &str, default: usize) -> usize {
    match args.get(name) {
        Some(Value::Number(n)) => n.as_u64().map(|v| v as usize).unwrap_or(default),
        Some(Value::String(s)) => s.parse().unwrap_or(default),
        _ => default,
    }
}

/// The full set, wired up. GUI tools join only when the guest has the
/// binaries to back them: a schema for a missing binary wastes context and
/// invites a call that can only fail.
pub fn registry() -> Registry {
    registry_for(crate::task::GuiMode::Off)
}

/// What the guest can actually back, probed from PATH. `chromedriver` plus a
/// chromium binary means `browser`; Xvfb plus xdotool means `desktop`.
pub fn gui_available() -> GuiAvail {
    GuiAvail {
        browser: has_bin("chromedriver") && has_chromium(),
        desktop: has_bin("Xvfb") && has_bin("xdotool"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuiAvail {
    pub browser: bool,
    pub desktop: bool,
}

fn has_bin(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| has_bin_on(&path, name))
}

/// The PATH-parameterized core of [`has_bin`]: pure over its inputs, so tests
/// pin the registration matrix against fixture PATHs without mutating the
/// process environment out from under sibling threads.
fn has_bin_on(path: &std::ffi::OsStr, name: &str) -> bool {
    std::env::split_paths(path).any(|dir| dir.join(name).is_file())
}

fn has_chromium() -> bool {
    ["chromium", "chromium-browser", "google-chrome"]
        .iter()
        .any(|n| has_bin(n))
}

fn has_chromium_on(path: &std::ffi::OsStr) -> bool {
    ["chromium", "chromium-browser", "google-chrome"]
        .iter()
        .any(|n| has_bin_on(path, n))
}

pub fn registry_for(mode: crate::task::GuiMode) -> Registry {
    let mut r = Registry::new();
    r.register(Box::new(read::Read));
    r.register(Box::new(write::Write));
    r.register(Box::new(edit::Edit));
    r.register(Box::new(search::Grep));
    r.register(Box::new(search::Find));
    r.register(Box::new(search::Glob));
    r.register(Box::new(bash::Bash));
    r.register(Box::new(git::Status));
    r.register(Box::new(git::Diff));
    let avail = gui_available();
    register_gui(r, mode, avail)
}

/// The `PATH`-parameterized core of [`registry_for`]: same policy, fixture
/// PATH instead of the process one. The live path stays a two-liner so the
/// policy cannot drift between production and test.
pub fn registry_for_on(mode: crate::task::GuiMode, path: &std::ffi::OsStr) -> Registry {
    let mut r = Registry::new();
    r.register(Box::new(read::Read));
    r.register(Box::new(write::Write));
    r.register(Box::new(edit::Edit));
    r.register(Box::new(search::Grep));
    r.register(Box::new(search::Find));
    r.register(Box::new(search::Glob));
    r.register(Box::new(bash::Bash));
    r.register(Box::new(git::Status));
    r.register(Box::new(git::Diff));
    let avail = GuiAvail {
        browser: has_bin_on(path, "chromedriver") && has_chromium_on(path),
        desktop: has_bin_on(path, "Xvfb") && has_bin_on(path, "xdotool"),
    };
    register_gui(r, mode, avail)
}

fn register_gui(mut r: Registry, mode: crate::task::GuiMode, avail: GuiAvail) -> Registry {
    // Playwright tasks drive the page through `bash` (python + playwright),
    // which needs no harness tool — but screenshots still go through
    // `browser`, so it registers there too.
    if avail.browser && mode != crate::task::GuiMode::Off {
        r.register(Box::new(browser::Browser));
    }
    if avail.desktop && mode == crate::task::GuiMode::Desktop {
        r.register(Box::new(desktop::Desktop));
    }
    r
}

/// Shared, so the alias stays a single type.
pub type SharedRegistry = Arc<Registry>;

/// A convenience for tools that need to report a size cap as plain text.
pub(crate) fn truncation_note(limit: usize) -> String {
    format!("\n[truncated to {limit} bytes]")
}

/// Kept so `HarnessError` stays reachable from tool modules that convert.
pub(crate) fn tool_error(name: &str, message: impl Into<String>) -> ToolFailure {
    ToolFailure {
        name: name.to_owned(),
        message: message.into(),
    }
}
