//! `browser`: drive a local Chromium through chromedriver's WebDriver HTTP API.
//!
//! The harness itself holds no browser automation dependency: `reqwest` (already
//! present for the model wire) speaks HTTP to a `chromedriver` process the tool
//! starts on demand against the `chromium` binary in the GUI image. No CDP
//! websocket, no new crate.
//!
//! One process-global session survives across tool calls behind a mutex, which
//! is what makes multi-step flows (navigate, then click, then screenshot)
//! possible at all: a per-call session would lose every navigation the moment
//! the call returned. `run_calls` dispatches sequentially, so holding the mutex
//! across the call's HTTP is race-free. A session that fails its health probe
//! is shut down and recreated; a live one is never restarted.
//!
//! Navigation is confined to `http(s)` — `file://`, `data:`, and `javascript:`
//! are refused as tool errors, because the caller's secrets live in files next
//! to this process. Localhost targets are allowed: the sandbox's loopback is
//! the fixture server, not the outside world.

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::process::{Child, Command};

use super::read::Call;
use super::{Tool, ToolContext, ToolImage, ToolOutput, field, tool_error};
use crate::ToolFailure;
use crate::context::MAX_SCREENSHOT_BASE64;
use crate::model::ToolSpec;

/// chromedriver's default port. Fixed so two sequential turns cannot race on
/// discovery; concurrent sessions are out of scope for one tool call.
const DRIVER_PORT: u16 = 19514;

pub struct Browser;

impl Tool for Browser {
    fn name(&self) -> &'static str {
        "browser"
    }
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "browser".into(),
            description:
                "Drive a local Chromium via chromedriver (started on demand, session persists \
                          across calls). Actions: navigate, click, type, text, screenshot. \
                          Only http(s) URLs; file:// and javascript: are refused."
                    .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["navigate", "click", "type", "text", "screenshot"],
                    },
                    "url": {"type": "string", "description": "For navigate: http(s) URL."},
                    "selector": {"type": "string", "description": "CSS selector for click/type."},
                    "text": {"type": "string", "description": "For type: keys to send."},
                },
                "required": ["action"],
                "additionalProperties": false
            }),
        }
    }

    fn call<'a>(&'a self, args: &'a Value, ctx: &'a ToolContext) -> Call<'a> {
        Box::pin(Browser::run(args, ctx))
    }
}

static SESSION: tokio::sync::Mutex<Option<Session>> = tokio::sync::Mutex::const_new(None);

struct Session {
    driver: Child,
    client: reqwest::Client,
    session_id: String,
}

impl Session {
    async fn start() -> Result<Self, ToolFailure> {
        let chromium = which_chromium().ok_or_else(|| {
            tool_error(
                "browser",
                "no chromium binary on PATH (chromium or google-chrome); this sandbox has no GUI profile",
            )
        })?;
        let driver = Command::new("chromedriver")
            .arg(format!("--port={DRIVER_PORT}"))
            .arg("--allowed-ips=127.0.0.1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| tool_error("browser", format!("chromedriver would not start: {e}")))?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| tool_error("browser", format!("http client failed: {e}")))?;
        let base = format!("http://127.0.0.1:{DRIVER_PORT}");

        // chromedriver takes a moment to listen; poll briefly rather than
        // sleeping a fixed second that is wrong in both directions.
        let mut last = String::new();
        for _ in 0..50 {
            match client.get(format!("{base}/status")).send().await {
                Ok(r) if r.status().is_success() => break,
                Ok(r) => last = format!("status {}", r.status()),
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if client
            .get(format!("{base}/status"))
            .send()
            .await
            .map(|r| !r.status().is_success())
            .unwrap_or(true)
        {
            return Err(tool_error(
                "browser",
                format!("chromedriver never came up: {last}"),
            ));
        }
        // `driver` carries `kill_on_drop`, so every early return below still
        // reaps the child; only the stored session owns it afterwards.

        let body = json!({
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "chrome",
                    "goog:chromeOptions": {
                        "binary": chromium,
                        "args": ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
                    },
                },
            },
        });
        let created: Value = client
            .post(format!("{base}/session"))
            .json(&body)
            .send()
            .await
            .map_err(|e| tool_error("browser", format!("session creation failed: {e}")))?
            .json()
            .await
            .map_err(|e| tool_error("browser", format!("session body unreadable: {e}")))?;
        let session_id = created
            .pointer("/value/sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| tool_error("browser", "chromedriver returned no sessionId"))?
            .to_owned();
        Ok(Self {
            driver,
            client,
            session_id,
        })
    }

    /// A live tab answers `/title`; a driver whose Chromium died does not, and
    /// neither does a socket nobody listens on. Either way the caller recreates.
    async fn healthy(&self) -> bool {
        self.client
            .get(self.url("/title"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    fn url(&self, path: &str) -> String {
        format!(
            "http://127.0.0.1:{DRIVER_PORT}/session/{}{path}",
            self.session_id
        )
    }

    /// Best-effort teardown: the session DELETE frees the tab, and dropping
    /// the child with `kill_on_drop` reaps the driver. Failures are ignored
    /// because this only runs when the session is already dead or replaced.
    async fn shutdown(mut self) {
        let _ = self.client.delete(self.url("")).send().await;
        let _ = self.driver.kill().await;
    }
}

fn which_chromium() -> Option<String> {
    for candidate in ["chromium", "chromium-browser", "google-chrome"] {
        if let Ok(path) = which(candidate) {
            return Some(path);
        }
    }
    None
}

/// PATH lookup without a dependency: `which` the crate is not vendored and
/// shelling out to `which(1)` reintroduces the shell this tool avoids.
fn which(name: &str) -> Result<String, ()> {
    let path = std::env::var_os("PATH").ok_or(())?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(())
}

fn refuse_scheme(url: &str) -> Result<(), ToolFailure> {
    let lower = url.trim_start().to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Ok(());
    }
    Err(tool_error(
        "browser",
        "only http(s) URLs may be navigated; file:// and javascript: are refused",
    ))
}

impl Browser {
    async fn run(args: &Value, ctx: &ToolContext) -> Result<ToolOutput, ToolFailure> {
        if ctx.phase == super::Phase::Validation {
            return Err(tool_error(
                "browser",
                "browser use is refused during validation",
            ));
        }
        let action = field(args, "action")?;
        match action {
            "navigate" | "click" | "type" | "text" | "screenshot" => {}
            other => {
                return Err(tool_error(
                    "browser",
                    format!("unknown action `{other}`; navigate, click, type, text, screenshot"),
                ));
            }
        }
        // The mutex is held across the call's HTTP: dispatch is sequential, so
        // no other task is waiting on it, and holding it is what keeps two
        // interleaved calls from splitting one session.
        let mut guard = SESSION.lock().await;
        let live = match guard.as_ref() {
            Some(session) => session.healthy().await,
            None => false,
        };
        if !live {
            if let Some(dead) = guard.take() {
                dead.shutdown().await;
            }
            *guard = Some(Session::start().await?);
        }
        let session = guard.as_ref().expect("session just started");
        Self::drive(session, args, action).await
    }

    async fn drive(
        session: &Session,
        args: &Value,
        action: &str,
    ) -> Result<ToolOutput, ToolFailure> {
        match action {
            "navigate" => {
                let url = field(args, "url")?;
                refuse_scheme(url)?;
                let body: Value = session
                    .client
                    .post(session.url("/url"))
                    .json(&json!({ "url": url }))
                    .send()
                    .await
                    .map_err(|e| tool_error("browser", format!("navigate failed: {e}")))?
                    .json()
                    .await
                    .map_err(|e| tool_error("browser", format!("navigate body unreadable: {e}")))?;
                if body.pointer("/status").and_then(Value::as_u64).unwrap_or(1) != 0 {
                    return Err(tool_error(
                        "browser",
                        format!("chromium refused the navigation: {body}"),
                    ));
                }
                Ok(ToolOutput::text(format!("navigated to {url}")))
            }
            "click" => {
                let selector = field(args, "selector")?;
                let id = Self::element(session, selector).await?;
                let body: Value = session
                    .client
                    .post(session.url(&format!("/element/{id}/click")))
                    .json(&json!({}))
                    .send()
                    .await
                    .map_err(|e| tool_error("browser", format!("click failed: {e}")))?
                    .json()
                    .await
                    .map_err(|e| tool_error("browser", format!("click body unreadable: {e}")))?;
                if body.pointer("/status").and_then(Value::as_u64).unwrap_or(1) != 0 {
                    return Err(tool_error(
                        "browser",
                        format!("chromium refused the click: {body}"),
                    ));
                }
                Ok(ToolOutput::text(format!("clicked {selector}")))
            }
            "type" => {
                let selector = field(args, "selector")?;
                let text = field(args, "text")?;
                let id = Self::element(session, selector).await?;
                // WebDriver `/value` appends, so the field is cleared first:
                // otherwise a retry types the same keys twice.
                let _ = session
                    .client
                    .post(session.url(&format!("/element/{id}/clear")))
                    .json(&json!({}))
                    .send()
                    .await;
                let body: Value = session
                    .client
                    .post(session.url(&format!("/element/{id}/value")))
                    .json(&json!({ "text": text }))
                    .send()
                    .await
                    .map_err(|e| tool_error("browser", format!("type failed: {e}")))?
                    .json()
                    .await
                    .map_err(|e| tool_error("browser", format!("type body unreadable: {e}")))?;
                if body.pointer("/status").and_then(Value::as_u64).unwrap_or(1) != 0 {
                    return Err(tool_error(
                        "browser",
                        format!("chromium refused the keys: {body}"),
                    ));
                }
                Ok(ToolOutput::text(format!(
                    "typed {} chars into {selector}",
                    text.len()
                )))
            }
            "text" => {
                let body: Value = session
                    .client
                    .get(session.url("/source"))
                    .send()
                    .await
                    .map_err(|e| tool_error("browser", format!("page source failed: {e}")))?
                    .json()
                    .await
                    .map_err(|e| tool_error("browser", format!("page source unreadable: {e}")))?;
                let html = body
                    .pointer("/value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| tool_error("browser", "chromedriver returned no page source"))?;
                Ok(ToolOutput::text(strip_tags(html)))
            }
            // WebDriver screenshots are PNG, always: there is no quality dial
            // on this endpoint, so the only honest bound is the context cap.
            "screenshot" => {
                let (data, bytes) = Self::shot(session).await?;
                let image = ToolImage::new("image/png", data).expect("png is always allowed");
                Ok(ToolOutput::sized(
                    format!("screenshot taken ({bytes} bytes of PNG)"),
                    bytes as u64,
                )
                .with_images(vec![image]))
            }
            _ => unreachable!("action validated above"),
        }
    }

    async fn element(session: &Session, selector: &str) -> Result<String, ToolFailure> {
        let body: Value = session
            .client
            .post(session.url("/element"))
            .json(&json!({ "using": "css selector", "value": selector }))
            .send()
            .await
            .map_err(|e| tool_error("browser", format!("element lookup failed: {e}")))?
            .json()
            .await
            .map_err(|e| tool_error("browser", format!("element body unreadable: {e}")))?;
        // W3C wraps the id in an opaque element-6066 key; legacy used ELEMENT.
        // Either way the id is a string inside the value object.
        let value = body
            .pointer("/value")
            .and_then(Value::as_object)
            .ok_or_else(|| tool_error("browser", format!("no element matches `{selector}`")))?;
        let id = value
            .get("ELEMENT")
            .and_then(Value::as_str)
            .or_else(|| value.values().find_map(Value::as_str))
            .ok_or_else(|| tool_error("browser", format!("no element matches `{selector}`")))?;
        Ok(id.to_owned())
    }

    /// One attempt, one refusal. WebDriver has no quality or width dial on
    /// this endpoint — the bytes are what Chromium rendered — so oversize is
    /// a tool error naming the cap, and the loop backstop stays the second
    /// line of defence for a tool that forgot to check.
    async fn shot(session: &Session) -> Result<(String, usize), ToolFailure> {
        let body: Value = session
            .client
            .get(session.url("/screenshot"))
            .send()
            .await
            .map_err(|e| tool_error("browser", format!("screenshot failed: {e}")))?
            .json()
            .await
            .map_err(|e| tool_error("browser", format!("screenshot body unreadable: {e}")))?;
        let png = body
            .pointer("/value")
            .and_then(Value::as_str)
            .ok_or_else(|| tool_error("browser", "chromedriver returned no screenshot"))?
            .to_owned();
        if png.len() > MAX_SCREENSHOT_BASE64 {
            return Err(tool_error(
                "browser",
                format!(
                    "screenshot is {} bytes, over the {} cap; navigate somewhere smaller",
                    png.len(),
                    MAX_SCREENSHOT_BASE64
                ),
            ));
        }
        let bytes = png.len();
        Ok((png, bytes))
    }
}

/// Visible text without a parser dependency: tags are cut, entities for the
/// five common escapes are decoded, runs collapse. Enough for "what does this
/// page say", not a DOM.
fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len().min(32 * 1024));
    let mut in_tag = false;
    let mut in_script = false;
    let mut chars = html.chars().peekable();
    while let Some(c) = chars.next() {
        if in_tag {
            if c == '>' {
                in_tag = false;
            }
            continue;
        }
        if c == '<' {
            let rest: String = chars.clone().take(7).collect();
            let lower = rest.to_ascii_lowercase();
            if lower.starts_with("script") {
                in_script = true;
            } else if lower.starts_with("/script") {
                in_script = false;
                // Skip to the closing `>`.
                for c in chars.by_ref() {
                    if c == '>' {
                        break;
                    }
                }
                continue;
            }
            in_tag = true;
            continue;
        }
        if !in_script {
            out.push(c);
        }
    }
    out.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
