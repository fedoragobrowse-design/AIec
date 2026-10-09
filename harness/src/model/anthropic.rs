//! The Anthropic Messages API.
//!
//! Structurally the harder of the two wire formats, and the differences are
//! not cosmetic. The system prompt travels out of band rather than as the first
//! message. A turn's content is an array of typed blocks, so text and tool
//! calls interleave in one reply and one assistant turn. A tool result is a
//! `user` message holding a `tool_result` block, which means consecutive tool
//! results have to be merged or the API refuses the request. And a tool call's
//! arguments are a JSON object here, where the neutral shape carries the raw
//! text the model produced — so they are parsed on the way out and
//! re-serialized on the way back in.
//!
//! The client is owned by the session. See `openai` for the reasoning behind
//! that; it is the same reasoning and the same constraint.

use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::HarnessError;
use crate::model::{
    Capabilities, Completion, Message, ModelConfig, ModelProvider, Response, Stop, ToolCall,
    ToolSpec, Usage,
};

/// The boxed future `ModelProvider::complete` returns. Written out once here
/// because the trait is dyn compatible: a provider has to be usable behind a
/// `Box<dyn ModelProvider>`, and a bare `async fn` in a trait is not.
type BoxFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = std::result::Result<T, HarnessError>> + Send + 'a>>;

/// A reply is JSON and nothing else; anything larger is a server that has lost
/// the plot, and reading it would be a memory problem rather than a useful
/// answer. 32 MiB is far past any real completion (roughly eight million tokens).
const MAX_BODY: usize = 32 * 1024 * 1024;

/// Error bodies are only ever quoted into an error message, so a small cap keeps
/// a hostile endpoint from making us buffer a gigabyte to say "400".
const MAX_ERROR_BODY: usize = 8 * 1024;

/// Longest provider text quoted back into an error.
const MAX_QUOTE: usize = 400;

/// The version this file speaks. Pinned rather than tracked: a moving version
/// header would make the same harness binary mean different things on different
/// days.
const API_VERSION: &str = "2023-06-01";

/// How often we try, and how long we are willing to wait between tries.
///
/// Retried because a model endpoint on a shared network fails for reasons that
/// have nothing to do with the agent, and a sandbox is disposable, so a retry
/// costs a second rather than the whole run. Not retried forever, because a
/// session that spends its budget sleeping is a session that never answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    /// Ceiling on the sum of every backoff in one `complete`, so the retry
    /// budget is bounded even if each individual sleep is legal.
    pub max_total_delay: Duration,
    /// Ceiling on a delay the SERVER asked for via `Retry-After`, kept
    /// separate from `max_total_delay` for the same reason as the
    /// OpenAI-compatible backend: a provider's own number about its own state
    /// should not be clipped to the budget for delays we chose ourselves.
    pub max_retry_after: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 4,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(8),
            max_total_delay: Duration::from_secs(20),
            max_retry_after: Duration::from_secs(30),
        }
    }
}

/// Builds a client for callers that do not want to reach for one themselves.
/// The session normally uses `crate::model::http_client`, which is the same
/// thing; this exists so a provider can be built in one call from anywhere.
pub fn http_client() -> Result<reqwest::Client, HarnessError> {
    crate::model::http_client()
}

/// The Anthropic provider.
#[derive(Debug)]
pub struct AnthropicProvider {
    client: reqwest::Client,
    config: ModelConfig,
    base_url: String,
    endpoint: String,
    retry: RetryPolicy,
}

impl AnthropicProvider {
    pub fn new(config: ModelConfig, client: reqwest::Client) -> Self {
        Self::with_retry(config, client, RetryPolicy::default())
    }

    pub fn with_retry(config: ModelConfig, client: reqwest::Client, retry: RetryPolicy) -> Self {
        let base = config
            .base_url
            .as_deref()
            .unwrap_or_else(|| config.provider.default_base_url())
            .trim_end_matches('/')
            .to_owned();
        // The default base is the bare host, but a proxy in front of the API is
        // usually configured with the version already attached; guessing wrong
        // here produces a 404 that looks like a routing problem.
        let endpoint = if base.ends_with("/v1") {
            format!("{base}/messages")
        } else {
            format!("{base}/v1/messages")
        };
        Self {
            client,
            config,
            base_url: base,
            endpoint,
            retry,
        }
    }

    /// The endpoint this provider posts to, for a result or a log line.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }
}

/// The free builder, so callers never name the struct just to make one.
pub fn build(config: ModelConfig, client: reqwest::Client) -> AnthropicProvider {
    AnthropicProvider::new(config, client)
}

/// The request body, as JSON.
///
/// Pure and public so the wire format can be asserted directly rather than
/// inferred from a mock server's echo of it.
pub fn build_request_body(config: &ModelConfig, request: &Completion) -> Value {
    let model = if request.model.trim().is_empty() {
        config.model.as_str()
    } else {
        request.model.as_str()
    };

    let mut body = Map::new();
    body.insert("model".into(), Value::String(model.to_owned()));
    // The system prompt is not a message here, and a conversation that starts
    // with a system turn is rejected outright, so it is lifted out.
    let system = system_prompt(&request.messages);
    if !system.is_empty() {
        body.insert("system".into(), Value::String(system));
    }
    body.insert("max_tokens".into(), json!(request.max_output_tokens));
    body.insert("messages".into(), Value::Array(messages(&request.messages)));
    if !request.tools.is_empty() {
        body.insert("tools".into(), Value::Array(tools(&request.tools)));
        body.insert("tool_choice".into(), json!({ "type": "auto" }));
    }
    // Streaming is declared in the capabilities but not implemented yet; saying
    // so explicitly is cheaper than letting a server pick a default we cannot
    // parse.
    body.insert("stream".into(), Value::Bool(false));
    // `reasoning` is deliberately not forwarded. The Messages API has no such
    // dial in this version and rejects fields it does not know, so sending one
    // is not "ignored", it is a 400 that costs the whole turn.
    Value::Object(body)
}

/// Every system turn, joined. More than one is unusual but legal in the neutral
/// shape, and dropping all but the first would silently lose a prompt.
fn system_prompt(input: &[Message]) -> String {
    let parts: Vec<&str> = input
        .iter()
        .filter_map(|message| match message {
            Message::System { content } => Some(content.as_str()),
            _ => None,
        })
        .filter(|part| !part.trim().is_empty())
        .collect();
    parts.join("\n\n")
}

/// The neutral conversation in Anthropic's message array.
fn messages(input: &[Message]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::with_capacity(input.len());
    for message in input {
        match message {
            // Already lifted out of band.
            Message::System { .. } => {}
            Message::User { content } => {
                out.push(json!({
                    "role": "user",
                    "content": [{ "type": "text", "text": content }],
                }));
            }
            Message::Assistant { text, tool_calls } => {
                let mut blocks: Vec<Value> = Vec::new();
                if let Some(text) = text.as_deref().filter(|text| !text.is_empty()) {
                    blocks.push(json!({ "type": "text", "text": text }));
                }
                blocks.extend(tool_calls.iter().map(tool_use));
                if blocks.is_empty() {
                    // An assistant turn with nothing in it is not a valid
                    // message; skipped rather than sent as an empty turn that
                    // the API would reject.
                    continue;
                }
                out.push(json!({ "role": "assistant", "content": blocks }));
            }
            Message::Tool {
                call_id,
                content,
                images,
                ..
            } => {
                // Images ride as sibling image blocks beside the tool_result,
                // never nested inside its content: the API takes content blocks.
                let mut blocks = vec![json!({
                    "type": "tool_result",
                    "tool_use_id": call_id,
                    "content": content,
                })];
                blocks.extend(images.iter().map(|image| {
                    json!({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": image.media_type,
                            "data": image.data_base64,
                        },
                    })
                }));
                // A tool result is a *user* turn on this API, and two user
                // turns in a row are an error. Results for calls the model made
                // in parallel arrive back to back, so they have to be merged
                // into one message or a perfectly good turn is refused.
                match out.last_mut() {
                    Some(last) if role_of(last) == Some("user") => {
                        if let Some(prior) = last.get_mut("content").and_then(Value::as_array_mut) {
                            prior.extend(blocks);
                        }
                    }
                    _ => out.push(json!({ "role": "user", "content": blocks })),
                }
            }
        }
    }
    out
}

fn role_of(message: &Value) -> Option<&str> {
    message.get("role").and_then(Value::as_str)
}

fn tool_use(call: &ToolCall) -> Value {
    json!({
        "type": "tool_use",
        "id": call.id,
        "name": call.name,
        // The neutral shape holds the raw text the model produced, because a
        // malformed argument is something dispatch should report back to the
        // model. This API wants an object, so a well-formed argument is parsed
        // and a malformed one is wrapped rather than dropped: the request still
        // goes out, the tool still runs, and the model sees the real complaint
        // instead of a 400 it cannot do anything about.
        "input": tool_input(&call.arguments),
    })
}

fn tool_input(arguments: &str) -> Value {
    match serde_json::from_str::<Value>(arguments) {
        Ok(value @ Value::Object(_)) => value,
        _ => json!({ "__raw": arguments }),
    }
}

fn tools(input: &[ToolSpec]) -> Vec<Value> {
    input
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.parameters,
            })
        })
        .collect()
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    content: Option<Vec<WireBlock>>,
    #[serde(default)]
    usage: Option<WireUsage>,
    #[serde(default)]
    stop_reason: Option<String>,
    /// The error envelope arrives with a 4xx/5xx, but a proxy in front of the
    /// provider can return one with a 200, and losing the reason would leave
    /// the loop with a reply that says nothing.
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Deserialize)]
struct WireBlock {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    input: Option<Value>,
}

#[derive(Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
}

/// Turns one reply into the neutral shape.
///
/// The content array is mixed-type by design: text and tool calls interleave in
/// the same reply. Pure, so the parser can be fed every shape a hostile
/// endpoint might produce.
pub fn parse_response(body: &str, latency_ms: u64) -> Result<Response, HarnessError> {
    let wire: WireResponse = serde_json::from_str(body)
        .map_err(|error| HarnessError::Model(format!("unreadable reply: {error}")))?;

    if let Some(error) = wire.error.as_ref() {
        return Err(HarnessError::Model(format!(
            "the provider reported an error: {}",
            quote(&error.to_string())
        )));
    }

    let blocks = wire.content.unwrap_or_default();
    let mut text: Option<String> = None;
    let mut tool_calls: Vec<ToolCall> = Vec::with_capacity(blocks.len());
    for block in &blocks {
        match block.kind.as_deref() {
            Some("text") => {
                let Some(part) = block.text.as_deref() else {
                    continue;
                };
                // Blocks concatenate: a reply split across two text blocks is
                // one answer, and joining with nothing is what the model meant.
                text.get_or_insert_with(String::new).push_str(part);
            }
            Some("tool_use") => tool_calls.push(ToolCall {
                id: block.id.clone().unwrap_or_default(),
                name: block.name.clone().unwrap_or_default(),
                arguments: arguments(block.input.as_ref()),
            }),
            // `thinking`, `redacted_thinking`, `server_tool_use`: not ours, and
            // not an error either.
            _ => {}
        }
    }

    let text = text.filter(|text| !text.is_empty());
    // Nothing to show the model and nothing to dispatch. Reported as a finished
    // turn it would end the session with no work done and no reason.
    if text.is_none() && tool_calls.is_empty() {
        return Err(HarnessError::Model(
            "the provider returned no content".to_owned(),
        ));
    }

    Ok(Response {
        text,
        tool_calls,
        usage: usage(wire.usage.as_ref()),
        stop: stop(wire.stop_reason.as_deref()),
        latency_ms,
    })
}

/// A tool call's arguments are an object on this API and a string in the neutral
/// shape, so the object is re-serialized here. The inverse of
/// [`tool_input`], and deliberately not a round trip through a lossy format:
/// what dispatch gets is what the model sent.
fn arguments(input: Option<&Value>) -> String {
    match input {
        None | Some(Value::Null) => "{}".to_owned(),
        Some(value) => value.to_string(),
    }
}

fn usage(usage: Option<&WireUsage>) -> Usage {
    let Some(usage) = usage else {
        return Usage::default();
    };
    Usage {
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        cache_read_tokens: usage.cache_read_input_tokens,
        cache_write_tokens: usage.cache_creation_input_tokens,
    }
}

/// A tool call and a stop are not exclusive: `tool_use` is a stop reason and
/// still a turn that finished.
pub fn stop(stop_reason: Option<&str>) -> Stop {
    match stop_reason {
        // Truncation is reported as an error rather than a finish. A turn cut
        // off mid-sentence, and above all mid-JSON, must not be mistaken for a
        // completed answer; the honest bucket is the only one that says "this
        // reply is not usable".
        Some("max_tokens") | Some("refusal") => Stop::ModelError,
        _ => Stop::ModelFinished,
    }
}

/// Whether a status is worth another attempt.
///
/// 429 and 5xx are the provider's own "not now"; 408 is a timeout the provider
/// chose to report. Everything else — a bad key, an unknown model, a malformed
/// body — is exactly as wrong on the second attempt as on the first.
pub fn is_retryable_status(status: u16) -> bool {
    status == 408 || status == 429 || (500..600).contains(&status)
}

/// Why one attempt failed, and whether trying again could help.
struct Failure {
    error: HarnessError,
    retryable: bool,
    retry_after: Option<Duration>,
}

impl Failure {
    fn permanent(error: HarnessError) -> Self {
        Self {
            error,
            retryable: false,
            retry_after: None,
        }
    }

    fn transient(error: HarnessError, retry_after: Option<Duration>) -> Self {
        Self {
            error,
            retryable: true,
            retry_after,
        }
    }
}

impl ModelProvider for AnthropicProvider {
    fn config(&self) -> &ModelConfig {
        &self.config
    }

    fn capabilities(&self) -> Capabilities {
        self.config.provider.capabilities()
    }

    /// Nothing to release: the client belongs to the session, not to us, and
    /// dropping it early would break every other turn.
    fn shutdown(&self) {}

    fn complete<'a>(&'a self, request: &'a Completion) -> BoxFuture<'a, Response> {
        Box::pin(async move {
            let key = credential(&self.config)?;
            let body = build_request_body(&self.config, request);
            let payload = serde_json::to_vec(&body)
                .map_err(|error| HarnessError::Model(format!("unserialisable request: {error}")))?;

            let attempts = self.retry.attempts.max(1);
            let mut spent = Duration::ZERO;
            let mut last: Option<HarnessError> = None;

            for attempt in 1..=attempts {
                let started = Instant::now();
                match self.send(&payload, &key).await {
                    Ok(text) => {
                        return parse_response(&text, elapsed_ms(started));
                    }
                    Err(failure) if failure.retryable => {
                        // A retryable failure that has run out of attempts is
                        // reported as a spent retry budget rather than as a
                        // plain model error: the caller can then tell "this
                        // endpoint is unwell" from "this request is wrong",
                        // which are different decisions.
                        last = Some(failure.error);
                        if attempt >= attempts {
                            break;
                        }
                        // A server that named a delay is believed, under its
                        // own ceiling. A delay we invented is under ours.
                        let delay = match failure.retry_after {
                            Some(asked) => asked.min(self.retry.max_retry_after),
                            None => {
                                let ours = backoff(&self.retry, attempt);
                                if spent + ours > self.retry.max_total_delay {
                                    break;
                                }
                                ours
                            }
                        };
                        spent += delay;
                        tokio::time::sleep(delay).await;
                    }
                    Err(failure) => return Err(failure.error),
                }
            }

            let reason = last.map_or_else(
                || "no attempt was made".to_owned(),
                |error| error.to_string(),
            );
            Err(HarnessError::RetriesExhausted(reason))
        })
    }
}

impl AnthropicProvider {
    /// One attempt: no retry logic, so the retry loop above is the only place
    /// that decides whether a failure was worth repeating.
    async fn send(&self, payload: &[u8], key: &str) -> Result<String, Failure> {
        // Rebuilt per attempt: a request that cannot be cloned is cheaper to
        // re-assemble than to keep, and the payload is the only part with any
        // size to it.
        let response = match self
            .client
            .post(&self.endpoint)
            .header("x-api-key", key)
            .header("anthropic-version", API_VERSION)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload.to_vec())
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                // A transport error is almost always transient, but a builder
                // or decode error is our own bug and would fail identically
                // every time.
                let retryable = !(error.is_builder() || error.is_decode() || error.is_redirect());
                let message = format!("request failed: {}", scrub(&error.to_string(), key));
                return Err(if retryable {
                    Failure::transient(HarnessError::Model(message), None)
                } else {
                    Failure::permanent(HarnessError::Model(message))
                });
            }
        };

        let status = response.status();
        if status.is_success() {
            return match read_capped(response, MAX_BODY, key).await {
                Ok(text) => Ok(text),
                Err(message) => Err(Failure::transient(HarnessError::Model(message), None)),
            };
        }

        let retry_after = retry_after(response.headers(), &self.retry);
        let body = read_capped(response, MAX_ERROR_BODY, key)
            .await
            .unwrap_or_default();
        Err(Failure {
            error: HarnessError::Model(format!("{status}: {}", quote(&body))),
            retryable: is_retryable_status(status.as_u16()),
            retry_after,
        })
    }
}

/// The credential, read at request time and never stored.
///
/// Reading it per request is deliberate: a key held in a struct is a key that
/// can reach a `Debug` line, a serialized config, or a crash report. Held only
/// in this frame, it cannot.
fn credential(config: &ModelConfig) -> Result<String, HarnessError> {
    let name = config.provider.credential_env();
    match std::env::var(name) {
        // Trimmed because a key pasted with a trailing newline is a very common
        // way to spend an afternoon on a 401.
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        _ => Err(HarnessError::MissingCredential(name.to_owned())),
    }
}

/// Reads a body without ever buffering more than `limit`.
async fn read_capped(
    response: reqwest::Response,
    limit: usize,
    key: &str,
) -> Result<String, String> {
    let mut buffer: Vec<u8> = Vec::with_capacity(limit.min(16 * 1024));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("reading the reply failed: {error}"))?;
        let room = limit.saturating_sub(buffer.len());
        if room == 0 {
            break;
        }
        if chunk.len() > room {
            buffer.extend_from_slice(&chunk[..room]);
            break;
        }
        buffer.extend_from_slice(&chunk);
    }
    // Lossy: a server sending invalid UTF-8 should cost us the odd character,
    // not the whole reply.
    Ok(scrub(&String::from_utf8_lossy(&buffer), key))
}

/// Removes the credential from any text we are about to quote.
///
/// A gateway that echoes the key back inside its own error message is a real
/// thing that happens, and that text ends up in the result file.
fn scrub(text: &str, key: &str) -> String {
    if key.is_empty() {
        return text.to_owned();
    }
    text.replace(key, "[redacted]")
}

fn quote(text: &str) -> String {
    if text.chars().count() <= MAX_QUOTE {
        return text.to_owned();
    }
    let kept: String = text.chars().take(MAX_QUOTE).collect();
    format!("{kept}…")
}

/// `Retry-After` in its delta-seconds form, clipped to the policy's ceiling on
/// what a server may ask for. The HTTP-date form falls back to the ordinary
/// backoff rather than being parsed wrong: a missing optimization is cheaper
/// than a wrong sleep.
fn retry_after(headers: &reqwest::header::HeaderMap, policy: &RetryPolicy) -> Option<Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    let seconds: u64 = raw.trim().parse().ok()?;
    Some(Duration::from_secs(seconds).min(policy.max_retry_after))
}

/// Exponential backoff with jitter.
///
/// The jitter is there so a fleet of harnesses that all hit the same 429 in the
/// same millisecond does not come back in lockstep and get throttled again.
fn backoff(policy: &RetryPolicy, attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(16);
    let grown = policy
        .base_delay
        .saturating_mul(1u32 << shift)
        .min(policy.max_delay);
    let with_jitter = grown + Duration::from_millis(jitter_millis(attempt));
    with_jitter.min(policy.max_delay)
}

fn jitter_millis(attempt: u32) -> u64 {
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let mut mixed = clock ^ u64::from(attempt).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mixed ^= mixed >> 33;
    mixed = mixed.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    mixed ^= mixed >> 33;
    mixed % 250
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
