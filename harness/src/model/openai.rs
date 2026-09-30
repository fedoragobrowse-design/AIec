//! The OpenAI chat-completions shape, which is also OpenRouter and most local
//! inference servers.
//!
//! One wire format covers most of the map, so this file is the reference for
//! what a provider backend owes the rest of the harness: build a body from the
//! neutral `Completion`, parse the reply back into the neutral `Response`,
//! retry what is worth retrying, and never let the credential escape.
//!
//! The client is owned by the session and borrowed here. A fresh client per
//! request would redo the TCP handshake, the TLS negotiation, and the HTTP/2
//! upgrade on every turn, which is the single easiest way for a small harness to
//! lose to a bigger one.

use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::HarnessError;
use crate::model::{
    Capabilities, Completion, Message, ModelConfig, ModelProvider, Reasoning, Response, Stop,
    ToolCall, ToolSpec, Usage,
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

/// How often we try, and how long we are willing to wait between tries.
///
/// Retried because a model endpoint on a shared network fails for reasons that
/// have nothing to do with the agent, and a sandbox is disposable, so a retry
/// costs a second rather than the whole run. Not retried forever, because a
/// session that spends its budget sleeping is a session that never answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, including the first.
    pub attempts: u32,
    /// The first sleep we choose ourselves.
    pub base_delay: Duration,
    /// Ceiling on any single sleep we choose ourselves.
    pub max_delay: Duration,
    /// Ceiling on the sum of every backoff in one `complete`, so the retry
    /// budget is bounded even if each individual sleep is legal.
    pub max_total_delay: Duration,
    /// Ceiling on a delay the SERVER asked for via `Retry-After`.
    ///
    /// Deliberately separate from `max_total_delay`. A throttled gateway that
    /// says "wait a second" is telling us the truth about its own state, and
    /// clipping that to our own small backoff ceiling turns an honest
    /// instruction into a guaranteed failure. The two budgets bound different
    /// things: ours is how long we choose to wait, theirs is how long the
    /// provider said it needs.
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

/// The OpenAI-compatible provider.
#[derive(Debug)]
pub struct OpenAiProvider {
    client: reqwest::Client,
    config: ModelConfig,
    base_url: String,
    retry: RetryPolicy,
}

impl OpenAiProvider {
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
        Self {
            client,
            config,
            base_url: base,
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
pub fn build(config: ModelConfig, client: reqwest::Client) -> OpenAiProvider {
    OpenAiProvider::new(config, client)
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
    body.insert("messages".into(), Value::Array(messages(&request.messages)));
    if !request.tools.is_empty() {
        body.insert("tools".into(), Value::Array(tools(&request.tools)));
        body.insert("tool_choice".into(), Value::String("auto".into()));
    }
    body.insert("max_tokens".into(), json!(request.max_output_tokens));
    // Streaming is declared in the capabilities but not implemented yet; saying
    // so explicitly is cheaper than letting a server pick a default we cannot
    // parse.
    body.insert("stream".into(), Value::Bool(false));
    if request.reasoning != Reasoning::Off {
        // Forwarded, not interpreted: the harness has no idea what "medium"
        // means to a provider it has never heard of, and guessing is worse.
        body.insert(
            "reasoning_effort".into(),
            Value::String(request.reasoning.as_str().to_owned()),
        );
    }
    Value::Object(body)
}

/// The neutral conversation in OpenAI's message array.
fn messages(input: &[Message]) -> Vec<Value> {
    let mut out = Vec::with_capacity(input.len());
    for message in input {
        out.push(match message {
            Message::System { content } => json!({ "role": "system", "content": content }),
            Message::User { content } => json!({ "role": "user", "content": content }),
            Message::Assistant { text, tool_calls } => {
                let mut map = Map::new();
                map.insert("role".into(), Value::String("assistant".into()));
                // `content` is required by the schema and explicitly nullable:
                // a turn that is only tool calls sends null, not "".
                map.insert(
                    "content".into(),
                    match text.as_deref() {
                        Some(text) if !text.is_empty() => Value::String(text.to_owned()),
                        _ => Value::Null,
                    },
                );
                if !tool_calls.is_empty() {
                    map.insert(
                        "tool_calls".into(),
                        Value::Array(tool_calls.iter().map(tool_call).collect()),
                    );
                }
                Value::Object(map)
            }
            Message::Tool {
                call_id, content, ..
            } => {
                json!({ "role": "tool", "tool_call_id": call_id, "content": content })
            }
        });
    }
    out
}

fn tool_call(call: &ToolCall) -> Value {
    json!({
        "id": call.id,
        "type": "function",
        // `arguments` is a JSON *string* on this side of the wire, not an
        // object: the model's raw text is forwarded so a malformed argument
        // stays visible to dispatch instead of being laundered here.
        "function": { "name": call.name, "arguments": call.arguments },
    })
}

fn tools(input: &[ToolSpec]) -> Vec<Value> {
    input
        .iter()
        .map(|tool| {
            json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                }
            })
        })
        .collect()
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    choices: Vec<WireChoice>,
    #[serde(default)]
    usage: Option<WireUsage>,
    /// The error envelope arrives with a 4xx/5xx, but a proxy in front of the
    /// provider can return one with a 200, and losing the reason would leave
    /// the loop with a reply that says nothing.
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Deserialize)]
struct WireChoice {
    #[serde(default)]
    message: Option<WireMessage>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct WireMessage {
    /// Typed as a `Value` because some gateways send content blocks instead of
    /// a string; a hostile shape should cost us the text, not the turn.
    #[serde(default)]
    content: Option<Value>,
    #[serde(default)]
    tool_calls: Vec<WireToolCall>,
}

#[derive(Deserialize, Default)]
struct WireToolCall {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: WireFunction,
}

#[derive(Deserialize, Default)]
struct WireFunction {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<Value>,
}

#[derive(Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: Option<WirePromptDetails>,
    /// A few gateways mirror Anthropic's cache counters onto this endpoint;
    /// reported when present, ignored when not.
    #[serde(default)]
    cache_read_input_tokens: Option<u64>,
    #[serde(default)]
    cache_creation_input_tokens: Option<u64>,
    #[serde(default)]
    cache_creation_tokens: Option<u64>,
}

#[derive(Deserialize, Default)]
struct WirePromptDetails {
    #[serde(default)]
    cached_tokens: u64,
}

/// Turns one reply into the neutral shape.
///
/// Pure, so the parser can be fed every shape a hostile endpoint might produce.
pub fn parse_response(body: &str, latency_ms: u64) -> Result<Response, HarnessError> {
    let wire: WireResponse = serde_json::from_str(body)
        .map_err(|error| HarnessError::Model(format!("unreadable reply: {error}")))?;

    if let Some(error) = wire.error.as_ref() {
        return Err(HarnessError::Model(format!(
            "the provider reported an error: {}",
            quote(&error.to_string())
        )));
    }

    // Usage is read before the choice is moved out, so nothing is cloned just
    // to satisfy the borrow checker.
    let usage = usage(wire.usage.as_ref());
    let Some(choice) = wire.choices.into_iter().next() else {
        return Err(HarnessError::Model(
            "the provider returned no choices".to_owned(),
        ));
    };
    let message = choice.message.unwrap_or_default();
    let tool_calls: Vec<ToolCall> = message
        .tool_calls
        .into_iter()
        .map(|call| ToolCall {
            id: call.id.unwrap_or_default(),
            name: call.function.name.unwrap_or_default(),
            arguments: arguments(call.function.arguments.as_ref()),
        })
        .collect();

    Ok(Response {
        text: text(message.content.as_ref()),
        tool_calls,
        usage,
        stop: stop(choice.finish_reason.as_deref()),
        latency_ms,
    })
}

/// Arguments come back as a JSON string in the neutral shape. Most servers send
/// one; a server that sends an object is re-serialized rather than dropped,
/// because a tool call with no arguments is still a tool call.
fn arguments(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "{}".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

fn text(content: Option<&Value>) -> Option<String> {
    match content? {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::String(_) => None,
        Value::Array(blocks) => {
            let mut joined = String::new();
            for block in blocks {
                if let Some(part) = block.get("text").and_then(Value::as_str) {
                    joined.push_str(part);
                }
            }
            (!joined.is_empty()).then_some(joined)
        }
        _ => None,
    }
}

fn usage(usage: Option<&WireUsage>) -> Usage {
    let Some(usage) = usage else {
        return Usage::default();
    };
    let cached = usage
        .prompt_tokens_details
        .as_ref()
        .map_or(0, |d| d.cached_tokens);
    Usage {
        input_tokens: usage.prompt_tokens,
        output_tokens: usage.completion_tokens,
        cache_read_tokens: cached.max(usage.cache_read_input_tokens.unwrap_or(0)),
        cache_write_tokens: usage
            .cache_creation_input_tokens
            .unwrap_or(0)
            .max(usage.cache_creation_tokens.unwrap_or(0)),
    }
}

/// A tool call and a stop are not exclusive: a turn that ends with tool calls
/// has still finished, and the loop dispatches the calls and comes back.
pub fn stop(finish_reason: Option<&str>) -> Stop {
    match finish_reason {
        // Truncation is reported as an error rather than a finish. A turn cut
        // off mid-sentence, and above all mid-JSON, must not be mistaken for a
        // completed answer; the honest bucket is the only one that says "this
        // reply is not usable".
        Some("length" | "max_tokens") | Some("content_filter") => Stop::ModelError,
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

impl ModelProvider for OpenAiProvider {
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
            let key = credential(&self.config, &self.base_url)?;
            let body = build_request_body(&self.config, request);
            let payload = serde_json::to_vec(&body)
                .map_err(|error| HarnessError::Model(format!("unserialisable request: {error}")))?;

            let url = format!("{}/chat/completions", self.base_url);
            let attempts = self.retry.attempts.max(1);
            let mut spent = Duration::ZERO;
            let mut last: Option<HarnessError> = None;

            for attempt in 1..=attempts {
                let started = Instant::now();
                match self.send(&url, &payload, key.as_deref()).await {
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
                        // Mixing the two means a throttled gateway that says
                        // "wait a second" gets clipped to a backoff budget
                        // sized for our own impatience, and then fails for
                        // having been honest.
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

impl OpenAiProvider {
    /// One attempt: no retry logic, so the retry loop above is the only place
    /// that decides whether a failure was worth repeating.
    async fn send(&self, url: &str, payload: &[u8], key: Option<&str>) -> Result<String, Failure> {
        // Rebuilt per attempt: a request that cannot be cloned is cheaper to
        // re-assemble than to keep, and the payload is the only part with any
        // size to it.
        let mut builder = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            // Absent rather than empty: an endpoint that needs no credential
            // should not see a bearer token at all.
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", key.unwrap_or_default()),
            )
            .body(payload.to_vec());
        if self.config.provider == crate::model::Provider::OpenRouter {
            // OpenRouter uses these for attribution. Not secrets, and harmless
            // to omit, so this is a courtesy rather than a requirement.
            builder = builder.header("x-title", "aiec-harness");
        }
        let response = match builder.send().await {
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
/// Reads the credential, if the endpoint wants one.
///
/// A custom base URL is allowed to need no key at all, because a real and
/// increasingly common case is an endpoint that serves a local or already
/// authenticated model: Ollama, vLLM, LM Studio, or a gateway that fronts a
/// subscription. Demanding `OPENAI_API_KEY` for those is wrong, and the fix is
/// not "send an empty bearer" but "send no Authorization header at all".
///
/// On the provider's own default URL the key is still required, because
/// omitting it there produces a confusing 401 instead of a clear message.
fn credential(config: &ModelConfig, base_url: &str) -> Result<Option<String>, HarnessError> {
    let name = config.provider.credential_env();
    match std::env::var(name) {
        // Trimmed because a key pasted with a trailing newline is a very common
        // way to spend an afternoon on a 401.
        Ok(value) if !value.trim().is_empty() => Ok(Some(value.trim().to_owned())),
        _ => {
            let on_default_endpoint =
                base_url.trim_end_matches('/') == config.provider.default_base_url();
            if on_default_endpoint {
                Err(HarnessError::MissingCredential(name.to_owned()))
            } else {
                Ok(None)
            }
        }
    }
}

/// Reads a body without ever buffering more than `limit`.
async fn read_capped(
    response: reqwest::Response,
    limit: usize,
    key: Option<&str>,
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
fn scrub(text: &str, key: Option<&str>) -> String {
    // No key means no key to leak, and `replace` with an empty pattern would
    // otherwise insert the marker between every character.
    match key {
        Some(key) if !key.is_empty() => text.replace(key, "[redacted]"),
        _ => text.to_owned(),
    }
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
