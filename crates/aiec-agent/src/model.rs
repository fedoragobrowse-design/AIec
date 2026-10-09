//! Talking to a model, without hardcoding a company.
//!
//! One wire format is implemented - the OpenAI-compatible chat completions shape,
//! which is what nearly every provider and every local inference server
//! speaks - and the abstraction is expressed as *capabilities* rather than as
//! provider names. A provider that does not stream, or has no prompt caching, or
//! cannot return token usage, is configured by declaring that, not by being
//! named in a match arm.
//!
//! The client is built once and reused. TLS sessions and HTTP/2 connections are
//! the second-largest cost after the model itself, and rebuilding a client per
//! request would make a 40-turn run pay that 40 times.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::task::{HarnessError, Task, Usage};

/// What a provider can do.
///
/// Declared rather than detected, because detecting means asking, and asking
/// costs a request on a machine whose whole purpose is to be cheap.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Capabilities {
    pub tools: bool,
    pub streaming: bool,
    pub usage: bool,
    /// The provider understands provider-specific reasoning hints.
    pub reasoning: bool,
}

/// A tool the model asked for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// Raw JSON arguments as the model produced them; parsed at dispatch so a
    /// malformed call becomes a tool error the model can read rather than a
    /// harness crash.
    #[serde(default)]
    pub arguments: String,
}

impl ToolCall {
    /// What the loop detector compares: the same call with the same arguments
    /// is the same call, whatever id the provider assigned.
    pub fn signature(&self) -> String {
        format!("{}:{}", self.name, self.arguments)
    }
}

/// One message in the conversation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum Message {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<ToolCall>,
    },
    Tool {
        tool_call_id: String,
        name: String,
        content: String,
    },
}

/// A schema advertised to the model.
#[derive(Clone, Debug, Serialize)]
pub struct ToolSchema {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters: serde_json::Value,
}

/// The model's reply.
#[derive(Clone, Debug, Default)]
pub struct Reply {
    pub text: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
}

/// Which wire format to speak. OpenAI-compatible chat completions is the
/// default; anything naming Anthropic/Claude speaks the Messages API, so a
/// Claude subscriber's key works without naming a base URL. Detection is by
/// model or base URL, never by key presence: an `ANTHROPIC_API_KEY` sitting
/// in the environment alongside an OpenAI model choice must not reroute it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
    OpenAi,
    Anthropic,
}

fn detect_provider(model: &str, base_url: &str) -> Provider {
    let haystack = format!("{model} {base_url}").to_lowercase();
    if haystack.contains("anthropic") || haystack.contains("claude") {
        Provider::Anthropic
    } else {
        Provider::OpenAi
    }
}

/// A configured endpoint.
#[derive(Clone, Debug)]
pub struct Client {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<zeroize::Zeroizing<String>>,
    model: String,
    capabilities: Capabilities,
    /// Opaque to the harness, passed through when the provider understands it.
    reasoning: Option<String>,
    provider: Provider,
}

/// Environment variables the harness reads, in priority order.
const KEY_VARS: &[&str] = &["AIEC_AGENT_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"];
const BASE_VARS: &[&str] = &["AIEC_AGENT_BASE_URL", "OPENAI_BASE_URL"];
const MODEL_VARS: &[&str] = &["AIEC_AGENT_MODEL", "OPENAI_MODEL", "ANTHROPIC_MODEL"];

impl Client {
    /// Builds a client from the task, falling back to the environment.
    pub fn from_task(task: &Task) -> Result<Self, HarnessError> {
        let chosen = task.model.as_ref();
        let model = chosen
            .map(|choice| choice.model.clone())
            .or_else(|| first_env(MODEL_VARS))
            .ok_or_else(|| {
                HarnessError::Config(
                    "no model configured: set AIEC_AGENT_MODEL or pass one in the task".to_owned(),
                )
            })?;
        let provider_name = chosen
            .and_then(|c| c.provider.clone())
            .filter(|value| !value.trim().is_empty());
        let base_url = provider_name
            .clone()
            .filter(|value| value.starts_with("http"))
            .or_else(|| first_env(BASE_VARS))
            .unwrap_or_else(|| {
                // The provider name doubles as a hint: `provider: "anthropic"`
                // with no URL still means the Messages API. The model name
                // covers the other direction (`model: "claude-..."` with no
                // provider), so either spelling selects Anthropic alone.
                let hint = provider_name.as_deref().unwrap_or_default();
                if detect_provider(&format!("{model} {hint}"), "") == Provider::Anthropic {
                    "https://api.anthropic.com".to_owned()
                } else {
                    "https://api.openai.com/v1".to_owned()
                }
            });
        let api_key = first_env(KEY_VARS).map(zeroize::Zeroizing::new);
        let reasoning = chosen.and_then(|c| c.reasoning.clone());

        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(600))
            .pool_max_idle_per_host(4)
            .user_agent(concat!("aiec-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| HarnessError::Model(format!("http client: {error}")))?;
        let base_url = base_url.trim_end_matches('/').to_owned();
        let named = provider_name.as_deref().unwrap_or_default();
        let provider = detect_provider(&format!("{model} {named}"), &base_url);
        Ok(Self {
            http,
            base_url,
            api_key,
            model,
            capabilities: Capabilities {
                tools: true,
                streaming: false,
                usage: true,
                reasoning: reasoning.is_some(),
            },
            reasoning,
            provider,
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// One completion. Retries transient failures with a bounded backoff.
    ///
    /// Only [`HarnessError::Model`] is retried. Permanent request refusals
    /// become [`HarnessError::ModelRefused`] and return on the first attempt
    /// with the provider's status and error text.
    pub async fn complete(
        &self,
        context: &Context,
        tools: &[ToolSchema],
        max_output_tokens: u32,
    ) -> Result<Reply, HarnessError> {
        // Retried because a model endpoint on a shared network fails for
        // reasons that have nothing to do with the agent, and a sandbox is
        // disposable, so a retry costs a second rather than the whole run.
        const ATTEMPTS: u32 = 3;
        let mut last: Option<HarnessError> = None;
        for attempt in 1..=ATTEMPTS {
            match self.try_once(context, tools, max_output_tokens).await {
                Ok(reply) => return Ok(reply),
                Err(error @ HarnessError::Model(_)) if attempt < ATTEMPTS => {
                    // Backoff grows so a struggling endpoint is not hammered,
                    // and so a slow start has room to come up.
                    tokio::time::sleep(Duration::from_millis(250 * u64::from(attempt) * 3)).await;
                    last = Some(error);
                }
                Err(other) => return Err(other),
            }
        }
        Err(last.unwrap_or_else(|| HarnessError::Model("no attempt was made".to_owned())))
    }

    async fn try_once(
        &self,
        context: &Context,
        tools: &[ToolSchema],
        max_output_tokens: u32,
    ) -> Result<Reply, HarnessError> {
        match self.provider {
            Provider::OpenAi => self.try_openai(context, tools, max_output_tokens).await,
            Provider::Anthropic => self.try_anthropic(context, tools, max_output_tokens).await,
        }
    }

    async fn try_openai(
        &self,
        context: &Context,
        tools: &[ToolSchema],
        max_output_tokens: u32,
    ) -> Result<Reply, HarnessError> {
        let mut body = serde_json::json!({
            "model": self.model,
            "messages": context.as_wire(),
            "max_tokens": max_output_tokens,
        });
        // Reasoning effort is passed through rather than interpreted: the
        // harness has no idea what "medium" means to a provider it has never
        // heard of, and guessing would be worse than forwarding the request.
        if let Some(effort) = &self.reasoning {
            body["reasoning_effort"] = serde_json::json!(effort);
        }
        if self.capabilities.tools && !tools.is_empty() {
            let advertised: Vec<_> = tools
                .iter()
                .map(|tool| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.parameters,
                        }
                    })
                })
                .collect();
            body["tools"] = serde_json::Value::Array(advertised);
            body["tool_choice"] = serde_json::json!("auto");
        }

        let mut request = self
            .http
            .post(format!("{}/chat/completions", self.base_url))
            .json(&body)
            .header("content-type", "application/json");
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|error| HarnessError::Model(format!("request failed: {error}")))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| HarnessError::Model(format!("reading reply: {error}")))?;
        if !status.is_success() {
            // The provider's own error text is included: it is the only thing
            // that says whether this is a bad key, a bad model name, or a quota
            // problem, and a harness that swallows it cannot be diagnosed.
            let detail = format!("provider returned {status}: {}", crate::clip(&text, 300));
            return Err(if worth_retrying(status) {
                HarnessError::Model(detail)
            } else {
                HarnessError::ModelRefused(detail)
            });
        }
        parse_reply(&text)
    }

    /// Anthropic Messages API. Same [`Reply`] surface as OpenAI: text plus
    /// tool calls, so the agent loop never learns which provider answered.
    ///
    /// Auth is the subscriber's own credential: `ANTHROPIC_API_KEY`, or an
    /// OAuth token from `claude login` (`ANTHROPIC_OAUTH_TOKEN`), sent as
    /// `x-api-key`. `AIEC_AGENT_API_KEY` wins when set, so one task can pin a
    /// different key without clearing the ambient subscription.
    async fn try_anthropic(
        &self,
        context: &Context,
        tools: &[ToolSchema],
        max_output_tokens: u32,
    ) -> Result<Reply, HarnessError> {
        let wire = context.as_wire();
        // The harness emits a leading system message; Messages takes it as a
        // top-level `system` string, not a conversation turn. Anything else
        // with a system role is folded into the first user turn: inventing a
        // second system block would misstate the contract.
        let mut system_parts: Vec<String> = Vec::new();
        let mut messages: Vec<serde_json::Value> = Vec::new();
        for entry in &wire {
            let role = entry.get("role").and_then(|r| r.as_str()).unwrap_or("user");
            let content = entry
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or_default()
                .to_owned();
            if role == "system" {
                system_parts.push(content);
            } else if role == "assistant" {
                messages.push(serde_json::json!({"role": "assistant", "content": content}));
            } else {
                // Tool results ride as `tool` role in the harness wire; on
                // Messages they are user turns carrying `tool_result` blocks
                // keyed by the call id the model was given.
                if entry.get("role").and_then(|r| r.as_str()) == Some("tool") {
                    let tool_call_id = entry
                        .get("tool_call_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    messages.push(serde_json::json!({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": tool_call_id,
                            "content": content,
                        }],
                    }));
                } else {
                    messages.push(serde_json::json!({"role": "user", "content": content}));
                }
            }
        }
        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": max_output_tokens,
            "system": system_parts.join("\n"),
            "messages": messages,
        });
        // Anthropic reasoning is a thinking budget in tokens, not an effort
        // word: forward it only when it parses, rather than sending a value
        // the endpoint would reject over a guess.
        if let Some(effort) = &self.reasoning
            && let Ok(budget) = effort.as_str().parse::<u32>()
        {
            body["thinking"] = serde_json::json!({"type": "enabled", "budget_tokens": budget});
        }
        if self.capabilities.tools && !tools.is_empty() {
            let advertised: Vec<_> = tools
                .iter()
                .map(|tool| {
                    serde_json::json!({
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.parameters,
                    })
                })
                .collect();
            body["tools"] = serde_json::Value::Array(advertised);
        }

        let url = format!("{}/v1/messages", self.base_url);
        let mut request = self
            .http
            .post(url)
            .json(&body)
            .header("content-type", "application/json")
            .header("anthropic-version", "2023-06-01");
        // Subscriber OAuth first would silently bill the wrong account when
        // both are set; explicit key env wins, OAuth is the fallback.
        let oauth = std::env::var("ANTHROPIC_OAUTH_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty());
        match (&self.api_key, oauth) {
            (Some(key), _) => {
                request = request.header("x-api-key", key.as_str());
            }
            (None, Some(token)) => {
                request = request.header("x-api-key", token);
            }
            (None, None) => {}
        }

        let response = request
            .send()
            .await
            .map_err(|error| HarnessError::Model(format!("request failed: {error}")))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| HarnessError::Model(format!("reading reply: {error}")))?;
        if !status.is_success() {
            let detail = format!("provider returned {status}: {}", crate::clip(&text, 300));
            return Err(if worth_retrying(status) {
                HarnessError::Model(detail)
            } else {
                HarnessError::ModelRefused(detail)
            });
        }
        parse_anthropic_reply(&text)
    }
}

/// Whether a status is worth sending the same request again for.
///
/// 5xx and 429 are the endpoint or its capacity failing, not the request, and
/// a bounded retry is the right answer to both. Every other 4xx is a statement
/// about this request - an unauthorised key, a model that does not exist, a
/// body the endpoint will not parse - and will be repeated exactly. 3xx stays
/// retryable too: it should have been followed by the client, so seeing one
/// means the path back to the endpoint is still unsettled.
fn worth_retrying(status: reqwest::StatusCode) -> bool {
    !(status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS)
}

#[derive(Deserialize)]
struct WireReply {
    #[serde(default)]
    choices: Vec<WireChoice>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
struct WireChoice {
    #[serde(default)]
    message: Option<WireMessage>,
}

#[derive(Deserialize)]
struct WireMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default, rename = "tool_calls")]
    tool_calls: Vec<WireToolCall>,
}

#[derive(Deserialize, Default)]
struct WireToolCall {
    #[serde(default)]
    id: String,
    #[serde(default)]
    function: WireFunction,
}

#[derive(Deserialize, Default)]
struct WireFunction {
    #[serde(default)]
    name: String,
    #[serde(default)]
    arguments: String,
}

#[derive(Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: Option<WireCached>,
}

#[derive(Deserialize, Default)]
struct WireCached {
    #[serde(default)]
    cached_tokens: u64,
}

fn parse_reply(text: &str) -> Result<Reply, HarnessError> {
    let wire: WireReply = serde_json::from_str(text)
        .map_err(|error| HarnessError::Model(format!("unreadable reply: {error}")))?;
    let Some(choice) = wire.choices.into_iter().next() else {
        return Err(HarnessError::Model(
            "the provider returned no choices".to_owned(),
        ));
    };
    let message = choice.message.unwrap_or(WireMessage {
        content: None,
        tool_calls: Vec::new(),
    });
    let usage = wire.usage.map_or(Usage::default(), |u| Usage {
        input_tokens: u.prompt_tokens,
        output_tokens: u.completion_tokens,
        cached_input_tokens: u.prompt_tokens_details.map_or(0, |c| c.cached_tokens),
        requests: 0,
    });
    Ok(Reply {
        text: message.content,
        tool_calls: message
            .tool_calls
            .into_iter()
            .map(|call| ToolCall {
                id: call.id,
                name: call.function.name,
                arguments: call.function.arguments,
            })
            .collect(),
        usage,
    })
}

/// Anthropic Messages response shapes. `content` is a heterogeneous block
/// list: `text` blocks join into the reply, `tool_use` blocks become tool
/// calls. Anything else (thinking, redacted) is skipped, not failed: the
/// agent loses reasoning detail, not the turn.
#[derive(Deserialize, Default)]
struct AnthropicReply {
    #[serde(default)]
    content: Vec<AnthropicBlock>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
}

#[derive(Deserialize, Default)]
struct AnthropicBlock {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    input: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

fn parse_anthropic_reply(text: &str) -> Result<Reply, HarnessError> {
    let wire: AnthropicReply = serde_json::from_str(text)
        .map_err(|error| HarnessError::Model(format!("unreadable reply: {error}")))?;
    if wire.content.is_empty() {
        return Err(HarnessError::Model(
            "the provider returned no content".to_owned(),
        ));
    }
    let mut reply_text: Vec<String> = Vec::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    for block in wire.content {
        match block.kind.as_str() {
            "text" => {
                if let Some(text) = block.text {
                    reply_text.push(text);
                }
            }
            "tool_use" => {
                tool_calls.push(ToolCall {
                    id: block.id.unwrap_or_default(),
                    name: block.name.unwrap_or_default(),
                    arguments: block
                        .input
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "{}".to_owned()),
                });
            }
            _ => {}
        }
    }
    let usage = wire.usage.map_or(Usage::default(), |u| Usage {
        input_tokens: u.input_tokens,
        output_tokens: u.output_tokens,
        cached_input_tokens: u.cache_read_input_tokens,
        requests: 0,
    });
    Ok(Reply {
        text: if reply_text.is_empty() {
            None
        } else {
            Some(reply_text.join(""))
        },
        tool_calls,
        usage,
    })
}

fn first_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn a_tool_reply_is_parsed() {
        let text = r#"{"choices":[{"message":{"content":null,"tool_calls":[
            {"id":"c1","function":{"name":"read","arguments":"{\"path\":\"a.rs\"}"}}]}}],
            "usage":{"prompt_tokens":10,"completion_tokens":4}}"#;
        let reply = parse_reply(text).expect("parsed");
        assert_eq!(reply.tool_calls.len(), 1);
        assert_eq!(reply.tool_calls[0].name, "read");
        assert!(reply.tool_calls[0].arguments.contains("a.rs"));
        assert_eq!(reply.usage.input_tokens, 10);
    }

    #[test]
    fn a_text_reply_is_parsed() {
        let text = r#"{"choices":[{"message":{"content":"done","tool_calls":[]}}]}"#;
        let reply = parse_reply(text).expect("parsed");
        assert_eq!(reply.text.as_deref(), Some("done"));
        assert!(reply.tool_calls.is_empty());
    }

    #[test]
    fn a_reply_with_no_choices_is_an_error_not_a_panic() {
        let error = parse_reply(r#"{"choices":[]}"#).unwrap_err();
        assert!(matches!(error, HarnessError::Model(_)));
    }

    #[test]
    fn a_malformed_reply_is_an_error_not_a_panic() {
        assert!(parse_reply("not json").is_err());
        assert!(
            parse_reply("{}").is_err(),
            "an object with no choices is not a usable reply"
        );
    }

    #[test]
    fn the_same_call_with_different_arguments_is_not_a_repeat() {
        let first = ToolCall {
            id: "1".to_owned(),
            name: "read".to_owned(),
            arguments: "{\"path\":\"a\"}".to_owned(),
        };
        let second = ToolCall {
            id: "2".to_owned(),
            name: "read".to_owned(),
            arguments: "{\"path\":\"b\"}".to_owned(),
        };
        assert_ne!(first.signature(), second.signature());
    }
    #[test]
    fn an_anthropic_text_and_tool_reply_is_parsed() {
        let text = r#"{"content":[
            {"type":"text","text":"reading now"},
            {"type":"tool_use","id":"tu1","name":"read","input":{"path":"a.rs"}}],
            "usage":{"input_tokens":7,"output_tokens":3,"cache_read_input_tokens":2}}"#;
        let reply = parse_anthropic_reply(text).expect("parsed");
        assert_eq!(reply.text.as_deref(), Some("reading now"));
        assert_eq!(reply.tool_calls.len(), 1);
        assert_eq!(reply.tool_calls[0].id, "tu1");
        assert_eq!(reply.tool_calls[0].name, "read");
        assert!(reply.tool_calls[0].arguments.contains("a.rs"));
        assert_eq!(reply.usage.input_tokens, 7);
        assert_eq!(reply.usage.cached_input_tokens, 2);
    }

    #[test]
    fn an_anthropic_empty_reply_is_an_error_not_a_panic() {
        assert!(parse_anthropic_reply(r#"{"content":[]}"#).is_err());
        assert!(parse_anthropic_reply("not json").is_err());
    }

    #[test]
    fn provider_detection_is_by_model_not_key_presence() {
        assert_eq!(
            detect_provider("claude-opus-4-6", "https://api.openai.com/v1"),
            Provider::Anthropic
        );
        assert_eq!(
            detect_provider("gpt-4o", "https://api.openai.com/v1"),
            Provider::OpenAi
        );
        // An Anthropic key sitting next to an OpenAI model must not reroute.
        assert_eq!(
            detect_provider("gpt-4o", "https://example.com/v1"),
            Provider::OpenAi
        );
    }

    /// An endpoint that answers every request with `status`, and counts them.
    ///
    /// The count is the whole point: what is under test is how many times the
    /// harness was willing to ask, not what it did with the answer.
    async fn refusing(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, Arc<Mutex<usize>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let address = listener.local_addr().expect("local address");
        let served = Arc::new(Mutex::new(0usize));
        let counted = served.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = Vec::new();
                let mut chunk = [0; 8192];
                // Read until the declared body has arrived, so the client is
                // never answered mid-write.
                loop {
                    let Ok(count) = socket.read(&mut chunk).await else {
                        return;
                    };
                    if count == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..count]);
                    let text = String::from_utf8_lossy(&buffer).into_owned();
                    let Some(header_end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let declared: usize = text[..header_end]
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.trim()
                                .eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().ok())?
                        })
                        .unwrap_or(0);
                    if text.len() - header_end - 4 >= declared {
                        break;
                    }
                }
                *counted.lock().expect("request count") += 1;
                let response = format!(
                    "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        });
        (format!("http://{address}/v1"), served)
    }

    fn task_for(base_url: &str) -> crate::task::Task {
        crate::task::Task {
            instruction: "do the thing".to_owned(),
            repo_path: None,
            validations: Vec::new(),
            max_turns: 4,
            max_requests: 4,
            max_tool_output_bytes: 4096,
            model: Some(crate::task::ModelChoice {
                provider: Some(base_url.to_owned()),
                model: "stub".to_owned(),
                reasoning: None,
            }),
            context_notes: Vec::new(),
        }
    }

    /// A bad key is not a transient failure.
    ///
    /// Previously three total attempts repeated the same permanent refusal.
    /// A loopback endpoint counts requests to prove that only one is sent.
    #[tokio::test]
    async fn a_refused_request_is_not_sent_again() {
        let (base_url, served) =
            refusing("401 Unauthorized", r#"{"error":"invalid api key"}"#).await;
        let client = Client::from_task(&task_for(&base_url)).expect("client");
        let context = Context::new(&task_for(&base_url));
        let error = client
            .complete(&context, &[], 64)
            .await
            .expect_err("a 401 is not a reply");
        assert_eq!(
            *served.lock().expect("request count"),
            1,
            "a refused request was retried"
        );
        // The status, and the provider's own words about it, are what an
        // operator has to work with.
        let text = error.to_string();
        assert!(text.contains("401"), "{text}");
        assert!(text.contains("invalid api key"), "{text}");
        assert!(
            matches!(error, HarnessError::ModelRefused(_)),
            "a refusal must not be classifiable as retryable: {text}"
        );
    }

    /// A 5xx is the endpoint's problem, and a bounded retry is the answer.
    ///
    /// The backoff is what makes this worth keeping: a sandbox is disposable
    /// and a retry costs a second rather than the whole run.
    #[tokio::test]
    async fn a_server_error_is_retried() {
        let (base_url, served) =
            refusing("503 Service Unavailable", r#"{"error":"overloaded"}"#).await;
        let client = Client::from_task(&task_for(&base_url)).expect("client");
        let context = Context::new(&task_for(&base_url));
        let error = client
            .complete(&context, &[], 64)
            .await
            .expect_err("503 on every attempt");
        assert_eq!(
            *served.lock().expect("request count"),
            3,
            "a server error was not retried the bounded number of times"
        );
        assert!(matches!(error, HarnessError::Model(_)), "{error}");
        assert!(error.to_string().contains("503"), "{error}");
    }
}
