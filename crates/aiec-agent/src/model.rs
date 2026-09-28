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
        let base_url = chosen
            .and_then(|c| c.provider.clone())
            .filter(|value| value.starts_with("http"))
            .or_else(|| first_env(BASE_VARS))
            .unwrap_or_else(|| "https://api.openai.com/v1".to_owned());
        let api_key = first_env(KEY_VARS).map(zeroize::Zeroizing::new);
        let reasoning = chosen.and_then(|c| c.reasoning.clone());

        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(600))
            .pool_max_idle_per_host(4)
            .user_agent(concat!("aiec-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| HarnessError::Model(format!("http client: {error}")))?;

        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
            model,
            capabilities: Capabilities {
                tools: true,
                streaming: false,
                usage: true,
                reasoning: reasoning.is_some(),
            },
            reasoning,
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// One completion. Retries transient failures with a bounded backoff.
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
            return Err(HarnessError::Model(format!(
                "provider returned {status}: {}",
                clip(&text, 300)
            )));
        }
        parse_reply(&text)
    }
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

fn first_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|value| !value.trim().is_empty())
}

fn clip(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let kept: String = text.chars().take(limit).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::{HarnessError, ToolCall, parse_reply};

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

    /// Parses a model reply for tests that feed hostile input.
    ///
    /// Exposed rather than duplicated so the tests exercise the real parser rather
    /// than a copy of it that can drift.
    #[doc(hidden)]
    pub fn parse_reply_for_test(text: &str) -> Result<Reply, HarnessError> {
        parse_reply(text)
    }

    #[cfg(test)]

    fn call(name: &str, arguments: &str) -> ToolCall {
        ToolCall {
            id: "1".to_owned(),
            name: name.to_owned(),
            arguments: arguments.to_owned(),
        }
    }

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
        assert!(parse_reply("{}").is_err(), "no choices is not a reply");
    }

    #[test]
    fn the_same_call_with_different_arguments_is_not_a_repeat() {
        let first = call("read", "{\"path\":\"a\"}");
        let second = call("read", "{\"path\":\"b\"}");
        assert_ne!(first.signature(), second.signature());
    }
