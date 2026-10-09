//! The model layer: one interface, several providers, capability-driven.
//!
//! Providers differ in wire format, not in what the loop needs. The loop asks
//! for a completion with capabilities attached and gets back text, tool calls,
//! and whatever usage the provider chose to report.
//!
pub mod anthropic;
pub mod openai;

use serde::{Deserialize, Serialize};

use crate::HarnessError;

/// The one HTTP client for the whole session.
///
/// A fresh client per request is the easiest way for a harness to lose to a
/// bigger one: it redoes the TCP handshake, the TLS negotiation, and the
/// HTTP/2 upgrade on every turn. Built once, here, and handed to the provider.
pub fn http_client() -> Result<reqwest::Client, crate::HarnessError> {
    reqwest::Client::builder()
        .http2_adaptive_window(true)
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300))
        .user_agent(concat!("aiec-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| crate::HarnessError::Model(format!("could not build an http client: {e}")))
}

/// What a provider can actually do. The loop reads these rather than branching
/// on a provider name, so adding a provider is not a change to the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub text: bool,
    pub tool_calling: bool,
    pub reasoning: bool,
    pub streaming: bool,
    pub usage: bool,
    pub cache_metadata: bool,
}

impl Capabilities {
    pub const FULL: Self = Self {
        text: true,
        tool_calling: true,
        reasoning: true,
        streaming: true,
        usage: true,
        cache_metadata: true,
    };

    /// The floor every provider we support meets.
    pub const MINIMAL: Self = Self {
        text: true,
        tool_calling: false,
        reasoning: false,
        streaming: false,
        usage: false,
        cache_metadata: false,
    };
}

/// How hard the model should think, where the provider offers a dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Reasoning {
    #[default]
    Off,
    Low,
    Medium,
    High,
}

impl Reasoning {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Where a model endpoint lives and who it is. Never carries a secret: the key
/// is read from the environment at request time and never stored in this value,
/// so it cannot reach the session file, the result, or a log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelConfig {
    pub provider: Provider,
    pub model: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub reasoning: Reasoning,
    #[serde(default)]
    pub context_window: u32,
    /// Wall-clock ceiling for one `complete`, set by the caller from the task's
    /// own budget.
    ///
    /// A disposable VM does not reward patience. Without this a single request
    /// can spend two minutes in retry backoff in a session whose whole budget
    /// is two, and the retries buy a result nobody will ever read.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// Anything speaking the OpenAI chat-completions shape, which is most
    /// hosted endpoints including local ones.
    OpenAiCompatible,
    Anthropic,
    /// An OpenAI-compatible endpoint behind a different name. Kept distinct so
    /// a result records what actually served the run.
    OpenRouter,
}

impl Provider {
    /// The environment variable holding this provider's key.
    pub fn credential_env(self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC_API_KEY",
            _ => "OPENAI_API_KEY",
        }
    }

    pub fn default_base_url(self) -> &'static str {
        match self {
            Self::Anthropic => "https://api.anthropic.com",
            Self::OpenRouter => "https://openrouter.ai/api/v1",
            Self::OpenAiCompatible => "https://api.openai.com/v1",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenRouter => "openrouter",
            Self::OpenAiCompatible => "openai-compatible",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "openai" | "openai-compatible" | "compat" => Some(Self::OpenAiCompatible),
            "anthropic" | "claude" => Some(Self::Anthropic),
            "openrouter" => Some(Self::OpenRouter),
            _ => None,
        }
    }

    pub fn capabilities(self) -> Capabilities {
        match self {
            Self::Anthropic => Capabilities::FULL,
            _ => Capabilities::FULL,
        }
    }
}

/// One tool the loop is offering, in the neutral shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// A tool the model asked for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// Raw JSON text as the model sent it. Parsed at dispatch so a malformed
    /// argument is a tool error the model can see, not a harness fault.
    pub arguments: String,
}

impl ToolCall {
    /// Identity for loop detection: the same call with the same arguments.
    pub fn signature(&self) -> String {
        format!("{} {}", self.name, self.arguments)
    }
}

/// What a provider reports about a request's cost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

impl Usage {
    pub fn merge(&mut self, other: &Self) {
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cache_read_tokens += other.cache_read_tokens;
        self.cache_write_tokens += other.cache_write_tokens;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stop {
    /// The model says it is finished.
    ModelFinished,
    MaxRequests,
    WallClock,
    NoProgress,
    ContextExhausted,
    ModelError,
}

/// One turn's worth of conversation, in the neutral shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Message {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<ToolCall>,
    },
    /// A tool's result, tied to the call it answers. Screenshots ride beside
    /// the text, never inside it: base64 truncated by compression is a corrupt
    /// image, so images skip `compress_output` end to end.
    Tool {
        call_id: String,
        name: String,
        content: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        images: Vec<ImageBlock>,
    },
}

/// One screenshot in the neutral shape. Both providers accept base64 PNG or
/// JPEG, so the media type is exactly one of those two strings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageBlock {
    pub media_type: String,
    pub data_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub model: String,
    pub reasoning: Reasoning,
    pub max_output_tokens: u32,
}

/// One model's answer.
#[derive(Debug, Clone)]
pub struct Response {
    pub text: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
    pub stop: Stop,
    /// Round trip, so the result can separate model latency from our own cost.
    pub latency_ms: u64,
}

/// The interface the loop talks to. One client for the whole session: a fresh
/// connection per request is the single easiest way to lose to a bigger
/// harness, and it is the cost this design exists to avoid.
pub trait ModelProvider: Send + Sync {
    fn config(&self) -> &ModelConfig;
    fn capabilities(&self) -> Capabilities;

    /// Completes one request. Transient failures are retried inside; a
    /// permanent one comes back as an error.
    ///
    /// Boxed rather than `async fn` so the trait stays object safe: the loop
    /// holds a `Box<dyn ModelProvider>`, so adding a provider is a new file
    /// and not a change here. `async_trait` would achieve the same at the
    /// cost of a proc-macro dependency in a binary whose size is a goal.
    fn complete<'a>(
        &'a self,
        request: &'a Completion,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, HarnessError>> + Send + 'a>,
    >;

    /// Called once at the end so a provider can release anything it holds.
    fn shutdown(&self) {}
}
