//! Wire-level tests for the two model backends.
//!
//! These call the real request builders and the real response parsers, and
//! where retry behaviour is involved they drive the real provider over a real
//! socket against a local server that counts what arrives. Nothing here asserts
//! against a mock's echo of itself: the JSON checked in is the JSON the provider
//! builds, and the request counts are the requests the provider actually made.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aiec_harness::HarnessError;
use aiec_harness::model::anthropic::{self, AnthropicProvider};
use aiec_harness::model::openai::{self, OpenAiProvider, RetryPolicy};
use aiec_harness::model::{
    Completion, Message, ModelConfig, ModelProvider, Provider, Reasoning, Stop, ToolCall, ToolSpec,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------- credentials

/// Sets both provider keys once for this test binary and hands back the OpenAI
/// one.
fn test_key() -> &'static str {
    static KEYS: LazyLock<String> = LazyLock::new(|| {
        // SAFETY: the only mutation of the environment in this binary. Every
        // test calls this before it reaches `credential`, and `LazyLock` holds
        // other threads inside the initializer, so no reader can be looking at
        // the environment while `set_var` runs.
        unsafe {
            std::env::set_var("OPENAI_API_KEY", "sk-test-0123456789abcdef");
            std::env::set_var("ANTHROPIC_API_KEY", "anthropic-test-0123456789");
        }
        "sk-test-0123456789abcdef".to_owned()
    });
    &KEYS
}

fn anthropic_key() -> String {
    test_key();
    std::env::var("ANTHROPIC_API_KEY").expect("set above")
}

// ------------------------------------------------------------------ fixtures
fn tool_specs() -> Vec<ToolSpec> {
    vec![ToolSpec {
        name: "read".to_owned(),
        description: "Reads a file in the repository.".to_owned(),
        parameters: json!({
            "type": "object",
            "properties": { "path": { "type": "string" } },
            "required": ["path"]
        }),
    }]
}

fn call(id: &str, name: &str, arguments: &str) -> ToolCall {
    ToolCall {
        id: id.to_owned(),
        name: name.to_owned(),
        arguments: arguments.to_owned(),
    }
}

/// The conversation that matters: a turn where the model called two tools and
/// both results came back. Every wire format has an opinion about it.
fn conversation() -> Vec<Message> {
    vec![
        Message::System {
            content: "You are a coding agent.".to_owned(),
        },
        Message::User {
            content: "read the two files".to_owned(),
        },
        Message::Assistant {
            text: Some("Reading both.".to_owned()),
            tool_calls: vec![
                call("call_1", "read", r#"{"path":"a.rs"}"#),
                call("call_2", "read", r#"{"path":"b.rs"}"#),
            ],
        },
        Message::Tool {
            call_id: "call_1".to_owned(),
            name: "read".to_owned(),
            content: "contents of a".to_owned(),
            images: Vec::new(),
        },
        Message::Tool {
            call_id: "call_2".to_owned(),
            name: "read".to_owned(),
            content: "contents of b".to_owned(),
            images: Vec::new(),
        },
    ]
}

fn completion() -> Completion {
    Completion {
        messages: conversation(),
        tools: tool_specs(),
        model: "test-model".to_owned(),
        reasoning: Reasoning::Off,
        max_output_tokens: 4096,
    }
}

fn openai_config(base: &str) -> ModelConfig {
    ModelConfig {
        provider: Provider::OpenAiCompatible,
        model: "configured-model".to_owned(),
        base_url: Some(base.to_owned()),
        reasoning: Reasoning::Off,
        context_window: 0,
        deadline_ms: None,
    }
}

fn anthropic_config(base: &str) -> ModelConfig {
    ModelConfig {
        provider: Provider::Anthropic,
        model: "claude".to_owned(),
        base_url: Some(base.to_owned()),
        reasoning: Reasoning::Off,
        context_window: 0,
        deadline_ms: None,
    }
}

/// Retries, but fast enough for a test. Each provider owns its policy type, so
/// the numbers are written once and mapped rather than repeated.
fn quick_retry(attempts: u32) -> RetryPolicy {
    RetryPolicy {
        attempts,
        base_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(20),
        max_total_delay: Duration::from_millis(500),
        // A server's `Retry-After` is not clipped by our own backoff budget,
        // so a test that wants to see the server's number honoured needs this
        // ceiling above one second.
        max_retry_after: Duration::from_secs(5),
    }
}

fn quick_retry_anthropic(attempts: u32) -> anthropic::RetryPolicy {
    let openai = quick_retry(attempts);
    anthropic::RetryPolicy {
        attempts: openai.attempts,
        base_delay: openai.base_delay,
        max_delay: openai.max_delay,
        max_total_delay: openai.max_total_delay,
        max_retry_after: openai.max_retry_after,
    }
}

// ------------------------------------------------------------ a fake endpoint

struct Reply {
    status: u16,
    body: String,
    retry_after: Option<u32>,
}

impl Reply {
    fn ok(body: &str) -> Self {
        Self {
            status: 200,
            body: body.to_owned(),
            retry_after: None,
        }
    }

    fn status(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_owned(),
            retry_after: None,
        }
    }

    fn throttled(body: &str, retry_after: u32) -> Self {
        Self {
            status: 429,
            body: body.to_owned(),
            retry_after: Some(retry_after),
        }
    }
}

/// A one-connection-per-request HTTP server: `connection: close` keeps each
/// request on its own socket, so the number of accepted connections is exactly
/// the number of attempts the provider made.
struct Fake {
    addr: SocketAddr,
    raw: Arc<Mutex<Vec<String>>>,
    finished: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Fake {
    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn request_count(&self) -> usize {
        self.raw.lock().expect("not poisoned").len()
    }

    fn requests(&self) -> Vec<String> {
        self.raw.lock().expect("not poisoned").clone()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        // The accept loop is parked in `incoming`; one connection wakes it so
        // the thread ends with the test rather than outliving it. The flag is
        // what actually ends it, because that wake-up connection is itself a
        // request the loop would otherwise serve.
        self.finished.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(replies: Vec<Reply>) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
    let addr = listener.local_addr().expect("an address");
    let raw: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let finished: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&finished);
    let sink = Arc::clone(&raw);
    let thread = std::thread::spawn(move || {
        let mut served = 0usize;
        for stream in listener.incoming() {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = stream else { break };
            let Ok(request) = read_request(&mut stream) else {
                continue;
            };
            if sink.lock().map(|mut g| g.push(request)).is_err() {
                break;
            }
            // The last reply repeats, so a test that expects a second attempt
            // gets the same answer again.
            let Some(reply) = replies.get(served).or_else(|| replies.last()) else {
                break;
            };
            served += 1;
            let _ = write_reply(&mut stream, reply);
        }
    });
    Fake {
        addr,
        raw,
        finished,
        thread: Some(thread),
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut header_end = None;
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
        if header_end.is_none() {
            header_end = raw
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|at| at + 4);
        }
        if let Some(end) = header_end {
            let head = String::from_utf8_lossy(&raw[..end]).to_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if raw.len() >= end + length {
                break;
            }
        }
    }
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

fn write_reply(stream: &mut TcpStream, reply: &Reply) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        reply.status,
        reason(reply.status),
        reply.body.len(),
    );
    if let Some(seconds) = reply.retry_after {
        head.push_str(&format!("retry-after: {seconds}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(reply.body.as_bytes())?;
    stream.flush()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

fn body_of(raw: &str) -> &str {
    raw.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn header(raw: &str, name: &str) -> Option<String> {
    raw.split("\r\n\r\n").next()?.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().eq_ignore_ascii_case(name)).then(|| value.trim().to_owned())
    })
}

// ------------------------------------------------------- the OpenAI request

#[test]
fn the_openai_request_is_the_chat_completions_shape() {
    let config = openai_config("https://example.invalid/v1");
    let body = openai::build_request_body(&config, &completion());

    assert_eq!(body["model"], json!("test-model"));
    assert_eq!(body["max_tokens"], json!(4096));
    assert_eq!(
        body["stream"],
        json!(true),
        "the request should ask for a stream"
    );

    let tools = body["tools"].as_array().expect("an array");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["type"], json!("function"));
    assert_eq!(tools[0]["function"]["name"], json!("read"));
    assert_eq!(
        tools[0]["function"]["parameters"]["required"],
        json!(["path"])
    );

    let messages = body["messages"].as_array().expect("an array");
    assert_eq!(messages.len(), 5, "every turn is sent, in order");
    assert_eq!(messages[0]["role"], json!("system"));
    assert_eq!(messages[0]["content"], json!("You are a coding agent."));
    assert_eq!(messages[1]["role"], json!("user"));

    // The assistant turn carries both its text and its calls, and the arguments
    // are a JSON *string*, which is the whole reason the neutral shape holds
    // raw text.
    let assistant = &messages[2];
    assert_eq!(assistant["role"], json!("assistant"));
    assert_eq!(assistant["content"], json!("Reading both."));
    let calls = assistant["tool_calls"].as_array().expect("an array");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["type"], json!("function"));
    assert_eq!(calls[0]["id"], json!("call_1"));
    assert_eq!(calls[0]["function"]["name"], json!("read"));
    assert_eq!(
        calls[0]["function"]["arguments"],
        json!(r#"{"path":"a.rs"}"#)
    );

    // A tool result is its own turn, tied to the call it answers.
    assert_eq!(messages[3]["role"], json!("tool"));
    assert_eq!(messages[3]["tool_call_id"], json!("call_1"));
    assert_eq!(messages[3]["content"], json!("contents of a"));
    assert_eq!(messages[4]["tool_call_id"], json!("call_2"));
}

#[test]
fn an_assistant_turn_with_only_tool_calls_sends_null_content() {
    // Not "" and not omitted: the schema requires the key and allows null, and
    // an empty string reads to some servers as "the model said nothing".
    let config = openai_config("https://example.invalid/v1");
    let mut request = completion();
    request.messages = vec![Message::Assistant {
        text: None,
        tool_calls: vec![call("call_1", "read", "{}")],
    }];
    let body = openai::build_request_body(&config, &request);
    let assistant = &body["messages"].as_array().expect("an array")[0];
    assert_eq!(assistant["content"], Value::Null);
    assert_eq!(assistant["tool_calls"].as_array().map(Vec::len), Some(1));
}

#[test]
fn an_empty_completion_model_falls_back_to_the_configured_one() {
    let config = openai_config("https://example.invalid/v1");
    let mut request = completion();
    request.model = String::new();
    let body = openai::build_request_body(&config, &request);
    assert_eq!(body["model"], json!("configured-model"));
}

#[test]
fn no_tools_means_no_tool_fields_at_all() {
    let config = openai_config("https://example.invalid/v1");
    let mut request = completion();
    request.tools.clear();
    let body = openai::build_request_body(&config, &request);
    assert!(body.get("tools").is_none());
    assert!(body.get("tool_choice").is_none());
}

// ------------------------------------------------------ the Anthropic request

#[test]
fn the_anthropic_request_takes_the_system_prompt_out_of_band() {
    let config = anthropic_config("https://example.invalid");
    let body = anthropic::build_request_body(&config, &completion());

    assert_eq!(body["model"], json!("test-model"));
    // The Anthropic path is not streamed. Its event format is a different
    // shape and is not implemented; claiming otherwise would be worse than
    // the latency it costs.
    assert_eq!(body["stream"], json!(false));
    // Out of band, not the first message: a conversation that opens with a
    // system turn is refused by the API.
    assert_eq!(body["system"], json!("You are a coding agent."));

    let tools = body["tools"].as_array().expect("an array");
    assert_eq!(tools[0]["name"], json!("read"));
    assert_eq!(
        tools[0]["input_schema"]["properties"]["path"]["type"],
        json!("string"),
        "the schema key is input_schema here, parameters on the other wire"
    );
    assert!(
        body["tools"][0].get("parameters").is_none(),
        "the OpenAI key is a hard error on this API"
    );

    let messages = body["messages"].as_array().expect("an array");
    assert_eq!(messages.len(), 3, "system is out of band, so three turns");
    assert_eq!(messages[0]["role"], json!("user"));
    assert_eq!(messages[0]["content"][0]["type"], json!("text"));
    assert_eq!(
        messages[0]["content"][0]["text"],
        json!("read the two files")
    );

    // Assistant content is a typed block array: text first, then the calls.
    let assistant = &messages[1];
    assert_eq!(assistant["role"], json!("assistant"));
    let blocks = assistant["content"].as_array().expect("an array");
    assert_eq!(blocks[0]["type"], json!("text"));
    assert_eq!(blocks[0]["text"], json!("Reading both."));
    assert_eq!(blocks[1]["type"], json!("tool_use"));
    assert_eq!(blocks[1]["id"], json!("call_1"));
    assert_eq!(blocks[1]["name"], json!("read"));
    // An object here, not a string: the neutral arguments are re-parsed.
    assert_eq!(blocks[1]["input"], json!({"path": "a.rs"}));
    assert_eq!(blocks[2]["id"], json!("call_2"));
    assert_eq!(blocks[2]["input"], json!({"path": "b.rs"}));
}

#[test]
fn consecutive_tool_results_become_one_user_turn() {
    // Two user turns in a row is an error on this API, and parallel tool calls
    // produce exactly that unless the results are merged.
    let config = anthropic_config("https://example.invalid");
    let body = anthropic::build_request_body(&config, &completion());
    let messages = body["messages"].as_array().expect("an array");
    let last = messages.last().expect("a last turn");
    assert_eq!(last["role"], json!("user"));
    let blocks = last["content"].as_array().expect("an array");
    assert_eq!(blocks.len(), 2, "both results ride in one user turn");
    assert_eq!(blocks[0]["type"], json!("tool_result"));
    assert_eq!(blocks[0]["tool_use_id"], json!("call_1"));
    assert_eq!(blocks[0]["content"], json!("contents of a"));
    assert_eq!(blocks[1]["tool_use_id"], json!("call_2"));
}

#[test]
fn a_malformed_argument_object_is_wrapped_rather_than_dropped() {
    // The model produced this text and dispatch already complained about it.
    // Dropping the call would send a request that answers a question the model
    // never asked, so it is wrapped and the loop keeps its turn.
    let config = anthropic_config("https://example.invalid");
    let mut request = completion();
    request.messages = vec![Message::Assistant {
        text: None,
        tool_calls: vec![call("call_1", "read", "{not json at all")],
    }];
    let body = anthropic::build_request_body(&config, &request);
    let input = &body["messages"][0]["content"][0]["input"];
    assert_eq!(input["__raw"], json!("{not json at all"));
}

#[test]
fn no_system_turn_means_no_system_field() {
    let config = anthropic_config("https://example.invalid");
    let mut request = completion();
    request
        .messages
        .retain(|message| !matches!(message, Message::System { .. }));
    let body = anthropic::build_request_body(&config, &request);
    assert!(body.get("system").is_none());
}

// ------------------------------------------------------------ usage mapping

#[test]
fn an_openai_usage_block_maps_onto_the_neutral_usage() {
    let raw = json!({
        "choices": [{"message": {"content": "done", "tool_calls": []}}],
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 34,
            "total_tokens": 154,
            "prompt_tokens_details": { "cached_tokens": 90 }
        }
    });
    let response = openai::parse_response(&raw.to_string(), 0).expect("parsed");
    assert_eq!(response.usage.input_tokens, 120);
    assert_eq!(response.usage.output_tokens, 34);
    assert_eq!(response.usage.cache_read_tokens, 90);
    assert_eq!(response.usage.cache_write_tokens, 0);
}

#[test]
fn an_openai_gateway_reporting_cache_writes_is_credited() {
    let raw = json!({
        "choices": [{"message": {"content": null, "tool_calls": []}}],
        "usage": { "prompt_tokens": 10, "completion_tokens": 2, "cache_creation_input_tokens": 7 }
    });
    let response = openai::parse_response(&raw.to_string(), 0).expect("parsed");
    assert_eq!(response.usage.cache_write_tokens, 7);
}

#[test]
fn an_anthropic_usage_block_maps_onto_the_neutral_usage() {
    let raw = json!({
        "content": [{ "type": "text", "text": "done" }],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 120,
            "output_tokens": 34,
            "cache_read_input_tokens": 100,
            "cache_creation_input_tokens": 20
        }
    });
    let response = anthropic::parse_response(&raw.to_string(), 0).expect("parsed");
    assert_eq!(response.usage.input_tokens, 120);
    assert_eq!(response.usage.output_tokens, 34);
    assert_eq!(response.usage.cache_read_tokens, 100);
    assert_eq!(response.usage.cache_write_tokens, 20);
}

#[test]
fn a_reply_with_no_usage_reports_none_rather_than_failing() {
    let raw = json!({ "choices": [{ "message": { "content": "hi" } }] });
    let response = openai::parse_response(&raw.to_string(), 0).expect("parsed");
    assert_eq!(response.usage.input_tokens, 0);
}

// --------------------------------------------------------- hostile responses

#[test]
fn a_reply_with_no_choices_is_an_error_not_a_panic() {
    let error = openai::parse_response(r#"{"choices":[]}"#, 0).expect_err("no choices is no reply");
    assert!(matches!(error, HarnessError::Model(_)), "{error:?}");
    assert!(error.to_string().contains("no choices"), "{error}");
}

#[test]
fn an_object_with_no_choices_key_is_an_error_not_a_panic() {
    let error = openai::parse_response("{}", 0).expect_err("empty object is not a reply");
    assert!(matches!(error, HarnessError::Model(_)), "{error:?}");
}

#[test]
fn an_empty_content_array_is_an_error_not_a_panic() {
    // Nothing to show the model and nothing to dispatch: reporting a finished
    // turn here would end the session with no work done.
    for raw in [r#"{"content":[]}"#, r#"{"content":null}"#, "{}"] {
        let error = anthropic::parse_response(raw, 0).expect_err("an empty reply is not a reply");
        assert!(matches!(error, HarnessError::Model(_)), "{raw}: {error:?}");
    }
}

#[test]
fn malformed_json_is_an_error_not_a_panic() {
    for provider in ["openai", "anthropic"] {
        let error = if provider == "openai" {
            openai::parse_response("<html>gateway timeout</html>", 0)
        } else {
            anthropic::parse_response("not json", 0)
        };
        let error = error.expect_err("not json is not a reply");
        assert!(matches!(error, HarnessError::Model(_)), "{error:?}");
    }
}

#[test]
fn a_provider_error_envelope_is_surfaced_even_on_a_success() {
    let raw = json!({ "error": { "message": "model not found" } });
    let error = openai::parse_response(&raw.to_string(), 0).expect_err("an error envelope");
    assert!(error.to_string().contains("model not found"), "{error}");
}

#[test]
fn a_garbage_tool_call_does_not_take_the_reply_down_with_it() {
    let raw = json!({
        "choices": [{ "message": { "content": null, "tool_calls": [
            { "function": { "name": "read" } },
            { "id": "c2", "type": "function", "function": { "name": "write", "arguments": "{}" } }
        ] }}]
    });
    let response = openai::parse_response(&raw.to_string(), 0).expect("parsed");
    assert_eq!(response.tool_calls.len(), 2);
    // A call with no arguments still has to be dispatchable.
    assert_eq!(response.tool_calls[0].arguments, "{}");
    assert_eq!(response.tool_calls[0].id, "");
}

// --------------------------------------------------------- tool call shapes

#[test]
fn an_openai_tool_call_keeps_its_arguments_as_a_json_string() {
    let raw = json!({
        "choices": [{ "message": { "content": null, "tool_calls": [
            { "id": "call_1", "type": "function",
              "function": { "name": "read", "arguments": r#"{"path":"a.rs","limit":20}"# } }
        ] }, "finish_reason": "tool_calls" }]
    });
    let response = openai::parse_response(&raw.to_string(), 0).expect("parsed");
    let call = response.tool_calls.first().expect("a call");
    assert_eq!(call.name, "read");
    let parsed: Value = serde_json::from_str(&call.arguments).expect("a JSON string");
    assert_eq!(parsed["path"], json!("a.rs"));
    assert_eq!(parsed["limit"], json!(20));
}

#[test]
fn an_anthropic_tool_call_comes_back_as_a_json_string() {
    // The wire carries an object and the neutral shape carries a string, so
    // this is a real conversion, not a pass-through.
    let raw = json!({
        "content": [
            { "type": "text", "text": "Let me look." },
            { "type": "tool_use", "id": "toolu_1", "name": "read", "input": { "path": "a.rs" } },
            { "type": "thinking", "thinking": "not ours" }
        ],
        "stop_reason": "tool_use"
    });
    let response = anthropic::parse_response(&raw.to_string(), 0).expect("parsed");
    let call = response.tool_calls.first().expect("a call");
    assert_eq!(call.id, "toolu_1");
    assert_eq!(call.name, "read");
    let parsed: Value = serde_json::from_str(&call.arguments).expect("a JSON string");
    assert_eq!(parsed, json!({"path": "a.rs"}));
    assert_eq!(response.text.as_deref(), Some("Let me look."));
    assert_eq!(
        response.tool_calls.len(),
        1,
        "unknown block kinds are skipped"
    );
}

#[test]
fn interleaved_anthropic_text_blocks_are_joined() {
    let raw = json!({
        "content": [
            { "type": "text", "text": "one " },
            { "type": "tool_use", "id": "t", "name": "read", "input": {} },
            { "type": "text", "text": "two" }
        ],
        "stop_reason": "tool_use"
    });
    let response = anthropic::parse_response(&raw.to_string(), 0).expect("parsed");
    assert_eq!(response.text.as_deref(), Some("one two"));
    assert_eq!(response.tool_calls.len(), 1);
}

#[test]
fn an_empty_text_reply_is_no_text_rather_than_an_empty_string() {
    let raw = json!({ "choices": [{ "message": { "content": "" }, "finish_reason": "stop" }] });
    let response = openai::parse_response(&raw.to_string(), 0).expect("parsed");
    assert_eq!(response.text, None);
}

// ---------------------------------------------------------------- stop rules

#[test]
fn a_tool_call_and_a_stop_are_not_exclusive() {
    let raw = json!({
        "choices": [{ "message": { "content": null, "tool_calls": [
            { "id": "c", "type": "function", "function": { "name": "read", "arguments": "{}" } }
        ] }, "finish_reason": "tool_calls" }]
    });
    let response = openai::parse_response(&raw.to_string(), 0).expect("parsed");
    assert_eq!(response.stop, Stop::ModelFinished);
    assert_eq!(response.tool_calls.len(), 1, "the call survives the stop");

    let raw = json!({
        "content": [{ "type": "tool_use", "id": "t", "name": "read", "input": {} }],
        "stop_reason": "tool_use"
    });
    let response = anthropic::parse_response(&raw.to_string(), 0).expect("parsed");
    assert_eq!(response.stop, Stop::ModelFinished);
}

#[test]
fn a_truncated_reply_is_not_reported_as_a_finished_one() {
    // A turn cut off mid-JSON must not read as a complete answer.
    assert_eq!(openai::stop(Some("length")), Stop::ModelError);
    assert_eq!(openai::stop(Some("max_tokens")), Stop::ModelError);
    assert_eq!(anthropic::stop(Some("max_tokens")), Stop::ModelError);
    assert_eq!(openai::stop(Some("stop")), Stop::ModelFinished);
    assert_eq!(anthropic::stop(Some("end_turn")), Stop::ModelFinished);
    // An endpoint that invents a finish reason should not stall the loop.
    assert_eq!(openai::stop(Some("something_new")), Stop::ModelFinished);
    assert_eq!(openai::stop(None), Stop::ModelFinished);
}

#[test]
fn the_measured_round_trip_is_reported() {
    let raw = json!({ "choices": [{ "message": { "content": "hi" } }] });
    let response = openai::parse_response(&raw.to_string(), 4242).expect("parsed");
    assert_eq!(response.latency_ms, 4242);
}

// ------------------------------------------------------------- over a socket

#[tokio::test]
async fn what_the_provider_sends_is_what_the_builder_built() {
    let key = test_key();
    let fake = serve(vec![Reply::ok(
        r#"{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}"#,
    )]);
    let config = openai_config(&fake.base_url());
    let provider = OpenAiProvider::with_retry(
        config,
        aiec_harness::model::http_client().unwrap(),
        quick_retry(1),
    );
    let request = completion();

    let response = provider.complete(&request).await.expect("a reply");
    assert_eq!(response.text.as_deref(), Some("ok"));

    let sent = fake.requests();
    assert_eq!(sent.len(), 1);
    let body: Value = serde_json::from_str(body_of(&sent[0])).expect("the body is JSON");
    let expected = openai::build_request_body(provider.config(), &request);
    assert_eq!(body, expected, "the wire matches the builder exactly");
    assert_eq!(
        header(&sent[0], "authorization").as_deref(),
        Some(format!("Bearer {key}").as_str()),
        "the key goes in the header, and nowhere else"
    );
}

#[tokio::test]
async fn the_anthropic_provider_sends_its_own_headers_and_key() {
    let key = anthropic_key();
    let fake = serve(vec![Reply::ok(
        r#"{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}"#,
    )]);
    let config = anthropic_config(&fake.base_url());
    let provider = AnthropicProvider::with_retry(
        config,
        aiec_harness::model::http_client().unwrap(),
        quick_retry_anthropic(1),
    );

    provider.complete(&completion()).await.expect("a reply");

    let sent = fake.requests();
    assert_eq!(sent.len(), 1);
    let raw = &sent[0];
    assert_eq!(header(raw, "x-api-key").as_deref(), Some(key.as_str()));
    assert_eq!(
        header(raw, "anthropic-version").as_deref(),
        Some("2023-06-01")
    );
    assert!(raw.starts_with("POST /v1/messages "), "{raw}");
    let body: Value = serde_json::from_str(body_of(raw)).expect("the body is JSON");
    assert_eq!(
        body,
        anthropic::build_request_body(provider.config(), &completion())
    );
}

#[tokio::test]
async fn a_permanent_status_is_not_retried() {
    let fake = serve(vec![Reply::status(
        400,
        r#"{"error":{"message":"bad request"}}"#,
    )]);
    let config = openai_config(&fake.base_url());
    let provider = OpenAiProvider::with_retry(
        config,
        aiec_harness::model::http_client().unwrap(),
        quick_retry(4),
    );

    let error = provider
        .complete(&completion())
        .await
        .expect_err("400 is fatal");
    assert!(matches!(error, HarnessError::Model(_)), "{error:?}");
    assert!(error.to_string().contains("400"), "{error}");
    assert_eq!(
        fake.request_count(),
        1,
        "a bad request is exactly as wrong the second time"
    );
}

#[tokio::test]
async fn a_rejected_key_is_not_retried_either() {
    let fake = serve(vec![Reply::status(
        401,
        r#"{"error":{"message":"invalid api key"}}"#,
    )]);
    let config = openai_config(&fake.base_url());
    let provider = OpenAiProvider::with_retry(
        config,
        aiec_harness::model::http_client().unwrap(),
        quick_retry(4),
    );

    let error = provider
        .complete(&completion())
        .await
        .expect_err("401 is fatal");
    assert!(error.to_string().contains("401"), "{error}");
    assert_eq!(fake.request_count(), 1);
}

#[tokio::test]
async fn a_throttled_request_is_retried_and_can_still_succeed() {
    let fake = serve(vec![
        Reply::status(500, r#"{"error":{"message":"upstream"}}"#),
        Reply::ok(r#"{"choices":[{"message":{"content":"recovered"},"finish_reason":"stop"}]}"#),
    ]);
    let config = openai_config(&fake.base_url());
    let provider = OpenAiProvider::with_retry(
        config,
        aiec_harness::model::http_client().unwrap(),
        quick_retry(4),
    );

    let response = provider.complete(&completion()).await.expect("recovered");
    assert_eq!(response.text.as_deref(), Some("recovered"));
    assert_eq!(fake.request_count(), 2, "one failure, one success");
}

#[tokio::test]
async fn retries_are_bounded_and_end_as_a_retry_error() {
    let fake = serve(vec![Reply::throttled(
        r#"{"error":{"message":"slow down"}}"#,
        0,
    )]);
    let config = anthropic_config(&fake.base_url());
    let provider = AnthropicProvider::with_retry(
        config,
        aiec_harness::model::http_client().unwrap(),
        quick_retry_anthropic(3),
    );

    let started = Instant::now();
    let error = provider
        .complete(&completion())
        .await
        .expect_err("never succeeds");
    assert!(
        matches!(error, HarnessError::RetriesExhausted(_)),
        "{error:?}"
    );
    assert_eq!(
        fake.request_count(),
        3,
        "attempts are capped, not unbounded"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the retry budget is bounded in time, not just in attempts"
    );
}

#[tokio::test]
async fn a_retry_after_header_is_obeyed() {
    // The backoff is twenty milliseconds; a one second `Retry-After` is only
    // visible if the server's number won over our own impatience.
    let fake = serve(vec![
        Reply::throttled(r#"{"error":{"message":"slow down"}}"#, 1),
        Reply::ok(r#"{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}"#),
    ]);
    let config = openai_config(&fake.base_url());
    let provider = OpenAiProvider::with_retry(
        config,
        aiec_harness::model::http_client().unwrap(),
        RetryPolicy {
            attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(20),
            max_total_delay: Duration::from_secs(5),
            max_retry_after: Duration::from_secs(5),
        },
    );

    let started = Instant::now();
    provider.complete(&completion()).await.expect("recovered");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "waited as asked"
    );
    assert_eq!(fake.request_count(), 2);
}

#[tokio::test]
async fn a_retry_after_beyond_the_ceiling_is_clipped() {
    // Honoring a server is not the same as obeying it forever: a throttled
    // endpoint asking for five minutes must not park the session for five
    // minutes.
    let fake = serve(vec![
        Reply::throttled(r#"{"error":{"message":"come back later"}}"#, 300),
        Reply::ok(r#"{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}"#),
    ]);
    let config = openai_config(&fake.base_url());
    let provider = OpenAiProvider::with_retry(
        config,
        aiec_harness::model::http_client().unwrap(),
        RetryPolicy {
            max_retry_after: Duration::from_millis(50),
            ..quick_retry(3)
        },
    );

    let started = Instant::now();
    provider.complete(&completion()).await.expect("recovered");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "five minutes became a nap"
    );
    assert_eq!(fake.request_count(), 2);
}

// ----------------------------------------------------------- the credential

#[tokio::test]
async fn a_key_echoed_back_by_a_gateway_never_reaches_the_error() {
    let key = test_key().to_owned();
    let fake = serve(vec![Reply::status(
        401,
        &format!(r#"{{"error":{{"message":"invalid key {key}"}}}}"#),
    )]);
    let config = openai_config(&fake.base_url());
    let provider = OpenAiProvider::with_retry(
        config,
        aiec_harness::model::http_client().unwrap(),
        quick_retry(1),
    );

    let error = provider
        .complete(&completion())
        .await
        .expect_err("401 is fatal");
    let text = error.to_string();
    assert!(
        !text.contains(&key),
        "the key leaked into the error: {text}"
    );
    assert!(text.contains("redacted"), "{text}");
    assert!(text.contains("401"), "{text}");
}

#[test]
fn a_key_cannot_be_reached_through_the_provider_or_its_config() {
    let key = test_key();
    let config = openai_config("https://example.invalid/v1");
    let provider = OpenAiProvider::new(config.clone(), aiec_harness::model::http_client().unwrap());

    assert!(!format!("{provider:?}").contains(key));
    let anthropic = AnthropicProvider::new(
        anthropic_config("https://example.invalid"),
        aiec_harness::model::http_client().unwrap(),
    );
    assert!(!format!("{anthropic:?}").contains(key));
    assert!(
        !serde_json::to_string(&config)
            .expect("serialisable")
            .contains(key),
        "the config is what reaches the session file"
    );
}

#[test]
fn the_base_url_is_normalized_for_both_providers() {
    let openai = OpenAiProvider::new(openai_config("http://localhost:1234/v1/"), http());
    assert_eq!(openai.base_url(), "http://localhost:1234/v1");
    // A version already on the base is not doubled: that 404 looks like a
    // routing problem and costs an afternoon.
    let anthropic = AnthropicProvider::new(anthropic_config("https://proxy.invalid/v1"), http());
    assert_eq!(anthropic.base_url(), "https://proxy.invalid/v1");
    let bare = AnthropicProvider::new(
        ModelConfig {
            base_url: None,
            ..anthropic_config("unused")
        },
        http(),
    );
    assert_eq!(bare.base_url(), "https://api.anthropic.com");
}

fn http() -> reqwest::Client {
    aiec_harness::model::http_client().expect("a client")
}

// ------------------------------------------------------------ stream decoding

/// A real streamed reply, in the shape an OpenAI-compatible endpoint sends:
/// a sequence of `data:` frames, the accumulated values spread across them.
fn sse(frames: &[&str]) -> String {
    frames
        .iter()
        .map(|f| format!("data: {f}\n\n"))
        .chain(std::iter::once("data: [DONE]\n\n".to_owned()))
        .collect()
}

#[test]
fn a_streamed_text_reply_is_assembled_into_the_whole_answer() {
    let body = sse(&[
        r#"{"choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":", "},"finish_reason":null}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"world"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":4}}"#,
    ]);
    let response = openai::parse_response(&body, 7).expect("parsed");
    assert_eq!(response.text.as_deref(), Some("Hello, world"));
    assert_eq!(response.usage.input_tokens, 11);
    assert_eq!(response.usage.output_tokens, 4);
    assert_eq!(response.latency_ms, 7);
}

#[test]
fn a_streamed_tool_call_is_reassembled_across_frames() {
    // The name and the arguments arrive in different frames, which is the
    // normal case and the one that breaks a naive line-by-line reader.
    let body = sse(&[
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"read","arguments":""}}]},"finish_reason":null}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":"}}]},"finish_reason":null}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"a.rs\"}"}}]},"finish_reason":"tool_calls"}]}"#,
    ]);
    let response = openai::parse_response(&body, 0).expect("parsed");
    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "read");
    assert_eq!(response.tool_calls[0].id, "call_1");
    // The reassembled arguments must still be valid json, or the dispatcher
    // will report a model syntax error as a tool failure.
    let args: serde_json::Value =
        serde_json::from_str(&response.tool_calls[0].arguments).expect("arguments are json");
    assert_eq!(args["path"], "a.rs");
}

#[test]
fn parallel_tool_calls_are_kept_apart_by_index() {
    let body = sse(&[
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"read","arguments":"{}"}}]},"finish_reason":null}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"bash","arguments":"{}"}}]},"finish_reason":null}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":\"x\"}"}}]},"finish_reason":null}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"command\":[\"ls\"]}"}}]},"finish_reason":"tool_calls"}]}"#,
    ]);
    let response = openai::parse_response(&body, 0).expect("parsed");
    assert_eq!(response.tool_calls.len(), 2);
    let read = response
        .tool_calls
        .iter()
        .find(|c| c.name == "read")
        .expect("read");
    let bash = response
        .tool_calls
        .iter()
        .find(|c| c.name == "bash")
        .expect("bash");
    assert!(read.arguments.contains("x"));
    assert!(bash.arguments.contains("ls"));
}

#[test]
fn a_data_field_wrapped_over_several_lines_is_one_event() {
    // A long payload is wrapped, and every line of it carries the `data:`
    // prefix. Reading line by line would treat each fragment as its own event
    // and lose everything.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a long\"\n",
        "data: }}],\"usage\":{\"prompt_tokens\":7}}\n\n",
        "data: [DONE]\n\n",
    );
    let response = openai::parse_response(body, 0).expect("parsed");
    assert_eq!(response.text.as_deref(), Some("a long"));
    assert_eq!(response.usage.input_tokens, 7);
}

#[test]
fn carriage_returns_do_not_break_event_framing() {
    let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"cr\"},\"finish_reason\":\"stop\"}]}\r\n\r\ndata: [DONE]\r\n\r\n";
    let response = openai::parse_response(body, 0).expect("parsed");
    assert_eq!(response.text.as_deref(), Some("cr"));
}

#[test]
fn an_endpoint_that_ignores_streaming_is_still_understood() {
    // Some endpoints answer a streaming request with one ordinary object.
    let body = r#"{"choices":[{"index":0,"message":{"content":"whole"},"finish_reason":"stop"}]}"#;
    let response = openai::parse_response(body, 0).expect("parsed");
    assert_eq!(response.text.as_deref(), Some("whole"));
}

#[test]
fn a_hostile_or_truncated_stream_does_not_panic() {
    for body in [
        "data: [DONE]\n\n",
        "data: \n\ndata: [DONE]\n\n",
        "data: {not json}\n\ndata: [DONE]\n\n",
        "data: {\"choices\":[]}\n\ndata: [DONE]\n\n",
        "data: {\"choices\":[{\"delta\":{}}]}\n\n",
        "",
        "data:",
        "event: message\ndata: {}\n\n",
    ] {
        // The only requirement is that it returns rather than unwinds.
        let _ = openai::parse_response(body, 0);
    }
}

#[test]
fn a_tool_result_with_a_screenshot_renders_on_both_wires() {
    use aiec_harness::model::ImageBlock;
    let shot = ImageBlock {
        media_type: "image/png".to_owned(),
        data_base64: "iVBORw0KGgo=".to_owned(),
    };
    let messages = vec![Message::Tool {
        call_id: "shot_1".to_owned(),
        name: "browser".to_owned(),
        content: "page loaded".to_owned(),
        images: vec![shot],
    }];
    let completion = Completion {
        messages,
        tools: vec![],
        model: "test-model".to_owned(),
        reasoning: Reasoning::Off,
        max_output_tokens: 4096,
    };
    let config = openai_config("http://127.0.0.1:1");
    let openai_body = openai::build_request_body(&config, &completion);
    let tool = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|m| m.first())
        .expect("one message");
    assert_eq!(tool.get("role").and_then(Value::as_str), Some("tool"));
    let parts = tool
        .get("content")
        .and_then(Value::as_array)
        .expect("array content");
    assert_eq!(parts.len(), 2);
    assert_eq!(
        parts[1].pointer("/image_url/url").and_then(Value::as_str),
        Some("data:image/png;base64,iVBORw0KGgo=")
    );

    let aconfig = anthropic_config("http://127.0.0.1:1");
    let anthropic_body = anthropic::build_request_body(&aconfig, &completion);
    let user = anthropic_body
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|m| m.first())
        .expect("one message");
    let blocks = user
        .get("content")
        .and_then(Value::as_array)
        .expect("blocks");
    assert_eq!(blocks.len(), 2);
    assert_eq!(
        blocks[0].get("type").and_then(Value::as_str),
        Some("tool_result")
    );
    assert_eq!(
        blocks[1].pointer("/source/data").and_then(Value::as_str),
        Some("iVBORw0KGgo=")
    );
}

#[test]
fn a_tool_result_without_images_keeps_the_old_string_shape() {
    // The images field defaults to empty on the wire, so text-only results
    // serialize exactly as before: a string, not a one-element array.
    let completion = completion();
    let config = openai_config("http://127.0.0.1:1");
    let body = openai::build_request_body(&config, &completion);
    let first = body
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|m| {
            m.iter()
                .find(|m| m.get("role").and_then(Value::as_str) == Some("tool"))
        })
        .expect("a tool message");
    assert!(first.get("content").and_then(Value::as_str).is_some());
}
