//! The agent loop, driven end to end against a stub model endpoint.
//!
//! The unit tests in the crate cover the pieces. This covers the wiring, which
//! is where the interesting failure was: the model asked for a tool, the tool
//! ran, and the transcript the model saw next turn was not a transcript - the
//! calls it had made were missing and the results carried no id, so nothing
//! said which question each result answered.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aiec_agent::agent;
use aiec_agent::task::{ModelChoice, Result_, StopReason, Task};

/// A model endpoint that answers a fixed script and records what it was sent.
struct StubModel {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl StubModel {
    /// `replies` are returned in order, one per request; the last one repeats.
    async fn start(replies: Vec<String>) -> StubModel {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let address = listener.local_addr().expect("local address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let handle = tokio::spawn(async move {
            let mut served = 0usize;
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = Vec::new();
                let mut chunk = [0; 8192];
                // Read until the headers are complete and the declared body has
                // arrived, which is all a request of this shape needs.
                let body = loop {
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
                        break text[header_end + 4..header_end + 4 + declared].to_owned();
                    }
                };
                seen.lock().expect("request log").push(body);
                let mut reply = replies
                    .get(served.min(replies.len().saturating_sub(1)))
                    .cloned()
                    .unwrap_or_default();
                // `{n}` becomes this request's number, so a scripted model can
                // vary its calls: a harness that repeats one call verbatim is
                // meant to notice, and that guard would end the run long before
                // the test's own ceiling.
                reply = reply.replace("{n}", &served.to_string());
                served += 1;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        });
        StubModel {
            base_url: format!("http://{address}/v1"),
            requests,
            handle,
        }
    }

    fn sent(&self) -> Vec<String> {
        self.requests.lock().expect("request log").clone()
    }
}

impl Drop for StubModel {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A repository with one commit, which is what the harness opens.
fn repository(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("aiec-loop-{label}-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&path).expect("scratch directory");
    let git = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(&path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
        assert!(status.success(), "git {args:?} failed");
    };
    git(&["init", "--quiet"]);
    git(&["config", "user.email", "harness@example.invalid"]);
    git(&["config", "user.name", "harness"]);
    std::fs::write(path.join("README.md"), "one\n").expect("seed file");
    git(&["add", "."]);
    git(&["commit", "--quiet", "-m", "seed"]);
    path
}

fn task(repo: &Path, model: &StubModel) -> Task {
    Task {
        instruction: "read the readme and stop".to_owned(),
        repo_path: Some(repo.to_string_lossy().into_owned()),
        validations: vec![vec!["true".to_owned()]],
        max_turns: 4,
        max_requests: 8,
        max_tool_output_bytes: 4096,
        model: Some(ModelChoice {
            provider: Some(model.base_url.clone()),
            model: "stub".to_owned(),
            reasoning: None,
        }),
        context_notes: Vec::new(),
    }
}

/// A reply that asks for one tool call, in the OpenAI-compatible shape.
fn asking_for_a_tool(id: &str) -> String {
    asking_for_a_read_of(id, "README.md")
}

/// The same, pointed at a file that is not there.
fn asking_for_a_tool_that_fails(id: &str) -> String {
    asking_for_a_read_of(id, "does-not-exist.md")
}

fn asking_for_a_read_of(id: &str, path: &str) -> String {
    serde_json::json!({
        "choices": [{"message": {
            "role": "assistant",
            "content": null,
            "tool_calls": [{
                "id": id,
                "type": "function",
                "function": {"name": "read", "arguments": serde_json::json!({"path": path}).to_string()}
            }]
        }, "finish_reason": "tool_calls"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    })
    .to_string()
}

/// A reply with no tool calls, which ends the loop.
fn finished() -> String {
    serde_json::json!({
        "choices": [{"message": {"role": "assistant", "content": "read it"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 4, "total_tokens": 24}
    })
    .to_string()
}

/// The second request is the one that matters: it carries the transcript the
/// model has to be able to read.
#[tokio::test]
async fn the_model_sees_its_own_calls_paired_with_their_results() {
    let repo = repository("paired");
    let model = StubModel::start(vec![asking_for_a_tool("call_1"), finished()]).await;
    let mut outcome = Result_::default();
    agent::execute(task(&repo, &model), &mut outcome)
        .await
        .expect("the run completes");

    let sent = model.sent();
    assert_eq!(
        sent.len(),
        2,
        "expected one request per turn, sent {sent:?}"
    );
    let second: serde_json::Value =
        serde_json::from_str(&sent[1]).expect("the second request is json");
    let messages = second["messages"].as_array().expect("messages");
    let assistant = messages
        .iter()
        .find(|m| m["role"] == "assistant" && m["tool_calls"].is_array())
        .unwrap_or_else(|| panic!("no assistant turn carried its calls: {messages:?}"));
    assert_eq!(
        assistant["tool_calls"][0]["id"], "call_1",
        "the model's own call must come back to it: {assistant}"
    );
    let tool = messages
        .iter()
        .find(|m| m["role"] == "tool")
        .unwrap_or_else(|| panic!("no tool result in the transcript: {messages:?}"));
    assert_eq!(
        tool["tool_call_id"], "call_1",
        "a result must name the call it answers: {tool}"
    );
    assert!(
        tool["content"].as_str().unwrap_or_default().contains("one"),
        "the result is the file's contents: {tool}"
    );
    assert_eq!(outcome.stop_reason, StopReason::ModelFinished);
    let _ = std::fs::remove_dir_all(repo);
}

/// A tool that fails is information, not the end of the run, and the failure
/// still reaches the model as an answer to its call.
#[tokio::test]
async fn a_failing_tool_is_answered_on_its_own_call() {
    let repo = repository("failing");
    let model = StubModel::start(vec![
        asking_for_a_tool_that_fails("call_missing"),
        finished(),
    ])
    .await;
    let mut outcome = Result_::default();
    agent::execute(task(&repo, &model), &mut outcome)
        .await
        .expect("the run completes");
    let sent = model.sent();
    let second: serde_json::Value = serde_json::from_str(&sent[1]).expect("json");
    let messages = second["messages"].as_array().expect("messages");
    let tool = messages
        .iter()
        .find(|m| m["role"] == "tool")
        .unwrap_or_else(|| panic!("no tool result: {messages:?}"));
    assert_eq!(tool["tool_call_id"], "call_missing");
    assert!(
        tool["content"]
            .as_str()
            .unwrap_or_default()
            .starts_with("error:"),
        "the model is told what went wrong: {tool}"
    );
    let _ = std::fs::remove_dir_all(repo);
}

/// The harness does not run away: a model that keeps asking for tools stops at
/// the task's own ceilings, and the result says which ceiling it hit.
#[tokio::test]
async fn a_model_that_never_stops_is_stopped_by_the_task_ceiling() {
    let repo = repository("ceiling");
    let model = StubModel::start(vec![asking_for_a_tool("call_loop")]).await;
    let mut spec = task(&repo, &model);
    spec.max_turns = 3;
    let mut outcome = Result_::default();
    agent::execute(spec, &mut outcome)
        .await
        .expect("the run completes");
    assert_eq!(outcome.stop_reason, StopReason::TurnBudget);
    assert!(outcome.turns <= 3, "{} turns", outcome.turns);
    let _ = std::fs::remove_dir_all(repo);
}

/// Usage is the caller's evidence, so it has to survive the run.
#[tokio::test]
async fn token_usage_accumulates_across_turns() {
    let repo = repository("usage");
    let model = StubModel::start(vec![asking_for_a_tool("call_u"), finished()]).await;
    let mut outcome = Result_::default();
    agent::execute(task(&repo, &model), &mut outcome)
        .await
        .expect("the run completes");
    assert_eq!(outcome.usage.input_tokens, 30, "10 + 20 across two turns");
    assert_eq!(outcome.usage.output_tokens, 9, "5 + 4 across two turns");
    assert_eq!(outcome.usage.requests, 2, "one request per turn");
    let _ = std::fs::remove_dir_all(repo);
}

/// The context ceiling is enforced, not merely declared.
///
/// A model that keeps asking for a tool and a repository that keeps answering
/// grow one request at a time. Without compaction the conversation reaches the
/// provider's window and the task dies with an error that names nothing the
/// operator can act on, so this runs long enough to pass it and checks that the
/// requests actually shrink.
#[tokio::test]
async fn a_long_run_compacts_instead_of_growing_without_end() {
    let repo = repository("compaction");
    // Around twenty kilobytes of source in the repository, which is roughly
    // five thousand tokens of conversation per turn.
    std::fs::write(repo.join("big.txt"), "pub fn example() {}\n".repeat(1_400))
        .expect("a file worth reading");
    let call = |id: &str, name: &str, arguments: serde_json::Value| {
        serde_json::json!({
            "id": id,
            "type": "function",
            "function": {"name": name, "arguments": arguments.to_string()}
        })
    };
    let reply = serde_json::json!({
        "choices": [{"message": {
            "role": "assistant",
            "content": null,
            "tool_calls": [
                // A real edit, so the no-progress guard does not end the run
                // first: what is under test here is the context ceiling, and
                // only a run that keeps making progress reaches it.
                call("call_write", "write",
                     serde_json::json!({"path": "notes.txt", "content": "turn {n}\n"})),
                // And a read of something substantial, so the conversation
                // actually grows. `{n}` becomes this request's number in the
                // stub, so no two calls are byte-identical.
                call("call_read", "read", serde_json::json!({"path": "big.txt"})),
            ]
        }, "finish_reason": "tool_calls"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    })
    .to_string();
    // One scripted reply, repeated: the run ends at the task's own ceiling, not
    // because the model decided it was finished.
    let model = StubModel::start(vec![reply]).await;
    let mut spec = task(&repo, &model);
    spec.max_turns = 160;
    spec.max_requests = 400;
    let mut outcome = Result_::default();
    agent::execute(spec, &mut outcome)
        .await
        .expect("the run completes");

    let sent = model.sent();
    assert!(
        sent.len() > 100,
        "the fixture has to run long: {}",
        sent.len()
    );
    let message_counts: Vec<usize> = sent
        .iter()
        .map(|body| {
            serde_json::from_str::<serde_json::Value>(body).expect("json")["messages"]
                .as_array()
                .expect("messages")
                .len()
        })
        .collect();
    // The conversation has to be cut back, not merely grow slower: every turn
    // adds an assistant message and a result, so without compaction the last
    // request would carry the whole run.
    let dropped = message_counts.windows(2).any(|pair| pair[1] + 10 < pair[0]);
    assert!(
        dropped,
        "no request was materially smaller than the one before it: the window \
         never gets cut back. counts: {message_counts:?}"
    );
    let compacted = outcome
        .events
        .iter()
        .filter(|event| matches!(event.kind, aiec_agent::task::EventKind::Compacted { .. }))
        .count();
    assert!(compacted > 0, "and the result says it happened");
    // And the last request is the proof that the run finished rather than
    // merely being cut off.
    assert_eq!(outcome.stop_reason, StopReason::TurnBudget);
    let _ = std::fs::remove_dir_all(repo);
}

/// A model that reads forever is stopped for making no progress.
///
/// Every call is different, so the repeated-call half of the guard cannot see
/// it; it never edits, so the other half can. The guard's second signal is
/// only reachable if the loop tells it what each call changed, and without that
/// this run would spend its whole turn ceiling learning nothing.
#[tokio::test]
async fn a_model_that_only_reads_is_stopped_for_no_progress() {
    let repo = repository("no-progress");
    let call = |id: &str, path: &str| {
        serde_json::json!({
            "id": id,
            "type": "function",
            "function": {
                "name": "read",
                "arguments": serde_json::json!({"path": path}).to_string()
            }
        })
    };
    let reply = serde_json::json!({
        "choices": [{"message": {
            "role": "assistant",
            "content": null,
            "tool_calls": [call("call_read", "{n}.txt")]
        }, "finish_reason": "tool_calls"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    })
    .to_string();
    let model = StubModel::start(vec![reply]).await;
    let mut spec = task(&repo, &model);
    // Well above the no-progress limit, so only the guard can end this.
    spec.max_turns = 60;
    let mut outcome = Result_::default();
    agent::execute(spec, &mut outcome)
        .await
        .expect("the run completes");
    assert_eq!(
        outcome.stop_reason,
        StopReason::NoProgress,
        "{} turns of reading ended for {:?}",
        outcome.turns,
        outcome.stop_reason
    );
    assert!(
        outcome.turns < 60,
        "the guard let it run {} of 60 turns",
        outcome.turns
    );
    let _ = std::fs::remove_dir_all(repo);
}
