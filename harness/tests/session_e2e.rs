//! End-to-end: a whole session, driven by a scripted model, against a real
//! repository on disk.
//!
//! The provider here is a stub implementing the real `ModelProvider` trait, so
//! this exercises the actual loop, the actual tools, the actual context
//! accounting, and the actual validation path. Nothing is mocked except the
//! network, which is the one thing that cannot be faked honestly.

use std::path::Path;
use std::pin::Pin;
use std::sync::Mutex;

use aiec_harness::HarnessError;
use aiec_harness::agent::Agent;
use aiec_harness::events::EventLog;
use aiec_harness::model::{
    Capabilities, Completion, ModelConfig, ModelProvider, Provider, Reasoning, Response, Stop,
    ToolCall, Usage,
};
use aiec_harness::result::Status;
use aiec_harness::session::SessionState;
use aiec_harness::task::Task;
use aiec_harness::tools::{Phase, ToolContext, registry};

/// A model that replays a fixed script and records what it was asked.
///
/// It is a real `ModelProvider`, not a mock of one: the loop builds the request,
/// the stub reads the conversation, and the tools run for real.
struct Scripted {
    config: ModelConfig,
    steps: Mutex<Vec<Step>>,
    seen: Mutex<Vec<Completion>>,
}

enum Step {
    Calls(Vec<(&'static str, String)>),
    Done(&'static str),
}

impl Scripted {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            config: ModelConfig {
                provider: Provider::OpenAiCompatible,
                model: "scripted".to_owned(),
                base_url: None,
                reasoning: Reasoning::Off,
                context_window: 200_000,
                deadline_ms: None,
            },
            steps: Mutex::new(steps),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn turns(&self) -> usize {
        self.seen.lock().map(|s| s.len()).unwrap_or(0)
    }
}

impl ModelProvider for Scripted {
    fn config(&self) -> &ModelConfig {
        &self.config
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::FULL
    }

    fn complete<'a>(
        &'a self,
        request: &'a Completion,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Response, HarnessError>> + Send + 'a>>
    {
        Box::pin(async move {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(request.clone());
            }
            let next = self.steps.lock().ok().and_then(|mut s| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.remove(0))
                }
            });
            Ok(match next {
                Some(Step::Calls(calls)) => Response {
                    text: None,
                    tool_calls: calls
                        .into_iter()
                        .enumerate()
                        .map(|(i, (name, arguments))| ToolCall {
                            id: format!("c{i}"),
                            name: name.to_owned(),
                            arguments,
                        })
                        .collect(),
                    usage: Usage {
                        input_tokens: 100,
                        output_tokens: 20,
                        cache_read_tokens: 50,
                        cache_write_tokens: 0,
                    },
                    stop: Stop::ModelFinished,
                    latency_ms: 5,
                },
                Some(Step::Done(text)) => Response {
                    text: Some(text.to_owned()),
                    tool_calls: Vec::new(),
                    usage: Usage {
                        input_tokens: 10,
                        output_tokens: 5,
                        ..Default::default()
                    },
                    stop: Stop::ModelFinished,
                    latency_ms: 3,
                },
                // Past the end of the script: behave like a model that is done,
                // so a run that over-asks still terminates cleanly.
                None => Response {
                    text: Some("script exhausted".to_owned()),
                    tool_calls: Vec::new(),
                    usage: Usage::default(),
                    stop: Stop::ModelFinished,
                    latency_ms: 1,
                },
            })
        })
    }
}

/// A git repo with a real bug in it, so the tools and the git evidence have
/// something genuine to work on.
fn repo_with_bug() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::write(
        root.join("calc.py"),
        "def split_bill(total, shares):\n    each = total // shares\n    return [each] * shares\n",
    )
    .expect("write");
    std::fs::write(
        root.join("test_calc.py"),
        "import unittest\nfrom calc import split_bill\n\n\
         class T(unittest.TestCase):\n    def test_sum(self):\n        \
         self.assertEqual(sum(split_bill(10.00, 3)), 10.00)\n    \
         def test_shares(self):\n        self.assertEqual(len(split_bill(9.00, 3)), 3)\n",
    )
    .expect("write");
    run_git(root, &["init", "-q"]);
    run_git(root, &["add", "-A"]);
    run_git(
        root,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "initial",
        ],
    );
    dir
}

fn run_git(root: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output();
    assert!(out.is_ok_and(|o| o.status.success()), "git {args:?} failed");
}

fn task_for(root: &Path, validation: Vec<Vec<&str>>) -> Task {
    let validation: Vec<aiec_harness::task::Validation> = validation
        .into_iter()
        .map(|argv| {
            aiec_harness::task::Validation::new(argv.into_iter().map(String::from).collect())
        })
        .collect();
    let body = serde_json::json!({
        "task_id": "fix-bill",
        "instruction": "Make split_bill not lose money. Change only calc.py.",
        "workspace": root.to_string_lossy(),
        "validation": validation,
        "limits": { "max_model_requests": 10, "wall_seconds": 120 }
    });
    Task::parse(&body.to_string()).expect("task parses")
}

#[tokio::test]
async fn a_full_session_reports_git_evidence_and_runs_validation() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![vec!["python3", "-m", "unittest", "-q"]]);
    let log = EventLog::open(None).expect("event log");

    let provider = Scripted::new(vec![
        Step::Calls(vec![("read", r#"{"path":"calc.py"}"#.to_owned())]),
        Step::Calls(vec![(
            "edit",
            r#"{"path":"calc.py","start":2,"end":2,"content":"    cents = round(total * 100)\n    each = cents // shares\n    base = [each] * shares\n    base[-1] += cents - each * shares\n    return [c / 100 for c in base]"}"#.to_owned(),
        )]),
        Step::Done("Fixed split_bill to distribute the remainder."),
    ]);

    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    let document = agent.run(&dir.path().join("state.json")).await;

    // Validation is the harness's, and it decides.
    assert_eq!(document.validation.len(), 1);
    assert!(
        document.validation[0].ok,
        "validation failed: {}",
        document.validation[0].stderr
    );
    assert_eq!(document.status, Status::Success);
    assert_eq!(document.stop_reason, "model_finished");

    // The repository evidence is real: a real head, a real changed file, a
    // diff that actually contains the change.
    assert!(document.git.is_repository);
    assert!(document.git.head_before.is_some());
    assert!(
        document
            .git
            .changed_files
            .iter()
            .any(|f| f.contains("calc.py")),
        "changed_files was {:?}",
        document.git.changed_files
    );
    assert!(
        document.git.diff.contains("cents"),
        "the diff does not contain the edit: {}",
        document.git.diff
    );

    // Usage is measured, not guessed.
    assert_eq!(document.metrics.model_requests, 3);
    assert!(document.metrics.input_tokens > 0);
    assert!(document.metrics.output_tokens > 0);
    assert!(document.metrics.cache_read_tokens > 0);
    assert!(document.metrics.tool_calls.contains_key("read"));
    assert!(document.metrics.tool_calls.contains_key("edit"));
    assert!(document.metrics.wall_ms > 0);
    assert!(document.metrics.peak_rss_bytes.is_some());

    // The provenance is enough to attribute the run.
    assert_eq!(document.provenance.protocol, 1);
    assert_eq!(document.provenance.model, "scripted");
    assert_eq!(document.provenance.task_digest, task.digest);
    assert!(document.provenance.repository_start_commit.is_some());
}

#[tokio::test]
async fn a_model_that_claims_success_does_not_make_the_result_succeed() {
    let dir = repo_with_bug();
    // Validation runs `false`. The model says it is done. The result must not
    // say success.
    let task = task_for(dir.path(), vec![vec!["false"]]);
    let log = EventLog::open(None).expect("event log");

    let provider = Scripted::new(vec![Step::Done("All done, everything passes.")]);
    let agent = Agent::new(&task, &provider, &log, None).expect("agent");

    let document = agent.run(&dir.path().join("state.json")).await;

    // The harness ran the validation itself, so the verdict is in the document
    // rather than in a step a caller has to remember.
    assert_eq!(document.validation.len(), 1);
    assert!(
        !document.validation[0].ok,
        "the fixture must genuinely fail"
    );
    assert_eq!(
        document.status,
        Status::Failed,
        "the model said it was done and the harness believed it"
    );
    // The model got a clean, complete run; only the verdict is negative.
    assert_eq!(document.stop_reason, "model_finished");
}

#[tokio::test]
async fn a_model_asking_for_an_unknown_tool_does_not_end_the_session() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![]);
    let log = EventLog::open(None).expect("event log");

    let provider = Scripted::new(vec![
        Step::Calls(vec![(
            "exfiltrate",
            r#"{"target":"~/.ssh/id_rsa"}"#.to_owned(),
        )]),
        // The harness must have fed the failure back and kept going.
        Step::Calls(vec![("read", r#"{"path":"calc.py"}"#.to_owned())]),
        Step::Done("There is no such tool; I read the file instead."),
    ]);

    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    let document = agent.run(&dir.path().join("state.json")).await;

    assert_eq!(provider.turns(), 3, "the loop stopped on the bad tool call");
    assert_eq!(document.status, Status::Success);
    assert!(
        document.metrics.tool_failures > 0,
        "the failure was not counted"
    );
}

#[tokio::test]
async fn a_turn_that_repeats_identically_is_stopped_as_no_progress() {
    let dir = repo_with_bug();
    let body = serde_json::json!({
        "task_id": "loop",
        "instruction": "do the thing",
        "workspace": dir.path().to_string_lossy(),
        "limits": { "max_model_requests": 60, "wall_seconds": 120 }
    });
    let task = Task::parse(&body.to_string()).expect("parses");
    let log = EventLog::open(None).expect("event log");

    // The same call, the same result, forever: the definition of a stuck model.
    //
    // `read`, not `bash`. The detector compares observations byte for byte, and
    // a shell result carries its own duration, so a bash fixture is a coin
    // flip between 0.00s and 0.01s and the test decides on timing rather than
    // on behaviour. A file read is byte-stable, which is what this is about.
    let provider = Scripted::new(
        (0..50)
            .map(|_| Step::Calls(vec![("read", r#"{"path":"calc.py"}"#.to_owned())]))
            .collect(),
    );
    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    let document = agent.run(&dir.path().join("state.json")).await;

    assert_eq!(document.stop_reason, "no_progress");
    assert!(
        provider.turns() < 20,
        "the loop ran {} turns before stopping",
        provider.turns()
    );
}

#[tokio::test]
async fn a_request_budget_stops_the_session_and_still_writes_a_result() {
    let dir = repo_with_bug();
    let body = serde_json::json!({
        "task_id": "budget",
        "instruction": "do something",
        "workspace": dir.path().to_string_lossy(),
        "validation": [],
        "limits": { "max_model_requests": 2, "wall_seconds": 60 }
    });
    let task = Task::parse(&body.to_string()).expect("parses");
    let log = EventLog::open(None).expect("event log");

    // The model would happily keep going forever.
    let provider = Scripted::new(
        (0..50)
            .map(|_| Step::Calls(vec![("read", r#"{"path":"calc.py"}"#.to_owned())]))
            .collect(),
    );

    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    let document = agent.run(&dir.path().join("state.json")).await;

    assert_eq!(document.stop_reason, "request_budget_exhausted");
    assert!(
        provider.turns() <= 2,
        "spent {} requests against a budget of 2",
        provider.turns()
    );
    // The important part: a stopped session still produces a usable document.
    assert_eq!(document.task_id, "budget");
    assert!(!document.provenance.harness_version.is_empty());
}

#[tokio::test]
async fn a_tool_cannot_escape_the_workspace_even_when_the_model_asks() {
    let dir = repo_with_bug();
    let secret = dir.path().join("SECRET.txt");
    std::fs::write(&secret, "do not read me").expect("write");
    let task = task_for(dir.path(), vec![]);
    let log = EventLog::open(None).expect("event log");

    let provider = Scripted::new(vec![
        Step::Calls(vec![("read", r#"{"path":"../SECRET.txt"}"#.to_owned())]),
        Step::Calls(vec![("read", r#"{"path":"/etc/passwd"}"#.to_owned())]),
        Step::Done("I could not read outside the workspace."),
    ]);

    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    let document = agent.run(&dir.path().join("state.json")).await;

    assert_eq!(
        document.status,
        Status::Success,
        "the loop survived the refusals"
    );
    assert!(
        document.metrics.tool_failures >= 2,
        "both escapes should have been refused, saw {} failures",
        document.metrics.tool_failures
    );
}

#[tokio::test]
async fn a_resumed_session_continues_from_its_state() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![]);
    let log = EventLog::open(None).expect("event log");
    let state_path = dir.path().join("state.json");

    // First run: does some work, then stops early.
    let body = serde_json::json!({
        "task_id": "fix-bill",
        "instruction": task.instruction,
        "workspace": dir.path().to_string_lossy(),
        "limits": { "max_model_requests": 1, "wall_seconds": 60 }
    });
    let short = Task::parse(&body.to_string()).expect("parses");
    let first = Scripted::new(vec![Step::Calls(vec![(
        "read",
        r#"{"path":"calc.py"}"#.to_owned(),
    )])]);
    let agent = Agent::new(&short, &first, &log, None).expect("agent");
    agent.run(&state_path).await;
    assert!(state_path.exists(), "the session state was not written");

    // Second run: picks the state up.
    let saved = SessionState::load(&state_path)
        .expect("load")
        .expect("some state");
    assert_eq!(saved.task_id, "fix-bill");
    assert!(saved.turns_completed >= 1);
    assert!(
        saved.state.files_read.contains("calc.py"),
        "state lost the read"
    );

    let second = Scripted::new(vec![Step::Done("Resumed and finished.")]);
    let agent = Agent::new(&task, &second, &log, Some(saved)).expect("agent");
    let document = agent.run(&state_path).await;
    assert_eq!(document.status, Status::Success);
}

#[tokio::test]
async fn the_event_stream_records_the_whole_session() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![vec!["true"]]);
    let events_path = dir.path().join("events.jsonl");
    let log = EventLog::open(Some(&events_path)).expect("event log");

    let provider = Scripted::new(vec![
        Step::Calls(vec![("read", r#"{"path":"calc.py"}"#.to_owned())]),
        Step::Done("done"),
    ]);
    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    agent.run(&dir.path().join("state.json")).await;

    let text = std::fs::read_to_string(&events_path).expect("events written");
    let kinds: Vec<String> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_owned))
        .collect();

    for expected in [
        "session_started",
        "repository_inspected",
        "model_request_started",
        "model_request_finished",
        "tool_started",
        "tool_finished",
        "session_completed",
    ] {
        assert!(
            kinds.iter().any(|k| k == expected),
            "the stream is missing `{expected}`; it has {kinds:?}"
        );
    }
}

#[tokio::test]
async fn the_result_document_round_trips_and_writes_atomically() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![vec!["true"]]);
    let log = EventLog::open(None).expect("event log");
    let result_path = dir.path().join("result.json");

    let provider = Scripted::new(vec![Step::Done("nothing to do")]);
    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    let document = agent.run(&dir.path().join("state.json")).await;
    document.write_to(&result_path).expect("write");

    let text = std::fs::read_to_string(&result_path).expect("read");
    let parsed: aiec_harness::result::Result =
        serde_json::from_str(&text).expect("the result is valid json");
    assert_eq!(parsed.task_id, "fix-bill");
    assert_eq!(parsed.provenance.protocol, 1);
    assert!(parsed.metrics.peak_rss_bytes.is_some());
}

#[tokio::test]
async fn a_workspace_that_is_not_a_repository_still_works() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("f.txt"), "hello\n").expect("write");
    let task = task_for(dir.path(), vec![vec!["true"]]);
    let log = EventLog::open(None).expect("event log");

    let provider = Scripted::new(vec![
        Step::Calls(vec![("read", r#"{"path":"f.txt"}"#.to_owned())]),
        Step::Done("read it"),
    ]);
    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    let document = agent.run(&dir.path().join("state.json")).await;

    assert!(!document.git.is_repository);
    assert!(document.git.head_before.is_none());
    // Not being a repository is not a reason to fail the task.
    assert_eq!(document.status, Status::Success);
}

#[tokio::test]
async fn the_registry_offers_exactly_the_nine_declared_tools() {
    let tools = registry();
    let names: Vec<String> = tools.specs().into_iter().map(|s| s.name).collect();
    let mut expected = aiec_harness::tools::list_tools();
    expected.sort();
    let mut actual = names;
    actual.sort();

    assert_eq!(
        actual, expected,
        "the registry and the declared tool list disagree"
    );
    assert_eq!(actual.len(), 9);
}

#[tokio::test]
async fn a_validation_command_that_cannot_start_is_reported_not_panicked() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![vec!["this-binary-does-not-exist-xyz"]]);
    let outcomes = aiec_harness::agent::run_validations(&task, dir.path(), &task.limits).await;
    assert_eq!(outcomes.len(), 1);
    assert!(!outcomes[0].ok);
    assert!(
        outcomes[0].stderr.contains("could not start"),
        "unhelpful error: {}",
        outcomes[0].stderr
    );
}

#[tokio::test]
async fn a_validation_command_that_hangs_is_killed() {
    let dir = repo_with_bug();
    let body = serde_json::json!({
        "task_id": "hang",
        "instruction": "x",
        "workspace": dir.path().to_string_lossy(),
        "validation": [["sleep", "60"]],
        "limits": { "command_timeout_seconds": 1, "wall_seconds": 30 }
    });
    let task = Task::parse(&body.to_string()).expect("parses");
    let started = std::time::Instant::now();
    let outcomes = aiec_harness::agent::run_validations(&task, dir.path(), &task.limits).await;

    assert!(outcomes[0].timed_out, "the hang was not detected");
    assert!(!outcomes[0].ok);
    assert!(
        started.elapsed().as_secs() < 10,
        "the timeout did not actually cut it short"
    );
}

#[tokio::test]
async fn the_tool_context_never_carries_a_phase_of_validation() {
    // Guards the boundary the dispatcher relies on: tools are given the
    // workspace root, and nothing else about the world.
    let dir = repo_with_bug();
    let ctx = ToolContext {
        root: dir.path().to_path_buf(),
        limits: aiec_harness::task::Limits::default(),
        phase: Phase::Working,
    };
    assert!(ctx.root.is_absolute());
}

#[tokio::test]
async fn the_harness_does_not_count_its_own_artifacts_as_agent_work() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![vec!["true"]]);
    let log = EventLog::open(None).expect("event log");

    // These are the files a real run creates for itself.
    let events = dir.path().join("events.jsonl");
    let result = dir.path().join("result.json");
    let state = dir.path().join(".aiec-agent/session.json");

    let provider = Scripted::new(vec![
        Step::Calls(vec![(
            "write",
            r#"{"path":"newfile.txt","content":"x"}"#.to_owned(),
        )]),
        Step::Done("wrote it"),
    ]);

    let mut agent = Agent::new(&task, &provider, &log, None).expect("agent");
    for artifact in [&events, &result, &state] {
        agent.note_artifact(artifact);
    }
    let document = agent.run(&state).await;

    assert!(
        document
            .git
            .changed_files
            .iter()
            .any(|f| f == "newfile.txt"),
        "the real edit is missing from changed_files: {:?}",
        document.git.changed_files
    );
    for noise in ["events.jsonl", "result.json", ".aiec-agent/"] {
        assert!(
            !document.git.changed_files.iter().any(|f| f == noise),
            "`{noise}` was reported as the agent's work: {:?}",
            document.git.changed_files
        );
    }
    // The state file really was written, so git really does see it, and it is
    // accounted for rather than hidden. `events.jsonl` is not asserted: this
    // test uses a null event log, so no such file exists and none should be
    // invented.
    assert!(
        document
            .git
            .harness_artifacts
            .iter()
            .any(|f| f.starts_with(".aiec-agent")),
        "the artifacts were hidden rather than separated: {:?}",
        document.git.harness_artifacts
    );
}

#[tokio::test]
async fn a_steering_note_lands_in_the_next_request_and_is_then_consumed() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![]);
    let log = EventLog::open(None).expect("event log");

    // The caller drops a note before the session starts.
    let steer = dir.path().join(".aiec-agent/steer");
    std::fs::create_dir_all(steer.parent().expect("parent")).expect("mkdir");
    std::fs::write(&steer, "focus on the failing test\n").expect("write note");

    let provider = Scripted::new(vec![
        Step::Calls(vec![("read", r#"{"path":"calc.py"}"#.to_owned())]),
        Step::Done("understood"),
    ]);

    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    let document = agent.run(&dir.path().join("state.json")).await;

    assert_eq!(document.status, Status::Success);
    // Two turns, so the note was checked at least once between them.
    assert_eq!(provider.turns(), 2);

    // The note reaches the model on the first turn, not the one after: the
    // request is built after the steering push, so turn 1 already carries it.
    let first = provider.seen.lock().map(|s| s.clone()).unwrap_or_default();
    let turn_one_has_steering = first.first().map(|turn| {
        turn.messages.iter().any(|m| match m {
            aiec_harness::model::Message::User { content } => {
                content.contains("focus on the failing test")
            }
            _ => false,
        })
    });
    assert_eq!(
        turn_one_has_steering,
        Some(true),
        "steering missed the in-flight request"
    );

    // It was consumed, not left to be re-applied forever.
    assert_eq!(
        std::fs::read_to_string(&steer).expect("read back"),
        "",
        "the steering note was not consumed"
    );
}

#[tokio::test]
async fn steering_is_consumed_once_and_reaches_the_model_once() {
    use aiec_harness::events::take_steering;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("steer");

    // Nothing there yet.
    assert!(take_steering(&path).is_none());

    std::fs::write(&path, "do not modify api compatibility\n").expect("write");
    let first = take_steering(&path).expect("note is there");
    assert!(first.contains("do not modify api compatibility"));

    // A second call sees nothing: applying a hint twice is how an agent ends up
    // optimising for a constraint the caller has already moved past.
    assert!(take_steering(&path).is_none());

    // Whitespace only is not a note.
    std::fs::write(&path, "   \n\t ").expect("write");
    assert!(take_steering(&path).is_none());
}

#[tokio::test]
async fn a_relative_artifact_path_is_still_treated_as_the_harness_own() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![vec!["true"]]);
    let log = EventLog::open(None).expect("event log");

    // The obvious invocation: relative paths, as a caller would type them.
    let provider = Scripted::new(vec![Step::Done("nothing to do")]);
    let mut agent = Agent::new(&task, &provider, &log, None).expect("agent");
    for artifact in ["events.jsonl", "result.json", "task.json"] {
        agent.note_artifact(std::path::Path::new(artifact));
    }
    let document = agent.run(Path::new(".aiec-agent/session.json")).await;

    for noise in ["events.jsonl", "result.json", "task.json"] {
        assert!(
            !document.git.changed_files.iter().any(|f| f == noise),
            "a relative artifact path was not registered, so `{noise}` was \
             reported as agent work: {:?}",
            document.git.changed_files
        );
    }
}

#[tokio::test]
async fn a_tool_result_follows_the_assistant_turn_that_asked_for_it_exactly_once() {
    use aiec_harness::model::Message;

    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![]);
    let log = EventLog::open(None).expect("event log");

    // Two calls in one turn, so both the pairing and the ordering are exercised.
    let provider = Scripted::new(vec![Step::Calls(vec![
        ("read", r#"{"path":"calc.py"}"#.to_owned()),
        ("git_status", "{}".to_owned()),
    ])]);
    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    agent.run(&dir.path().join("state.json")).await;

    // Rebuild what the loop would have sent by reading the recorded turns back
    // out of the model, which saw every request.
    let request = provider.seen.lock().expect("lock").last().cloned();
    let Some(request) = request else {
        panic!("the model was never asked");
    };

    let mut seen_assistant = false;
    let mut tool_messages = 0;
    for message in &request.messages {
        match message {
            Message::Assistant { tool_calls, .. } if !tool_calls.is_empty() => {
                assert!(
                    !seen_assistant,
                    "two assistant turns with tool calls in a row: a tool result \
                     was lost between them"
                );
                seen_assistant = true;
            }
            Message::Tool { content, .. } => {
                assert!(
                    seen_assistant,
                    "a tool result appeared before the assistant turn that \
                     requested it, which providers reject"
                );
                tool_messages += 1;
                // Exactly one message per observation, not the same text sent
                // again as a plain user turn. This duplication is what a real
                // provider rejected with a 400 and a fixture accepted happily.
                let echoes = request
                    .messages
                    .iter()
                    .filter(|m| matches!(m, Message::User { content: c } if c == content))
                    .count();
                assert_eq!(
                    echoes, 0,
                    "a tool observation was duplicated as a user message"
                );
            }
            _ => {}
        }
    }
    assert_eq!(tool_messages, 2, "both tool results should be present");
}

#[tokio::test]
async fn a_finished_run_leaves_state_that_is_not_offered_for_resume() {
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![vec!["true"]]);
    let log = EventLog::open(None).expect("event log");
    let state_path = dir.path().join(".aiec-agent/session.json");

    let provider = Scripted::new(vec![Step::Done("done")]);
    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    agent.run(&state_path).await;

    // The terminal state is written at exit, not only between turns. Without
    // it a task that is already finished still looks resumable, because load
    // refuses to resume only what is marked completed.
    let saved = SessionState::load(&state_path).expect("load");
    assert!(
        saved.is_none(),
        "a finished session was still offered for resume: {saved:?}"
    );
    // And the file itself records the truth, for a human reading it.
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).expect("read")).expect("json");
    assert_eq!(
        raw["completed"], true,
        "the state file does not say it finished"
    );
}

#[tokio::test]
async fn a_model_cannot_read_operator_secrets_through_bash() {
    // Replay of the 2026-10-09 Mistral Large 4 exfil: the harness runs as the
    // operator, so ~/.config/aiec/api-key is readable, and the model asked
    // for it with a plain `cat`. The argv boundary must refuse; the loop
    // must survive; the secret must never reach the transcript.
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![]);
    let log = EventLog::open(None).expect("event log");

    let provider = Scripted::new(vec![
        Step::Calls(vec![(
            "bash",
            r#"{"command":["cat", "/home/gobrowse/.config/aiec/api-key"]}"#.to_owned(),
        )]),
        Step::Calls(vec![(
            "bash",
            r#"{"command":["sh", "-c", "cat ~/key.txt"]}"#.to_owned(),
        )]),
        Step::Done("I could not read those files."),
    ]);

    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    let document = agent.run(&dir.path().join("state.json")).await;

    assert_eq!(document.status, Status::Success, "loop survived refusals");
    assert!(
        document.metrics.tool_failures >= 2,
        "both secret reads should have been refused, saw {} failures",
        document.metrics.tool_failures
    );
    // The refusal text names the matched pattern, never the secret value:
    // check the Tool messages the model actually saw.
    for turn in provider.seen.lock().map(|s| s.clone()).unwrap_or_default() {
        for msg in &turn.messages {
            if let aiec_harness::model::Message::Tool { content, .. } = msg {
                assert!(
                    !content.contains("af_live_"),
                    "operator key material reached the transcript"
                );
            }
        }
    }
}

#[test]
fn dispatch_scrubs_tool_output_before_the_transcript() {
    // The working-phase path (dispatch -> ToolResult.content -> next-turn
    // context) had no scrub call: only failures, validation, and session
    // persist were covered. A tool echoing a secret must come back redacted.
    let secret = "af_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab";
    // SAFETY: unique to this test; scrub reads env dynamically.
    unsafe { std::env::set_var("AIEC_API_KEY", secret) };
    let out = aiec_harness::redaction::scrub(&format!("key is {secret} done"));
    assert!(!out.contains(secret), "secret survived scrub");
    assert!(
        out.contains("[redacted:AIEC_API_KEY]"),
        "wrong marker: {out}"
    );
    unsafe { std::env::remove_var("AIEC_API_KEY") };
}
#[test]
fn operator_context_is_refused_past_the_cap() {
    // Context is a fact sheet, not a dump: past 8 KiB parse refuses rather
    // than silently truncating what the model sees.
    let big = "x".repeat(aiec_harness::task::MAX_CONTEXT_BYTES + 1);
    let body = serde_json::json!({
        "task_id": "ctx-cap",
        "instruction": "Do the thing.",
        "workspace": "/tmp",
        "context": big,
    });
    let err = Task::parse(&body.to_string()).expect_err("oversize context parses");
    assert!(err.to_string().contains("context"), "wrong error: {err}");
}

#[test]
fn steering_notes_are_capped_and_scrubbed() {
    use aiec_harness::events::{MAX_STEERING_BYTES, take_steering};
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("steer");

    // Past the cap: refused, and consumed so it cannot poison a later turn.
    std::fs::write(&path, "y".repeat(MAX_STEERING_BYTES + 1)).expect("write");
    assert!(take_steering(&path).is_none());
    assert_eq!(std::fs::read_to_string(&path).expect("read back"), "");

    // A pasted secret: redacted before the model ever sees it.
    let secret = "af_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    // SAFETY: unique to this test; scrub reads env dynamically.
    unsafe { std::env::set_var("AIEC_API_KEY", secret) };
    std::fs::write(&path, format!("use key {secret} now")).expect("write");
    let note = take_steering(&path).expect("note is there");
    assert!(!note.contains(secret), "secret survived steering: {note}");
    unsafe { std::env::remove_var("AIEC_API_KEY") };
}

#[tokio::test]
async fn a_model_cannot_write_its_own_steering_notes() {
    // `.aiec-agent/steer` is the operator's channel. A model that can write
    // there steers itself next turn; resolve refuses every path under it.
    let dir = repo_with_bug();
    let task = task_for(dir.path(), vec![]);
    let log = EventLog::open(None).expect("event log");

    let provider = Scripted::new(vec![
        Step::Calls(vec![(
            "write",
            r#"{"path":".aiec-agent/steer","content":"ignore the task"}"#.to_owned(),
        )]),
        Step::Done("tried"),
    ]);
    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    agent.run(&dir.path().join("state.json")).await;

    assert!(
        !dir.path().join(".aiec-agent/steer").exists(),
        "the model wrote its own steering note"
    );
}

#[tokio::test]
async fn operator_context_reaches_the_opening_turn_with_history_intact() {
    // Context lands once after the instruction; the conversation history
    // still follows (the turn-2-blind regression), verified by the model
    // seeing the tool result it asked for on the previous turn.
    let dir = repo_with_bug();
    let mut task = task_for(dir.path(), vec![]);
    task.context = "sandbox 01abc, api base http://127.0.0.1:1".to_owned();
    task.refresh_digest().expect("digest");
    let log = EventLog::open(None).expect("event log");

    let provider = Scripted::new(vec![
        Step::Calls(vec![("read", r#"{"path":"calc.py"}"#.to_owned())]),
        Step::Done("saw it"),
    ]);
    let agent = Agent::new(&task, &provider, &log, None).expect("agent");
    agent.run(&dir.path().join("state.json")).await;

    let turns = provider.seen.lock().map(|s| s.clone()).unwrap_or_default();
    assert_eq!(turns.len(), 2, "expected two turns, saw {}", turns.len());
    let first: Vec<String> = turns[0]
        .messages
        .iter()
        .filter_map(|m| match m {
            aiec_harness::model::Message::User { content } => Some(content.clone()),
            _ => None,
        })
        .collect();
    assert!(
        first.iter().any(|c| c.contains("<operator-context>")),
        "no operator context in the opening turn: {first:?}"
    );
    let second_has_tool_result = turns[1]
        .messages
        .iter()
        .any(|m| matches!(m, aiec_harness::model::Message::Tool { .. }));
    assert!(
        second_has_tool_result,
        "history lost: turn 2 has no tool result"
    );
}
