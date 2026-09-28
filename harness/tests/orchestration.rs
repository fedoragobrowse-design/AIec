//! The orchestration layer: budgeting, compaction, loop detection, redaction,
//! and the task/result documents.
//!
//! These are the parts that decide when a session stops and what it says on the
//! way out, so they are tested for behaviour that could plausibly be wrong
//! rather than for coverage.

use aiec_harness::budget::Budget;
use aiec_harness::context::{Budget as ContextBudget, Context, compress_output, estimate_tokens};
use aiec_harness::loop_guard::{LoopGuard, Progress};
use aiec_harness::model::{Response, Stop, ToolCall, Usage};
use aiec_harness::redaction;
use aiec_harness::result::{Result as RunResult, Status};
use aiec_harness::session::SessionState;
use aiec_harness::task::Task;
use aiec_harness::tools::resolve;

fn tool_call(name: &str, args: &str) -> ToolCall {
    ToolCall {
        id: "1".to_owned(),
        name: name.to_owned(),
        arguments: args.to_owned(),
    }
}

fn reply(text: Option<&str>, calls: Vec<ToolCall>) -> Response {
    Response {
        text: text.map(str::to_owned),
        tool_calls: calls,
        usage: Usage::default(),
        stop: Stop::ModelFinished,
        latency_ms: 1,
    }
}

// ---------------------------------------------------------------- context ---

#[test]
fn a_context_that_fits_is_never_compacted() {
    let mut ctx = Context::new("do the thing", ContextBudget::new(200_000, 8_192));
    for _ in 0..50 {
        let compacted = ctx.push_turn(
            &reply(None, vec![tool_call("read", "{\"path\":\"a.rs\"}")]),
            &[],
        );
        assert!(!compacted, "a small context must not compact");
    }
    assert_eq!(ctx.compactions(), 0);
}

#[test]
fn a_context_that_outgrows_its_window_compacts_and_keeps_the_objective() {
    // A window this small forces compaction within a few turns.
    let mut ctx = Context::new("make the failing test pass", ContextBudget::new(600, 100));
    for _ in 0..40 {
        let big = "x".repeat(4_000);
        ctx.push_turn(&reply(None, vec![tool_call("read", "{}")]), &[(big, false)]);
    }
    assert!(ctx.compactions() > 0, "the context should have compacted");

    // The objective is the one thing a summary must never lose.
    assert!(ctx.state.objective.contains("failing test"));

    // And the transcript is still bounded, which was the entire point.
    assert!(
        ctx.tokens() < 600,
        "compaction left {} tokens in a 600 token window",
        ctx.tokens()
    );
}

#[test]
fn compaction_keeps_the_most_recent_exchange_verbatim() {
    let mut ctx = Context::new("objective stays", ContextBudget::new(400, 50));
    for _ in 0..30 {
        ctx.push_turn(
            &reply(None, vec![tool_call("read", "{}")]),
            &[("old noise".repeat(50), false)],
        );
    }
    // The final observation must be findable without a model summary.
    ctx.push_turn(
        &reply(None, vec![tool_call("read", "{}")]),
        &[("THE FINAL OBSERVATION".to_owned(), true)],
    );
    let rendered: String = ctx.messages.iter().map(|m| format!("{m:?}")).collect();
    assert!(
        rendered.contains("THE FINAL OBSERVATION"),
        "compaction discarded the most recent turn"
    );
}

#[test]
fn output_compression_keeps_both_ends_and_says_what_it_dropped() {
    let body = format!(
        "ERROR at the top\n{}{}summary at the bottom",
        "filler line\n".repeat(5_000),
        ""
    );
    let squeezed = compress_output(&body, 2_000);

    assert!(
        squeezed.len() < 2_400,
        "compression did not bound the output"
    );
    assert!(squeezed.contains("ERROR at the top"), "lost the head");
    assert!(squeezed.contains("summary at the bottom"), "lost the tail");
    assert!(squeezed.contains("elided"), "did not say what was dropped");
}

#[test]
fn output_compression_never_splits_a_character() {
    // Every character is multi-byte, so any naive byte slicing panics or produces
    // invalid utf8.
    let body = "é".repeat(10_000);
    let squeezed = compress_output(&body, 1_000);
    // If this were invalid utf8 it could not exist as a String at all, so simply
    // having built it is the assertion; check the bound held too.
    assert!(squeezed.len() < 2_000);
}

#[test]
fn output_below_the_limit_is_returned_untouched() {
    let body = "short".to_owned();
    assert_eq!(compress_output(&body, 1_000), body);
}

#[test]
fn the_token_estimate_is_monotonic() {
    assert!(estimate_tokens(&"a".repeat(400)) > estimate_tokens(&"a".repeat(40)));
}

// ------------------------------------------------------------ loop guard ---

#[test]
fn an_identical_turn_repeating_is_caught() {
    let mut guard = LoopGuard::new(3);
    let r = reply(None, vec![tool_call("bash", "{\"command\":[\"true\"]}")]);
    // Deliberately no new progress between turns: the same call, the same result.
    let mut tripped = false;
    for _ in 0..10 {
        if guard.observe_turn(&r, &[("exit 0".to_owned(), true)]) {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "an identical turn repeating was never caught");
}

#[test]
fn a_turn_that_makes_progress_is_not_a_loop() {
    let mut guard = LoopGuard::new(3);
    for i in 0..20 {
        // Each turn reads a different file: real work, identical shape.
        let r = reply(
            None,
            vec![tool_call("read", &format!("{{\"path\":\"f{i}.rs\"}}"))],
        );
        assert!(
            !guard.observe_turn(&r, &[("ok".to_owned(), true)]),
            "genuine progress was mistaken for a loop at turn {i}"
        );
        guard.record_progress(&[Progress::NewFileInspected(format!("f{i}.rs"))]);
    }
}

#[test]
fn the_same_call_with_different_arguments_is_not_a_repeat() {
    let mut guard = LoopGuard::new(2);
    for i in 0..10 {
        let r = reply(
            None,
            vec![tool_call("edit", &format!("{{\"path\":\"a{i}.rs\"}}"))],
        );
        assert!(!guard.observe_turn(&r, &[("edited".to_owned(), true)]));
    }
}

// ---------------------------------------------------------------- budget ---

#[test]
fn a_request_budget_stops_before_overdrawing() {
    let mut budget = Budget::new(aiec_harness::task::Limits {
        max_model_requests: 3,
        ..Default::default()
    });
    for expected in 1..=3 {
        assert_eq!(budget.check().expect("within budget"), expected);
        budget.record_request();
    }
    assert_eq!(budget.check().unwrap_err(), Stop::MaxRequests);
    assert_eq!(budget.remaining_requests(), 0);
}

#[test]
fn a_wall_clock_budget_of_zero_stops_immediately() {
    let budget = Budget::new(aiec_harness::task::Limits {
        wall_seconds: 0,
        ..Default::default()
    });
    assert_eq!(budget.check().unwrap_err(), Stop::WallClock);
}

// ------------------------------------------------------------- redaction ---

#[test]
fn a_known_secret_never_survives_into_output() {
    // Set through the process environment so `scrub` sees it exactly as it
    // would in a real session.
    let secret = "sk-test-0123456789abcdef";
    // SAFETY: single-threaded test setup; the value is unique to this test.
    unsafe { std::env::set_var("AIEC_AGENT_API_KEY", secret) };

    let text = format!("the request failed with key {secret} in the header");
    let scrubbed = redaction::scrub(&text);
    assert!(
        !scrubbed.contains(secret),
        "the secret survived redaction: {scrubbed}"
    );
    assert!(scrubbed.contains("[redacted:"));
}

#[test]
fn redaction_walks_a_nested_document() {
    let secret = "sk-nested-9876543210";
    unsafe { std::env::set_var("OPENAI_API_KEY", secret) };
    let mut value = serde_json::json!({
        "ok": true,
        "tools": [{"name": "bash", "stdout": format!("leaked {secret}")}],
        "count": 3
    });
    redaction::scrub_value(&mut value);
    let text = value.to_string();
    assert!(!text.contains(secret), "a nested secret survived");
    // Redaction must not disturb the shape of the document.
    assert_eq!(value["count"], 3);
    assert_eq!(value["ok"], true);
}

#[test]
fn a_config_digest_does_not_reveal_the_config() {
    let config = "provider=anthropic model=claude key=sk-live-1234567890";
    let digest = redaction::digest(config);
    assert!(!digest.contains("sk-live"));
    assert_eq!(digest.len(), 64);
    // Stable, so two runs can be compared.
    assert_eq!(digest, redaction::digest(config));
}

// ------------------------------------------------------------------ path ---

#[test]
fn no_resolved_path_can_escape_the_workspace() {
    let root = std::env::temp_dir();
    for raw in [
        "../etc/passwd",
        "a/../../etc/passwd",
        "./../../secret",
        "a/b/../../../root/.ssh/id_rsa",
        "/etc/passwd",
        "\0/etc/passwd",
        "",
    ] {
        assert!(
            resolve(&root, raw).is_err(),
            "`{raw}` was allowed to resolve"
        );
    }
}

#[test]
fn an_ordinary_relative_path_resolves_inside_the_workspace() {
    let root = std::env::temp_dir();
    let resolved = resolve(&root, "src/main.rs").expect("ordinary path");
    assert!(resolved.starts_with(&root));
    // `./` and interior `.` are noise, not escapes.
    assert!(resolve(&root, "./src/./main.rs").is_ok());
}

// ------------------------------------------------------------------ task ---

#[test]
fn a_task_with_a_blank_instruction_is_refused() {
    for body in [
        r#"{"instruction":"","workspace":"/tmp"}"#,
        r#"{"instruction":"   \n  ","workspace":"/tmp"}"#,
    ] {
        let error = Task::parse(body).expect_err("blank instruction must be refused");
        assert!(error.to_string().contains("instruction"), "{error}");
    }
}

#[test]
fn a_task_digest_changes_with_the_work() {
    let base =
        r#"{"task_id":"t","instruction":"fix it","workspace":"/tmp","validation":[["true"]]}"#;
    let first = Task::parse(base).expect("parses").digest;
    let same = Task::parse(base).expect("parses").digest;
    assert_eq!(first, same, "the digest must be stable for the same task");

    let different = r#"{"task_id":"t","instruction":"fix it differently","workspace":"/tmp"}"#;
    assert_ne!(Task::parse(different).expect("parses").digest, first);

    let extra_validation =
        r#"{"task_id":"t","instruction":"fix it","workspace":"/tmp","validation":[["false"]]}"#;
    assert_ne!(
        Task::parse(extra_validation).expect("parses").digest,
        first,
        "a different validation is a different task"
    );
}

#[test]
fn an_empty_validation_argv_is_refused() {
    let body = r#"{"instruction":"x","workspace":"/tmp","validation":[[]]}"#;
    assert!(Task::parse(body).is_err());
}

#[test]
fn a_malformed_task_document_is_refused_without_panicking() {
    for body in [
        "",
        "null",
        "[]",
        "{",
        r#"{"instruction":NaN}"#,
        r#"{"instruction":123}"#,
        "\u{0}\u{1}",
        &"x".repeat(2_000_000),
    ] {
        let _ = Task::parse(body);
    }
}

// ---------------------------------------------------------------- result ---

#[test]
fn a_result_is_written_atomically_and_leaves_no_partial() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("result.json");
    let document = RunResult::for_error("t1", provenance(), "because");

    document.write_to(&path).expect("write");
    let text = std::fs::read_to_string(&path).expect("read back");
    let parsed: RunResult = serde_json::from_str(&text).expect("valid json");
    assert_eq!(parsed.task_id, "t1");
    assert_eq!(parsed.status, Status::Error);

    // The temp file is gone: a collector must not find two candidates.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("readdir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("partial"))
        .collect();
    assert!(leftovers.is_empty(), "left behind {leftovers:?}");
}

fn provenance() -> aiec_harness::result::Provenance {
    aiec_harness::result::Provenance {
        harness_version: "0.0.0".to_owned(),
        protocol: 1,
        provider: "test".to_owned(),
        model: "test".to_owned(),
        task_digest: String::new(),
        config_digest: String::new(),
        repository_start_commit: None,
    }
}

// --------------------------------------------------------------- session ---

#[test]
fn a_finished_session_is_not_resumable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("session.json");
    let mut state = SessionState::new(&task_for("t1", "do a thing"), "m", "p");
    state.completed = true;
    state.save(&path).expect("save");

    assert!(
        SessionState::load(&path).expect("load").is_none(),
        "a completed session was offered for resume"
    );
}

#[test]
fn a_corrupt_session_file_is_ignored_rather_than_fatal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("session.json");
    std::fs::write(&path, "{ truncated garbage").expect("write");
    assert!(
        SessionState::load(&path).expect("load").is_none(),
        "a corrupt state file should mean nothing to resume, not a failure"
    );
}

#[test]
fn a_session_from_a_different_task_does_not_match() {
    let a = SessionState::new(&task_for("t1", "do a thing"), "m", "p");
    let b = SessionState::new(&task_for("t2", "do another thing"), "m", "p");
    assert!(!a.matches(&task_for("t2", "do another thing")));
    assert!(a.matches(&task_for("t1", "do a thing")));
    assert_ne!(a.task_digest, b.task_digest);
}

fn task_for(id: &str, instruction: &str) -> Task {
    Task::parse(&format!(
        r#"{{"task_id":"{id}","instruction":"{instruction}","workspace":"/tmp"}}"#
    ))
    .expect("task parses")
}
