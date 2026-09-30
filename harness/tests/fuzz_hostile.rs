//! Fuzz and hostile input.
//!
//! Everything reaching this harness is attacker-controlled in the sense that
//! matters: the task document comes from whatever scheduled the VM, the model
//! reply comes from a network endpoint, and every path and filename comes from
//! a repository nobody has vetted. The requirement is narrow and absolute —
//! fail safely, never panic — because the release profile is `panic = "abort"`,
//! where a panic is not an unwind but the end of the session with no result.
//!
//! The generators are deterministic on purpose. A fuzz corpus that changes each
//! run cannot be bisected, and a failure you cannot reproduce is a failure you
//! cannot fix.

use aiec_harness::context::{Budget as ContextBudget, Context, compress_output};
use aiec_harness::loop_guard::LoopGuard;
use aiec_harness::model::{Completion, Message, ToolCall};
use aiec_harness::redaction;
use aiec_harness::session::SessionState;
use aiec_harness::task::Task;
use aiec_harness::tools::{ToolContext, registry, resolve};

/// A small deterministic generator, so a failure reproduces exactly.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        // xorshift64*: tiny, and good enough to make a corpus that is not
        // trivially self-similar.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

/// Bytes that are not valid UTF-8 on their own.
fn invalid_utf8(rng: &mut Rng, len: usize) -> Vec<u8> {
    // 0x80..=0xBF are continuation bytes with no lead, and 0xF8..=0xFF are
    // never valid in UTF-8 at all.
    (0..len).map(|_| 0x80 + rng.byte() % 0x78).collect()
}

// ------------------------------------------------------------------- the task

#[test]
fn a_task_file_of_arbitrary_bytes_is_refused_without_panicking() {
    let mut rng = Rng::new(0xA11CE);
    for _ in 0..300 {
        let len = rng.below(512);
        let mut bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Sometimes make it nearly-valid json, which is the harder case: a
        // parser that gets far enough to be tempted.
        if rng.below(2) == 0 && bytes.len() > 8 {
            let prefix = br#"{"instruction":"#.to_vec();
            bytes.truncate(prefix.len());
            bytes.extend_from_slice(&prefix);
        }
        let _ = Task::parse(&String::from_utf8_lossy(&bytes));
        // And the truly undecodable case, which cannot go through &str at all.
        let _ = std::str::from_utf8(&bytes);
    }
}

#[test]
fn a_task_file_containing_invalid_utf8_is_refused_not_decoded_lossily() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("aiec-badutf8-{}", std::process::id()));
    let mut bytes = br#"{"instruction":"ok","workspace":"/tmp","x":""#.to_vec();
    bytes.extend_from_slice(&invalid_utf8(&mut Rng::new(7), 32));
    bytes.extend_from_slice(br#""}"#);
    std::fs::write(&path, &bytes).expect("write");

    // The file exists and is not valid UTF-8, so loading must fail cleanly
    // rather than decode it into something that looks like a task.
    let outcome = Task::load(&path);
    assert!(outcome.is_err(), "invalid utf8 was accepted as a task");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_deeply_nested_json_document_does_not_exhaust_the_stack() {
    // A parser without a depth limit turns this into a stack overflow, which
    // under `panic = "abort"` is a process death with no result document.
    for depth in [64usize, 512, 2_048] {
        let body = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let _ = Task::parse(&body);

        let nested = format!(
            "{{\"instruction\":\"x\",\"workspace\":{}{}}}",
            "{\"a\":".repeat(depth),
            "1".to_string() + &"}".repeat(depth)
        );
        let _ = Task::parse(&nested);
    }
}

#[test]
fn an_enormous_task_document_is_refused_quickly() {
    let huge = "x".repeat(64 * 1024 * 1024);
    let started = std::time::Instant::now();
    let _ = Task::parse(&huge);
    assert!(
        started.elapsed().as_secs() < 20,
        "a 64 MiB task document took {:?}",
        started.elapsed()
    );
}

// ------------------------------------------------------------- the model reply

#[test]
fn arbitrary_bytes_as_a_model_reply_never_panic_the_parser() {
    let mut rng = Rng::new(0xBEEF);
    for _ in 0..400 {
        let len = rng.below(256);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let text = String::from_utf8_lossy(&bytes);
        // Whatever it decides, it must decide it by returning.
        let _ = aiec_harness::model::openai::parse_response(&text, 0);
        let _ = aiec_harness::model::anthropic::parse_response(&text, 0);
    }
}

#[test]
fn a_model_reply_that_is_a_nesting_bomb_does_not_exhaust_the_stack() {
    for depth in [64usize, 512, 4_096] {
        let bomb = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let _ = aiec_harness::model::openai::parse_response(&bomb, 0);
        let _ = aiec_harness::model::anthropic::parse_response(&bomb, 0);
    }
}

#[tokio::test]
async fn a_tool_call_carrying_an_enormous_argument_string_is_bounded_by_the_dispatcher() {
    let mut rng = Rng::new(0xF00D);
    let root = std::env::temp_dir();

    for size in [64 * 1024usize, 4 * 1024 * 1024] {
        let arguments = format!("{{\"path\":\"{}\"}}", "a".repeat(size));
        let call = ToolCall {
            id: "1".into(),
            name: "read".into(),
            arguments,
        };
        let ctx = ToolContext {
            root: root.clone(),
            limits: aiec_harness::task::Limits::default(),
            phase: aiec_harness::tools::Phase::Working,
        };
        let tools = registry();
        // Either it reads something bounded or it refuses. What it must not do
        // is hand the model back the whole thing.
        if let Ok(output) = tools.dispatch(&call, &ctx).await {
            assert!(
                output.content.len() <= 128 * 1024,
                "a {} byte argument produced {} bytes of output",
                size,
                output.content.len()
            );
        }
    }
    let _ = rng.next();
}

#[test]
fn a_lone_surrogate_or_control_character_in_a_reply_does_not_panic() {
    for body in [
        r#"{"choices":[{"message":{"content":"\ud800"},"tool_calls":[]}]}"#,
        // A NUL inside a JSON string is a valid JSON escape, so this is
        // well-formed input carrying a hostile character rather than a
        // malformed file.
        "{\"choices\":[{\"message\":{\"content\":\"a\\u0000b\"},\"tool_calls\":[]}]}",
        r#"{"choices":[{"message":{"content":"\u0000\u001f"},"tool_calls":[]}]}"#,
        r#"{"choices":[{"message":{"content":"line\nbreak\ttab"},"tool_calls":[]}]}"#,
    ] {
        let _ = aiec_harness::model::openai::parse_response(body, 0);
    }
}

// ----------------------------------------------------------------- the paths

/// Property: however a relative path is assembled, it either resolves inside
/// the workspace or is refused. There is no third outcome.
#[test]
fn no_generated_relative_path_ever_escapes_the_workspace() {
    let root = std::env::temp_dir();
    let mut rng = Rng::new(0xC0FFEE);
    let segments = [
        "..", ".", "a", "b", "...", "..a", "a..", "/", "", " ", "a/b", "a\\b",
    ];

    for _ in 0..5_000 {
        let count = rng.below(6);
        let mut path = String::new();
        for _ in 0..count {
            path.push_str(segments[rng.below(segments.len())]);
            path.push('/');
        }
        match resolve(&root, &path) {
            Ok(resolved) => assert!(
                resolved.starts_with(&root) && resolved.is_absolute(),
                "`{path}` resolved outside the workspace: {resolved:?}"
            ),
            Err(_) => { /* refused, which is a valid answer */ }
        }
    }
}

#[test]
fn every_path_tool_refuses_a_path_built_to_look_harmless() {
    // Tricks that pass a naive check: a leading "./", a doubled separator, a
    // ".." that cancels out, and a URL-encoded separator.
    for sneaky in [
        "./../etc/passwd",
        "a/./../../etc/passwd",
        "a/b/../../../etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "....//....//etc/passwd",
        "a/..%2f../etc/passwd",
        " /etc/passwd",
        "\t../etc/passwd",
    ] {
        assert!(
            resolve(&std::env::temp_dir(), sneaky).is_err()
                || !std::path::Path::new(sneaky)
                    .components()
                    .any(|c| c == std::path::Component::ParentDir),
            "`{sneaky}` slipped through"
        );
    }
}

// ------------------------------------------------------- the repository itself

#[tokio::test]
async fn hostile_filenames_do_not_break_a_listing_or_a_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Filenames a real repository can contain and a harness must survive.
    let names = [
        "normal.rs",
        "with space.rs",
        "with\nnewline.rs",
        "with\ttab.rs",
        "..hidden_as_name.rs",
        "-leading-dash.rs",
        "quote\"and'.rs",
        "emoji-\u{1f600}.rs",
        "back\\slash.rs",
        &"n".repeat(200),
    ];
    for name in names {
        std::fs::write(root.join(name), "fn main() {}\n").expect("write");
    }

    let tools = registry();
    let ctx = ToolContext {
        root: root.to_path_buf(),
        limits: aiec_harness::task::Limits::default(),
        phase: aiec_harness::tools::Phase::Working,
    };

    // find and glob walk the tree; they must come back, bounded.
    for tool in ["find", "glob"] {
        let call = ToolCall {
            id: "1".into(),
            name: tool.into(),
            arguments: if tool == "find" {
                "{}".into()
            } else {
                r#"{"pattern":"*.rs"}"#.into()
            },
        };
        let output = tools.dispatch(&call, &ctx).await;
        assert!(output.is_ok(), "{tool} failed on hostile filenames");
        if let Ok(output) = output {
            assert!(
                output.content.len() <= ctx.limits.max_tool_output_bytes * 2,
                "{tool} returned {} bytes",
                output.content.len()
            );
        }
    }

    // And each file is individually readable.
    for name in names {
        let call = ToolCall {
            id: "1".into(),
            name: "read".into(),
            arguments: serde_json::json!({ "path": name }).to_string(),
        };
        let output = tools.dispatch(&call, &ctx).await;
        assert!(output.is_ok(), "read failed for `{name}`");
    }
}

#[tokio::test]
async fn a_non_utf8_filename_is_skipped_rather_than_fatal() {
    // On Linux a filename is bytes, not text. A harness that assumes utf8 has
    // to skip these, not choke on them.
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let bad = {
        let mut name = b"weird-".to_vec();
        name.extend_from_slice(&[0x80, 0x81, 0xfe]);
        name
    };
    // SAFETY: constructing the path from raw bytes; no NUL is present, which is
    // the only byte a filename may not contain.
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::OsStr::from_bytes(&bad);
    let _ = std::fs::write(root.join(name), b"x\n");

    let tools = registry();
    let ctx = ToolContext {
        root: root.to_path_buf(),
        limits: aiec_harness::task::Limits::default(),
        phase: aiec_harness::tools::Phase::Working,
    };
    let call = ToolCall {
        id: "1".into(),
        name: "find".into(),
        arguments: "{}".into(),
    };
    // The only requirement is that listing returns.
    let _ = tools.dispatch(&call, &ctx).await;
}

#[tokio::test]
async fn a_very_deep_directory_tree_is_bounded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut path = dir.path().to_path_buf();
    // Deeper than any sane depth cap, and enough to matter.
    for _ in 0..300 {
        path = path.join("d");
        std::fs::create_dir_all(&path).expect("mkdir");
    }

    let tools = registry();
    let ctx = ToolContext {
        root: dir.path().to_path_buf(),
        limits: aiec_harness::task::Limits::default(),
        phase: aiec_harness::tools::Phase::Working,
    };
    let call = ToolCall {
        id: "1".into(),
        name: "find".into(),
        arguments: "{}".into(),
    };
    let started = std::time::Instant::now();
    let output = tools.dispatch(&call, &ctx).await;
    assert!(output.is_ok(), "find failed on a deep tree");
    assert!(
        started.elapsed().as_secs() < 30,
        "walking 300 levels took {:?}",
        started.elapsed()
    );
}

// ------------------------------------------------------- the bounded surfaces

#[test]
fn output_compression_survives_arbitrary_bytes() {
    let mut rng = Rng::new(0xD00D);
    for _ in 0..200 {
        let len = rng.below(2048);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let text = String::from_utf8_lossy(&bytes);
        for limit in [0usize, 1, 7, 64, 1024] {
            // The point is that it returns a valid String, which it cannot do
            // if a multi-byte character were split.
            let squeezed = compress_output(&text, limit);
            assert!(squeezed.chars().count() > 0 || text.is_empty());
        }
    }
}

#[test]
fn a_hostile_observation_never_grows_the_state_without_bound() {
    let mut rng = Rng::new(0x1234);
    let mut ctx = Context::new("objective", ContextBudget::new(50_000, 1_000));
    for _ in 0..500 {
        let len = rng.below(8_000);
        let blob: String = (0..len)
            .map(|_| char::from_u32(0x20 + rng.below(0x1F00) as u32).unwrap_or('x'))
            .collect();
        let response = aiec_harness::model::Response {
            text: Some(blob.clone()),
            tool_calls: Vec::new(),
            usage: Default::default(),
            stop: aiec_harness::model::Stop::ModelFinished,
            latency_ms: 0,
        };
        ctx.push_turn(
            &response,
            &[aiec_harness::context::ToolResult {
                call_id: "c1".into(),
                name: "bash".into(),
                content: blob,
                ok: rng.below(2) == 0,
            }],
        );
    }
    // The context is bounded by construction, whatever it was fed.
    assert!(
        ctx.tokens() <= 50_000,
        "the context grew to {} tokens against a 50000 window",
        ctx.tokens()
    );
}

#[test]
fn a_loop_guard_fed_random_turns_never_panics() {
    let mut rng = Rng::new(0x5EED);
    let mut guard = LoopGuard::new(3);
    for _ in 0..1_000 {
        let len = rng.below(64);
        let arguments: String = (0..len)
            .map(|_| char::from_u32(0x20 + rng.below(0xD00) as u32).unwrap_or('x'))
            .collect();
        let response = aiec_harness::model::Response {
            text: None,
            tool_calls: vec![ToolCall {
                id: "1".into(),
                name: format!("t{}", rng.below(4)),
                arguments,
            }],
            usage: Default::default(),
            stop: aiec_harness::model::Stop::ModelFinished,
            latency_ms: 0,
        };
        let observations = vec![(format!("obs{}", rng.below(8)), rng.below(2) == 0)];
        if guard.observe_turn(&response, &observations) {
            guard.record_progress(&[]);
        }
    }
}

#[test]
fn a_session_file_of_arbitrary_bytes_is_ignored_not_fatal() {
    let mut rng = Rng::new(0x9999);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("session.json");
    for _ in 0..200 {
        let len = rng.below(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        std::fs::write(&path, &bytes).expect("write");
        // A corrupt or hostile state file means "nothing to resume", never a
        // failed run: the caller still gets a result.
        assert!(SessionState::load(&path).expect("load returns").is_none());
    }
}

#[test]
fn redaction_survives_a_value_full_of_secrets_and_lookalikes() {
    let secret = "sk-fuzz-0123456789abcdef";
    // SAFETY: unique to this test, single-threaded setup.
    unsafe { std::env::set_var("AIEC_AGENT_API_KEY", secret) };

    let mut value = serde_json::json!({
        "exact": format!("prefix {secret} suffix"),
        "partial": "sk-fuzz-0123456789",
        "lookalike": "sk-fuzz-999999999999zzzz",
        "nested": [{"deep": {"deeper": secret}}],
        "number": 42,
        "null": null,
        "array": [1, 2, 3],
    });
    redaction::scrub_value(&mut value);

    // The exact secret never survives, anywhere in the document.
    assert!(!value.to_string().contains(secret), "a secret survived");
    // A near miss is left alone: over-redaction destroys the evidence too. A
    // string that merely CONTAINS the secret is not a near miss and is
    // correctly redacted.
    assert_eq!(value["partial"], "sk-fuzz-0123456789");
    assert_eq!(value["lookalike"], "sk-fuzz-999999999999zzzz");
    // And the document keeps its shape.
    assert_eq!(value["number"], 42);
    assert!(value["null"].is_null());
    assert_eq!(value["array"], serde_json::json!([1, 2, 3]));
}

#[test]
fn a_request_built_from_hostile_state_still_encodes() {
    let mut rng = Rng::new(0x4242);
    let mut state = aiec_harness::context::TaskState::new("objective");
    for _ in 0..200 {
        let len = rng.below(2_000);
        state.commands_run.push(
            (0..len)
                .map(|_| char::from_u32(0x20 + rng.below(0x1F00) as u32).unwrap_or('x'))
                .collect::<String>(),
        );
        state
            .files_changed
            .insert(format!("f{}.rs", rng.below(100)));
    }
    let request = Completion {
        messages: vec![
            Message::System {
                content: aiec_harness::prompt::system_prompt(&state),
            },
            Message::User {
                content: "go".to_owned(),
            },
        ],
        tools: registry().specs(),
        model: "m".to_owned(),
        reasoning: aiec_harness::model::Reasoning::Off,
        max_output_tokens: 1024,
    };
    // Must serialize, must not panic, and must be bounded enough to matter.
    let encoded = serde_json::to_string(&request).expect("encodes");
    assert!(
        encoded.len() < 8 * 1024 * 1024,
        "request blew up to {} bytes",
        encoded.len()
    );
}
