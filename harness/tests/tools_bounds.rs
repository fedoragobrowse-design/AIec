//! Behavioural tests for the tool boundary.
//!
//! These are about the things that are easy to get wrong and hard to notice:
//! a bound that does not bind, a truncation marker that is not there, a shell
//! quietly interposed between the model and the workspace, a symlink walked
//! straight through. Each test asserts an observable a broken implementation
//! would fail, not merely that a call returned.

use std::path::{Path, PathBuf};
use std::time::Instant;

use aiec_harness::model::ToolCall;
use aiec_harness::task::Limits;
use aiec_harness::tools::{
    Phase, Tool, ToolContext, ToolOutput, bash::Bash, edit::Edit, git, list_tools, read::Read,
    registry, search, write::Write,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn ctx(root: &Path, max_tool_output_bytes: usize) -> ToolContext {
    ToolContext {
        root: root.to_path_buf(),
        limits: Limits {
            max_tool_output_bytes,
            command_timeout_seconds: 10,
            ..Limits::default()
        },
        phase: Phase::Working,
    }
}

/// A workspace, canonicalised the way the loop canonicalises it.
fn workspace() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("temp dir");
    let real = dir.path().canonicalize().expect("canonical temp dir");
    (dir, real)
}

async fn content_of(tool: &dyn Tool, args: Value, ctx: &ToolContext) -> String {
    match tool.call(&args, ctx).await {
        Ok(ToolOutput { content, .. }) => content,
        Err(failure) => panic!("{} failed unexpectedly: {}", tool.name(), failure.message),
    }
}

async fn failure_of(tool: &dyn Tool, args: Value, ctx: &ToolContext) -> String {
    match tool.call(&args, ctx).await {
        Ok(out) => panic!(
            "{} unexpectedly succeeded with: {}",
            tool.name(),
            out.content
        ),
        Err(failure) => failure.message,
    }
}

fn write_file(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, body).expect("write fixture");
}

// ------------------------------------------------------------------ read

#[tokio::test]
async fn read_bounds_its_output_and_says_what_it_dropped() {
    let (_dir, root) = workspace();
    let body: String = (1..=5_000).map(|i| format!("line {i}\n")).collect();
    write_file(&root, "big.txt", &body);

    let ctx = ctx(&root, 2_048);
    let out = content_of(&Read, json!({ "path": "big.txt" }), &ctx).await;

    assert!(
        out.len() <= 2_048,
        "read ignored the ceiling: {}",
        out.len()
    );
    assert!(
        out.contains("[truncated:"),
        "no truncation marker in: {out}"
    );
    // The header has to name the real size, or the model believes it has seen
    // the whole file. A partial read cannot know the line count, and must not
    // pretend to.
    assert!(
        out.contains(&format!("{} bytes on disk", body.len())),
        "no file size in: {out}"
    );
    assert!(out.contains("more bytes not read"), "no byte note: {out}");
}

#[tokio::test]
async fn read_reports_binary_instead_of_emitting_mojibake() {
    let (_dir, root) = workspace();
    std::fs::write(
        root.join("blob.bin"),
        [0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01, 0x02],
    )
    .expect("write");

    let ctx = ctx(&root, 8 * 1024);
    let out = content_of(&Read, json!({ "path": "blob.bin" }), &ctx).await;

    assert!(out.contains("binary"), "binary file not identified: {out}");
    assert!(!out.contains('\u{0}'), "raw NUL leaked into the output");
}

#[tokio::test]
async fn read_numbers_lines_the_way_edit_expects_them() {
    let (_dir, root) = workspace();
    write_file(&root, "n.txt", "alpha\nbeta\ngamma\n");

    let ctx = ctx(&root, 8 * 1024);
    let out = content_of(&Read, json!({ "path": "n.txt" }), &ctx).await;
    assert!(
        out.contains("     2\tbeta"),
        "second line not numbered 2: {out}"
    );

    // The whole point of the numbering: a line the model saw as `2` is the
    // line `edit` changes.
    let edited = content_of(
        &Edit,
        json!({ "path": "n.txt", "start": 2, "end": 2, "content": "BETA\n" }),
        &ctx,
    )
    .await;
    assert!(
        edited.contains("now 3 lines"),
        "unexpected line count: {edited}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("n.txt")).expect("read back"),
        "alpha\nBETA\ngamma\n"
    );
}

#[tokio::test]
async fn read_offset_is_zero_based_and_line_numbers_are_not() {
    let (_dir, root) = workspace();
    write_file(&root, "n.txt", "one\ntwo\nthree\n");

    let ctx = ctx(&root, 8 * 1024);
    let out = content_of(&Read, json!({ "path": "n.txt", "offset": 1 }), &ctx).await;
    assert!(
        out.contains("showing lines 2-3"),
        "offset 1 should start at line 2: {out}"
    );
    assert!(out.contains("     2\ttwo"), "numbering restarted: {out}");
    assert!(!out.contains("one"), "offset did not skip: {out}");
}

// ----------------------------------------------------------------- edit

#[tokio::test]
async fn edit_inserts_deletes_and_refuses_a_range_past_the_end() {
    let (_dir, root) = workspace();
    let ctx = ctx(&root, 8 * 1024);
    write_file(&root, "f.txt", "a\nb\nc\n");

    // Insert before line 1: start > end, nothing removed.
    let out = content_of(
        &Edit,
        json!({ "path": "f.txt", "start": 1, "end": 0, "content": "top\n" }),
        &ctx,
    )
    .await;
    assert!(
        out.contains("now 4 lines"),
        "insert did not add a line: {out}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("f.txt")).expect("read back"),
        "top\na\nb\nc\n"
    );

    // Delete lines 2-3 with empty content.
    let out = content_of(
        &Edit,
        json!({ "path": "f.txt", "start": 2, "end": 3, "content": "" }),
        &ctx,
    )
    .await;
    assert!(
        out.contains("now 2 lines"),
        "delete did not remove lines: {out}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("f.txt")).expect("read back"),
        "top\nc\n"
    );

    // Past the end of a two line file.
    let message = failure_of(
        &Edit,
        json!({ "path": "f.txt", "start": 5, "end": 5, "content": "x\n" }),
        &ctx,
    )
    .await;
    assert!(
        message.contains("past the end"),
        "unhelpful error: {message}"
    );

    // A zero start is a 1-based mistake, not line zero.
    let message = failure_of(
        &Edit,
        json!({ "path": "f.txt", "start": 0, "end": 0, "content": "x\n" }),
        &ctx,
    )
    .await;
    assert!(message.contains("1-based"), "unhelpful error: {message}");
}

#[tokio::test]
async fn edit_keeps_the_rest_of_a_large_file_intact() {
    let (_dir, root) = workspace();
    let body: String = (1..=5_000).map(|i| format!("line {i}\n")).collect();
    write_file(&root, "big.txt", &body);
    let ctx = ctx(&root, 4_096);

    let out = content_of(
        &Edit,
        json!({ "path": "big.txt", "start": 2500, "end": 2502, "content": "replaced\n" }),
        &ctx,
    )
    .await;
    assert!(
        out.contains("now 4998 lines"),
        "wrong new line count: {out}"
    );

    let after = std::fs::read_to_string(root.join("big.txt")).expect("read back");
    let lines: Vec<&str> = after.lines().collect();
    assert_eq!(lines.len(), 4_998);
    assert_eq!(lines[2_498], "line 2499", "text before the edit changed");
    assert_eq!(
        lines[2_499], "replaced",
        "replacement is in the wrong place"
    );
    assert_eq!(lines[2_500], "line 2503", "text after the edit changed");
}

#[tokio::test]
async fn edit_refuses_a_symlink_that_leaves_the_workspace() {
    let (_dir, root) = workspace();
    let outside_dir = TempDir::new().expect("outside temp dir");
    let outside = outside_dir.path().join("secret.txt");
    std::fs::write(&outside, "untouched\n").expect("write outside");
    std::os::unix::fs::symlink(&outside, root.join("link.txt")).expect("symlink");

    let ctx = ctx(&root, 8 * 1024);
    let message = failure_of(
        &Edit,
        json!({ "path": "link.txt", "start": 1, "end": 1, "content": "pwned\n" }),
        &ctx,
    )
    .await;
    assert!(
        message.contains("outside the workspace"),
        "unhelpful: {message}"
    );
    assert_eq!(
        std::fs::read_to_string(&outside).expect("read outside"),
        "untouched\n",
        "the file outside the workspace was modified"
    );
}

#[tokio::test]
async fn edit_refuses_a_binary_file() {
    let (_dir, root) = workspace();
    std::fs::write(root.join("blob.bin"), [0x00, 0x01, b'a', b'\n']).expect("write");
    let ctx = ctx(&root, 8 * 1024);

    let message = failure_of(
        &Edit,
        json!({ "path": "blob.bin", "start": 1, "end": 1, "content": "x\n" }),
        &ctx,
    )
    .await;
    assert!(message.contains("binary"), "unhelpful error: {message}");
}

// ---------------------------------------------------------------- write

#[tokio::test]
async fn write_creates_parents_and_reports_the_bytes_it_wrote() {
    let (_dir, root) = workspace();
    let ctx = ctx(&root, 8 * 1024);

    let out = content_of(
        &Write,
        json!({ "path": "deep/nested/new.txt", "content": "hello\nworld\n" }),
        &ctx,
    )
    .await;
    assert!(out.contains("12 bytes"), "byte count missing: {out}");
    assert!(out.contains("2 lines"), "line count missing: {out}");
    assert_eq!(
        std::fs::read_to_string(root.join("deep/nested/new.txt")).expect("read back"),
        "hello\nworld\n"
    );
}

#[tokio::test]
async fn write_refuses_a_symlink_directory_pointing_out_of_the_workspace() {
    let (_dir, root) = workspace();
    let outside_dir = TempDir::new().expect("outside temp dir");
    std::os::unix::fs::symlink(outside_dir.path(), root.join("out")).expect("symlink");

    let ctx = ctx(&root, 8 * 1024);
    let message = failure_of(
        &Write,
        json!({ "path": "out/planted.txt", "content": "pwned" }),
        &ctx,
    )
    .await;
    assert!(
        message.contains("outside the workspace"),
        "write followed a symlink out: {message}"
    );
    assert!(
        !outside_dir.path().join("planted.txt").exists(),
        "a file was created outside the workspace"
    );
}

// ----------------------------------------------------------------- grep

#[tokio::test]
async fn grep_bounds_the_number_of_matches_and_names_the_loss() {
    let (_dir, root) = workspace();
    for i in 0..300 {
        write_file(&root, &format!("m/{i}.txt"), &format!("needle here {i}\n"));
    }
    // Never searched, never counted.
    write_file(&root, ".git/config", "needle in git internals\n");
    write_file(
        &root,
        "node_modules/dep/index.js",
        "needle in a dependency\n",
    );
    write_file(&root, "target/debug/build.rs", "needle in build output\n");

    let ctx = ctx(&root, 64 * 1024);
    let out = content_of(&search::Grep, json!({ "pattern": "needle" }), &ctx).await;

    let matches = out.lines().filter(|l| l.contains(":needle")).count();
    assert_eq!(matches, 200, "match cap not applied: {matches} shown");
    assert!(out.contains("[truncated:"), "no marker: {out}");
    assert!(!out.contains(".git/"), "searched .git: {out}");
    assert!(
        !out.contains("node_modules"),
        "searched node_modules: {out}"
    );
    assert!(!out.contains("target/"), "searched target: {out}");
}

#[tokio::test]
async fn grep_output_is_bounded_by_the_tool_ceiling() {
    let (_dir, root) = workspace();
    for i in 0..200 {
        write_file(&root, &format!("m/{i}.txt"), &format!("needle {i}\n"));
    }
    let ctx = ctx(&root, 512);

    let out = content_of(&search::Grep, json!({ "pattern": "needle" }), &ctx).await;
    assert!(out.len() <= 512, "ceiling ignored: {}", out.len());
    assert!(out.contains("[truncated"), "no marker: {out}");
}

#[tokio::test]
async fn grep_refuses_an_invalid_regex_and_honours_a_glob_filter() {
    let (_dir, root) = workspace();
    write_file(&root, "a.rs", "fn main() {}\n");
    write_file(&root, "b.md", "fn main() {}\n");
    let ctx = ctx(&root, 8 * 1024);

    let message = failure_of(&search::Grep, json!({ "pattern": "fn (" }), &ctx).await;
    assert!(message.contains("regex"), "unhelpful error: {message}");

    let out = content_of(
        &search::Grep,
        json!({ "pattern": "fn main", "glob": "*.rs" }),
        &ctx,
    )
    .await;
    assert!(out.contains("a.rs:"), "glob filter dropped a match: {out}");
    assert!(!out.contains("b.md"), "glob filter did not exclude: {out}");
}

// ----------------------------------------------------------- find / glob

#[tokio::test]
async fn find_bounds_a_large_tree_and_skips_git() {
    let (_dir, root) = workspace();
    for i in 0..700 {
        write_file(&root, &format!("t/{i}/mod.rs"), "// x\n");
    }
    write_file(&root, ".git/HEAD", "ref: refs/heads/main\n");

    let ctx = ctx(&root, 64 * 1024);
    let out = content_of(&search::Find, json!({ "name": "mod.rs" }), &ctx).await;

    let listed = out.lines().filter(|l| l.starts_with("t/")).count();
    assert_eq!(listed, 500, "name cap not applied: {listed} listed");
    assert!(
        out.contains("200-more matching files not listed"),
        "no count of what was dropped: {out}"
    );
    assert!(!out.contains(".git/"), "listed .git: {out}");
}

#[tokio::test]
async fn glob_matches_across_directories_and_stays_bounded() {
    let (_dir, root) = workspace();
    for i in 0..600 {
        write_file(&root, &format!("g/{i}/x.toml"), "k = 1\n");
    }
    write_file(&root, "top.toml", "k = 1\n");
    let ctx = ctx(&root, 32 * 1024);

    let out = content_of(&search::Glob, json!({ "pattern": "**/*.toml" }), &ctx).await;
    assert!(
        out.contains("g/0/x.toml"),
        "did not cross directories: {out}"
    );
    assert!(out.contains("601 paths"), "wrong total: {out}");
    assert!(
        out.contains("101-more matches not listed"),
        "no drop note: {out}"
    );

    // `*` stays inside one directory, so this is the top level file only.
    let out = content_of(&search::Glob, json!({ "pattern": "*.toml" }), &ctx).await;
    assert!(
        out.contains("top.toml"),
        "did not match at the top level: {out}"
    );
    assert!(
        !out.contains("g/0/x.toml"),
        "`*` crossed a separator: {out}"
    );
}

// ------------------------------------------------------------------ bash

#[tokio::test]
async fn bash_executes_argv_without_a_shell() {
    let (_dir, root) = workspace();
    let ctx = ctx(&root, 8 * 1024);

    // If a shell were interposed, this would create the file and print `b`.
    let out = content_of(
        &Bash,
        json!({ "command": ["echo", "a; touch pwned; echo b"] }),
        &ctx,
    )
    .await;
    assert!(
        out.contains("a; touch pwned; echo b"),
        "the argument was not passed through literally: {out}"
    );
    assert!(!root.join("pwned").exists(), "a shell interpreted `;`");

    // Nor is there variable expansion, globbing, or redirection.
    let out = content_of(&Bash, json!({ "command": ["echo", "$HOME"] }), &ctx).await;
    assert!(
        out.contains("$HOME"),
        "the shell expanded a variable: {out}"
    );

    // Nor is there globbing: with a file present, a shell would have expanded
    // `*` to its name.
    write_file(&root, "expand-me.txt", "x\n");
    let out = content_of(&Bash, json!({ "command": ["echo", "*"] }), &ctx).await;
    assert!(out.contains("\n*\n"), "the shell globbed: {out}");
    assert!(!out.contains("expand-me.txt"), "the shell globbed: {out}");

    // A shell string is refused rather than quietly split.
    let message = failure_of(&Bash, json!({ "command": "echo hi" }), &ctx).await;
    assert!(
        message.contains("array"),
        "a shell string was accepted: {message}"
    );
}

#[tokio::test]
async fn bash_runs_in_the_requested_directory_and_reports_the_exit_code() {
    let (_dir, root) = workspace();
    write_file(&root, "sub/marker.txt", "x\n");
    let ctx = ctx(&root, 8 * 1024);

    let out = content_of(&Bash, json!({ "command": ["ls"], "cwd": "sub" }), &ctx).await;
    assert!(out.contains("marker.txt"), "cwd not honoured: {out}");
    assert!(out.contains("exit 0"), "no exit code: {out}");
}

#[tokio::test]
async fn bash_kills_a_command_that_outlives_its_timeout() {
    let (_dir, root) = workspace();
    let ctx = ctx(&root, 8 * 1024);

    let started = Instant::now();
    let out = content_of(
        &Bash,
        json!({ "command": ["sleep", "30"], "timeout_seconds": 1 }),
        &ctx,
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
        out.contains("timed out"),
        "the timeout was not reported: {out}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "the call waited for the process instead of killing it: {elapsed:?}"
    );
}

#[tokio::test]
async fn bash_caps_output_from_a_command_that_prints_forever() {
    let (_dir, root) = workspace();
    let ctx = ctx(&root, 64 * 1024);

    // `yes` never stops. Without a cap on the pipe this is an out-of-memory
    // kill rather than a tool result; the read end closing once the cap is
    // reached is what ends it, so this must come back promptly.
    let started = Instant::now();
    let out = content_of(
        &Bash,
        json!({ "command": ["yes", "spam"], "timeout_seconds": 20 }),
        &ctx,
    )
    .await;
    assert!(
        out.contains("stdout incomplete at"),
        "unbounded stdout: {out}"
    );
    assert!(out.len() <= 64 * 1024, "ceiling ignored: {}", out.len());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the call hung on a command that never stops"
    );
}

#[tokio::test]
async fn bash_reports_a_command_that_cannot_start() {
    let (_dir, root) = workspace();
    let ctx = ctx(&root, 8 * 1024);

    let message = failure_of(
        &Bash,
        json!({ "command": ["definitely-not-a-real-binary-xyz"] }),
        &ctx,
    )
    .await;
    assert!(
        message.contains("could not start"),
        "unhelpful error: {message}"
    );
}

// ------------------------------------------------------------------ git

fn git(root: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} failed");
}

fn repo_with_one_commit(root: &Path) {
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "harness@example.invalid"]);
    git(root, &["config", "user.name", "harness"]);
    write_file(root, "tracked.txt", "original\n");
    git(root, &["add", "tracked.txt"]);
    git(root, &["commit", "-q", "-m", "first"]);
}

#[tokio::test]
async fn git_status_and_diff_use_git_and_report_what_changed() {
    let (_dir, root) = workspace();
    repo_with_one_commit(&root);
    write_file(&root, "tracked.txt", "original\nchanged\n");
    let ctx = ctx(&root, 64 * 1024);

    let status = content_of(&git::Status, json!({}), &ctx).await;
    assert!(status.contains("head: "), "no HEAD: {status}");
    assert!(
        status.contains("tracked.txt"),
        "change not reported: {status}"
    );

    let diff = content_of(&git::Diff, json!({}), &ctx).await;
    assert!(diff.contains("+changed"), "diff missing the change: {diff}");
    assert!(diff.contains("1 file changed"), "no diffstat: {diff}");
}

#[tokio::test]
async fn git_diff_bounds_a_very_large_diff() {
    let (_dir, root) = workspace();
    repo_with_one_commit(&root);
    // Comfortably past the diff cap.
    let body: String = (0..20_000).map(|i| format!("before {i}\n")).collect();
    write_file(&root, "tracked.txt", &body);
    let after: String = (0..20_000).map(|i| format!("after {i}\n")).collect();
    write_file(&root, "tracked.txt", &after);
    let ctx = ctx(&root, 512 * 1024);

    let diff = content_of(&git::Diff, json!({}), &ctx).await;
    assert!(
        diff.contains("[truncated: diff incomplete at"),
        "unbounded diff"
    );
    assert!(diff.len() <= 512 * 1024, "ceiling ignored: {}", diff.len());
}

#[tokio::test]
async fn git_tools_say_so_plainly_outside_a_repository() {
    let (_dir, root) = workspace();
    let ctx = ctx(&root, 8 * 1024);

    let status = content_of(&git::Status, json!({}), &ctx).await;
    assert!(status.contains("not a git repository"), "unclear: {status}");

    let diff = content_of(&git::Diff, json!({}), &ctx).await;
    assert!(diff.contains("not a git repository"), "unclear: {diff}");
}

// -------------------------------------------------------- path escapes

#[tokio::test]
async fn every_path_tool_refuses_to_leave_the_workspace() {
    let (_dir, root) = workspace();
    write_file(&root, "inside.txt", "x\n");
    let ctx = ctx(&root, 8 * 1024);
    let escape = "../escape";

    let attempts: Vec<(&dyn Tool, Value)> = vec![
        (&Read, json!({ "path": escape })),
        (&Write, json!({ "path": escape, "content": "x" })),
        (
            &Edit,
            json!({ "path": escape, "start": 1, "end": 1, "content": "x" }),
        ),
        (&search::Grep, json!({ "pattern": "x", "path": escape })),
        (&search::Find, json!({ "name": "x", "path": escape })),
        (&search::Glob, json!({ "pattern": "*", "path": escape })),
        (&Bash, json!({ "command": ["ls"], "cwd": escape })),
    ];

    for (tool, args) in attempts {
        let message = failure_of(tool, args, &ctx).await;
        assert!(
            message.contains("leaves the workspace") || message.contains("outside the workspace"),
            "{} let `{}` through: {message}",
            tool.name(),
            escape
        );
    }
}

#[tokio::test]
async fn every_path_tool_refuses_an_absolute_path() {
    let (_dir, root) = workspace();
    let ctx = ctx(&root, 8 * 1024);
    let absolute = "/etc/passwd";

    let attempts: Vec<(&dyn Tool, Value)> = vec![
        (&Read, json!({ "path": absolute })),
        (&Write, json!({ "path": absolute, "content": "x" })),
        (
            &Edit,
            json!({ "path": absolute, "start": 1, "end": 1, "content": "x" }),
        ),
        (&search::Grep, json!({ "pattern": "x", "path": absolute })),
    ];

    for (tool, args) in attempts {
        let message = failure_of(tool, args, &ctx).await;
        assert!(
            message.contains("absolute"),
            "{} accepted an absolute path: {message}",
            tool.name()
        );
    }
}

/// The registry is the only thing that knows a tool's name, and it is the one
/// place an object-safety mistake in an impl would show up as a refusal rather
/// than a compile error.
#[tokio::test]
async fn every_advertised_name_dispatches_through_the_registry() {
    let (_dir, root) = workspace();
    write_file(&root, "f.txt", "one\ntwo\n");
    let ctx = ctx(&root, 8 * 1024);
    let registry = registry();

    for name in list_tools() {
        let arguments = match name {
            "read" => json!({ "path": "f.txt" }),
            "write" => json!({ "path": "w.txt", "content": "x" }),
            "edit" => json!({ "path": "f.txt", "start": 1, "end": 1, "content": "uno\n" }),
            "grep" => json!({ "pattern": "uno" }),
            "find" => json!({ "name": "f" }),
            "glob" => json!({ "pattern": "*.txt" }),
            "bash" => json!({ "command": ["true"] }),
            "git_status" | "git_diff" => json!({}),
            other => panic!("no arguments known for {other}"),
        };
        let call = ToolCall {
            id: "t1".into(),
            name: name.to_owned(),
            arguments: arguments.to_string(),
        };
        match registry.dispatch(&call, &ctx).await {
            Ok(out) => assert!(!out.content.is_empty(), "{name} returned nothing"),
            Err(failure) => panic!("{name} did not dispatch: {}", failure.message),
        }
    }
}

/// GUI registration is conditional on two independent facts: the task asked
/// (mode) and the guest can back it (binaries). The matrix below pins the
/// corners against fixture PATHs — never the process environment, which
/// sibling threads share — so a refactor that registers unbacked tools, or
/// drops backed ones, fails loudly.
#[test]
fn gui_tools_register_only_when_asked_and_backed() {
    use aiec_harness::task::GuiMode;
    use aiec_harness::tools::registry_for_on;
    use std::os::unix::fs::PermissionsExt;

    fn touch(dir: &std::path::Path, name: &str) {
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("fixture binary");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("fixture binary executable");
    }
    fn names(mode: GuiMode, path: &std::ffi::OsStr) -> Vec<String> {
        registry_for_on(mode, path)
            .specs()
            .iter()
            .map(|s| s.name.clone())
            .collect()
    }
    let modes = [
        GuiMode::Off,
        GuiMode::Browser,
        GuiMode::Desktop,
        GuiMode::Playwright,
    ];

    // Nothing on the fixture PATH: no GUI tool anywhere, whatever is asked.
    let empty = tempfile::tempdir().expect("tempdir");
    for mode in modes {
        let got = names(mode, empty.path().as_os_str());
        assert!(
            !got.contains(&"browser".to_owned()),
            "{mode:?} registered browser unbacked"
        );
        assert!(
            !got.contains(&"desktop".to_owned()),
            "{mode:?} registered desktop unbacked"
        );
    }
    // Full GUI guest: browser everywhere except Off, desktop only on Desktop.
    let full = tempfile::tempdir().expect("tempdir");
    for bin in ["chromedriver", "chromium", "Xvfb", "xdotool"] {
        touch(full.path(), bin);
    }
    let full_path = full.path().as_os_str().to_owned();
    assert!(!names(GuiMode::Off, &full_path).contains(&"browser".to_owned()));
    assert!(!names(GuiMode::Off, &full_path).contains(&"desktop".to_owned()));
    assert!(names(GuiMode::Browser, &full_path).contains(&"browser".to_owned()));
    assert!(!names(GuiMode::Browser, &full_path).contains(&"desktop".to_owned()));
    assert!(names(GuiMode::Desktop, &full_path).contains(&"browser".to_owned()));
    assert!(names(GuiMode::Desktop, &full_path).contains(&"desktop".to_owned()));
    assert!(names(GuiMode::Playwright, &full_path).contains(&"browser".to_owned()));
    assert!(!names(GuiMode::Playwright, &full_path).contains(&"desktop".to_owned()));
    // Browser binaries but no X stack: desktop never registers.
    let browser_only = tempfile::tempdir().expect("tempdir");
    for bin in ["chromedriver", "chromium"] {
        touch(browser_only.path(), bin);
    }
    let browser_path = browser_only.path().as_os_str().to_owned();
    assert!(names(GuiMode::Desktop, &browser_path).contains(&"browser".to_owned()));
    assert!(!names(GuiMode::Desktop, &browser_path).contains(&"desktop".to_owned()));
}

#[test]
fn gui_digest_differs_across_modes() {
    // A result earned with a browser must never verify against a text-only
    // task: the mode joins the digest, so swapping it changes the hash.
    use aiec_harness::task::Task;
    let raw = |gui: &str| {
        format!(r#"{{"instruction": "click the button", "workspace": "/tmp", "gui": "{gui}"}}"#)
    };
    let off = Task::parse(&raw("off")).expect("off parses").digest;
    let browser = Task::parse(&raw("browser")).expect("browser parses").digest;
    let desktop = Task::parse(&raw("desktop")).expect("desktop parses").digest;
    assert_ne!(off, browser);
    assert_ne!(browser, desktop);
    assert_ne!(off, desktop);
}
