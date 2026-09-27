//! Proves the local-only guarantee and the absence of a host execution path.
//!
//! These tests read the crate's own source rather than trusting that a
//! reviewer noticed: a workload command reaching the host would be a silent
//! failure of the whole product's premise, and the only reliable guard is one
//! that fails if the invariant is ever broken.

use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(crate_root().join("src")).expect("src is readable") {
        let path = entry.expect("readable entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    files.sort();
    assert!(!files.is_empty(), "the crate has source files");
    files
}

/// Removes line comments and doc comments.
///
/// The invariant is about code, not prose: these files *document* that they do
/// not spawn a process, and a naive scan would flag the very comment that
/// promises it.
fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        // Drop a trailing `// ...`, keeping any string literal before it. This
        // is intentionally simple: the files under test do not contain a `//`
        // inside a string on the same line as code that matters here.
        let code = match line.find("//") {
            Some(index) if !line[..index].contains('"') => &line[..index],
            _ => line,
        };
        out.push_str(code);
        out.push('\n');
    }
    out
}

#[test]
fn no_workload_can_be_executed_on_the_host() {
    // A process spawn anywhere in this crate would be a way for a tool call to
    // run on the machine hosting the MCP server. Startup maintenance is done by
    // the binary entry point alone, and even there no external process is
    // spawned.
    let offenders: Vec<String> = sources()
        .into_iter()
        .filter_map(|path| {
            // Comments are stripped first: these files *document* that they do
            // not spawn a process, and that promise would otherwise trip the
            // very scan that enforces it.
            let text = strip_comments(&std::fs::read_to_string(&path).expect("readable"));
            for needle in ["std::process::Command", "process::Command", "Command::new"] {
                if text.contains(needle) {
                    return Some(format!(
                        "{} uses `{needle}`",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }
            }
            None
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "workload execution must never reach the host, but found: {offenders:?}"
    );
}

#[test]
fn the_crate_does_not_name_a_cloud_or_external_provider() {
    // The local-only guarantee is only meaningful if the code cannot even name a
    // hosted endpoint outside of the refusal messages that reject it.
    for path in sources() {
        let text = strip_comments(&std::fs::read_to_string(&path).expect("readable"));
        if path.file_name().is_some_and(|name| name == "guard.rs") {
            // guard.rs names the cloud endpoint precisely in order to reject it.
            continue;
        }
        for needle in ["aiec.gobrowse.dev", "api.e2b.dev", "e2b.dev"] {
            assert!(
                !text.contains(needle),
                "{} names an external provider `{needle}`; this server is local-only",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
        }
    }
}

#[test]
fn hosted_and_provider_runtimes_are_refused() {
    for runtime in ["hosted", "e2b", "E2B", "Hosted"] {
        let refused = aiec_mcp::guard::LocalEndpoint::require_local_runtime(runtime);
        if runtime == "Hosted" {
            // An unknown spelling is rejected as an invalid argument, which is
            // also a refusal: it never silently becomes a local runtime.
            assert!(refused.is_err(), "`{runtime}` must not be accepted");
        } else {
            assert!(
                refused.is_err(),
                "`{runtime}` must be refused by the local-only guard"
            );
        }
    }
    for runtime in ["firecracker", "bwrap-dev", "docker"] {
        assert!(
            aiec_mcp::guard::LocalEndpoint::require_local_runtime(runtime).is_ok(),
            "`{runtime}` is a local runtime and must be allowed"
        );
    }
}

#[test]
fn a_remote_control_plane_is_refused_in_every_spelling() {
    for url in [
        "https://api.aiec.gobrowse.dev",
        "https://api.aiec.gobrowse.dev/",
        "http://api.aiec.gobrowse.dev:8080",
        // A private address is not a remote one, but it is not loopback either,
        // and it is refused unless the operator opted in.
        "https://192.168.1.10:18443",
        "https://10.0.0.5",
        "https://example.com",
    ] {
        assert!(
            aiec_mcp::guard::LocalEndpoint::parse(url, false).is_err(),
            "`{url}` must be refused by default"
        );
    }
}
