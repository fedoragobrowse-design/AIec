//! The repository, understood through git rather than by walking it.
//!
//! Almost every coding-agent task happens in a git repository, so the index is
//! the cheapest possible description of it: one command answers "what is
//! tracked, what is the head, what is dirty" without touching the filesystem.
//! A checkout of a large repository must not cost a scan before the first
//! model request.

use std::path::Path;
use std::process::Command;

use crate::task::{GitEvidence, HarnessError};

/// A bound on the diff handed to the model, so a large change does not become a
/// context-sized bill.
const MAX_DIFF: usize = 120 * 1024;

pub struct Repository {
    root: std::path::PathBuf,
    available: bool,
}

impl Repository {
    /// Opens the repository at `path`, which may be a subdirectory of it.
    pub fn open(path: &Path) -> Result<Self, HarnessError> {
        let root = git_root(path).unwrap_or_else(|| path.to_path_buf());
        let available = git(&root, &["rev-parse", "--git-dir"]).is_ok();
        Ok(Self { root, available })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn is_git(&self) -> bool {
        self.available
    }

    pub fn head(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        git(&self.root, &["rev-parse", "HEAD"])
            .ok()
            .map(|text| text.trim().to_owned())
    }

    pub fn branch(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        git(&self.root, &["rev-parse", "--abbrev-ref", "HEAD"])
            .ok()
            .map(|text| text.trim().to_owned())
    }

    /// Empty when git is unavailable, so a caller can tell "clean" from "no
    /// repository here" without a second call.
    pub fn status(&self) -> String {
        if !self.available {
            return String::new();
        }
        status(&self.root).unwrap_or_default()
    }

    /// Everything a reader needs to judge what the agent did, collected after
    /// the fact rather than reconstructed from the agent's own account.
    pub fn collect_after(&self) -> GitEvidence {
        let head_after = self.head();
        let diff = if self.available {
            diff(&self.root).unwrap_or_default()
        } else {
            String::new()
        };
        // Once, and unquoted. The changed-file list is parsed out of the same
        // bytes the status is rendered from, so reading it twice means the
        // evidence can disagree with itself: a file written between the two
        // calls appears in one field and not the other, and nothing downstream
        // can tell which list is the real one.
        let status = if self.available {
            raw_status(&self.root).unwrap_or_default()
        } else {
            String::new()
        };
        let changed_files = changed_files(&self.root, &status);
        let status = render_status(&status);
        GitEvidence {
            head_before: None,
            head_after,
            branch: self.branch(),
            status,
            diff_truncated: diff.len() >= MAX_DIFF,
            diff,
            changed_files,
        }
    }
}

/// Working tree status, as the `git_status` tool returns it.
pub fn status(root: &Path) -> Result<String, HarnessError> {
    raw_status(root).map(|raw| render_status(&raw))
}

/// The raw porcelain stream: NUL-separated records, every path exactly as it
/// exists.
///
/// `-z` is not a display choice. Without it git C-quotes any path holding a
/// backslash, a control character or a non-ASCII byte, and the two status
/// columns sit in front of the path with a variable number of spaces between
/// them - so a parser that trims the remainder hands back `M src/main.rs`, or
/// `new name.txt -> old name.txt`, neither of which is a path that exists.
fn raw_status(root: &Path) -> Result<String, HarnessError> {
    git(root, &["status", "--porcelain=v1", "-z"])
        .map_err(|_| HarnessError::Tool("git status failed; is this a repository?".to_owned()))
}

/// The `-z` stream rendered for a human reading it.
///
/// NUL written as a newline, because that is what separates the records anyway;
/// `changed_files` holds the exact paths this was rendered from.
fn render_status(raw: &str) -> String {
    raw.replace('\0', "\n")
}

/// The uncommitted diff, as the `git_diff` tool returns it.
pub fn diff(root: &Path) -> Result<String, HarnessError> {
    let text = git(root, &["--no-pager", "diff", "HEAD"]).unwrap_or_default();
    if text.len() <= MAX_DIFF {
        return Ok(text);
    }
    Ok(crate::tools::compress(&text, MAX_DIFF))
}

/// Distinct paths touched by the working tree, parsed from the raw `-z` stream.
///
/// Each record is two status characters, a space, then the path - and for a
/// rename or a copy the *original* path follows as its own NUL-terminated
/// field. Only the destination is kept: that is the path the run left behind,
/// and the original is what the caller already has from the commit.
fn changed_files(root: &Path, status: &str) -> Vec<String> {
    if !status.is_empty() {
        return porcelain_paths(status);
    }
    // No porcelain output: fall back to the diff's own file headers.
    git(root, &["--no-pager", "diff", "--name-only", "HEAD"])
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The paths `git status --porcelain=v1 -z` reported, exactly as it printed them.
fn porcelain_paths(porcelain: &str) -> Vec<String> {
    let mut fields = porcelain.split('\0');
    let mut paths = Vec::new();
    while let Some(record) = fields.next() {
        let bytes = record.as_bytes();
        // The shortest possible record is `XY ` plus one byte of path.
        if bytes.len() < 4 || bytes[2] != b' ' {
            continue;
        }
        // `bytes[2]` is ASCII, so index 3 is a character boundary and this
        // slice can never split one.
        paths.push(record[3..].to_owned());
        if matches!(bytes[0], b'R' | b'C') {
            let _ = fields.next();
        }
    }
    paths
}

fn git_root(path: &Path) -> Option<std::path::PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        return None;
    }
    Some(std::path::PathBuf::from(text))
}

fn git(root: &Path, args: &[&str]) -> Result<String, HarnessError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| HarnessError::Io(format!("git: {error}")))?;
    if !output.status.success() {
        return Err(HarnessError::Tool(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("aiec-git-{label}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).unwrap();
        let run = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(&path)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
                .output()
                .unwrap()
        };
        run(&["init", "-q"]);
        std::fs::write(path.join("a.txt"), "one\n").unwrap();
        run(&["add", "a.txt"]);
        run(&["commit", "-q", "-m", "initial"]);
        path
    }

    #[test]
    fn a_repository_reports_its_head_and_branch() {
        let path = repo("head");
        let repository = Repository::open(&path).expect("opened");
        assert!(repository.is_git());
        assert_eq!(repository.head().map(|h| h.len()), Some(40));
        assert!(repository.branch().is_some());
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn a_dirty_tree_is_visible() {
        let path = repo("dirty");
        std::fs::write(path.join("a.txt"), "one\ntwo\n").unwrap();
        std::fs::write(path.join("b.txt"), "new\n").unwrap();
        let repository = Repository::open(&path).expect("opened");
        let evidence = repository.collect_after();
        assert!(evidence.status.contains("a.txt"), "{}", evidence.status);
        assert!(
            evidence.changed_files.iter().any(|f| f == "b.txt"),
            "{:?}",
            evidence.changed_files
        );
        assert!(
            evidence.diff.contains("two"),
            "the diff should show the change"
        );
        let _ = std::fs::remove_dir_all(path);
    }

    /// The changed-file list has to hold paths, and the paths have to exist.
    ///
    /// A file an agent edited without staging is porcelain ` M src/main.rs`:
    /// two status columns, then the path. Splitting the line at its first space
    /// and trimming the rest - the obvious way - yields `M src/main.rs`, which
    /// is not a file. Renames came back as `new name.txt -> old name.txt`, and
    /// a path holding a non-ASCII byte came back in git's C-quoted form. All
    /// three were reported as files the run touched.
    #[test]
    fn changed_files_are_paths_that_exist() {
        let path = repo("changed");
        std::fs::create_dir_all(path.join("src")).unwrap();
        std::fs::write(path.join("src/main.rs"), "fn main() {}\n").unwrap();
        let run = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(&path)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
                .output()
                .unwrap()
        };
        run(&["add", "src/main.rs"]);
        run(&["commit", "-q", "-m", "second"]);

        // A plain edit: the single most common thing a coding agent does.
        std::fs::write(path.join("src/main.rs"), "fn main() { println!(); }\n").unwrap();
        // A rename of something committed above.
        std::fs::write(path.join("a.txt"), "one\n").unwrap();
        run(&["add", "a.txt"]);
        run(&["commit", "-q", "-m", "third"]);
        run(&["mv", "a.txt", "renamed a.txt"]);
        run(&["add", "-A"]);
        // A name git C-quotes unless -z is asked for.
        std::fs::write(path.join("caf\u{e9}.txt"), "x\n").unwrap();

        let repository = Repository::open(&path).expect("opened");
        let evidence = repository.collect_after();
        assert!(
            evidence.changed_files.contains(&"src/main.rs".to_owned()),
            "an edited file reported as {:?}",
            evidence.changed_files
        );
        assert!(
            evidence.changed_files.contains(&"renamed a.txt".to_owned()),
            "a rename reported as {:?}",
            evidence.changed_files
        );
        assert!(
            evidence.changed_files.contains(&"caf\u{e9}.txt".to_owned()),
            "a quoted path reported as {:?}",
            evidence.changed_files
        );
        for reported in &evidence.changed_files {
            assert!(
                path.join(reported).exists(),
                "{reported:?} is not a file in the repository"
            );
        }
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn a_directory_outside_a_repository_is_not_a_git_repository() {
        let path = std::env::temp_dir().join(format!("aiec-nogit-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).unwrap();
        let repository = Repository::open(&path).expect("opened");
        // Not a failure: an agent may legitimately be pointed at a plain
        // directory, and refusing to start would be worse than losing the diff.
        assert!(!repository.is_git());
        assert!(repository.head().is_none());
        let _ = std::fs::remove_dir_all(path);
    }
}
