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
        let changed_files = changed_files(&self.root, &self.status());
        GitEvidence {
            head_before: None,
            head_after,
            branch: self.branch(),
            status: self.status(),
            diff_truncated: diff.len() >= MAX_DIFF,
            diff,
            changed_files,
        }
    }
}

/// Working tree status, as the `git_status` tool returns it.
pub fn status(root: &Path) -> Result<String, HarnessError> {
    git(root, &["status", "--porcelain=v1"])
        .map_err(|_| HarnessError::Tool("git status failed; is this a repository?".to_owned()))
}

/// The uncommitted diff, as the `git_diff` tool returns it.
pub fn diff(root: &Path) -> Result<String, HarnessError> {
    let text = git(root, &["--no-pager", "diff", "HEAD"]).unwrap_or_default();
    if text.len() <= MAX_DIFF {
        return Ok(text);
    }
    Ok(crate::tools::compress(&text, MAX_DIFF))
}

/// Distinct paths touched by the working tree, parsed from porcelain status.
fn changed_files(root: &Path, status: &str) -> Vec<String> {
    if !status.is_empty() {
        return status
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| line.split_once(' ').map(|(_, rest)| rest.trim().to_owned()))
            .collect();
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
