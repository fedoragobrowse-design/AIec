//! The agent loop: one turn, one model request, one batch of tool calls.
//!
//! Kept beside the machinery it drives rather than in the binary, so the loop can
//! reach the context engine and the budgets directly instead of through
//! accessors that exist only to satisfy a boundary it does not have.

use crate::task::{GitEvidence, HarnessError, Result_, StopReason, Task};
use crate::{HARNESS_VERSION, budget, context, events, loop_guard, model, tools};
use std::sync::Arc;

/// Drives one task from a task document to a settled result.
pub async fn execute(task: Task, outcome: &mut Result_) -> Result<(), HarnessError> {
    let repo = task.repo();
    let events = Arc::new(events::Sink::new(HARNESS_VERSION));
    events.started();

    // The repository is understood through git's index rather than by
    // walking the tree: a checkout of a large repository must not cost a
    // filesystem scan before the first model request.
    let git = tools::git::Repository::open(&repo)?;
    // What the repository looked like before the run, kept because the
    // after-collection cannot know it: `collect_after` runs once, at the end,
    // and reports `head_before: null` for every run it is given. Held here
    // instead of being written into `outcome` directly because the merge at
    // the bottom is the thing that has to be right, and it is the thing that
    // can be tested on its own.
    let before = GitEvidence {
        head_before: git.head(),
        branch: git.branch(),
        status: git.status(),
        ..Default::default()
    };

    let registry = tools::Registry::new(&repo);
    let model = model::Client::from_task(&task)?;
    let mut budget = budget::Budget::new(task.max_turns, task.max_requests);
    let mut context = context::Context::new(&task);
    let mut guard = loop_guard::Guard::default();

    let stop = loop {
        if budget.turns_exhausted() {
            break StopReason::TurnBudget;
        }
        if budget.requests_exhausted() {
            break StopReason::RequestBudget;
        }
        if let Some(reason) = guard.stalled() {
            break reason;
        }

        budget.next_turn();
        events.turn(budget.turns());
        if context.should_compact() {
            let (from, to) = context.compact();
            events.compacted(from, to);
        }
        // Before the request, not after it: a request that is already over the
        // window is the failure this exists to prevent. The ceiling used to be
        // a constant nothing read, so a long run grew one request at a time
        // until the provider refused it and the whole task failed with an
        // error that named nothing the operator could act on.

        let reply = match model
            .complete(&context, &registry.schemas(), budget.reserve_output())
            .await
        {
            Ok(reply) => {
                budget.charge_request();
                context.push_assistant(reply.text.clone());
                budget.absorb(reply.usage);
                reply
            }
            Err(HarnessError::Budget(_)) => break StopReason::RequestBudget,
            Err(error) => return Err(error),
        };
        // The model's own calls go into the conversation before any of them
        // runs. They are the questions the results below answer, and a
        // transcript that keeps the answers and drops the questions is one the
        // model cannot read on its next request.
        context.push_tool_calls(reply.tool_calls.clone());

        if reply.tool_calls.is_empty() {
            context.push_note(format!(
                "agent finished: {}",
                reply.text.unwrap_or_default()
            ));
            break StopReason::ModelFinished;
        }

        for call in reply.tool_calls {
            guard.observe(&call);
            // The guard's second signal needs to know whether the call changed
            // anything. Only an edit does: a model that reads and searches for
            // forty turns has learned nothing about the repository and is
            // spending a VM's budget on it. Without this call the no-progress
            // half of the guard was never reached from the loop at all, so it
            // was a rule that existed only in its own tests.
            guard.observe_effect(matches!(call.name.as_str(), "write" | "edit"));
            events.tool_call(&call.name);
            let outcome_for_call = registry.execute(&call, &repo).await;
            let rendered = match outcome_for_call {
                Ok(text) => {
                    events.tool_result(&call.name, true);
                    text
                }
                Err(error) => {
                    // A tool that fails is information for the model, not
                    // the end of the run: it is told what went wrong and
                    // gets to try something else.
                    events.tool_result(&call.name, false);
                    format!("error: {error}")
                }
            };
            context.push_tool_result(&call, &rendered);
        }
    };

    outcome.turns = budget.turns();
    outcome.requests = budget.requests();
    outcome.usage = budget.usage;
    outcome.stop_reason = stop;
    events.stopped(stop);

    // Validation is the caller's definition of done, not the model's.
    let validations = tools::validate::run_all(&repo, &task.validations).await;
    let all_passed = validations.iter().all(|v| v.ok);
    outcome.validations = validations;

    // The evidence, collected from inside the machine where the work
    // happened rather than guessed from the agent's own account of it.
    outcome.git = merge_git_evidence(&before, git.collect_after());

    outcome.summary = context.summary();
    outcome.ok = all_passed && stop == StopReason::TaskComplete
        || (all_passed && stop == StopReason::ModelFinished);
    outcome.events = events.drain();
    Ok(())
}

/// Combines the observation made before the run with the one made after it.
///
/// `collect_after` can only describe the state it finds at the end, so on its
/// own it reports `head_before: null` and the diff has no commit to be read
/// against - a result document that cannot say what the agent changed it from.
/// Only `head_before` is taken from the earlier observation: everything else
/// (`status`, `diff`, `changed_files`, `head_after`) is an overwrite by the
/// after-collection, deliberately, because it describes the tree the run left
/// behind and that is what the document is evidence *of*. `branch` is the one
/// field both sides observed; the run's own branch is the truthful one when it
/// moved, and the before-branch fills in only when the after-collection could
/// not read one at all.
fn merge_git_evidence(before: &GitEvidence, mut after: GitEvidence) -> GitEvidence {
    after.head_before = before.head_before.clone();
    if after.branch.is_none() {
        after.branch = before.branch.clone();
    }
    after
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A repository with one commit, which is the state the harness opens.
    fn repository(label: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("aiec-agent-{label}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).unwrap();
        let git = |args: &[&str]| {
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
        git(&["init", "-q"]);
        std::fs::write(path.join("a.txt"), "one\n").unwrap();
        git(&["add", "a.txt"]);
        git(&["commit", "-q", "-m", "initial"]);
        path
    }

    /// The result document says what the run started from, not only where it
    /// ended up.
    ///
    /// `collect_after` alone reported `head_before: null` for every run, so a
    /// reader had the final head and a diff and no way to tie the two
    /// together - which is the one question the evidence exists to answer.
    /// Here the run commits, so the two heads are genuinely different and
    /// swapping one for the other would be visible.
    #[test]
    fn the_pre_run_head_survives_the_evidence_collection() {
        let path = repository("evidence");
        let git = tools::git::Repository::open(&path).expect("opened");
        let before = GitEvidence {
            head_before: git.head(),
            branch: git.branch(),
            status: git.status(),
            ..Default::default()
        };

        std::fs::write(path.join("b.txt"), "two\n").unwrap();
        Command::new("git")
            .args(["add", "b.txt"])
            .current_dir(&path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-q", "-m", "second"])
            .current_dir(&path)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .output()
            .unwrap();

        let merged = merge_git_evidence(&before, git.collect_after());
        assert!(
            merged.head_before.is_some(),
            "the pre-run head was dropped: {merged:?}"
        );
        assert_eq!(merged.head_before, before.head_before);
        assert_ne!(
            merged.head_before, merged.head_after,
            "the head moved and both observations must survive"
        );
        // The branch did not move, so the before-observation and the
        // after-collection agree; the merge must not have invented a third
        // answer for it.
        assert_eq!(merged.branch, before.branch, "{merged:?}");
        let _ = std::fs::remove_dir_all(path);
    }
}
