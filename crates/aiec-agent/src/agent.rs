//! The agent loop: one turn, one model request, one batch of tool calls.
//!
//! Kept beside the machinery it drives rather than in the binary, so the loop can
//! reach the context engine and the budgets directly instead of through
//! accessors that exist only to satisfy a boundary it does not have.

use crate::task::{HarnessError, Result_, StopReason, Task};
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
    outcome.git.head_before = git.head();
    outcome.git.branch = git.branch();
    outcome.git.status = git.status();

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

        if reply.tool_calls.is_empty() {
            context.push_note(format!(
                "agent finished: {}",
                reply.text.unwrap_or_default()
            ));
            break StopReason::ModelFinished;
        }

        for call in reply.tool_calls {
            guard.observe(&call);
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
            context.push_tool_result(&call.name, &rendered);
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
    outcome.git = git.collect_after();

    outcome.summary = context.summary();
    outcome.ok = all_passed && stop == StopReason::TaskComplete
        || (all_passed && stop == StopReason::ModelFinished);
    outcome.events = events.drain();
    Ok(())
}
