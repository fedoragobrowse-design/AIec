//! Running many things: batches, matrices and repetitions.
//!
//! These exist because agent evaluation is a product of several variables and
//! the product has to be cleaned up however it turns out. Everything here is
//! built on the same [`crate::runs::submit_and_execute`] as a single run, so a
//! matrix cell is not a different kind of work from a one-off - it is the same
//! work, scheduled.
//!
//! Two properties matter more than the ergonomics:
//!
//! * **Bounded concurrency.** Asking for fifty runs must not be a way to take
//!   the cluster. Concurrency is capped, and the scheduler's own admission
//!   still applies underneath, so this only limits our appetite rather than
//!   replacing the control plane's judgement.
//! * **No collapsed evidence.** An agent is nondeterministic, so repetitions
//!   are the point. Every run is kept and reported separately; summarising
//!   them into one number is how a flaky agent looks reliable.

use std::collections::BTreeMap;

use aiec_core::TenantId;
use aiec_core::run::RepoSpec;
use aiec_core::run::{BatchOptions, Run, RunState, WorkloadSpec};
use chrono::{DateTime, Utc};
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::runs::{RunRequest, submit_and_execute};
use crate::{AppState, CoreError};

/// One cell of a matrix: a named combination of variables.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixCell {
    /// The variable name and value, e.g. `{"model": "opus"}`.
    pub axis: BTreeMap<String, String>,
    pub request: RunRequest,
}

/// A set of combinations to run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MatrixSpec {
    #[serde(default)]
    pub cells: Vec<MatrixCell>,
    #[serde(default)]
    pub options: BatchOptions,
}

/// A cell's outcome, kept whole.
#[derive(Clone, Debug, Serialize)]
pub struct CellResult {
    pub axis: BTreeMap<String, String>,
    pub run_id: Uuid,
    pub state: RunState,
    pub succeeded: bool,
    /// Populated when the cell was retained for debugging.
    pub sandbox_id: Option<Uuid>,
    pub failure_reason: Option<String>,
}

/// What a matrix produced.
#[derive(Clone, Debug, Serialize)]
pub struct MatrixResult {
    pub matrix_id: Uuid,
    pub requested_at: DateTime<Utc>,
    pub max_parallel: usize,
    pub results: Vec<CellResult>,
}

impl MatrixResult {
    /// How many cells succeeded, reported without judging which was better.
    pub fn successes(&self) -> usize {
        self.results.iter().filter(|r| r.succeeded).count()
    }

    /// Per-axis breakdown, so a reader can see which variable moved the number
    /// rather than being handed a single verdict.
    pub fn by_axis(&self) -> BTreeMap<String, (usize, usize)> {
        let mut summary: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for result in &self.results {
            for (key, value) in &result.axis {
                let entry = summary.entry(format!("{key}={value}")).or_insert((0, 0));
                entry.0 += usize::from(result.succeeded);
                entry.1 += 1;
            }
        }
        summary
    }
}

/// How many cells a batch may run at once.
///
/// Extracted so the bound can be tested without a cluster. The bound is the
/// point of a batch - asking for fifty runs must not be a way to take the
/// cluster - and a test that needs a live scheduler to observe a `min` is a
/// test that will not be run.
fn effective_parallelism(options: &BatchOptions, requested: usize) -> usize {
    if requested == 0 {
        return 1;
    }
    options.max_parallel.clamp(1, requested)
}

/// Runs a list of workloads with bounded concurrency.
///
/// The tasks are chunked rather than all fired at once: a slow task must not
/// hold the whole batch behind it, and the cluster must never see more
/// simultaneous requests than it agreed to.
pub async fn run_batch(
    state: &AppState,
    tenant: TenantId,
    requests: Vec<RunRequest>,
    options: &BatchOptions,
) -> Result<Vec<Run>, CoreError> {
    options.validate()?;
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let limit = effective_parallelism(options, requests.len());

    // A sliding window rather than fixed chunks.
    //
    // Chunks bound the concurrency correctly but stall: a chunk finishes only
    // when its slowest cell does, so one cell that takes three minutes holds
    // the rest of its chunk idle even when slots have been free for two of
    // them. On a matrix of variable workloads that is most of the wall time
    // spent waiting on the slowest member of whichever group it landed in.
    //
    // `buffer_unordered` keeps the same bound and fills each freed slot
    // immediately, which is the property that matters when the point of the
    // bound is to match the cluster's real capacity rather than merely not
    // exceed it.
    let outcomes = futures::stream::iter(requests)
        .map(|request| submit_and_execute(state, tenant, request))
        .buffer_unordered(limit)
        .collect::<Vec<_>>()
        .await;
    // A batch reports the runs it managed to start. One cell failing to
    // schedule must not abandon the others: the point of a batch is that
    // fifty tasks do not need fifty separate submissions.
    Ok(outcomes.into_iter().flatten().collect())
}

/// Runs the same workload several times.
///
/// Each repetition is its own sandbox and its own run, because an agent that
/// happens to pass twice is not the same as one that passes reliably.
pub async fn run_repetitions(
    state: &AppState,
    tenant: TenantId,
    request: RunRequest,
    repetitions: u32,
    options: &BatchOptions,
) -> Result<Vec<Run>, CoreError> {
    if repetitions == 0 {
        return Ok(Vec::new());
    }
    let mut requests = Vec::with_capacity(repetitions as usize);
    for _ in 0..repetitions {
        let mut copy = request.clone();
        // Each repetition gets its own idempotency scope, otherwise the second
        // would be handed the first's run and nothing would execute at all.
        copy.idempotency_key = request.idempotency_key.as_ref().map(|key| {
            let mut unique = key.clone();
            unique.push_str(&format!("-{}", Uuid::now_v7()));
            unique
        });
        requests.push(copy);
    }
    run_batch(state, tenant, requests, options).await
}

/// Expands and runs a matrix.
pub async fn run_matrix(
    state: &AppState,
    tenant: TenantId,
    spec: &MatrixSpec,
) -> Result<MatrixResult, CoreError> {
    spec.options.validate()?;
    let matrix_id = Uuid::now_v7();
    let requested_at = Utc::now();

    // Parent every cell on the matrix so the set is addressable as a group.
    let mut requests = Vec::with_capacity(spec.cells.len());
    let mut axes = Vec::with_capacity(spec.cells.len());
    for cell in &spec.cells {
        let mut request = cell.request.clone();
        request.matrix_id = Some(matrix_id);
        if request.idempotency_key.is_none() {
            request.idempotency_key = Some(format!("matrix-{matrix_id}-{}", Uuid::now_v7()));
        }
        requests.push(request);
        axes.push(cell.axis.clone());
    }

    let runs = run_batch(state, tenant, requests, &spec.options).await?;

    let results = runs
        .into_iter()
        .enumerate()
        .map(|(index, run)| CellResult {
            axis: axes.get(index).cloned().unwrap_or_default(),
            succeeded: run.state == RunState::Succeeded,
            sandbox_id: run.retained_sandbox_id,
            run_id: run.id,
            state: run.state,
            failure_reason: run.failure_reason,
        })
        .collect();

    let result = MatrixResult {
        matrix_id,
        requested_at,
        max_parallel: spec.options.max_parallel,
        results,
    };

    // The matrix as a whole is summarised, never judged: what "better" means
    // depends on the metric the caller cares about, and picking one for them
    // would be inventing a conclusion the data does not support.
    let summary = serde_json::json!({
        "cells": result.results.len(),
        "successes": result.successes(),
        "by_axis": result.by_axis(),
    });
    let _ = state
        .repository()
        .append_run_event(aiec_core::run::RunEvent {
            id: crate::new_id(),
            run_id: matrix_id,
            sandbox_id: None,
            event_type: "matrix.completed".to_owned(),
            occurred_at: Utc::now(),
            detail: summary,
        })
        .await;

    Ok(result)
}

/// A reusable evaluation suite: named tasks against a repository.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuiteTask {
    pub name: String,
    pub repo_url: String,
    #[serde(default)]
    pub reference: Option<String>,
    pub command: Vec<String>,
    #[serde(default)]
    pub validations: Vec<Vec<String>>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Suite {
    pub name: String,
    #[serde(default)]
    pub tasks: Vec<SuiteTask>,
}

impl Suite {
    /// Parses a suite from YAML-ish JSON/TOML-compatible text.
    ///
    /// Deliberately not a bespoke language: a suite has to be reviewable in a
    /// pull request, and a format nobody can read is a format nobody reviews.
    pub fn parse(contents: &str) -> Result<Self, CoreError> {
        serde_json::from_str(contents)
            .map_err(|error| CoreError::InvalidRequest(format!("invalid suite: {error}")))
    }

    /// Expands the suite into one workload per task.
    pub fn to_matrix(&self, image: Option<String>, parallelism: usize) -> MatrixSpec {
        let cells = self
            .tasks
            .iter()
            .map(|task| {
                let mut axis = BTreeMap::new();
                axis.insert("task".to_owned(), task.name.clone());
                let workload = WorkloadSpec {
                    image: image.clone(),
                    repo: Some(RepoSpec {
                        url: task.repo_url.clone(),
                        reference: task.reference.clone(),
                        ..Default::default()
                    }),
                    command: task.command.clone(),
                    validations: task.validations.clone(),
                    timeout_seconds: task.timeout_seconds,
                    ..Default::default()
                };
                MatrixCell {
                    axis,
                    request: RunRequest {
                        workload,
                        ..Default::default()
                    },
                }
            })
            .collect();
        MatrixSpec {
            cells,
            options: BatchOptions {
                max_parallel: parallelism.max(1),
            },
        }
    }
}

#[cfg(test)]
mod parallelism_tests {
    use super::effective_parallelism;
    use aiec_core::run::BatchOptions;

    /// The batch bound, stated as arithmetic rather than as a live run.
    ///
    /// Both halves matter and they fail differently: without the `min` a
    /// two-cell batch would still open `max_parallel` futures, and without the
    /// floor a caller asking for zero would silently run nothing.
    #[test]
    fn the_batch_never_exceeds_what_was_asked_or_what_exists() {
        let at = |parallel: usize, requested: usize| {
            effective_parallelism(
                &BatchOptions {
                    max_parallel: parallel,
                },
                requested,
            )
        };
        assert_eq!(at(3, 10), 3, "never more than was asked for");
        assert_eq!(at(10, 3), 3, "never more futures than there are cells");
        assert_eq!(at(64, 100), 64, "a large batch is still bounded");
        assert_eq!(at(0, 5), 1, "a caller asking for zero gets one, not none");
        assert_eq!(at(8, 0), 1, "an empty batch is not a division by zero");
    }
}
