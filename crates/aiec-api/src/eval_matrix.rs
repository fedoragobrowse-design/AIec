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

use aiec_core::run::MatrixCellIdentity;
use aiec_core::run::RepoSpec;
use aiec_core::run::{BatchOptions, ResourceRequirements, Run, RunState, WorkloadSpec};
use aiec_core::run_queue::RunQueueLimits;
use aiec_core::runtime::{RuntimeCapabilities, RuntimeIsolation, capabilities_satisfy};
use aiec_core::storage::{MatrixCursor, WorkerStatus};
use aiec_core::{QuotaLimits, QuotaUsage, RuntimeKind, TenantId};
use aiec_storage::NODE_HEARTBEAT_TTL_SECONDS;
use chrono::{DateTime, Duration, Utc};
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::runs::{RunRequest, parse_runtime, required_capabilities, submit_and_execute};
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
    /// The run this cell became, when it became one.
    ///
    /// Optional because a cell can be refused before it ever runs, and a
    /// matrix that hid a refusal behind an error for the whole request would be
    /// hiding the other cells with it: they have executed, they have been
    /// billed, and they would be filed under a matrix id the caller was never
    /// told.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<Run>,
    /// Why this cell produced no run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What a matrix produced.
#[derive(Clone, Debug, Serialize)]
pub struct MatrixResult {
    pub matrix_id: Uuid,
    pub requested_at: DateTime<Utc>,
    /// The bound the caller asked for.
    pub max_parallel: usize,
    /// The bound the batch actually ran under, which capacity may have lowered.
    pub effective_parallel: usize,
    pub results: Vec<CellResult>,
}

impl MatrixResult {
    /// How many cells succeeded, reported without judging which was better.
    pub fn successes(&self) -> usize {
        self.results
            .iter()
            .filter(|result| {
                result
                    .run
                    .as_ref()
                    .is_some_and(|run| run.state == RunState::Succeeded)
            })
            .count()
    }

    /// Per-axis breakdown, so a reader can see which variable moved the number
    /// rather than being handed a single verdict.
    pub fn by_axis(&self) -> BTreeMap<String, (usize, usize)> {
        let mut summary: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for result in &self.results {
            for (key, value) in &result.axis {
                let entry = summary.entry(format!("{key}={value}")).or_insert((0, 0));
                entry.0 += usize::from(
                    result
                        .run
                        .as_ref()
                        .is_some_and(|run| run.state == RunState::Succeeded),
                );
                entry.1 += 1;
            }
        }
        summary
    }
}

/// What the cluster could be running right now, sampled once for a whole batch.
///
/// A batch needs a bound on how many of its cells run at once, and the caller's
/// own `max_parallel` does not answer that question: it answers "how many did
/// you ask for", which on a cluster with two free slots is a wish. A bound taken
/// from the wish is a bound nobody enforced. This is the answer the cluster's
/// own ledgers give - who can place a cell shaped like this one, and how much of
/// the tenant's quota is left - read once per batch rather than once per cell.
/// A capacity read per cell is exactly how a batch becomes an N+1 against the
/// one query it needed.
///
/// Both numbers are `None` when nothing can answer, and that is not zero: a
/// deployment that runs its sandboxes in-process registers no workers, keeps no
/// quota ledger, and still has capacity. Guessing low there would serialise
/// precisely the deployments that have no queue to serialise them against.
#[derive(Clone, Copy, Debug, Default)]
pub struct BatchCapacity {
    /// Cells the workers eligible for this batch could start right now.
    free_slots: Option<usize>,
    /// Cells this tenant's remaining quota could admit.
    tenant_slots: Option<usize>,
}

impl BatchCapacity {
    /// Reads both ledgers once and sizes the batch against its heaviest cell.
    ///
    /// The heaviest cell of each group, because a matrix mixes shapes: sizing
    /// for the smallest would promise a concurrency the largest member cannot
    /// use, and sizing per cell would size the batch for the cell that happens
    /// to be submitted first rather than the one that decides whether the
    /// cluster can cope.
    async fn sample(state: &AppState, tenant: TenantId, requests: &[RunRequest]) -> Self {
        let Some(groups) = placement_groups(state, requests).await else {
            return Self::default();
        };
        // One worker read for the whole batch. Every cell's eligibility is
        // decided against this same snapshot, so a batch that samples per cell
        // cannot promise capacity it then spends on its own N+1.
        let workers = match state.repository().list_workers(false).await {
            Ok(workers) => workers,
            Err(error) => {
                tracing::warn!(%error, "batch capacity unknown: worker ledger unreadable");
                return Self {
                    free_slots: None,
                    tenant_slots: tenant_slots(state, tenant, &groups).await,
                };
            }
        };
        let now = Utc::now();
        Self {
            free_slots: worker_slots(&workers, &groups, now),
            tenant_slots: tenant_slots(state, tenant, &groups).await,
        }
    }
}

/// Cells that can only ever be placed the same way, and the heaviest of them.
///
/// One group per distinct (runtime, capability demand). A batch that mixes
/// runtimes has to be sized against the worst of them, because any cell in
/// flight could be one of the awkward ones: bounding by the roomiest group
/// would let the batch open more waiters than the tightest group can place.
#[derive(Clone, Debug)]
struct PlacementGroup {
    runtime: RuntimeKind,
    required: RuntimeCapabilities,
    minimum: Option<RuntimeIsolation>,
    demand: CellDemand,
}

/// Groups the batch by where its cells would actually land, or `None` when that
/// cannot be resolved.
///
/// Resolution goes through the same runtime registry the placement path uses,
/// because the alternative is guessing: a deployment whose registry selects
/// Hosted places nothing on a worker at all, and reading that as "the workers
/// are full" would serialise a batch the cluster never queued.
async fn placement_groups(
    state: &AppState,
    requests: &[RunRequest],
) -> Option<Vec<PlacementGroup>> {
    let mut groups: Vec<PlacementGroup> = Vec::new();
    for request in requests {
        let requested = match request.requested_runtime.as_deref() {
            Some(raw) => match parse_runtime(raw) {
                Ok(kind) => Some(kind),
                Err(error) => {
                    // The cell will be refused at admission; sizing the rest of
                    // the batch from an unreadable runtime would be a guess.
                    tracing::warn!(%error, "batch capacity unknown: unusable requested runtime");
                    return None;
                }
            },
            None => None,
        };
        let required = required_capabilities(&request.requirements);
        let minimum = if request.requirements.full_kernel_isolation {
            Some(RuntimeIsolation::MicroVm)
        } else {
            None
        };
        let (runtime, minimum_disk_mb) = match state.runtime_registry() {
            Some(registry) => match registry.select(requested, &required, minimum).await {
                Ok(selection) => (selection.runtime, selection.capabilities.minimum_disk_mb),
                Err(error) => {
                    tracing::warn!(%error, "batch capacity unknown: runtime selection failed");
                    return None;
                }
            },
            None => (
                state.runtime_kind(),
                state.runtime().capabilities().minimum_disk_mb,
            ),
        };
        let group = PlacementGroup {
            runtime,
            required,
            minimum,
            demand: cell_demand(&request.resources, minimum_disk_mb),
        };
        match groups
            .iter_mut()
            .find(|existing| same_placement(existing, &group))
        {
            Some(existing) => {
                existing.demand = heaviest(existing.demand, group.demand);
            }
            None => groups.push(group),
        }
    }
    Some(groups)
}

/// Whether two cells would be placed by the same rule.
fn same_placement(left: &PlacementGroup, right: &PlacementGroup) -> bool {
    left.runtime == right.runtime
        && left.minimum == right.minimum
        && left.required == right.required
}

/// The larger of two shapes, field by field.
fn heaviest(left: CellDemand, right: CellDemand) -> CellDemand {
    CellDemand {
        cpu: left.cpu.max(right.cpu),
        memory_bytes: left.memory_bytes.max(right.memory_bytes),
        disk_bytes: left.disk_bytes.max(right.disk_bytes),
    }
}

/// One cell's share of a host, as the placement path will actually ask for it.
#[derive(Clone, Copy, Debug)]
struct CellDemand {
    cpu: u32,
    memory_bytes: u64,
    disk_bytes: u64,
}

/// The floors a sandbox is created with, so the estimate asks for what the run
/// will really reserve rather than what its request left at zero.
fn cell_demand(resources: &ResourceRequirements, minimum_disk_mb: u64) -> CellDemand {
    CellDemand {
        cpu: resources.cpu.max(1),
        memory_bytes: u64::from(resources.memory_mb.max(512)) * 1024 * 1024,
        disk_bytes: u64::from(resources.disk_mb.max(1024))
            .max(minimum_disk_mb)
            .saturating_mul(1024 * 1024),
    }
}

/// How many cells the eligible workers could start right now, or `None` when
/// the batch does not run on workers at all.
///
/// `None` for a hosted batch is the honest answer rather than a zero: hosted
/// capacity is reached through a provider inside the runtime and is never
/// leased from a worker, so a local worker ledger says nothing about it. A
/// mixed batch is unbounded for the same reason - one of its cells has no
/// worker - and bounding it by the others would cap a batch on behalf of a
/// queue that never sees the hosted cell.
fn worker_slots(
    workers: &[WorkerStatus],
    groups: &[PlacementGroup],
    now: DateTime<Utc>,
) -> Option<usize> {
    if workers.is_empty()
        || groups
            .iter()
            .any(|group| group.runtime == RuntimeKind::Hosted)
    {
        // A deployment that runs its sandboxes in-process registers no workers
        // and still has capacity; reading an absent ledger as zero would
        // serialise precisely the deployments with no queue to serialise them.
        return None;
    }
    // The tightest group, because every in-flight cell could be one of its
    // members: sizing by the roomiest group would promise placements the
    // tightest one cannot accept.
    Some(
        groups
            .iter()
            .map(|group| {
                workers
                    .iter()
                    .filter(|worker| eligible(worker, group, now))
                    .map(|worker| slots_on(worker, group.demand))
                    .fold(0usize, usize::saturating_add)
            })
            .min()
            .unwrap_or(0),
    )
}

/// Whether placement would actually consider this worker for this cell.
///
/// The same things `select_schedulable_node` checks, in the same terms: a
/// worker that is drained, unhealthy, or has stopped heartbeating is present
/// and unusable, and one running a different runtime, or missing a capability
/// the cell needs, cannot host it however much room it has. Counting it anyway
/// is how a Firecracker-only batch ends up sized against a cluster full of free
/// Docker workers.
///
/// Explicit isolation is exact-match, like placement's JSON containment.
/// `Process` means unspecified here and is omitted from that demand.
fn eligible(worker: &WorkerStatus, group: &PlacementGroup, now: DateTime<Utc>) -> bool {
    let registration = &worker.registration;
    registration.healthy
        && worker.accepting_sandboxes
        && registration.last_heartbeat + Duration::seconds(NODE_HEARTBEAT_TTL_SECONDS) >= now
        && registration.runtime == group.runtime
        && (group.required.isolation == RuntimeIsolation::Process
            || registration.capabilities.isolation == group.required.isolation)
        && capabilities_satisfy(&registration.capabilities, &group.required, group.minimum)
}

/// How many cells of `demand` one worker's free ledger can take.
fn slots_on(worker: &WorkerStatus, demand: CellDemand) -> usize {
    let registration = &worker.registration;
    let cpu = usize::try_from(registration.available_vcpus / demand.cpu).unwrap_or(usize::MAX);
    let memory = usize::try_from(registration.available_memory_bytes / demand.memory_bytes)
        .unwrap_or(usize::MAX);
    let disk = usize::try_from(registration.available_disk_bytes / demand.disk_bytes)
        .unwrap_or(usize::MAX);
    cpu.min(memory).min(disk)
}

/// How many cells of each group this tenant has quota left for, or `None` when
/// the store keeps no quota to read.
///
/// The scheduler still decides: every cell passes through it and it re-reads
/// the same rows under a lock. This only stops the batch from opening more
/// waiters than the tenant could ever fill, which on its own would leave a
/// caller watching cells fail one by one on a quota it was already over.
async fn tenant_slots(
    state: &AppState,
    tenant: TenantId,
    groups: &[PlacementGroup],
) -> Option<usize> {
    let (limits, usage) = match state.repository().get_tenant_quota_usage(tenant).await {
        Ok(quota) => quota,
        // No ledger is not no capacity, so an absent quota store simply does
        // not bound the batch.
        Err(CoreError::Unsupported(_)) => return None,
        Err(error) => {
            tracing::warn!(%error, "tenant quota unreadable: batch not bounded by it");
            return None;
        }
    };
    Some(
        groups
            .iter()
            .map(|group| quota_slots(limits, usage, group.demand))
            .min()
            .unwrap_or(0),
    )
}

/// Cells of `demand` still inside the tenant's remaining quota.
fn quota_slots(limits: QuotaLimits, usage: QuotaUsage, demand: CellDemand) -> usize {
    let mebibyte = 1024 * 1024;
    let active = u64::from(
        limits
            .max_active_sandboxes
            .saturating_sub(usage.active_sandboxes),
    );
    let cpu = u64::from(limits.max_vcpus.saturating_sub(usage.vcpus)) / u64::from(demand.cpu);
    let memory = limits.max_memory_mb.saturating_sub(usage.memory_mb)
        / (demand.memory_bytes / mebibyte).max(1);
    let disk =
        limits.max_disk_mb.saturating_sub(usage.disk_mb) / (demand.disk_bytes / mebibyte).max(1);
    usize::try_from(active.min(cpu).min(memory).min(disk)).unwrap_or(usize::MAX)
}

/// How many cells a batch may have in flight.
///
/// Five ceilings, each answering a different question, and none of them allowed
/// to answer "none": what the caller asked for, what the durable queue will
/// execute, what the cluster says is free for these cells, what the tenant's
/// quota has room for, and never fewer than one waiter.
fn effective_parallelism(
    options: &BatchOptions,
    requested: usize,
    capacity: &BatchCapacity,
    admission: Option<&RunQueueLimits>,
) -> usize {
    if requested == 0 {
        return 1;
    }
    let mut bound = options.max_parallel.clamp(1, requested);
    if let Some(limits) = admission {
        // The queue executes at most `max_active` cells at a time and admits at
        // most `tenant_pending` for one tenant, whatever a caller asks for.
        // Those bound how fast this batch can go, not whether it may be asked
        // for at all.
        bound = bound
            .min(limits.max_active as usize)
            .min(limits.tenant_pending as usize);
    }
    if let Some(free) = capacity.free_slots {
        bound = bound.min(free);
    }
    if let Some(quota) = capacity.tenant_slots {
        bound = bound.min(quota);
    }
    // One waiter is still progress. A busy cluster hands a slot to the queue as
    // it frees one, so a batch that opened no waiters would sit there until
    // something noticed; and refusing it would turn "the cluster is full" into
    // "the evaluation never happened", which is a worse answer than a slower
    // one.
    bound.max(1)
}

/// A finished batch and the bound it ran under.
#[derive(Debug)]
pub struct BatchReport {
    /// One entry per submitted request, in submission order. A cell that was
    /// refused appears as its error rather than being missing.
    pub runs: Vec<Result<Run, CoreError>>,
    /// Cells the batch kept in flight at once.
    ///
    /// Reported rather than inferred: a caller that asked for sixteen and got
    /// four has been given a smaller batch than it asked for, and the only
    /// honest way to say so is to say it.
    pub effective_parallel: usize,
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
    // All-or-nothing for callers that asked for a list of runs. `collect`
    // reports the first failure and drops the rest, which is what a caller of
    // this function wants: a partial list of runs is not a batch.
    run_batch_bounded(state, tenant, requests, options)
        .await?
        .runs
        .into_iter()
        .collect::<Result<Vec<Run>, CoreError>>()
}

/// Runs a list of workloads and reports the bound it ran under.
///
/// The cells are chunked rather than all fired at once: a slow cell must not
/// hold the whole batch behind it, and the cluster must never see more
/// simultaneous requests than it agreed to.
pub async fn run_batch_bounded(
    state: &AppState,
    tenant: TenantId,
    requests: Vec<RunRequest>,
    options: &BatchOptions,
) -> Result<BatchReport, CoreError> {
    options.validate()?;
    if requests.is_empty() {
        // Nothing ran, so there is no bound to report. Reporting the requested
        // one here would claim a concurrency an empty batch never used.
        return Ok(BatchReport {
            runs: Vec::new(),
            effective_parallel: 0,
        });
    }
    // One ledger read for the whole batch, before the first cell is submitted.
    let capacity = BatchCapacity::sample(state, tenant, &requests).await;
    // The queue's ceilings only mean something where there is a queue. A store
    // that executes in the request has no `max_active`, and pretending it does
    // would cap an in-process deployment by a number it never applies.
    let admission = state
        .repository()
        .supports_run_queue()
        .then(|| state.run_queue_limits());
    let limit = effective_parallelism(options, requests.len(), &capacity, admission.as_ref());

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
    let mut outcomes =
        futures::stream::iter(requests.into_iter().enumerate())
            .map(|(index, request)| async move {
                (index, submit_and_execute(state, tenant, request).await)
            })
            .buffer_unordered(limit)
            .collect::<Vec<_>>()
            .await;
    // Completion order must not relabel matrix axes or repetition numbers.
    outcomes.sort_unstable_by_key(|(index, _)| *index);
    // Every cell's outcome is kept, in submission order, including the ones
    // that failed. Collecting into a `Result` here would drop every run that
    // did execute the moment any sibling was refused, and the caller would
    // never learn that those machines existed.
    Ok(BatchReport {
        runs: outcomes.into_iter().map(|(_, outcome)| outcome).collect(),
        effective_parallel: limit,
    })
}

/// Ceiling on one request's repetitions, whatever the caller asks for.
///
/// The expansion in `run_repetitions` allocates one owned `RunRequest` per
/// repetition before any of them is admitted, and a `RunRequest` is over a
/// kilobyte, so an uncapped `u32` turns a forty-byte request body into a
/// five-terabyte allocation. That is an abort rather than a refusal a caller
/// could read, so the bound belongs at the expansion and not only on the route.
pub const MAX_EVAL_REPETITIONS: u32 = 1000;

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
    if repetitions > MAX_EVAL_REPETITIONS {
        return Err(CoreError::InvalidRequest(format!(
            "repetitions must be at most {MAX_EVAL_REPETITIONS}, asked for {repetitions}"
        )));
    }
    let mut requests = Vec::with_capacity(repetitions as usize);
    for number in 0..repetitions {
        let mut copy = request.clone();
        // Each repetition gets its own idempotency scope, otherwise the second
        // would be handed the first's run and nothing would execute at all. The
        // scope is the repetition's position and not a fresh random suffix,
        // because a retried submission must ask for the same repetitions: a
        // random suffix turns every retry into another full execution of an
        // experiment the caller asked to run once.
        copy.idempotency_key = request
            .idempotency_key
            .as_deref()
            .map(|key| repetition_key(key, number));
        requests.push(copy);
    }
    run_batch(state, tenant, requests, options).await
}

/// The idempotency scope of one repetition of a keyed request.
///
/// A function of the key and the repetition's position, so the same request
/// asked for again asks for the same runs: a scope that changed per attempt
/// would make every retry execute the experiment again, which is the opposite
/// of what an idempotency key is for. Distinct per repetition, so the second
/// repetition is not handed the first one's run.
fn repetition_key(key: &str, number: u32) -> String {
    format!("{key}-rep-{number:04}")
}

/// The matrix id this submission is under.
///
/// A caller that gave every cell its own idempotency key has said what the
/// experiment is: this tenant, these cells, in this order, under these keys. So
/// the id is derived from those facts rather than minted, and a retry after a
/// lost response lands on the matrix the first submission created - which is
/// the matrix whose runs the store holds, and whose id the caller can read
/// back. A fresh id for the same submission would be an id nothing is filed
/// under, and a 404 for a matrix that ran.
///
/// Anything less gets a fresh id: a cell whose key the server has to invent
/// says nothing about which submission this is, and two submissions that differ
/// only in the keys we made up are not the same experiment.
fn matrix_identity(tenant: TenantId, cells: &[MatrixCell]) -> Uuid {
    if cells
        .iter()
        .any(|cell| cell.request.idempotency_key.is_none())
    {
        return Uuid::now_v7();
    }
    let mut hasher = Sha256::new();
    // Length-delimited throughout, including the tenant: without lengths, a
    // tenant whose id ends in digits and a cell whose axis begins with the same
    // digits would hash the same as a different tenant and a different axis.
    digest_field(&mut hasher, tenant.as_bytes());
    digest_field(&mut hasher, &(cells.len() as u64).to_be_bytes());
    for (index, cell) in cells.iter().enumerate() {
        digest_field(&mut hasher, &(index as u64).to_be_bytes());
        digest_field(
            &mut hasher,
            cell.request
                .idempotency_key
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        for (name, value) in &cell.axis {
            digest_field(&mut hasher, name.as_bytes());
            digest_field(&mut hasher, value.as_bytes());
        }
    }
    version_8_uuid(hasher.finalize().as_slice())
}

/// One length-delimited field of a derived identity.
fn digest_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// A v8 UUID built from a digest.
///
/// Version and variant are stamped here rather than through the uuid crate's
/// generator so that the whole derivation is this one function: the bits a
/// reader would have to trust are the bits written in front of them.
fn version_8_uuid(digest: &[u8]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// Checks that a matrix is keyed throughout or not at all.
///
/// The two halves of the retry contract pull in opposite directions on a
/// partly-keyed matrix, and the losing side is the expensive one. A cell the
/// caller keyed keeps its key, so a retry resolves it to the run the FIRST
/// submission created - under a different matrix id, because a matrix with an
/// unkeyed cell is minted fresh. The unkeyed cells meanwhile get a fresh
/// matrix-scoped key and execute again. The contradiction is only visible after
/// `run_batch_bounded` has spent the whole batch, so it is refused here, where
/// the answer costs a request.
fn matrix_keying(cells: &[MatrixCell]) -> Result<(), String> {
    let keyed = cells
        .iter()
        .filter(|cell| cell.request.idempotency_key.is_some())
        .count();
    if keyed == 0 || keyed == cells.len() {
        return Ok(());
    }
    Err(format!(
        "a matrix is either idempotent or not: key every cell or no cell, \
         not {keyed} of {}",
        cells.len()
    ))
}

/// Expands and runs a matrix.
pub async fn run_matrix(
    state: &AppState,
    tenant: TenantId,
    spec: &MatrixSpec,
) -> Result<MatrixResult, CoreError> {
    spec.options.validate()?;
    matrix_keying(&spec.cells).map_err(CoreError::InvalidRequest)?;
    let requested_at = Utc::now();
    let matrix_id = matrix_identity(tenant, &spec.cells);

    // Every cell is admitted as the cell it is, before any of them runs: the
    // matrix and its position travel in the run's own insert, so a cell that
    // fails, an API that restarts, or a response nobody receives cannot lose
    // the labels that make the matrix readable afterwards.
    let mut requests = Vec::with_capacity(spec.cells.len());
    let mut cells = Vec::with_capacity(spec.cells.len());
    for (index, cell) in spec.cells.iter().enumerate() {
        let position = u32::try_from(index).map_err(|_| {
            CoreError::InvalidRequest("a matrix cannot have more cells than a position".into())
        })?;
        let identity = MatrixCellIdentity {
            index: position,
            axis: cell.axis.clone(),
        };
        let mut request = cell.request.clone();
        request.matrix_id = Some(matrix_id);
        request.matrix_cell = Some(identity.clone());
        // Key the cells that arrived unkeyed by their position, so two cells of
        // one matrix never collide with each other and a cell the caller keyed
        // keeps the scope the caller chose.
        if request.idempotency_key.is_none() {
            request.idempotency_key = Some(format!("matrix-{matrix_id}-{position:06}"));
        }
        requests.push(request);
        cells.push(identity);
    }

    let report = run_batch_bounded(state, tenant, requests, &spec.options).await?;

    // The answer is the stored one. A replay resolves to the runs its keys
    // already produced, and each of those runs is checked against the cell it
    // was asked to be - so a returned matrix id always addresses runs that
    // exist, and a run belonging to another matrix is refused rather than
    // relabelled into this one.
    //
    // A cell that was refused is reported as a cell with no run, beside the
    // cells that did run. Failing the whole request instead would answer
    // "error" and keep the matrix id to itself: the siblings have executed,
    // they have been billed, and `GET /eval/matrix/{id}` is the only route that
    // could have found them. The id is derived from the tenant and the cells,
    // so a caller that is never told it cannot compute it.
    let mut results = Vec::with_capacity(report.runs.len());
    for (outcome, submitted) in report.runs.iter().zip(&cells) {
        match outcome {
            Ok(run) => {
                let stored = stored_cell(run, submitted, matrix_id)?;
                results.push(CellResult {
                    axis: stored.axis,
                    run: Some(run.clone()),
                    error: None,
                });
            }
            Err(error) => results.push(CellResult {
                axis: submitted.axis.clone(),
                run: None,
                error: Some(error.to_string()),
            }),
        }
    }

    // The matrix is reported, never judged: what "better" means depends on the
    // metric the caller cares about, and picking one for them would be inventing
    // a conclusion the data does not support.
    Ok(MatrixResult {
        matrix_id,
        requested_at,
        max_parallel: spec.options.max_parallel,
        effective_parallel: report.effective_parallel,
        results,
    })
}

/// The cell a run was actually admitted as, or an error naming the mismatch.
///
/// A retry carrying this matrix's keys resolves to the runs those keys produced,
/// which is exactly what should happen: no second execution, and the stored
/// identity in the answer. What must never happen is the same key quietly
/// reporting as somebody else's run, so a run filed under a different matrix -
/// or under a different cell of this one - is an explicit error. A matrix
/// reported over a relabelled run is an evaluation of the wrong experiment.
fn stored_cell(
    run: &Run,
    submitted: &MatrixCellIdentity,
    matrix: Uuid,
) -> Result<MatrixCellIdentity, CoreError> {
    match (run.matrix_id, run.matrix_cell.as_ref()) {
        (Some(matrix_id), Some(cell)) if matrix_id == matrix && cell == submitted => {
            Ok(cell.clone())
        }
        (Some(matrix_id), Some(cell)) => Err(CoreError::InvalidRequest(format!(
            "matrix cell {} was already admitted as run {} in matrix {matrix_id} at cell {}",
            submitted.index, run.id, cell.index
        ))),
        _ => Err(CoreError::InvalidRequest(format!(
            "matrix cell {} resolved to run {}, which is not a cell of matrix {matrix}: \
             its idempotency key was reused outside this matrix",
            submitted.index, run.id
        ))),
    }
}

/// One cell of a recovered matrix: the run it became, and how it was labelled.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixCellView {
    pub run: Run,
    /// Position in the submitted matrix, when the run was admitted as a cell.
    pub index: Option<u32>,
    /// The cell's axis values, or `None` when the run carries none.
    ///
    /// Absent is a real answer: the run is here and its labels are not, which
    /// is a different thing from a cell that had no axis to begin with.
    pub axis: Option<BTreeMap<String, String>>,
}

/// One bounded page of a recovered matrix.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixPage {
    pub matrix_id: Uuid,
    /// This page's cells, in submission order.
    pub cells: Vec<MatrixCellView>,
    /// Cells on this page that succeeded.
    ///
    /// A page and not a verdict about the matrix: the rest of the cells are on
    /// the pages this one points at, and a count that quietly covered all of
    /// them would be reporting on rows nobody asked for.
    pub successes: usize,
    /// Per-axis breakdown of this page, in the same terms.
    pub by_axis: BTreeMap<String, (usize, usize)>,
    /// Where the next page starts, or `None` when this is the last one.
    pub next: Option<MatrixCursor>,
}

/// Reads a matrix back in one bounded page.
///
/// The point of this read is that a caller who lost the submission response can
/// get the cells back without the control plane turning one matrix id into a
/// request per cell. The page is bounded by the caller, the read is
/// tenant-scoped, and a matrix belonging to another tenant is reported as not
/// found rather than as an empty success.
pub async fn read_matrix(
    state: &AppState,
    tenant: TenantId,
    matrix: Uuid,
    limit: u32,
    after: Option<MatrixCursor>,
) -> Result<MatrixPage, CoreError> {
    let page = state
        .repository()
        .list_matrix_cells(tenant, matrix, limit, after)
        .await?;
    let first_page = page.cells.is_empty() && after.is_none();
    if first_page {
        // Either it never existed or it belongs to somebody else, and those two
        // must be indistinguishable from outside.
        return Err(CoreError::NotFound("matrix not found".into()));
    }
    let cells: Vec<MatrixCellView> = page
        .cells
        .iter()
        .map(|cell| MatrixCellView {
            run: cell.run.clone(),
            index: cell.index,
            axis: cell.axis.clone(),
        })
        .collect();
    let successes = cells
        .iter()
        .filter(|cell| cell.run.state == RunState::Succeeded)
        .count();
    let mut by_axis: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for cell in &cells {
        for (key, value) in cell.axis.iter().flat_map(|axis| axis.iter()) {
            let entry = by_axis.entry(format!("{key}={value}")).or_insert((0, 0));
            entry.0 += usize::from(cell.run.state == RunState::Succeeded);
            entry.1 += 1;
        }
    }
    Ok(MatrixPage {
        matrix_id: matrix,
        cells,
        successes,
        by_axis,
        next: page.next,
    })
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
mod tests {
    use super::*;
    use aiec_core::new_id;
    use aiec_core::storage::WorkerRegistration;

    fn capabilities() -> RuntimeCapabilities {
        RuntimeCapabilities {
            exec: true,
            files: true,
            ..Default::default()
        }
    }

    /// One worker with a stated amount of room, on a stated runtime.
    fn worker(runtime: RuntimeKind, vcpus: u32, gigabytes: u64) -> WorkerStatus {
        WorkerStatus {
            registration: WorkerRegistration {
                node_id: new_id(),
                name: "worker".to_owned(),
                runtime,
                capabilities: capabilities(),
                control_endpoint: "http://worker".to_owned(),
                total_vcpus: vcpus,
                total_memory_bytes: gigabytes * 1024 * 1024 * 1024,
                total_disk_bytes: 64 * 1024 * 1024 * 1024,
                available_vcpus: vcpus,
                available_memory_bytes: gigabytes * 1024 * 1024 * 1024,
                available_disk_bytes: 64 * 1024 * 1024 * 1024,
                healthy: true,
                version: 1,
                metadata: serde_json::json!({}),
                started_at: Utc::now(),
                last_heartbeat: Utc::now(),
            },
            sandbox_count: 0,
            observed_sandbox_count: 0,
            last_error: None,
            accepting_sandboxes: true,
            drain_reason: None,
        }
    }

    fn group(runtime: RuntimeKind) -> PlacementGroup {
        PlacementGroup {
            runtime,
            required: capabilities(),
            minimum: None,
            demand: cell_demand(&ResourceRequirements::default(), 0),
        }
    }

    #[test]
    fn a_runtime_disk_floor_prevents_promising_a_slot_that_cannot_fit() {
        let mut limited = worker(RuntimeKind::Firecracker, 8, 8);
        limited.registration.available_disk_bytes = 3 * 1024 * 1024 * 1024;
        let requested = ResourceRequirements::default();
        assert_eq!(slots_on(&limited, cell_demand(&requested, 4096)), 0);
        assert_eq!(slots_on(&limited, cell_demand(&requested, 1024)), 3);
    }

    /// A batch whose cells run somewhere else cannot be sized by workers that
    /// are free: a Firecracker-only batch on a cluster of idle Docker workers has
    /// nowhere to place a single cell, and reporting room for it is a bound the
    /// scheduler cannot honour.
    #[test]
    fn a_runtime_mismatch_invents_no_slots() {
        let now = Utc::now();
        let workers = vec![worker(RuntimeKind::Docker, 16, 64)];
        assert_eq!(
            worker_slots(&workers, &[group(RuntimeKind::Firecracker)], now),
            Some(0),
            "an idle worker of the wrong runtime is not a slot"
        );
        assert_eq!(
            worker_slots(&workers, &[group(RuntimeKind::Docker)], now),
            Some(16),
            "a matching worker is still counted for a matching batch"
        );
    }

    /// A worker that has been drained or has stopped heartbeating is present
    /// and unusable, so its room is not a slot either.
    #[test]
    fn drained_and_stale_workers_are_not_slots() {
        let now = Utc::now();
        let mut drained = worker(RuntimeKind::Docker, 16, 64);
        drained.accepting_sandboxes = false;
        drained.drain_reason = Some("maintenance".to_owned());
        let mut stale = worker(RuntimeKind::Docker, 16, 64);
        stale.registration.last_heartbeat = now - Duration::seconds(NODE_HEARTBEAT_TTL_SECONDS + 1);
        let healthy = worker(RuntimeKind::Docker, 16, 64);
        assert_eq!(
            worker_slots(&[drained, stale], &[group(RuntimeKind::Docker)], now),
            Some(0)
        );
        assert_eq!(
            worker_slots(&[healthy], &[group(RuntimeKind::Docker)], now),
            Some(16)
        );
    }

    /// Hosted cells are reached through a provider inside the runtime and are
    /// never leased from a worker, so a busy local cluster says nothing about
    /// them. Bounding a hosted batch by the local ledger would serialise a batch
    /// the queue never sees those workers for.
    #[test]
    fn a_hosted_batch_is_not_capped_by_busy_local_workers() {
        let now = Utc::now();
        let busy = worker(RuntimeKind::Docker, 0, 0);
        assert_eq!(
            worker_slots(
                std::slice::from_ref(&busy),
                &[group(RuntimeKind::Docker)],
                now
            ),
            Some(0),
            "a full local worker is a real constraint on a local batch"
        );
        assert_eq!(
            worker_slots(&[busy], &[group(RuntimeKind::Hosted)], now),
            None,
            "the local ledger cannot answer for hosted capacity"
        );
        assert_eq!(
            worker_slots(&[], &[group(RuntimeKind::Hosted)], now),
            None,
            "a deployment with no workers still runs hosted cells"
        );
    }

    /// Tenant quota is one more ceiling, not the scheduler's decision: a batch
    /// over what the tenant has left is narrowed to what it has left, and a
    /// ledger that cannot answer leaves the batch unbounded by it.
    #[test]
    fn quota_narrows_the_batch_to_what_the_tenant_has_left() {
        let limits = QuotaLimits {
            max_active_sandboxes: 4,
            max_vcpus: 4,
            max_memory_mb: 2048,
            max_disk_mb: 4096,
        };
        let demand = CellDemand {
            cpu: 1,
            memory_bytes: 1024 * 1024 * 1024,
            disk_bytes: 1024 * 1024 * 1024,
        };
        let idle = QuotaUsage::default();
        assert_eq!(
            quota_slots(limits, idle, demand),
            2,
            "memory is the limit here"
        );
        // One gigabyte used leaves one cell of that shape, not two.
        let used = QuotaUsage {
            active_sandboxes: 1,
            vcpus: 1,
            memory_mb: 1024,
            disk_mb: 1024,
        };
        assert_eq!(quota_slots(limits, used, demand), 1);
        let full = QuotaUsage {
            active_sandboxes: 4,
            vcpus: 4,
            memory_mb: 4096,
            disk_mb: 4096,
        };
        assert_eq!(
            quota_slots(limits, full, demand),
            0,
            "an exhausted quota has no room"
        );
    }

    /// The tightest group bounds a mixed batch: any cell in flight could be one
    /// of the awkward ones.
    #[test]
    fn a_mixed_batch_is_sized_against_its_tightest_group() {
        let now = Utc::now();
        let workers = vec![
            worker(RuntimeKind::Docker, 8, 64),
            worker(RuntimeKind::Firecracker, 2, 64),
        ];
        assert_eq!(
            worker_slots(
                &workers,
                &[group(RuntimeKind::Docker), group(RuntimeKind::Firecracker)],
                now
            ),
            Some(2),
            "room in the roomy runtime cannot place a cell that needs the other one"
        );
    }

    fn cell(task: &str, key: Option<&str>) -> MatrixCell {
        let mut axis = BTreeMap::new();
        axis.insert("task".to_owned(), task.to_owned());
        MatrixCell {
            axis,
            request: RunRequest {
                idempotency_key: key.map(str::to_owned),
                ..Default::default()
            },
        }
    }

    /// A fully keyed matrix keeps one identity across submissions, so a retry
    /// after a lost response lands on the matrix whose runs the store holds -
    /// and the id it returns is one a reader can ask for.
    #[test]
    fn a_fully_keyed_matrix_is_the_same_matrix_every_time_it_is_submitted() {
        let tenant = new_id();
        let first = matrix_identity(tenant, &[cell("a", Some("k-a")), cell("b", Some("k-b"))]);
        let retry = matrix_identity(tenant, &[cell("a", Some("k-a")), cell("b", Some("k-b"))]);
        assert_eq!(
            first, retry,
            "the same keyed submission must resolve to the same matrix"
        );
        assert_eq!(
            first.get_version_num(),
            8,
            "a derived id says it is derived"
        );

        let relabelled = matrix_identity(tenant, &[cell("a", Some("k-a")), cell("b", Some("k-c"))]);
        assert_ne!(
            first, relabelled,
            "a different key is a different experiment"
        );
        let reordered = matrix_identity(tenant, &[cell("b", Some("k-b")), cell("a", Some("k-a"))]);
        assert_ne!(
            first, reordered,
            "the same keys in another order is another experiment"
        );
        let other_axis = matrix_identity(tenant, &[cell("a", Some("k-a")), cell("c", Some("k-b"))]);
        assert_ne!(
            first, other_axis,
            "the same keys under other axes is another experiment"
        );
        let other_tenant =
            matrix_identity(new_id(), &[cell("a", Some("k-a")), cell("b", Some("k-b"))]);
        assert_ne!(first, other_tenant, "identity is tenant-scoped");
    }

    /// A matrix with a cell the server had to key itself is a fresh submission
    /// every time: nothing about it says it is one anybody submitted before.
    #[test]
    fn a_partly_unkeyed_matrix_gets_a_fresh_identity() {
        let tenant = new_id();
        let first = matrix_identity(tenant, &[cell("a", Some("k-a")), cell("b", None)]);
        let second = matrix_identity(tenant, &[cell("a", Some("k-a")), cell("b", None)]);
        assert_ne!(first, second);
        assert_eq!(first.get_version_num(), 7, "a minted id says it was minted");
    }

    /// A matrix is either keyed by its caller throughout or not at all. Mixing
    /// the two cannot satisfy both halves of the contract at once: the keyed
    /// cells keep their keys across a retry and so resolve to the FIRST
    /// matrix's runs, while the unkeyed cells are re-keyed against a freshly
    /// minted id and run again. The mismatch is only detectable after the
    /// batch has been spent, so it is refused before any cell is admitted.
    #[test]
    fn a_partly_keyed_matrix_is_refused_before_anything_is_admitted() {
        let keyed = vec![cell("a", Some("k-a")), cell("b", Some("k-b"))];
        let unkeyed = vec![cell("a", None), cell("b", None)];
        let mixed = vec![cell("a", Some("k-a")), cell("b", None)];
        assert!(matrix_keying(&keyed).is_ok());
        assert!(matrix_keying(&unkeyed).is_ok());
        let error = matrix_keying(&mixed).unwrap_err();
        assert!(
            error.contains("every cell") && error.contains("no cell"),
            "the refusal has to say what to do: {error}"
        );
        // A single cell is not a mix in either direction, and neither is none.
        assert!(matrix_keying(&[cell("a", Some("k-a"))]).is_ok());
        assert!(matrix_keying(&[]).is_ok());
    }

    /// Repetitions of a keyed request ask for the same runs on every retry, and
    /// still do not collapse into one another.
    #[test]
    fn repetition_scopes_are_stable_and_distinct() {
        assert_eq!(repetition_key("suite", 0), repetition_key("suite", 0));
        assert_ne!(repetition_key("suite", 0), repetition_key("suite", 1));
        assert_ne!(
            repetition_key("suite", 0),
            "suite".to_owned(),
            "a repetition is not the request it repeats"
        );
    }

    /// The answer is the stored identity, and a run filed somewhere else is an
    /// error rather than a relabelled result.
    #[test]
    fn a_replayed_run_is_the_stored_cell_and_a_mismatch_is_refused() {
        let matrix = new_id();
        let submitted = MatrixCellIdentity {
            index: 3,
            axis: BTreeMap::from([("task".to_owned(), "c".to_owned())]),
        };
        let mut run = Run {
            id: new_id(),
            tenant_id: new_id(),
            state: RunState::Succeeded,
            requested_at: Utc::now(),
            queued_at: None,
            started_at: None,
            completed_at: None,
            workload: Default::default(),
            resources: Default::default(),
            requirements: Default::default(),
            placement: Default::default(),
            results: Default::default(),
            failure_reason: None,
            retention: Default::default(),
            retained_sandbox_id: None,
            retained_until: None,
            idempotency_key: None,
            parent_run_id: None,
            matrix_id: Some(matrix),
            matrix_cell: Some(submitted.clone()),
        };
        assert_eq!(
            stored_cell(&run, &submitted, matrix).ok(),
            Some(submitted.clone())
        );

        let mut elsewhere = run.clone();
        elsewhere.matrix_id = Some(new_id());
        let error = stored_cell(&elsewhere, &submitted, matrix)
            .expect_err("a run from another matrix must not be reported as this cell");
        assert!(
            error.to_string().contains("already admitted"),
            "the error must name the mismatch: {error}"
        );

        let mut relabelled = run.clone();
        relabelled.matrix_cell = Some(MatrixCellIdentity {
            index: 4,
            axis: BTreeMap::new(),
        });
        assert!(
            stored_cell(&relabelled, &submitted, matrix).is_err(),
            "a run admitted as a different cell must not be relabelled"
        );

        run.matrix_cell = None;
        assert!(
            stored_cell(&run, &submitted, matrix).is_err(),
            "a run with no cell of its own is not evidence of this one"
        );
    }
}
