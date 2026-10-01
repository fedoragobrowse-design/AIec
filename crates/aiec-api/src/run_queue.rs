//! Bounded, service-owned execution. Dropping an HTTP waiter never drops a job.
use std::{future::Future, time::Duration};

use aiec_core::{
    CoreError, new_id,
    run::{Run, RunState},
    run_queue::{RunQueueClaim, RunQueueLimits},
};
use chrono::{DateTime, Utc};
use tokio::{
    sync::watch,
    task::{JoinHandle, JoinSet},
};

use crate::{
    AppState,
    runs::{RunRequest, execute_created, reclaim_run},
};

/// Service lifetime guard. Shutdown stops admission to executors, cancels work,
/// then waits for all owned teardown futures; it does not abort cleanup tasks.
pub struct RunQueueDispatcher {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl RunQueueDispatcher {
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for RunQueueDispatcher {
    fn drop(&mut self) {
        // The supervisor retains and drains its JoinSet even if a service error
        // drops the guard. Normal service shutdown awaits it explicitly.
        let _ = self.stop.send(true);
    }
}

pub(crate) fn spawn(
    state: AppState,
    limits: RunQueueLimits,
) -> Result<RunQueueDispatcher, CoreError> {
    let limits = limits.validate()?;
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(dispatch(state, limits, receiver));
    Ok(RunQueueDispatcher {
        stop,
        task: Some(task),
    })
}

pub(crate) async fn enqueue_and_wait(
    state: &AppState,
    run: Run,
    request: RunRequest,
    limits: RunQueueLimits,
) -> Result<Run, CoreError> {
    let store = state.repository();
    let document =
        serde_json::to_value(&request).map_err(|error| CoreError::Backend(error.to_string()))?;
    let (tenant, id) = (run.tenant_id, run.id);
    // The queue owns the insert, so this is the first moment the Run exists for
    // any reader. A retry carrying a key already used joins the original run,
    // so only a genuinely new one is announced.
    let created = store.enqueue_run(run, document, limits).await?;
    if created.id == id {
        crate::runs::announce_created(state, &created, &request).await;
    }
    // A retry that carried a key already in use joined the run that key
    // produced, so the run to wait for is the one the store returned - not the
    // id this request proposed, which was never written.
    let id = created.id;
    if created.state.is_terminal() {
        return Ok(created);
    }
    // This waiter owns no execution handle and is safe to disconnect or retry.
    // A large evaluation multiplies waiters, so the poll backs off instead of
    // spinning: two queries a second per pending run is a load the queue would
    // otherwise be paying to keep its own capacity.
    let mut delay = WAIT_MIN_INTERVAL;
    let mut observed: Option<(RunState, Option<DateTime<Utc>>)> = None;
    // When the run first settled, as opposed to when it was last seen changing.
    // The difference is the whole point: a run whose teardown keeps failing is
    // terminal and stays terminal, and waiting for it to become un-waitable
    // is waiting forever.
    let mut terminal_since: Option<std::time::Instant> = None;
    loop {
        let current = store.get_run(tenant, id).await?;
        // Only a terminal run has a queue status worth asking about, so the
        // second query is spent where it changes the answer.
        if current.state.is_terminal() {
            let since = *terminal_since.get_or_insert_with(std::time::Instant::now);
            let settled = store.run_queue_finished(tenant, id).await?;
            if waiter_should_return(settled, since.elapsed()) {
                // Either the teardown settled, so the response carries the
                // persisted cleanup evidence, or it is not going to. The run's
                // answer is known either way, and returning it is the only
                // honest option left: the caller learns the outcome and that
                // cleanup is still outstanding, which is what
                // `results.cleanup_failed` is recorded for. Holding the
                // connection open instead leaves the caller with nothing - no
                // run, no id, no error - and, in an evaluation, blocks every
                // cell queued behind this one.
                return store.get_run(tenant, id).await;
            }
        } else {
            terminal_since = None;
        }
        let now = (current.state, current.completed_at);
        if observed.is_some_and(|previous| previous != now) {
            // Progress is when the answer is about to change, so a moving run is
            // still observed at the fast rate.
            delay = WAIT_MIN_INTERVAL;
        }
        observed = Some(now);
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(WAIT_MAX_INTERVAL);
    }
}

/// Fastest waiter poll, and the rate a settling run is still observed at.
const WAIT_MIN_INTERVAL: Duration = Duration::from_millis(100);

/// Slowest waiter poll, reached after a few seconds of no visible progress.
const WAIT_MAX_INTERVAL: Duration = Duration::from_secs(2);

/// How long a waiter keeps asking whether a terminal run's teardown has
/// settled.
///
/// Long enough that an ordinary teardown, which waits on a worker's destroy and
/// then writes its report, is normally inside it. Bounded because the condition
/// being waited for includes one the run itself can prevent: `finish_run_queue`
/// refuses a run whose `cleanup_failed` is set, and a teardown that keeps
/// failing repopulates it on every reclaim.
const WAIT_SETTLED_GRACE: Duration = Duration::from_secs(30);

/// Whether a waiter for a run that has been terminal for `settled_for` should
/// answer now.
///
/// Two ways out, and the second one is what this function exists for. The queue
/// row normally becomes `finished` once the teardown has written its report,
/// and the waiter waits for that so the response carries the evidence. But
/// `finish_run_queue` refuses any run whose `cleanup_failed` is set, and a
/// teardown that keeps failing repopulates that field on every reclaim - so a
/// run whose machine cannot be destroyed never becomes `finished`, and a waiter
/// with no second exit polls at 0.5 Hz for the life of the process.
fn waiter_should_return(queue_finished: bool, settled_for: Duration) -> bool {
    queue_finished || settled_for >= WAIT_SETTLED_GRACE
}

async fn dispatch(state: AppState, limits: RunQueueLimits, mut stop: watch::Receiver<bool>) {
    let mut tasks = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            changed = stop.changed() => { if changed.is_err() || *stop.borrow() { break; } }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    tracing::error!("Run queue executor task panicked; durable lease recovery will reclaim it");
                }
            }
            _ = tick.tick(), if tasks.len() < limits.max_active as usize => {
                let store = state.repository();
                let owner = new_id();
                // Recovery comes before fresh work; unreclaimed compute still holds a slot.
                let claim = match store.recover_run_queue(owner, limits).await {
                    Ok(Some(claim)) => Some(claim),
                    Ok(None) => match store.claim_run_queue(owner, limits).await {
                        Ok(claim) => claim,
                        Err(_) => { tracing::warn!("Run queue claim unavailable"); None }
                    },
                    Err(_) => { tracing::warn!("Run queue recovery unavailable"); None }
                };
                if let Some(claim) = claim {
                    tasks.spawn(run_claim(state.clone(), claim, limits, stop.clone()));
                }
            }
        }
    }
    // In-flight cleanup is awaited, but shutdown cannot hang on an unresponsive
    // runtime: an unreclaimed teardown keeps an expiring lease and the next
    // dispatcher recovers it, so a bounded abort loses evidence, never work.
    let drained = tokio::time::timeout(
        Duration::from_secs(u64::from(limits.lease_seconds) * 2),
        async {
            while let Some(result) = tasks.join_next().await {
                if result.is_err() {
                    tracing::error!(
                        "Run queue shutdown task panicked; durable lease recovery will reclaim it"
                    );
                }
            }
        },
    )
    .await;
    if drained.is_err() {
        tracing::warn!(
            "Run queue drain exceeded its window; unfinished teardowns stay owned by recovery"
        );
        tasks.shutdown().await;
    }
}

/// Own and renew a grant while polling slow I/O outside database transactions.
/// Any failed renewal drops the I/O future; an expired grant cannot be revived.
async fn with_lease<T>(
    state: &AppState,
    claim: &RunQueueClaim,
    limits: RunQueueLimits,
    mut stop: Option<watch::Receiver<bool>>,
    work: impl Future<Output = T>,
) -> Option<T> {
    let store = state.repository();
    let period = Duration::from_secs(u64::from(limits.lease_seconds / 3));
    let mut heartbeat = tokio::time::interval(period);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let budget = claim
        .execution_deadline
        .filter(|_| stop.is_some())
        .map(|deadline| {
            (deadline - chrono::Utc::now())
                .to_std()
                .unwrap_or(Duration::ZERO)
        });
    let deadline = async {
        match budget {
            Some(budget) => {
                tokio::time::sleep(budget).await;
            }
            // A reclaiming grant owns cleanup only, so it is bounded by the
            // lease rather than by an execution deadline that already expired.
            None => {
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::pin!(deadline);
    tokio::pin!(work);
    loop {
        if stop.as_ref().is_some_and(|stop| *stop.borrow()) {
            return None;
        }
        tokio::select! {
            biased;
            _ = &mut deadline => { return None; }
            _ = async {
                match stop.as_mut() {
                    Some(stop) => { let _ = stop.changed().await; }
                    None => std::future::pending::<()>().await,
                }
            } => { return None; }
            _ = heartbeat.tick() => {
                let renewed = tokio::time::timeout(period,
                    store.heartbeat_run_queue(claim.run.tenant_id, claim.run.id,
                        claim.owner, limits.lease_seconds)).await;
                if !matches!(renewed, Ok(Ok(true))) { return None; }
            }
            result = &mut work => { return Some(result); }
        }
    }
}

async fn run_claim(
    state: AppState,
    claim: RunQueueClaim,
    limits: RunQueueLimits,
    stop: watch::Receiver<bool>,
) {
    if claim.reclaiming {
        reclaim_owned(&state, &claim, limits).await;
        return;
    }
    let request = match serde_json::from_value::<RunRequest>(claim.request.clone()) {
        Ok(request) => request,
        Err(_) => {
            fail_and_reclaim(&state, &claim, limits, "Persisted Run request is invalid").await;
            return;
        }
    };
    let result = with_lease(
        &state,
        &claim,
        limits,
        Some(stop.clone()),
        execute_created(&state, claim.run.tenant_id, claim.run.clone(), request),
    )
    .await;
    match result {
        Some(Ok(run)) if run.state.is_terminal() && run.results.cleanup_failed.is_none() => {
            // Expired ownership is rejected, so recovery remains responsible if
            // this final write races the deadline or another owner's grant.
            let _ = state
                .repository()
                .finish_run_queue(run.tenant_id, run.id, claim.owner)
                .await;
        }
        Some(_) => {
            fail_and_reclaim(
                &state,
                &claim,
                limits,
                "Run executor did not settle cleanly",
            )
            .await
        }
        None if *stop.borrow() => {
            // Shutdown never starts new teardown work: the expiring lease is the
            // handoff, and recovery reclaims this run rather than losing it.
            tracing::info!(run_id = %claim.run.id, "Run executor handed back to durable recovery at shutdown");
        }
        None => fail_and_reclaim(&state, &claim, limits, "Run executor lost ownership").await,
    }
}

async fn fail_and_reclaim(
    state: &AppState,
    claim: &RunQueueClaim,
    limits: RunQueueLimits,
    reason: &str,
) {
    match state
        .repository()
        .fail_run_queue(
            claim.run.tenant_id,
            claim.run.id,
            claim.owner,
            reason.into(),
        )
        .await
    {
        Ok(true) => reclaim_owned(state, claim, limits).await,
        // No cleanup under a lost lease: recovery acquires a new teardown grant.
        _ => {
            tracing::warn!(run_id = %claim.run.id, "Run queue failure relinquished to durable recovery")
        }
    }
}

async fn reclaim_owned(state: &AppState, claim: &RunQueueClaim, limits: RunQueueLimits) {
    // Cleanup ignores service cancellation but is still fenced by renewable
    // ownership. A cleanup that keeps failing is never finished away: the row
    // stays `reclaiming` with an expiring lease, its `cleanup_failed` evidence
    // stays on the run, and the next recovery pass re-acquires a teardown grant
    // and tries again. It also holds an active slot, so a cluster cannot keep
    // admitting new work while holding compute it has not released.
    let result = with_lease(state, claim, limits, None, async {
        let current = state
            .repository()
            .get_run(claim.run.tenant_id, claim.run.id)
            .await?;
        reclaim_run(state, &current).await
    })
    .await;
    match result {
        Some(Ok(run)) if run.results.cleanup_failed.is_none() => {
            // Only a settled run with no cleanup failure is finished. Anything
            // else keeps its reclaiming row and its evidence for recovery.
            let _ = state
                .repository()
                .finish_run_queue(run.tenant_id, run.id, claim.owner)
                .await;
        }
        Some(Ok(run)) => {
            tracing::warn!(run_id = %claim.run.id, retained = ?run.retained_sandbox_id,
            "Run queue cleanup failed and stays owned by recovery")
        }
        Some(Err(error)) => tracing::warn!(run_id = %claim.run.id, error = %error,
            "Run queue cleanup errored and stays owned by recovery"),
        None => tracing::warn!(run_id = %claim.run.id,
            "Run queue cleanup lost ownership and stays owned by recovery"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A waiter must not give up on a teardown that is merely slow, and must
    /// not keep waiting on one that is never going to finish.
    #[test]
    fn a_waiter_leaves_on_settlement_or_on_a_teardown_that_never_settles() {
        // Settled: answer at once, however long the run took.
        assert!(waiter_should_return(true, Duration::ZERO));
        assert!(waiter_should_return(true, WAIT_SETTLED_GRACE * 10));
        // Not settled and still young: keep waiting, because that is the
        // ordinary case where cleanup is doing its work.
        assert!(!waiter_should_return(false, Duration::ZERO));
        assert!(!waiter_should_return(
            false,
            WAIT_SETTLED_GRACE - Duration::from_millis(1)
        ));
        // Not settled and old: answer anyway. The run is terminal, so its
        // outcome is known and its teardown failure is already recorded on it.
        assert!(waiter_should_return(false, WAIT_SETTLED_GRACE));
        assert!(waiter_should_return(
            false,
            WAIT_SETTLED_GRACE + Duration::from_secs(3600)
        ));
        // The grace has to be long enough to cover an ordinary destroy, or
        // every run would be answered before its cleanup report was written.
        assert!(
            WAIT_SETTLED_GRACE >= Duration::from_secs(10),
            "a {WAIT_SETTLED_GRACE:?} grace would cut short an ordinary teardown"
        );
    }
}
