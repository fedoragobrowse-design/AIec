//! One lifecycle operation at a time per sandbox.
//!
//! A sandbox's durable state and the machine behind it are two things that have
//! to agree, and the sequence a handler runs is: act on the runtime, then
//! compare-and-swap the row. Two handlers acting on the same sandbox at once
//! interleave those steps, and the interleavings produce states neither
//! handler asked for.
//!
//! Pause is the sharpest case. It pauses the guest, then swaps Running to
//! Paused. A snapshot that started first swaps Running to Snapshotting, and
//! when the capture finishes it swaps Snapshotting back to Running. The pause
//! then finds a row that is no longer Running, its swap fails, and it returns a
//! conflict - having already paused the guest. The row says Running, the guest
//! is stopped, and `resume` refuses because it requires a durable Paused. The
//! tenant's sandbox is wedged until they destroy it.
//!
//! Serializing the lifecycle handlers per sandbox removes the interleaving:
//! one operation runs from its runtime call through its durable commit before
//! the next one starts. The lock is keyed by sandbox, so unrelated sandboxes
//! never wait on each other, and it is bounded, so a flood of distinct
//! sandboxes cannot grow it without limit.
//!
//! This is deliberately a per-process lock. It closes the race between two
//! requests served by one control plane, which is where the wedge above was
//! observed. Two control planes against one database can still interleave;
//! closing that needs a lease held in PostgreSQL, which is a larger change than
//! this defect warrants and is recorded as a residual limit rather than
//! silently assumed.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Ceiling on sandboxes holding a lifecycle lock at once. A request for a
/// sandbox beyond it is refused rather than queued, so the table cannot be
/// grown by naming sandboxes nobody owns. It is well above the number of
/// machines a deployment runs.
pub const MAX_TRACKED_SANDBOXES: usize = 4096;

/// The error a lifecycle lock reports when it cannot admit a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleBusy;

impl std::fmt::Display for LifecycleBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("too many sandboxes are holding a lifecycle operation")
    }
}

impl std::error::Error for LifecycleBusy {}

/// A per-sandbox mutual exclusion table.
///
/// Entries are reference counted. The map holds a weak reference so the entry
/// disappears as soon as the last holder releases it, which means the table
/// tracks the sandboxes currently mid-operation rather than every sandbox this
/// process has ever seen.
#[derive(Clone, Default)]
pub struct LifecycleLocks {
    inner: Arc<Mutex<HashMap<uuid::Uuid, std::sync::Weak<Mutex<()>>>>>,
}

impl LifecycleLocks {
    /// A table with no tracked sandboxes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the lock for one sandbox, waiting for any other lifecycle
    /// operation on it to finish.
    ///
    /// The guard releases on drop, including when a handler returns early with
    /// an error, so a refused operation cannot wedge the sandbox for good.
    pub async fn acquire(
        &self,
        sandbox_id: uuid::Uuid,
    ) -> Result<OwnedMutexGuard<()>, LifecycleBusy> {
        let mut entries = self.inner.lock().await;
        // Entries whose lock nobody holds are stale, and counting them would
        // make the ceiling permanent rather than a limit on sandboxes actually
        // mid-operation: a burst would fill the table once and every later
        // acquire would be refused even though nothing was running.
        entries.retain(|_, entry| entry.strong_count() > 0);
        // Reuse the live lock if this sandbox already has one, otherwise
        // install a fresh one. The upgrade path must happen under the map lock
        // so two callers cannot both install one.
        let entry = match entries.get(&sandbox_id).and_then(std::sync::Weak::upgrade) {
            Some(existing) => existing,
            None => {
                if entries.len() >= MAX_TRACKED_SANDBOXES {
                    return Err(LifecycleBusy);
                }
                let fresh = Arc::new(Mutex::new(()));
                entries.insert(sandbox_id, Arc::downgrade(&fresh));
                fresh
            }
        };
        // Drop the map lock before waiting: holding it would make acquisition
        // of an unrelated sandbox block behind the one being waited on.
        drop(entries);
        let guard = entry.lock_owned().await;
        // The table may have grown past the ceiling while this caller waited,
        // or an entry may have been superseded. Prune here so the ceiling is
        // enforced on the way out as well as on the way in.
        Self::prune(&self.inner).await;
        Ok(guard)
    }

    /// Drops entries whose lock nobody holds any more.
    async fn prune(entries: &Mutex<HashMap<uuid::Uuid, std::sync::Weak<Mutex<()>>>>) {
        let mut entries = entries.lock().await;
        entries.retain(|_, entry| entry.strong_count() > 0);
    }

    /// How many sandboxes currently hold or wait for a lock. Test-facing.
    #[cfg(test)]
    async fn tracked(&self) -> usize {
        Self::prune(&self.inner).await;
        self.inner.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn operations_on_one_sandbox_are_serialized() {
        let locks = LifecycleLocks::new();
        let sandbox = uuid::Uuid::now_v7();
        let held = locks.acquire(sandbox).await.unwrap();

        // A second acquisition of the same sandbox waits for the first.
        let waiting = {
            let locks = locks.clone();
            tokio::spawn(async move { locks.acquire(sandbox).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(locks.tracked().await, 1, "one sandbox, one entry");
        drop(held);
        // The waiter proceeds only once the holder released.
        let acquired = waiting.await.unwrap().unwrap();
        drop(acquired);
        assert_eq!(locks.tracked().await, 0, "an idle sandbox is not tracked");
    }

    #[tokio::test]
    async fn unrelated_sandboxes_do_not_wait_on_each_other() {
        let locks = LifecycleLocks::new();

        let held = locks.acquire(uuid::Uuid::now_v7()).await.unwrap();
        // A different sandbox acquires immediately while one is held.
        let other = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            locks.acquire(uuid::Uuid::now_v7()),
        )
        .await
        .expect("an unrelated sandbox waited on a held lock")
        .unwrap();
        drop(other);
        drop(held);
    }

    #[tokio::test]
    async fn the_table_refuses_rather_than_growing_without_bound() {
        let locks = LifecycleLocks::new();
        let mut held = Vec::new();
        for _ in 0..MAX_TRACKED_SANDBOXES {
            held.push(locks.acquire(uuid::Uuid::now_v7()).await.unwrap());
        }
        assert!(
            locks.acquire(uuid::Uuid::now_v7()).await.is_err(),
            "the ceiling was exceeded instead of refused"
        );
        // Releasing makes room again rather than leaving the table wedged.
        drop(held.pop());
        locks.acquire(uuid::Uuid::now_v7()).await.unwrap();
    }
}
