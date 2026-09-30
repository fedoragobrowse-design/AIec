# Known defects

Found by a read-only audit of the run subsystem, then confirmed against a live
cluster where possible. Fixed items are listed with the commit that fixed them
so this file does not become a place where stale problems go to hide.

Each entry says what is wrong, how it shows up, and what is not yet done.

## Fixed

| Defect | Cause | Fix |
|---|---|---|
| Every run leaked its machine | `cleanup` called `repository().delete_sandbox`, which flips the row and credits capacity but never calls `runtime.destroy` or `scheduler.release` | `983debf` |
| Capacity was only reclaimed by a human | `POST /v1/reconcile` existed and nothing called it on a timer, so each leak was a permanent reduction | `983debf` |
| A kept machine leaked and was never reported | retention was set in memory; `record_run_results` never wrote `retained_sandbox_id`/`retained_until`, which is what the sweeper selects on | `b3c2953` |
| A finished run could outlive its machine on a database deadlock | destroy gave up because the retry matched prose, not SQLSTATE | `a5737da`, `d0a52d6` |
| Guaranteed deadlock destroying a sandbox | `delete_sandbox` locked sandbox-then-lease while every other path locked lease-then-sandbox | `8a9cc7a` |
| A failed run's machine was destroyed anyway | `cleanup` ran before the outcome was decided, so retention saw a failure as success | `8614e40` |

## Open

### Sandboxes in a non-terminal state are never reclaimed

A sandbox left in `running`, `starting` or `creating` whose lease is gone is
never selected by anything. The sweeper expires leases; it does not notice a
sandbox whose owner has vanished.

Observed consequence: eight such sandboxes held a tenant's entire
`max_active_sandboxes` quota with nothing running on them, and every subsequent
run failed with `tenant resource quota exceeded` while nodes still reported free
capacity. Enough of these and a tenant cannot submit work at all.

The reconciler's recovery path exists for this and is not wired to anything that
would run it: `reassign_expired_lease` returns `Ok(None)` when it cannot place a
sandbox, the caller drops that action, and the lease is no longer `active` so it
is never selected again.

### Eight exit paths after placement skip cleanup

`execute` reaches `cleanup` on two paths. Every other exit after a sandbox is
acquired propagates with `?` and destroys nothing - `runtime_for`, each
`advance`, and the setup, task and validation `run_command` calls. Those errors
are retryable, so each attempt leaks one machine and the caller is only told the
run failed.

### The client gives up before the server does

The SDK's run timeout is `timeout + 60s`; the server's budget is
`timeout + 120s`. A run that uses its full budget is dropped by the client while
the server is still executing it, which leaves the run non-terminal with no
terminal event and the machine unreleased. It fires on exactly the runs that
hold a machine longest.

### Idempotency only guards terminal runs

A client retrying `POST /v1/runs` with the same `Idempotency-Key` while the first
request is still in flight gets the in-flight row, passes the `is_terminal()`
guard, and executes the workload again on a second machine, billing twice. The
loser's terminal write is then rejected, and the final `fail()` overwrites the
winner's state because `set_run_failure` has no compare-and-set.

### `record_run_results` loses results on the final failure

The last `fail()` passes the pre-execution snapshot, whose state is `Queued`.
Writing results in that state is rejected by the lifecycle, so `phase_ms` and
`cleanup_failed` are silently dropped for every run that failed after placement
- which is precisely the population that may be holding compute.

### Results are lost when settling fails

`fail()` returns `Ok(())` whether or not either of its two writes succeeded, and
both are warn-only. A database blip during settlement leaves a run permanently
non-terminal while a `run.failed` event already exists - a terminal event for a
run that never became terminal.

### Placement failures are flattened

`acquire_sandbox` maps every placement failure to `Unavailable`, discarding the
distinction between a quota refusal and an exhausted cluster. A tenant over
quota with `max_attempts: 5` makes five placement attempts for an error that
cannot succeed on the sixth, and the run reports an outage when the cause was a
refusal.

### A worker restarts machines for sandboxes whose runs finished

Observed directly: six containers reappeared with "Up about a minute" for
sandboxes whose runs had finished long before, ids unchanged. The control plane
believes those sandboxes are stranded while the worker re-materialises them, so
reclaiming capacity by expiring their leases does not stick. Not yet traced to
the worker code that does it.

### `register_worker` can wedge a worker permanently

The upsert updates `total_vcpus` but deliberately omits `available_vcpus`. A
worker that re-registers after being reprovisioned smaller trips the
`nodes_capacity_within_total` check, which surfaces as a conflict; a worker that
cannot register cannot heartbeat, and one that cannot heartbeat is never
recovered.
