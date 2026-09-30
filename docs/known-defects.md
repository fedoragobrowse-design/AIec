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
| Machines leaked on eight exit paths after placement | `execute` reached cleanup on two paths; the rest returned past it with `?` | `5b40d36` |
| Stranded sandboxes exhausted a tenant's quota forever | nothing selected a non-terminal sandbox with no live lease and no unfinished run | `5b40d36` |
| The control plane logged nothing at all | `EnvFilter::from_default_env` with no `RUST_LOG` means no directives, so every `tracing::` line was discarded | `5b40d36` |
| A retried idempotency key ran the workload twice | the guard asked whether the run was finished, not whether this call created it | `e4275c6` |
| Every fully-budgeted run was dropped by the client | SDK timeout `stated + 60s` was shorter than the server's `stated + 120s` budget | `e4275c6` |

## Open

### `set_run_failure` has no compare-and-set

`set_run_failure` writes `state` and `failure_reason` unconditionally. A
cancelled run whose synchronous `execute` then fails is rewritten from
`cancelled` to `failed`, so a caller that was told `200 OK / cancelled` reads a
run that says `failed`. `advance` also adopts a terminal state and returns `Ok`,
which lets `execute` keep running commands on a machine `cancel_run` already
destroyed.

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
