# AFTER — current deployed build, matched benchmark and soaks

Measurements below were taken against the deployment that started at
2026-10-01T03:51:44Z (`aiec-server` sha256 `94554bfcf8e7c92c…`, `aiec` sha256
`2867702cd1f561e1…`), whose guest rootfs is sha256 `71b72e9b…2227b`. The
baseline conditions fingerprint `602f511b90348c50` is reproduced exactly:
scenarios `control-plane` + `empty-exec`, `runtime_requested: null`,
image `python:3.13`, cpu 1 / memory 512 MiB / disk 2048 MiB, command `true`,
no setup, validations, artifacts, repo or workload timeout, 25 samples. The
baseline file itself is unmodified (sha256 `29fdbcb4fe4a123d…`).

Every workload ran under `flock /tmp/aiec-acceptance.lock` through the durable
Run API. No service was changed, no source was edited, no guest was reclaimed
manually, and `--reclaim-leaked` was never used.

## Control plane and empty exec, matched to baseline

`after-2026-09-30.json`, fingerprint `602f511b90348c50`, 25/25 succeeded
(baseline: 22 succeeded, 3 failed), 213 API requests, 0 rate-limit 429s.

| metric | before (n=22) | after (n=25) | change |
|---|---|---|---|
| run_total p50 | 25.58 s | 15.05 s | −41.2 % |
| run_total p95 | — | 17.50 s | — |
| wall_time p50 | 23.78 s | 13.18 s | −44.6 % |
| queue_wait p50 | 8.27 s | 7.77 s | −6.1 % |
| placement p50 | — | 4.68 s | — |
| cleanup p50 | 13.35 s | 3.09 s | −76.8 % |
| task p50 | 0.87 s | 0.70 s | −19.1 % |
| residual unattributed p50 | 6.00 s | 6.07 s | +1.2 % |
| /health p50 | 0.0027 s | 0.0029 s | +7.4 % |
| /ready p50 | 0.1616 s | 0.1653 s | +2.3 % |

Success throughput over the durable Run window (04:03:18Z → 04:09:39Z,
381.5 s) is 25/381.5 = 0.0655 succeeded/s. Failed outcomes: none in this
window; the three baseline failures were stale-generation errors that do not
recur here. p99 is withheld wherever the sample is under 100, since a
nearest-rank p99 over 25 samples is the maximum pretending to be a tail.

## Sequential soak — 100 true-command runs

`sequential-current-2026-09-30.json`: 100 requested, 100 succeeded, 0 not
succeeded, 0 rejected, 1477.5 s wall clock, 4.06 succeeded/min.
run_total p50 13.81 s, p95 19.49 s, p99 20.62 s (n=100, percentiles valid).

Observed peaks over 816 one-second samples: queued 1, executing 1, active Runs
1, active leases 3, non-terminal sandboxes 3, PostgreSQL client backends 20
(3 active), API RSS 61.7 MiB / 36 FDs / 14 threads, docker worker RSS 85.7 MiB
/ 20 FDs / 14 threads, Firecracker worker 17.6 MiB / 14 FDs / 13 threads.

Before/after capacity is identical: 2 pre-existing non-terminal sandboxes and
2 active leases both before and after (their generation counters advance, which
is renewal, not accumulation), 3 running containers before and after (testdb
plus those two pre-existing sandboxes), same 23 container records, 0 TAP
devices, 185 state directories before and after, 0 archives or partials,
statvfs free within 0.03 %. No leak evidence; nothing hidden.

## Parallel soak — 20 explicit batches of 4

`parallel-current-2026-09-30.json`: 20 batches, 4 Runs each, every batch
censused immediately before and after (that is why the file has 20 batch
records with their own before/after census, not a rolling pool).
80 requested, 80 succeeded, 0 failed, 452.6 s, 10.61 succeeded/min,
per-batch duration 18.8–24.1 s.

Observed peaks over 253 samples: queued 4, executing 4, active Runs 4, active
leases 6, non-terminal sandboxes 6, PostgreSQL backends 20 with at most 4
idle-in-transaction, API RSS 63.0 MiB / 40 FDs / 14 threads, docker worker
85.7 MiB / 24 FDs / 14 threads. Concurrency never exceeded the requested
four; capacity, containers, directories, TAP devices and archives returned to
the starting census.

## Firecracker, current deployed path

`firecracker-current-2026-09-30.json`: 3 bounded repetitions,
`requested_runtime: firecracker`, network disabled, placed on worker
`01a0e4b5-…` (`fc-host`) with reason "explicit runtime Firecracker selected",
3/3 succeeded. Placement 5.55–5.83 s, task 0.58–0.62 s, cleanup 2.91–3.06 s.
Afterwards: 0 firecracker processes, no new `/tmp/aiec-fc` socket directories
(92 before and after), no new worker state directories, no new archives, no
non-terminal sandbox beyond the two pre-existing Docker ones.

## Cancellation

`running-cancel-current-2026-09-30.json`: two Runs cancelled while `running`
against a 120 s task. Both cancels returned 200 with state `cancelled`, the
second cancel returned 200 again (idempotent), the blocking submission returned
`cancelled`, and the task was actually stopped — recorded `exit_code 137`,
duration 2.8–3.0 s, not the full 120 s. Event order
`run.created → sandbox.assigned → task.started → task.finished →
run.cancelled`; the attempt is `cancelled`; active leases fell from 3 to 2 and
non-terminal sandboxes returned to the two pre-existing.

`lifecycle-current-2026-09-30.json`, queued cancellation: with 4 Runs holding
all Docker capacity and one more queued, the queued Run was cancelled
(queued → cancelled, submission returned `cancelled`, no `cleanup_failed`),
and the queue emptied with no orphan Run. The four running blockers there were
cancelled after they had already reached `succeeded`; the API returned the
terminal Run unchanged, which is the documented behaviour and not a
cancellation of work in flight — the running-state proof above is the one that
shows real interruption.

## KeepOnFailure retention and natural TTL expiry

Same file: a Run with `retention: keep_on_failure` and
`retained_seconds: 15`, task exits 7. Run `failed` with reason "the task did
not succeed", `retained_sandbox_id` set, `retained_until` 15 s out. The
retained machine was still openable: `exec cat /workspace/retained-marker`
returned `retained-marker`, so it was genuinely the failed run's guest. Events
include `sandbox.retained` and `sandbox.retention_expired`; after expiry the
sandbox read back `destroyed` and the non-terminal census was back to the two
pre-existing sandboxes. Leases, ledger rows and guest state before/after are
in the file. No manual reclamation anywhere in this evidence set.

## Limitations

* Linux `task_count` counts OS threads, not Tokio tasks; no Rust-level task
  census is reachable without a deployment change.
* One-second SQL sampling reports the observed peak, not an unobserved
  instantaneous maximum.
* The matched benchmark's own host/SQL monitor failed serialization after the
  report was written; the report is complete and its 25 durable Runs were
  recovered from the database, but no host-RSS baseline claim is made for that
  phase. Every later phase has full monitoring.
* These binaries predate the repo-cache authorization fix and the dotted
  `placement.*` subphase timings, so no result here is attributed to them.
* Guest protocol 1 rootfs; the parent's cutover to protocol 2 is a different
  guest and is not covered by this evidence.