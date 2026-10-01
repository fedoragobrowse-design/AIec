# Orchestration report

What was verified on a live cluster, where the evidence is, and what remains
unproven. Every claim here is an observation; the files named are the raw
records.

Deployment under test: `192.168.1.250`, `aiec-server` `ab17097283cb838d…`,
`aiec` `bb4e1e60e060ad82…`, Firecracker guest rootfs `195983e85e3ed9645…`
(`guest_protocol_version: 2`, admission signature `7d99393e103daaa7…`),
MinIO object storage, PostgreSQL, two workers (firecracker 4 vCPU, docker 8).

## The two primitives

**Sandbox** is the low-level execution primitive and is still that: a row, a
lease, a machine, an explicit lifecycle. It is never created implicitly by
anything except a Run's own placement, and `POST /v1/sandboxes` remains
available for callers that want exactly that.
`runtime-rootfs-docker-live-2026-09-30.json`.

**Run** is a first-class durable object: admitted to a durable queue, claimed by
an executor under a renewable lease, executed to a terminal state, and settled
with attempt-level evidence. Dropping the HTTP connection stops the waiting, not
the work. A cancelled run whose executor later fails stays `cancelled`
(`known-defects.md`, closed).

## Automatic sandbox creation and real work

Every Run in this round created its own machine, ran a real command in it, and
reclaimed it. The 100-run sequential soak on the final build: 100 requested,
**100 succeeded**, 1 535 s, 3.91 runs/min, zero non-terminal sandboxes at the
end, free vCPUs 12.0 → 12.0.
`after2-soak-sequential-2026-09-30.json`.

## Results and disposable destruction

Run results carry the task's exit code and bounded output, the validations with
their own exit codes, git evidence, collected artifacts, and the cleanup
verdict. 80 parallel Runs across 20 batches of four: 77 succeeded, 3 refused for
capacity, **0 non-terminal sandboxes and 0 cleanup failures** afterwards.
`after2-soak-parallel-2026-09-30.json`.

## Failure retention and natural expiry

A Run with `retention: keep_on_failure` and `retained_seconds: 15` whose task
exits 7 settles `failed`, keeps `retained_sandbox_id`, and the retained machine
is genuinely the failed run's guest — `exec cat /workspace/retained-marker`
returned the marker. Events include `sandbox.retained` and
`sandbox.retention_expired`; after expiry the sandbox read back `destroyed` and
the census returned to baseline. `lifecycle-current-2026-09-30.json`.

## Cancellation and timeout, for real

Two Runs cancelled while `running` against a 120 s task: both cancels returned
`200 cancelled`, the second was idempotent, the blocking submission returned
`cancelled`, and the task was actually stopped — `exit_code 137` after 2.8–3.0 s
rather than 120 s. Event order `run.created → sandbox.assigned → task.started →
task.finished → run.cancelled`. A queued Run was cancelled while four others held
all Docker capacity, and the queue emptied with no orphan.
`running-cancel-current-2026-09-30.json`, `lifecycle-current-2026-09-30.json`.

## Artifacts survive their machine

A Run's artifacts are collected in bounded 64 KiB groups and served from object
storage after the machine is gone. An empty file, a 66 770-byte file and a
16 777 216-byte file were each collected and then downloaded; every served byte
hashed to the digest recorded at collection. Collection of 16.8 MiB took
**8 945 ms** after the group read, against 129 360 ms with one read per chunk.

## git diff and status capture

A tracked-file edit on the pinned `octocat/Hello-World` commit: status
` M README`, the exact nonempty diff, `changed_files: ['README']`, and the
pinned `results.commit`. Untracked files report `?? name` with the changed-file
list and no diff, which is what `git diff` actually says.
`runtime-rootfs-docker-live-2026-09-30.json`.

## Repetitions, matrix expansion and bounded concurrency

A matrix of unequal durations returned its cells in submission order with axes
preserved; an idempotent replay returned the same `matrix_id` and the same runs.
Cells that exceeded capacity were **deferred, never dropped**. Paging with
`limit=2` produced three stable pages with no duplicates and `next: null` at the
end; `limit=256` and `limit=9999` both clamped.
`database-pressure-after.json`.

Bounded concurrency: 20 explicit batches of 4, each censused immediately before
and after. Concurrency never exceeded the requested four, and capacity,
containers, directories and archives returned to the starting census.

## Capability placement with no downgrade

`requirements.full_kernel_isolation = true` places on the microVM runtime and
fails with `runtime Docker lacks required capabilities` when Docker is requested
instead — refusal, not a silent fallback. Three bounded Firecracker repetitions
succeeded on the deployed path, and afterwards no Firecracker process, socket
directory or state directory remained and the lease was released.
`firecracker-current-2026-09-30.json`.

## Cross-tenant denial

A second tenant's read of another tenant's matrix is `404 not_found`, not an
empty page, and a half-supplied cursor is `400 invalid_request`. Run artifacts
are tenant-scoped by object key. `database-pressure-after.json`.

## SDK, CLI and MCP

The documented import contract holds (`from agentforge import AIec, AIecError`),
37 Python SDK tests pass, and the Rust client, CLI and MCP server all drive the
same wire protocol. The MCP server runs a real agent inside a real disposable
sandbox and reports durable cleanup evidence rather than logging a warning.

## Queue fairness, proven with two tenants

Tenant A submitted 8 concurrent Runs and tenant B submitted 1 while A still had 4
queued. Peak concurrency was 4 — the configured `max_active` — and B started at
04:11:02 with four of A's still queued. Across 65 samples of 9 runs, each run had
exactly one distinct owner. 9/9 succeeded, and afterwards 15 queue rows
finished, 15 sandboxes were destroyed, 15 leases released and 0 artifact objects
remained. `database-pressure-after.json`.

## Database cost, measured on the real dataset

`EXPLAIN (ANALYZE, BUFFERS)` on the deployed database with 554 Runs and a
populated queue: tenant run page 0.181 ms index scan, matrix page 0.092 ms, run
events 0.314 ms bitmap index scan, run attempts 0.13 ms, queue claim 0.357 ms
through `run_queue_pending_tenant_idx` with `LockRows`. All shared hits, zero
shared reads. Connection peaks over 30 samples during a concurrent soak: 17
backends against `max_connections` 901, longest idle-in-transaction 1.56 s.
`database-pressure-after.json`.

## Host pressure and no aggregate overcommit

Workers report vCPUs, `MemAvailable` and free disk on every heartbeat, and
`aiec_host_has_headroom` refuses on a stale heartbeat, a missing reading, a
post-reserve zero, a negative demand, or a sibling's reservation — fourteen
cases exercised against the deployed function inside a rolled-back transaction.
Two siblings holding 10 of 8 vCPUs refuse because the demand is aggregated, not
summed. Heartbeats advance `last_heartbeat` and the pressure observations while
`total_*` stays fixed; only `available_vcpus` moves, from scheduler debit and
release. `database-pressure-after.json`.

## Resource release exactly once

Across the whole round: 0 run cleanup failures, 0 new non-terminal sandboxes, 0
orphaned leases, free vCPU and free disk within 0.03 % of their starting values,
and no scratch or partial files. The one case that used to strand a lease — a
lease still `active` on a sandbox already `failed`, invisible to a sweeper that
only looks at expired leases and a stranded-sweep that only selects sandboxes
with no live lease — is selected explicitly.

## Bounded owned work

The run executor is not detached: a run's lifetime is its request's, so there is
no task to outlive cancellation, and the API measured 14 threads and 36 file
descriptors across a 100-run soak without growth. Concurrency is bounded by the
queue's `max_active`, artifact collection by an upload semaphore, guest image
verification by a bounded identity cache, and the repository cache by entry,
byte, member and operation limits.

## OMP through the generic path

`benchmarks/omp-after-2026-09-30.json`. Two revisions, Docker runtime, pinned
target commit, credentials delivered over the ordinary authenticated file route
and never in the Run request, argv, environment or a requested artifact. **Proven**:
both sides `succeeded`, 3/3 validations, git evidence recorded, agent
transcripts collected with digests, cleanup reported. One earlier sample failed
2/3 because the agent left its 15-byte file without a trailing newline, which
`wc -l` counts as zero; both revisions behaved identically in both samples.

## Known limits, stated rather than hidden

- Firecracker networking is unavailable on this host: the worker cannot create a
  TAP device. MicroVM Runs are exercised with networking off.
- The hosted E2B path was not exercised against a real provider.
- The repository object cache moved 26× more network bytes than the ordinary
  clone and is left off. Its cost model is wrong, not its safety model; see
  `AFTER2.md`.
- `pressure.observed_at` staleness is accepted and unproven; the admission gate
  uses `last_heartbeat` freshness, which is the documented contract.
- `list_run_events`, `list_run_attempts` and `list_run_artifacts` remain complete
  per-Run reads without a `LIMIT`. Only matrix recovery is keyset-paginated. The
  measured cost of those three is 0.13–0.31 ms on the deployed dataset, so the
  bound is not load-bearing today.
- The repository cache's authorization bypass is proven by a live run
  (`repo-cache-on-2026-09-30.json`, the last sample), not by a unit test: the
  decision is a two-term flag carried from the Run request, and the mock
  runtimes in the suite do not advertise `portable_workspace`, so a unit test
  would exercise a path no real run takes.
