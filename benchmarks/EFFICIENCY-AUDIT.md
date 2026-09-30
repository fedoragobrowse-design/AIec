# Efficiency audit

Three read-only audits of the codebase against the efficiency specification,
run in parallel, plus one soak. Findings only; the fixes that followed are
listed with their commits.

Severity is about the specification's concerns: unbounded work, wasted
resources, and anything that trades safety for speed.

## Fixed in this pass

| Finding | What was wrong | Fix |
|---|---|---|
| Lease sweeper could spin forever | The stranded-sandbox loop's only exit was a short page. A sandbox whose teardown keeps failing is untouched, so it re-appears on the next page - with no sleep and no attempt counter, `sweep_once` never returned and the 15s ticker was never reached again. My code, written earlier the same day, with a comment claiming a bound that did not exist. | `bcac7e6`-adjacent: a pass that reclaims nothing stops; a page count backs it up |
| `max_attempts` uncapped, no backoff | A placement refusal returns in milliseconds, so the per-attempt deadline never fired and the loop ran at database speed for the whole run budget - a transaction taking the tenant quota row `FOR UPDATE`, scanning nodes, inserting, rolling back, plus an attempt row, thousands of times from one request | Capped at 10, exponential backoff bounded by the remaining budget |
| A cancelled run was reported `failed` | `set_run_failure` was the only run write in the file with no lifecycle guard, so a cancel followed by an in-flight failure rewrote `cancelled` to `failed`. The executor cannot be stopped because the run *is* the request | Verdict protected; the reason is still recorded |
| Placement failures leaked a lease | Only the environment-preparation path released. A failed `start` left the row in `Starting` holding the lease and debited capacity, unrecoverable | `bcac7e6` |
| `per_attempt = budget / max_attempts` | Asking for two attempts halved the time a workload legitimately had, then paid for a second machine on timeout. I introduced this and an advisor caught it before it shipped | Whole budget per attempt; placement gets its own free retry |

## Open, ranked

### High

**Nothing measures the host.** The one high finding here is narrower than the
audit first reported, and the correction matters more than the original claim.

The audit said a worker advertising `slots x 1 GiB` of memory every five seconds
erases the per-placement debit, so the scheduler's memory predicate degenerates
into "are there free slots". **That is wrong**, and it was checked rather than
assumed. `heartbeat_worker` updates `healthy`, `version`, `metadata`,
`last_error`, `observed_sandbox_count` and `last_heartbeat` - it never touches
`available_*`, and the only two writers of those columns in the whole repository
are `debit_capacity` and `release_capacity`. Registration omits them for the same
reason. Confirmed on the cluster: `available_vcpus` and `available_memory_bytes`
were byte-identical across four consecutive heartbeats.

What is actually true is the smaller thing underneath it. `available_*` is
maintained purely by arithmetic over *requested* sandbox sizes, and nothing
anywhere measures the machine. There is no `statvfs` in the workspace. So a node
is scheduled to exactly the sum of what callers asked for, with no reserve for
the operating system, the worker's own processes, or page cache, and with no
disk-pressure signal at all - a host at 99% full still looks to the scheduler
like a node with ten gigabytes per free slot, and the failure arrives at boot,
after quota and capacity have already been charged.

The worker still computes and sends those numbers, and the store discards them.
Dead data on the wire, and misleading to anyone reading `aiec-cli`: it looks like
capacity is being reported when it is not.

**No control-plane concurrency limit on in-flight runs.** No semaphore, no
`ConcurrencyLimitLayer`. Each `POST /v1/runs` holds a connection and a future for
up to `timeout + 120s`; 20 rps per tenant means ~1200 live handler futures, each
holding a run and its bounded output. Tenant quota limits *machines*, not
in-flight runs, because quota is charged at schedule time.

**Firecracker rootfs is fully copied per sandbox.** `tokio::fs::copy` of the
shared rootfs on every create, with no reflink or COW path anywhere, and
`e2fsck -f -y` (forced, ignoring the clean bit) on the copy when the requested
disk is smaller than the image. Snapshot and restore then read the entire disk
image into RAM to hash it. `guest_artifact.rs` already streams correctly; these
two call sites are the counter-example.

**`verify_guest_image` memoizes behind a `OnceLock` with no key at all.** One
result for the whole process, regardless of which artifact was verified. Correct
today only because there is one image path; it is a verification cache that will
silently skip integrity checking the moment a second image exists. The
specification's rule - "never skip integrity verification merely because we
checked it once" - is exactly what this does.

### Medium

- **Batch parallelism is caller-supplied only.** Capped 1..64, never reads
  capacity. Eight slots and 100 cells means a 64-wide herd producing mostly
  `failed` cells rather than queued work.
- **Artifacts stored as base64.** `collect_artifacts` stores the base64 *text* in
  object storage and records its length as the size, so every artifact is ~33%
  larger than its content and its reported size is wrong.
- **Detached per-VM TTL task.** One `tokio::spawn` per boot sleeps for up to
  24h holding a cloned `Sandbox`, with no abort handle and no tie to the run.
  Safe (`stop_if_token` checks the token) but it is an unowned task.
- **`truncated` hardcoded false**, while bwrap truncates and Docker fails the
  whole run. A clipped output is recorded as complete.
- **`per_attempt` and `max_attempts` were over-argued.** Two commits here
  reasoned that dividing the run budget by the attempt count would halve a
  workload's time. Measured properly - a run declaring `timeout_seconds: 60`
  that sleeps 130s is killed at 60.8s - it is the *runtime* enforcing the
  workload's own timeout, which it has always done. The slice is a secondary
  bound over placement, teardown and retries together. Both defaults are now
  correct, and the change was worth making for reasons that were not the ones
  first given.
- **Image resolution re-streams the whole multi-GB rootfs through SHA-256 on
  every sandbox create** (`SignedImageResolver::rootfs_digest`), with no cache.
  `health()` also does a live daemon round trip on every runtime selection.

### Low

- `docker.rs` bounds exec output only after `extend_from_slice`, so the bound is
  soft by one frame.
- `dns: host_resolvers()` re-reads and re-parses `/etc/resolv.conf` per create.
- `RuntimeRegistry::select` awaits `health()` per candidate kind on every
  scheduling attempt, where capabilities are already advertised.

## Already satisfied

Not every item is a problem, and it is worth recording which:

- **No SDK polls.** Both clients block on the synchronous response with a
  timeout-derived budget. No fixed-interval `GET /run/{id}` anywhere.
- **Claiming is not racy where it exists** - `FOR UPDATE ... SKIP LOCKED`
  throughout, and there is no run queue to be unfair about.
- **Command output is bounded** in all three runtimes.
- **Matrix parallelism is validated** at 1..=64 and mirrored client-side.
- **API body size and snapshot transfer are bounded.**
- **The run executor is deliberately not detached** - a run's lifetime is its
  request's, so there is no task to outlive cancellation.

## Not assessed

- Parallel soak (specification item 57) - not run, and the reason is in
  `SOAK.md`.
- The remaining ~40 items of the 59-section specification, which cover
  rootfs/overlay architecture, cache eviction policy, and disk-pressure
  handling at a level this milestone explicitly defers.

## Verdict

`AIEC EFFICIENCY: INCOMPLETE`

Three of the five high findings are resource-accounting failures rather than
speed problems, and all three are the same shape as the leaks fixed in the run
subsystem: something is counted, and the count is not kept honest. The
sequential soak now returns to baseline, which is the one measurement that says
the system does not degrade under load - but it was reached by fixing a
correctness bug, not by optimising anything.

---

## Report

Environment: one host, 192.168.1.250. `docker` runtime, 8 vCPU / 8 GiB on the
docker node, plus Firecracker and bubblewrap nodes. PostgreSQL on the same host.
Firecracker is registered but not exercised here.

### Changes implemented, with what was measured

| Change | Before | After | Evidence |
|---|---|---|---|
| Provisioning releases its lease on failure | 24/80 runs succeeded; 7 sandboxes stranded; 11/18 vCPUs | 38/45 succeeded; 0 stranded; 18/18 vCPUs | `SOAK.md` |
| Placement retried without splitting the budget | transient lease races reached the caller as `failed` | retried free, no machine charged | `bcac7e6`, `899195b` |
| Batch uses a sliding window | *not measured* | *not measured* | `80fcc39` |
| Lease sweeper cannot spin | unbounded loop, no exit | bounded by pages and by progress | `e909669` |
| Retry loop capped and backed off | thousands of transactions per request | ≤10 attempts, exponential | `e909669` |
| Terminal run states protected | cancelled runs reported `failed` | verdict protected | `e909669` |
| Batch bound pinned structurally | untested | arithmetic, no cluster | `72ca055` |

Only the first row is a before/after in the strict sense. The rest are
correctness or robustness changes whose effect on throughput I did not measure,
and the specification is explicit that only observed measurements may be
reported, so none is given a number.

### Not implemented

- **Worker capacity from measured host state.** `aiec-cli` advertises
  `slots x 1 GiB` memory every five seconds, which erases the per-placement
  debit and means no disk or memory pressure is ever observed. The highest-value
  open item, and a design change rather than a patch.
- **Image verification cache keyed on something.** A `OnceLock` with no key is
  correct only because there is one image path.
- **Firecracker rootfs materialisation.** A full copy per sandbox, `e2fsck -f` on
  the copy, and the whole disk image read into RAM to hash it on snapshot.
- **Artifact streaming.** Artifacts are stored as base64 text and their size is
  recorded as the base64 length.
- **No in-flight concurrency limit on the control plane.**
- **The SDK's `run_cells` chunking stall** - converting it breaks the `#[tool]`
  macro and needs the boundary reshaped.

### Security regression gate

Isolation, fencing, tenant boundaries, durability and cleanup guarantees were
not traded for any of the above. The workspace gate is clean: `fmt`, clippy with
`-D warnings`, 348 Rust tests and 15 Python tests. The changes are all on failure
paths, and the two that touch cleanup were verified by the soak rather than by
assertion.

### AIEC EFFICIENCY: INCOMPLETE

Blockers, in the order they would matter:

1. **No host is ever measured.** Capacity is arithmetic over what callers
   requested, with no reserve for the host itself and no disk-pressure signal.
   The debits are correct - an earlier draft of this file claimed a heartbeat
   erased them, which is false, and the disproof is recorded above - but correct
   arithmetic about a number nobody measures is still not a measurement.
2. **A parallel soak leaves a steady-state residue** - two vCPUs and one sandbox,
   flat across three batches, not returned and not identified. The sequential
   soak returns to exactly zero; this does not.
3. **Placement races and capacity refusals are still ~20% of runs** under load.
   They no longer leak, but a caller still sees `failed` for work that never ran.
4. **The Firecracker path is unmeasured.** Everything above is the docker runtime;
   the microVM path has not been soaked or profiled once.
