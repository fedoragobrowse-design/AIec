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

**Worker capacity is advertised from CLI flags, not measured.** `aiec-cli` sends
`available_memory_bytes = slots x 1 GiB` and `available_disk_bytes = slots x
10 GiB`, every five seconds. Two consequences: the per-placement memory debit is
*erased* by the next heartbeat, so the scheduler's memory predicate degenerates
into "are there free slots" - a node told 8 GiB is free accepts eight 8 GiB
sandboxes and the host is asked for 64 GiB. And no disk pressure is measured
anywhere: there is no `statvfs` in the workspace, so a host at 99% full keeps
advertising disk and fails at boot, after quota and capacity have been charged.

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
