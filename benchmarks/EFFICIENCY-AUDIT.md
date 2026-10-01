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

## Repository object cache (opt-in, measured, and not shippable as written)

Specification items 14 and 15 ("workspace preparation cache", "git cache")
are now implemented in `crates/aiec-api/src/repo_cache.rs`, and the
implementation is **off by default**: `AIEC_REPO_CACHE_ENABLED=true` is the
only way to turn it on, and unset or anything else means ordinary
`git clone` behaviour is unchanged.

What is actually reused is Git *objects* for one immutable commit, and nothing
else. The flow, entirely inside the fresh sandbox:

1. `git ls-remote` against the canonical HTTPS URL, inside the sandbox that is
   about to be prepared, resolves the requested branch, tag (peeled) or commit
   to a full commit id. A mutable ref is therefore resolved on **every** run,
   and an immutable commit is still re-checked for anonymous access: a
   repository that was public and is now private stops hitting the cache on the
   next run rather than on the next eviction.
2. A miss fetches that one commit into a fresh bare repository at
   `/workspace/.aiec-repo-objects` (`--template=`, no hooks, credential helpers
   and global/system configuration disabled, no redirect following, no
   protocol other than `https` for the remote side). `FETCH_HEAD` is deleted
   because it embeds the remote URL.
3. Only `objects/`, the cache ref, `HEAD`, `config` and `shallow` are read back,
   through the existing `list_files`/`get_file` file API, and serialized as the
   existing `PortableWorkspaceArchive` format. `SnapshotProvider::capture` is
   deliberately *not* used: it would also copy the working tree and leave a
   per-snapshot archive file in the worker state directory with no bounded
   deletion contract.
4. A hit imports that archive with the existing
   `SandboxRuntime::import_workspace_archive`, then materializes a fresh
   checkout: `git clone --no-hardlinks --no-checkout` of the staging mirror into
   `/workspace/repository`, `origin` reset to the real URL, detached checkout of
   the resolved commit, and the staging mirror removed.

The safety properties that matter, and why each one is structural rather than
conventional:

- **No sandbox ever writes the shared cache.** Archives are handed to a
  runtime as bytes through the existing import API; there is no host path, no
  bind mount, no exposed cache directory. The guest sees a mirror directory
  that belongs to that sandbox and is deleted before the Run's setup runs.
- **Identity.** The key is tenant + canonical repository URL + resolved commit,
  plus shallow/full history, worker node, runtime kind, image id and a digest of
  the sandbox's network policy. Two tenants cannot collide by construction; a
  Run whose sandbox carries secrets, or whose exec environment is caller-supplied,
  skips the cache entirely, because there is no secure authorization identity
  for a private repository to be isolated by yet.
  The check happens on the Run's declared workload, not on what the guest
  happens to hold: a fresh sandbox has no installed secrets yet, so
  `provision_sandbox` carries an `authorization_present` flag from the Run
  request (`workload.secrets` or `workload.environment` non-empty) into
  `prepare_environment`, which ORs it with the sandbox's own secret values.
  Consulting only the installed secrets let a credential-carrying Run reach
  the shared object store.
- **Never reused:** `.git/index`, the working tree, untracked files, credential
  helpers, cookies, extra headers, hooks, alternates, reflogs and logs. Each Run
  gets a fresh independent `.git`, and the cache is only ever *read* by a guest.
- **Bounds.** At most 16 entries, 64 MiB total, 16 MiB per entry, 4096 archive
  members, 30-minute TTL, LRU eviction, two concurrent cache operations, a
  fetch with a per-file size limit inside the sandbox, and no retained
  temporary files on the host at all.
- **Single flight.** Concurrent Runs on one key share one fill. The fill is
  owned by the first Run's future, never by a detached task, so a cancelled or
  failed leader releases every waiter with a real error and leaves no in-flight
  entry behind.

**What measuring it found.** Both phases ran on the deployed build through the
durable Run API, six samples each on one worker, pinned commit, Docker runtime.
Sample 0 is the fill, samples 1-5 are hits. Every sample asserted inside the
guest, before any work: clean tree, no private mirror left behind, `HEAD` equal
to the pinned commit, marker present in the captured diff, sandbox terminal.

| | cache OFF | cache ON (warm) | bypass run (ON, skipped) |
|---|---:|---:|---:|
| guest receive bytes, first | 9 280 | 260 690 | — |
| guest receive bytes, median of rest | 9 654 | **253 223** | 9 496 |
| placement, median of rest | 6 963 ms | 9 076 ms | 6 860 ms |

The cache moves **26x more** network bytes than the clone it replaces and is
about two seconds slower per Run. Calibrated in the same guest against the same
repository, with the interface counter read either side of the command:
`git clone --depth 1` moves 8 580 bytes, `git ls-remote -- <url> HEAD` moves
**250 950**. `resolve_commit` re-resolves the ref on every Run, including a
hit, to re-check that the repository is still anonymously readable — and that
one check costs 29x the whole shallow clone. The guard that makes the cache
safe costs more than the work it avoids. The bypass run matches the OFF phase
exactly, which is the authorization fix working.

**Two real defects were found and fixed on the way.** The Docker directory
listing dropped every subdirectory (a tar names a directory with a trailing
slash and the one-level test ran before stripping it) and matched only the
workspace-relative spelling of entry names while the daemon names copied
entries after the directory it was asked for, so every listing below the first
level came back empty. A recursive walk over a Git mirror therefore stopped
after one level and the archive captured no objects at all — which is why the
first live attempt failed with git's exit 128 on a mirror that was not a
repository. The same defect was in the public `GET /v1/sandboxes/{id}/files`
route. A capture that declines is now logged instead of falling back silently.

**What is deliberately not changed.** Bounding the per-Run re-resolution by an
interval instead of removing it is a real weakening of the property that a
repository which was public and is now private stops being served from a shared
object store, and the staleness bound is somebody else's decision. The feature
is off by default, so leaving it off costs nothing and shipping it as written
costs a regression.

The cache is also *not* a general build or package cache. There is no shared
writable build directory, no cross-tenant cache and no personal/trusted-local
mode beyond this single explicit opt-in; Firecracker isolation is untouched
either way.

## Verdict

`AIEC EFFICIENCY: COMPLETE WITH ONE REJECTED FEATURE`

The headline is not a micro-optimisation. Matched conditions fingerprint,
same host, same workers, same images: run_total p50 **25.58 s → 14.56 s
(−43.1 %)** and 22/25 → 25/25 succeeded. `phase_cleanup` alone accounts for
−76.5 % of it, and the unattributed residual is flat at ~6 s, so the gain is
inside accounted phases rather than moved into the unaccounted bucket. Full
table in [`AFTER2.md`](AFTER2.md).

Three of the five original high findings were resource-accounting failures
rather than speed problems, and all three were the same shape as the leaks
fixed in the run subsystem: something is counted, and the count is not kept
honest. The sequential soak returns to baseline, which is the one measurement
that says the system does not degrade under load — reached by fixing a
correctness bug, not by optimising anything.

Two performance defects were found by measuring the final build rather than by
reasoning about it, and both are fixed: artifact collection cost 459.8 ms per
64 KiB chunk because every read cost three HTTPS round trips, and the Docker
directory listing silently hid every subdirectory.

One feature is rejected on its own numbers: the repository object cache moves
26x more network bytes than the ordinary clone it replaces. It is off by
default and stays off.

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

### Implemented since this file was first written

- **Worker capacity from measured host state.** Done: workers report vCPUs,
  `MemAvailable` and free disk on every heartbeat, and admission refuses on a
  stale heartbeat, a missing reading or a sibling's reservation. Fourteen cases
  exercised against the deployed function.
- **Image verification cache keyed on something.** Done: keyed on the complete
  identity of the bytes it checks, bounded on entries, bytes and time to live,
  with eviction that is deterministic rather than map-order.
- **Firecracker rootfs materialisation.** Done: `FICLONE` with a per-
  materialization probe and a byte-copy fallback, base never opened for
  writing, exclusive destination, cancellable, no partial image left behind.
  Measured `method=reflink` on a 4 GiB base in production.
- **Artifact streaming.** Done: bounded 64 KiB groups from sandbox to worker to
  control plane to object store, no stage holding the whole file, and a
  download verified in full before any byte is served.
- **In-flight concurrency limits on the control plane.** Done: queue
  `max_active`, upload semaphore, and per-worker boot and snapshot slots.

### Still not implemented

- **The SDK's `run_cells` chunking stall** - converting it breaks the `#[tool]`
  macro and needs the boundary reshaped.
- **Per-Run pagination on `list_run_events`, `list_run_attempts` and
  `list_run_artifacts`.** They remain complete per-Run reads. The measured cost
  is 0.13-0.31 ms on the deployed dataset, so the bound is not load-bearing
  today, but it is a bound that is absent rather than one that holds.

### Security regression gate

Isolation, fencing, tenant boundaries, durability and cleanup guarantees were
not traded for any of the above. The workspace gate is clean: `fmt`, clippy with
`-D warnings`, the full workspace test suite, the SDK import contract and the
Python SDK tests. The changes on failure paths were verified by the soaks
rather than by assertion, and the two changes that touch authorization — the
cache bypass and the group read — each have a test that fails if the check is
removed.

### AIEC EFFICIENCY: COMPLETE WITH ONE REJECTED FEATURE

What each of the original blockers turned out to be, in the order they were
written:


1. **Resolved: the host is measured.** Workers report vCPUs, `MemAvailable` and
   free disk on every heartbeat, `aiec_host_has_headroom` refuses on a stale
   heartbeat, a missing reading or a sibling's reservation, and the reserves are
   512 MiB of memory and 2 GiB of disk. `database-pressure-after.json` exercises
   fourteen admission cases against the deployed function. The staleness of
   `pressure.observed_at` is recorded as accepted and unproven, not enforced.
2. **Resolved: the parallel soak returns to its starting census.** Twenty
   batches of four, each censused immediately before and after. The earlier
   build succeeded 80/80; the final build succeeded 77/80 with three transient
   `no schedulable worker has capacity` refusals at four-way concurrency. Either
   way the census afterwards is the census before: capacity, containers,
   directories, TAP devices and archives all back where they started, with no
   new non-terminal sandbox and no cleanup failure. `AFTER.md`, `AFTER2.md`.
3. **Placement races and capacity refusals are no longer ~20% of runs.** The
   25-sample matched benchmark succeeded 25/25 with none of the baseline's three
   stale-generation failures, and the 100-run sequential soak succeeded 100/100.
   The parallel soak still saw three transient capacity refusals in 80, which is
   the same class and does not accumulate.
4. **Resolved: the Firecracker path is measured.** Three bounded repetitions on
   the deployed microVM runtime, plus a live proof of rootfs copy-on-write, guest
   destruction and lease release. It remains a smaller sample than the docker
   path and no throughput claim is made from it.
5. **Open, and the one that matters: the repository object cache costs 26x the
   network bytes it saves** because its per-Run anonymous-access re-check is
   29x the shallow clone it replaces. It is off by default and should stay off
   until the re-check is redesigned. Measured numbers are above.

## Current-state Firecracker verification

The earlier statement that the Firecracker path had never been exercised is
superseded by this direct check. This is one smoke run, not a soak or a
performance baseline.

- Run `01a0f061-21b4-7753-9506-ca3067dc85ed` requested
  `requirements.full_kernel_isolation=true` and explicitly selected Firecracker.
  Placement reported worker `01a0e4b5-b3da-725a-9a51-b23717207c11`.
- The command printed the guest kernel, waited 30 seconds, and printed
  `verified-guest`. Result: `succeeded`, exit 0, stdout
  `6.1.186\nverified-guest`. Host kernel: `7.2.7-200.fc44.x86_64`.
- During execution, PID `1193374` ran the configured binary
  `/home/gobrowse/aiec/bin/firecracker-v1.17.0-x86_64`. Its file descriptors
  included `/dev/kvm`, `anon_inode:kvm-vm`, and `anon_inode:kvm-vcpu:0`.
- Reported phases: placement 5,805 ms, task 30,802 ms, cleanup 2,753 ms.
  No percentiles or throughput claim follow from this sample.
- After completion, sandbox `01a0f061-2416-77d1-921d-031dcaae03bd` was
  `destroyed`, its lease was `released`, its VM directory was absent, no
  configured Firecracker process remained, and both Firecracker nodes had
  4/4 available vCPUs.
- A second request specifying Docker with
  `requirements.full_kernel_isolation=true` failed before task execution:
  `unsupported operation: runtime Docker lacks required capabilities`.

The prior chat claim of a silent isolation downgrade was false. Its request
placed `full_kernel_isolation` under `workload` rather than `requirements`,
the process observation sampled before VM boot, and the binary lookup checked
an unversioned filename rather than the configured versioned path. No fallback
inside Firecracker was demonstrated, and no fix is claimed.

Network-enabled creation is a separate environment limitation: an earlier
request failed with `TAP setup failed: ioctl(TUNSETIFF): Operation not permitted`.
Network-disabled VM execution requires no TAP device. Repository cloning inside
a network-enabled Firecracker guest remains unverified on this worker.

## Re-measuring these findings

The findings above are left as they were recorded. What has changed since is
that each of them can now be re-measured rather than re-argued:

```
python3 benchmarks/bench.py soak --iterations 40 --max-parallel 8 \
    --checkpoint-every 8 --label after-the-lease-fix
```

The harness takes the same observations this report had to gather by hand -
non-terminal sandboxes, free vCPUs, running containers, run states - at every
checkpoint and at the end of the loop, and it takes the final observation
*before* any cleanup, so a leak cannot be hidden by the measuring.

The high finding **"nothing measures the host"** is only partly addressable from
outside the worker, and the report is explicit about which part. `/metrics`
exposes the scheduler's reserved capacity, which is arithmetic over requested
sizes and not a measurement of a machine; the harness's own host numbers - load,
available memory, free disk, running containers - describe the machine the
harness ran on, and say so in a `scope` field. Run the harness *on the worker*
and the container count and host pressure become worker measurements; run it
anywhere else and they are explicitly unavailable rather than reported as zero.
See [`README.md`](README.md).
