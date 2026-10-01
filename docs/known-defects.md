# Known defects

Found by auditing the run subsystem and by running the MCP server against a
live cluster. This is the single file for both: it previously existed twice,
`docs/known-defects.md` and `docs/KNOWN_ISSUES.md`, which differ only in case
and therefore collide on a case-insensitive checkout. Fixed items are listed
with the change that fixed them so this file does not become a place where
stale problems go to hide.

Each entry says what is wrong, how it shows up, and what is not yet done.

The adversarial review of 2026-10-01 — five read-only hunters over distinct
subsystems, plus two subsystems reviewed directly — is written up in
[`bug-hunt-2026-10-01.md`](bug-hunt-2026-10-01.md). Nineteen defects were
confirmed and fixed there with the test each fix was watched failing for, and
seven findings are recorded there as deferred with the reason each was not
changed. The items below are the ones this file already tracked.

## Resolved against a live cluster

### Docker outbound egress and workspace snapshot restore

**Status:** resolved on `192.168.1.250` by the deployed runtime/API fixes.
`benchmarks/runtime-rootfs-docker-live-2026-09-30.json` records:

- A network-enabled worker-created Docker guest fetched `https://example.com`
  with certificate verification and received HTTP 200.
- A Run cloned pinned `octocat/Hello-World`, edited tracked `README`, and
  persisted the exact nonempty diff, ` M README` status and changed-file list.
- A workspace snapshot was captured, its original guest destroyed, restored
  into a distinct new Docker guest, and the exact marker read successfully.
  The restored guest and snapshot were then deleted.

The earlier DNS/connectivity observations apply to the previous deployment, not
the current one. Firecracker networking remains a separate host-permission
limitation: the worker lacks the capability needed to create a TAP device.
Network-disabled Firecracker create/first-exec/destroy is verified.

### A destroyed sandbox could be reported as destroyed when it was not

**Status:** fixed. Kept because the shape of the bug is worth remembering.

A `aiec_run_repo_task` that ended in a failing command left its sandbox running:
`aiec_list_sandboxes` still showed it after the tool returned, holding capacity
the caller believed had been released.

Two defects compounded:

- **The cleanup failure was invisible.** `SandboxGuard::release` logged a
  warning and dropped the error, so the tool returned a result that read as
  "the machine is gone". A cleanup failure is now reported in the result as
  `cleanup_failed`, with the sandbox id and the reason, and the run's
  measurements are still returned.
- **The destroy was racy.** Issued immediately after a failed task it could come
  back `conflict: worker lease generation or status changed`, because the worker
  was still resyncing its lease. The identical call a minute later succeeded
  against the same sandbox with an `active` lease, which is what identified it as
  transient rather than a state error. Destroy is now retried briefly on that
  specific conflict.

A related honesty fix: `destroy_sandbox` used to give up after a two-second poll
and return `"destroyed"` whether or not it had seen the sandbox disappear. It now
reports the state it actually observed and fails if the machine is still there.


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
| A quota refusal cost five placement attempts and read as an outage | `acquire_sandbox` mapped every placement failure to `Unavailable`, the one kind the run loop retries | "Stop calling a quota refusal an outage" |
| Sandboxes could not resolve names, or could not resolve at all | the container spec set no resolvers and let the daemon pick a public one the network blocks | `e975003` |

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


### `aiec_compare_omp` drops the per-run output

**Status:** open. **Severity:** reporting, not correctness — the comparison still
runs both sides correctly and cleans up.

`aiec_compare_omp` returns `last_output: ""` for every side, even when the run
succeeded and the same command's output is captured by `aiec_test_omp`.

#### Repro

The same `omp_command` and the same `validation_commands`, against the same
revisions, on the same cluster:

```
aiec_test_omp     -> omp.stdout == "PROBE_MARKER\n"    validations == ["CHECKOUT_PRESENT\n"]
aiec_compare_omp  -> last_output == ""                  validation_passes == 1
```

Both are called with `omp_command: ["echo", "PROBE_MARKER"]`.

#### What has been ruled out

- **Not concurrency.** `max_parallel: 1` and `max_parallel: 2` both return empty.
- **Not the command.** The exit code is `0` and the validations pass, so the exec
  ran; only its captured output is missing.
- **Not the runtime.** `aiec_exec` on a Docker-runtime sandbox returns stdout and
  stderr correctly, and `aiec_test_omp` — which calls the very same
  `run_omp_once` — returns it.
- **Not a dropped argument.** `setup_command` and `omp_command` reach the tool
  schema and are propagated into each side's `OmpRunRequest`; before that fix the
  side silently fell back to `["omp", "run"]` and failed with exit 127, which is
  how the argument plumbing was found in the first place.

#### Where to look

`SideSummary::from_runs` in `crates/aiec-mcp/src/eval.rs` reads `run.omp.stdout`
and `run.omp.stderr`, and the value is empty for runs produced by
`compare_omp` while the same field is populated for runs produced by
`aiec_test_omp`. Since both call `run_omp_once`, the loss is either in how
`compare_omp` collects the results of `join_all` into `baseline_runs` /
`candidate_runs`, or in a move of `run.omp` before aggregation. Adding a
`tracing::debug!` of the raw per-run stdout inside `from_runs` would settle it in
one run.

#### Why it matters

A comparison is only checkable if you can see what each side actually did. Two
sides reporting identical numbers mean nothing without the evidence, so this is
the first thing to fix before trusting a comparison result.

### A worker's `available_*` does not follow a capacity change

**Status:** open. **Severity:** operational.

Raising a worker's `--capacity` updates its `total_*` on the next heartbeat, but
`available_vcpus` / `available_memory_bytes` / `available_disk_bytes` are
deliberately left alone by the registration upsert, so they keep the old value.
A worker taken from 3 to 8 vCPU still advertises 3 available, and concurrent
work is refused with `LOCAL_CAPACITY_UNAVAILABLE` even though the cluster is
idle.

The upsert is right not to clobber these — they are a running reservation, and
overwriting them would hand the same vCPU to two sandboxes. What is missing is
any reconciliation of "reserved" against "in use". Until then, changing a
worker's capacity needs its node row reconciled by hand:

```sql
update nodes
   set available_vcpus = total_vcpus,
       available_memory_bytes = total_memory_bytes,
       available_disk_bytes = total_disk_bytes
 where name = '<worker>' and sandbox_count = 0;
```

The `sandbox_count = 0` guard matters: without it the update would hand
capacity that a live sandbox is holding to the next placement.

### The `initialize` handshake never answers `2026-07-28`

**Status:** SDK behaviour, not a defect. Recorded so nobody re-investigates it.

A client that asks for `2026-07-28` on `initialize` is answered `2025-11-25`:

```
client asks 2026-07-28 -> server answers 2025-11-25
client asks 2025-11-25 -> server answers 2025-11-25
client asks 2025-06-18 -> server answers 2025-06-18
```

This is what rmcp 3.4.1 does on purpose. Its own comment on
`negotiate_protocol_version` says that `2026-07-28` replaced the handshake with
per-request metadata, so a client naming that revision "is answered with the
server's newest legacy version instead". `ProtocolVersion::LATEST` in the SDK is
still `2025-11-25`, and `2026-07-28` is a known version used on the modern path.

So the transport is current — Streamable HTTP — and the SDK is the official Rust
implementation, which is what the milestone asked for. Setting
`ServerConfig.protocol_version` to `V_2026_07_28` was tried and changed nothing,
because the fallback is computed from the newest *legacy* version the server
supports. It was reverted rather than left in, because it would have made
`serverInfo` advertise a version the handshake does not answer.

A `2026-07-28` client talks to this server over per-request metadata instead of
the legacy handshake; that path is the SDK's, not ours.

## Verification notes

Two things about this cluster that cost time and will again.

**A sandbox with no network cannot resolve anything.** `NetworkPolicy::Disabled`
maps to Docker's `network_mode: none`, so a run that does not ask for network
gets no interface, no resolver, and fails every lookup with "could not resolve
host" - which reads like a broken image. A workload that clones a repository or
installs anything needs `"resources": {"network": {"enabled": true}}`, and the
failure otherwise surfaces as a bare `exit 128` from the setup step.

**The resolvers a sandbox can use come from the worker, not the host.** The
runtime reads `/etc/resolv.conf` as seen by the worker process. On this host
that file lists only `127.0.0.53`, systemd-resolved's loopback stub, which is
filtered because a container cannot use it; the nameservers a sandbox actually
receives (`169.254.1.1`, `192.168.1.1`) come from the worker's own container
configuration. That is why the change is a no-op when read from the host and a
fix when read from the worker.
