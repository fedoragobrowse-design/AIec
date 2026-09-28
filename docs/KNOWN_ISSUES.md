# Known open defects

Real problems found while running the MCP server against a live cluster. Each
one is reproducible; none is worked around silently in the code.

---

## `aiec_compare_omp` drops the per-run output

**Status:** open. **Severity:** reporting, not correctness — the comparison still
runs both sides correctly and cleans up.

`aiec_compare_omp` returns `last_output: ""` for every side, even when the run
succeeded and the same command's output is captured by `aiec_test_omp`.

### Repro

The same `omp_command` and the same `validation_commands`, against the same
revisions, on the same cluster:

```
aiec_test_omp     -> omp.stdout == "PROBE_MARKER\n"    validations == ["CHECKOUT_PRESENT\n"]
aiec_compare_omp  -> last_output == ""                  validation_passes == 1
```

Both are called with `omp_command: ["echo", "PROBE_MARKER"]`.

### What has been ruled out

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

### Where to look

`SideSummary::from_runs` in `crates/aiec-mcp/src/eval.rs` reads `run.omp.stdout`
and `run.omp.stderr`, and the value is empty for runs produced by
`compare_omp` while the same field is populated for runs produced by
`aiec_test_omp`. Since both call `run_omp_once`, the loss is either in how
`compare_omp` collects the results of `join_all` into `baseline_runs` /
`candidate_runs`, or in a move of `run.omp` before aggregation. Adding a
`tracing::debug!` of the raw per-run stdout inside `from_runs` would settle it in
one run.

### Why it matters

A comparison is only checkable if you can see what each side actually did. Two
sides reporting identical numbers mean nothing without the evidence, so this is
the first thing to fix before trusting a comparison result.

---

## A worker's `available_*` does not follow a capacity change

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

---

## The `initialize` handshake never answers `2026-07-28`

**Status:** SDK behaviour, not a defect. Recorded so nobody re-investigates it.

A client that asks for `2026-07-28` on `initialize` is answered
`2025-11-25`:

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

---

## A destroyed sandbox could be reported as destroyed when it was not

**Status:** fixed. Found by auditing the acceptance matrix, kept here because
the shape of the bug is worth remembering.

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
