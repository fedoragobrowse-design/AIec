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
