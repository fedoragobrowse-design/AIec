# Baseline

Measured, not estimated. Produced by `benchmarks/bench.py` against a live
cluster; re-run it rather than trusting these numbers after a change.

```
python3 benchmarks/bench.py --base-url https://127.0.0.1:18443 \
    --api-key af_live_... --samples 20 --runtime docker --insecure
```

That is the invocation these numbers were taken with, kept as it was run. The
current form of the same measurement - which takes the key from a file rather
than a command line - is in [The harness that produced this](#the-harness-that-produced-this).

## Conditions

- Single control plane and two workers (Firecracker and Docker) on one host.
- `docker` runtime, `python:3.13`, 1 vCPU / 512 MiB.
- Workload: `command: ["true"]`, no repository, no validations, no artifacts.
  This isolates orchestration overhead from real work on purpose.
- 20 samples. **Percentiles are withheld below 20 samples** by the harness,
  because a p99 over ten measurements has no error bar and reporting one as if
  it did is how a benchmark starts lying.

## Result

**13 of 20 reached `succeeded`.** The other 7 returned a well-formed response in
some other state and are excluded from the timing below rather than counted as
fast. The harness reports that split explicitly (`completed`,
`excluded_not_succeeded`) so a median over 13 is never read as a median over 20.

| Phase | Median | Share of run |
|---|---:|---:|
| cleanup (stop the machine, return its capacity) | 12.59 s | 58% |
| placement (schedule, create, start, lease, prepare workspace) | 4.34 s | 20% |
| task (the command itself) | 0.87 s | 4% |
| collection (artifacts, git diff) | 0.00 s | 0% |
| unmeasured control-plane overhead | 3.86 s | 18% |
| **total** | **21.68 s** | |

Each phase is taken per run and the residual is computed per run as
`total − Σ phases`, then summarised. Subtracting two independently-aggregated
medians is not the same number, and the previous version of this file did
exactly that.

## What it says

**A run that does nothing takes 21.7 seconds, and 0.87 of them is the work.**

The dominant cost is now teardown, at 58%. That is a direct consequence of a
correction, not a regression: until `983debf`, cleanup flipped the sandbox row
to `destroyed` and credited the node's capacity back without ever stopping the
machine. It was fast because it was lying, and seventeen containers were left
running while the control plane reported them gone. The old figure of 1.71 s for
"cleanup" was measuring a row update. This one measures `runtime.destroy` on a
real container.

So the previous baseline was not merely stale, it described a system that was
not doing the work. It attributed 45% to placement and 15% to teardown, and
concluded that the lever was warm capacity rather than a faster scheduler. On
the old numbers that reasoning was sound and the subject was wrong.

Placement is still 4.3 s of real cost and is a microVM or container booting, so
nothing in the control plane is the lever there either.

The 18% residual is the part the control plane is actually responsible for:
creating the run row, the state transitions, writing results and placement, and
the HTTP round trip. It is halved from the 32% the old file reported, and the
difference is cleanup instrumentation that did not exist when that number was
taken.

## What is deliberately not done

No optimisation has been applied on the strength of these numbers, for the same
reason as before and with more force: the largest cost is stopping a container,
which is not a control-plane problem. The tempting move is to make teardown
asynchronous so a caller is not billed for it, and that is a product decision
about what `POST /v1/runs` means - it changes the contract from "returns when the
run is finished" to "returns when the run is accepted". Worth doing deliberately,
not as a side effect of a benchmark.

The residual at 18% is the only remaining candidate for control-plane work, and
it needs finer instrumentation before it can be attributed to anything.

## Known measurement traps

Two things make this benchmark silently measure nothing, both encountered while
producing the numbers above:

- **Stranded sandboxes consume tenant quota.** A sandbox left in `running` or
  `starting` whose lease is gone is never reclaimed, and still counts against
  `max_active_sandboxes`. Eight of them exhausted a tenant's quota and every
  submission failed with `tenant resource quota exceeded` while nodes reported
  free capacity. The 7 excluded runs above are very likely this.
- **Silent stderr.** A syntax error in this harness produced an empty JSON
  document and a clean-looking failure rather than an error. `bench.py` output
  being empty is a bug, not a result.

## Reproducing

Percentiles appear only at 20+ successful samples:

```
python3 benchmarks/bench.py --base-url ... --samples 40 --runtime docker
```

`--insecure` exists because Python's TLS is stricter than curl's about a
self-signed CA with no keyUsage extension. It prints a warning, is never the
default, and has no place against a real deployment.

## The harness that produced this

The measurements above were taken by hand against a live cluster. They are left
exactly as they were recorded, because a baseline that has been edited is not a
baseline. What has changed since is that the same measurement is now
repeatable: [`bench.py`](README.md) is a documented harness with one module per
question, and the run it produces is a JSON report rather than a table somebody
assembled.

The historical command still works and still measures the same thing - with no
scenario named, the harness runs `control-plane` and then `empty-exec`:

```
python3 benchmarks/bench.py --base-url https://127.0.0.1:18443 \
    --api-key-file /run/secrets/aiec-key --ca /etc/aiec/ca.pem \
    --samples 20 --runtime docker --image python:3.13
```

What the current harness reports that the run above could not:

- **Per-run lifecycle gaps from the run's own timestamps** - admission, queue
  wait, start latency and wall time - rather than only the total.
- **`aiec_api_requests_total` per run**, labelled as an HTTP request count. The
  number of *database* queries a run issues is not observable through the API
  and is reported as unavailable rather than inferred from it.
- **Observations at the start and the end of the invocation**: the sandbox
  census, free vCPUs, queued runs, the harness host, the local Docker daemon,
  and - when `AIEC_BENCH_DATABASE_URL` is set - PostgreSQL connections and run
  rows. Every one of those is `{"available": false, "reason": ...}` when the
  door is shut, and never `0`.
- **A `--compare` mode** that prints a delta against an earlier report only when
  the two share a conditions fingerprint, and otherwise names the condition
  that differs and prints nothing.

No arithmetic correction applies to the table above. An earlier draft of this
document claimed that `results.phase_ms` also carries `attempts` as a *count*,
and that summing the map as milliseconds added the attempt count to every
run's measured time. That is not true of this control plane: every entry
`crates/aiec-api/src/runs.rs` writes there is a duration
(`placement`, `placement.*`, `setup`, `task`, `validation`, `collection`,
`cleanup`), and no code in the workspace writes an `attempts` key. The
harness still keeps a count-valued key out of the time sums
(`harness.COUNT_PHASE_KEYS`) and reports it under `count_attempts` if one
ever appears, but that path is defensive: today it excludes nothing and the
residual in the table is unchanged.

The scenarios added since this baseline was taken - repeated runs against a
pinned repository commit, the bounded leak soak, snapshot and workspace
restore, and the OMP before/after through the local MCP server - are
documented in [`README.md`](README.md), and the soak results are in
[`SOAK.md`](SOAK.md).

## Measured baseline — 2026-09-30, live cluster

Taken with `benchmarks/bench.py` against the deployed control plane, 25
samples per scenario. Percentiles are withheld below 20 samples by the
harness, which is why the first attempt at 10 samples reported none.

```bash
python3 benchmarks/bench.py control-plane empty-exec \
    --base-url https://127.0.0.1:18443 --ca <ca> \
    --api-key-file <file> --samples 25 --out bench-baseline25.json
```

### Control-plane reads (n=25)

| endpoint | p50 | p95 | mean |
|---|---|---|---|
| health | 2.7 ms | 3.3 ms | 2.7 ms |
| ready | 161.6 ms | 169.6 ms | 157.3 ms |
| list_queued_runs | 315.8 ms | 329.7 ms | 314.7 ms |
| usage | 317.2 ms | 402.0 ms | 323.4 ms |
| current_account | 324.7 ms | 406.2 ms | 337.4 ms |
| list_runs | 395.3 ms | 485.2 ms | 406.9 ms |
| list_sandboxes | 557.2 ms | 592.7 ms | 551.6 ms |

### Empty-exec run (n=22 of 25 succeeded)

| phase | p50 | p95 |
|---|---|---|
| run_total | 25.50 s | 28.11 s |
| wall_time | 23.77 s | 25.78 s |
| **phase_cleanup** | **13.35 s** | **14.23 s** |
| queue_wait | 8.22 s | 9.99 s |
| phase_placement | 5.10 s | 6.55 s |
| phase_task | 0.87 s | 0.97 s |
| phase_collection | 0.0 s | 0.0 s |
| admission | 0.0 s | 0.0 s |

### What this says

**Cleanup is the largest reported phase.** Its p50 is 13.35 s, compared with
23.77 s wall time and 0.87 s task time. Ratios of independent medians are not
per-run proportions; trace the teardown path before assigning its cause.

**Queue wait is 8.22 s p50.** These timings do not distinguish dispatcher
cadence, admission, capacity contention, or lease round trips.

**Three of 25 runs failed** with `stale sandbox lease generation`. A journal
query returned zero worker floor warnings in the queried window, but this
alone does not prove which producer returned the error. Both the storage
state-transition fence and worker authorization can emit this message.
Storage-fence attribution remains a hypothesis pending causal diagnostics.

### Scenario coverage of this baseline

| scenario | ran? | note |
|---|---|---|
| control-plane | yes | 25 samples |
| empty-exec | yes | 25 samples, 22 succeeded |
| matrix | not run | missing `--repo`; no matrix submission was attempted |
| snapshot | attempted separately | earlier create refusals; later restore failed with `500 backend io: No such file or directory` |
| soak | attempted separately | 20 sequential iterations, 18 succeeded and 2 failed with stale-generation errors |
| repo | not run | requires repository access; egress diagnosis open |
| omp | not run | requires repository access; egress diagnosis open |

The later `matrix snapshot soak` invocation had fingerprint
`4283960eec2cb341`, not the baseline fingerprint. Its repetitions subscenario
completed one successful Run. Snapshot completed one capture before restore
failed; it left a new `restoring` sandbox and scheduler capacity one vCPU below
the initial census. The raw artifact must retain this leak evidence.
These outcomes are not proof of a shared fencing cause.

The control-plane/empty-exec artifact is
[`baseline-2026-09-30.json`](baseline-2026-09-30.json), conditions fingerprint
`602f511b90348c50`. Use matching workload conditions for a later `--compare`;
do not compare different scenario sets as though they share a fingerprint.
