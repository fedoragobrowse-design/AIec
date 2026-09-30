# Baseline

Measured, not estimated. Produced by `benchmarks/bench.py` against a live
cluster; re-run it rather than trusting these numbers after a change.

```
python3 benchmarks/bench.py --base-url https://127.0.0.1:18443 \
    --api-key af_live_... --samples 20 --runtime docker --insecure
```

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
