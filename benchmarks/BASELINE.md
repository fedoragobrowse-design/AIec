# Baseline

Measured, not estimated. Produced by `benchmarks/bench.py` against a live
cluster; re-run it rather than trusting these numbers after a change.

```
python3 benchmarks/bench.py --base-url https://127.0.0.1:18443 \
    --api-key af_live_... --samples 10 --runtime docker
```

## Conditions

- Single control plane and two workers (Firecracker and Docker) on one host.
- `docker` runtime, `python:3.13`, 1 vCPU / 512 MiB.
- Workload: `command: ["true"]`, no repository, no validations, no artifacts.
  This isolates orchestration overhead from real work on purpose.
- 10 samples. **Percentiles are withheld below 20 samples** by the harness,
  because a p99 over ten measurements has no error bar and reporting one as if
  it did is how a benchmark starts lying.

## Result

Runs: 8 of 10 reached `succeeded`; 2 settled in another state and are excluded
from the timing below rather than counted as fast.

| Phase | Median | Share of run |
|---|---:|---:|
| placement (schedule, create, start, lease, prepare workspace) | 5.18 s | 45% |
| cleanup (destroy the machine) | 1.71 s | 15% |
| task (the command itself) | 0.87 s | 8% |
| unmeasured control-plane overhead | ~3.7 s | 32% |
| **total** | **11.46 s** | |

Run total: median 11.46 s, mean 11.93 s, min ~9.8 s, max ~13.9 s.

## What it says

**A run that does nothing takes 11.5 seconds, and 0.87 of them is the work.**
That is the headline, and it is a property of the platform rather than of this
workload.

Placement dominates at 45%, and it is a microVM booting. Nothing in the control
plane is doing anything expensive there; the cost is the machine starting, and
the lever is warm capacity or a faster image, not a faster scheduler.

The 32% that no phase accounts for is worth naming precisely, because it is the
only part the control plane is actually responsible for: creating the run row,
the state transitions around it, writing results and placement, and the HTTP
round trip. It is the part to instrument next, and it is the part a caller
actually waits on when submitting a batch.

Cleanup at 15% is podman tearing a container down. It is real cost and it is
already accounted for rather than hidden, which is the only reason it is visible.

## What is deliberately not done

No optimisation has been applied on the strength of these numbers. The largest
cost is sandbox boot, which is not a control-plane problem, and the remainder
needs finer instrumentation before it can be attributed. Optimising the scheduler
because "placement is slow" would be optimising the wrong thing.

## Reproducing

Percentiles appear only at 20+ samples:

```
python3 benchmarks/bench.py --base-url ... --samples 40 --runtime docker
```

`--insecure` exists because Python's TLS is stricter than curl's about a
self-signed CA with no keyUsage extension. It prints a warning, is never the
default, and has no place against a real deployment.
