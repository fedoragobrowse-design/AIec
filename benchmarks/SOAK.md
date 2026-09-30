# Soak results

Two sequential soaks of the same workload against the same host: create, exec,
destroy, repeated. 1 vCPU / 256 MiB / 512 MiB, `python:3.13`, docker runtime.
The only difference between them is code.

This exists because the specification asks for a bounded soak and because a
hundred-run loop is what found the worst leak in the system. Everything below is
measured, not estimated.

## Before and after

| | Soak 1 | Soak 2 |
|---|---:|---:|
| runs | 80 | 45 |
| succeeded | 24 | 38 |
| success rate | 30% | 84% |
| sandboxes still held at the end | 7 | **0** |
| free vCPUs at the end (of 18) | 11 | **18** |
| containers still running at the end | 3 | **0** |

Soak 1 did not merely fail more; it **degraded**. Twenty runs succeeded and then
every run after that failed, because each failed placement left a sandbox stuck
in `creating` or `starting` holding a lease and a slot. Nothing reclaims those -
the sweeper deliberately leaves rows with a live lease alone - so the tenant was
slowly locked out of its own cluster until it refused all work on quota while the
nodes still reported free capacity.

Soak 2 tracks its own progress, which is the more useful form:

```
baseline: containers=0 vcpus=18 nonterminal=0
  15: succeeded=14 failed=1  nonterminal=0 vcpus=18
  30: succeeded=27 failed=3  nonterminal=0 vcpus=18
  45: succeeded=38 failed=7  nonterminal=0 vcpus=18
```

Every checkpoint is the baseline. That is the property the first soak lacked
entirely, and it is worth more than the success rate: a platform that leaks one
slot per failed placement is unusable at any size, and one that returns to
baseline under load can be trusted to keep going.

## What changed

`provision_sandbox` released its lease on exactly one failure path - the
environment preparation step. A `create` that failed left a `Failed` row still
holding its lease; a `start` that failed left the row in `Starting` holding the
lease and the node's debited capacity, with no cleanup at all. All provisioning
now runs as one block whose single failure path stops the machine, marks the
row, and hands the lease back.

Same class of defect as the run-cleanup leak found earlier the same day, reached
through placement instead of teardown. Both were invisible to unit tests and to a
single run, and both were obvious within twenty iterations of a loop.

## What is still failing

Seven of forty-five, and they no longer accumulate:

- `stale sandbox lease generation` - a lease expires between scheduling and the
  first state commit. Now retried for free, because nothing has run yet when it
  happens.
- transient `quota exceeded` - sandboxes accumulate faster than they clear while
  the cluster is saturated, briefly reaching the tenant's limit and then
  recovering.

Neither leaks. Both are worth understanding before the system is given more load
than eight slots, and neither is a correctness failure: a caller that sees either
can resubmit and will not be charged for work that did not happen.

## Parallel soak

Five batches of eight concurrent runs, forty in total, sampling live state after
each batch:

```
baseline: containers=0 vcpus=18 nonterminal=0
  batch 1: submitted= 8 succeeded= 6 containers=0 vcpus=17 nonterminal=0
  batch 2: submitted=16 succeeded=13 containers=0 vcpus=16 nonterminal=1
  batch 3: submitted=24 succeeded=19 containers=0 vcpus=16 nonterminal=1
  batch 4: submitted=32 succeeded=25 containers=0 vcpus=16 nonterminal=1
  batch 5: submitted=40 succeeded=31 containers=0 vcpus=16 nonterminal=1
FINAL: containers=0 vcpus=16 nonterminal=1
```

**The property that matters held under concurrency**: no running containers at
any sample, and non-terminal sandboxes flat at one from batch two onward rather
than climbing. The sequential soak's failure mode was accumulation, and eight
simultaneous placements did not produce it - which is the evidence that the
provisioning fix is about the leak and not about load level.

**Two things did not return to baseline**, and saying otherwise would be the
easy lie:

- vCPUs settled at 16 of 18, not 18.
- One non-terminal sandbox remained.

Both stopped moving after batch two and held flat for the remaining three
batches, so this is a steady-state residue rather than a leak - but it is a
residue, and 2 vCPUs and one sandbox are still held by something. The sequential
soak returned to exactly zero, so whatever holds these is specific to concurrent
placement and has not been identified. It is worth two vCPUs of a small cluster
now and considerably more on a real one.

Nine of forty failed. The failure classes are the same two as the sequential
soak - placement lease races and transient capacity refusals - and neither
accumulates.

## Not done
- **The remaining audit findings** are in `docs/known-defects.md`. The three
  fixed in this pass - the sweeper's unbounded reclaim loop, the uncapped retry
  loop, and the unguarded terminal-state write - are listed there with their
  commits.
- **Before/after for the individual optimisations** is not reported, because no
  performance optimisation was applied. What is measured here is a correctness
  fix whose effect on throughput is a side effect of not leaking.
