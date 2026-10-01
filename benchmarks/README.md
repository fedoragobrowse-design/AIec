# Benchmark harness

`bench.py` measures a live AIec control plane. It exists because the performance
milestone says to optimise from measurements, and because the two results
documents next to this file - [`BASELINE.md`](BASELINE.md) and
[`SOAK.md`](SOAK.md) - were produced by hand and are therefore hard to repeat.

The results written during the final measurement round are
[`AFTER2.md`](AFTER2.md) (matched before/after deltas, soaks, the repository
cache OFF/ON comparison, and the artifact collection cost), and
[`ORCHESTRATION.md`](ORCHESTRATION.md) (what the platform was verified to do,
with the file each claim came from). [`EFFICIENCY-AUDIT.md`](EFFICIENCY-AUDIT.md)
records the cost model and its verdict.

Everything here drives the real thing: the real HTTPS API, the real workers, and
for the agent comparison the real local MCP server. Nothing is stubbed, and no
scenario runs a command anywhere except inside a sandbox.

```
python3 benchmarks/bench.py --help
```

## Requirements

* CPython 3.10 or newer. No third-party packages: the harness is stdlib only, so
  it runs on a jump host next to a deployment without a virtualenv.
* A reachable control plane and an API key that may start sandboxes.
* For the `omp` scenario only: a built `aiec-mcp` listening on loopback, with its
  token in `AIEC_MCP_TOKEN` or `~/.config/aiec/mcp-token`.

## Credentials and TLS

The API key comes from `--api-key-file`, the `AIEC_API_KEY` environment
variable, or an interactive prompt - in that order of preference, with the
prompt last. `--api-key` still works and warns, because a credential on a
command line is in every process listing on the host.

For a control plane behind a private CA, pass `--ca /path/to/ca.pem`. TLS
verification is on by default and there is no flag to turn it off quietly:
`--insecure` prints a warning to stderr and exists for throwaway test clusters
whose self-signed CA lacks a `keyUsage` extension, which Python's TLS rejects and
curl's accepts.

The key never appears in the report. The report records only *where it came
from* (`"credential_source": "env:AIEC_API_KEY"`), and every message the harness
prints is scrubbed of it first.

## Scenarios

| Scenario | What it measures | Needs |
|---|---|---|
| `control-plane` | Request latency for the read endpoints, so a change in run latency can be attributed to the control plane or to the machines | nothing |
| `empty-exec` | End-to-end run cost and the per-phase breakdown, for a run whose command is `true` | nothing |
| `repo` | Repeated runs against one pinned repository commit: clone cost, cold versus warm, and the commit each run actually got | `--repo` |
| `matrix` | The server-side evaluation path: one workload on N fresh machines, and a matrix over a pinned commit, both under `max_parallel` | nothing (`--repo` enables the matrix half) |
| `soak` | A bounded loop of real runs, with the sandbox census sampled throughout, answering "does it return to baseline" | nothing |
| `snapshot` | create→running, first exec, snapshot, destroy, workspace restore - with a marker file proving the restore restored something | nothing |
| `omp` | Baseline versus candidate OMP revision, through the local MCP server, with a comparability check | `--omp-repo --baseline-ref --candidate-ref --target-repo --task` |

With no scenario named, the harness runs `control-plane empty-exec` - the
historical default, and the shape [`BASELINE.md`](BASELINE.md) quotes. `all`
runs everything.

## What a report contains

JSON on stdout, always, whether the run worked or not; a short readable summary
on stderr. An empty document is a bug in a benchmark rather than a result, so
even an unreachable control plane produces a report that says why.

* **`conditions` and `conditions_fingerprint`** - everything that has to match
  before two reports may be compared, and a digest of it.
* **`scenarios.<name>`** - per-metric summaries, the success/failure split, the
  failure-reason histogram, and every phase the run recorded.
* **`observations`** - a timestamped pass at the start and the end of the
  invocation, plus one at every soak checkpoint.
* **`leak_accounting`** - the sandbox census before and after, the sandboxes that
  are new and still non-terminal at the end, and any run that reported a cleanup
  failure.
* **`harness_cleanup`** - what this harness created and destroyed, and what it
  could not.
* **`limitations`** - what this particular run knows it did not measure.

### Statistics

Medians, means, min and max are always reported. `p50`, `p95` and `p99` appear
only at twenty or more samples, and below that the report says
`percentiles_withheld` and why. A p99 over six samples has no error bar, and
printing it as if it did is how a benchmark starts lying.

Two arithmetic rules the harness will not bend:

* **Successes and failures are never averaged together.** A run that did not
  succeed has phases describing a different population from its total, so it is
  counted separately, with its reason, and excluded from the timing column.
* **Residuals are computed per run, then summarised.** The unattributed time is
  `total − Σ phases` for each run and then a median over those differences.
  Subtracting two independently aggregated medians is a different number.

Every entry `results.phase_ms` carries today is a duration. The harness still
excludes a count-valued key (`harness.COUNT_PHASE_KEYS`) from every time sum and
would report it under `count_attempts`, because adding a count in milliseconds
to each run's time is a small error nobody would notice - but no code in this
workspace writes such a key, so today that exclusion removes nothing.

### Observations, and what stays unavailable

| Observation | Source | When it is unavailable |
|---|---|---|
| Sandbox census by state | `GET /v1/sandboxes` | the call fails or the key cannot read sandboxes |
| Free vCPUs and memory, request counter | `GET /metrics` | the deployment exposes no `aiec_node_*` gauges |
| Queued runs | `GET /v1/runs?state=queued` | capped at one page, so a deep queue is "at least N" |
| Tenant usage counters | `GET /v1/usage` | the key cannot read usage |
| Harness host load, memory, free disk | `/proc`, `statvfs` | not Linux |
| Running containers | `docker ps` on the harness host | no local Docker daemon - which is most deployments, and is why it is never reported as zero |
| PostgreSQL connections and run rows | `psql` against `AIEC_BENCH_DATABASE_URL` | not configured, or `psql` is not installed |

Anything unavailable is `{"available": false, "reason": "..."}`. It is never
`0`: zero is a number somebody will optimise against, and a missing metric must
never become a claim. Two things are worth stating plainly because no door
currently opens onto them:

* **Database queries per run are not observable.** The API exposes an HTTP
  request counter, which is what `api_request_accounting` reports and labels as
  such. Counting queries needs `pg_stat_statements` on the database.
* **Worker host CPU, memory and disk are not observable from here.** The
  scheduler's `available_*` columns are arithmetic over requested sizes, not
  measurements of a machine - which is itself one of the findings in
  [`EFFICIENCY-AUDIT.md`](EFFICIENCY-AUDIT.md). The host numbers the harness
  does report are labelled as the *harness* host.

## Bounds

A benchmark that takes the cluster down has measured the cluster falling over,
so the bounds are refused rather than attempted:

* `--max-parallel` above 64 is refused, matching `scripts/load-soak-test.sh`.
* `--rps` (default 5) paces the client below the control plane's default
  sustained limit of 20 rps, and every 429 the limiter returns is counted in
  `rate_limit_429s`. A latency sample that included back-off would not be a
  latency sample.
* `--max-duration` stops a soak on a wall clock, and the report says it stopped
  early and why, rather than quietly running fewer iterations.
* `--omp-parallel` is capped at 16, which is the local MCP server's own cap, and
  the harness says so when a larger value will be clamped. `--matrix-parallel`
  is the `max_parallel` the evaluation routes are asked for, and is bounded the
  same way: a matrix asking for more machines than the cluster can serve
  measures the queue.

## Leaks

The ordering is the whole point:

1. measure,
2. observe the sandbox census,
3. *then* destroy what this harness created.

Machines the **platform** leaked are listed in
`leak_accounting.sandbox_census_delta.new_nonterminal_sandbox_ids` and in
`leak_accounting.run_cleanup_failures`, and are not destroyed. That is the
evidence, and a benchmark that quietly collects its own evidence is not measuring
the thing that matters. `--reclaim-leaked` destroys them *after* reporting them,
for when the quota needs clearing and the result has already been read.

Only sandboxes this harness created through the sandbox API are ever destroyed
automatically. Every one it failed to destroy is in `harness_cleanup.failed`,
with the status and code, and the run records a limitation saying they are still
running.

## Before and after

```
python3 benchmarks/bench.py --label before --samples 40 --out before.json
# ...the change...
python3 benchmarks/bench.py --label after  --samples 40 --out after.json --compare before.json
```

The comparison is refused unless the two reports share a conditions
fingerprint: same scenarios, image, requested runtime, resources, command,
setup, validations, artifacts, workload timeout, repository URL *and reference*,
soak shape, snapshot kind, and - for the OMP comparison - the same repository,
target, task and repetitions. When they differ, the report names the differing
condition and prints no delta, because a number computed across two different
workloads describes neither run.

Sample count is deliberately *not* part of the fingerprint: changing how many
samples were taken changes precision, not what was measured. The comparison
still prints both sample counts next to every delta, and the success counts of
both runs, so a "20% faster" next to a drop in successful runs is visible as
what it is.

The `omp` scenario does its own before/after - baseline revision against
candidate revision - and additionally verifies comparability from the run
evidence before printing anything:

* both sides ran the requested number of repetitions;
* both sides ran on the same runtime;
* every run recorded the same target commit, and the harness confirms the target
  commit rather than trusting the request;
* each side actually checked out the revision that was asked for;
* every run on both sides produced an agent outcome;
* no run was lost to a submission failure, and no run leaked its machine.

If any check fails the report says `comparable: false`, lists the failures, and
prints no delta. It never names a winner: the judgement belongs to whoever asked
the question.

## Exact invocations

```bash
# the historical baseline: control-plane reads, then runs that do nothing
python3 benchmarks/bench.py --base-url https://127.0.0.1:18443 \
    --api-key-file /run/secrets/aiec-key --ca /etc/aiec/ca.pem \
    --samples 20 --runtime docker --image python:3.13

# a real repository at a pinned commit, five times
python3 benchmarks/bench.py repo --repo https://github.com/can1357/oh-my-pi \
    --ref 7f3c1e9d0b2a4c5d6e8f90a1b2c3d4e5f60718293 \
    --command "bun install && bun run build" \
    --validation "bun test" --samples 5

# the server-side evaluation path: repetitions and a matrix, bounded
python3 benchmarks/bench.py matrix --repetitions 4 --matrix-parallel 2 \
    --repo https://github.com/can1357/oh-my-pi --ref 7f3c1e9d0b2a4c5d6e8f90a1b2c3d4e5f60718293

# sequential leak watch
python3 benchmarks/bench.py soak --iterations 40 --max-parallel 1 \
    --checkpoint-every 5 --max-duration 1800

# the same loop with bounded concurrency
python3 benchmarks/bench.py soak --iterations 40 --max-parallel 4 \
    --checkpoint-every 5

# snapshot and workspace restore
python3 benchmarks/bench.py snapshot --samples 5 --snapshot-kind workspace

# the OMP before/after, through the local MCP server
python3 benchmarks/bench.py omp \
    --omp-repo https://github.com/can1357/oh-my-pi \
    --baseline-ref v18.3.5 --candidate-ref v18.4.0 \
    --target-repo https://github.com/octocat/Hello-World \
    --task "Add a regression test that covers truncated command output." \
    --repetitions 3 --omp-parallel 2

# everything, with the PostgreSQL observations switched on
AIEC_BENCH_DATABASE_URL='postgresql://aiec@db/aiec' \
python3 benchmarks/bench.py all --api-key-file key.txt --samples 20 \
    --max-parallel 4 --out full.json
```

The PostgreSQL URL is read from the environment and handed to `psql` through
`PGDATABASE`, which libpq accepts as a connection string. The password is never
a command-line argument and never appears in the report; `psql` error text is
scrubbed before it is stored.

## The OMP suite

`evaluations/omp-regression.json` is a reviewable OMP comparison spec. The
harness does not read that file - the OMP comparison is driven through the MCP
tool, which takes the same fields - but the file is where the task, the target
repository and the two revisions are already written down, so it is the natural
starting point for `--task`, `--target-repo` and the two refs.

## Files

```
bench.py                     the entry point
aiecbench/client.py          one authenticated HTTP client, with timing and TLS
aiecbench/stats.py           summaries, and the rule about small samples
aiecbench/harness.py         shared state, ownership, cleanup, run arithmetic
aiecbench/observe.py         the sandbox census, capacity, host, Docker, PostgreSQL
aiecbench/mcp.py             a minimal MCP client for the OMP comparison
aiecbench/report.py          report assembly, the human summary, before/after
aiecbench/cli.py             arguments, bounds, and the report lifecycle
aiecbench/scenarios/
    control_plane.py         read-only endpoint latency
    empty_exec.py            end-to-end run cost and per-phase breakdown
    repo.py                  repeated runs against one pinned commit
    matrix.py                /v1/eval/repetitions and /v1/eval/matrix, bounded
    soak.py                  the bounded loop, with checkpoints
    snapshot.py              snapshot and workspace restore, with a marker
    omp.py                   baseline versus candidate, and the comparability check
```
