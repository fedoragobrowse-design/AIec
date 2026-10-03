# AIec

**AI elastic compute — isolated, disposable computers for autonomous agents.**

AIec gives an AI agent an isolated computer to clone a repository, run code,
edit files, run tests and collect the diff. Firecracker provides the guest
kernel; Guard governs network access and model credentials outside the guest.
You run the control plane, workers, PostgreSQL and object storage yourself.

```python
from agentforge import AIec

af = AIec(base_url="https://your-control-plane.example", api_key="af_live_...")

box = af.sandboxes.create(image="aiec-coding:latest")
result = box.exec(["python", "-c", "print('hello from AIec')"])
print(result["stdout"])
box.destroy()
```

No SSH. No database access. No worker access. No manual repair.

---

## Why this exists

Agent workloads are not like ordinary software. An agent writes code nobody has
reviewed, runs it thousands of times, needs strong isolation from the host and
from every other tenant, and needs the machine gone the moment it is finished.

That shape is described in detail in the paper this project is built on:

> **DeepSeek Elastic Compute (DSec): A Sandbox Infrastructure for Effective
> Agentic Training at Scale.**
> Jialiang Huang, Hongxuan Tang, Jingchang Chen, Yuxuan Liu, Yixiao Chen, Yuan
> Cheng, Yi Tao, … Mingxing Zhang, Liyue Zhang, Panpan Huang, Wenfeng Liang.
> DeepSeek-AI & Tsinghua University, 2026. arXiv:2609.22978.

DSec argues that agentic training needs *elastic execution* rather than a single
sandbox runtime: sandboxes arrive in bursts, span heterogeneous isolation
requirements, and carry state across long interactions. AIec implements the
architectural ideas that matter for a production deployment of that shape:

| From the paper | In AIec |
|---|---|
| Unified runtime contract across isolation levels | One `SandboxRuntime` trait; Firecracker, hosted, and Docker behind it |
| Heterogeneous, capability-aware placement | The scheduler matches a worker's advertised capabilities before placing |
| Sandboxes in large bursts | Bounded admission: quotas, rate limits, and a global execution budget |
| Fenced, recoverable sandbox ownership | Monotonic lease generations; a superseded owner is rejected |
| State that survives a lost worker | Workspace archives in shared object storage, restored on the new owner |

The full discussion of where AIec follows the paper and where it deliberately
diverges is in [`docs/DESIGN.md`](docs/DESIGN.md).

---

## How it runs

AIec is open source and self-hosted. There is no hosted version and no hosted
API: the control plane, the workers and the sandboxes run on hardware you
choose.

| | |
|---|---|
| Who runs it | You do |
| Cost | Free, Apache 2.0 |
| Compute | Your own KVM hosts |
| Database | Your own PostgreSQL |
| Object storage | Your own S3 or MinIO |
| Operations | You own upgrades, backups and monitoring |

Usage is still metered against your own tenants and exported, so you can see
what the cluster is doing and what it would cost elsewhere — nobody bills you
for it.

A hosted AIec may be offered later. It would be optional, would not change a
line of your code, and would not change the licence. Nothing here depends on it.

→ [github.com/fedoragobrowse-design/AIec](https://github.com/fedoragobrowse-design/AIec) ·
[aiec.gobrowse.dev](https://aiec.gobrowse.dev)

---

## Security model

Public workloads run under **Firecracker** microVMs. A tenant cannot select a
weaker runtime; the Cloud control plane refuses container runtimes for untrusted
workloads, and Docker remains available for trusted self-hosted deployments and
local development.

Each sandbox gets its own guest kernel, its own root filesystem, and its own
network namespace whose egress policy blocks the host LAN, RFC1918 ranges,
link-local and cloud metadata addresses, the control plane, and other tenants.
The guest control channel is a vsock socket that never touches the network, and
guest paths are confined to the sandbox workspace.

**Guard** adds out-of-guest governance on top of that. Policy, the network
gateway, credentials and the evidence journal all live outside the machine, so a
compromised guest cannot widen its own permissions or rewrite its own record. A
guarded sandbox reaches exactly one path - its own gateway - and model traffic
carries a `placeholder://<binding>` that the gateway swaps for a real credential
the guest never holds. No policy selected means no network.

Around that:

| | |
|---|---|
| **No egress without a witness** | A guarded attachment carries no network at all until an out-of-guest watchdog reports an observation it has verified. Stop reporting and the network is cut and stays cut. |
| **Quarantine, not just refusal** | Repeated denials quarantine a machine: network cut, pause, forensic capture that never resumes it, durable quarantine state, an incident report and a notification. Repeating it returns the same incident. |
| **Budgets a restart cannot reset** | Lifetime and model request and byte ceilings are control-plane state, reserved before a byte is forwarded. |
| **Agent authority, not only destinations** | Where Guard can see a request it governs MCP method and tool names, GraphQL operations and root fields, and HTTP method and path. Anything unnamed is denied. |
| **Propose, never approve** | An agent can ask for a policy change. Only a human can approve one, the verifier runs first, and only a separate human capability releases a held machine. |

```bash
aiec guard show <sandbox>         # policy hash, attachment, budgets, incident
aiec guard events <sandbox>       # verified journal entries
aiec guard quarantine <sandbox>   # operator-initiated
aiec guard release <sandbox>      # human release of a held machine
aiec guard proposals <sandbox>    # pending and decided policy proposals
aiec guard verify policy.yaml     # compile and verify, apply nothing
```

The watchdog is a separate process, deliberately: it runs where the guest cannot
reach it, and it can ask for a quarantine but never approve a policy or release
one.

Guard's relationship to OpenShell's policy schema, and the fields it refuses
rather than approximates, is in
[`docs/openshell-compatibility.md`](docs/openshell-compatibility.md). The
policy format is [`docs/GUARD_POLICY.md`](docs/GUARD_POLICY.md), operating it is
[`docs/GUARD.md`](docs/GUARD.md), and what it does and does not defend is
[`docs/GUARD_THREAT_MODEL.md`](docs/GUARD_THREAT_MODEL.md).

The four built-in policy templates are `no_network`, `model_only`,
`model_plus_allowlist` and `read_only_api`. An optional watcher can request
restrictive actions but cannot approve a proposal, loosen policy or release a
quarantine. Signed-image admission checks kernel and rootfs digests; per-VM
control identities and canaries add checks outside the guest.

Details, including the limits we have not solved: [`SECURITY.md`](SECURITY.md).

## Verified behavior and remaining limits

The [Guard report](docs/guard-report.md) separates implementation, regression
tests and live acceptance evidence. The published runs use real Firecracker
guests, isolated state and local mock model providers—not a claim about every
deployment or external model service.

| Live acceptance | Published result |
|---|---|
| Core network, DNS and credential boundary | [48/48](benchmarks/guard-core-acceptance.json) |
| Watchdog, dead-man switch and quarantine | [29/29](benchmarks/guard-phase2-acceptance.json) |
| MCP/GraphQL rules and policy proposals | [47/47](benchmarks/guard-phase3-acceptance.json) |
| Optional restrictive watcher | [51/51](benchmarks/guard-phase4-acceptance.json) |
| Canaries, image trust and per-VM identity | [37/37, full suite](benchmarks/guard-phase5-acceptance.json) |
| Durable lifetime reaper | [16/16](benchmarks/guard-reaper-acceptance.json), [16/16 through the external-database relay](benchmarks/guard-reaper-external-db-acceptance.json) |
| Workspace snapshot, destroy and restore through real S3 storage | [12/12](benchmarks/snapshot-acceptance.json) |

These results are not a blanket production certification. Multi-host security
and aarch64 runtime/performance remain unvalidated; aarch64 has build evidence.
The dated parallel soak remains **77/80**, with three unattributed capacity
refusals and no accumulated resources; it has not been rerun after the scheduler
fix. A CONNECT tunnel requiring Layer 7 visibility is refused rather than
forwarded ungoverned. Arbitrary in-guest `exec` file reads are not observable
through trusted host file APIs.

SDK `run_cells` chunking and per-Run pagination for events, attempts and artifacts
remain unimplemented. See the report for measurement scope, exact acceptance
commands, and deployment steps.

---

## Quickstart

```bash
pip install agentforge-sdk
```

Create a key against your own control plane (`aiec key create`), then:

```python
from agentforge import AIec

af = AIec(base_url="https://127.0.0.1:8080", api_key="af_live_...")
box = af.sandboxes.create(image="aiec-coding:latest")
print(box.exec(["git", "--version"])["stdout"])
box.destroy()
```

There is no account to sign up for and no key to request from anyone.

Set `base_url` to your deployed endpoint, or use `AIEC_URL`. The SDK's fallback
is `http://127.0.0.1:8080` for a local control plane, not a hosted service.

Available images: `aiec-coding:latest` (the default, with `git`, Python and a
build toolchain), `python:3.13`, `node:24`, `rust:stable`, `ubuntu:24.04` and
`alpine:3.21`.

For work that is a self-contained task rather than an interactive session, ask
for a **run**: the control plane places a machine, runs the command, collects
the artifacts and reclaims the machine, and hands back the settled record.

```python
run = af.runs.create(
    repo="https://github.com/me/fixture",
    command="pytest -q",
    validations=[["pytest", "-q"]],
    artifacts=["report.txt"],
    requirements={"full_kernel_isolation": True},
)
print(run["state"], run["results"]["task"]["exit_code"])
```

`af.runs.list()`, `.get()`, `.events()`, `.artifacts()` and `.cancel()` read and
stop runs; `run_batch`, `run_repetitions` and `run_matrix` fan a workload out
with bounded concurrency (`max_parallel`, default 2).

`af.evals` is the same machinery in bulk, and it runs in the control plane
rather than in your process: `af.evals.batch(...)`, `.repetitions(...)` and
`.matrix(...)` post one bounded request and answer with the runs.
`af.evals.run_suite(...)` and `.compare(...)` take a suite — the same reviewable
document `aiec eval suite --suite` takes, described below — and expand it into
that matrix, one cell per task, revision and repetition, each cell checked out
at the revision it is standing for and labelled so it can be argued with
afterwards.

```python
comparison = af.evals.compare(
    baseline="main",
    candidate="feature-x",
    suite="evals/nightly.json",
    repetitions=3,
    max_parallel=4,
)

# Measurements for both sides. No verdict: what "better" means is yours to say.
print(comparison.by_revision["main"]["succeeded"])
print(comparison.by_revision["feature-x"]["succeeded"])
print(comparison.by_revision["feature-x"]["task_exit_codes"])
print(len(comparison.cells), "runs, each kept whole")
```

`repetitions`, `max_parallel`, `retention`, `max_attempts`, `retained_seconds`
and `idempotency_key` all reach every cell: with an `idempotency_key`, each
cell's scope is derivable, so a retried request returns the runs that already
exist instead of quietly starting a second set of machines. Without one, each
cell is named by the control plane, so running the same comparison again runs
it again.

A complete agent workflow — clone, inspect, edit, validate, diff, destroy — is in
[`examples/coding_agent.py`](examples/coding_agent.py).

---

## Runs and evaluations from the CLI

`aiec` talks to your own control plane with `--url` (`AIEC_URL`) and `--api-key`
(`AIEC_API_KEY`), and prints JSON, so anything below pipes into `jq`.

A run is described by a document, because a workload somebody else has to
review is a workload that belongs in a pull request:

```json
{
  "workload": {
    "image": "aiec-coding:latest",
    "repo": { "url": "https://github.com/me/fixture", "reference": "main" },
    "command": ["pytest", "-q"],
    "validations": [["pytest", "-q"]],
    "artifacts": ["report.txt"],
    "timeout_seconds": 900
  },
  "requirements": { "full_kernel_isolation": true },
  "retention": "keep_on_failure"
}
```

```bash
aiec run submit run.json            # submit it, print the settled run
aiec run submit run.json --dry-run  # print what would be sent, send nothing
aiec run submit --repo https://github.com/me/fixture --dry-run -- pytest -q
```

The flags are a shorthand for the same request and override whatever the
document said; `--setup` and `--validate` take a JSON argument vector each
(`--setup '["pip","install","-e","."]'`), so a command stays a vector and is
never re-split into a shell line. `--timeout-seconds`, `--cpu`,
`--memory-mb`, `--disk-mb`, `--network`, `--full-kernel-isolation`,
`--retention`, `--artifact`, `--env KEY=VALUE`, `--secret`,
`--requested-runtime` and `--idempotency-key` cover the rest.

Everything a run left behind is readable, and a run that is still holding a
machine can be stopped:

```bash
aiec run list --state failed --limit 20
aiec run show <run-id>
aiec run results <run-id>      # command outcomes, the diff, per-phase timings
aiec run events <run-id>       # the history, in the order it happened
aiec run artifacts <run-id>    # what was collected, with a URL per artifact
aiec run cancel <run-id>
```

Evaluations are the same runs, in bulk, at a bound the caller sets. They all
need `sandboxes:write`, because they start machines:

```bash
aiec eval batch --request task-a.json --request task-b.json --max-parallel 2
aiec eval repetitions --request task-a.json --repetitions 5
aiec eval matrix --spec matrix.json
aiec eval suite --suite suite.json --image aiec-coding:latest
```

Each takes `--dry-run` to print the request it would send. A batch or
repetitions answer is the runs themselves, one per cell; a matrix answer
carries each cell's axis *and* the run it produced, so a cell can be argued
with rather than believed:

```json
{
  "options": { "max_parallel": 4 },
  "cells": [
    { "axis": { "model": "opus" },   "request": { "workload": { "command": ["pytest", "-q"] } } },
    { "axis": { "model": "sonnet" }, "request": { "workload": { "command": ["pytest", "-q"] } } }
  ]
}
```

A suite is the same thing written as tasks rather than cells, and is expanded
into that matrix by the control plane:

```json
{
  "name": "nightly",
  "tasks": [
    {
      "name": "unit",
      "repo_url": "https://github.com/me/fixture",
      "reference": "main",
      "command": ["pytest", "-q"],
      "validations": [["pytest", "-q"]],
      "timeout_seconds": 900
    }
  ]
}
```

The same three routes are `POST /v1/eval/batch`, `/v1/eval/repetitions` and
`/v1/eval/matrix`; the typed helpers live in `aiec-client` as `eval_batch`,
`eval_repetitions` and `eval_matrix`.

---

## Local MCP server

Point any MCP-capable agent at your own cluster and it gets a disposable machine
per task — a real microVM, created and destroyed on demand:

```bash
export AIEC_LOCAL_API_URL=https://127.0.0.1:18443
export AIEC_LOCAL_API_KEY=af_live_...
./target/release/aiec-mcp
```

| | |
|---|---|
| URL | `http://127.0.0.1:8765/mcp` |
| Transport | Streamable HTTP |
| Authorization | `Bearer <~/.config/aiec/mcp-token>` |

It is local-only by construction: a remote AIec URL is refused at startup, and
the `hosted` and `e2b` runtimes are unavailable, so a workload cannot escape to
a hosted provider. A busy local worker reports `LOCAL_CAPACITY_UNAVAILABLE`
rather than quietly sending work elsewhere.

Thirteen tools cover the lifecycle, exec and files, plus higher-level ones that
clone a repo, run a task and return the diff, and that run a coding agent — or
compare two revisions of one — each side in its own clean sandbox.

→ [aiec.gobrowse.dev/mcp](https://aiec.gobrowse.dev/mcp) ·
[docs/MCP.md](docs/MCP.md)

---

## Self-hosting

AIec OSS has no dependency on any managed provider. You need a Linux host with
KVM, PostgreSQL, and S3-compatible object storage.

```bash
git clone https://github.com/fedoragobrowse-design/AIec.git
cd AIec
cargo build --release -p aiec-api -p aiec-cli -p aiec-mcp
export PATH="$PWD/target/release:$PATH"
export AIEC_KERNEL=/path/to/vmlinux
export AIEC_GUEST_SECRET="$(openssl rand -hex 32)"
./scripts/build-firecracker-guest.sh  # requires Docker and a compatible kernel
aiec doctor                         # report missing host/configuration prerequisites
```

The image builder writes the rootfs and its digests; configure signed-image
admission separately. Protect the guest secret and output image as credentials.
`aiec doctor` validates KVM, the Firecracker binary, the guest artifact and its
digest, the database, object storage, networking and TLS. It reports missing
prerequisites; it does not configure or start a cluster.
Full instructions: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

Guard workers need `CAP_NET_ADMIN` and `CAP_NET_RAW` for network enforcement.
The packaged [`deploy/aiec-worker.service`](deploy/aiec-worker.service) grants
both; an alternate launcher must grant them explicitly. A worker that cannot
use nftables reports `network_policy: false` and refuses governed placement,
rather than silently downgrading it. Deploy a freshly built guest image and
configure TLS, image trust, credentials and the watchdog as described in the
deployment guide.

---

## Documentation

Start at the website — <https://aiec.gobrowse.dev/docs> — or read it here:

| Document | What it covers |
|---|---|
| [Docs](https://aiec.gobrowse.dev/docs) | Quickstart, images, sandbox lifecycle, self-hosting |
| [Pricing](https://aiec.gobrowse.dev/pricing) | What running it yourself costs |
| [Security](https://aiec.gobrowse.dev/security) | The same threat model as [`SECURITY.md`](SECURITY.md) |
| [Status](https://aiec.gobrowse.dev/status) | Published verification results and known limits, not live cluster health |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Architecture, and how it maps onto the DSec paper |
| [`docs/API.md`](docs/API.md) | Every endpoint, with request and response shapes |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Self-hosting, TLS, workers, object storage, backups |
| [`SECURITY.md`](SECURITY.md) | Threat model, isolation boundaries, reporting a vulnerability |
| [`docs/GUARD.md`](docs/GUARD.md) | Operating Guard: the watchdog, budgets, quarantine and release |
| [`docs/GUARD_POLICY.md`](docs/GUARD_POLICY.md) | The Guard policy format, templates and verifier |
| [`docs/GUARD_THREAT_MODEL.md`](docs/GUARD_THREAT_MODEL.md) | What Guard defends, and what it does not |
| [`docs/guard-report.md`](docs/guard-report.md) | Live acceptance evidence, benchmarks, remaining limits and exact commands |
| [`docs/MCP.md`](docs/MCP.md) | The local-only MCP server: giving an agent a disposable machine |
| [`docs/known-defects.md`](docs/known-defects.md) | Open defects, resolved findings, and the cluster notes that cost time |
| [`docs/FIRECRACKER_GUEST.md`](docs/FIRECRACKER_GUEST.md) | How the coding guest image is built and verified |

---

## Repository layout

| Path | What it is |
|---|---|
| `crates/aiec-core` | Domain model, protocols, runtime and storage traits |
| `crates/aiec-runtime` | Firecracker, hosted and Docker runtimes |
| `crates/aiec-api` | The control plane, worker service and HTTP API |
| `crates/aiec-storage` | PostgreSQL and S3-compatible persistence |
| `crates/aiec-network-linux` | TAP and nftables isolation |
| `crates/aiec-guard` | Out-of-guest policy, gateway, enforcement, watchdog, canaries and evidence journal |
| `crates/aiec-client` | Rust SDK |
| `sdk/python` | Python SDK (`pip install agentforge-sdk`) |
| `policies/guard` | Shipped Guard policy templates, selection examples and boundaries |
| `guest/aiec-guest` | The in-guest agent serving the control channel |
| `web` | Static documentation website, page fragments and shared build script |

The Rust crate names keep the `aiec-` prefix: they are code identifiers that
would break every consumer if renamed, and they are not the product's name.

---

## Development

```bash
./scripts/gate.sh
```

That runs formatting, clippy with `-D warnings`, the full test suite, and the
documentation contract check, and it fails on any of them. The contract check is
part of the gate because the website, this file and the SDK can otherwise drift
apart: it fails if any documented import is not the real one (`from agentforge
import AIec`), if a documented name is not exported, or if a sample names an
image the API cannot resolve.

## Licence

Apache 2.0 — see [`LICENSE`](LICENSE).
