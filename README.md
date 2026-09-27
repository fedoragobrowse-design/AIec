# AIec

**AI elastic compute — isolated, disposable computers for autonomous agents.**

AIec hands an AI agent a real machine: its own kernel, its own filesystem, its own
network. The agent clones a repository, runs code, edits files, runs tests, reads
the diff, and destroys the environment — thousands of times an hour — without ever
touching the host.

```python
from aiec import AIec

af = AIec(api_key="af_live_...")

box = af.sandboxes.create(image="python:3.13")
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

## Two ways to run it

| | **AIec Cloud** | **AIec OSS** |
|---|---|---|
| Who runs it | We do | You do |
| Cost | Usage-based | Free, open source |
| Compute | Hosted Firecracker capacity | Your own KVM host |
| Database | Managed PostgreSQL (Neon) | Your own PostgreSQL |
| Object storage | Managed S3 | Your own S3 or MinIO |
| Operations | We upgrade, patch, back up, monitor | You own the host |

They are the same API, the same SDK, the same runtime model. Customers pay for
convenience, managed infrastructure, capacity and operations — **not** for access
to the source code.

- Cloud: `https://aiec.gobrowse.dev` · API `https://api.aiec.gobrowse.dev`
- OSS: `https://github.com/fedoragobrowse-design/AIec`

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

Details, including the limits we have not solved: [`SECURITY.md`](SECURITY.md).

---

## Quickstart

```bash
pip install aiec-sdk
```

```
open https://aiec.gobrowse.dev/cloud/keys
copy your key
```

```python
from aiec import AIec

af = AIec(api_key="af_live_...")          # defaults to https://api.aiec.gobrowse.dev
box = af.sandboxes.create(image="aiec-coding:latest")
print(box.exec(["git", "--version"])["stdout"])
box.destroy()
```

A complete agent workflow — clone, inspect, edit, validate, diff, destroy — is in
[`examples/coding_agent.py`](examples/coding_agent.py).

---

## Self-hosting

AIec OSS has no dependency on any managed provider. You need a Linux host with
KVM, PostgreSQL, and S3-compatible object storage.

```bash
git clone https://github.com/fedoragobrowse-design/AIec.git
cd AIec
./scripts/build-firecracker-guest.sh     # build the coding guest image
agentforge doctor                        # check every prerequisite
```

`agentforge doctor` validates KVM, the Firecracker binary, the guest artifact and
its digest, the database, object storage, networking and TLS, and tells you
exactly what is missing. Full instructions: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## Documentation

| Document | What it covers |
|---|---|
| [`docs/DESIGN.md`](docs/DESIGN.md) | Architecture, and how it maps onto the DSec paper |
| [`docs/API.md`](docs/API.md) | Every endpoint, with request and response shapes |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Self-hosting, TLS, workers, object storage, backups |
| [`SECURITY.md`](SECURITY.md) | Threat model, isolation boundaries, reporting a vulnerability |
| [`docs/FIRECRACKER_GUEST.md`](docs/FIRECRACKER_GUEST.md) | How the coding guest image is built and verified |

---

## Repository layout

| Path | What it is |
|---|---|
| `crates/agentforge-core` | Domain model, protocols, runtime and storage traits |
| `crates/agentforge-runtime` | Firecracker, hosted and Docker runtimes |
| `crates/agentforge-api` | The control plane, worker service and HTTP API |
| `crates/agentforge-storage` | PostgreSQL and S3-compatible persistence |
| `crates/agentforge-network-linux` | TAP and nftables isolation |
| `crates/agentforge-client` | Rust SDK |
| `sdk/python` | Python SDK (`pip install aiec-sdk`) |
| `guest/agentforge-guest` | The in-guest agent serving the control channel |
| `web` | Website and Cloud console |

The Rust crate names keep the `agentforge-` prefix: they are code identifiers that
would break every consumer if renamed, and they are not the product's name.

---

## Development

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Licence

Apache 2.0 — see [`LICENSE`](LICENSE).
