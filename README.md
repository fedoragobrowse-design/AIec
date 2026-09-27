# AgentForge

**Computers for AI agents.**

AgentForge gives autonomous AI agents isolated, disposable computers: a sandbox
with its own kernel, filesystem, network and lifecycle. An agent can clone a
repository, run code, edit files, run tests, read the diff, and throw the whole
environment away — thousands of times an hour — without ever touching the host.

```python
from agentforge import AgentForge

af = AgentForge(api_key="af_live_...")

box = af.sandboxes.create(image="python:3.13")
result = box.exec(["python", "-c", "print('hello from AgentForge')"])
print(result["stdout"])
box.destroy()
```

No SSH. No database access. No worker access. No manual repair.

---

## Two ways to use the same product

| | **AgentForge Cloud** | **AgentForge OSS** |
|---|---|---|
| Who runs it | We do | You do |
| Cost | Paid, usage-based | Free, open source |
| Compute | Hosted Firecracker capacity | Your own KVM host |
| Database | Managed PostgreSQL | Your own PostgreSQL |
| Object storage | Managed S3 | Your own S3 or MinIO |
| Operations | We upgrade, patch, back up and monitor | You own the host |

They are the same API, the same SDK, the same runtime model. Customers pay for
convenience, managed infrastructure, capacity, reliability and operations —
**not** for access to the source code.

- Cloud: `https://aiec.gobrowse.dev` · API `https://api.aiec.gobrowse.dev`
- OSS: `https://github.com/fedoragobrowse-design/AIec`

---

## Security model

Public workloads run under **Firecracker** microVMs. A tenant cannot select a
weaker runtime; the Cloud control plane forces Firecracker for untrusted
workloads, and Docker remains available for trusted self-hosted deployments and
local development.

Each sandbox gets its own guest kernel, its own virtio network namespace with an
egress policy that blocks the host LAN, RFC1918, link-local and cloud metadata
ranges, and a vsock control channel that is never exposed to the network. Guest
paths are validated against a fixed workspace root, and the host is not reachable
from inside the sandbox.

Details, including known limitations: [`docs/SECURITY.md`](docs/SECURITY.md).

---

## Self-hosting

AgentForge OSS has no dependency on any managed provider. It needs a Linux host
with KVM, PostgreSQL, and S3-compatible object storage.

```bash
git clone https://github.com/fedoragobrowse-design/AIec.git
cd AIec
docker compose up -d postgres minio          # or point at your own
./scripts/build-firecracker-guest.sh         # build the coding guest image
agentforge doctor                            # check every prerequisite
```

`agentforge doctor` validates KVM, the Firecracker binary, the guest artifact,
the database, object storage, networking and TLS, and tells you exactly what is
wrong. Full instructions: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## Documentation

| Document | What it covers |
|---|---|
| [`docs/API.md`](docs/API.md) | Every REST endpoint, with request and response shapes |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Self-hosting, TLS, workers, object storage, backups |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model, isolation boundaries, reporting a vulnerability |
| [`docs/FIRECRACKER_GUEST.md`](docs/FIRECRACKER_GUEST.md) | How the coding guest image is built and verified |
| [`docs/PRIVATE_ALPHA.md`](docs/PRIVATE_ALPHA.md) | Verified private-alpha evidence |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | What is next |

---

## How it works

```
agent
  ↓
AgentForge API  →  scheduler  →  worker  →  runtime  →  isolated sandbox
   auth            leases      HTTPS     Firecracker / hosted
   tenants         quotas                or Docker (trusted)
   quotas          fencing generations
```

A sandbox is a leased resource. The scheduler picks a worker with matching
capability and free capacity, records a monotonically increasing fencing
generation, and every state-changing operation is checked against that
generation. If a worker dies, its lease expires, the control plane reassigns the
sandbox to a new owner at a higher generation, and the new owner reconstructs the
durable workspace. The old worker, if it returns, is fenced out.

The design follows the mechanisms described in the DSec paper
(*DeepSeek Elastic Compute: A Sandbox Infrastructure for Effective Agentic
Training at Scale*, arXiv:2609.22978): a unified runtime contract, capability-based
scheduling, and fenced, recoverable sandbox ownership.

---

## Repository layout

| Path | What it is |
|---|---|
| `crates/agentforge-core` | Domain model, protocols, runtime and storage traits |
| `crates/agentforge-runtime` | Docker, Bubblewrap, Firecracker and hosted runtimes |
| `crates/agentforge-api` | The control plane, worker service and HTTP API |
| `crates/agentforge-storage` | PostgreSQL and S3-compatible persistence |
| `crates/agentforge-client` | Rust SDK |
| `sdk/python` | Python SDK (`pip install agentforge-sdk`) |
| `guest/agentforge-guest` | The in-guest agent that serves the control channel |
| `examples` | Runnable end-to-end examples |

## Development

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Licence

See [`LICENSE`](LICENSE).
