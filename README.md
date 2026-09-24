# AgentForge

**Serverless compute built specifically for autonomous AI agents.**

AgentForge is an independent, open-source sandbox control plane inspired by published sandbox-platform research. It is not affiliated with or endorsed by DeepSeek.

> **Development runtimes are not a public security boundary.** `bwrap-dev` and Docker development modes run hostile code with substantially weaker isolation than Firecracker. Never expose them to strangers or untrusted public workloads. Production mode is `firecracker` and fails closed when KVM, Firecracker, a kernel, rootfs, or guest networking prerequisites are missing.

## Quick start

Requirements: Linux x86_64, Rust 1.88+, `bubblewrap`, PostgreSQL 15+ for production, and `tar`.

```bash
git clone <your-repository-url> agentforge
cd agentforge
cargo build --release

# One explicit development server; this prints a generated API key once.
export AGENTFORGE_RUNTIME=bwrap-dev
export AGENTFORGE_DEV_API_KEY=af_live_$(openssl rand -hex 24)
export AGENTFORGE_BIND=127.0.0.1:8080
./target/release/agentforge server
```

In another shell:

```bash
export AF_URL=http://127.0.0.1:8080
export AF_API_KEY='the-key-printed-by-server'
ID=$(curl -fsS -H "Authorization: Bearer $AF_API_KEY" -H 'content-type: application/json' \
  -d '{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300,"network":{"enabled":false}}' \
  "$AF_URL/v1/sandboxes" | jq -r .id)
curl -fsS -H "Authorization: Bearer $AF_API_KEY" -H 'content-type: application/json' \
  -d '{"command":["python3","-c","print(\"AgentForge works\")"]}' \
  "$AF_URL/v1/sandboxes/$ID/exec" | jq
```

The development runtime is intentionally separate. Production uses an independent PostgreSQL-backed API, scheduler, authenticated worker RPC, Firecracker VM, and guest-agent VSock channel. See `docs/DEPLOYMENT.md` for exact production variables and worker launch.


## Components

- `agentforge-core`: domain state, limits, paths, API keys, tenant identities.
- `agentforge-runtime`: Firecracker lifecycle/config and explicit bubblewrap development backend.
- `agentforge-storage`: tenant-scoped repository, append-only usage, PostgreSQL, node state, object storage boundary.
- `agentforge-api`: Axum API, lifecycle orchestration, health and metrics.
- `agentforge-client` and `agentforge-cli`: Rust SDK and command-line UX.
- `guest/agentforge-guest`: minimal framed guest control agent.

See `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and `docs/DEPLOYMENT.md` before production use.

## Development infrastructure

`docker compose` is optional for PostgreSQL, MinIO, and Prometheus. The application itself runs on the host. The committed compose file is infrastructure-only.

## Verified Firecracker path

The KVM integration test boots Firecracker, waits for the guest agent, executes commands inside the guest, writes/reads a guest file, creates a full memory/device snapshot plus disk copy, destroys the source VM, restores the snapshot in a new Firecracker process, and reads the preserved file:

```bash
AGENTFORGE_RUN_FIRECRACKER_TESTS=1 \
AGENTFORGE_FIRECRACKER_BIN=/opt/firecracker/firecracker \
AGENTFORGE_KERNEL=/var/lib/agentforge/images/vmlinux \
AGENTFORGE_ROOTFS=/var/lib/agentforge/images/agentforge-rootfs.ext4 \
AGENTFORGE_GUEST_SECRET='<same secret used to build the guest>' \
cargo test -p agentforge-runtime --test firecracker -- --nocapture
```

On the development host this completed in 37.23 seconds (40.17 seconds including Cargo startup), with 529,304 KiB maximum resident set size for the test process. This is a single-host functional measurement, not a production benchmark.

## Validation

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

An end-to-end script is in `scripts/smoke.sh`. Benchmarks are only reported after `agentforge benchmark` measures real requests; this README publishes no invented numbers.
