# AgentForge

**Serverless compute built specifically for autonomous AI agents.**

AgentForge is an independent, open-source sandbox control plane inspired by published sandbox-platform research. It is not affiliated with or endorsed by DeepSeek.

> **Development and Docker runtimes are not a public security boundary.** `bwrap-dev` and Docker runtimes have weaker isolation than Firecracker. Never expose them to strangers or untrusted public workloads. Production accepts an explicit `AGENTFORGE_RUNTIME=firecracker` or `AGENTFORGE_RUNTIME=docker`; Firecracker remains the recommended boundary for untrusted code.

## Quick start

Requirements: Linux x86_64, Rust 1.88+, `bubblewrap` for the development runtime, a reachable Docker Engine for the Docker runtime, PostgreSQL 15+ and S3-compatible storage for production, and `tar` for development snapshots.

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

The development runtime is intentionally separate. Production uses an independent PostgreSQL-backed API, scheduler, authenticated worker RPC, and the explicitly configured Firecracker microVM or Docker Engine backend. See `docs/DEPLOYMENT.md` for exact variables and worker launch.


## Components

- `agentforge-core`: dependency-light domain contracts and `Platform` composition for runtimes, scheduling, metadata, artifacts, networking, images, snapshots, and policy.
- `agentforge-runtime`: Firecracker and Docker Engine API backends plus the explicit bubblewrap development backend; all implement the Core runtime contract.
- `agentforge-storage`: PostgreSQL metadata/scheduling and S3/filesystem artifacts, adapted to Core storage contracts.
- `agentforge-api`: Axum API, worker RPC, lifecycle orchestration, health, and metrics; production and development launchers compose a Core `Platform` first.
- `agentforge-client` and `agentforge-cli`: Rust SDK and command-line UX over AgentForge's versioned HTTP API.
- `guest/agentforge-guest`: minimal framed guest control agent.

AgentForge is the batteries-included distribution over AgentForge Core. The default server therefore consumes the same public trait objects available to custom systems rather than bypassing Core with a private composition path. See `docs/ARCHITECTURE.md` for the dependency graph, `docs/EXTENDING.md` for compile-time extension boundaries, and `docs/DEPLOYMENT.md` for production configuration.

The runnable `custom_core_platform` example composes the real bubblewrap runtime and filesystem artifact store with custom scheduler, policy, and network implementations. It performs platform validation without starting a server:

```bash
cargo run -p agentforge-api --example custom_core_platform
```

## Development infrastructure

`docker compose` is optional for PostgreSQL, MinIO, and Prometheus. The committed Compose file uses the locally built `agentforge-minio:RELEASE.2025-10-15T17-29-55Z` image by default; set `AGENTFORGE_MINIO_IMAGE` to an approved internal image when running elsewhere. The application itself runs on the host. `scripts/bootstrap-local-services.sh` requires a trusted host `mc` executable via `AGENTFORGE_MC_BIN` or `PATH`.

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

Earlier Firecracker measurements are historical only. The current authoritative run is blocked before boot because `AGENTFORGE_FIRECRACKER_BIN` is unset; this is not current PASS evidence.

## Validation

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

An end-to-end script is in `scripts/smoke.sh`. Benchmarks are only reported after `agentforge benchmark` measures real requests; this README publishes no invented numbers.

## Private-alpha status

The current repository preserves the DSec-inspired Core/default-distribution split and contains Firecracker and Docker runtime paths. Live Docker Engine API execution, live PostgreSQL storage, live MinIO/S3 artifact workflows, and a real Firecracker v1.17.0 microVM test have passed. The Firecracker test used the approved uncompressed `.agentforge/images/vmlinux`, a freshly built rootfs, and the retained guest secret; it exercised exec, stdin, files, pause/resume, full snapshot, destroy, and restore. Two independent production workers remain blocked because the production worker client requires HTTPS and this host has no TLS-terminated worker endpoints. Remaining gaps are tracked in `docs/PRIVATE_ALPHA.md` with exact prerequisites and test commands.
The following private-alpha capabilities remain intentionally incomplete and are not implied by the current evidence: live multi-worker recovery and distribution, durable independent toolkit layers, portable cross-worker memory recovery, domain-accurate restricted egress, Docker restricted-network allowlists and snapshots, durable per-sandbox secrets, TLS/mTLS worker identity and certificate rotation, WebSocket PTY sessions, rate limits and lifetime quotas, failure-injection convergence, and warm pools. These are tracked in `docs/PRIVATE_ALPHA.md` with exact prerequisites and test commands.
