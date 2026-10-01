# Private-alpha milestone status

This report is evidence-based. `PASS` means the repository contains an executed behavioral test. `PARTIAL` means code exists but required integration, persistence, or isolation evidence is incomplete. `BLOCKED_BY_ENVIRONMENT` means the test could not run on this host. `UNSUPPORTED` means the capability is intentionally not implemented and is not advertised as working.

## DSec mechanisms

| Mechanism | Status | Evidence / boundary |
|---|---|---|
| Unified Core contracts | PASS | `cargo test -p aiec-core`; `cargo run -p aiec-api --example custom_core_platform` |
| Heterogeneous runtime capability discovery | PASS | `RuntimeCapabilities`; Bubblewrap and Firecracker report distinct capabilities |
| Docker Engine runtime | PASS (current run) | The Docker daemon is reachable through the operator's `docker` group. The opt-in Docker suite passed real Alpine lifecycle/files/security, portable workspace snapshot/restore, and the separately flagged 100-container churn test. Restricted network allowlists remain `UNSUPPORTED`. |
| Worker capability scheduling | PASS (current run) | Runtime capabilities are advertised, persisted, and included in scheduler predicates. Same-host HTTPS worker registration, placement and recovery all ran live in this run, and the Firecracker worker advertises `coding_guest` from the verified guest artifact. |
| Capability-based runtime policy | PASS (current run) | Workspace tests cover Docker-first auto selection, microVM selection, and tagged dispatch; live production scheduler placement and recovery now also run against a real control plane. |
| Runtime registry dispatch | PASS (current run) | Runtime selection tests and the opt-in Docker↔Firecracker workspace archive exchange passed. The exchange used real Docker and Firecracker with a short socket path. |
| Stateful lifecycle and files | PASS (current run) | Real Bubblewrap, current-run Docker, and current-run Firecracker lifecycle evidence exists, including a full production-path Firecracker coding-agent dogfood with an in-guest HTTPS Git clone and a retrieved `git diff`. |
| Firecracker microVM | PASS (current run) | Firecracker v1.17.0, `/dev/kvm`, kernel, and rootfs were used with a short socket path and serial execution. Real exec/files/stdin/env, pause/resume, full VM snapshot/restore, and portable workspace restore passed. |
| Cluster scheduler and fenced leases | PASS (current run) | Live worker death, lease expiry, reassignment to a new owner at a higher generation, workspace reconstruction, stale-owner fencing for exec/file/stop/destroy/lease-completion, late heartbeat and late completion were all exercised 3 times consecutively in a same-host two-worker HTTPS cluster. |
| Content-addressed image references | PASS | Core image identity and resolver tests |
| Composable base/workspace/toolkit layers | PARTIAL | Core carries independent `LayerSpec` identities with kind, name, content digest, and bounded validation. API materialization writes content-bearing layer payloads to a managed workspace path with read-only mode `0444`; the focused test uses a recording runtime, not a real Docker/Firecracker guest read. Independent runtime layer persistence and writable-overlay semantics remain open. |
| Environment composition contract | PARTIAL | `EnvironmentSpec`, `WorkspaceSpec`, `ToolkitSpec`, and `LayerSpec` validation plus content-digest-checked API writes are covered. Toolkit setup remains command-based rather than independently materialized toolkit layers. |
| Git workspace clone and checkout | PASS | Real development SDK workflow used a temporary local `git://` daemon, shallow-cloned the repository, checked out `main`, read the file, and inspected the commit; production Git admission remains untested. A focused two-Bubblewrap-runtime archive handoff test also passes, demonstrating development archive portability only, not live worker recovery. |
| Toolkit setup commands | PASS | Bounded named `ToolkitSpec.setup_commands` run inside the sandbox after workspace setup; deterministic API test passed. This is not independent composable toolkit-layer support. |
| Restricted host allowlists | UNSUPPORTED | Linux backend reports `restricted_allowlists: false` and fails closed for non-empty host allowlists pending a DNS/IP policy plugin. |
| Guest control secret | UNSUPPORTED | The guest still has one build-time shared control secret; this is separate from the per-sandbox workload secret API and remains a production limitation |
| Per-sandbox secret lifecycle and injection | PARTIAL | Development API stores one-hour in-memory secrets, injects them into exec, revokes them, bounds secret count, and tests metadata non-disclosure. Production endpoints fail closed until durable secret storage is configured; persistence and crash cleanup remain unimplemented. |
| Signed image admission | PASS | `SignedImageResolver` verifies the manifest signature, reference, rootfs SHA-256, and minimum 32-byte secret; production composition requires manifest configuration. Deployment key rotation and external manifest governance remain operator concerns. |
| TLS worker transport admission | PARTIAL | Plaintext Firecracker endpoints are rejected, but native TLS/mTLS identity verification is not implemented |
| Warm pools | UNSUPPORTED | No warm-pool implementation exists. At the current single-host development scale there is no measured cold-versus-warm baseline justifying added state-isolation complexity; defer until production density measurements establish a benefit. |
| Portable VM memory recovery | UNSUPPORTED | Firecracker snapshot metadata remains worker-local because device paths are host-specific |
| DSec EROFS/3FS/overlaybd | UNSUPPORTED | AIec uses a deliberately smaller private-alpha ext4 + workspace model; toolkit setup commands are not independent layers. |

## Verification gates

| Gate | Result | Evidence |
|---|---|---|
| `cargo fmt --check` | PASS | Direct run after the acceptance work completed successfully. |
| `cargo check --workspace --all-targets --all-features` | PASS | Direct run completed successfully. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS | Direct run completed with no warnings. |
| `cargo test --workspace --all-targets --all-features` | PASS | 139 tests passed against the live PostgreSQL `DATABASE_URL`, up from 125 before the acceptance work. |
| `git diff --check` | PASS | Direct run completed successfully. |
| Real Firecracker | PASS (current run) | Firecracker v1.17.0 direct runtime tests passed: 2 tests in 278.73s, including exec, files, pause/resume and portable workspace snapshot/restore against the rebuilt coding guest. |
| Coding Firecracker guest artifact | PASS (current run) | `scripts/build-firecracker-guest.sh` builds a debian:bookworm-slim@sha256:3783cc01… guest with git 2.39.5, curl 7.88.1, Python 3.11.2, tar 1.34, CA certificates and the static musl guest agent. `scripts/guest_artifact_report.py` verified rootfs sha256 `71b72e9bd36cf715ad093db1fb66c6038a494740dcfb457eacbb483e9192227b`; `debugfs` confirmed `/usr/bin/git`, `libcrypto.so.3`, `libssl.so.3`, `libc.so.6`, `/usr/bin/python3` and the guest agent are present. |
| Firecracker guest networking | PASS (current run) | A network-enabled sandbox received `ip=172.30.x.2::172.30.x.1:255.255.255.252:aiec:eth0:off` from the Firecracker boot cmdline; the guest kernel logged `IP-Config: Complete` and the in-guest HTTPS clone succeeded through TAP + nftables masquerade. |
| Firecracker coding-agent dogfood | PASS (current run) | `scripts/firecracker-coding-dogfood.sh` ran the full client → API → PostgreSQL → HTTPS worker → Firecracker → guest path. A real Firecracker sandbox was created and placed, `git --version` reported 2.39.5 inside the guest, `git clone https://github.com/octocat/Hello-World.git` succeeded with CA verification (no TLS bypass), `git status` and a file read succeeded, README was edited inside the guest, a real validation command printed `VALIDATION_OK`, `git diff` was retrieved and proven to contain the in-guest edit, the file API returned the edited bytes, and destroy plus cleanup (no VM, no container, no TAP) were verified. |
| Live worker recovery and fencing | PASS (current run) | `scripts/worker-recovery-validation.sh` ran SAME_HOST_MULTI_WORKER_VALIDATION 3 consecutive iterations against real PostgreSQL (an isolated per-run database), a real API over HTTPS with a disposable CA, and two real worker processes with independent ids, ports and state dirs. Every iteration passed all 14 assertions: sandbox placed on worker A at generation N, durable marker written, workspace snapshotted, worker A SIGKILLed without deregistering, lease expired normally, control plane reassigned to worker B at a higher generation, B reconstructed the workspace marker and accepted a file write, and after stale A returned with its previous state dir every stale exec, file mutation, stop, destroy and lease completion was rejected with `conflict`. A late heartbeat that still claimed the lost sandbox was refused with `worker reports 1 running sandboxes but holds no active lease`, and ownership and generation were unchanged; a late completion from generation N could not overwrite N+1. Final cleanup line: `processes=0 containers=0 firecracker=0 taps=0 active_leases=0`. The recovery pass may retry placement a few times before succeeding, so the observed generation is typically 4 rather than exactly N+1; that is bounded retry, not a fencing defect. |
| Real Bubblewrap lifecycle | PASS | Real API lifecycle/file/snapshot/restore test passed. |
| PostgreSQL | PASS (current run) | `docker exec ... pg_isready` reported accepting connections; the live `DATABASE_URL` PostgreSQL suite passed, including quota and scheduler races, fenced state updates, lease reassignment and workspace snapshot round-trips. |
| MinIO/S3 | PASS (current run) | The live S3 PUT/GET/DELETE test passed against the running MinIO service and cleaned up its object. Workspace archives are persisted to this shared object store, which is what makes a captured workspace readable by a different worker. |
| Docker Engine lifecycle | PASS (current run) | The Docker suite ran 3 tests: 2 real lifecycle/security and portable snapshot/restore tests passed; the churn test returned early because its separate opt-in flag was unset. A separate run with `AIEC_RUN_DOCKER_CHURN=1` passed the real 100-container churn test in 37.98s. |
| Cross-runtime portability | PASS (current run) | The opt-in Docker→Firecracker→Docker workspace archive exchange passed in 7.19s with real Docker and Firecracker. |
| Same-host two-worker HTTPS | PASS (current run) | Provisioned as a disposable same-host production-path cluster: real PostgreSQL (an isolated per-run database), a real API over HTTPS with a disposable CA, and two worker processes with independent node ids, ports and state dirs. This is same-host evidence and is not claimed as multi-host. |
| Docker API benchmark | PARTIAL | Docker API benchmark completed 10/10 creates with concurrency 2: p50 440.471 ms, p95 479.521 ms, p99 479.521 ms, total 2086.778 ms. This is a 10-sandbox Docker development API benchmark, not a 100-sandbox or Docker/Firecracker production comparison. |
| Coverage | BLOCKED_BY_ENVIRONMENT | `cargo-llvm-cov` is not installed. |

The historical `sg docker` churn command was:

```bash
sg docker -c 'AIEC_RUN_DOCKER_CHURN=1 AIEC_DOCKER_TEST_IMAGE=alpine:3.21 cargo test -p aiec-runtime --test docker real_docker_hundred_container_churn -- --nocapture'
```

That historical run completed 100 create/start/destroy cycles and reported zero managed containers afterward. It is not current-run evidence: the current shell's `docker info` failed with permission denied.

The development path completed a live bounded 10-sandbox lifecycle benchmark through the running API: 10/10 successful, p50 4.499 ms, p95 6.626 ms, p99 6.626 ms, total 24.646 ms. This is a development measurement, not the requested production or Docker/Firecracker comparison.

The live development smoke workflow passed after correcting the file-download route to `/files/content`: create, exec, binary file write/read, snapshot, restore, and destroy. This proves the Bubblewrap development API path only; it is not a Docker or Firecracker coding-agent dogfood proof. A 25-iteration API churn attempt was correctly rejected by the configured `disk_mb` quota and is not counted as a leak test; disposable state was removed after the API stopped.

The CLI benchmark uses a bounded semaphore and `JoinSet`; it does not silently execute serially when `--concurrency` is greater than one. This implementation is compiled and covered by the final workspace gate; production benchmark numbers remain blocked until a TLS-enabled production worker deployment is available.

## Contract matrix policy

The full requested matrix is not marked complete while unsupported or environment-blocked items remain. This is intentional: an unexecuted test is never reported as PASS. The supported Core and development contract has real tests; the production acceptance matrix requires the prerequisites above.

Environment setup currently runs after runtime start. A failed Git clone or toolkit command destroys the runtime and marks the sandbox failed; tenant resource quota policy, tenant-scoped locking, aggregate admission, and 429 mapping are implemented in PostgreSQL, but rate limits and lifetime quotas remain unimplemented. The live PostgreSQL suite exercised the durable quota and capacity races; rate-limit and lifetime-quota behavior remains unimplemented. The client receives `environment_setup_failed` for a non-zero setup command.

Firecracker `create()` writes an owner marker when `sandbox.node_id` is set; unowned legacy directories require explicit `claim_local_vm`. Firecracker startup runs an owner-scoped report-only local scan, and the report is included in worker registration metadata. The scan reports missing-API-socket candidates and never kills processes, deletes directories, or infers ownership from `/proc`. Worker RPC carries the active lease generation; `WorkerService` rejects lower generations before replay or runtime execution. A worker also verifies durable ownership against the control plane before executing any state-changing operation, and the generation it learns is persisted in its state directory so a restarted worker with stale local state still rejects superseded generations. Live worker death, reassignment, workspace reconstruction and stale-owner fencing are exercised by the same-host two-worker scenario recorded above.

## Reproducing the acceptance runs

Both acceptance harnesses need a toolchain image and, for the Firecracker path, a privileged container (TAP devices and `/dev/kvm` are unavailable to an unprivileged shell). Build the image once and run the harnesses from it:

```bash
# Firecracker coding-agent dogfood (real /dev/kvm and TAP, network host).
sg docker -c 'docker build -t aiec-acceptance scripts/acceptance-container.Dockerfile'
sg docker -c 'docker run --rm --privileged --network host \
  -v /dev/kvm:/dev/kvm -v "$PWD:$PWD" -w "$PWD" \
  -e DATABASE_URL=postgresql://aiec:aiec-dev-only@127.0.0.1:5432/aiec \
  -e AIEC_S3_ENDPOINT=http://127.0.0.1:9000 -e AIEC_S3_REGION=us-east-1 \
  -e AIEC_S3_BUCKET=aiec -e AIEC_S3_ACCESS_KEY_ID=aiec \
  -e AIEC_S3_SECRET_ACCESS_KEY=aiec-dev-only \
  -e AIEC_GUEST_SECRET=0123456789abcdef0123456789abcdef \
  aiec-acceptance bash scripts/firecracker-coding-dogfood.sh'

# Live recovery and fencing, three iterations.
sg docker -c 'docker run --rm --privileged --network host \
  -v /var/run/docker.sock:/var/run/docker.sock -v /dev/kvm:/dev/kvm \
  -v "$PWD:$PWD" -w "$PWD" -e AIEC_RECOVERY_ITERATIONS=3 \
  -e DATABASE_URL=postgresql://aiec:aiec-dev-only@127.0.0.1:5432/aiec \
  -e AIEC_S3_ENDPOINT=http://127.0.0.1:9000 -e AIEC_S3_REGION=us-east-1 \
  -e AIEC_S3_BUCKET=aiec -e AIEC_S3_ACCESS_KEY_ID=aiec \
  -e AIEC_S3_SECRET_ACCESS_KEY=aiec-dev-only \
  aiec-acceptance bash scripts/worker-recovery-validation.sh'
```

The recovery harness provisions and drops its own database, so run at most one instance at a time: the control plane binds fixed ports and concurrent runs collide.

Pause/resume now has explicit Core state, runtime trait, worker operation, and API routes. The development mock path tests `running → paused → running` and invalid resume returns `409`; Bubblewrap's explicit `501` response is covered by a focused API test. Firecracker pause issues the Firecracker `PATCH /vm` pause transition and is explicitly advertised as non-reclaiming; real Firecracker boot, pause and resume are covered by the opt-in `real_firecracker_exec_file_snapshot_restore` integration test and by the coding-agent dogfood.

## Current product surface

- Rust Core contracts: runtime, scheduler, metadata, artifacts, network, image, snapshot, policy, and platform composition.
- Rust and Python HTTP clients.
- Python synchronous context-managed sandbox API.
- Bubblewrap development runtime with bounded exec, files, workspace snapshots, and local snapshot restore.
- Firecracker runtime with guest VSock protocol, file operations, bounded exec, and local snapshot/restore.
- Docker Engine API runtime with explicit container isolation, bounded archive file transfer, restrictive host configuration, capability advertisement, and portable workspace snapshot support; restricted-network allowlists remain `UNSUPPORTED`.
- PostgreSQL and S3 adapters have live local integration evidence. Same-host Docker + Firecracker HTTPS worker registration passed, and live recovery, fencing, and reassignment now run in a same-host two-worker cluster.

The development API smoke workflow executed successfully against the Bubblewrap backend: create, exec, binary file write/read, snapshot, restore, and destroy. This is development-backend evidence, not Docker/Firecracker coding-agent dogfood evidence.

The development filesystem artifact API supports tenant-scoped upload, download, checksum verification, deletion, and sorted metadata listing with symlink rejection. Live S3 PUT/GET/DELETE against local MinIO passed; S3 listing remains unsupported. Shared-format portable workspace exchange between Docker and Firecracker passed in both directions, and captured workspace archives are now persisted to the shared object store with a checksum verified on read, which is what allows a new worker to reconstruct a dead worker's workspace. The development API smoke workflow above is Bubblewrap-backend evidence; the Firecracker coding-agent dogfood is separate evidence and is recorded in the verification gates.

Run artifact collection and download are now streamed rather than buffered: bounded binary chunks cross sandbox → worker → control plane → object store, object writes are incremental, and a download is checksum-verified in full before any byte reaches the caller. The evidence for this is source and unit/integration level only — the streaming storage, worker binary-chunk, and guest chunk tests pass, but no live deployed run has yet collected an artifact through the new path, and the Firecracker guest agent must be rebuilt (the wire protocol revision is now recorded in `guest-capabilities.json` and enforced at startup) before that live path can run.

Destroying a sandbox removes its in-memory secret map entry. The focused secret test verifies metadata non-disclosure and post-destroy cleanup; durable secret persistence and crash cleanup remain partial.

The Python SDK artifact workflow was executed against the temporary development API: upload `proof.txt`, download and compare bytes, delete it, and verify the post-delete `404`. Live S3 object put/get/delete was separately exercised through `S3ObjectStore`.
