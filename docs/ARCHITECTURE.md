# Production architecture

```text
                    AIec Core
       domain + runtime/scheduler/storage/network
       image/snapshot/policy contracts + Platform
                              ^
                              |
        +---------------------+---------------------+
        |                                           |
AIec API / worker / CLI              custom Core products
        |
        +-- WorkerRuntime ---------------------- Core SandboxRuntime
        +-- PostgreSQL scheduler/metadata ----- Core Scheduler/MetadataStore
        +-- S3 artifacts ---------------------- Core ArtifactStore
        +-- Linux network --------------------- Core NetworkBackend
        +-- standard images ------------------- Core ImageResolver
        +-- Firecracker snapshot capabilities - Core SnapshotProvider
        +-- default policy -------------------- Core Policy
```

The dependency direction is acyclic. Core contains generic sandbox, worker, resource, storage, network, image, snapshot, and policy contracts. Backend crates depend on Core; AIec's API, worker, and CLI select and consume those backends. Core does not import SQLx, Firecracker, Axum, AWS, or Linux implementation types.

## Control plane

`aiec-server` builds an AIec `Platform` from Core trait objects before constructing API state. Its production modes use the worker RPC runtime, storage-backed scheduler, PostgreSQL metadata, S3 artifacts, Linux networking, configured runtime policy, and the selected Firecracker or Docker backend. Firecracker mode adds signed image resolution; Docker mode uses normal OCI references and worker-advertised capabilities.

The production API requires an explicit `AIEC_RUNTIME` (`firecracker` or `docker`) and does not silently select a local fallback. Firecracker mode requires signed image-manifest configuration; Docker mode uses the worker-advertised container capabilities and normal OCI image references. PostgreSQL remains authoritative for tenants, keys, sandboxes, transitions, worker capacity, assignments, fenced leases, operation idempotency, snapshots, images, usage, and tenant quota policy.

The scheduler filters healthy, non-expired, runtime-compatible workers with enough CPU, RAM, and disk. A tenant advisory lock plus `SELECT ... FOR UPDATE SKIP LOCKED` and one transaction enforce tenant quota aggregation, reserve capacity, create the lease, and assign the sandbox. Lease generations fence stale workers. Heartbeats carry monotonic worker versions; expired leases enter explicit reconciliation history.

The metadata store fences state changes by lease generation: a fenced state transition takes the sandbox row lock and reads the sandbox's active, unexpired lease in the same transaction, and is rejected unless the caller's generation is still current. Lease recovery is a single transaction that locks the expired lease, releases the dead owner's debited capacity, places the sandbox on a healthy worker chosen with the same selection the scheduler uses, and issues a replacement lease with a strictly higher generation. It accepts a lease the reconciler already expired, commits the capacity release even when no worker is available, and returns no placement so the caller can retry.

## Worker data plane

`aiec worker --runtime firecracker` is an independent authenticated HTTP service. The API sends typed, request-ID-bearing lifecycle and I/O operations. Responses are capped and idempotently replayed by request ID. Workers register capacity, heartbeat, claim durable assignments, and invoke the control-plane expired-lease reconciliation endpoint. Firecracker startup runs an owner-scoped report-only local scan, and the report is included in worker registration metadata; it reports missing local API sockets but does not perform process cleanup or reassignment. Production worker RPC requires HTTPS and bearer authentication; native mTLS identity verification and certificate rotation remain pending. Worker requests carry the scheduler's active lease generation, and the worker rejects stale generations before replay or runtime execution. Live startup recovery, reassignment, and multi-worker evidence remain open.
Docker workers register `container` isolation plus `exec` and `files` capabilities in the first-class `nodes.capabilities` column; `streaming` is explicitly false. PostgreSQL scheduler selection filters by requested runtime, capacity, and required capability JSON before ranking workers. Docker Engine API lifecycle, archive file transfer, workspace bind mounts, labels, and restrictive host settings remain backend-specific; Docker snapshots are explicitly unsupported until safe portable archive materialization is implemented.

## DSec parity boundary

AIec is inspired by DSec and preserves its Core/runtime split, but the Docker backend is not DSec-equivalent. DSec §3.3 places container workloads inside a QEMU/libvirt VM, with an edge node-local admission path, EROFS/overlayfs composable layers, aether/chronus session proxies, 3FS on-demand image data, and OverlayBD-backed writable storage. AIec currently uses a direct host Docker Engine API with a managed workspace bind mount, archive transfer, capability advertisement, and restrictive container settings. It does not implement DSec's nested isolation VM, aether/chronus, 3FS, EROFS, overlayfs layer composition, OverlayBD, or DSec's local edge admission protocol. These are roadmap gaps, not implemented mechanisms.

## Firecracker and guest control

The worker starts Firecracker through its API socket, configures vCPU, RAM, ext4 root disk, vsock, and an optional isolated TAP, then waits for the guest agent. The host opens Firecracker's UDS and sends `CONNECT 1024`; the guest listens on AF_VSOCK port 1024. Every request is an HMAC-SHA256-authenticated, versioned, UUID-keyed, length-delimited JSON frame capped at 2 MiB. Replay IDs are rejected per connection.

Guest operations run only inside the VM: argv exec, bounded output, command timeout, workspace file read/write/list/mkdir/remove, shutdown, and snapshot preparation. Path resolution canonicalizes existing paths and rejects traversal or symlink escape.

## Snapshots

The worker pauses the microVM, creates a full Firecracker memory/VM-state snapshot, copies and checksums the ext4 disk, then resumes it. Restore verifies the disk checksum, restores the original disk path expected by the versioned VM state, loads Firecracker snapshot state, overrides vsock, and resumes in a new process. This preserves memory, devices, processes, sockets, and disk state. Firecracker releases before `1.17` do not support restoring to a changed block-device path; restore is therefore worker-local and must remain on a compatible Firecracker version and filesystem layout.

## Network and resources

Firecracker enforces vCPU and RAM. The worker resizes each ext4 disk to the requested limit, command timeout/output/upload limits are enforced in the guest, and worker lifetime expiry stops the VM. Disabled networking creates no NIC. Enabled networking creates a per-VM TAP and nftables output rules that block metadata, loopback, and RFC1918 destinations before teardown. Restricted host allowlists currently fail closed pending a DNS/IP policy plugin; domain allowlists and bandwidth accounting remain future policy layers.

The create request's `EnvironmentSpec` is persisted in the sandbox row and included in the scheduler idempotency fingerprint. The API provisions Git/toolkit setup after the runtime becomes reachable; failed setup destroys runtime resources and releases production capacity. Snapshot-derived workspace provisioning is implemented for workspace snapshots and rejects full-VM snapshots.

## Recovery

Sandbox state changes and `sandbox_events` commit together. Operations and creates accept idempotency keys. Expired worker leases and assignments are reconciled rather than silently forgotten. VM snapshots preserve running guest state; database retries reuse durable operation IDs. Snapshot object upload/database failure ordering still requires a production reconciliation job before internet-scale operation. A development-only Bubblewrap archive handoff test now exports a checksummed, size-bounded workspace archive and imports it into a distinct runtime root; this demonstrates local archive portability only. Firecracker memory/device snapshots remain worker-local, and live cross-worker recovery remains unverified.
