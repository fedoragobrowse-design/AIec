# Production architecture

```text
                    AgentForge Core
       domain + runtime/scheduler/storage/network
       image/snapshot/policy contracts + Platform
                              ^
                              |
        +---------------------+---------------------+
        |                                           |
AgentForge API / worker / CLI              custom Core products
        |
        +-- WorkerRuntime ---------------------- Core SandboxRuntime
        +-- PostgreSQL scheduler/metadata ----- Core Scheduler/MetadataStore
        +-- S3 artifacts ---------------------- Core ArtifactStore
        +-- Linux network --------------------- Core NetworkBackend
        +-- standard images ------------------- Core ImageResolver
        +-- Firecracker snapshot capabilities - Core SnapshotProvider
        +-- default policy -------------------- Core Policy
```

The dependency direction is acyclic. Core contains generic sandbox, worker, resource, storage, network, image, snapshot, and policy contracts. Backend crates depend on Core; AgentForge's API, worker, and CLI select and consume those backends. Core does not import SQLx, Firecracker, Axum, AWS, or Linux implementation types.

## Control plane

`agentforge-server` builds an AgentForge `Platform` from `Arc<dyn Core ...>` values before constructing API state. Its production defaults are the worker RPC runtime, storage-backed scheduler, PostgreSQL metadata, S3 artifacts, Linux networking, standard image resolution, Firecracker snapshot capabilities, and default policy. API and worker launchers do not retain a second private composition architecture.

The server has no local production runtime fallback. It requires `AGENTFORGE_RUNTIME=firecracker`, `DATABASE_URL`, tenant/API credentials, worker credentials, and private S3-compatible storage. PostgreSQL is authoritative for tenants, keys, sandboxes, transition events, worker capacity, sandbox assignments, fenced leases, operation idempotency, snapshots, images, and usage.

The scheduler filters healthy, non-expired, runtime-compatible workers with enough CPU, RAM, and disk. `SELECT ... FOR UPDATE SKIP LOCKED` and one transaction reserve capacity, create the lease, and assign the sandbox. Lease generations fence stale workers. Heartbeats carry monotonic worker versions; expired leases enter explicit reconciliation history.

## Worker data plane

`agentforge worker --runtime firecracker` is an independent authenticated HTTP service. The API sends typed, request-ID-bearing lifecycle and I/O operations. Responses are capped and idempotently replayed by request ID. Workers register capacity, heartbeat, claim durable assignments, renew leases, and reconcile state after restart. The worker and the explicit `agentforge server` development path both store their selected backend as a Core runtime trait object.

## Firecracker and guest control

The worker starts Firecracker through its API socket, configures vCPU, RAM, ext4 root disk, vsock, and an optional isolated TAP, then waits for the guest agent. The host opens Firecracker's UDS and sends `CONNECT 1024`; the guest listens on AF_VSOCK port 1024. Every request is an HMAC-SHA256-authenticated, versioned, UUID-keyed, length-delimited JSON frame capped at 2 MiB. Replay IDs are rejected per connection.

Guest operations run only inside the VM: argv exec, bounded output, command timeout, workspace file read/write/list/mkdir/remove, shutdown, and snapshot preparation. Path resolution canonicalizes existing paths and rejects traversal or symlink escape.

## Snapshots

The worker pauses the microVM, creates a full Firecracker memory/VM-state snapshot, copies and checksums the ext4 disk, then resumes it. Restore verifies the disk checksum, restores the original disk path expected by the versioned VM state, loads Firecracker snapshot state, overrides vsock, and resumes in a new process. This preserves memory, devices, processes, sockets, and disk state. Firecracker releases before `1.17` do not support restoring to a changed block-device path; restore is therefore worker-local and must remain on a compatible Firecracker version and filesystem layout.

## Network and resources

Firecracker enforces vCPU and RAM. The worker resizes each ext4 disk to the requested limit, command timeout/output/upload limits are enforced in the guest, and worker lifetime expiry stops the VM. Disabled networking creates no NIC. Enabled networking creates a per-VM TAP and nftables output rules that block metadata, loopback, and RFC1918 destinations before teardown. Domain allowlists and bandwidth accounting remain future policy layers.

## Recovery

Sandbox state changes and `sandbox_events` commit together. Operations and creates accept idempotency keys. Expired worker leases and assignments are reconciled rather than silently forgotten. VM snapshots preserve running guest state; database retries reuse durable operation IDs. Snapshot object upload/database failure ordering still requires a production reconciliation job before internet-scale operation.
