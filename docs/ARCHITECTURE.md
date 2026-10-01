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
        +-- S3 artifacts ---------------------- Core ArtifactStore (streamed put/verified download)
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

Artifact transfer crosses the same boundaries in binary chunks: `SandboxRuntime::get_file_chunk` returns one bounded, version-tagged range, the worker serves it as raw bytes under the sandbox's active lease generation, and `ArtifactStore::put_stream` consumes those ranges one at a time, so neither the control plane nor an object-store backend ever holds a whole artifact. The download direction is the mirror image: `ArtifactStore::get_verified` spools and checksums an object under its expected digest before it exposes any body to the caller.

The metadata store fences state changes by lease generation: a fenced state transition takes the sandbox row lock and reads the sandbox's active, unexpired lease in the same transaction, and is rejected unless the caller's generation is still current. Lease recovery is a single transaction that locks the expired lease, releases the dead owner's debited capacity, places the sandbox on a healthy worker chosen with the same selection the scheduler uses, and issues a replacement lease with a strictly higher generation. It accepts a lease the reconciler already expired, commits the capacity release even when no worker is available, and returns no placement so the caller can retry.

### Run admission and executor ownership

`POST /v1/runs` and the internal matrix/evaluation paths commit a `Run` and a
`run_queue` row in one transaction, so a run cannot exist without a queue entry
and no executor sees a half-admitted request. The queue row stores the full
unresolved `RunRequest` document, the tenant, a queue deadline and a fixed
execution budget, so dispatch never depends on an HTTP connection, an in-process
timer or a retrying client.

- **Admission is atomic and idempotent.** Per-tenant and global pending counts are
  counted under a cluster-wide advisory lock; exceeding either is a
  `quota exceeded` refusal, and a repeated `idempotency_key` resolves to the
  existing run even when the queue is full.
- **Dispatch is bounded and fair.** `AIEC_RUN_QUEUE_MAX_ACTIVE` (default 4) caps
  concurrently executing runs cluster-wide; excess work stays `queued`. Claims use
  `FOR UPDATE ... SKIP LOCKED`, ordering by a tenant's active count, then that
  tenant's last dispatch, then FIFO, so a busy tenant cannot monopolize a slot and
  no run is claimed twice.
- **Ownership is short and fenced.** Each claim takes an owner UUID and a
  renewable lease (`AIEC_RUN_QUEUE_LEASE_SECONDS`, default 30s, heartbeated every
  third of that). The execution deadline — the workload timeout plus placement and
  teardown grace — is fixed at claim time and heartbeats cannot extend it. Renew,
  fail and finish statements all require a live lease, so an expired owner cannot
  revive, settle or clean up work after recovery took it.
- **No VM or network I/O runs inside a queue transaction.** Claims, heartbeats and
  recovery are short row updates; the executor polls slow I/O outside them and
  abandons its future the moment a heartbeat is lost.
- **Recovery is teardown, never replay.** An expired lease, an expired queue
  deadline, or a run that left `queued` outside the queue is terminally failed in
  the same transaction that marks it `reclaiming`, its unfinished attempt is
  closed with the same reason, and the owner runs the normal teardown path
  against the existing sandbox links. Attempt results and placement are preserved.
  A run whose `cleanup_failed` is set keeps its slot, so the failed cleanup stays
  visible and is retried instead of being dropped.
- **Shutdown is explicit.** The dispatcher guard stops new claims, cancels in-flight
  work and drains every owned teardown future; dropping the guard signals the same
  stop. A process that dies outright leaves leases that expire, and the next
  dispatcher's recovery retires those runs, so no active run stays active.
- **Waiters poll, and they back off.** A caller waiting for a terminal result
  re-reads its run with exponential backoff (100 ms, doubling to a 2 s cap) that
  resets whenever the run's state or completion time changes, and it asks about
  the queue row only once the run is terminal. A settled run is still answered
  within roughly 100 ms, while a long queue costs a logarithmic number of
  queries per waiter instead of a fixed spin — a matrix multiplies waiters, not
  load.

## Worker data plane

`aiec worker --runtime firecracker` is an independent authenticated HTTP service. The API sends typed, request-ID-bearing lifecycle and I/O operations. Responses are capped and idempotently replayed by request ID. Workers register capacity, heartbeat, claim durable assignments, and invoke the control-plane expired-lease reconciliation endpoint. Firecracker startup runs an owner-scoped report-only local scan, and the report is included in worker registration metadata; it reports missing local API sockets but does not perform process cleanup or reassignment. Production worker RPC requires HTTPS and bearer authentication; native mTLS identity verification and certificate rotation remain pending. Worker requests carry the scheduler's active lease generation, and the worker rejects stale generations before replay or runtime execution. Live startup recovery, reassignment, and multi-worker evidence remain open.

Operations that change whether a sandbox exists — create, start, stop, pause,
resume, destroy, snapshot, restore — are serialized per sandbox, at the worker
and again inside the Firecracker runtime. Replaying by request ID is not enough:
a destroy and a create for the same sandbox are two different request IDs, and
running them together let a destroy report success while a create was still
copying into the directory it had just removed. The table is bounded and
self-clearing, and reaching its bound is a refusal rather than growth. A
request that waits is authorized again before it runs, because waiting is a
window in which the control plane can move the sandbox to another worker.
Exec and the file operations take no such gate: a destroy must never queue
behind the command it exists to interrupt. A snapshot capture does hold the
sandbox, so a destroy waits for the capture rather than killing the guest
halfway through one.

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

Before it materializes anything, a Firecracker create re-measures the host
against the same reserve the heartbeat publishes and refuses a sandbox it cannot
physically hold: an unmeasurable host, insufficient memory, or insufficient
disk, where the disk demand is the larger of the requested `disk_mb` and the
base image's own size, since every sandbox disk is a copy of that image. This is
admission only and rewrites no ledger counter. The copy itself is
copy-on-write where the filesystem supports it, and a create that is cancelled
— a client that disconnected, a request the control plane abandoned — stops at
its next chunk boundary, removes its destination, and kills any `resize2fs` it
started, so a cancelled or failed boot leaves nothing that a completed destroy
has not already removed.

The create request's `EnvironmentSpec` is persisted in the sandbox row and included in the scheduler idempotency fingerprint. The API provisions Git/toolkit setup after the runtime becomes reachable; failed setup destroys runtime resources and releases production capacity. Snapshot-derived workspace provisioning is implemented for workspace snapshots and rejects full-VM snapshots.

## Recovery

Sandbox state changes and `sandbox_events` commit together. Operations and creates accept idempotency keys. Expired worker leases and assignments are reconciled rather than silently forgotten. VM snapshots preserve running guest state; database retries reuse durable operation IDs. Snapshot object upload/database failure ordering still requires a production reconciliation job before internet-scale operation. A development-only Bubblewrap archive handoff test now exports a checksummed, size-bounded workspace archive and imports it into a distinct runtime root; this demonstrates local archive portability only. Firecracker memory/device snapshots remain worker-local, and live cross-worker recovery remains unverified.
