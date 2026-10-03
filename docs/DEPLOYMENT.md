# Production deployment

## Host prerequisites

Use dedicated Linux worker hosts with:

- readable/writable `/dev/kvm` for the worker service account;
- Firecracker v1.17+ and optional jailer;
- an AIec-compatible Linux guest kernel and ext4 rootfs;
- `ip(8)`, `nft`, `e2fsck`, and `resize2fs` for network/disk enforcement;
- a cgroup-v2-enabled kernel for predictable Firecracker snapshot performance;
- private connectivity among API, PostgreSQL, S3, and workers.

Docker workers are explicit runtime backends, not a production fallback. Start one with `aiec worker --runtime docker`; the worker uses the Docker Engine API, advertises `container`, `exec`, and `files` capabilities (`streaming: false`), and registers those capabilities for capability-aware scheduling. Docker containers use a managed workspace bind mount under the configured state root, drop all capabilities, disable privilege escalation, use a read-only root filesystem, and run a long-lived `sh -c 'sleep 3600'` process so exec operations have a stable container process. The default seccomp profile is left to Docker's daemon defaults; restricted network policies fail closed until an egress allowlist backend exists. Docker snapshot capture/restore is currently `UNSUPPORTED`.

## Guard on a worker

Guard is additive: a Firecracker worker enforces it by default, and a sandbox
with no policy selected gets no network. Two operator settings enable it.

```bash
# Binding name -> real secret. Owner-only, mode 0600, never passed as an argument.
AIEC_GUARD_CREDENTIALS_FILE=/etc/aiec/guard/credentials.json

# Operator boundary: extra blocked ranges, protected addresses, blocked hosts.
AIEC_GUARD_BOUNDARY_FILE=/etc/aiec/guard/boundary.json
```

The worker needs the privileges the existing network backend already required
— `CAP_NET_ADMIN` and `CAP_NET_RAW` — because Guard installs nftables tables
and TAP devices of its own.

The packaged unit, `deploy/aiec-worker.service`, grants both as ambient
capabilities, so a worker installed from it enforces Guard out of the box. A
worker started some other way — a container, a hand-written unit, a
supervisor — needs them granted by whatever starts it, and the startup probe
below is what tells you whether it has them.

That is checked rather than assumed. The worker probes `nft list ruleset` once
at startup — a read, which does not modify the firewall — and advertises the
`network_policy` capability only if it succeeds. A host without `nft`, or
without the privilege to use it, therefore reports `network_policy: false`, and
a guarded run or sandbox is refused *at placement* rather than admitted and
then failing at boot. Check it yourself with:

```bash
nft list ruleset >/dev/null && echo "can enforce" || echo "cannot"
```

The pre-Guard network backend is available only when the operator asks for it
explicitly:

```bash
AIEC_ALLOW_LEGACY_NETWORK=1
```

Without that variable, a sandbox that asks for a network but selects no Guard
policy is refused rather than silently placed on the ordinary NAT path. See
[`GUARD_POLICY.md`](../GUARD_POLICY.md) for the policy, the templates, and how
to verify a policy without deploying it.

Docker workers are explicit runtime backends, not a production fallback. Start one with `aiec worker --runtime docker`; the worker uses the Docker Engine API, advertises `container`, `exec`, and `files` capabilities (`streaming: false`), and registers those capabilities for capability-aware scheduling. Docker containers use a managed workspace bind mount under the configured state root, drop all capabilities, disable privilege escalation, use a read-only root filesystem, and run a long-lived `sh -c 'sleep 3600'` process so exec operations have a stable container process. The default seccomp profile is left to Docker's daemon defaults; restricted network policies fail closed until an egress allowlist backend exists. Docker snapshot capture/restore is currently `UNSUPPORTED`.

Build the local guest artifacts with:

```bash
export AIEC_GUEST_SECRET="$(openssl rand -hex 32)"
export AIEC_KERNEL=/var/lib/aiec/images/vmlinux
scripts/build-firecracker-guest.sh /var/lib/aiec/images
```

The resulting image starts `/sbin/init`, mounts guest pseudo-filesystems, starts `aiec-guest`, and listens on vsock port 1024. The secret is baked into the private rootfs and must be protected as a host credential.

Artifact collection reads sandbox files over the guest wire protocol, so the guest agent inside the root filesystem must speak the protocol revision this control plane requires. `guest-capabilities.json` records it as `guest_protocol_version`, and the runtime refuses metadata that records a different revision, so an image built before bounded range reads are refused at startup instead of failing at the first artifact collection. Rebuild the image with `scripts/build-firecracker-guest.sh` (it records the current revision), and re-sign the admission manifest whose rootfs digest changed.

## TLS certificates

The control plane's certificate authority must carry its extensions explicitly:

```bash
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -subj '/CN=AIec CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out ca.crt
```

A CA minted without them still passes `openssl verify` and works for clients
that trust the file directly, so the omission is easy to miss. It fails at
handshake time for stricter clients: Python 3.13 and later reject it with
`CERTIFICATE_VERIFY_FAILED: CA cert does not include key usage extension`,
which makes the Python SDK unable to reach an otherwise healthy control plane
while the Rust client keeps working. Note that `openssl req -x509` accepts
`-addext` but rejects `-extfile`.

## PostgreSQL and S3

The production server runs committed SQLx migrations and refuses to start without `DATABASE_URL`. Use TLS, backups, least privilege, and migration rollback procedures. Configure a private bucket through `AIEC_S3_ENDPOINT`, region, bucket, prefix, and credentials. S3 requests use AWS Signature V4 and SHA-256 checksums; the bucket must not be public.

## API server

Required configuration:

```bash
export AIEC_RUNTIME=firecracker
export DATABASE_URL='postgres://...'
export AIEC_TENANT_ID='<uuid>'
export AIEC_API_KEY='af_live_<48 hex chars>'
export AIEC_WORKER_TOKEN='<at least 32 bytes>'
export AIEC_IMAGE_MANIFEST=/var/lib/aiec/images/manifest.json
export AIEC_IMAGE_MANIFEST_SECRET='<protected manifest signing secret>'
export AIEC_S3_ENDPOINT='https://minio.internal:9000'
export AIEC_S3_REGION=us-east-1
export AIEC_S3_BUCKET=aiec
export AIEC_S3_ACCESS_KEY_ID='...'
export AIEC_S3_SECRET_ACCESS_KEY='...'
aiec-server
```

The production API accepts `AIEC_RUNTIME=docker` without Firecracker image-manifest variables in that mode. A Docker worker still requires a reachable Docker daemon and a worker registration; the API itself remains a scheduler/control plane. The production launcher does not silently substitute another backend.
Docker containers use an explicit long-lived `sh -c 'sleep 3600'` process rather than preserving the image entrypoint. The private-alpha Docker test image is Alpine and verifies exec, binary files, nested workspace creation, pause/resume, security settings, and cleanup. Operators using other images must provide a shell and `sleep` compatible with that image until configurable process supervision is implemented.
Docker containers use a TTY and keep stdin open to support common image-provided REPL entrypoints. This does not change the runtime API contract: AIec exec remains buffered rather than a streaming PTY protocol.
Docker exec requests are buffered and time-bounded at the API response level, but timeout handling does not yet kill the process tree inside the container. Treat Docker exec process-tree timeout and cleanup as unsupported until container-level termination is implemented.

The durable run queue is sized once at startup and is never read per request:
`AIEC_RUN_QUEUE_MAX_ACTIVE` (default 4) bounds concurrent runs cluster-wide,
`AIEC_RUN_QUEUE_GLOBAL_PENDING` (1024) and `AIEC_RUN_QUEUE_TENANT_PENDING` (128)
bound admission, `AIEC_RUN_QUEUE_TIMEOUT_SECONDS` (300) is how long a run may wait
before it fails, and `AIEC_RUN_QUEUE_LEASE_SECONDS` (30) is the executor
ownership lease, heartbeated every third of that and never extended past the run's
own execution deadline. Every API replica may run a dispatcher: dispatch is
fenced by the database, so replicas share the same active cap rather than
multiplying it. An invalid value refuses startup instead of silently falling back
to a default, because a queue that is not the size the operator asked for is a
capacity surprise. See [ARCHITECTURE.md](ARCHITECTURE.md#run-admission-and-executor-ownership).

`AIEC_REPO_CACHE_ENABLED=1` turns on the optional node-local repository object
cache on the API host. It is off by default because it trades a cold-start
failure mode for a warm-start one: with it off, every run clones from the
network and any git error is the run's own; with it on, a run whose commit is
already cached materializes from a bounded local mirror. The cache is bounded
(16 entries, 64 MiB total, 30-minute TTL, LRU), keyed by tenant plus the
resolved commit, and only ever used for anonymous HTTPS repositories with no
run secrets, so a private repository or a credentialed run always takes the
ordinary clone path. Each run still gets its own working tree, index and
`.git`. See
[EFFICIENCY-AUDIT.md](../benchmarks/EFFICIENCY-AUDIT.md#repository-object-cache-opt-in-implemented-unmeasured)
for the measured-versus-unmeasured state of it.

The systemd API unit starts `aiec-server`. The shorter `aiec server` command supports explicit `bwrap-dev` and `docker` single-process development distributions.

## Firecracker workers

```bash
export AIEC_FIRECRACKER_BIN=/opt/firecracker/firecracker
export AIEC_KERNEL=/var/lib/aiec/images/vmlinux
export AIEC_ROOTFS=/var/lib/aiec/images/aiec-rootfs.ext4
export AIEC_GUEST_SECRET='<same protected secret used to build the rootfs>'
export AIEC_STATE_DIR=/var/lib/aiec/firecracker
aiec --url http://aiec-api:8080 worker --runtime firecracker --name worker-a \
  --bind 0.0.0.0:9000 --capacity 8
```

The worker endpoint must be reachable only from the API/control network and protected by `AIEC_WORKER_TOKEN`. Run at least two workers for a multi-node deployment. Worker registration, versioned heartbeats, assignment claims, and lease renewal are persisted in PostgreSQL.

The example units are starting points. A Firecracker worker needs narrowly scoped `/dev/kvm`, network administration, writable VM/snapshot storage, and `NoNewPrivileges=false` or an equivalent reviewed jailer arrangement. API and worker storage should be separate encrypted volumes.

## Host pressure and reserves

A worker's declared capacity (`total_*`, seeded once into `available_*`) is the
operator's allocation and nothing else: `--capacity 8` declares 8 GiB of memory
and 80 GiB of disk whatever the host currently reports. Host pressure is a
separate measurement that gates admission and never rewrites a ledger counter.

Each registration and each 5-second heartbeat publishes, under
`metadata.pressure`:

| Field | Meaning |
|---|---|
| `host_id` | 32 hex characters, a truncated SHA-256 of `/etc/machine-id` (falling back to the DMI product UUID, then the hostname). Stable per machine and shared by every worker on it; never the raw identifier, which is a host credential. |
| `observed_at` | When the reading was taken. |
| `total_memory_bytes` / `total_disk_bytes` | `MemTotal`, and the size of the filesystem backing `--state-dir`. |
| `memory_available_bytes` / `disk_available_bytes` | `MemAvailable` and `f_bavail` **after** the reserve. `null` when the measurement could not be taken. |
| `reserves.memory_bytes` / `reserves.disk_bytes` | The reserve this reading was taken against. |

Disk is measured on the filesystem holding `--state-dir`, not on `/`. They are
the same filesystem on an ordinary host and emphatically not the same in a
container, where `/` is the image's overlay and the workspaces live on a
mounted volume.

Reserves are configurable and default to 512 MiB of memory and 2 GiB of disk:

```bash
aiec worker --runtime firecracker --name worker-a \
  --memory-reserve-mib 1024 --disk-reserve-mib 8192
```

`AIEC_WORKER_MEMORY_RESERVE_MIB` and `AIEC_WORKER_DISK_RESERVE_MIB` are the
environment equivalents. The reserve is subtracted from every reading and never
spendable, so lowering it hands the host's last bytes to tenants. A reading that
falls below the reserve saturates to zero, which is a host with no headroom left
rather than a host nobody could measure.

### The boot re-checks the host

The heartbeat decides *placement*. It cannot decide the boot, because a host
fills between the two: a placement admitted against a reading from ten seconds
ago spends memory and disk that something else may have taken since. So every
Firecracker `create` measures the host again, immediately before it materializes
anything, and refuses on three counts:

- a reading that could not be taken (it is not a reading of a host with room);
- less memory than the guest is configured with;
- less disk than the sandbox needs, where "needs" is the larger of the requested
  `disk_mb` and the base image's own size. Every sandbox disk starts as a copy
  of that image, so a request below the image's size is a request the host
  cannot honour however small it is. Firecracker reports that floor as
  `minimum_disk_mb` in its advertised capabilities.

The refusal costs one `stat` of the base image and one read of `/proc/meminfo`
and the state directory's filesystem, and it happens before the sandbox
directory, the owner marker, and the image copy exist. A refused create has
spent nothing, so the caller can retry it on another worker or after the host
recovers, and the same reserve is used as for the heartbeat — set
`AIEC_WORKER_MEMORY_RESERVE_MIB` / `AIEC_WORKER_DISK_RESERVE_MIB`, or
`--memory-reserve-mib` / `--disk-reserve-mib` on the worker command, and the
runtime uses the same value.

This is admission only. It never rewrites `available_*` or any other ledger
counter, and a host that refuses a boot keeps every sandbox already running.

### Failure behaviour

- **Measurement failed** (`null`): a production worker stops claiming new
  assignments and its pressure publishes as `null`, so the scheduler refuses
  placement on it too. Existing sandboxes keep running and keep their leases;
  only new placements stop, and they resume on the first heartbeat that
  measures successfully. A worker that cannot measure its host must not claim
  its allocation - that fallback is what let a full host keep taking work.
  `bwrap-dev` is the exception: it runs the developer's own shell, so it claims
  anyway rather than becoming a worker that registers and silently never runs
  anything. A *measured* full host stops claiming under every runtime.
- **Reading below the reserve**: zero, and the worker stops claiming while the
  scheduler refuses placements larger than the measured headroom. It does not
  stop work already running and does not modify `available_*`.
- **Health is never pressure**: `healthy` stays the worker's own answer about
  itself. A host that cannot be measured is not a broken worker, and the two
  call for different responses. `healthy = false` additionally hides the node
  from `list_workers(false)` and bypasses the ownership check at
  `heartbeat_worker`, neither of which pressure should be able to trigger.
- **Recovery**: pressure moves on every heartbeat. A host that frees memory or
  disk admits again with no ledger row rewritten, because nothing about
  admission is stored in the ledger in the first place.

### Aggregate admission across workers on one host

`host_id` exists so that N workers on one machine can be accounted for as one
machine. Without it, four workers each read the same figures and each spend
them, and the cluster comes to believe 35 GiB of memory exists where the host
has 26.

`aiec_core::host_pressure::host_admission_budget` implements the arithmetic.
The scheduler equivalent, for the integration to apply in
`select_schedulable_node`, is:

```sql
-- Freshness, measured on the DATABASE clock. `observed_at` is a string the
-- worker wrote and is kept as data only: gating on it would let a worker whose
-- clock runs fast keep contributing a stale reading indefinitely, and one whose
-- clock runs slow have a fresh reading discarded.
AND n.last_heartbeat >= now() - ($8::bigint * interval '1 second')
AND (n.metadata->'pressure'->>'host_id') IS NOT NULL
AND (n.metadata->'pressure'->>'memory_available_bytes') IS NOT NULL
AND (n.metadata->'pressure'->>'disk_available_bytes') IS NOT NULL
-- Aggregate across every node reporting the same host_id, and only across
-- those that heartbeated recently.
--
-- MIN, not MAX. A sibling that is inside the freshness window but has not
-- re-measured yet still reports its last reading, and that reading may be more
-- generous than the host's current state. Taking the least favourable fresh
-- reading means a stale-but-in-window peer can only ever understate capacity,
-- which costs some utilization; taking the most favourable would let it
-- overstate it, which costs tenants their jobs.
AND (
  SELECT COALESCE(MIN((p.metadata->'pressure'->>'memory_available_bytes')::bigint), 0)
       - COALESCE(SUM(p.total_memory_bytes - p.available_memory_bytes), 0)
  FROM nodes p
  WHERE (p.metadata->'pressure'->>'host_id') IS NOT NULL
    AND (p.metadata->'pressure'->>'host_id') = (n.metadata->'pressure'->>'host_id')
    AND p.last_heartbeat >= now() - ($8::bigint * interval '1 second')
    AND (p.metadata->'pressure'->>'memory_available_bytes') IS NOT NULL
) >= $3::bigint
-- The same shape, with disk_available_bytes, total_disk_bytes,
-- available_disk_bytes and $4::bigint.
```

with `$8` bound to `NODE_HEARTBEAT_TTL_SECONDS`, `$3` to the sandbox's memory
demand and `$4` to its disk demand. The subquery is a correlated aggregate over
`nodes`, so it must see every sibling's row at the same snapshot the outer scan
used; take `pg_advisory_xact_lock(hashtextextended('host:' || host_id, 0))`
before the select when a worker is admitted to a placement concurrently with
another placement on the same machine, so two placements cannot each read the
same aggregate and each spend it. `debit_capacity` remains the only writer of
`available_*`, and `release_capacity` its only restorer.

The subtraction is deliberately pessimistic, and the cost is real. The memory
the running sandboxes already hold is *inside* the reading and is counted a
second time, because deciding which worker's sandboxes a reading was taken with
in front of them is not something the control plane can know. A host therefore
gets used to roughly `available / (available + held)` of what it could have
taken, which on a busy host means new placements are refused earlier than
strictly necessary. An idle host pays nothing. This is the direction to be
wrong in: under-booking wastes headroom, over-booking fails tenants' jobs at
boot after their quota has been charged.

### Re-checking immediately before VM create

Pressure is re-read inside `aiec_core::host_pressure::HostPressure::admits`
immediately before the runtime materialises a VM, because a host can fill
between the heartbeat that admitted the placement and the boot that spends it.
The integration point, in the sandbox runtime's `create`, ahead of any
allocation and ahead of writing anything to disk:

```rust
let reserves = HostReserves::from_mib(memory_reserve_mib, disk_reserve_mib);
HostPressure::measure(&state_dir, reserves)
    .admits(u64::from(sandbox.memory_mb) * 1_048_576,
            u64::from(sandbox.disk_mb) * 1_048_576)?;
```

`admits` returns `CoreError::Unavailable` for an incomplete reading, which is
the retryable class the placement loop already treats as transient. It is a
synchronous read of `/proc/meminfo` and one `statvfs` - no probe task and no
detached background work.

## Snapshots and restore


Firecracker worker advertisements must use `https://`. The API/PostgreSQL registration path rejects plaintext Firecracker control endpoints, and the CLI rejects plaintext `--advertise-url` before launch. Terminate TLS with a private-network trust boundary or add native mTLS before treating bearer authentication alone as sufficient identity verification.
Firecracker snapshot memory and VM-state files reference the disk path active when the snapshot was created. AIec stores a checksummed manifest and restores that compatible local disk path before loading state. Do not move snapshots between hosts or Firecracker versions until a supported block-path override is available and verified. S3 supplies durable artifact storage; reconcile completed object uploads whose database transaction failed before relying on automatic crash recovery.

## Network policy

Disabled-network sandboxes have no NIC. Enabled-network sandboxes receive a per-VM TAP and nftables output rules blocking metadata, loopback, and RFC1918 destinations. Production operators must additionally verify host routing/NAT, DNS policy, domain allowlists, egress accounting, and cleanup after crashes. Never bridge these TAPs to the management network.

## Production gate

The opt-in Firecracker runtime test passed locally with Firecracker v1.17.0, the approved uncompressed kernel, a freshly built rootfs, and the retained guest secret; it exercised exec, files, pause/resume, snapshot, destroy, and restore. Production multi-worker deployment and recovery remain blocked on this host because no TLS-terminated worker endpoints are available. Before strangers can execute code, complete live two-worker recovery, failure-injection convergence, rate limits and lifetime quotas, backups/alert rules, TLS/mTLS and secret rotation, vulnerability scanning, and an independent Firecracker/network security assessment.
