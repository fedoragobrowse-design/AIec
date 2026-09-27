# Production deployment

## Host prerequisites

Use dedicated Linux worker hosts with:

- readable/writable `/dev/kvm` for the worker service account;
- Firecracker v1.17+ and optional jailer;
- an AIec-compatible Linux guest kernel and ext4 rootfs;
- `ip(8)`, `nft`, `e2fsck`, and `resize2fs` for network/disk enforcement;
- a cgroup-v2-enabled kernel for predictable Firecracker snapshot performance;
- private connectivity among API, PostgreSQL, S3, and workers.

Docker workers are explicit runtime backends, not a production fallback. Start one with `agentforge worker --runtime docker`; the worker uses the Docker Engine API, advertises `container`, `exec`, and `files` capabilities (`streaming: false`), and registers those capabilities for capability-aware scheduling. Docker containers use a managed workspace bind mount under the configured state root, drop all capabilities, disable privilege escalation, use a read-only root filesystem, and run a long-lived `sh -c 'sleep 3600'` process so exec operations have a stable container process. The default seccomp profile is left to Docker's daemon defaults; restricted network policies fail closed until an egress allowlist backend exists. Docker snapshot capture/restore is currently `UNSUPPORTED`.

Build the local guest artifacts with:

```bash
export AGENTFORGE_GUEST_SECRET="$(openssl rand -hex 32)"
export AGENTFORGE_KERNEL=/var/lib/agentforge/images/vmlinux
scripts/build-firecracker-guest.sh /var/lib/agentforge/images
```

The resulting image starts `/sbin/init`, mounts guest pseudo-filesystems, starts `agentforge-guest`, and listens on vsock port 1024. The secret is baked into the private rootfs and must be protected as a host credential.

## PostgreSQL and S3

The production server runs committed SQLx migrations and refuses to start without `DATABASE_URL`. Use TLS, backups, least privilege, and migration rollback procedures. Configure a private bucket through `AGENTFORGE_S3_ENDPOINT`, region, bucket, prefix, and credentials. S3 requests use AWS Signature V4 and SHA-256 checksums; the bucket must not be public.

## API server

Required configuration:

```bash
export AGENTFORGE_RUNTIME=firecracker
export DATABASE_URL='postgres://...'
export AGENTFORGE_TENANT_ID='<uuid>'
export AGENTFORGE_API_KEY='af_live_<48 hex chars>'
export AGENTFORGE_WORKER_TOKEN='<at least 32 bytes>'
export AGENTFORGE_IMAGE_MANIFEST=/var/lib/agentforge/images/manifest.json
export AGENTFORGE_IMAGE_MANIFEST_SECRET='<protected manifest signing secret>'
export AGENTFORGE_S3_ENDPOINT='https://minio.internal:9000'
export AGENTFORGE_S3_REGION=us-east-1
export AGENTFORGE_S3_BUCKET=agentforge
export AGENTFORGE_S3_ACCESS_KEY_ID='...'
export AGENTFORGE_S3_SECRET_ACCESS_KEY='...'
agentforge-server
```

The production API accepts `AGENTFORGE_RUNTIME=docker` without Firecracker image-manifest variables in that mode. A Docker worker still requires a reachable Docker daemon and a worker registration; the API itself remains a scheduler/control plane. The production launcher does not silently substitute another backend.
Docker containers use an explicit long-lived `sh -c 'sleep 3600'` process rather than preserving the image entrypoint. The private-alpha Docker test image is Alpine and verifies exec, binary files, nested workspace creation, pause/resume, security settings, and cleanup. Operators using other images must provide a shell and `sleep` compatible with that image until configurable process supervision is implemented.
Docker containers use a TTY and keep stdin open to support common image-provided REPL entrypoints. This does not change the runtime API contract: AIec exec remains buffered rather than a streaming PTY protocol.
Docker exec requests are buffered and time-bounded at the API response level, but timeout handling does not yet kill the process tree inside the container. Treat Docker exec process-tree timeout and cleanup as unsupported until container-level termination is implemented.

The systemd API unit starts `agentforge-server`. The shorter `agentforge server` command supports explicit `bwrap-dev` and `docker` single-process development distributions.

## Firecracker workers

```bash
export AGENTFORGE_FIRECRACKER_BIN=/opt/firecracker/firecracker
export AGENTFORGE_KERNEL=/var/lib/agentforge/images/vmlinux
export AGENTFORGE_ROOTFS=/var/lib/agentforge/images/agentforge-rootfs.ext4
export AGENTFORGE_GUEST_SECRET='<same protected secret used to build the rootfs>'
export AGENTFORGE_STATE_DIR=/var/lib/agentforge/firecracker
agentforge --url http://agentforge-api:8080 worker --runtime firecracker --name worker-a \
  --bind 0.0.0.0:9000 --capacity 8
```

The worker endpoint must be reachable only from the API/control network and protected by `AGENTFORGE_WORKER_TOKEN`. Run at least two workers for a multi-node deployment. Worker registration, versioned heartbeats, assignment claims, and lease renewal are persisted in PostgreSQL.

The example units are starting points. A Firecracker worker needs narrowly scoped `/dev/kvm`, network administration, writable VM/snapshot storage, and `NoNewPrivileges=false` or an equivalent reviewed jailer arrangement. API and worker storage should be separate encrypted volumes.

## Snapshots and restore


Firecracker worker advertisements must use `https://`. The API/PostgreSQL registration path rejects plaintext Firecracker control endpoints, and the CLI rejects plaintext `--advertise-url` before launch. Terminate TLS with a private-network trust boundary or add native mTLS before treating bearer authentication alone as sufficient identity verification.
Firecracker snapshot memory and VM-state files reference the disk path active when the snapshot was created. AIec stores a checksummed manifest and restores that compatible local disk path before loading state. Do not move snapshots between hosts or Firecracker versions until a supported block-path override is available and verified. S3 supplies durable artifact storage; reconcile completed object uploads whose database transaction failed before relying on automatic crash recovery.

## Network policy

Disabled-network sandboxes have no NIC. Enabled-network sandboxes receive a per-VM TAP and nftables output rules blocking metadata, loopback, and RFC1918 destinations. Production operators must additionally verify host routing/NAT, DNS policy, domain allowlists, egress accounting, and cleanup after crashes. Never bridge these TAPs to the management network.

## Production gate

The opt-in Firecracker runtime test passed locally with Firecracker v1.17.0, the approved uncompressed kernel, a freshly built rootfs, and the retained guest secret; it exercised exec, files, pause/resume, snapshot, destroy, and restore. Production multi-worker deployment and recovery remain blocked on this host because no TLS-terminated worker endpoints are available. Before strangers can execute code, complete live two-worker recovery, failure-injection convergence, rate limits and lifetime quotas, backups/alert rules, TLS/mTLS and secret rotation, vulnerability scanning, and an independent Firecracker/network security assessment.
