# Production deployment

## Host prerequisites

Use dedicated Linux worker hosts with:

- readable/writable `/dev/kvm` for the worker service account;
- Firecracker v1.17+ and optional jailer;
- an AgentForge-compatible Linux guest kernel and ext4 rootfs;
- `ip(8)`, `nft`, `e2fsck`, and `resize2fs` for network/disk enforcement;
- a cgroup-v2-enabled kernel for predictable Firecracker snapshot performance;
- private connectivity among API, PostgreSQL, S3, and workers.

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
export AGENTFORGE_S3_ENDPOINT='https://minio.internal:9000'
export AGENTFORGE_S3_REGION=us-east-1
export AGENTFORGE_S3_BUCKET=agentforge
export AGENTFORGE_S3_ACCESS_KEY_ID='...'
export AGENTFORGE_S3_SECRET_ACCESS_KEY='...'
agentforge-server
```

There is no production bubblewrap, Docker, in-memory, or local-object-store fallback. Put TLS in front of the private API listener.

## Firecracker workers

```bash
export AGENTFORGE_FIRECRACKER_BIN=/opt/firecracker/firecracker
export AGENTFORGE_KERNEL=/var/lib/agentforge/images/vmlinux
export AGENTFORGE_ROOTFS=/var/lib/agentforge/images/agentforge-rootfs.ext4
export AGENTFORGE_GUEST_SECRET='<same protected secret used to build the rootfs>'
export AGENTFORGE_STATE_DIR=/var/lib/agentforge/firecracker
agentforge worker --runtime firecracker --name worker-a \
  --control-url http://agentforge-api:8080 \
  --bind 0.0.0.0:9000 --capacity 8
```

The worker endpoint must be reachable only from the API/control network and protected by `AGENTFORGE_WORKER_TOKEN`. Run at least two workers for a multi-node deployment. Worker registration, versioned heartbeats, assignment claims, and lease renewal are persisted in PostgreSQL.

The example units are starting points. A Firecracker worker needs narrowly scoped `/dev/kvm`, network administration, writable VM/snapshot storage, and `NoNewPrivileges=false` or an equivalent reviewed jailer arrangement. API and worker storage should be separate encrypted volumes.

## Snapshots and restore

Firecracker snapshot memory and VM-state files reference the disk path active when the snapshot was created. AgentForge stores a checksummed manifest and restores that compatible local disk path before loading state. Do not move snapshots between hosts or Firecracker versions until a supported block-path override is available and verified. S3 supplies durable artifact storage; reconcile completed object uploads whose database transaction failed before relying on automatic crash recovery.

## Network policy

Disabled-network sandboxes have no NIC. Enabled-network sandboxes receive a per-VM TAP and nftables output rules blocking metadata, loopback, and RFC1918 destinations. Production operators must additionally verify host routing/NAT, DNS policy, domain allowlists, egress accounting, and cleanup after crashes. Never bridge these TAPs to the management network.

## Production gate

The real Firecracker integration test passed on the development host, but external review is still mandatory before strangers can execute code. Add rate limits, quotas, image signing, backups, alert rules, TLS, secret rotation, vulnerability scanning, and an independent Firecracker/network security assessment.
