# Security and threat model

AgentForge treats every tenant workload as hostile. `bwrap-dev` is retained only for local development and is not a production boundary.

## Implemented controls

- Firecracker/KVM production mode with no automatic runtime fallback.
- Minimal ext4 guest, read-only system tools, private `/workspace`, argv exec, and resource limits.
- HMAC-SHA256 authenticated version 1 guest protocol, 2 MiB frame cap, UUID request IDs, constant-time tag checks, and per-connection replay rejection.
- Guest file operations canonicalize paths and reject traversal and symlink escape outside `/workspace`.
- Firecracker-enforced vCPU/RAM, ext4 disk sizing, guest command timeout/output/upload caps, and worker lifetime stop.
- Per-VM TAP plus nftables blocks for metadata, loopback, and RFC1918 destinations when network is enabled; no NIC when disabled.
- Hashed/scoped/rotatable API keys, PostgreSQL tenant ownership, and no cross-tenant object access.
- Constant-time authenticated worker RPC, request IDs, bounded responses, and idempotent operation replay.
- PostgreSQL CAS transitions, transition events, row locks, `SKIP LOCKED`, monotonic worker versions, fenced/renewable leases, and reconciliation history.
- S3 Signature V4, SHA-256 checksums, safe keys, and explicit development-only filesystem object storage.
- Firecracker full memory/device snapshots plus checksummed disk copies and restore validation.

## Threats still requiring deployment controls

- VM escape, Firecracker CVEs, malicious kernels, and jailer misconfiguration require independent review and prompt patching.
- The guest image contains a shared HMAC secret. Per-tenant guest secrets, secret rotation, and compromise containment are not implemented.
- Snapshot restore is worker-local with Firecracker 1.17 because block-path override is not yet released.
- Enabled networking blocks broad private/metadata ranges but has no domain allowlist, DNS policy, bandwidth quota, or egress accounting.
- No rate limiting, organization quotas, malware scanning, signed images, billing enforcement, or HSM-backed secrets.
- Worker/API endpoints require private network placement and TLS termination.
- Object-success/database-failed snapshot operations need a reconciliation controller.
- Bubblewrap must never face untrusted public workloads.
- No independent penetration test or production certification has occurred.

Report vulnerabilities privately. Do not include exploit details in public issues.
