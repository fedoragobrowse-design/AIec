# Roadmap

Near-term production gates: complete Firecracker vsock guest operations; S3/MinIO adapter; jailer/TAP lifecycle; nftables egress policy; transactional multi-worker reservations; durable API-key management; rate limits; quotas; snapshot signing/scanning; backups; metrics/alerting; professional security review.

## DSec-derived future architecture

The following are future parity targets from *DeepSeek Elastic Compute (DSec): A Sandbox Infrastructure for Effective Agentic Training at Scale*, not claims about the current AIec implementation. They are derived from DSec §§3.3, 5.1, 5.2, and 5.3:

- **Nested isolation boundary:** evaluate QEMU/libvirt as the isolation boundary for container workloads rather than running Docker directly on the host kernel (DSec §3.3).
- **Node-local admission and session model:** add an edge-local admission/launcher component plus aether/chronus-equivalent session proxies, health monitoring, concurrent sessions, and process-tree termination (DSec §3.3).
- **Composable layers:** materialize independent base, workspace, and toolkit layers with immutable EROFS lower layers, overlayfs semantics, and a local writable upper layer (DSec §5.1).
- **Scalable image distribution:** use 3FS-compatible shared image data with local metadata/writes and on-demand, bulk read loading; preserve compatibility with OCI-to-EROFS conversion (DSec §3.3, §5.3).
- **Writable storage and snapshots:** evaluate OverlayBD-backed writable disks and incremental snapshots for the microVM path (DSec §3.3, §5.1).
- **High-density resource management:** evaluate virtio-pmem/DAX, DAMON plus virtio-balloon free-page reporting, and QoS-aware CPU/core scheduling for latency-sensitive versus best-effort work (DSec §5.2).

The current host-Docker MVP intentionally implements none of these nested-VM, proxy, layer, image-distribution, storage, or QoS mechanisms. Keep them separate from current `PARTIAL`, `BLOCKED_BY_ENVIRONMENT`, and `UNSUPPORTED` evidence until each has an implemented path and executed validation.

Commercial follow-ons: organizations and projects, reservations and warm pools, image registry/build service, signed custom images, region-aware scheduling, persistent workspaces, git worktrees, secrets injection with audit, GPU and browser sandboxes, PTY/WebSocket terminals, snapshot dedup, batch APIs, and organization invoicing. Implement in measured order; do not promise DeepSeek-scale performance for a small cluster.
