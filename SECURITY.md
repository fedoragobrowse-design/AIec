# Security Policy

AIec runs untrusted, agent-generated code. Isolation is the product, so
this document describes exactly where the boundaries are, what is enforced, and
what is not yet true.

## Supported versions

AIec is in **public alpha**. Security fixes land on the `main` branch and
in the latest tagged release. Older alpha tags are not patched.

| Version | Supported |
|---|---|
| `main` / latest alpha tag | Yes |
| Anything older | No |

There is no SLA and no guaranteed response time during alpha.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Email **security@gobrowse.dev** with:

- what an attacker can do, and what they need in order to do it;
- the affected component (API, runtime, guest, SDK, dashboard, deployment);
- reproduction steps, or a proof of concept;
- the AIec version, runtime (`firecracker`, `docker`, hosted), and
  deployment mode (Cloud or self-hosted) if relevant;
- any logs or request IDs, with secrets redacted.

We will acknowledge within 3 business days, triage within 7, and keep you
updated until a fix or a mitigation is shipped. We will tell you when a report
is declined and why.

There is **no bug bounty**. Do not assume one exists, and do not build a
disclosure strategy that depends on one.

## Threat model

AIec assumes:

- **Workload code is hostile.** Anything an agent writes and executes is
  attacker-controlled.
- **Tenants are mutually hostile.** Tenant A must never observe or influence
  Tenant B's resources.
- **The host is trusted.** The operator's host, database and object store are
  trusted; the workload is not.
- **Availability matters.** A runaway agent must not be able to exhaust the
  platform for other tenants.

Out of scope: attacks on the underlying hypervisor, on the host operating system
where the operator has misconfigured it, and on the Cloudflare/Neon/E2B
infrastructure itself.

## Isolation boundaries

### Public workloads run on Firecracker

AIec Cloud forces Firecracker microVMs for untrusted tenant workloads. A
tenant cannot request `runtime=docker` and downgrade their own isolation
boundary; the control plane's runtime policy is authoritative.

Docker remains available for:

- trusted self-hosted deployments the operator controls,
- local development,
- internal operator tasks.

### Sandbox isolation

Each Firecracker sandbox has:

- its own guest kernel, with no shared kernel surface with other sandboxes;
- its own ext4 root filesystem, created per sandbox and destroyed with it;
- a vsock control channel that never touches the network stack;
- bounded CPU, memory and disk;
- bounded exec wall-clock time and bounded stdout/stderr.

The guest agent executes commands with a fixed `PATH`, an explicit environment,
and a working directory confined to `/workspace`. Guest path handling rejects
traversal and symlink escapes.

### Network isolation

A public sandbox is attached to its own TAP device with an nftables policy that
blocks:

- the host LAN and RFC1918 ranges,
- link-local and cloud metadata addresses (`169.254.169.254`),
- the AIec control plane,
- the worker's management endpoints,
- other tenants' sandboxes.

Public internet egress is permitted according to policy. The
`NetworkPolicy::Restricted` mode **fails closed**: a non-empty host allowlist
without a DNS/IP policy plugin is rejected rather than silently ignored.

### Secrets

Tenant and sandbox secrets are never returned in public metadata, never written
to snapshots, and never included in error messages or audit records. Transient
in-sandbox secret material is destroyed with the sandbox.

**Known limitation:** the guest control secret is a single build-time shared
secret in the current image. Per-sandbox workload secrets are stored in the
control plane and injected at exec time, but the control channel itself is not
yet using per-VM mutual TLS identity.

## What is enforced

- **Authentication.** API keys are stored as hashes, compared in constant time,
  and revocable. Rotation issues a new key and invalidates the old one.
- **Authorization.** Every tenant-scoped query is filtered by the authenticated
  tenant. Possession of a resource ID does not imply authorization.
- **Quotas.** Aggregate vCPU, RAM, disk and active-sandbox quotas are enforced in
  the same transaction as placement, under a per-tenant advisory lock, so
  concurrent creates cannot exceed them.
- **Rate limiting.** The public API is rate limited per authenticated tenant and
  per client address, returning `429` with a machine-readable code and a
  `Retry-After` header.
- **Fencing.** Every state-changing worker operation is checked against the
  durable lease owner and its monotonic fencing generation. A superseded worker
  cannot execute, write, stop, destroy, or complete against a reassigned sandbox.
- **Audit.** Security-relevant operations (API key lifecycle, sandbox lifecycle,
  quota changes, worker registration, authorization denials) are recorded in an
  append-only audit log that database triggers prevent from being rewritten.
- **Usage.** Usage events are append-only and idempotent, so retries and recovery
  do not double-count.

## Known limitations (public alpha)

These are real and are not hidden:

- No SLA, and no guaranteed availability.
- Invite-only, limited-capacity signup during alpha.
- Single execution region.
- Public workloads are Firecracker-only; Docker is not offered to public tenants.
- The API surface is not yet stable; alpha endpoints may change.
- Guest control channel uses a shared build-time secret rather than mutual TLS.
- Per-tenant **snapshot and persistent-storage byte quotas** are not yet
  enforced; per-request size ceilings are.
- **Sandbox lifetime** is enforced by the runtime, and a worker restart resets
  the in-process timer; there is not yet a control-plane lifetime reaper.
- Portable workspace snapshots are the supported recovery unit. **Running VM
  memory does not survive** a worker failure and is not claimed to.
- The audit log is not yet exposed through a dashboard view.
- Multi-host (separate control and worker machines) has not been validated;
  same-host multi-worker recovery has been.

## Hardening guidance for self-hosters

- Terminate TLS with certificates, not the self-signed development defaults.
- Keep the control-plane port, worker management ports, and the MinIO admin
  console off the public internet. A Cloudflare Tunnel or equivalent means you do
  not need to expose the API at all.
- Give PostgreSQL and object storage their own credentials, rotated, and never
  reuse them anywhere else.
- Do not run the Docker runtime for untrusted workloads.
- Keep `nftables`/`ip_forward` enabled if you want sandbox egress, and re-check
  the isolation rules after any kernel or firewall change.
- Back up both the database and the object store, and test the restore.
