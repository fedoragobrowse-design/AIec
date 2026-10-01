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

AIec's runtime policy forces Firecracker microVMs for untrusted workloads. A
tenant cannot request `runtime=docker` and downgrade their own isolation
boundary; the control plane's policy is authoritative. There is no hosted
deployment, so this is a property of the software you run rather than a promise
about someone else's cluster.

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

**The default is no network at all.** A public sandbox is attached to its own
TAP device, and on that interface nftables permits exactly one path: the
Guard gateway on the guest's DNS and broker ports. Everything else is dropped -
the host LAN, RFC1918 and other private ranges, link-local and cloud metadata
addresses (`169.254.169.254`), the AIec control plane, the worker's management
endpoints, every other tenant's sandbox, all IPv6, and all forwarding in either
direction. No NAT is involved, and no rule accepts on connection state, so a cut
takes effect against a flow that was already established.

There is no implicit "internet" mode. A sandbox that asks for a network without
selecting a Guard policy is **refused**, not quietly filtered and not quietly
granted. The pre-Guard network backend exists only when the operator asks for it
by name, with `AIEC_ALLOW_LEGACY_NETWORK=1`; that is the one supported way to get
an ungoverned attachment, and it is off by default because a deployment that
believes it is filtered and is not is worse than one that is openly unfiltered.

`NetworkPolicy::Restricted` **fails closed**: a non-empty host allowlist without
a DNS/IP policy plugin is rejected rather than silently ignored.

### Guard: governance outside the guest

Guard moves the decisions out of the machine. Policy, the network gateway, the
credentials and the evidence journal all live on the worker, so a fully
compromised guest cannot widen its own permissions or rewrite its own record.
This is a different boundary from microVM isolation, and it is additive: the
same sandbox, lease and lifecycle paths serve guarded and unguarded workloads.

For a guarded sandbox the worker installs per-attachment nftables rules that
permit exactly one path, from the assigned guest source to the gateway's DNS
and broker ports, and drop everything else on that interface - including
forwarding in both directions, any other source, and all IPv6. No accept is
made on connection state, so a cut takes effect against a flow that was already
established. Guard owns only the two tables it created for one attachment and
never references a host table.

Model credentials never enter the guest. The guest holds a
`placeholder://<binding>`, the gateway substitutes the real secret outside the
machine, and DNS for the model name resolves to the gateway so the guest cannot
open a direct connection to the provider. Secrets are not arguments, not part of
a sandbox or run document, and not written into an image, environment or
snapshot.

Guard's honest limits:

- **Opaque TLS is not inspected.** A `CONNECT` tunnel is permitted only for
  destination-only rules, with a validated visible SNI, and refuses ECH, early
  data, and a missing or duplicated server name. A rule that needs method, path
  or tool visibility is refused on that path rather than quietly unenforced.
- **Prompts are not a data-loss boundary.** Model prompts remain an information
  channel, and Guard does not perform complete DLP.
- **Host or gateway compromise defeats it.** Enforcement here is
  software-only.
- **The journal proves integrity, not completeness.** A hash chain detects
  mutation, reordering and interior deletion; it cannot by itself detect a
  removed tail, so the remote sink's acknowledged head is the anchor to check.
- **Per-VM control identity and durable budgets are later phases.** Until then
  the gateway's byte and rate budgets are process-scoped and lost on restart.

An unreadable, truncated or unreplayable journal is refused rather than
repaired, and a journal that cannot be written cuts the gateway: recovering a
sink is not recovering a gateway. See [`GUARD_POLICY.md`](GUARD_POLICY.md).

### Secrets

Tenant and sandbox secrets are never returned in public metadata, never written
to snapshots, and never included in error messages or audit records. Transient
in-sandbox secret material is destroyed with the sandbox.

**Run secrets are names, not values.** `POST /v1/runs` accepts
`workload.secrets` as a list of secret *names*. The workload document is
durable — it is stored with the run, copied into attempts and the event log,
and returned by `GET /v1/runs/{id}` — so a value written there is a value in a
backup, a replica and an audit trail. The control plane resolves the names into
values immediately before a command is executed inside the machine, injects
them through the same `environment` map as any other setting, and stores them
nowhere.

#### Deployment format

Values come from a directory named by `AIEC_RUN_SECRETS_DIR`, one file per
tenant, named after the tenant UUID:

```text
$AIEC_RUN_SECRETS_DIR/
├── <tenant-uuid>.json
└── <another-tenant-uuid>.json
```

```json
{
  "tenant_id": "0f6c1d2e-6f3a-7c1b-9a55-2f0f1d3b4c5a",
  "secrets": {
    "GITHUB_TOKEN": "ghp_..."
  }
}
```

`tenant_id` inside the file must match the tenant that is asking, so a file
copied into the wrong tenant's slot is refused instead of handing one tenant
another's credentials.

```bash
install -d -m 0700 -o aiec -g aiec /var/lib/aiec/run-secrets
install -m 0600 -o aiec -g aiec /root/tenant.json \
  /var/lib/aiec/run-secrets/0f6c1d2e-6f3a-7c1b-9a55-2f0f1d3b4c5a.json
export AIEC_RUN_SECRETS_DIR=/var/lib/aiec/run-secrets
```

The directory and every file in it must be owned by the user running the API
and must not be group- or world-accessible: mode `0700` for the directory,
`0600` for the file. A file or directory with any group or other bit set is
refused, a symlink is refused, and a file larger than 64 KiB, declaring more than
32 names, or holding an empty or NUL-bearing value is refused. The API refuses
to start if the directory is configured but unusable.

There is no network call, no vault client and no shared guest path involved: a
secret reaches the guest only as a process environment variable, and a value
rotated on disk is used by the next run without restarting anything.

#### What is refused, and when

- A run requesting no secrets works with no store configured at all.
- A run requesting a secret with no store configured is rejected before a
  machine is placed. It is never given a placeholder or an empty value.
- A name that is not a valid environment variable (uppercase ASCII, digits and
  underscores, up to 64 characters) is rejected before any machine is placed.
- A name the tenant has no value for is rejected before any machine is placed,
  naming the reference so the request can be corrected. A name is not itself a
  secret.
- A name already present in the command's environment — the workload's own
  `environment`, or a per-sandbox secret — is rejected. Neither is allowed to
  win silently, because a literal in the run document is exactly what must not
  be stored.

#### No read API

There is no endpoint that returns a run secret's value, to any caller, in any
role. `GET /v1/runs/{id}` and the event stream return names only. Captured
command output is scrubbed of resolved values before it is stored, bounded to
8 KiB per stream; error messages are scrubbed while keeping their error type,
so a caller can still branch on *why* a run failed.

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

- No SLA, and no guaranteed availability. You run the cluster.
- There is no hosted offering, so availability is entirely yours to provide.
- Recovery and fencing are proven with two workers on one host. Genuinely
  distributed operation across separate machines is not yet demonstrated.
- The API surface is not yet stable; endpoints may change.
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
- Keep `$AIEC_RUN_SECRETS_DIR` (`0700`, one `0600` file per tenant) readable
  only by the service account, excluded from backups you do not control, and
  rotated by rewriting the file — the next run picks it up without a restart.
- Do not run the Docker runtime for untrusted workloads.
- Keep `nftables`/`ip_forward` enabled if you want sandbox egress, and re-check
  the isolation rules after any kernel or firewall change.
- Back up both the database and the object store, and test the restore.
