# Guard operations

Guard is optional per sandbox and on by default for Firecracker. This guide
covers what an operator runs, what they observe, and what they must decide.

## What runs, and where

| Component | Where | Runs as |
|---|---|---|
| Guard packet rules (nftables) | worker host, per attachment | worker |
| Guard gateway (DNS, model broker, credentials) | worker host, per attachment | worker |
| `aiec-guard-watchdog` | outside the guest, one per guarded sandbox | operator service |
| Budget, lifetime and incident state | control plane database | control plane |

Nothing in this list runs inside the guest, and nothing in it is reachable from
the guest's network.

## Enabling Guard

Guard is attached by the sandbox's `guard` configuration:

```yaml
resources:
  guard:
    topology: inside            # or `outside` for topology B
    policy_template: model_only
    model_endpoint:
      host: api.model.example
      port: 443
      scheme: https
      allowed_methods: [POST]
      allowed_paths: ["/v1/chat/completions"]
      credential: model-main
    watchdog_timeout_ms: 10000  # 1000..60000; the dead-man deadline
    max_model_requests: 10000   # immutable durable ceiling
```

`no_network`, `model_only`, `model_plus_allowlist` and `read_only_api` are the
built-in templates. An explicit `policy` replaces the template. Guard requires
the Firecracker runtime and refuses a guarded sandbox on a weaker one by
default. Setting `AIEC_ALLOW_REDUCED_ISOLATION=1` on the control plane accepts
the weaker boundary deliberately; the creation response then carries an
`x-aiec-isolation` header naming what was given up, so the downgrade is visible
to whoever reads the sandbox rather than buried in a log.

The guest receives `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (both cases) and an
empty `NO_PROXY`, plus an `AIEC_AGENT_API_KEY` placeholder. Nothing else in the
guest's environment is needed for governance.

## The watchdog

One process per guarded sandbox, started outside the guest:

```bash
aiec-guard-watchdog \
  --control-plane https://api.internal:8443 \
  --sandbox-id  "$SANDBOX" \
  --tenant-id    "$TENANT" \
  --policy-hash  "$POLICY_HASH" \
  --token-file   /etc/aiec/guard-watchdog.token \
  --config       /etc/aiec/guard-watchdog.json \
  --control-plane-ca-cert /etc/aiec/tls/ca.crt
```

The token must carry `guard:read`, `guard:heartbeat` and `guard:quarantine`, and
nothing else. An ordinary tenant key will not do: it would be refused on the
first poll and the dead-man switch would cut the sandbox.

The watchdog polls authoritative telemetry, verifies the journal against its
acknowledged head, and heartbeats only on an observation it could verify. It may
request a quarantine; it can never approve a policy or release one.

**Dead-man behaviour.** An attachment starts deny-all. The first heartbeat
installs its rules. If heartbeats stop for `watchdog_timeout_ms`, the gateway
and the kernel rules cut the attachment and the cut latches. The guest is not
destroyed: an operator may still pause it and take a forensic capture.

## Incident reports and notification

A quarantine writes a Markdown report into the durable incident record and, if
`AIEC_GUARD_WEBHOOK_URL` is set, posts a secret-free notification. The webhook
receives the incident id, identity, rules, and stage timestamps; it does not
receive reasons, destinations, evidence or the report body. Without a webhook
the notifier is explicitly disabled, and a completed incident says so rather
than claiming delivery.

## Budgets and lifetime

Model requests and bytes are reserved against the control plane before they are
forwarded. Ceilings and expiry are immutable once written, so a worker restart
cannot hand a machine a fresh allowance. A sandbox whose lifetime expires, or
whose model budget is spent, is quarantined by the control-plane reaper rather
than destroyed.

## Privileges

A worker that installs Guard rules needs `CAP_NET_ADMIN` for nftables and TUN/TAP.
A worker without it advertises `network_policy: false` and refuses every
governed placement - visibly, and correctly. This is worth checking before a
deployment is declared protected:

```bash
# `nft list tables` shows whether Guard's rules are installed on this host.
# `aiec doctor` reports runtime prerequisites, not Guard state.
nft list tables | grep aiec_guard
```

## Approving a high-risk call

Guard refuses by default. A small number of calls are refused *pending a human
decision*, and those go through a two-phase exchange so that the answer comes
from a person rather than from the caller.

The two phases are separate endpoints with separate scopes, on purpose. Asking
needs only `SandboxesWrite`, because a harness must be able to ask; deciding
needs `GuardApprove`, because deciding is an operator's act and not a caller's.

```
POST /v1/sandboxes/{id}/guard/approval              # ask, needs SandboxesWrite
GET  /v1/sandboxes/{id}/guard/tool-approvals        # the operator's queue, needs GuardApprove
POST /v1/sandboxes/{id}/guard/tool-approvals        # decide, needs GuardApprove
```

An ask carries the sandbox, the tool, and `digest` — a SHA-256 over the
canonical JSON of that one call's arguments, hex encoded. The digest is what
makes an approval an approval *of a call* rather than of a tool. An operator
who permitted `write_file("/etc/rc", A)` did not permit `write_file("/etc/rc",
B)`, and the request body has no field that could persuade the control plane
otherwise. `digest` is required, and a request without one is refused.

Asking returns a refusal, never a wait: the caller is told `approved: false`,
and the request is recorded as `pending`. Nothing polls.

Deciding takes the `request_id` from the queue and a `decision` of `granted` or
`denied`. The recorded requester comes from the authenticated principal, never
from the body, so a caller cannot nominate who decides for it.

Three properties are enforced in the database, beneath the API:

- **Self-approval is refused.** A key holding both `SandboxesWrite` and
  `GuardApprove`, or `Admin`, still cannot decide its own request. This is a
  constraint on `requested_by_key_id`, not on scope names, because one
  principal can hold both scopes. The API returns one `409` for unknown,
  already-decided and self-approval alike, so probing for authority reveals
  nothing.
- **A grant is spent once.** Spending is a single conditional `UPDATE` that
  requires the row to be unconsumed, granted, unexpired and written by this
  requester. Two concurrent spends cannot both match the same row.
- **A grant belongs to the key that asked.** Another key in the same tenant
  holding `SandboxesWrite` cannot spend an approval a different harness
  requested.

The digest is defined once, in `aiec_core::approval_request_digest`: the tool
name, a NUL byte, and the canonical JSON of the arguments, SHA-256'd and hex
encoded. A pinned test holds the expected value for a fixed call, because the
acceptance suite implements the same rule in Python and is only meaningful as
an independent check if the two cannot drift apart silently. The separator is
spelled out because getting it wrong is not a loud failure — a client that
guessed a newline would present a digest no call ever matches, and its grant
would simply never be spendable.

The queue is readable only with `GuardApprove`. It has to be: an operator
cannot decide what they cannot see, and without it `request_id` would only be
discoverable by reading the table directly.

### What has actually been run

`benchmarks/guard-approval-acceptance.json` — 10 cases, all passing, no
cleanup errors, against the release binaries over HTTPS with PostgreSQL as the
store. The suite runs the control plane and a worker on a database of its own
and drives the flow over HTTP only; no case reads the table to decide whether
it passed, because "the row says so" is a weaker claim than "the next call was
allowed and the one after it was refused".

It mints its keys per run, so the scope and identity properties are tested
against the narrowest keys that can play each part: a harness holding only
`SandboxesWrite`, an operator holding only `GuardApprove`, and one holding
every scope. Three properties are worth recording, because each is a way the
suite would otherwise have passed for the wrong reason.

- The self-approval case asserts that the decider's key id **equals the
  requester's recorded key id**, read back from the account API rather than
  assumed from the mint. Approving another key's request is an operator's job,
  not a self-approval; a test that reused another harness's request would pass
  with the constraint removed.
- The all-scopes key is refused `409` on a request it raised itself, and
  refused `403` by the narrow key before reaching the approval check at all.
  Two different refusals, and conflating them would hide which one is doing
  the work.
- Replay and changed-content are separate cases. An approval that survived a
  replay, or that covered a changed payload, would each pass while looking
  like a successful grant.

Underneath, `crates/aiec-storage/src/postgres/guard/approvals.rs` runs eleven
cases against a real PostgreSQL, two of which write directly to the table so
the only thing that can refuse them is the migration's own trigger: a
self-approval, and a requester rewritten after the fact.

Tools not classified as safe are refused until somebody classifies them. The
allowlist is small and explicit (`sandbox.get`, `sandbox.read_file`,
`sandbox.list_files`, `sandbox.list_owned`, `secret.list`, `snapshot.list`), so
a tool added tomorrow fails closed rather than open.

The MCP server opts into this with `AIEC_MCP_APPROVAL_REQUIRED=1`. It is off by
default because switching it on denies destructive tools to every existing MCP
client at once. Once enabled it fails closed: an unreachable control plane is a
refusal, and the refusal distinguishes an unanswered request (`unreachable:
true`) from an explicit denial so an operator can tell the two apart.

## Hardware

The gate compiles the whole workspace for `aarch64-unknown-linux-gnu` as well
as the host architecture, so an x86_64 build cannot hide an aarch64-only type
error. That check found one: a `gethostname` buffer typed `i8`, which is
correct on x86_64 and wrong on aarch64, where `c_char` is `u8`. It is now
typed as `c_char` and the workspace cross-checks clean.

**What this is and is not.** It is a compile check of every target, including
tests and examples. It is not a run: no aarch64 machine, emulator or
Firecracker-on-aarch64 run is part of the evidence, and no performance number
here was taken on aarch64. The guest image build is a separate matter and
still has only been produced for x86_64; `scripts/build-firecracker-guest.sh`
builds whatever host it runs on and has not been run on aarch64.

The cross-check needs a C toolchain for the target, which the host does not
have and cannot install without root, so it runs in
`ghcr.io/cross-rs/aarch64-unknown-linux-gnu`. Where Docker is unavailable the
step reports `SKIPPED` rather than `ok`; `AIEC_SKIP_CROSS=1` skips it
deliberately.

## Deployment modes

- **Worker-host hardened process** (default). The gateway and the rules live on
  the worker. A root attacker on that host defeats the boundary.
- **Separate gateway VM.** The gateway runs on its own machine. Worker
  compromise no longer reaches the credential, at the cost of a network hop and
  an extra hardened host.
- **Separate physical gateway.** The same, with a small dedicated appliance.
  Higher operational cost, narrower blast radius.

The modes are not equivalent and are not claimed to be.

**Only the first is implemented.** The worker allocates the gateway's `/30`
from its own host address space and runs the gateway in-process on that
address, so there is no setting that points a guest's gateway at another
machine. Modes B and C are the deployment shapes this design supports and the
trust properties they would change; neither has a code path or has been
validated. Treat them as design intent, not as a feature.

## Operating checks

```bash
aiec guard show <sandbox>          # policy hash, attachment, budgets, incident
aiec guard events <sandbox>        # verified journal entries
aiec guard quarantine <sandbox>    # operator-initiated quarantine
aiec guard release <sandbox>       # operator release of a held sandbox
aiec guard proposals               # pending policy proposals
aiec guard proposal approve <id>   # human only; runs the verifier first
aiec guard proposal deny <id>
aiec guard verify <policy>         # compile and verify without applying
aiec guard import-openshell <file>
```

## Guest images and per-sandbox identities

A guarded sandbox authenticates its control channel with a per-sandbox identity
that the worker issues when the machine is created and plants in the sandbox's
own disk. The guest reads it from `/etc/aiec-guest-secret`; an image built
before that file existed falls back to the build-time `AIEC_GUEST_SECRET`.

The two sides must agree. A guest image that predates the planted identity will
authenticate with the shared build-time secret while the host uses the
per-sandbox one, and the machine will fail to boot with an unexplained
handshake error. **Rebuild the guest image after this change** (`scripts/build-firecracker-guest.sh`);
`benchmarks/guard-core-acceptance.json` was produced against images that do not
yet read the planted file.

## What to read next

`docs/GUARD_POLICY.md` for the policy format and what each field means, and
`docs/GUARD_THREAT_MODEL.md` for what is and is not defended.