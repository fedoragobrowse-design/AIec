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
aiec doctor --json | grep network_policy
nft list tables | grep aiec_guard
```

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