# AIec Guard: implementation and evidence report

Every claim below names the artifact or the command that backs it. Where a
property is implemented and tested but has not been observed on the deployment
host, it is written as such rather than as a guarantee.

## Baseline before the work

AIec ran untrusted agent code with a network policy it did not enforce: the
Docker runtime's rules were host-global nftables, there was no credential
substitution, no outbound telemetry, no watcher, and no containment. The
baseline test suite and its results are recorded in the commits before
`5db56ef`; the gate has passed on every commit since.

## Architecture added

| Component | Where | Runs as |
|---|---|---|
| Policy model, compiler, verifier | `crates/aiec-guard/src/{policy,compiler,deployment}.rs` | in-process, outside the guest |
| Packet enforcement (nftables + test backend) | `crates/aiec-guard/src/enforcement.rs`, `crates/aiec-network-linux` | worker host |
| DNS gateway and model broker | `crates/aiec-guard/src/{dns,gateway,gateway/connect}.rs` | worker host |
| Hash-chained telemetry | `crates/aiec-guard/src/events{,/file,/remote}.rs` | worker host, remote sink |
| Watchdog | `crates/aiec-guard/src/watchdog.rs`, `src/bin/aiec-guard-watchdog.rs` | separate host process |
| Durable budgets, incidents, proposals | `crates/aiec-storage`, `crates/aiec-api/src/guard*.rs` | control plane |
| Layer 7 governance, proposals, OpenShell import | `crates/aiec-guard/src/{l7,proposals,openshell}.rs` | worker host + control plane |
| Watcher | `crates/aiec-guard/src/watcher.rs` | host process, optional |
| Canaries, image trust, per-VM identity | `crates/aiec-guard/src/canaries.rs`, `crates/aiec-core/src/image_trust.rs`, `crates/aiec-runtime/src/control_identity.rs` | worker host |

## Trust boundary

The guest may be compromised, the harness may be manipulated, and repository
contents may be malicious. Enforcement, credentials, telemetry and containment
live in processes the guest cannot reach: the worker host installs packet rules
before boot, substitutes the model credential host-side, and an outside-guest
watchdog cuts an attachment that stops reporting. `docs/GUARD_THREAT_MODEL.md`
states what this does and does not defend.

## What each layer does

- **Policy.** Versioned, canonicalized, content-hashed; unknown fields are
  refused rather than ignored, and every set-like list is normalized so two
  documents that mean the same thing hash the same. Templates: `no_network`,
  `model_only`, `model_plus_allowlist`, `read_only_api`.
- **Verifier.** Compiles a policy against the operator boundary and refuses
  contradictions with counterexamples; a proposal is verified before it is
  applied.
- **Enforcement.** One guest egress path; direct IPv4/IPv6, external DNS,
  DoT/DoH, metadata, RFC1918, the control plane, the worker and other
  sandboxes are denied and counted.
- **DNS.** Guard resolves only the policy's zones and record types, so DNS
  cannot be used as a side channel.
- **Model gateway.** Bound destination, method and path; the real credential is
  substituted host-side and never enters the guest.
- **Telemetry.** Bounded metadata only, hash-chained, with an acknowledged head
  that a tail truncation cannot fake.
- **Watchdog.** Deterministic rules over authoritative counters and the verified
  journal. Guest-supplied evidence is never authoritative.
- **Dead-man.** An attachment carries no egress until an identity-matched
  heartbeat installs its rules; losing the watchdog latches a cut, and the
  guest is left alive for forensics rather than destroyed.
- **Quarantine.** One path: cut, fence, pause, forensic capture without
  resuming, durable latch, authoritative event, incident report, notification.
  A repeat call finishes pending stages or returns the existing incident.
- **Budgets and lifetime.** Durable ceilings; a worker restart cannot reset
  them.
- **Layer 7.** Method, path, MCP method/tool and GraphQL operation/root-field
  policy, default deny, applied only where Guard can see the request; TLS
  interception is an explicit operator opt-in.
- **Approvals.** An agent may propose; only a human may approve, and the
  verifier runs first. The high-risk release path has its own scope.
- **Watcher.** Optional, disabled by default, structurally unable to allow,
  approve or release.
- **Canaries.** Synthetic file, hostname and credential tripwires; a fired
  canary holds the attachment cut.
- **Image trust.** Signed manifest and verified kernel/rootfs digests, opt-in,
  refusing boot before the VM starts.
- **Per-VM identity.** Every sandbox gets its own short-lived control secret,
  planted in its own disk and never stored in a portable snapshot.
- **Pre-tool approvals.** A deployment that sets `AIEC_MCP_APPROVAL_REQUIRED=1`
  routes the high-risk tools through the control plane before they run: the
  MCP server asks `POST /v1/sandboxes/{id}/guard/approval` and honours the
  answer. The gate is fail-closed - an approval service that cannot be
  reached refuses, and the refusal is reported as `APPROVAL_REFUSED` with
  `unreachable: true`, so an unanswered ask is distinguishable from a
  decision. The harness cannot supply the answer: the approver is a client of
  the control plane, and the control plane only relays an operator's recorded
  decision. Off by default, because a deployment with no recorded approvals
  would otherwise refuse every destructive tool.

## Evidence

**Phase 1 — `benchmarks/guard-core-acceptance.json`: PASS, 47 cases, 111.5
seconds, no cleanup errors.**
Real Firecracker microVMs, real nftables, local mocks only. Includes the
secret-scan (13.4 GB of memory, state and disk with no copy of the real model
credential) and a case proving an attachment carries traffic only after a
watchdog heartbeat.

**What Guard costs a DNS lookup.** Ten identical A queries, medians of the
batch, measured in the same run on the same host:

| | median |
|---|---:|
| guarded — the guest's system resolver, in the guest, through the gateway | 4.022 ms |
| unguarded — the same A query to a policy-free resolver in the same namespace | 0.034 ms |
| **difference** | **3.987 ms** |

**This is an upper bound, not a policy-engine measurement.** The guarded side
includes the vsock hop and the guest's own resolver stack on top of the policy
check, and the two sides are not the same code path: the unguarded query is a
raw UDP packet from the host, while the guarded one is a real guest resolver
lookup. It bounds Guard's total contribution and does not isolate it, so the
figure should not be quoted as "the cost of enforcement". Two samples in the
guarded batch (26.9 ms and 23.8 ms) are cold first-lookups; the steady state is
the 3.5-4.5 ms cluster the median sits in.

The direct host-to-gateway comparison that would have isolated the gateway's
own cost is not possible: the gateway deliberately answers DNS only for its own
guest, and bypassing that to time it from the host would have meant measuring a
configuration Guard does not offer.

**The incident reproduction.** The sentinel cases above show destinations being
blocked, which on its own cannot separate enforcement from a route that never
existed, a dead mock, or a mistyped address. So the bypass class is reproduced
twice with the same resolver, name and destination:

- **Control leg** — a deliberately unguarded sandbox, general outbound access,
  no Guard config. The guest points itself at a resolver it chose, resolves
  `chatbot.example.test`, and connects. Expected to succeed. The proof is the
  mock chatbot's own hit counter, not the guest's report that it connected: a
  guest reporting success without the destination having seen a connection is
  exactly the failure mode this leg exists to exclude.
- **Guarded legs** — the same attempt under a model-only policy, twice. Once
  against the guest-chosen resolver, which the gateway-DNS permit does not
  cover, so the packet is dropped and an nft counter moves. Once against the
  gateway itself, which the gateway answers and then refuses the unapproved
  name with a recorded `DNS name denied` — the leg that ties the reproduction to
  a policy decision rather than to a default-deny that would have fired anyway.

Both legs assert on host-owned evidence only: nft counters and the hash-chained
event journal, neither writable by the guest. The chatbot is not reached during
the guarded legs, asserted by the same counter the control leg incremented.

The control leg needs one unguarded sandbox, which is the one thing the main
acceptance must never contain, so it is opt-in: `AIEC_REPRO_LEGACY_CONTROL=1`
makes the launcher set `AIEC_ALLOW_LEGACY_NETWORK=1`. The launcher unsets both
by default, so an operator who exported the variable beforehand still cannot
get an unguarded guest into an ordinary run. Without the flag the guarded legs
still run and their results are still real, but they cannot be attributed to
Guard rather than to a route that never existed — and the artifact records the
control leg as absent rather than implying it was covered.

Observed, with the control leg enabled: the unguarded guest resolved
`chatbot.example.test` through the resolver it chose and the mock chatbot
answered `HTTP/1.1 200 OK`, its hit counter at 1. Under Guard the same guest got
`resolved: false` at the `resolve` stage with `deny_delta: 1` from the nft
counter, and the chatbot counter did not move. Asked through the gateway instead
of through its own resolver, it got `rcode: 5` (`REFUSED`) with zero answers, and
the gateway wrote a chain-linked denial naming `chatbot.example.test`.

The reproduction deliberately produces one denial, not a burst, so it does not
cross a rule threshold and no quarantine is raised. That path is covered by the
phase 2 run above, where a triggered rule is taken all the way to
`completed_at`; the reproduction's job is to establish that the request is
blocked at all, which is the precondition the threshold logic sits behind.

**Phase 2 — `benchmarks/guard-phase2-acceptance.json`: PASS, 28 cases, no
cleanup errors, 77 seconds.** Real control plane, worker, guest, watchdog
process, database and kernel tables. Observed: guarded start; a narrowly-scoped
watchdog key that cannot create sandboxes; anchored telemetry; a real watchdog
holding the attachment live; authoritative denials reaching the watchdog; a
triggered rule; the full quarantine chain to `completed_at`; resume refused;
a repeat quarantine returning the same incident; a worker restart leaving the
quarantine in force; and the sandbox held rather than orphaned.

**Static gates.** `scripts/gate.sh` passes: `fmt`, clippy with `-D warnings`,
the full workspace test suite (875 tests) including the Postgres paths, the SDK
import contract, 44 Python SDK tests, and an `aarch64-unknown-linux-gnu`
cross-check of every target. A step that cannot run reports `SKIPPED` rather
than `ok`.

## Defects the acceptance work found and fixed

The live runs were worth more than the unit tests: a watchdog that would not
heartbeat a cut attachment (a self-sustaining deadlock with zero heartbeats
across 382 observations); a fence compared for equality across lease renewals;
incidents persisted without a verifiable evidence anchor; an evidence refresh
that rewrote the anchor it was supposed to extend; a capture that could not be
retried after the pause; a quarantine endpoint holding an HTTP request open
across a multi-minute capture; refusals surfacing as TCP resets; an operator cut
indistinguishable from a dead-man latch; a gateway shutdown that could not
complete; a canary cut undone by the next heartbeat; a hostname matcher
inverted so that subdomains did not match and unrelated domains did.

## Known limitations

1. **Resolved as a blocker; the rebuilt image is not yet deployed.** The
   deployed `agentforge-rootfs.ext4` carries a guest agent that predates the
   per-sandbox control identity, so a guarded machine failed to boot with
   `early eof` against the new host. A new image was built with
   `scripts/build-firecracker-guest.sh` - the script remains the only writer of
   the recorded digests - using `AIEC_GUEST_BINARY` for a guest agent compiled by
   `scripts/guest-musl-build.Dockerfile`, because this workstation has the musl
   target but no musl C toolchain for the two crates in the guest's graph that
   compile C in their build scripts. Root filesystem
   `4af9ced62fe8f0fcaa6baef1a63fc68b46baf2fd5f442cf6174443373cd26eff`, guest
   agent `d6996c41b774b3c810a6ba195b49803e2241a4a768d27694ac4c4979f1306775`,
   built 2026-10-02T02:48:56Z. **The still-deployed
   `agentforge-rootfs.ext4` was not replaced**: the image built here lives
   beside it, and deploying it is the operator's step.
2. **The lifetime reaper has never been observed firing.** The ceilings are
   durable and restart-proof (Postgres tests); the reaper's action is untested
   against a live run, and the in-process timer still races it for the guest VM.
3. **The production Firecracker worker on this host cannot enforce Guard.**
   `aiec-worker.service` runs as an unprivileged user with no `CAP_NET_ADMIN`,
   so every governed placement is refused and `network_policy` reads false.
4. **Resolved: a guest packet reaches `GuardNetworkManager::create_guard`'s
   attachment and is denied there.** The driver records the host's own view of
   the attachment alongside the counters. In the 28/28 run the TAP was
   `UP,LOWER_UP`, carried its /30 address, and had a neighbour entry for the
   guest, while Guard's own table counted `blocked_range: 3` - so the packets
   arrived, were denied by the ruleset, and the denial was what the watchdog
   then acted on. Phase 1 still exercises its counters on driver-created TAPs;
   this is the first run in which the manager's own attachment is the one under
   test.
5. **Layer 7 rules need interception to see a request.** In the default SNI
   mode Guard matches the requested name and forwards the tunnel; a CONNECT
   tunnel to a governed host is refused rather than forwarded ungoverned.
6. **The approval hook is wired; no approval is ever granted.** The gate is
   now in the production dispatch path, fail-closed, and its refusal is
   distinguishable from an unanswered ask. What does not exist is the other
   half: the control plane has no queue for a human to answer, so every
   high-risk tool is refused. The hook is proven to deny, not to admit.
7. **Multi-host deployment modes are documented, not validated.** The hardening
   decision for a separate gateway host is untested.
8. **aarch64 is compile-verified, not run-verified.** The gate cross-checks the
   whole workspace for `aarch64-unknown-linux-gnu` and it is clean; that found
   and fixed a real bug, a `gethostname` buffer typed `i8` where aarch64's
   `c_char` is `u8`. No aarch64 machine is part of the evidence: nothing was
   executed there, no performance number was taken there, and the guest image
   has only ever been built for x86_64.

## Environment findings for the operator

- The deployment's Neon `DATABASE_URL` password was printed into a working
  session while the acceptance was being set up. **Rotate it.**
- Local build artifacts reached 156 GB; the incremental cache has since been
  purged and builds run with `CARGO_INCREMENTAL=0`.

## Rebuilding the guest image

The path that produced the artifacts above, and the one to repeat when the
guest agent changes:

```bash
# 1. Compile the guest statically. The image needs a C compiler as well as
#    musl-tools: two crates in the guest's graph compile C in their build
#    scripts, and without one the build dies at portable-atomic before any
#    guest code is reached.
docker build -f scripts/guest-musl-build.Dockerfile -t aiec-guest-musl .
docker create --name af-guest aiec-guest-musl
docker cp af-guest:/out-aiec-guest ./aiec-guest
docker rm af-guest
file ./aiec-guest        # must say static(-pie) linked

# 2. Build the image with the script that owns the recorded digests. On a host
#    with no Rust toolchain, step 1's binary is all it needs: `cargo` is only
#    required when the script compiles the guest itself. It refuses a binary
#    that is not statically linked, and one that cannot read the planted
#    control identity, so a stale agent cannot be baked into an image whose
#    digest is about to be trusted.
AIEC_GUEST_BINARY=$PWD/aiec-guest \
AIEC_GUEST_SECRET=$(openssl rand -hex 32) \
AIEC_KERNEL=/path/to/vmlinux \
AIEC_OUT=$PWD/out \
  bash scripts/build-firecracker-guest.sh

# 3. Point the acceptances at the new image and its manifest together.
export AIEC_ROOTFS=$PWD/out/aiec-rootfs.ext4
export AIEC_GUEST_ARTIFACT_DIR=$PWD/out
```

## Exact commands

```bash
# Static gates
bash scripts/gate.sh

# Phase 1: real microVMs, real nftables (needs an acceptance rootfs with iproute2)
cargo build --release -p aiec-runtime --example guard_core_acceptance
AIEC_ROOTFS=<acceptance rootfs> TMPDIR=<short scratch> \
  bash scripts/guard-core-acceptance.sh ./target/release/examples/guard_core_acceptance

# Phase 2: control plane, worker, guest, watchdog, database, all disposable
cargo build --release -p aiec-api --bin aiec-server -p aiec-cli --bin aiec \
  -p aiec-guard --bin aiec-guard-watchdog
P2_DRIVER=$PWD/scripts/guard-phase2-acceptance.py \
  bash scripts/guard-phase2-acceptance.sh

# After any guest-image change, before booting a guarded sandbox
bash scripts/build-firecracker-guest.sh
```

## Verdict

**AIEC GUARD: PHASES 1-2 PROVEN LIVE; PHASES 3-5 IMPLEMENTED, NOT YET PROVEN LIVE**

Phases 1 and 2 run on real Firecracker machines against one image whose digest
is a consequence of the build that wrote it: 41/41 and 28/28, no cleanup
errors. That includes the packet path that was previously undecided - a guest
packet reaches `GuardNetworkManager::create_guard`'s own attachment and is
denied there - and the guest identity path that was previously unbootable.

Phases 3 to 5 are implemented and covered by unit and integration tests, with
their acceptance exercised against local mocks rather than real machines. Two
green artifacts do not make that whole surface proven, and the two are kept
apart on purpose.

Still outstanding, from the limitations above: items 2 to 8 - the lifetime
reaper has never fired in a live run, `CAP_NET_ADMIN` is absent from the
production worker on this host, layer 7 needs interception to govern a
tunnelled request, the approval hook denies but has never admitted, multi-host
deployment modes are documented but unvalidated, and aarch64 is compiled but
never run. Two of those are operator actions rather than code: deploying the
rebuilt image, and granting the worker `CAP_NET_ADMIN`.