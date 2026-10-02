# Guard threat model

Guard governs the authority and communications of agent sandboxes from outside
the guest. This document states what that does and does not defend against, in
the terms a reader can check against the code and the acceptance runs.

## The separation Guard depends on

```
AIec control plane  ── places, fences, budgets, quarantine
AIec worker         ── owns the microVM and the Guard attachment
AIec Guard gateway ── DNS, model broker, credentials, packet rules
AIec Watchdog       ── observes authoritative telemetry, requests quarantine
guest               ── the agent's computer; not trusted
```

The sandbox may be compromised. The harness inside it may be compromised. The
repository contents may be malicious. What still holds is that the network and
credential boundary is enforced by processes the guest cannot reach or modify -
and only that. It is a statement about where enforcement runs, not about what a
host-level attacker can do afterwards; see 'What Guard does not defend' below.

## Assets

| Asset | Where it lives | Who must not reach it |
|---|---|---|
| Model provider credential | worker-side credential file | the guest, always |
| Any tenant secret | control-plane secret store | the guest, always |
| Policy and its hash | durable control-plane state | the guest, always |
| Guard journal | worker-side file plus remote sink | the guest, always |
| Host network stack | kernel | the guest, always |
| Other sandboxes | other attachments | this guest |
| The control plane | host | the guest |

## Adversaries

1. **A compromised guest.** Arbitrary code as the sandbox user, arbitrary
   syscalls, arbitrary packets.
2. **A compromised harness.** The model's tool-calling loop is attacker-
   influenced and may issue any request the tools allow.
3. **A malicious dependency or repository content.** Code the agent runs is
   attacker-chosen.
4. **A confused or coerced operator.** A human is talked into widening a policy.

## What Guard defends

- **Direct egress.** The guest's only permitted destination is the Guard
  gateway. Direct IPv4, IPv6, alternate DNS, metadata addresses, private ranges,
  the control plane, the worker and other sandboxes are denied by nftables
  outside the guest. Measured on real microVMs in `benchmarks/guard-core-acceptance.json`.
- **Credential exposure.** The model credential is substituted host-side for a
  placeholder. A full snapshot, memory image and disk scan finds no copy of the
  real secret, measured over 13.4 GB.
- **Exfiltration through allowed channels.** Under a model-only policy the
  request and response are byte-limited and the model endpoint is bound; an
  unrelated endpoint is refused even when the guest resolves it.
- **DNS as a covert channel.** Only Guard resolves names, only for zones the
  policy allows, only for record types the policy allows.
- **Loss of the watcher.** If the watchdog stops reporting, the gateway and the
  kernel rules cut the attachment. Silence is not health.
- **Runaway workloads.** Lifetime and model request and byte ceilings are
  durable control-plane state, and a worker restart cannot reset them. The
  reaper that acts on an expired budget is implemented and covered by database
  tests; no live run has yet observed it firing.
- **A machine that misbehaves.** Repeated authoritative denials request a
  quarantine, and the control plane cuts the network, pauses the VM, captures
  forensics without resuming it, latches durable quarantine state, appends an
  authoritative event, writes an incident report and completes - observed live,
  end to end, in `benchmarks/guard-phase2-acceptance.json`. A repeat call
  returns the same incident rather than acting twice.
- **Unauthorized policy change.** An agent may propose a policy change; only a
  human may approve one, and the existing verifier runs before it is applied.

## What Guard does not defend

- **Host compromise.** Everything Guard runs is on the host. A root attacker on
  the host rewrites nftables, reads the credential file and forges the journal.
- **The model API as a data channel.** A model endpoint is a channel. Guard
  bounds it and binds it, but bytes that reach the model provider are bytes the
  provider received.
- **Gateway compromise.** The Guard gateway holds the model credential and can
  read the traffic it proxies. A compromised gateway defeats the network
  boundary it enforces.
- **Collusion between the harness and a permitted endpoint.** If the policy
  permits a destination, the guest may talk to it.
- **Layer 7 semantics without TLS interception.** In the default SNI mode Guard
  sees the hostname and the connection, not the HTTP method or path. Method and
  path policy exists only where the operator has explicitly enabled
  interception, which means Guard holds a key that can read the traffic.
- **The guest's own data.** Files inside the guest, and anything the guest
  writes into a permitted channel, are the guest's.
- **A watcher's judgement.** The optional watcher is a second reviewer. It can
  only be more restrictive; it can be wrong, and it can be manipulated by
  untrusted evidence. It never widens anything.
- **Hardware attestation.** AIec verifies hashes and, for guarded workloads,
  signed manifests. There is no TPM-backed attestation, and none is claimed.
- **Multi-host security.** Guard's assumptions are about one worker host and its
  guest. A deployment that separates the gateway from the worker changes the
  trust properties and is documented as such rather than claimed equivalent.

## Trust boundaries that matter

- **Guest → host kernel.** The guest writes packets; the host decides. Guard's
  rules are installed by the worker before the guest boots and replaced only by
  a fenced action.
- **Guest → gateway.** The gateway accepts connections only from the address the
  attachment assigned to this guest, and only after the watchdog's first
  heartbeat for this identity.
- **Gateway → control plane.** Reservations are committed by the control plane
  before any byte is forwarded. A gateway that cannot reach it refuses traffic.
- **Watchdog → control plane.** The watchdog's key carries only
  `guard:read`, `guard:heartbeat` and `guard:quarantine`. It cannot create
  sandboxes, read tenant data or release a quarantine.
- **Human → policy.** Approval is a separate capability from proposing.

## Deployment modes and what each defeats

| Mode | What it defeats | What a compromise of that component defeats |
|---|---|---|
| Worker-host hardened process | guest escape attempts; the default | a root attacker on the worker host defeats the whole boundary |
| Separate gateway VM | a compromise confined to the worker host that does not reach the gateway host | the gateway host holds model credentials; its compromise reads proxied traffic |
| Separate physical gateway | a compromised worker host with no route to gateway state | the gateway itself is a single high-value target; latency and operational cost are real |

## Evidence discipline

Every claim above that says "denied", "bounded" or "measured" names an artifact.
`benchmarks/guard-core-acceptance.json` is a run on real microVMs with real
nftables. `benchmarks/guard-phase2-acceptance.json` is the watchdog, dead-man
and quarantine run. Claims not covered by an artifact are written as
limitations, not as guarantees.