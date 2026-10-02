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
- **Retry, then terminal.** An unfinished quarantine is resumed by posting
  again, on a growing delay, and every attempt carries a closed data-free
  failure label. When neither the incident nor the control plane answers within
  the retry window the watchdog exits instead of continuing to look like a
  working observer. That direction is fail-closed: the exit withholds the
  heartbeat, which is exactly what the gateway's deadman needs in order to cut.
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

**Phase 1 and §49 — `benchmarks/guard-core-acceptance.json`: PASS, 48 cases,
97.9 seconds, no cleanup errors.**
Real Firecracker microVMs, real nftables, local mocks only. Includes the
secret-scan (13.4 GB of memory, state and disk with no copy of the real model
credential) and a case proving an attachment carries traffic only after a
watchdog heartbeat.

**What Guard costs a DNS lookup.** The published core artifact records ten
identical A queries per side. Its driver sorts and selects index `n/2`, so the
values are **upper-middle order statistics**, not conventional even-sample
medians:

| | upper-middle value |
|---|---:|
| guarded — the guest's system resolver, in the guest, through the gateway | 2.963 ms |
| unguarded — the same A query to a policy-free resolver in the same namespace | 0.024 ms |
| **difference** | **2.939 ms** |

**This is an upper bound, not a policy-engine measurement.** The guarded side
includes the vsock hop and the guest's resolver stack; the unguarded side is a
raw UDP query from the host. The comparison does not isolate enforcement CPU
or latency.

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

**Phase 2 — `benchmarks/guard-phase2-acceptance.json`: PASS, 29 cases, 78.1
seconds, no cleanup errors.** Real control plane, worker, guest, watchdog
process, database and kernel tables. Observed: guarded start; a narrowly-scoped
watchdog key that cannot create sandboxes; anchored telemetry; a real watchdog
holding the attachment live; authoritative denials reaching the watchdog; a
triggered rule; the full quarantine chain to `completed_at`; resume refused;
a repeat quarantine returning the same incident; a worker restart leaving the
quarantine in force; and the sandbox held rather than orphaned.

**Backward compatibility —
`benchmarks/guard-compat-acceptance.json`: PASS, 8 cases, 59.0 seconds, no
cleanup errors.** A third live suite, run the same way against the same deployed
binaries, exercising only what was true of the product before Guard existed:
the create body a pre-Guard client sends, the legacy response fields and their
types, exec, the file round trip, destroy, the two spellings of the dev runtime,
and the fact that `AIEC_ALLOW_LEGACY_NETWORK=1` cannot unguard a Firecracker
sandbox. The launcher is the phase 2 one with different ports, so the two suites
can run on one host.

**Two-phase human approval —
`benchmarks/guard-approval-acceptance.json`: PASS, 10 cases, no cleanup
errors.** The deployed binaries over HTTPS with PostgreSQL as the store, on a
database of its own. Ten cases covering an undecided call refused immediately,
the operator queue readable only with `GuardApprove`, the requester recorded
from the authenticated principal, self-approval refused even for a key holding
every scope, a grant recorded against a different identity, an approved call
allowed once, its replay refused, changed content at the same path refused, a
denial that is neither spendable nor overturnable, and an ask without a digest
refused. Launched by `scripts/guard-approval-acceptance.sh`, which mints its
own certificate authority and its own keys per run.

**What this suite does not cover.** It runs on the container runtime with no
Guard gateway and no microVM, because the approval surface is ownership-scoped
rather than runtime-scoped: what is under test is who may decide and who may
spend. It is not evidence about Guard's network enforcement or about placement;
Phases 1 and 2 are.

Two properties are deliberately *not* claimed by that suite.
`AIEC_ALLOW_LEGACY_NETWORK` is only asserted to grant nothing on Firecracker,
where Guard is injected into every request; the branch it actually guards —
`environment.guard.is_none()` — is unreachable on this deployment, so the flag
is not exercised where it takes effect. And `AIEC_ALLOW_REDUCED_ISOLATION` is
not tested here at all.

**Static gates.** The final serial run of `scripts/gate.sh` with
`RUST_TEST_THREADS=1` passed in 153.44 seconds: `fmt`, clippy with `-D warnings`,
the workspace tests including PostgreSQL, the SDK import contract, Python SDK
tests, and the `aarch64-unknown-linux-gnu` cross-check. The parallel run failed
in `a_workspace_snapshot_is_storable_and_restorable`; that test passed alone.
This establishes a concurrency-sensitive failure, not its root cause.

### What is not backward compatible, stated plainly

One thing changed for a client that asked for nothing, and it is a security
change rather than an oversight: **a Firecracker sandbox is now guarded by
default.** `crates/aiec-api/src/lib.rs:1884` injects `environment.guard` with
the default `no-network` template into every Firecracker request that omits it.
A pre-Guard client therefore gets a sandbox with no egress, whether or not it
knows Guard exists. The request shape, the response shape, and the exec and
file operations are unchanged; what changed is the default posture, and it is
recorded on the wire under `environment.guard` rather than applied silently.

The consequence worth stating plainly: **`AIEC_ALLOW_LEGACY_NETWORK` cannot
restore the old behaviour for Firecracker.** The flag is consulted in
`GuardNetworkManager::prepare` behind `sandbox.environment.guard.is_none()`,
and on Firecracker that is never true. There is no supported configuration in
which a Firecracker sandbox runs with unguarded network — which is the intended
outcome, but it means the flag is not the escape hatch an operator upgrading
from a pre-Guard deployment would expect it to be.

Everything else held: the create body a pre-Guard client sends is still
accepted, the legacy response fields are still present and still have the types
a pre-Guard parser expects, exec works, the file round trip works, and destroy
reaches a terminal state. The dev-runtime spellings `bwrap-dev` and `bwrap_dev`
still parse to the same runtime — both are refused identically, naming
`BwrapDev` — which is what distinguishes a parser that understands the
underscore form from one that silently stopped accepting it. That runtime is not
available on this deployment and nothing here claims that it is.

One qualification on that, because "additive" is doing work it should not be
asked to do: the sandbox response is **not** byte-identical to a pre-Guard one.
It gained a nested `environment.guard`. Every field a pre-Guard client read is
unchanged, but a client built on a strict deserializer that rejects unknown
fields will fail on it. The Rust SDK and the Python SDK both tolerate the extra
field; a stricter third-party client may not, and this suite does not claim to
have tested one.

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

Two more came out of running the suites rather than out of the product: the
phase 2 launcher's second `trap ... EXIT` silently replaced the first, so every
run leaked its lock and the next one refused while nothing was running; and the
same launcher stopped postgres but never reaped the control plane and worker it
had launched, so every interrupted run left servers bound to that run's ports.

The compatibility suite found two false passes and one case pointed at the wrong
point in the lifecycle. Both kinds are worth recording, because a false pass is
worse than a broken assertion — it is a claim about the product that nothing
observed:

- **Guard defaulting reported as "no Guard".** A case asserting that a
  pre-Guard client saw no policy scanned only top-level response keys. Guard is
  injected under `environment.guard`, so the sandbox was guarded the whole time
  and the case passed on what it had failed to look at.
- **Types recorded but never checked.** The response case wrote the observed
  type of each field into its evidence and asserted only that the field was
  present. It now asserts `isinstance` for every field it names.
- **The legacy-network case asking a question the runtime cannot answer.** This
  one failed loudly rather than passing falsely, which is why it was found. The
  case had asserted that create returns 4xx without the opt-in; it returned 200
  and the suite reported a failure. Reading the source to explain the 200 turned
  up the finding recorded above: `crates/aiec-api/src/lib.rs:1884` injects
  `environment.guard` into every Firecracker request, so
  `GuardNetworkManager::prepare`'s `guard.is_none()` branch is never entered
  and the flag is never consulted on that runtime. No delayed refusal was
  observed, and none is claimed.

  The case was rewritten to assert what is actually observable here: with
  `AIEC_ALLOW_LEGACY_NETWORK=1` set on the worker, a Firecracker sandbox still
  reaches `running` with its Guard metadata intact. The template is recorded in
  the evidence rather than asserted, and no egress probe is made, so this makes
  no claim to have watched traffic or proved the network is cut — the
  enforcement evidence for that is in the phase 1 and phase 2 runs above. The
  flag is not exercised where it takes effect, because no reachable path in
  this deployment reaches it.

- **A capture that could not have detected its own failure.** The zero-egress
  proof is a packet capture of the guest's own TAP, and the read of that pcap
  ran `tcpdump -r` without `-Z root`. In the user namespace the suite runs in,
  tcpdump cannot drop to the `tcpdump` account, so the read exited non-zero
  having printed nothing — and the harness counted zero lines. Every count in
  that window was therefore a false zero that looked exactly like proof of
  silence. It was caught because an isolated reproduction showed a 109-byte
  pcap containing one packet reading back as an empty list.

  The read now passes `-Z root`, treats a non-zero exit as an error rather than
  an empty result, and records the pcap's size on disk so that "recorded
  nothing" is distinguishable from "never ran".

- **A positive control that was structurally incapable of passing.** The suite
  proved its capture instrument by having the host write a frame onto the
  guest's TAP through `AF_PACKET`. That cannot work: such a frame leaves
  through the tun file descriptor and never appears in a capture taken on that
  same TAP. Measured — a 24-byte packet-free pcap, where the identical injection
  on a dummy device *was* captured. The control could only ever have passed if
  the capture were broken in some new way.

  It was replaced with a stimulus that genuinely traverses the link. The suite
  had been asserting, in its own evidence, that guest egress is dropped in an
  `output` hook; Guard installs no such chain, so those packets cross the TAP
  and are denied in the host's `input` chain on arrival. The guest's own connect
  attempts are therefore a valid control for both instruments at once, and the
  two agree exactly: 6 routable frames captured, `cnt_other_denied` +6.

  The control must specifically record a ROUTABLE frame, not merely any frame.
  Satisfying it with an ARP or neighbour-discovery frame would leave a broken
  `ROUTABLE` expression able to ship as a passing artifact that still claimed
  zero egress.

## What Guard costs

Every figure below comes from the live runs whose artifacts are in
`benchmarks/`, on one host, stated with the method that produced them. Nothing
here is projected from a smaller or different run.

**Host.** Intel Core 7 240H, x86_64, Linux 7.0.0-34-generic, recorded in the
core artifact's `cpu_model` and `kernel_arch` fields. Every guest is a real
Firecracker microVM; the model is a local mock, so no figure here includes
real internet latency.

Streaming values below are medians of each side's three samples; added latency
is the difference of those medians, not the artifact's mean paired difference.
The DNS driver selects index `n/2` after sorting: for ten samples that is the
upper-middle value, not the average of the two middle values.

| measurement | guarded | unguarded baseline | added | samples |
|---|---:|---:|---:|---:|
| guest DNS A lookup, upper median | 2.963 ms | 0.024 ms | 2.939 ms | 10 per side |
| model stream, first byte, median | 13.26 ms | 6.63 ms | 6.62 ms | 3 per side |
| model stream, total duration, median | 790.68 ms | 786.25 ms | 4.43 ms | 3 per side |

**Stream throughput.** Each response contains 4 194 318 bytes. The guarded
median duration is 790.68 ms with a median 515 chunks, against 786.25 ms and
132 chunks for a host-side client bypassing Guard. End-to-end throughput is
5.06 MiB/s guarded versus 5.09 MiB/s direct, including the client read loops.
The chunk counts describe these clients and transports; they do not establish
a general chunk-amplification ratio or attribute buffering to Guard alone.

**What the DNS figure does not say.** It is an upper bound, not the cost of the
policy engine. The guarded side is a real guest resolver lookup and the
unguarded side the identical query to a policy-free resolver in the same
namespace, so the difference also carries the vsock hop and the guest's
resolver stack.

**What the streaming comparison does not say.** The 4.43 ms median duration
difference is inside the observed spread of three samples (guarded:
784.68–792.94 ms; direct: 784.89–789.99 ms). Neither a speedup nor a stable
percentage overhead is established. The first-byte difference is 6.62 ms, but
the guest and host clients use different stacks, so it is not an isolated
policy-engine cost.

### Isolated gateway CPU/RSS (§51)

[`benchmarks/guard-resource-benchmark.json`](../benchmarks/guard-resource-benchmark.json)
records **seven matched pairs** on the Intel Core 7 240H, Linux
7.0.0-34-generic, x86_64, with 16 logical CPUs available and two Tokio worker
threads. Each side makes 64 sequential requests returning **1 MiB each**:
448 measured requests per side. Each response is length- and SHA-256-verified.
The provider emits 16 KiB HTTP chunks and accepts the gateway's chunked
uploads; the guarded path substitutes the real host-held credential.

Each pair starts a fresh release-built `guard_resource_gateway` acceptance
process running the production `GuardGateway` library, HTTP budget client,
credential store, and file-event sink. Both sides get two warmup requests.
Direct and guarded order alternates. A private SQLite budget authority commits
each debit before acknowledgment; every guarded sample verifies exactly 64
admissions, 64 MiB received, and the uploaded request bytes. Direct samples
leave its ledger unchanged.

| conventional median, n=7 per side | direct provider path | guarded path |
|---|---:|---:|
| gateway CPU per 64-request window | 0.00 s (idle gateway) | **0.46 s** |
| sampled peak gateway RSS | 7 936 KiB | **8 896 KiB** |
| client wall time per 64 requests | 0.176 s | 1.614 s |

Three RSS baselines are recorded separately because they answer different
questions. The **pre-request startup** RSS, read after the gateway is serving
and before any traffic, has median 7 056 KiB. The **warmed-idle** RSS, read
after both sides' warmups have run, has median 7 860 KiB and is steady-state
rather than cold: buffer and allocator growth from warmup traffic sits inside
it. The paired guarded peak minus warmed idle is **988 KiB** (range
620–1 144 KiB) and so understates memory attributable to serving requests,
since warmup already paid part of it. The paired guarded peak minus
**startup** is **1 804 KiB** (range 1 356–1 876 KiB); that is the larger and
more honest figure for memory this workload added, and neither is the
subtraction of two independently aggregated medians.

Gateway CPU minus the pair's one-second idle CPU rate, normalized to the
guarded accounting window, has median **0.46 s**. Gross gateway CPU ranges
0.33–0.54 s: the median corresponds to **7.2 ms CPU per request for this
workload**, not a general request cost or an end-to-end CPU delta.


CPU comes from `/proc/PID/stat` across gateway threads at 100 ticks/s, with
before/after snapshots enclosing each client invocation. RSS comes from
`VmRSS` sampled every 5 ms; lifetime `VmHWM` is also retained. Sampling is not
an absolute peak-memory guarantee, and RSS includes shared resident pages.
A positive control allocated 32 MiB and burned CPU: the same instrument saw
31 CPU ticks and 32 772 KiB RSS growth. A second control reached the authority,
observed its HTTP 403 and the gateway's HTTP 503, and verified no provider call
or durable debit. Failed runs do not replace the published artifact; a failed
gateway-start smoke verified that behavior. Cleanup errors: none.

**Scope.** Gateway process accounting includes forwarding, durable-budget HTTP
requests, credential substitution, audit writes, the DNS listener, and the
acceptance owner's activation/heartbeat task. Provider, client, SQLite
authority, external watchdog, control-plane server, Firecracker, guest, and
nftables are excluded. The direct path bypasses an otherwise idle gateway
process retained only for baseline observation. Both paths run in a disposable
user/network namespace using a benchmark-only provider address, without WAN or
TLS, guest-image changes, or production-daemon validator changes. The fixture
authority is not a production control-plane deployment benchmark. These
measurements establish isolated gateway cost for this bounded workload, not
total platform overhead, a confidence interval, or a percentile.

### Earlier live-run resource observations

**Aggregate process cost (n=1 run).** The §49 run reports 59.12 s of CPU and a
30 376 KiB peak RSS for the acceptance driver process. This covers the driver,
gateway, and mocks during a 97.9 s run; Firecracker and guest processes are
outside it. The model-only leg (n=1) separately records 0.04 s CPU (0.03 s
harness upload, 0.01 s tool loop) and 32 KiB resident-set growth in that shared
process. These are measured usage, not isolated gateway overhead versus a
baseline. The 0.01 s loop sample has coarse CPU-clock resolution; it establishes
no per-request cost distribution.

**Model-only leg (§49).** One real four-turn tool loop ran in a real VM
(`read` → `write` → `bash` → final), observed as 4 authenticated model requests
by the host-side mock, with 0 connections to any forbidden destination and 0
policy-table denials on the allowed leg. The 28 admitted packets in
`broker_permitted` are packet-weighted and are deliberately **not** compared to
the request count.

**Topology B leg (§50).** 15/15 cases, with the zero-egress result established
two independent host-side ways that agree: 6 routable frames captured on the
guest's own TAP in the positive-control window, and `cnt_other_denied` moving by
exactly 6 packets on the same stimulus, while every counter read 0 across the
agent loop.

**Quarantine latency (n=1).** The
`alert-to-network-cut-latency-is-bounded` case in
`benchmarks/guard-phase2-acceptance.json` records 23.656 ms from
`triggered_at` to `network_cut_at`: the exposure window in which the rule had
fired but egress was still up. Same hardware, real watchdog holding the
attachment live. It is not a distribution and establishes no percentile.

**Not measured.** No aarch64 runtime/performance figure exists; only
cross-compilation has been exercised. The controlled x86_64 resource benchmark
above closes the previously missing isolated CPU/RSS evidence. Deployment-wide
resource overhead and quarantine-latency distributions remain outside these
bounded measurements.

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
6. **Resolved: human tool approval can admit one invocation.** The live §44
   suite observed a grant by a different authenticated identity, one successful
   consumption, and replay refusal. PostgreSQL regressions additionally cover
   retries after pending expiry and preservation of a still-open deadline.
   Approval gating remains an explicit MCP opt-in.
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

# §51: isolated CPU/RSS; no guest image or deployed process changes
cargo build --release -p aiec-guard --example guard_resource_gateway
python3 scripts/guard-resource-benchmark.py \
  --output benchmarks/guard-resource-benchmark.json

# After any guest-image change, before booting a guarded sandbox
bash scripts/build-firecracker-guest.sh
```

```bash
# Phase 5 acceptance, on a freshly rebuilt scratch image. The launcher mints
# this run's per-run image manifest, TLS material, guard credentials and trust
# keys, and refuses to start against a named-but-absent manifest. P5_PHASES is
# an operator diagnostic: a subset run reports acceptance_scope
# "diagnostic_subset" and cannot stand as acceptance for the suite.
AIEC_FIRECRACKER_BIN=$PWD/.agentforge/bin/firecracker-v1.17.0-x86_64 \
AIEC_KERNEL=/path/to/vmlinux \
AIEC_ROOTFS=/path/to/freshly/built/aiec-rootfs.ext4 \
AIEC_GUEST_SECRET=/path/to/guest-secret \
P5_PG_BIN=/path/to/postgres/bin \
P5_DRIVER=scripts/guard-phase5-acceptance.py \
  bash scripts/guard-phase5-acceptance.sh
```

## §60 definition-of-done audit

| required area | evidence and disposition |
|---|---|
| Phase 1 enforcement, DNS, model credentials, telemetry | Live core suite: 48/48. Includes §49's model-only in-guest tool loop. Local mock providers only. |
| Phase 2 watchdog, dead-man switch, quarantine, budgets, incident | Live Phase 2 suite: 29/29; alert→network-cut latency 23.656 ms (n=1), from the incident timestamps. The durable lifetime reaper itself has not been observed firing. |
| Phase 3 MCP/GraphQL policy, proposals, human approval | Live Phase 3 suite: 47/47, no cleanup errors (`benchmarks/guard-phase3-acceptance.json`), on real Firecracker guests inside a network namespace with an isolated PostgreSQL. Covers agent submission of a proposal, operator approval, the approved policy applying to a running attachment, the enforcement generation moving with it so heartbeats and budget reservations survive the change, allowlisted read authority reaching its destination live, DNS answers rewritten to the gateway, TLS with SNI matching, interception refused without credentials, blocked and private destinations denied, and an OpenShell import producing an enforced policy. |
| Optional Phase 4 watcher | Implemented and test-covered; no complete live optional-watcher acceptance is claimed. |
| Phase 5 canaries, image trust, identity, red-team CI | Live Phase 5 suite: 36/36 full-suite, no cleanup errors (`benchmarks/guard-phase5-acceptance.json`). Real Firecracker guests on a freshly rebuilt scratch image, an isolated PostgreSQL, a real worker and watchdog, all inside a network namespace. Covers unsigned/untrusted/tampered/expired image refusal, kernel and rootfs digest enforcement, distinct per-VM identities, cross-sandbox frame refusal, revocation and rotation, host-observed DNS, credential and file canaries with a durable cut and a preserved machine, and a completed incident with cut, pause, snapshot and report timestamps. |
| Topologies A and B | §49 completes a real in-guest tool loop; §50 completes an external loop with positive-control-validated host capture and counters (15/15). |
| Existing lifecycle, snapshots, fencing, MCP, eval | Workspace regressions passed in the serial gate; compatibility suite passes 8/8 within its documented coverage. Untested legacy branches and strict response deserializers remain excluded. |
| §51 performance | DNS upper-middle order statistics (n=10 per side), conventional streaming medians (n=3 per side), quarantine alert→network-cut latency (n=1), and isolated gateway CPU/RSS (n=7 matched pairs) have published artifacts, hardware/kernel/architecture, explicit baselines, and scope. No aarch64 runtime/performance or deployment-wide resource claim. |
| Static quality gate | Serial gate passes. Parallel storage-test reliability remains unresolved; serial success does not prove the failure's cause. |

This audit separates implementation and regression coverage from live proof.
The full non-deferred definition of done is not satisfied.

## Verdict

**AIEC GUARD: PHASES 1-3 AND 5 PROVEN LIVE; PHASE 4 AND THE REAPER NOT YET**

Phases 1, 2, 3 and 5 run on real Firecracker machines against the image produced
by the build: 48/48, 29/29, 47/47 and 36/36 full-suite, none with cleanup
errors. §49 proves the in-guest model-only tool loop; §50 independently proves
the external loop and its bounded zero-egress window (15/15). The guest
identity, host attachment, approved-policy and OpenShell-import paths are all
inside the live Phase 3 evidence.

Phase 4 is implemented and unit-covered but has no live run, and the lifetime
reaper has never been observed firing. Also outstanding: `CAP_NET_ADMIN` is
absent from the production worker on this host; Layer 7 needs interception to
govern a tunnelled request; multi-host deployment modes are unvalidated; and
aarch64 is compiled but never run. Parallel test reliability is unresolved.
Operator actions remain deploying the rebuilt image and granting the worker
`CAP_NET_ADMIN`.

## What Phase 3 changed in the product

Three defects were found by running it, none of which unit coverage could see.

**An approved policy could not reach the guest it was approved for.** The
attachment's gateway named the generation it booted with, and approval installs
a new policy without restarting it, so every heartbeat and every budget
reservation after an approval was refused against a generation that no longer
existed. The gateway now names the installed generation at the point the policy
is applied, and refuses to name anything the live policy cell is not already
enforcing (`Gateway::adopt_policy`, `Runtime::adopt_policy`). Ownership, node,
lease fence and release state are unchanged by it: only the hash moves, and only
where the policy is installed. Heartbeats are additionally checked against the
policy actually in force, so a watchdog still reporting under a superseded
generation is refused rather than trusted until someone remembers to tell the
gateway.

**An approval moved the record but not every other consumer of it.** The
sandbox record, journal expectations and durable budget each derived the
installed policy separately. The control plane now derives the policy the
worker actually installed, verifies its hash against what the worker reports,
and persists that; the durable budget is re-initialised across the change,
preserving usage and caps and moving only the policy hash. Published migrations
are immutable, so this is migration `0023_guard_budget_policy_rebind.sql`.
Journal pages are checked for chain order, completeness and ownership; a page
written under an earlier generation is history, not a page from another
tenant's sandbox, so its recorded hash is not re-judged as if it were current.

**An allowlist without a model endpoint was unenforceable.** The kernel permit
for the gateway's broker listener was derived from the presence of a model
endpoint alone. A `read_only_api` policy, which is what an OpenShell import
produces, names destinations but no model, so its guest was sealed and its
allowlist could never apply. The permit now follows whether the policy gives
the guest any destination to reach at all; the gateway is Guard's enforcement
point, not a privilege, and what the guest can then reach is still decided rule
by rule inside the gateway. `no-network` has neither and keeps neither listener.

## Running Phase 3

The harness creates its own database, credentials, TLS material, ports and
scratch paths, and performs its own trusted namespace initialization. It needs
only an image directory and an administrative PostgreSQL URL; a supplied image
directory is used exactly as given, and a missing one is an error rather than a
search.

```text
P3_IMAGES=/path/to/a/directory/holding/vmlinux-and-aiec-rootfs.ext4 \
P3_PG_ADMIN_URL=postgresql://user:password@127.0.0.1:5432/aiec \
  python3 scripts/guard-phase3-acceptance.py
```

The report is written to `benchmarks/guard-phase3-acceptance.json`, with
per-case detail, the provider request count, and the observation provenance
that distinguishes host-observed evidence from a guest's own claim.


## What Phase 4 changed in the product

The Phase 4 harness runs a real watcher and a real watchdog against a real
attachment. Two defects in the quarantine path were found by running it, both
of them invisible to unit coverage because both depend on a *sequence* rather
than on a single call.

**A forensic capture of an already-paused VM waited thirty seconds for a guest
that could not answer.** `capture_forensics` asks the guest to
`PrepareSnapshot` - which fsyncs the workspace inside the guest - before it
issues the pause itself, because a paused guest has no agent scheduled to
respond. Quarantine routinely reaches a machine that is *already* paused: an
operator pause, or an earlier incident. On that path nothing was running to
answer, and `guest_call_timeout` floors every operation at
`config.readiness_timeout`, which is 30 s. The write sat on the vsock for that
entire window, and the capture holds the sandbox lifecycle gate throughout, so
every other operation on that sandbox - the watcher's telemetry, the quarantine
orchestration's own `observe()` - queued behind it. That is the thirty-second
stall, and it is why one incident showed a cut, a pause and a snapshot but no
report: the report step was waiting on a guest call that had nowhere to go.

The runtime now asks Firecracker for the VM's state and makes the guest call
only when the answer is `Running`. The state is asked for rather than
remembered, because the failure mode of guessing wrong is a blocked channel
rather than an error. The endpoint is `GET /` — this was established against the
1.17.0 binary on this host, not assumed: `GET /` answers `200` with
`{"state": ...}`, while `GET /instance-info` and `GET /vm` are both refused with
`Invalid request method and/or path`. A fake server in the tests recognises only
the root request too, so a wrong endpoint cannot pass in either.

**A refused delete destroyed the sandbox on its way to answering 409.**
`tear_down_sandbox` called `runtime.destroy()` before the repository decided
whether the row could be deleted, but `delete_sandbox` refuses a quarantined
row. So a DELETE against a quarantined sandbox destroyed the microVM and
released the Guard attachment - writing `released: true` into the attachment
record - and *then* returned 409. A request that failed had the side effects of
one that succeeded, and it discarded the machine and the evidence the
quarantine exists to preserve. The refusal is now decided from durable state
before anything is torn down, so a rejected delete changes nothing.

Both are covered by regression tests that fail if the fix is removed: one
asserts a paused-VM capture completes without attempting a guest call, the
other asserts a refused delete reaches `destroy` zero times.

**The watcher waited for the cut to finish by asking whether the cut had
started.** The deterministic-floor rule posts a quarantine and then polls. It
decided the cut was done from `observation.budget.quarantined`, which is stage
three of five: the network is down, the machine is not yet paused, there is no
snapshot and there is no report. The moment that mark appeared, the loop skipped
the only line that refreshed completion and went back to the top of the tick —
so it held the window correctly and forever, and the case timed out with the
incident already complete on the server. The response to the POST is no better
evidence: the stages run on the control plane's own task, so that body
describes the incident as it stood when the request was accepted.

Completion is now read from the incident record itself, on every pass, until
`completed_at`, `network_cut_at`, `paused_at`, a `snapshot_id` and a nonempty
report are all present. The mark is still what tells the watcher *not* to post a
second quarantine. Those passes do not count as ticks: a window is owed only
once the window's own cut has finished, so a run bounded in iterations is bounded
in windows reviewed, and the harness timeout remains the outer bound.

**The release path had no sanctioned exit and reached for the wrong one.** The
quarantine latch on `sandboxes` and the monotone rule on `guard_budgets` are
each correct on their own: an operator release is the only thing that may clear
a quarantine. Until now the budget had no sanctioned exit at all, and the release
did two things that were both wrong. It ran `ALTER TABLE sandboxes DISABLE
TRIGGER guard_quarantine_latched` — catalog state, permanent, and never
re-enabled anywhere in the tree, so one release weakened the table for the life
of the deployment. And it issued `UPDATE guard_budgets SET quarantined = false`,
against a column that was never created, so the statement failed and took the
whole transaction with it: the network came back and the quarantine did not,
which is the worst of both worlds and left the sandbox undeletable.

Migration `0024` gives the budget the same escape `0018` gave the sandbox:
`guard_released_at`/`guard_released_by`, required in the same statement as the
clearing, and checked against the sandbox being already released in the same
transaction. The release now moves the sandbox to `paused` with the marker and
clears the budget's payload mark with `jsonb_set` in one transaction, scoped by
`tenant_id`, and disables nothing. The regression test asserts the outcome
that matters (a later read reports no quarantine) and the catalog fact that no
row assertion can see (both triggers still enabled) — and it fails if the
`DISABLE TRIGGER` is put back.

**A quarantine's cut was reopened by the next healthy heartbeat.** The gateway
cleared its cut on every authenticated heartbeat, unconditionally. A heartbeat
is the watchdog reporting liveness, and a quarantine is a containment decision
that knows nothing about the watchdog: the watchdog was alive and healthy
throughout, so the first heartbeat after the quarantine re-armed egress while
the incident's own telemetry reported the attachment as cut. The dead-man's
`held` field already existed for exactly this — a cut that reporting must not
undo — but only the dead-man wrote it and only the dead-man read it, so the
quarantine path posted an ordinary cut into a gate that reopened on the next
tick. `GatewayControl::hold_cut` is now the containment entry point, and
`heartbeat` clears the cut only when nothing holds it. An ordinary cut still
reopens, because that is the watchdog's cut to reclaim, and holding every one
of them would make a healthy attachment unusable for the life of its lease. Two
regression tests pin both halves; the held one fails if the `held.is_none()`
check is removed.

**A verdict's quarantine reported the reviewer's decision and nothing else.**
When the watcher's model returned `quarantine`, the watcher posted it, read the
reply, and moved on. The reply is the incident as it stood when the request was
accepted — the pause and the snapshot run afterwards, on the control plane's own
task — so the reply read `status: incomplete` with every completion field null,
and the watcher took it at face value: it recorded no outcome for the window at
all and exited zero with the cut it had just started still running. The
harness caught it as an empty window rather than a wrong one. The deterministic
path already polled the incident to completion, and the verdict path now does
the same, inside the window that requested it: the post-action observation is
issued after the incident reports all five completion fields, so the recorded
outcome names an action the host has actually taken. The window is not
reviewed twice, which would otherwise spend a second reviewer request on
evidence that had already been judged.

## What the Phase 5 rerun changed in the product

The Phase 5 suite asserts, after the worker is stopped, that no writable
rootfs is left in its state tree. On the first run against the current tree it
failed with exactly two disks, and both belonged to the two machines the
canaries had quarantined.

**A quarantined sandbox's writable disk outlived the worker, along with its
guest.** Nothing in the worker reclaims machines on exit. The listener was
awaited alone, so the process ended on `SIGTERM` with no teardown at all — and
the default disposition of that signal runs no destructor either, so the
`kill_on_drop(true)` on each Firecracker child never fired. The guest process
survived its controller, and with it a 4 GiB writable disk under
`state-vms/vms/<id>/`, per sandbox, for as long as the filesystem did.

The quarantine is what made this look like intended behaviour rather than a
leak, and it is worth stating plainly why the machine cannot be resumed after
the worker exits: `resume()` looks the sandbox up in the running process's
`vms` map, and `reconcile_local` only *reports* a surviving VM directory as an
orphan candidate for an operator — it never adopts one. A held machine is
resumable for exactly as long as the process that created it is alive. The
forensic capture under `guard-forensics` is the copy that survives on purpose,
and the census already allowed it.

Three changes, each with the ordering it needs:

- **The worker drains, then reclaims.** `serve_worker_tls_until` takes the
  termination signal and gives it to the server, which stops accepting and
  waits (bounded at five seconds) for in-flight requests before returning. Only
  then does the runtime reclaim. The reverse order deadlocks in practice rather
  than in theory: an in-flight create holds its sandbox's lifecycle gate for the
  length of a rootfs copy, and `reclaim` waits on that same gate.
- **Reclamation does not wait on a guest.** `terminate_vm` asks the guest to
  shut itself down only when a request is waiting for the answer. A quarantined
  machine is paused, a paused guest has no agent scheduled to reply, and the
  write would sit on the vsock until `guest_call_timeout` — once per machine,
  serially. The disk is deleted either way, so a flush has nothing to protect.
  Machines are reclaimed concurrently.
- **A missing owner record costs the attachment its release and nothing
  else.** Releasing an attachment is checked against the identity it was
  created under, and a shutdown holds no `Sandbox` to check. `publish_vm` now
  records one per live VM; where it is absent the guest is still stopped and
  the disk still removed, because an unidentifiable machine is still a guest
  running on the host, and the attachment record left behind is inert without
  it. No identity is ever guessed.

The census is unchanged in strength: `live_rootfs_copies: 0`, with the two
quarantined forensic captures retained. The worker log for that run records
`reclaimed=2`, so the two disks are gone because the worker took them with it,
not because the assertion was relaxed.

### Reading the logs when a request seems to vanish

`tracing::info!("api request")` is emitted after the handler returns, so a
request's logged timestamp is its *completion* time. A missing log line during
a window does not mean no request was in flight - it means no request
*finished*. A stalled request is invisible in that log by construction, which
is why both blocked callers above had to be identified from the control plane's
own stage timestamps and the worker's continued `ownership` polls rather than
from the API access log.