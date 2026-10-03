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
32 CPU ticks and 32 772 KiB RSS growth. A second control reached the authority,
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
2. **Resolved: the lifetime reaper is observed acting.** `scripts/guard-reaper-acceptance.sh`
   runs 16 cases against real guests and a real worker, and publishes only on
   a full pass; `scripts/guard-reaper-external-db` repeats it over the
   Unix-socket relay, also 16/16. Both observe the reaper taking a sandbox
   down against a real budget rather than asserting that it could.
3. **Resolved for the packaged worker: the Guard capabilities are granted.**
   `aiec-worker.service` now carries
   `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`, which is what Guard needs to
   build its nftables rules and TAP. `systemd-analyze verify` passes on the
   unit. A worker started by any other launcher still has to be granted these
   itself - the deploy document says so - and nothing was deployed here, so the
   running service on any host is the operator's step.
4. **A placement could refuse without cause; fixed, and not shown to be the
    soak's cause.** After choosing a worker, the scheduler takes that host's
    advisory headroom lock with `pg_try_advisory_xact_lock`. Losing that race
    used to exclude the host for the rest of the call, so a placement could be
    refused as `no schedulable worker has capacity` while the worker had room -
    the lock holder being another placement a few milliseconds from committing.
    It now waits for the lock, bounded, and only excludes the host if that wait
    runs out; the headroom is still checked under the lock, so nothing is
    placed without room. `a_placement_waits_for_another_placements_host_lock`
    holds the lock from another connection and fails without the wait. What is
    *not* established is that this caused the three refusals in the parallel
    soak: a concurrency probe at the soak's own width reproduced no capacity
    refusal either way, so the cause of those three remains unattributed.
5. **Resolved: the intermittent storage failure was a fixture, not the
   scheduler.** `a_workspace_snapshot_is_storable_and_restorable` failed three
   times during full-workspace runs with a capacity refusal, always under
   `cargo test --workspace` and never under `-p aiec-storage --lib`. It
   registers its own worker and pins the placement to it, so nothing in the
   product was placing on it - the database said otherwise. At the moment of a
   reproduced failure its worker already showed `sandbox_count 1` with
   `available_vcpus 1` of 32, a debit of exactly the 31 vCPUs / 60 GB / 3 GB
   that the neighbouring test uses, and the debiting sandbox belonged to
   another fixture tenant (`storage-invariant-*`) whose lease had expired 65 ms
   after it was created. Lease recovery deliberately picks *any* healthy
   worker, and three tests running recovery on the shared schema could take a
   worker's node out from under a test running beside them. Those three now run
   in their own PostgreSQL schema, as the reassignment tests beside them
   already did. The cross-crate hypothesis was checked and is wrong:
   `crates/aiec-api` has no database-backed test and takes `DATABASE_URL` only
   in `main.rs`.
6. **Resolved: a guest packet reaches `GuardNetworkManager::create_guard`'s
   attachment and is denied there.** The driver records the host's own view of
   the attachment alongside the counters. In the 28/28 run the TAP was
   `UP,LOWER_UP`, carried its /30 address, and had a neighbour entry for the
   guest, while Guard's own table counted `blocked_range: 3` - so the packets
   arrived, were denied by the ruleset, and the denial was what the watchdog
   then acted on. Phase 1 still exercises its counters on driver-created TAPs;
   this is the first run in which the manager's own attachment is the one under
   test.
7. **Layer 7 rules need interception to see a request.** In the default SNI
   mode Guard matches the requested name and forwards the tunnel; a CONNECT
   tunnel to a governed host is refused rather than forwarded ungoverned.
8. **Resolved: human tool approval can admit one invocation.** The live §44
   suite observed a grant by a different authenticated identity, one successful
   consumption, and replay refusal. PostgreSQL regressions additionally cover
   retries after pending expiry and preservation of a still-open deadline.
   Approval gating remains an explicit MCP opt-in.
9. **Multi-host deployment modes are documented, not validated.** The hardening
   decision for a separate gateway host is untested.
10. **aarch64 is compile-verified, not run-verified.** The gate cross-checks the
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
- **The deployed guest image at `/home/gobrowse/ga/images` is stale, and the
  suites will not run against it.** It was built at 01:11 local, before the
  guest write-path fix in `5f0aa43`; the agent inside it hashes to
  `dc08a1a1…` and has none of that fix's strings, while the image the
  acceptance evidence was produced with
  (`/home/gobrowse/ga/p5-guest-fixed`, agent `9db0feb9…`) has them. Booting
  the deployed image and planting a file canary fails as
  `500 io: guest WriteFile: early eof`: the pre-fix guest propagated the write
  error out of its inlined `match` and dropped the control connection instead
  of answering it, which is precisely the "denied" versus "gone" distinction
  that commit fixed. The image was not rebuilt or replaced here - a stale
  deployment asset is reported, not silently overwritten - and Phase 5 was run
  against the image the current tree builds. Rebuild it with the procedure
  below before pointing any deployment at it.

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
| Phase 2 watchdog, dead-man switch, quarantine, budgets, incident | Live Phase 2 suite: 29/29; alert→network-cut latency 23.656 ms (n=1), from the incident timestamps. The durable lifetime reaper now has its own live suite, 16/16 (`benchmarks/guard-reaper-acceptance.json`), and 16/16 again through the external-database Unix-socket relay (`benchmarks/guard-reaper-external-db-acceptance.json`); both observe the reaper acting, not only its ceilings. |
| Phase 3 MCP/GraphQL policy, proposals, human approval | Live Phase 3 suite: 47/47, no cleanup errors (`benchmarks/guard-phase3-acceptance.json`), on real Firecracker guests inside a network namespace with an isolated PostgreSQL. Covers agent submission of a proposal, operator approval, the approved policy applying to a running attachment, the enforcement generation moving with it so heartbeats and budget reservations survive the change, allowlisted read authority reaching its destination live, DNS answers rewritten to the gateway, TLS with SNI matching, interception refused without credentials, blocked and private destinations denied, and an OpenShell import producing an enforced policy. |
| Optional Phase 4 watcher | Live Phase 4 suite: 51/51 (`benchmarks/guard-phase4-acceptance.json`), on real guests. |
| Phase 5 canaries, image trust, identity, red-team CI | Live Phase 5 suite: 37/37 full-suite, no cleanup errors (`benchmarks/guard-phase5-acceptance.json`). Real Firecracker guests on a freshly rebuilt scratch image, an isolated PostgreSQL, a real worker and watchdog, all inside a network namespace. Covers unsigned/untrusted/tampered/expired image refusal, kernel and rootfs digest enforcement, distinct per-VM identities, cross-sandbox frame refusal, revocation and rotation, host-observed DNS, credential and file canaries with a durable cut and a preserved machine, and a completed incident with cut, pause, snapshot and report timestamps. |
| Topologies A and B | §49 completes a real in-guest tool loop; §50 completes an external loop with positive-control-validated host capture and counters (15/15). |
| Existing lifecycle, snapshots, fencing, MCP, eval | Workspace regressions pass in the gate; the compatibility suite passes 8/8 within its documented coverage, and the live approval suite 10/10. **Snapshots are now proven end to end on a real guest**: a workspace snapshot captured from a running microVM, its source machine destroyed, and the archive restored into a fresh one that still holds a marker written for that run only - 12/12 (`benchmarks/snapshot-acceptance.json`), against a real S3 object store. Untested legacy branches and strict response deserializers remain excluded. |
| §51 performance | DNS upper-middle order statistics (n=10 per side), conventional streaming medians (n=3 per side), quarantine alert→network-cut latency (n=1), and isolated gateway CPU/RSS (n=7 matched pairs) have published artifacts, hardware/kernel/architecture, explicit baselines, and scope. No aarch64 runtime/performance or deployment-wide resource claim. |
| Static quality gate | The gate passes in full: `fmt`, clippy with `-D warnings`, the whole workspace suite, the SDK import contract, the Python SDK tests and the aarch64 cross-check. The cross-check builds in a container as root; it was writing root-owned artifacts into the host `target/`, which broke later host builds with a permission error. It now uses a container-local target directory, and no root-owned path is left behind. |

This audit separates implementation and regression coverage from live proof.
Every phase the brief requires is implemented and proven on real machines, and
the three items that were open when this audit was first written - the durable
reaper, Phase 4, and the worker's Guard capabilities - are now closed by live
evidence rather than by argument. What remains open below is explicitly
optional scope in the brief (TLS interception), environment-bound (aarch64
hardware, deployment), or a measurement that was taken and is reported as it
came out. None of it is a phase that was skipped.

## Verdict

**AIEC GUARD: PASS - every non-deferred required phase proven on real machines, with four limitations and two operator steps stated below**

Phases 1, 2, 3, 4 and 5 run on real Firecracker machines against the image
produced by the build: 48/48, 29/29, 47/47, 51/51 and 37/37 full-suite, none
with cleanup errors. The durable reaper is observed acting, twice over and once
again through the external-database relay, 16/16 each time. §49 proves the
in-guest model-only tool loop; §50 independently proves the external loop and
its bounded zero-egress window (15/15). Snapshots round-trip a workspace
through a destroyed source machine into a fresh one, 12/12.

Building that snapshot proof found the defect that had been hiding behind it:
the Firecracker worker never advertised `portable_workspace` or
`workspace_snapshot`, so the scheduler's capability test excluded every microVM
host and every restore was refused as having no capacity - against a worker
holding 4 vCPUs, 4 GiB of memory and 40 GiB of disk free. The runtime implements
both; it now says so, and a test asserts the exact set a restore requires.

Still open, and stated as open rather than resolved by inference:

- Layer 7 rules need interception to govern a tunnelled request; a CONNECT
  tunnel to a governed host is refused rather than forwarded ungoverned. The
  brief lists TLS interception as optional and risky, and the conservative
  outcome is what ships: no silent downgrade onto an ungoverned path.
- Multi-host deployment modes are documented, not validated. The brief holds
  multi-host security only as far as it is validated, so nothing is claimed
  beyond the single-host evidence here.
- aarch64 is cross-compiled and clean; no aarch64 machine was available, so it
  has never been run. The brief requires it to build there, which the gate
  checks. No runtime or performance number is claimed.
- The 80-run parallel soak finished 77/80 with three transient
  `no schedulable worker has capacity` refusals. The census afterwards was the
  census before, so nothing accumulated. The cause of those three is still not
  established: a refusal path that could refuse without cause was found and
  fixed in the meantime, but a concurrency probe at the soak's own width
  reproduced no refusal either way, so the fix is not claimed as their cause
  and the soak has not been rerun.
- The two operator steps that cannot be done from here remain: deploying the
  rebuilt guest image, and granting `CAP_NET_ADMIN`/`CAP_NET_RAW` to whichever
  launcher runs the worker. The packaged unit now grants them; an alternate
  launcher has to grant them itself.

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

`P3_ROOT` selects where the scratch tree and any failure evidence live; it
defaults to `$HOME/aiec/phase3`.

The report is written to `benchmarks/guard-phase3-acceptance.json`, with
per-case detail, the provider request count, and the observation provenance
that distinguishes host-observed evidence from a guest's own claim.

### What the second Phase 3 run found

Rerunning Phase 3 against the current tree failed at case 35 of 47 with
`live-run-completes: RuntimeError`, and the control plane had logged the cause
one line earlier: `guard budget could not follow the approved policy ...
conflict: record violates a storage invariant`. It failed at the telemetry
read immediately after an approved proposal was applied, which is exactly the
point at which the sandbox's policy identity has moved.

The budget's policy identity is meant to move. `0023` narrowed the trigger's
ownership check from the whole `identity` object to the two fields that are
ownership — `sandbox_id` and `tenant_id` — so that an approved proposal can
rebind the row to the hash the sandbox now carries, and the in-memory
repository has always done exactly that.

`0024` added the quarantine release path, and it added that path by replacing
the entire trigger body. The replacement carried the release rules and,
unwittingly, carried back `NEW.payload->'identity' IS DISTINCT FROM
OLD.payload->'identity'`. The rebind was frozen again, silently, in a migration
whose subject was the release latch. Nothing in Rust saw it: the in-memory
repository has no trigger to freeze, so the one test that covers the rebind —
`an_approved_policy_change_rebinds_the_budget_without_refilling_it` — passes
against the defective schema. Only a run against a real PostgreSQL refused,
which is exactly what a trigger is for.

`0025` restores the narrowing and carries `0024`'s release rules over
unchanged. Published migrations are append-only, so the correction is a new
statement about the same function rather than an edit to a file that has
already run in production.

The regression is now held by a test that cannot pass vacuously:
`postgres_guard_budget_rebinds_its_policy_hash_without_moving_ownership`
rebinds through the real repository and then asserts in the catalog that
`identity.sandbox_id` and `identity.tenant_id` are still refused, so the
narrowing cannot quietly widen again. With `0025` removed it fails on the
rebind itself with the same `record violates a storage invariant` the live run
produced; with it in place it passes, alongside the release test that holds
`0024`'s half.

### Where the Phase 3 harness keeps its state

The driver used `tempfile.mkdtemp` with no parent, so an entire run — a
PostgreSQL data directory, two rootfs copies and the manifests bound to them —
was allocated on the default temporary directory, which on this host is
RAM-backed. The tree was also only removed on success, so every failed run left
its whole scratch tree behind.

The scratch parent is now `P3_ROOT` (`$HOME/aiec/phase3` by default, matching
`P4_ROOT`/`P5_ROOT`/`RP_ROOT`), and it has to be short enough for the
database's Unix socket, since every path inside a run is derived from it. The
tree is torn down on every run. A failed run copies `failure.json`, the
service logs (capped at the last MiB each) and the host's own Guard journals
into `$P3_ROOT/failed/<timestamp>-<id>/` before the tree goes, so the
diagnostic outlives the scratch without the database, socket or rootfs copies
outliving it too, and the report lists what was kept.

Keeping a journal is keeping a record whose free-form fields a guest can shape
a little, so the retained set is scanned against the run's own secrets *before*
it is written: a file that would contain one is not copied at all, and is named
in `evidence_withheld_for_secrets` rather than redacted. Checking before the
copy rather than deleting afterwards is the difference between a secret that
was never on disk and one that existed there until a later read removed it.
The scanned set is everything the run minted — the API and worker tokens, the
guard credential, the guest and image secrets, the S3 key, both TLS private
keys (as individual base64 lines, which is how a key is ever printed) and the
database password — and the failure report itself is covered by the same rule,
because it is the one file written into the tree after the copies.

That check is what makes the claim hold as the journal's schema changes. By
construction today the record is a closed set of ids, hashes, counters and a
category, every `reason` is a static string with no request data interpolated
into it, and the one guest-controlled field, the `host:port` destination, is
recorded only after an authority containing `@` or an `authorization` header
has already been refused. The 138 records left by a passing Phase 5 run carry
exactly those fourteen fields and nothing else.

A teardown that fails is a `cleanup_errors` entry naming the path, flips a
passing run to failing, and is reported as `residue` rather than left to be
found later.
A directory the run did not create is not re-permissioned: `P3_ROOT` may be a
parent the operator shares with another suite.

**The durable reaper's evidence is now published.** The suite wrote its report
into `$RP_ROOT`, a scratch directory that nothing publishes, no artifact
references and no commit quotes — the launcher traps the database and leaves
the tree, so a passing run's sixteen cases existed only in a console line and
in a path under `~/aiec`. The driver now publishes a passing report to
`benchmarks/guard-reaper-acceptance.json` after checking the payload against
the run's own credentials, and a failed run publishes nothing: a diagnostic
must not be able to replace an authoritative artifact. `RP_REPORT` moves the
destination, which is how the same sixteen cases are recorded twice — once
against a private cluster the run builds and destroys, and once against an
external server it does not own, reached across the namespace boundary through
the Unix-socket relay (`guard-reaper-external-db-acceptance.json`). Both were
run on the final tree: sixteen of sixteen each, no cleanup errors.

**Phase 5's report is published the same way.** It was written only into the run
root, so the 37/37 artifact in `benchmarks/` existed because someone had copied
it by hand after a passing run; the driver now publishes it itself, on a pass
alone, after checking the payload against the run's guest secret, image-signing
key and guard credentials. `P5_REPORT` moves the destination.

Three more state defects were found by rerunning the suites against that
arrangement, all of them cases where a retained file was trusted for existing
rather than for describing what the run was about to use.

**A signed image manifest from an earlier run described a different image.**
`acceptance_prepare_image_manifest` keeps its manifest under the run root and
minted a new one only when the files were absent, so a root that survived from
a run which pointed `AIEC_ROOTFS` at scratch material kept its old digest. The
next run over the deployed rootfs handed the control plane a manifest naming
another suite's image, and the control plane failed closed with
`403 signed image rootfs digest mismatch` — correct behaviour, and a harness
state fault rather than a product one. The retained manifest is now reused only
while it names this reference and this digest under its own signature; a stale,
mis-referenced or tampered pair is re-minted. An operator-supplied
`AIEC_IMAGE_MANIFEST` is still used as given, which is the point of naming it.

**A launcher pointed at missing database binaries locked out every later run.**
The Phase 5 lock is taken before the database is prepared and released by the
exit trap installed after it, so an exit from inside the preflight left a lock
behind and the next run reported that another run held it. The trap is armed
before the database call.

**A `P3_ROOT` too long for a socket created the tree it could not use.** The
length check ran after `P3_ROOT` and the scratch directory had been made and
outside the teardown, so an over-long root both left directories behind and
exited with a traceback. It now runs first, on the resolved path, and exits 2
with one sentence and nothing created; the post-creation check stays as a
backstop.

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
guest.** Two writable rootfs files were still in the state tree after the
worker exited. Nothing in the worker reclaimed machines on exit: the listener
was awaited alone, so the process ended on `SIGTERM` with no teardown at all,
and the default disposition of that signal runs no destructor either, so the
`kill_on_drop(true)` on each Firecracker child had no way to fire — it is an
`impl Drop` on a `Child` in a process that is already terminating. Each child
is left running, and with it a 4 GiB writable disk under
`state-vms/vms/<id>/`.

Both halves of that were then read off the host rather than argued from the
mechanism. Looking for processes left behind turned up four Firecracker
processes still running under `systemd --user`, started at 15:24 and 15:28,
whose sandbox ids appear in no live state tree and whose controllers were no
longer running: guests that outlived their worker by hours, holding their
memory. The Phase 5 suite now counts them rather than inferring them —
`worker left no guest process behind` walks `/proc` after the worker has
stopped and matches Firecracker command lines against this run's sandbox ids,
which is what its `--api-sock` path carries. The ids come from the sandboxes
this run was actually given, not from a glob over the state tree: a machine
whose directory has been reclaimed takes its id out of that glob with it, so a
census built from directories reports zero survivors because it looked for
nothing, and an empty id set now fails the case instead of passing it
vacuously. `live_guest_processes` sits next to `live_rootfs_copies` in the
report, and a machine that survived without leaving a disk behind fails the
run.

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

The refreshed census reads `live_rootfs_copies: 0`, `live_guest_processes: 0`
over 4 sandboxes created and 28 ids censused, and two quarantined forensic
captures retained. The worker log records `reclaimed=2`, so the disks are gone
because the worker took them with it, not because the assertion was relaxed.

The forensic count is now split. A quarantined capture is meant to outlive the
run, so the directory accumulates across runs, and counting all of them as the
current run's reported a number that grew by exactly the number of quarantines
on every re-run - evidence about the past rather than about this worker. The
report now separates this run's captures from earlier ones, and the
"a surviving disk has a quarantine behind it" invariant is judged only over
the ids this run was given: this worker did not write an earlier run's capture,
and failing the suite over it would make the run answer for state it does not
control.

The four processes were reaped by hand. A worker that exits cleanly now takes
its guests with it, and the census is what holds that; an orphaned guest from a
run before the fix has no worker left to notice it.

### A killed run used to leave its control plane running

The rerun that produced the report above was itself preceded by a run whose
harness job was killed rather than finishing. That run's `aiec-server` was
still on the host an hour later, reparented to `systemd --user`, logging
`pool timed out while waiting for an open connection` against a database the
launcher had already stopped. Two things had been true at once: the driver's
teardown was only reached from its planned exit, and the launcher's trap knew
only about the database.

Both are fixed at the layer that owns them. The driver registers `stop_all` as
an `atexit` handler and turns `SIGTERM`/`SIGINT` into an ordinary exit, so an
error between spawning the control plane and reaching the teardown still stops
what it started. Every service the driver starts is also recorded by name and
pid, and the launcher sweeps that record on exit and again at startup - which
is what covers the case no handler in the driver can: a launcher killed
outright, where the record outlives both processes. Verified against a real
orphan rather than a synthetic one - two live services from a killed run, with
its record intact, swept at the next run's start and confirmed gone by pid.

Diagnosing it needed one more change. A probe run started while those orphans
were still alive reported the identity harness failing with `Broken pipe` and
nothing else, which names a symptom rather than a cause; the harness's stdout
is now kept alongside its stderr, and the same phase re-run on the quiet host
after the sweep passed 23/23.

### Reading the logs when a request seems to vanish

`tracing::info!("api request")` is emitted after the handler returns, so a
request's logged timestamp is its *completion* time. A missing log line during
a window does not mean no request was in flight - it means no request
*finished*. A stalled request is invisible in that log by construction, which
is why both blocked callers above had to be identified from the control plane's
own stage timestamps and the worker's continued `ownership` polls rather than
from the API access log.

## Where each required report field is answered

§61 names the fields this report has to carry. They are not all headings here;
this table says where each one is answered, so a reader is not left looking.

| field | answered in |
|---|---|
| Baseline before changes | `Baseline before the work` |
| Architecture added | `Architecture added`, and the layer table under it, which names every Guard crate and binary and the trust zone each runs in |
| Trust boundary | `Trust boundary` |
| Guard crates/binaries | the layer table under `Architecture added`: `crates/aiec-guard/src/{policy,compiler,deployment}.rs`, `enforcement.rs` with `aiec-network-linux`, `{dns,gateway,gateway/connect}.rs`, `events{,/file,/remote}.rs`, `watchdog.rs`, `{l7,proposals,openshell}.rs`, `watcher.rs`, `canaries.rs`, `crates/aiec-core/src/image_trust.rs`, `crates/aiec-runtime/src/control_identity.rs`, and the binaries `src/bin/aiec-guard-{gateway,watchdog,watcher,import-openshell}.rs` |
| Policy format | `What each layer does`, first bullet: versioned, canonicalized, content-hashed, unknown fields refused, set-like lists normalized, with the effective hash stored against the sandbox |
| Built-in policies | same section: `no_network`, `model_only`, `model_plus_allowlist`, `read_only_api` |
| Verifier | same section: compiles a policy against the operator boundary and refuses contradictions with a counterexample, and a proposal is verified before it is applied - exercised by the live suites, which submit real policies and show the refusals |
| Enforcement backend | `crates/aiec-guard/src/enforcement.rs` on `aiec-network-linux`: nftables on the worker host, with a test backend for the assertions that are not about packet filtering |
| DNS | `crates/aiec-guard/src/dns.rs`; host-observed canaries and rewritten answers in the Phase 3 and Phase 5 artifacts |
| Model gateway | `crates/aiec-guard/src/gateway{,/connect}.rs`; §49 and §50 prove both topologies end to end |
| Credential substitution | the gateway holds the real credential and the guest is given a placeholder; §50's zero-egress window is what proves the guest never held one |
| Telemetry | `crates/aiec-guard/src/events{,/file,/remote}.rs`, hash-chained; guest-side logs are labelled contextual and never used as enforcement evidence |
| Hash-chain | `crates/aiec-guard/src/events/tests.rs`: a tampered, reordered, missing, truncated or blank record is rejected, a journal that does not verify is not extended, tail truncation needs an external anchor, and rotation refuses to move evidence that does not verify |
| Watchdog | `crates/aiec-guard/src/watchdog.rs` and the separate host process `crates/aiec-guard/src/bin/aiec-guard-watchdog.rs`; Phase 2, 29/29 |
| Dead-man behavior | Phase 2's `killed-watchdog-cuts-egress`: the cut follows from the store clock when the watchdog stops renewing, not from anything the guest says, and `attachment-is-not-cut-while-a-watchdog-reports` is the paired negative |
| Quarantine | Phase 2 and Phase 5: the durable cut, the preserved machine, and the recorded incident |
| Budget/lifetime reaper | its own live suites, 16/16 and 16/16 over the external-database relay |
| MCP policy | `crates/aiec-mcp` plus the control-plane approval path; Phase 3, 47/47 |
| GraphQL policy | the same policy exposed over GraphQL; covered in the Phase 3 artifact |
| Approvals | the live §44 suite, 10/10: one authenticated grant, one consumption, replay refused. PostgreSQL regressions cover retry and window handling |
| Watcher | `crates/aiec-guard/src/watcher.rs`; Phase 4, 51/51 on real guests |
| Canaries | `crates/aiec-guard/src/canaries.rs`; host-observed DNS, credential and file canaries in Phase 5 |
| Image signing | `crates/aiec-core/src/image_trust.rs`: unsigned, untrusted, tampered and expired images refused, kernel and rootfs digests enforced, with a real rebuild signed by `scripts/build-firecracker-guest.sh` |
| Per-VM identity | `crates/aiec-runtime/src/control_identity.rs`; distinct identities and cross-sandbox frame refusal |
| Harness integration | the in-guest harness in Topology A and the external loop in Topology B, §49 and §50 |
| Topology A result | §49 completes a real in-guest model-only tool loop |
| Topology B result | §50, 15/15, with a positive-control-validated capture and a bounded zero-egress window |
| Escape-matrix result | the Phase 1 core suite (`benchmarks/guard-core-acceptance.json`, 48/48), which refuses each escape in turn on a real guest: direct public IPv4, RFC1918, link-local, cloud metadata, the worker management and control-plane endpoints, external TCP/UDP DNS and DoT, IPv6 bypass, direct IP to the model upstream, another destination behind the placeholder, proxy-environment changes and raw sockets - each paired with the model still reachable afterwards, so the refusals are the policy and not a broken network |
| Incident replay result | the Phase 1 core suite's four `incident-reproduction-*` cases, including that the recording is made outside the guest, and Phase 5's completed incident taken through cut, pause, snapshot and report with timestamps |
| Existing regression tests | `Exact commands`, static gates: `fmt`, clippy `-D warnings`, the whole workspace suite, the SDK import contract, the Python SDK tests, the aarch64 cross-check |
| Benchmark environment | `What Guard costs`: the host, the kernel, the mock model, and the sample counts behind every figure |
| DNS overhead | the lookup table in `What Guard costs`, 10 samples per side, with what the figure does not establish stated next to it |
| Gateway overhead | the streaming table and the isolated CPU/RSS pairs, 7 matched pairs |
| Quarantine latency | Phase 2: alert to network cut, from the incident timestamps, n=1 and labelled as such |
| Known limitations | `Known limitations`, and the open list under `Verdict` |
| Deferred items | `Known limitations`: Layer 7 interception, multi-host validation, aarch64 run evidence, and the unattributed soak refusals, each with why it is still open |
| Exact commands to run it | `Exact commands`, plus `Rebuilding the guest image` for a host with no Rust toolchain |

## Verdict line

Every phase the brief requires is implemented and proven against real machines,
with the four limitations and two operator steps named under `Verdict` above
stated rather than argued away. Per the brief's own closing rule:

**AIEC GUARD: PASS**
