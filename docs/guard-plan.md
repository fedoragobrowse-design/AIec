Where phase 1 stands, with the evidence for each claim.

## Components delivered

`aiec-guard` is a new crate with no dependency on the control plane, so it
cannot create a cycle with the runtime or the API:

- `policy.rs` - versioned strict YAML, four templates, canonical JSON and a
  content hash, `GuardConfig` selection with no ambiguous expansion.
- `compiler.rs` - the operator boundary and a finite verifier that reports
  concrete counterexamples, plus `denied_networks()` as the single list of
  ranges denied at the kernel.
- `enforcement.rs` + private `render.rs` - per-attachment nftables tables,
  atomic replacement, named cumulative counters, and a `TestBackend` that
  models the same transitions.
- `gateway.rs` + `dns.rs` - the outside-guest broker, explicit allowlist proxy,
  and the authoritative resolver.
- `events.rs` + `events/` - the hash-chained journal, bounded replay, rotation,
  and a real bounded HTTPS remote sink.
- `bin/aiec-guard-gateway.rs` - a runnable policy verifier and standalone
  gateway.

Integration touches `aiec-core` (a typed optional Guard selection on
`EnvironmentSpec`), `aiec-network-linux` (`GuardNetworkManager`, the guarded
attachment lifecycle, and a legacy path that requires explicit operator
consent), `aiec-runtime` (Firecracker wiring, guest resolver configuration, and
broker model environment injection), `aiec-api` (an explicit Firecracker
requirement for Guard, a microVM placement floor for a guarded run, and a stored
policy hash verified at placement), and the client surfaces: the Python SDK's
`guard=` argument, the CLI's `--guard`, and `resources.guard` on the Run
document.

A Guard selection *replaces* the ordinary network policy rather than sitting
beside it, in the API, the SDK, the CLI and the run path alike. Two descriptions
of one egress would be two ways to reach the internet, and the wider one would
be the one that applied.

## One deliberate API change

`GuardGateway::restore` returns as soon as a release is *accepted*; traffic
stays cut until the release's audit record is durable. `restore_and_wait`
confirms the release actually took effect. This follows from the audit defect
below: a release that reopened traffic before its evidence existed could not be
distinguished, after the fact, from a cut that never happened.

## What the tests establish

Run by the parent, on the integrated tree:

- `aiec-guard`: 111 unit tests and 13 real-socket integration tests. The unit
  tests include ruleset-level accept/drop evaluation per chain, full-identifier
  table naming, nft-syntax injection attempts, protected-range denial, counter
  categorisation and accumulation, and the fail-closed transitions. The
  integration suite uses real listeners, real DNS wire messages, and real
  streaming backpressure.
- `aiec-runtime`: 101 unit tests plus the cross-runtime, Docker, E2B and
  failure-injection suites, including the 22 workspace-capture tests.
- `aiec-core` 57, `aiec-storage` 81, `aiec-api`, `aiec-cli` 10, `aiec-client` 11,
  and the Python SDK's 44 tests.

## Defects found by measuring, all reproduced and fixed

1. **Mixed-version artifact groups.** The first burst passed
   `expected_version = None` per chunk, so a same-size replacement between two
   completed chunks produced a group carrying the first half of one file and the
   second of another; the worker relabelled every frame with the last chunk's
   version and storage's checksum authenticated the hybrid. Fixed by pinning the
   first chunk's version *and* size across the group, and by refusing a
   disagreeing group before any frame is encoded.
2. **Reversible audit failure.** A journal write failure set the same flag an
   operator release clears; the regression test failed with a real request
   reaching the mock. Fixed with a latched terminal fault and durable
   release-before-reopen ordering.
3. **Docker workspace TOCTOU.** A guest that swapped a workspace entry for a
   symlink after the type check leaked host bytes into a tenant snapshot
   (`host bytes were captured at /workspace/probe`). Fixed with
   descriptor-relative `O_NOFOLLOW` traversal classified from `fstat` on the
   opened descriptor.
4. **Unbounded snapshot buffering.** A 512 MiB sparse file was read in full
   before the 64 MiB budget applied (`bytes_read=536872577`). The size is now
   checked on the opened descriptor before any allocation; the same measurement
   reports `bytes_read=1665`.
5. **Listing coupled to descendant contents.** A directory listing downloaded a
   recursive content archive, so three small files could fail a metadata
   request. Listing now answers from the bind mount directly.
6. **A link traversal reported a raw errno.** With `O_DIRECTORY` set a link
   answers `ENOTDIR`, not `ELOOP`, so listing through one surfaced
   `io error: Not a directory` instead of naming the link.

`docs/bug-hunt-2026-10-01.md` records each with its reproduction.

## The live Firecracker acceptance, as observed

Run on 2026-10-01 against the deployment host (`Linux 7.2.7-200.fc44.x86_64`,
x86_64, KVM available), with the driver built from this tree and run by
`scripts/guard-core-acceptance.sh` inside a disposable user+network namespace.
**40 of 40 cases pass on the release build, with `cleanup_errors: []`.**
The complete machine-readable evidence is
[`benchmarks/guard-core-acceptance.json`](../benchmarks/guard-core-acceptance.json).
This is one full acceptance run, not a throughput or multi-host security claim.

Observed passing, each on a real Firecracker microVM under a real Guard
attachment:

- two guarded sandboxes booted side by side, each with its own TAP, gateway,
  policy hash and nftables table;
- the synthetic model credential is absent from the actual guest environment,
  scanned host-side from the real exec output;
- the guest resolves the model hostname through the Guard resolver
  (10 DNS samples), and unrelated hostnames, TCP-DNS, `NS`, `TXT`, `NULL` and
  `ANY` queries are all refused;
- streaming model traffic through the broker with the placeholder (3 samples);
- wrong binding, wrong placeholder, wrong host, wrong method, wrong path, and a
  placeholder aimed at another proxy destination are each refused;
- direct public IPv4, RFC1918, link-local, cloud metadata, worker management,
  the control plane, external TCP DNS and DoT/853 are all refused, each
  verified against a host-side baseline that was reachable before the policy
  was installed - so a denied packet is a denial, not a missing route;
- `cleanup_errors: []`.

### The image prerequisite, now resolved

The earlier run stopped at `ipv6-route-preparation`: the deployed guest lacked
`ip`, so it could not install the IPv6 route needed to test the bypass. That
failure also meant the cases after it had not run, not that they had passed.

A separate acceptance rootfs was built without host root or a musl compiler:
`debugfs` extracted the already-deployed static guest agent; a disposable Debian
container supplied the packages including `iproute2`; `mke2fs -d` built the
filesystem in a root-mapped user namespace. No mount was required. The live
worker's image was not modified. The acceptance rootfs SHA-256 is
`62d77174adddec4e22f5566fff0ac22cfe7817e5d53c4d0dc2592e9f0aff1958`.

The guest installed its IPv6 address, permanent neighbor and default route.
The bypass then incremented the authoritative IPv6 deny counter and reached no
sentinel. The full memory/state/disk snapshot was created and scanned with both
VM disks, event journals and logs: **13,421,855,103 bytes, zero matches** for the
synthetic model secret. Eight model requests authenticated at the bound local
mock; none used a wrong credential.

Acceptance state used a short disk-backed `TMPDIR` (`/home/gobrowse/aiec/g`):
the host's quota-enabled `/tmp` tmpfs could not hold the full snapshot, and a
longer disk-backed path exceeded Linux's Unix socket path limit. Neither
constraint was bypassed by omitting a check.

The standard build script now includes `iproute2`. On an operator build host:

```sh
cargo build --release -p aiec-runtime --example guard_core_acceptance
# Load the Firecracker environment and point AIEC_ROOTFS at the built image.
# Select a short disk-backed scratch directory with room for full VM snapshots.
TMPDIR=/path/to/short/scratch \
  bash scripts/guard-core-acceptance.sh target/release/examples/guard_core_acceptance
```

### What the run found that the tests did not

Four real defects, all fixed, and each now carries a regression test:

1. **A worker could never admit its first sandbox.** Host headroom is measured
   with `statvfs` on the state directory, which does not exist until something
   creates it; the reading came back empty, which reads as an unmeasurable host
   and refuses every placement. The measurement now walks to the nearest
   existing ancestor. *Covered:* `a_path_that_does_not_exist_yet_still_yields_its_filesystem`
   and `a_worker_can_admit_with_a_state_directory_it_has_not_created_yet`.
2. **An unavailable backend was reported as an I/O error.** `into_core` collapsed
   every non-`Core` runtime error into `CoreError::Io`, discarding the class a
   caller branches on and burying "Guard refused" under a category that says
   nothing about who refused. *Covered:* `into_core_tests` in
   `crates/aiec-runtime/src/lib.rs` - the unavailable variant survives, a core
   error passes through unchanged, and everything else is still an I/O error with
   its text intact.
3. **A second sandbox could never attach.** The boundary accumulates the
   host's occupied addresses as protected ranges without deduplicating, so the
   second sandbox re-added a range the operator file already protected and Guard
   refused the duplicate. *Covered:*
   `an_address_the_boundary_already_protects_is_not_added_twice` and
   `a_guarded_peer_is_protected_once_however_often_it_appears`.
4. **The local-mock validator could not pass in the namespace it exists for.** It
   compared `/proc/self/ns/net` against `/proc/1/ns/net`, and PID 1's namespace
   link is unreadable from inside a fresh user+network namespace - so it failed
   with a permission error on exactly the configuration it was written to
   permit. The launcher now records the host's namespace inode before unsharing
   and the validator compares against that. *Covered:* five tests in
   `crates/aiec-guard/src/deployment.rs` covering both directions of the
   comparison, the unrecorded case, and a mock address outside the benchmarking
   range.

Guard's own failure messages were also a bare errno at every layer that could
refuse; those sites now name the operation, the address, and the reason. Finding
all four above depended on that, and no test asserts the labelling.

Two additional defects appeared only after the image prerequisite was removed:

- The raw ICMP probe constructed an odd-length packet but unpacked it as an
  even-length checksum input. The checksum now zero-pads only its summation
  input; the transmitted packet is unchanged. The live raw-socket bypass case
  then ran and was denied.
- Peer forwarding drops at equal hook priorities could charge the destination
  sandbox's counter rather than the originating sandbox's. Destination-side
  drops now run after all source-side Guard chains, for IPv4 and IPv6. The
  existing live peer-access case failed with a zero source deny delta before
  this change and passed with a source `blocked_range` increment afterward.
  No access permission or acceptance assertion was weakened.

Verification for these fixes: `scripts/gate.sh` passed, including all-feature
clippy and workspace tests and 44 Python SDK tests;
`cargo check --workspace --all-targets --all-features` passed separately.

### A note on commit `f530393`

That commit's message describes an experiment with configuring the guest's IPv6
address through a raw `SIOCSIFADDR` ioctl. The experiment was run, did not work
(`ENODEV` on a synthetic interface, `EINVAL` in the guest once the interface is
up, because the prefix length belongs in a netlink `RTM_NEWADDR` message rather
than in the ifreq a socket ioctl takes), and was reverted. The commit itself
contains one line: it removed the trailing newline from
`scripts/guard_core_guest_probe.py`. The message is wrong about its own contents.
It was pushed before the discrepancy was noticed, and force-pushing to correct
it would be worse than leaving history alone, so the record is corrected here
instead: the probe now reports `{"configured": false, "reason": "no ip binary
on the guest"}`, and the image prerequisite is unchanged.

## Phase 2: watchdog, dead-man switch and quarantine

### Implemented, and exercised by the gate

`fmt`, clippy with `-D warnings`, the full workspace test suite, the SDK import
contract and 44 Python SDK tests pass. The implementation covers:

- **Durable control-plane state.** `SandboxState::Quarantined` has no outgoing
  transition. Seven `MetadataStore` methods with concrete Memory and Postgres
  implementations and migration `0017_guard_durable_control.sql`. Ceilings and
  expiry are immutable after initialisation, usage only grows, and a SQL latch
  trigger refuses any update or delete that would release a quarantine.
  Reconcile, reassignment, stranded cleanup, claim and delete all exclude
  quarantined sandboxes. The scopes `guard:read`, `guard:heartbeat` and
  `guard:quarantine` exist, and a key cannot grant what its holder lacks.
- **Gateway dead-man switch.** A guarded attachment starts deny-all; the first
  identity-matched heartbeat installs the packet rules. The deadline is
  independent of the journal, so an audit failure cannot delay a cut. A
  dead-man cut latches and only the authorized release path clears it; an
  ordinary release is refused and the refusal is journaled.
- **Durable budget admission.** Every model request and every byte is reserved
  against the control plane through a fence-carrying HTTP client before it is
  forwarded. An unreachable authority refuses traffic rather than falling back
  to RAM. The policy's per-session ceilings are still enforced locally, so a
  permissive authority cannot widen what the operator wrote.
- **Watchdog.** A separate `aiec-guard-watchdog` process: deterministic rules
  over authoritative counters and the hash-verified journal, guest advisory data
  excluded, bounded configuration, private-CA support, retries that withhold the
  heartbeat rather than exiting, a webhook notifier with an explicit `Disabled`
  outcome, and an escaped Markdown incident report.
- **Control-plane orchestration.** Telemetry, heartbeat, quarantine and incident
  endpoints; a quarantine that cuts, captures without resuming, marks durably,
  appends the authoritative event, generates the report and notifies, with each
  stage retried until it succeeds and evidence extended rather than replaced.

### Proven by running code

- Phase 1 acceptance re-run against the phase 2 code: **41 of 41** on real
  Firecracker microVMs with real nftables, including a new case proving that an
  attachment carries traffic only after a watchdog heartbeat activates it.
  `benchmarks/guard-core-acceptance.json`.
- Phase 2 live acceptance (`scripts/guard-phase2-acceptance.sh`: a real control
  plane, worker, guest, watchdog process, database and kernel tables inside a
  disposable namespace). Observed passing: the watchdog key is narrowly scoped
  and cannot create sandboxes; a guarded sandbox starts; telemetry is anchored
  and authoritative; the watchdog heartbeats and the attachment stays live;
  killing the watchdog cuts egress while the VM survives for forensics; a
  triggered rule reaches the control plane; the durable quarantine mark lands and
  a resume is refused before and after a worker restart.
  `benchmarks/guard-phase2-acceptance.json` records the run in full, including
  the cases that failed.

### Defects the acceptance work found

1. The watchdog declined to heartbeat a cut attachment, and an attachment only
   leaves the cut *by* that heartbeat: a self-sustaining deadlock in which no
   guest ever had egress. Found by counting zero heartbeats across 382
   successful observations.
2. A quarantine fence compared for equality refused every request after a lease
   renewal, because a renewal legitimately advances the generation.
3. The first incident write was refused by the store's evidence validator,
   because the control plane created it with an empty anchor instead of seeding
   it from the authoritative journal.
4. The evidence refresh rewrote the incident's anchors with a continuation
   page's anchors, so every stage update was silently dropped.
5. The capture stage was gated on the pause, so a capture that failed after the
   pause could never be retried.
6. The quarantine endpoint held an HTTP request open across a multi-minute
   capture, which every client with a one-second budget abandoned.
7. A refused connection produced a TCP reset rather than a legible 503, and
   killing the connection hid the handler's own refusal.
8. An operator `cut()` was indistinguishable from a dead-man latch: an ordinary
   release could not reopen one, and a dead-man latch could be cleared by one.

## What is still not proven

- **A quarantine has not been observed reaching `completed_at` in a live run.**
  The pause-and-capture stage has not yet been seen to finish end to end on the
  deployed stack. Its behaviour is exercised by tests, and the durable mark, the
  resume refusal and the dead-man cut are observed live, but "the incident
  completes" is not yet observed evidence.
- **The phase 2 acceptance namespace is intermittently unable to move a packet
  from the guest to the attachment** - the guest reports ENETUNREACH with a
  default route present - which is why its blocked-range case passes in some runs
  and not others. The same counter path passes deterministically in the phase 1
  acceptance, so the mechanism is sound and the fault is in the harness's
  network setup, not in enforcement.
- **Phases 3 to 5 are not started**: L7 governance and human-only policy
  proposals, the optional watcher, canaries, image identity, per-VM credentials
  and the adversarial red-team harness. None of the phase 2 evidence stands in
  for any of them.

## Phases 2 to 6, and what gates each

The gates are not formality. Each phase's acceptance is what makes the next one
safe to start, and a phase that has not been exercised on real hardware is
code, not evidence.

**Phase 2 - watchdog and quarantine.** A separate deterministic observer, not a
second policy engine. It fails closed on lost liveness: if the watchdog cannot
observe what it is watching within its deadline, the sandbox is cut, because
silence is not health. Actions are idempotent and fenced to a sandbox and a
policy generation, so a cut already applied is not a second cut and an action
computed against a stale generation is refused. Escalation is ordered - cut,
then pause for forensics, then quarantine - and evidence is written *before*
each action, because an unrecorded cut is indistinguishable from a bug later.
This phase also carries the durable budgets phase 1 left process-scoped.
*Gate:* a cut, pause and quarantine each shown effective against a real sandbox;
a duplicate action shown to be a no-op; a stale-generation action refused; a
restart shown to preserve the budget; a watchdog whose own death leaves the
sandbox cut.

**Phase 3 - L7 governance.** Bounded inspection of visible HTTP, MCP and
GraphQL, with default-deny method and tool policies, plus human-only proposals
that a person decides and that are verified and applied atomically. This is
also where an OpenShell import reports what it cannot preserve. *Gate:* a
denied method, tool and GraphQL field shown actually refused; a proposal shown
requiring a human; an import shown reporting its unsupported fields rather than
converting silently.

**Phase 4 - optional watcher.** Disabled by default, with no tools, a rigid
validated output vocabulary, untrusted evidence kept separate from
authoritative facts, and sampled batched budgets. Deterministic restrictions
always win over anything the watcher says. *Gate:* a watcher output outside the
vocabulary refused; an unavailable watcher shown producing the recorded
continue-with-rules or pause-if-unavailable behaviour rather than silence.

**Phase 5 - additional safeguards.** Synthetic canaries for files, hostnames
and credentials; signed manifests and verified kernel/rootfs digests for
guarded workloads; a unique short-lived rotatable per-VM control identity held
outside portable snapshots; and a local-only adversarial red-team harness. *Gate:*
a canary reached is detected; a rotated identity is refused; a tampered manifest
is refused before boot.

**Phase 6 - integration and production acceptance.** The real tool-using
harness under model-only with a local streaming mock, topology B with zero guest
egress, the motivating DNS bypass reproduced and shown blocked, the escape
matrix, measured overhead, and deployment recovery. *Gate:* the full report,
with every claim tied to a command that was run.

## How the live runs are done, and what the environment still withholds

Both acceptances run the whole stack inside a disposable user+network namespace
(`unshare --user --map-root-user --net`), which is what supplies the privilege to
install nftables rules and keeps every table, TAP device and route out of the
host. Phase 1 uses `scripts/guard-core-acceptance.sh` and
`scripts/guard_core_guest_probe.py`; phase 2 uses
`scripts/guard-phase2-acceptance.sh` with the same probe.

```bash
# Phase 1: real microVMs, real nftables, local mocks only.
cargo build -p aiec-runtime --example guard_core_acceptance --release
AIEC_ROOTFS=<acceptance rootfs with iproute2> TMPDIR=<short disk-backed path> \
  bash scripts/guard-core-acceptance.sh ./target/release/examples/guard_core_acceptance

# Phase 2: control plane, worker, guest, watchdog process and database, all disposable.
cargo build --release -p aiec-api --bin aiec-server -p aiec-cli --bin aiec \
  -p aiec-guard --bin aiec-guard-watchdog
P2_DRIVER=$PWD/scripts/guard-phase2-acceptance.py \
  bash scripts/guard-phase2-acceptance.sh
```

Both emit one JSON document with a per-case status, the evidence for that case,
and any cleanup failure. A case that cannot be exercised is reported as failed,
never skipped.

### Two environment facts that are not Guard bugs

- **The running deployment's Firecracker worker cannot install Guard rules at
  all.** `aiec-worker.service` on 192.168.1.250 runs as `gobrowse` with no
  `User=`, no `AmbientCapabilities` and no file capabilities on the binary
  (`getcap` is empty and `sudo` needs a password), and its node row advertises
  `network_policy: false`. Every governed placement on that host is therefore
  refused with `nft could not read the host ruleset: Operation not permitted` -
  which is Guard behaving correctly, but it means **the production worker there
  has never enforced anything and is not enforcing anything now.** The fix is
  operational: run the worker as root, or grant it `CAP_NET_ADMIN`. The phase 2
  acceptance had to supply that privilege through a disposable user namespace
  precisely because the host could not.
- **The deployment's Neon `DATABASE_URL` password was printed into this working
  session while the acceptance was being set up, and should be rotated.** It was
  never written into this repository, but a credential that has been on a screen
  is a credential to replace.

### What the namespace still does not settle

The phase 2 harness intermittently cannot move a packet from the guest to the
attachment - the guest reports ENETUNREACH with a default route present - which
is why its blocked-range case passes in some runs and not others. The phase 1
acceptance exercises the same counter path deterministically, so the mechanism
is sound and the fault is in the harness's network setup. That is recorded as
an open harness defect, not as enforcement evidence in either direction.
