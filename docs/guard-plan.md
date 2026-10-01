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
**18 of 19 cases pass; the 19th fails for a reason stated below.**

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

### The failing case, and why it was not made to pass

`ipv6-route-preparation` asserts that a guest *which has an IPv6 route* still
cannot bypass the unconditional IPv6 drop. The deployed guest image ships no
`ip` binary, so the guest cannot install that route and the case reports
`{"configured": false, "reason": "no ip binary on the guest"}` - correctly, as a
failure.

The image fix is `iproute2` in the guest package list, which is now in
`scripts/build-firecracker-guest.sh`. Rebuilding the image here is not possible:
the guest agent is a static musl binary by design, the deployment host has no
`musl-tools` and no root to install it, and the ext4 image cannot be mounted
unprivileged. So this case is **not exercised**, and it is recorded as such
rather than redefined into a pass - weakening the assertion to accept a guest
that could not run it would have made the report say something the evidence
does not support.

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

## What is still not proven

`ipv6-route-preparation`, above, and everything phase 2 onward. The phase 2
watchdog, phases 3 to 5, and the phase 6 production acceptance are unimplemented
by design: the plan gates them on the phase 1 run, and the phase 1 run is not
clean.

**No later phase may start before that case passes.** Phase 2's design is
settled in `local://guard-phase2-contract.md` and deliberately not implemented.

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

## Why the live run has not happened here

The acceptance needs three things, and this workstation has only the first:
KVM, a built guest image, a control plane to place against, and — less
obviously — the privilege to install nftables rules. It has KVM and Docker but
no running control plane (`https://127.0.0.1:18443/health` does not answer),
and the deployment host's Firecracker environment is reached over SSH rather
than exercised in place.

The privilege one is a property of the code, not of the host, and is worth
stating plainly: a worker probes `nft list ruleset` at startup and advertises
`network_policy: false` without `CAP_NET_ADMIN`. On this workstation that
probe returns "Operation not permitted", so a worker started here would refuse
every governed placement — correctly, and for a reason that has nothing to do
with the acceptance driver. This is also why
`scripts/guard-core-acceptance.sh` runs the whole thing under
`unshare --user --map-root-user --net`: the namespace is what supplies the
privilege. Treat a run that reports "cannot enforce" as a missing prerequisite,
not as a Guard bug.

So the driver and launcher are delivered, compile, and are written to fail
loudly - a missing route, an unreachable sentinel, an absent counter, a wrong
event reason, a secret found in the guest, or a leftover table all prevent a
`PASS` - but their output has not been observed. Anyone with a Firecracker
worker can run it directly:

```bash
cargo build -p aiec-runtime --example guard_core_acceptance --release
# with the worker's Firecracker environment loaded:
bash scripts/guard-core-acceptance.sh ./target/release/examples/guard_core_acceptance
```

The result is a single JSON document with one entry per acceptance case, the
kernel counter deltas, the verified event chain, the observed stream and DNS
latencies, the hardware it ran on, and any cleanup failure. A case that could
not be exercised is reported as failed, not skipped.