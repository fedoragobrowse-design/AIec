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

## What is not yet proven

The live Firecracker acceptance run has not been executed. The driver
(`crates/aiec-runtime/examples/guard_core_acceptance.rs`) and launcher
(`scripts/guard-core-acceptance.sh`) exist, compile, and are designed to fail
loudly rather than report a partial pass, but until the run is observed on real
hardware with a real guest, the escape matrix, the guest-visible credential
absence, the streaming and DNS measurements and the cleanup census are claims
about code rather than observations.

**No later phase may start before that run passes.** Phase 2's design is settled
in `local://guard-phase2-contract.md` and is deliberately not implemented.

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

The acceptance needs a Firecracker host with KVM, a built guest image, and a
control plane to place against. This workstation has KVM and Docker but no
running AIec control plane (`https://127.0.0.1:18443/health` does not answer),
and the deployment host's Firecracker environment is reached over SSH rather
than exercised in place. Running the driver against a control plane the
operator has not started would mean starting one, and that is a deployment
change rather than a test.

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