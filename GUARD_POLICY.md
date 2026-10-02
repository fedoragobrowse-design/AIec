# AIec Guard

Guard governs what a sandbox can reach, from outside the guest, and proves what
it did. It is a set of components added to the existing AIec platform, not a
second platform: the same `Sandbox`, `Run`, worker, lease and lifecycle paths
serve guarded and unguarded workloads.

## What Guard is for

An agent inside a disposable machine is the least trusted part of the system.
It runs model-chosen commands, it is handed a workspace it can rewrite, and a
prompt injection in a repository it clones is enough to make it try. Guard
therefore keeps the *decisions* outside the machine: which destinations exist,
which DNS names resolve, which credentials are used, and what was attempted.
A guest that is fully compromised can still ask for things; Guard is what
refuses them, and the evidence is kept where the guest cannot rewrite it.

## The two topologies

**Topology A - the agent runs inside the VM.** The guest gets exactly one
reachable path: the Guard broker on its own TAP. Model traffic is addressed to
a placeholder, `placeholder://<binding>`, and Guard substitutes the real
credential outside the guest. DNS answers for the model name resolve to the
gateway, so the guest cannot open a direct connection to the provider even if it
ignores the harness configuration. This is the recommended shape for in-VM
agent loops.

**Topology B - the agent runs outside.** The trusted harness drives the sandbox
through AIec's existing control channel, and the guest is given no egress at
all. No policy selected means no network.

Guard is not a data-loss-prevention system, and it is not a claim of
completeness. Model prompts remain an information channel. Host or gateway
compromise defeats software-only enforcement, which is why enforcement, policy,
credentials and evidence all live outside the guest rather than being
configuration the guest can be trusted to honour.

## How enforcement works

For a guarded sandbox, the worker creates an isolated TAP pair, assigns one
`/30` from its own address space, and installs nftables rules that only ever
touch the two tables it created for that attachment. On the guest's interface:

- only the assigned guest source reaching the gateway address on the DNS and
  broker ports is permitted;
- operator blocked ranges - including Guard's default private, loopback,
  link-local, metadata, CGNAT, multicast, documentation and reserved space, and
  the protected gateway/guest/peer/management addresses - are dropped and
  counted;
- any other source is dropped as anti-spoofing, and everything else is dropped
  too, with no accept on connection state, so a cut takes effect against a flow
  that was already established;
- forwarding is dropped in both directions, so the guest is not a router;
- IPv6 is dropped unconditionally.

There is no NAT and no ordinary internet path. Nothing in Guard references a
host table, and applying or releasing one sandbox cannot change traffic that
belongs to another.

## Verifying a policy without deploying it

```bash
cargo run -p aiec-guard --bin aiec-guard-gateway -- \
  --policy policies/guard/model-only.yaml \
  --operator-boundary policies/guard/boundary.production.yaml \
  --verify-only
```

The verifier walks the finite rule model and refuses a policy whose egress
rules, model endpoint or credential bindings name a host that the operator
boundary blocks, reporting a concrete counterexample naming the host, port,
rule and range. `Ok` is a pass for that model. It is not a proof about the host
network, live DNS answers, or the guest kernel.

## Operating a guarded worker

| Variable | Meaning |
| --- | --- |
| `AIEC_GUARD_CREDENTIALS_FILE` | Owner-only `0600` JSON map of binding name to secret. Read by the worker, never by the guest. |
| `AIEC_GUARD_BOUNDARY_FILE` | Operator boundary: extra blocked ranges, protected addresses, blocked hosts, and operator test destinations. |
| `AIEC_ALLOW_LEGACY_NETWORK` | `1` permits the pre-Guard network backend. Without it, an unguarded sandbox that asks for a network is refused rather than silently unfiltered. |
| `AIEC_GUARD_TEST_MODE` | `1` enables local mock destinations, and only inside an isolated network namespace using `198.18.0.0/15` addresses. |
| `AIEC_ALLOW_REDUCED_ISOLATION` | Control-plane only. `1` permits a guarded sandbox on a runtime weaker than a microVM. Default off, and the creation response reports the downgrade in `x-aiec-isolation`. Guard's network guarantees are stated for microVMs; this is the setting that stops them applying, so it belongs in the same table as the other ways to weaken a boundary. |

Credentials are never arguments, never part of a sandbox or run document, and
never written into a guest image, environment, or snapshot. The broker
substitutes them on the way out and the guest only ever holds a placeholder.

## What Guard does not do

- It does not inspect opaque TLS. A `CONNECT` tunnel is permitted only for
  destination-only rules, is validated for a visible matching SNI, and refuses
  ECH, early data, and a missing or duplicated server name. Rules that need
  method, path, tool or operation visibility are refused on a CONNECT path with
  an explicit event rather than being quietly unenforced.
- It does not follow redirects or environment proxies. Redirects are denied and
  upstream addresses are resolved and checked by the gateway itself.
- It does not answer `ANY`, `NS`, `TXT` or `NULL` queries, and it does not
  recursively resolve a name outside the configured zones.
- It does not keep a durable, per-VM control identity or a durable model budget
  across restarts yet. Those are later phases, and the gateway reports its
  limits as process-scoped until then.
- It does not claim OCSF conformance. The event schema is OCSF-inspired.

## Evidence

Guard writes a hash-chained journal outside the guest, one JSON record per
decision, with bounded metadata only: there is no field for a prompt, a body, a
header, or a credential, and records carrying one are refused. The chain proves
mutation, reordering and interior deletion. It cannot by itself prove that a
trailing run of records was removed, so the remote sink's acknowledged head is
the anchor an operator checks against. A journal that is unreadable, truncated
or fails to replay is refused rather than repaired: a record is only accepted
once it is durably on disk.

If the journal cannot be written, the gateway is cut and stays cut. Recovering
a sink is not recovering a gateway - that requires a new gateway after a
verified replay - so a release request is refused while the fault is latched,
and the latched state is reported by `health`.

## Policy files

`policies/guard/` holds the shipped templates, selection examples, and boundary
files, documented in [`policies/guard/README.md`](policies/guard/README.md).

## Relationship to OpenShell

Guard was designed against the current public NVIDIA OpenShell policy schema
(<https://github.com/NVIDIA/OpenShell/blob/main/docs/how-it-works/policies/schema.mdx>,
Apache-2.0), which is read for its semantics only. No OpenShell code is copied.

OpenShell's schema is richer than an out-of-guest gateway can honestly honour.
Its rules are scoped to *binaries*, and Guard cannot verify from outside the
guest which executable opened a connection - a compromised guest can claim any
binary it likes. Landlock, filesystem and process-identity fields are enforced
by OpenShell's own sandbox runtime, not by a network gateway. An import of an
OpenShell policy is therefore expected to report unsupported semantics and to
refuse lossy conversion; there is no blanket compatibility claim. See
[`docs/openshell-compatibility.md`](docs/openshell-compatibility.md).
