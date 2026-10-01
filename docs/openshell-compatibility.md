# OpenShell policy compatibility

Source: NVIDIA OpenShell, Apache-2.0, policy schema reference, read at commit
`71440b28f48d5fefc569d779f70d6e63893aa80a` (2026-10-01):
<https://github.com/NVIDIA/OpenShell/blob/71440b28f48d5fefc569d779f70d6e63893aa80a/docs/how-it-works/policies/schema.mdx>

Pinned deliberately. A `main` URL moves under this document, and a branch moving
is how a compatibility claim quietly stops describing the thing it describes.
The path `docs/reference/policy-schema.mdx` is 404 at this commit and was not
used; earlier drafts of this file that cited it were wrong.

No OpenShell code is copied into AIec. This document records what its schema
means for a Guard policy, field by field, because "we support OpenShell
policies" is not a claim that can be made honestly.

## Directly expressible

| OpenShell | Guard |
| --- | --- |
| `version: 1` | `version: 1` |
| endpoint `host`, `port`, `ports` | exact host and single port |
| `protocol: tcp` | `protocol: tcp` |
| `access: read-only` | `allowed_methods: [GET, HEAD, OPTIONS]` |
| `access: read-write` | `allowed_methods` including `POST`, `PUT`, `PATCH` |
| `access: full` | no method restriction |
| REST `rules[].allow.method` | `allowed_methods` |
| REST `rules[].allow.path` | `allowed_paths` (segment-prefix match) |
| `enforcement: enforce` | always: a rule either permits or refuses |
| `tls: skip` | destination-only rules; see limitations |
| `allowed_ips` | not accepted; Guard resolves and checks the actual address |
| `network_policies.<name>` | `network.egress` entries, keyed by host and port |

`enforcement: audit` has no equivalent, deliberately. A Guard rule that cannot
be enforced is refused rather than logged and allowed, because the audit mode's
purpose - observing what a policy *would* block - is only meaningful while
something else blocks it.

## Not expressible, and refused rather than approximated

**Binary-scoped rules.** Every OpenShell endpoint may carry a `binaries` list,
and the semantics are "the executable that opens the connection, or any of its
parent processes", with the executable's hash recorded on first use. A gateway
that runs outside the guest cannot establish which executable opened a
connection: a compromised guest controls what it reports. Guard's rules are
therefore per-sandbox, not per-binary, and a `binaries` clause is refused. A
policy that depends on binary scoping for its security property does not
convert.

**Filesystem, Landlock and process identity.** `filesystem_policy`,
`landlock.compatibility`, `process.run_as_user` and `process.run_as_group` are
enforced by OpenShell inside the sandbox. They have no meaning to a network
gateway, and Guard's host-side gateway cannot grant them. Note that OpenShell
itself rejects root for `run_as_user`; that is a property of their policy
schema, not something Guard reproduces.

**Credential binding and signing.** `credential_binding.provider`,
`request_body_credential_rewrite`, `websocket_credential_rewrite`,
`allow_uninspected_credentials`, `credential_signing`, `signing_service` and
`signing_region` describe provider-profile integration. Guard substitutes a
single bound credential on the model path and has no provider profile, body
rewriting, WebSocket credential rewriting or AWS request signing. These fields
are refused.

**DNS policy.** OpenShell's DNS controls are binary-scoped as well, so the same
argument applies. Guard's DNS is a strict subset by design: exact configured
names, `A` and `AAAA` only, no recursion into unknown zones, and
`allowed_record_types` that cannot name `ANY`, `NS`, `TXT` or `NULL`.

**Middleware.** `network_middlewares`, including `on_error: fail_closed`, run
in-process on inspected traffic. Guard has no in-process middleware chain in
phase 1, so a middleware stanza is refused.

**GraphQL, MCP and JSON-RPC inspection.** OpenShell inspects request bodies
against per-revision rules: GraphQL operation types and field globs, MCP tool
names and method availability per protocol revision, JSON-RPC method names.
Guard phase 1 does not inspect request bodies at all. A policy carrying
GraphQL, `mcp`, `json-rpc` or `deny_rules` is refused as unsupported, because
accepting it would mean reporting a restriction Guard does not apply. These are
the subject of the later governance phase, which will inspect bounded requests
and report exactly what it can and cannot see.

## Import behaviour

An importer, when written, must produce a report listing every field it
dropped, mapped or refused, and must refuse the conversion if any unsupported
field carries a security property that the operator did not explicitly
acknowledge. A conversion that silently drops a `binaries` clause would hand
the operator a policy that looks equivalent and is strictly weaker.

## The honest summary

Guard and OpenShell agree on destination-level, default-deny, operator-bounded
network policy, and on refusing what cannot be enforced. They do not overlap on
in-sandbox enforcement, and a policy is not portable between them in either
direction without a report.
