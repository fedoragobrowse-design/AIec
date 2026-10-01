# AIec Guard policy files

Operator-facing policy, selection and boundary files for AIec Guard phase 1.
Everything here is parsed and validated by `aiec-guard` (`policy.rs`,
`compiler.rs`); no file is read by the guest and no file contains a secret.

## Policy templates

| File | Template | Who may reach what |
| --- | --- | --- |
| `no-network.yaml` | `no-network` | Nothing. Default when no policy is selected. |
| `model-only.yaml` | `model-only` | Only the configured model endpoint, through the Guard broker. Recommended for in-VM agent loops (topology A). |
| `model-plus-allowlist.yaml` | `model-plus-allowlist` | The model endpoint plus the listed read destinations. |
| `read-only-api.yaml` | `read-only-api` | Listed destinations, read-only methods only, no model credential. |
| `model-only.local-mock.yaml` | `model-only` (operator test only) | A local mock model service over plain HTTP; requires the matching operator test mapping. |

`guard-config.no-network.yaml` and `guard-config.model-only.yaml` are the compact
selection form (`GuardConfig`) that `effective_policy()` expands into exactly the
same policy as the corresponding full document.

Selecting nothing is `no-network`. A selection is either an explicit `policy:` or
a template plus its inputs; supplying both is rejected as ambiguous. Nothing in
the schema widens to open internet.

## What the schema refuses

* unknown or duplicate YAML keys, and documents over 64 KiB;
* non-canonical hosts: uppercase, wildcards, trailing dots, IP literals, URLs,
  ports, paths or credential-bearing forms;
* port 0, any protocol other than `tcp`, paths with traversal, wildcards, query
  or fragment syntax, non-uppercase method tokens;
* DNS record types other than `A` and `AAAA` (`ANY`, `NS`, `TXT`, `NULL` are
  refused, not ignored);
* zero or out-of-range limits, an unbounded list, a duplicate destination, a
  credential binding that does not match the model endpoint exactly, a model
  endpoint with no egress rule, and a DNS zone with no route behind it.

## Boundary files

`boundary.production.yaml` is the production operator boundary.
`boundary.local-test.yaml` is for local acceptance runs only and must never ship
to a worker.

Precedence, highest first:

1. `protected_cidrs` and `blocked_hosts` always deny, including the gateway,
   guest, peer-sandbox and management `/32`s runtime adds. A test mapping can
   never override them.
2. Operator `blocked_cidrs` always deny.
3. Guard's default non-public ranges deny RFC1918, loopback, link-local and the
   `169.254.169.254` metadata endpoint, CGNAT, multicast, documentation and
   reserved space, plus the IPv6 equivalents.
4. An exact `test_destinations` entry (`host:port` -> addresses) may authorize a
   local mock address past step 3, and only for that host and port.

`test_destinations` entries are operator input: they may list only non-public
addresses, they never create an egress permission on their own, and a model
endpoint with `scheme: http` is refused at compile time unless one exists for its
exact host and port.

## Verifier scope

`compile()` validates the policy, canonicalizes and hashes it, then evaluates the
finite rule model exhaustively: every egress rule, model endpoint and credential
binding is checked against the boundary, and every blocked range is probed with
concrete representative addresses. Failures are reported as concrete
counterexamples naming host, port, rule and range, for example:

```
DENIED BOUNDARY VIOLATION: host=api.example-model.com port=any protocol=any
matched rule=Guard default blocked range: 169.254.169.254 is inside
169.254.0.0/16 (link-local range, includes the cloud metadata endpoint
169.254.169.254)
```

This is complete for the compiled rule model. It is not a formal proof about the
host network, live DNS answers or the guest kernel, and no SMT solver is claimed.