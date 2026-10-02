# Guard policy reference

A Guard policy is one document that compiles into every enforcement artifact:
nftables rules, the DNS resolver's answers, the model broker's routes, the
credential bindings and the telemetry reasons. Its SHA-256 hash is the
identity Guard and the watchdog use, and it is stored on the sandbox.

## The two halves

**Sandbox configuration** (`guard`) is per sandbox and is not itself hashed:

| Field | Meaning |
|---|---|
| `topology` | `inside` runs the agent loop in the guest; `outside` runs it on the control plane |
| `policy_template` | `no_network`, `model_only`, `model_plus_allowlist`, `read_only_api` |
| `policy` | an explicit policy, mutually exclusive with the template inputs |
| `model_endpoint` | host, port, scheme, methods, paths, credential name |
| `allowlist` | extra destinations for `model_plus_allowlist` |
| `watchdog_timeout_ms` | dead-man deadline, 1000-60000, default 10000 |
| `max_model_requests` | immutable durable admission ceiling |
| `l7` | optional layer 7 governance (§27-§29) |
| `watcher` | optional second reviewer, disabled by default |
| `canaries` | optional synthetic tripwires |
| `require_signed_image` | refuse an untrusted image before boot |

**Policy** (`GuardPolicy`) is the hashed half:

```yaml
version: 1
network:
  dns:
    allowed_zones: ["model.example"]
    allowed_record_types: ["A", "AAAA"]
  egress:
    - host: api.model.example
      port: 443
      protocol: tcp
      allowed_methods: ["POST"]
      allowed_paths: ["/v1/chat/completions"]
model:
  host: api.model.example
  port: 443
  scheme: https
  allowed_methods: ["POST"]
  allowed_paths: ["/v1/chat/completions"]
  credential: model-main
credentials:
  - name: model-main
    from_env: MODEL_API_KEY
limits:
  requests_per_minute: 60
  dns_queries_per_minute: 120
  bytes_in: 1048576
  bytes_out: 262144
  max_request_bytes: 262144
  max_response_bytes: 1048576
  max_concurrent_requests: 4
```

Every list is normalized before hashing, so two documents that mean the same
thing produce the same hash and the same rules. Unknown fields are refused
rather than ignored: a policy that silently drops a field is a policy whose
enforcement nobody has read.

## Templates

| Template | The guest may | Named for |
|---|---|---|
| `no_network` | nothing at all | running untrusted code with no egress |
| `model_only` | one model endpoint, through Guard | coding and tool-use agents |
| `model_plus_allowlist` | the model plus an operator's list | agents that genuinely need a package registry |
| `read_only_api` | GET/HEAD on read-only APIs | research and analysis agents |

No template can express open internet access, and adding one is a policy change
that goes through the same verifier and the same human approval as any other.

## The verifier

`aiec guard verify <policy>` compiles the policy against the operator boundary
and reports contradictions with counterexamples: a destination that is both
allowed and blocked, a credential bound to a host the policy does not permit, a
limit that exceeds the boundary, a path rule that can never match. It is not a
linter; it refuses policies whose enforcement would not be what the document
says.

The operator boundary is separate from the policy on purpose. It is what the
host forbids - metadata ranges, the cluster's own networks, loopback - and a
policy cannot widen it. The acceptance suite includes counterexamples for each
class of contradiction.

## Layer 7 governance

Layer 7 rules apply only to traffic Guard can see. In the default `sni` mode
Guard matches the requested hostname and forwards the tunnel: it sees the name,
not the request. Method and path policy requires `mode: intercept` and an
explicit `intercept_ack`, because interception means Guard terminates TLS and
can therefore read everything it forwards.

```yaml
l7:
  mode: intercept
  intercept_ack: true
  http:
    - host: api.github.com
      methods: [GET, HEAD]
      paths: ["/repos/*/readme"]
  mcp:
    allowed_methods: ["tools/list", "tools/call"]
    allowed_tools: ["read_file", "search"]
    denied_tools: ["delete_repository", "deploy", "rotate_key"]
  graphql:
    allow_mutations: false
    operations: ["ReadRepo"]
    root_fields: ["repository", "viewer"]
```

An unlisted MCP method or tool is denied. An unlisted GraphQL operation or root
field is denied, and mutations are denied unless `allow_mutations`. GraphQL
parsing is bounded: a document Guard cannot parse within its limits is refused,
not guessed at.

## Credentials

A credential is a named binding from an environment variable to a placeholder
the guest receives. The guest never holds the real value: the broker
substitutes it at request time, for the bound destination only, and the
substitution is logged as a metadata event with no secret in it. A placeholder
presented to any other destination is refused, and a canary credential
configured for the sandbox is an immediate quarantine.

## Changing a policy

An agent may propose. Only a human may approve, and approval runs the verifier
first. A rejected verification blocks the apply, an applied policy produces a
new hash, and both outcomes are audit events. The previous policy stays in force
until the new one is applied atomically.