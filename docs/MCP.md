# AIec Local MCP

An MCP server that hands any MCP-capable agent a disposable computer on **your
own** AIec cluster.

> **This server uses LOCAL AIEC COMPUTE.** It does not use AIec Cloud, and it
> does not use an external sandbox provider. Every command runs inside a sandbox
> on a control plane you control. The server refuses to start if it is pointed at
> a remote endpoint.

---

## Quickstart

```bash
cargo build --release -p aiec-mcp
```

Configure it:

```bash
export AIEC_LOCAL_API_URL=https://127.0.0.1:18443
export AIEC_LOCAL_API_KEY=af_live_...
export AIEC_TLS_CA_CERT=/path/to/ca.pem     # if the control plane uses TLS

./target/release/aiec-mcp
```

It listens on `127.0.0.1:8765` and serves MCP at `http://127.0.0.1:8765/mcp`.

On first run a bearer token is generated and stored at
`~/.config/aiec/mcp-token` with mode `0600`. Set `AIEC_MCP_TOKEN` to supply your
own, or `AIEC_MCP_TOKEN_FILE` to move it.

### Connecting an MCP client

| | |
|---|---|
| Name | `AIec Local` |
| URL | `http://127.0.0.1:8765/mcp` |
| Transport | Streamable HTTP |
| Authorization | `Bearer <contents of ~/.config/aiec/mcp-token>` |

The token is required on every `/mcp` request. `GET /health` is deliberately
left open so a supervisor can probe it without holding a credential.

---

## Tools

| Tool | What it does |
|---|---|
| `aiec_create_sandbox` | Create a disposable local sandbox |
| `aiec_list_sandboxes` | List sandboxes this server created |
| `aiec_get_sandbox` | Current state of one sandbox |
| `aiec_destroy_sandbox` | Destroy a sandbox and confirm cleanup |
| `aiec_exec` | Run a command **inside** a sandbox |
| `aiec_read_file` / `aiec_write_file` / `aiec_list_files` | Files inside a sandbox |
| `aiec_prepare_repo` | Clone a repo into a fresh sandbox |
| `aiec_run_repo_task` | Clone → setup → task → validate → diff → destroy |
| `aiec_test_omp` | Build one OMP revision in a clean sandbox and run it |
| `aiec_compare_omp` | Baseline vs candidate, each in its own clean sandbox |
| `aiec_health` | Local control-plane and capacity status |

A typical loop from an agent:

```json
{"name": "aiec_create_sandbox", "arguments": {"image": "aiec-coding:latest", "runtime": "firecracker"}}
{"name": "aiec_exec", "arguments": {"sandbox_id": "<id>", "command": ["git", "status"]}}
{"name": "aiec_destroy_sandbox", "arguments": {"sandbox_id": "<id>"}}
```

Resources: `aiec://sandboxes`, `aiec://sandboxes/{id}`, `aiec://local-capacity`.
Prompts: `test-repo-in-clean-sandbox`, `reproduce-bug-in-clean-machine`.

---

## Guarantees

These are enforced in code, with tests, not just documented:

- **Local only.** A non-loopback AIec URL is refused at startup. A private
  network address additionally requires `AIEC_MCP_ALLOW_PRIVATE_NETWORK=1`;
  `https://api.aiec.gobrowse.dev` is refused outright and cannot be enabled.
- **No host execution.** Workload commands are sent to AIec as an argument
  vector. There is no `std::process::Command` anywhere in the execution path, and
  a test asserts the crate contains none.
- **No provider fallback.** `hosted` and `e2b` runtimes are refused. If the local
  cluster is full you get `LOCAL_CAPACITY_UNAVAILABLE`, never a silent handoff.
- **Bounded.** Exec output is clipped and commands are subject to a timeout,
  enforced by AIec itself.
- **Clean.** High-level tools destroy their sandbox on success *and* on failure.
  Shutdown cleans only sandboxes this server created.

### Errors

`SANDBOX_NOT_FOUND`, `SANDBOX_NOT_RUNNING`, `LOCAL_CAPACITY_UNAVAILABLE`,
`COMMAND_TIMEOUT`, `OUTPUT_LIMIT_EXCEEDED`, `FILE_TOO_LARGE`,
`UNSUPPORTED_OPERATION`, `AIEC_API_UNAVAILABLE`, `LOCAL_RUNTIME_UNAVAILABLE`,
`AUTH_FAILED`, `INVALID_ARGUMENT`.

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AIEC_MCP_BIND` | `127.0.0.1:8765` | Listen address; non-loopback needs `AIEC_MCP_ALLOW_REMOTE_BIND=1` |
| `AIEC_LOCAL_API_URL` | `https://127.0.0.1:18443` | Local control plane |
| `AIEC_LOCAL_API_KEY` | — | **Required**; the control-plane key |
| `AIEC_MCP_TOKEN` | generated | Token MCP clients present |
| `AIEC_MCP_TOKEN_FILE` | `~/.config/aiec/mcp-token` | Where the token lives |
| `AIEC_MCP_MAX_PARALLEL` | `2` | Concurrent sandboxes for comparison runs |
| `AIEC_MCP_DEFAULT_TTL` | `1800` | Sandbox lifetime in seconds |
| `AIEC_MCP_MAX_OUTPUT_BYTES` | `1048576` | Output and file size bound |
| `AIEC_MCP_ALLOW_PRIVATE_NETWORK` | off | Permit a control plane on your LAN |

---

## The OMP workflow

`aiec_compare_omp` runs a baseline and a candidate revision of a coding agent
against the same target repository, task, validations and resources, each in its
**own** clean sandbox, and returns measurements:

> I changed OMP's compaction implementation. Does it actually improve things?

```json
{"name": "aiec_compare_omp", "arguments": {
  "omp_repo": "https://github.com/can1357/oh-my-pi",
  "baseline_ref": "main",
  "candidate_ref": "feature/compaction-v2",
  "target_repo": "https://github.com/me/fixture",
  "task": "add a regression test for truncated output",
  "repetitions": 3
}}
```

You get successful/failed runs, validation passes, wall time, exit codes,
changed-file counts and diff sizes, per side. All sandboxes are destroyed
afterwards. It returns measurements, never a verdict about which is better.

The generic tools work with any agent; OMP-specific conveniences live in this
layer only. If OMP needs a model, give the sandbox the provider credentials it
expects (`models.yml`, or the provider's own environment variable) — the server
deliberately does not hold model credentials for you.

---

## Architecture

```
MCP client  →  127.0.0.1:8765/mcp  →  aiec-mcp  →  local AIec API  →  worker  →  sandbox
```

MCP is an adapter on top of AIec, not a dependency of it: the dependency runs
Core → API/client → MCP, and AIec is fully usable with no MCP server present.
