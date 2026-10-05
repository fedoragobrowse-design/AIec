# AIec Local MCP

An MCP server that hands any MCP-capable agent a disposable computer on **your
own** AIec cluster.

> **This server uses LOCAL AIEC COMPUTE.** AIec is open source and self-hosted;
> there is no hosted API. This server does not use an external sandbox provider
> either. Every command runs inside a sandbox on a control plane you control,
> and it refuses to start if it is pointed at a remote endpoint.

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
| `aiec_test_omp` | Submit one durable Run for an OMP revision and task |
| `aiec_compare_omp` | Bounded generic Run batch for baseline vs candidate |
| `aiec_run` | Run one workload and return the settled result |
| `aiec_run_batch` | Run several workloads, bounded concurrency |
| `aiec_run_matrix` | Run a matrix of cells, summarised per axis |
| `aiec_run_status` | Current state of one run |
| `aiec_run_events` | A run's history, in order |
| `aiec_run_cancel` | Stop a run and reclaim its machines |
| `aiec_health` | Local control-plane and capacity status |


### What "sandboxes this server created" means

`aiec_list_sandboxes`, the `aiec://sandboxes` resource and `aiec_health` all read
the same list: the machines this MCP server process created, fetched by id
rather than by scanning the tenant's list. Two properties of that list are worth
knowing before relying on it.

It **forgets**. A machine that has finished — destroyed, failed, or aged past
retention so the control plane no longer has it — is dropped from the list the
first time it is seen. So the list is "machines I still hold", not "machines I
have ever made", and a long-running server does not accumulate every sandbox it
has ever created. An explicitly destroyed sandbox was always removed.

It is **bounded**, and past the bound it is refused rather than shortened. A
partial list would be indistinguishable from a complete one, and a caller
treating "these are my machines" as complete would leave the rest running
without ever learning of them. Keep fewer than 200 live at once and destroy what
you no longer need. The bound is on this list only — the control plane's own
`GET /v1/sandboxes` is separately paged.

A typical loop from an agent:

```json
{"name": "aiec_create_sandbox", "arguments": {"image": "aiec-coding:latest", "runtime": "firecracker"}}
{"name": "aiec_exec", "arguments": {"sandbox_id": "<id>", "command": ["git", "status"]}}
{"name": "aiec_destroy_sandbox", "arguments": {"sandbox_id": "<id>"}}
```

The same loop as one durable run, which is the shape to reach for when the work
is a self-contained task rather than an interactive session:

```json
{"name": "aiec_run", "arguments": {
  "repo_url": "https://github.com/me/fixture",
  "command": ["pytest", "-q"],
  "validation_commands": [["pytest", "-q"]],
  "artifacts": ["report.txt"],
  "requirements": {"full_kernel_isolation": true}
}}
```

`aiec_run` returns the settled run: state, the task's exit code, bounded
stdout/stderr, changed files, artifact URLs and any machine that outlived it.
A workload that *failed* is reported on that document, not as a tool error --
"the work failed" is an outcome you asked for.

Runs are the control plane's own workflow, so this server does not rebuild it:
the API reserves the record, places the machine through the same registry the
sandbox API uses, runs the command, collects artifacts and reclaims the machine
before it answers. That is why a run keeps a history (`aiec_run_events`) and why
`idempotency_key` returns the run that already exists instead of doing the work
twice. `aiec_run_batch`, `aiec_run_matrix` and OMP comparisons use the generic
client's bounded Run batch, with `max_parallel` enforced before submission.
Generic HTTP evaluation routes also exist under `/v1/eval/`.

Resources: `aiec://sandboxes`, `aiec://sandboxes/{id}`, `aiec://local-capacity`.
Prompts: `test-repo-in-clean-sandbox`, `reproduce-bug-in-clean-machine`.

---

## Guarantees

These are enforced in code, with tests, not just documented:

- **Local only.** A non-loopback AIec URL is refused at startup. A private
  network address additionally requires `AIEC_MCP_ALLOW_PRIVATE_NETWORK=1`;
  A public cloud endpoint would be refused outright and cannot be enabled.
- **No host execution.** Workload commands are sent to AIec as an argument
  vector. There is no `std::process::Command` anywhere in the execution path, and
  a test asserts the crate contains none.
- **No provider fallback.** `hosted` and `e2b` runtimes are refused. If the local
  cluster is full you get `LOCAL_CAPACITY_UNAVAILABLE`, never a silent handoff.
- **Bounded.** Exec output is clipped and commands are subject to a timeout,
  enforced by AIec itself.
- **Clean.** Durable workflows use the Run's retention policy; destruction
  failures are returned as `cleanup_failed`, never silently treated as cleanup.
  `keep_sandbox` retains an OMP Run's machine for the configured debugging TTL.
  Legacy interactive sandbox ownership remains scoped to this server.

### Errors

`SANDBOX_NOT_FOUND`, `SANDBOX_NOT_RUNNING`, `LOCAL_CAPACITY_UNAVAILABLE`,
`COMMAND_TIMEOUT`, `OUTPUT_LIMIT_EXCEEDED`, `FILE_TOO_LARGE`,
`UNSUPPORTED_OPERATION`, `AIEC_API_UNAVAILABLE`, `LOCAL_RUNTIME_UNAVAILABLE`,
`AUTH_FAILED`, `INVALID_ARGUMENT`, `APPROVAL_REFUSED`.

`APPROVAL_REFUSED` is returned only when `AIEC_MCP_APPROVAL_REQUIRED=1` and the
control plane did not approve the call. Its details carry
`unreachable: true` when nobody answered, which is not the same as a refusal
and is not retryable.

The ask carries a SHA-256 digest of the whole call, not of its name, so an
operator's approval covers one invocation rather than a tool. `aiec_write_file`
digests `path` and `content` together: an approval to write one payload at a
path is not an approval to write another. For `aiec_write_file` the digest
covers every argument the tool accepts, and the operator queue shows the path
with a content length rather than the content itself — enough to recognise the
call, without printing an arbitrary payload into an approval queue.

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AIEC_MCP_BIND` | `127.0.0.1:8765` | Listen address; non-loopback needs `AIEC_MCP_ALLOW_REMOTE_BIND=1` |
| `AIEC_LOCAL_API_URL` | `https://127.0.0.1:18443` | Local control plane |
| `AIEC_LOCAL_API_KEY` | — | **Required**; the control-plane key |
| `AIEC_MCP_TOKEN` | generated | Token MCP clients present |
| `AIEC_MCP_TOKEN_FILE` | `~/.config/aiec/mcp-token` | Where the token lives |
| `AIEC_MCP_MAX_PARALLEL` | `2` | Maximum concurrent Runs in comparisons |
| `AIEC_MCP_DEFAULT_TTL` | `1800` | Sandbox lifetime in seconds |
| `AIEC_MCP_MAX_OUTPUT_BYTES` | `1048576` | Output and file size bound |
| `AIEC_MCP_ALLOW_PRIVATE_NETWORK` | off | Permit a control plane on your LAN |
| `AIEC_MCP_APPROVAL_REQUIRED` | off | Ask the control plane before a high-risk tool runs |

---

## The OMP workflow

`aiec_test_omp` and `aiec_compare_omp` are thin adapters to ordinary durable
Runs, not another sandbox scheduler. A comparison submits a bounded generic
batch for the baseline and candidate, with each repetition in its **own**
clean sandbox against the same target repository, task, validations and resources:

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

Results contain real durable `run_id`s, setup/task/validation outcomes, timing
phases, actual agent and target commits, git evidence and cleanup failures.
The `omp` task outcome and its exit-code slot are `null` if preparation failed
before execution; unknown wall time is `null`, not zero. Side summaries include
successful output as well as failed setup and validation diagnostics, and every
run's evidence remains in `baseline_runs` / `candidate_runs`. A rejected
submission is listed in `submission_failures`, not dropped or turned into a
fabricated task failure. Measurements are returned without choosing a winner.

The adapter always fetches the requested OMP branch, tag or commit into
`/workspace/omp`. By default it runs `bun install && bun run build` there;
`build_command` overrides that step. `setup_command` prepares the **target**
repository afterwards and cannot silently skip the OMP checkout. For a custom
invocation that does not need a build, explicitly use `build_command: ["true"]`.
The default invocation is the checkout's
`/bin/sh /workspace/omp/packages/coding-agent/scripts/omp --print -- <task>`,
not an assumed global `omp` executable. The upstream launcher starts Bun with
the checkout CLI/preload and restores the target working directory; the task
is one literal positional argument. An `omp_command` override gets the same
task on stdin and in `OMP_TASK`. The invocation is recorded in the task outcome.
The guest must provide Bun and whatever that revision's build requires.

OMP tools preserve `runtime`, `timeout_seconds`, `cpu`, `memory_mb`, `disk_mb`
and the generic `requirements` capability demands. Defaults are Firecracker,
900 seconds, 2 CPUs, 2048 MiB RAM and 2048 MiB disk, with outbound Internet
enabled for both repository checkouts and dependency/model access. Comparisons
use destroy retention; `aiec_test_omp` can request `keep_sandbox: true`, with
expiry managed by the control plane rather than MCP-private lifetime code.
Cleanup failure details are still returned when destruction fails.

Pass model credential **references** in `secrets`, resolved by the tenant's
secret store at execution time. `environment` is only for non-secret settings,
such as model selection and cache paths. Do not embed credentials in repository
URLs, command arguments, setup scripts or reports. Secrets are never copied
into the OMP adapter's request/report as values. Generic Run tools remain
agent-agnostic; OMP conventions live only in this adapter.

---

## Using it from an agent

A ready-made skill is in
[`docs/skills/aiec-sandboxes/SKILL.md`](skills/aiec-sandboxes/SKILL.md).
Copy it into your agent's skills directory to teach it the whole loop — which
tool for which situation, how to keep the sandbox TTL honest, and which typed
errors mean "wait" rather than "try somewhere else":

```bash
mkdir -p ~/.omp/agent/skills
cp docs/skills/aiec-sandboxes/SKILL.md ~/.omp/agent/skills/aiec-sandboxes/
```

---

## Architecture

```
MCP client  →  127.0.0.1:8765/mcp  →  aiec-mcp  →  local AIec API  →  worker  →  sandbox
```

MCP is an adapter on top of AIec, not a dependency of it: the dependency runs
Core → API/client → MCP, and AIec is fully usable with no MCP server present.
