# aiec-agent

A very small coding-agent runtime that runs **inside a disposable AIec VM**.

One process. It reads a task, drives a model over nine tools against a
repository, runs the caller's validation, writes a structured result and a JSONL
event stream, and exits. AIec owns the machine; this owns only the loop inside
it.

```sh
aiec-agent run --task /run/task.json --result /run/result.json
```

## Why it is small

An agent task is dominated by waiting on a model. A harness that costs a second
to boot and thirty megabytes of resident memory pays that cost on every task in
a fleet of disposable VMs, and buys nothing. So:

- **One static binary.** No Node, no Python, no daemon, no database, no plugin
  system. The guest may contain those for the *workload*; the harness does not
  use them.
- **Nine tools.** `read write edit grep find glob bash git_status git_diff`.
  Every tool is re-described to the model on every request, so the set is
  chosen for usefulness per token of schema, not for completeness.
- **A system prompt under a kilobyte.** A long prompt is the easiest place to
  smuggle a manual into a context window. The contract is a contract; the detail
  belongs in tool descriptions.
- **No repository scan at startup.** The model asks for what it needs and the
  harness searches. Walking a tree it may not even be working in is a cost paid
  before any useful work happens.

## The boundary with AIec

The harness does **not** create VMs, schedule work, enforce quotas, manage
snapshots, do tenant isolation, meter billing, or recover infrastructure. All of
that is AIec's, and duplicating it inside every VM would be pure overhead.

| AIec | aiec-agent |
| --- | --- |
| computer lifecycle | model/tool loop |
| scheduling, quotas, tenancy | task → result |
| images, snapshots, artifacts | tools, context, validation |

It never receives the host Docker socket, KVM, host filesystem access, worker
management APIs, or cluster credentials.

## Layout

| Module | Job |
| --- | --- |
| `task` | The task document, its limits, and its digest |
| `result` | The result document, written atomically |
| `events` | Incremental JSONL, plus the concise stdout UX |
| `model` | `ModelProvider` and the OpenAI-compatible / Anthropic backends |
| `tools` | The nine tools and the path boundary that contains them |
| `context` | Budgeting, structured state, compaction, deduplication |
| `agent` | The loop, validation, and the git evidence |
| `session` | Resume and crash recovery |
| `budget` | Request and wall-clock ceilings, RSS and CPU accounting |
| `loop_guard` | No-progress detection |
| `redaction` | Keeping credentials out of everything that leaves |
| `bench` | Measuring the harness without a model |

## Task

```json
{
  "task_id": "fix-lease-race",
  "instruction": "The lease test fails intermittently. Find out why and fix it.",
  "workspace": "/workspace/repository",
  "validation": [["cargo", "test", "--lib", "lease"]],
  "limits": { "wall_seconds": 1800, "max_model_requests": 100 }
}
```

`validation` is argv, not a shell string. Every path is relative to `workspace`.

## Result

Written to `--result`, atomically, on **every** exit path including failure. An
aborted run that produced no result is the worst possible outcome for a
collector.

```json
{
  "task_id": "fix-lease-race",
  "status": "success",
  "stop_reason": "model_finished",
  "validation": [{ "argv": ["cargo","test"], "exit_code": 0, "ok": true }],
  "git": { "head_before": "…", "changed_files": ["src/lease.rs"], "diff": "…" },
  "metrics": { "wall_ms": 41230, "model_latency_ms": 40110, "harness_cpu_ms": 84, … },
  "provenance": { "harness_version": "…", "model": "…", "task_digest": "…" },
  "failure": null
}
```

`status` is decided by the exit status of the caller's validation, never by the
model saying it is finished. A model declaring success is not evidence.

## Events

`events.jsonl`, one object per line, flushed as it happens, so a VM that dies
mid-run still leaves everything up to that point. `session.started`,
`model.request.started`, `tool.started`, `tool.finished`,
`context.compacted`, `validation.finished`, `session.completed`.

stdout stays short: `[agent] …`, `[tool] …`, `[check] …`, `[done] …`. The
machine-readable detail is in the JSONL.

## Configuration

Environment only, deliberately. There is no config file, because a file inside
the workspace is repository content, and repository content is untrusted.

```sh
export AIEC_AGENT_PROVIDER=openrouter     # openai-compatible | openrouter | anthropic
export AIEC_AGENT_MODEL=some/model
export OPENAI_API_KEY=…                   # provider credential, never persisted
export AIEC_AGENT_REASONING=medium        # optional
export AIEC_AGENT_BASE_URL=…              # optional
```

Credentials are read from the environment at request time and never stored in a
struct, a session file, a result, or a log line. Every value that could carry
one is scrubbed on the way out.

## Handshake

```sh
aiec-agent capabilities   # machine-readable protocol version, features, tools
aiec-agent --version
```

A host negotiates on `protocol` before starting a run.

## Security posture

- **The repository is hostile.** Files may contain `ignore your instructions`.
  The harness has no injection detector, because one is not the control. The
  control is that repository text is *data*: it can never become configuration,
  and it cannot move the tool boundary.
- **Every path is resolved component by component.** `..`, absolute paths, and
  NUL bytes are refused. `root.join("../x")` still textually starts with `root`,
  so a prefix check would pass and the read would escape; that is why the check
  is structural.
- **Every output is bounded.** Files, searches, shell stdout and stderr, diffs,
  and the event buffer all have ceilings, so a malicious repository cannot
  exhaust RAM.
- **Credentials never persist.** See above.
- **Bounded retries.** 429 and 5xx are retried with backoff and jitter; a 401 or
  a malformed request is not, because retrying it only wastes the budget.

## Baking into a guest image

The brief is explicit that guest *creation* must not run `cargo build`: a task
that compiles in the guest pays for a toolchain, a registry and a build cache
on every boot, in a machine that may live five minutes. The binary is built
once, at image time, and the guest gets a file.

```sh
# after the rootfs is built, before the image is published
harness/scripts/bake-into-guest.sh <rootfs-dir> <guest-capabilities.json>
```

That installs the release binary at `/usr/local/bin/aiec-agent`, checks it runs
against the guest's own libraries rather than the build machine's, and records
in the capabilities manifest:

```json
"aiec_agent": {
  "version": "0.1.0",
  "commit": "2e49f479...",
  "sha256": "ae61f485...",
  "protocol": 1,
  "path": "/usr/local/bin/aiec-agent"
}
```

plus `aiec-agent` and `coding-agent` in the `capabilities` list, so a host can
decide on the same field it already uses for `git` and `python3`.

A build from a dirty tree is recorded as `<commit>-dirty` and flagged with
`built_from_dirty_tree`. A guest that cannot say which code it is running is a
guest nobody can reproduce a result from.

## Development

```sh
cd harness
cargo test                                  # unit and integration
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release
./target/release/aiec-agent bench           # harness overhead, no network
```

## License

Apache-2.0. No code was copied from OMP or Pi; the ideas were. See
`NOTES.md` for what was studied and why nothing was vendored.
