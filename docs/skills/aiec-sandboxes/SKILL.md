---
name: aiec-sandboxes
description: Run code, tests and agent evaluations in disposable local sandboxes on the user's own AIec cluster via the local MCP server. Use when asked to "run this in a sandbox", "test this in isolation", "get a clean machine", "evaluate two revisions of an agent", "compare OMP versions", "reproduce a bug in a clean environment", or when a task involves running untrusted, generated, or repetitive code that should not touch the host. Covers aiec_create_sandbox, aiec_exec, file tools, aiec_run_repo_task, aiec_test_omp and aiec_compare_omp.
---

# AIec local sandboxes

Give the user disposable computers on hardware they control, instead of running
generated or untrusted code on the host.

The MCP server is **local-only by construction**: it refuses to start against a
remote AIec endpoint, and `hosted` / `e2b` runtimes are unavailable. Every
command runs inside a sandbox. **Never** fall back to running a command on the
host because a sandbox failed, and never suggest a cloud provider as a
substitute.

---

## Setup

The server is already running for this instance:

| | |
|---|---|
| Endpoint | `http://127.0.0.1:8765/mcp` |
| Auth | `Bearer <contents of /tmp/aiec_mcp_token>` |
| Control plane | `https://127.0.0.1:18443` (forwarded to the KVM host) |

If it is not responding, start it from the AIec repository:

```bash
./target/release/aiec-mcp
```

A token is generated on first run and stored `0600`. Never print it in full, and
never commit it.

---

## Choose the right tool

| Situation | Tool |
|---|---|
| One command, or a few | `aiec_create_sandbox` → `aiec_exec` → `aiec_destroy_sandbox` |
| Need files in the machine | `aiec_read_file`, `aiec_write_file`, `aiec_list_files` |
| Clone a repo and poke at it | `aiec_prepare_repo` |
| Run a task and report the diff | `aiec_run_repo_task` |
| Test one revision of a coding agent | `aiec_test_omp` |
| Compare two revisions of a coding agent | `aiec_compare_omp` |
| Is the local cluster healthy? | `aiec_health` |

Prefer the high-level tools. `aiec_run_repo_task` clones, runs setup, runs the
task, runs every validation, collects `git_status` and `git_diff`, and destroys
the machine — including when the task fails. Doing that by hand with
`aiec_exec` is how sandboxes get leaked.

---

## Patterns

### Run something once

```json
{"name": "aiec_create_sandbox", "arguments": {"image": "aiec-coding:latest", "runtime": "firecracker"}}
{"name": "aiec_exec", "arguments": {"sandbox_id": "<id>", "command": ["pytest", "-q"], "timeout_seconds": 600}}
{"name": "aiec_destroy_sandbox", "arguments": {"sandbox_id": "<id>"}}
```

`aiec_exec` takes an **argument vector**, not a shell string. It runs inside the
sandbox, is bounded, and times out. Pass `{"command": ["sh","-c","..."]}` only
when you genuinely need shell features.

Always destroy the sandbox when you are done, including after a failure.

### A repository task, start to finish

```json
{"name": "aiec_run_repo_task", "arguments": {
  "repo_url": "https://github.com/owner/repo",
  "runtime": "docker",
  "task_command": ["python", "-m", "pytest", "-q"],
  "validation_commands": [["python", "-m", "pytest", "tests/test_x.py"]],
  "timeout_seconds": 900
}}
```

`sandbox_id` is `null` in the result when the machine was cleaned up. It is only
set when you passed `keep_sandbox: true`.

`runtime` defaults to `firecracker`. Use `docker` on a host whose worker cannot
be granted `CAP_NET_ADMIN`, because a microVM there cannot get a network and any
repository clone will fail.

### Reproduce a failure and keep the machine

Pass `keep_sandbox: true`, then work inside the returned id with `aiec_exec` and
`aiec_read_file`, and destroy it yourself at the end. The machine still has a
TTL, so do not leave it around.

### Compare two revisions of an agent

```json
{"name": "aiec_compare_omp", "arguments": {
  "omp_repo": "https://github.com/can1357/oh-my-pi",
  "baseline_ref": "v9.7.0",
  "candidate_ref": "v9.8.0",
  "target_repo": "https://github.com/me/fixture",
  "task": "add a regression test for truncated output",
  "repetitions": 1,
  "runtime": "docker"
}}
```

Each side runs in its **own** clean sandbox with the same target, task,
validations and resources. You get successful and failed runs, validation
passes, wall time, exit codes, changed-file counts and diff sizes.

**Report the measurements, not a verdict.** "The candidate is better" is not a
supported conclusion from these numbers — say what improved, what regressed, by
how much, and where the evidence is thin. If one repetition is all you ran, say
that the result is a single sample.

---

## Things that will bite you

- **Network is opt-in.** `network_enabled` defaults to `false`. A clone needs it
  on. On a Firecracker host without `CAP_NET_ADMIN`, `network_enabled: true`
  fails at create; use the `docker` runtime instead.
- **Images.** `aiec-coding:latest` is the coding guest. `python:3.13`,
  `node:24`, `rust:stable`, `ubuntu:24.04` and `alpine:3.21` are the standard
  set. `aiec:latest` does not resolve.
- **Read-only rootfs** for container sandboxes: `/root` is not writable. Point
  `HOME`, `PI_INSTALL_DIR` and any cache at the workspace.
- **Disk.** The stock rootfs image is 4 GiB; asking for more fails at create.
- **Typed errors, not prose.** `LOCAL_CAPACITY_UNAVAILABLE` means the local
  worker is full — wait or use a smaller sandbox. Do **not** quietly reroute the
  work elsewhere. `SANDBOX_NOT_RUNNING` means it died; create another.
  `COMMAND_TIMEOUT` and `OUTPUT_LIMIT_EXCEEDED` mean the command was cut short,
  so its result is not trustworthy.
- **A non-zero exit is a measurement, not an error.** `aiec_run_repo_task` still
  runs every validation and still cleans up, so a failure is informative.
