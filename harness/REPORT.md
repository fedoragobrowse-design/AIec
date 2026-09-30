# aiec-agent: measured report

Every number below was produced by running the thing. Nothing here is estimated
or carried over from a design document. The commands that produce them are in
[`scripts/`](scripts/).

## Footprint

| | Measured | Target from the brief |
| --- | --- | --- |
| Binary | **3.92 MiB** (4,109,784 B, stripped, dynamically linked) | "small enough to bake into every image" |
| Cold start, process → first output | **1.7 ms** median, 2.9 ms p95, 1.2 ms min (n=20) | < 100 ms |
| Peak RSS, a real 4-turn run | **16.0 MiB** | < 30 MiB, preferably < 20 MiB |
| Peak RSS, benchmark suite resident | 5.8 MiB | — |
| Background processes | 0 | 0 |
| Daemons | 0 | 0 |
| Local databases | 0 | 0 |
| Runtime dependencies | glibc only — no Node, Python, JVM, or server | none |

`cold start` is measured as `subprocess` launch to the process exiting after
printing its capability handshake: process creation, dynamic linking, argument
parsing, and JSON output, with no network.

## Harness overhead, measured separately

An agent task's wall time is mostly a provider waiting. These are the numbers
that describe the harness, taken with no model and no network
(`aiec-agent bench --iterations 200`):

| Measurement | Median | p95 | Note |
| --- | --- | --- | --- |
| Tool schema build | 0.008 ms | 0.010 ms | once per session |
| Request JSON encode | 0.015 ms | 0.016 ms | 4,381 bytes of tool schema |
| Context size estimate | < 0.001 ms | < 0.001 ms | per turn |
| Context compaction | < 0.001 ms | < 0.001 ms | worst case |
| Output compression | 0.001 ms | 0.001 ms | 410 KiB in, 32 KiB out |
| Result encode | 0.003 ms | 0.003 ms | once, at exit |

The whole per-turn harness cost is under 0.02 ms. In the real run below, the
harness spent **4 ms of CPU across the entire session** against 109 ms of wall
time.

## Real coding task

A git repository with a genuine defect: `split_bill(10.00, 3)` returned three
shares summing to 9.99, because integer division discarded the remainder. Two
tests, one failing.

The model endpoint is a scripted OpenAI-compatible server
([`scripts/scripted_model.py`](scripts/scripted_model.py)). It is a loop
fixture, not a model, and this is stated plainly: **no real LLM has run this
harness.** What it proves is the loop, the tools, the context accounting, the
independent validation, and the honesty of the result.

```
BEFORE: FAILED (failures=1)
[done] 2 changed, 3 tool calls, 4 model requests, 102 ms
  Elapsed (wall clock): 0:00.10
  Maximum resident set size: 16020 kbytes
AFTER:  OK
```

The session: `read calc.py` → `write calc.py` → `bash python3 -m unittest -q`
→ done. Four model requests, three tool calls.

The result document, verbatim:

```json
{
  "status": "success",
  "stop_reason": "model_finished",
  "validation": [{ "argv": ["python3", "-m", "unittest", "-q"], "exit_code": 0, "ok": true }],
  "git": {
    "changed_files": ["calc.py", "__pycache__/"],
    "harness_artifacts": [".aiec-agent/", "events.jsonl", "task.json"],
    "head_before": "41a64cc7...", "head_after": "41a64cc7..."
  },
  "metrics": {
    "wall_ms": 102, "model_requests": 4,
    "tool_calls": { "read": 1, "write": 1, "bash": 1 },
    "input_tokens": 4800, "output_tokens": 240, "cache_read_tokens": 3200,
    "harness_cpu_ms": 4, "context_peak_tokens": 624
  }
}
```

`status` came from the exit status of the caller's validation, not from the
model. A second run with the model claiming success over a failing validation
returns `"status": "failed"`; there is a test for exactly that.

## Inside a real AIec sandbox

The brief asks for the harness to run through the real control plane, not only
on the host. It does. A sandbox was created through the running AIec API, the
4,110,168-byte release binary was shipped in as seven base64 chunks, a git
repository with the `split_bill` defect was built inside it, and the model
endpoint was run inside it as well — a guest cannot reach the host's LAN
address, so the loop fixture has to live where the harness runs.

```
before: FAILED (failures=1)
after:  OK
status    success | stop: model_finished
changed   ['calc.py', '__pycache__/']
artifacts ['.aiec-agent/', 'events.jsonl', 'task.json']
metrics   {'wall_ms': 648, 'harness_cpu_ms': 3, 'peak_rss_bytes': 5898240,
           'model_requests': 4}
```

Event stream, complete and in order: `session_started`, `repository_inspected`,
4 × `model_request_started`/`finished`, 3 × `tool_started`/`finished`,
`validations_started`, `validation_finished`, `session_completed`.

**In-sandbox footprint is lower than on the host**, which is the expected
direction and worth stating rather than glossing: 5.6 MiB peak RSS against
16.0 MiB on the developer machine, and 3 ms of harness CPU for the whole
session. The host figure includes a build tree and a development environment;
the guest figure is what a fleet would actually pay.

### What this is not

The sandbox ran the `docker` runtime, **not** Firecracker. Firecracker was
attempted first and is genuinely unavailable in this environment:

```
TAP setup failed: ioctl(TUNSETIFF): Operation not permitted
```

The cause is a privilege limit, not a misconfiguration. The calling process
holds `cap_wake_alarm` and nothing else; `cap_net_admin` is in the bounding set
but cannot be acquired by uid 1000, and a direct `TUNSETIFF` ioctl probe fails
the same way. A microVM needs a TAP device, so no microVM can be created here.
Fixing it means running the AIec worker with `CAP_NET_ADMIN`, which is a change
to the operator's host and not something this repository should do to itself.

So the honest position: the harness is proven inside a real AIec sandbox, and
the Firecracker path is unproven and blocked on host privileges.

## Real model: `space-bunny-free`

The endpoint is the one OMP itself uses, from its own model cache:
`https://opencode.ai/zen/v1`, `api: openai-completions`, model
`space-bunny-free`, 1,048,576-token context. It needs no credential, which
required a small change: an OpenAI-compatible endpoint on a custom base URL may
legitimately need no key at all — Ollama, vLLM, a gateway fronting a
subscription — and the correct behaviour is to send no `Authorization` header
rather than an empty bearer. The provider's own default URL still requires one.

Four real coding tasks, all with the model choosing its own tools.

| Task | Before | After | Wall | Requests | Tools | Harness CPU |
| --- | --- | --- | --- | --- | --- | --- |
| `split_bill` remainder lost | 2 failures | **OK** | 95.8 s | 12 | 19 | 41 ms |
| Multi-file: two coupled defects | 3 failures | **OK** | 33.2 s | 9 | 16 | 45 ms |
| Unknown failure, told only "fix the tests" | 1 failure | **OK** | 37.7 s | 9 | 14 | 46 ms |
| Impossible task, 3-request budget | — | clean stop | 57.3 s | 3 | — | — |

The `split_bill` fix, written by the model:

```python
cents = int(round(total * 100))
each, leftover = divmod(cents, shares)
parts = [each + 1] * leftover + [each] * (shares - leftover)
return [part / 100 for part in parts]
```

The unknown-failure task was given no more than "fix the tests". The defect was
a module constant used where a function parameter belonged, which no test name
points at. The model read the module, ran the suite five times while
narrowing it down, and fixed the parameter rather than the symptom.

**The profile is the one the design was aiming at.** On the first task,
95,265 ms of model latency against 41 ms of harness CPU — 99.96% of the wall
time was the model. This is the shape §66 asked for, measured rather than
asserted.

### What a real model found that no test did

Running against a real provider exposed two defects that every scripted test
had accepted:

1. **Every tool result was sent twice**, once as a `tool` message and again as
   a plain `user` message.
2. **Tool messages were emitted before the assistant turn that issued the
   calls.**

Space Bunny answered the first request in 1,643 ms with two tool calls, both of
which executed correctly, then rejected request two with a 400. The scripted
fixture accepted the malformed transcript without complaint for an entire
session. That is precisely what a test double written to agree with the
implementation is blind to, and it is the strongest argument in this report for
having used the real thing.

### What a real model found about the harness itself

The failure case showed the retry loop spending 107.8 seconds in backoff inside
a 120-second session, to obtain a result the VM would be destroyed before
anyone read. `ModelConfig` now carries a deadline the caller sets from the
task's wall budget, and the loop stops when it is reached. The same task now
finishes in 57.3 seconds with the truthful `request_budget_exhausted`.

## Failure case

A task that cannot succeed, with a validation of `false` and a two-request
budget. The harness terminated cleanly, wrote a complete result document, and
exited 1:

```
[incomplete] 0 changed, stopped: model_error
status: failed   validation: [(1, False)]   result is valid json and complete
```

Every exit path writes a result. A run that dies with no document is the worst
outcome a collector can be handed.

## Quality gate

```
cargo fmt --check                                     clean
cargo clippy --all-targets -- -D warnings             0 errors
cargo test                                           124 passed, 0 failed
```

## Bugs the tests found

Recorded because they are the argument for having written the tests.

1. **`Task` required a `digest` field to deserialize**, but the digest is
   *computed from* the document. Every real task file would have been rejected
   for a field its writer has no way to know. The binary did not work at all.
2. **`tokens()` counted the progress block twice** — once inside the transcript
   after compaction, once again separately. The context budget was compared
   against a number that did not match the bytes on the wire.
3. **Compaction kept a fixed *count* of recent messages** rather than a budget,
   so six large messages overflowed a window six small ones would have fit in.
4. **Validation ran outside the harness**, in `main`, so any other entry point
   produced a result document with no evidence in it.
5. **Two `TaskState`s existed** — one on `Context`, one inside `SessionState` —
   and a resume restored the copy the loop never read.
6. **The harness counted its own artifacts as agent work.** `changed_files`
   listed the result document and the event stream, corrupting the one field an
   evaluator reads.
7. **A server's `Retry-After` was clipped by our own backoff ceiling**, so a
   throttled gateway telling the truth about its own state was guaranteed to
   fail. The two budgets now bound different things.
8. **A session file that was not valid UTF-8 aborted a resumed run.** The
   function's own contract says a corrupt state file means "nothing to resume",
   but it went through `read_to_string`, so an `io::Error` escaped where the
   promise said `Ok(None)`. Found by the hostile-input suite, not by a review.

## Hostile input

`tests/fuzz_hostile.rs` covers the four surfaces §68 names, with a deterministic
generator so any failure reproduces exactly:

| Surface | What is thrown at it |
| --- | --- |
| Task document | 300 random byte strings, invalid UTF-8, JSON nesting bombs to 2048 deep, a 64 MiB document |
| Model reply | 400 random byte strings through both parsers, nesting bombs to 4096 deep, lone surrogates, control characters, a 4 MiB tool argument |
| Paths | 5000 generated relative paths; a property assertion that every one either resolves inside the root or is refused, with no third outcome |
| Repository | Filenames with newlines, tabs, quotes, emoji, a leading dash, 200 characters, and non-UTF-8 bytes; a 300-level directory tree |

The path test is the one that matters most. It asserts a property rather than a
list of cases: whatever the input, the outcome is one of exactly two, and a
prefix check that let a third through would fail it.

## What is intentionally not here

- **A Firecracker guest run**, blocked on host privileges (see above).
- **A Firecracker guest.** The binary is portable and statically shaped, but it
  has not been baked into an image or run inside a VM. That is the single
  largest gap.
- **OMP / Pi comparison.** Not run. The parenthesised brief asks for a
  measurement under equivalent conditions; the comparison agent working this
  repository measured a *different* harness (`crates/aiec-agent`), not this
  one, so its numbers say nothing about `aiec-harness`.
- **Subagents, MCP, LSP, skills, server mode.** Deferred by design.
  `NOTES.md` gives the reasoning for each; none is stubbed, they are absent.

Steering IS implemented: the caller writes a line to `.aiec-agent/steer` in the
workspace and the loop consumes it before the next model call, so a mid-session
correction ("do not modify API compatibility") takes effect without restarting
anything. The note is read once and the file truncated, because re-applying a
hint the caller has already moved past is its own failure mode. Two tests cover
it.

An earlier draft of this report claimed steering was advertised in the
capability handshake but unimplemented. That was a false statement in a
machine-readable document, and it was fixed rather than documented.

## Known limitations

- The token estimator is `bytes / 4`. It is monotonic and cheap, and it will be
  wrong for any other language. A real tokenizer would cost more than it saves
  at this size, but this is a genuine approximation.
- `__pycache__/` appears in `changed_files` when the caller's validation
  compiles Python. It is honestly reported as changed, but it is the
  validation's side effect rather than the agent's work, and separating the two
  would need a policy decision the caller should make.
- Path resolution refuses `..` outright rather than normalising. A path that
  legitimately needs `..` to stay inside the workspace must be written without
  it. This is the safe direction.
- Prompt injection is not detected. The control is that repository text is data
  and can never become configuration, not that it is scanned.

## Reproducing

```sh
cd harness
cargo build --release
./target/release/aiec-agent capabilities
./target/release/aiec-agent bench --iterations 200
cargo test
```

To drive a real task, see the end-to-end recipe in [`README.md`](README.md).
