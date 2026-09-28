# Notes: what was studied, and what was deliberately not taken

## The two systems

**OMP (Oh My Pi)** — a general coding-agent harness: TypeScript, distributed as a
Bun binary, with an extensive tool surface, subagent delegation, MCP, LSP, and
session persistence.

**Pi coding-agent** — the smaller, single-purpose harness style that OMP builds
on: one loop, a model abstraction, a tool interface, a context budget.

Both are the reference points for *shape*: what a coding agent needs in order to
work, and what it is tempted to build that it does not need.

## Licensing

Checked before reading anything reusable, and the outcome settled the question
of reuse immediately: **nothing was vendored.** This crate is an independent
implementation. It shares no code, no tables, no constants, and no structure with
either project. The ideas below are ideas, not code, and no notices are owed
because no code was taken.

## What was worth taking

**The neutral model interface.** Providers differ in wire format, not in what a
loop needs. One `ModelProvider` trait, capability flags rather than provider-name
branches, and adding a provider becomes a new file instead of a change to the
loop. This is the single most valuable structural decision in either system.

**Bounded tool output.** A compiler that prints fifty thousand lines will exhaust
a context window faster than any reasoning problem will. Both harnesses bound
results, and both keep the head and the tail, because the first error and the
last summary are what a model acts on.

**Explicit context accounting.** Know the size before sending, rather than
discovering the window is full from a provider error.

**Git as the source of truth for repository state.** Four cheap commands at
startup, a diff at the end. Never a filesystem walk.

**Validation run by the harness.** The strongest idea in either system, and the
one most often got wrong. The caller's commands run after the agent says it is
done, and their exit status decides the result. A model asserting success is not
evidence.

## What was deliberately left out

**A large tool set.** OMP ships many tools. Each one costs schema tokens on every
request for the life of the session, and the marginal tool is not worth its
permanent prompt cost. Nine survived the "useful per token" test; the rest did
not. The likely mistake here is under-shipping: a task needing a domain-specific
tool will be slower, and the honest fix is a task-provided command, not a
built-in.

**A large system prompt.** OMP's accumulated prompt is a manual. This one's
contract is under a kilobyte, and the detail moved into tool descriptions, where
it is read when it is relevant instead of always.

**Summarising compaction.** Asking a model to summarise the transcript is a lossy
operation performed under exactly the pressure most likely to make it lossy. This
crane maintains a structured `TaskState` — objective, constraints, decisions,
files read and changed, commands, test results, open problems — accumulated as
facts while they were still true, and compacts into that plus the most recent
exchanges. Nothing is lost that was recorded.

**Eager capabilities.** MCP servers and language servers are connected on
demand. Connecting everything at startup is a cost paid before any work happens,
for a capability most sessions never use.

**Subagents.** Deferred deliberately: the spec asks for them only if measurement
justifies them, and the measurement has not been taken yet. A subagent inside the
same VM buys a separate context, not a separate computer, and AIec-level
parallelism is the better answer for anything needing real isolation.

**Server mode.** One task, one process. A Unix socket daemon is a second thing to
get wrong in a VM that may vanish mid-write.

## The one design principle

OMP is a general coding-agent harness. The question here was narrower: *what is
the minimum high-quality harness an agent needs inside a disposable VM?*

The answer is what survives above, and nothing else. Everything between "VM boots"
and "VM disappears" has to justify its CPU, RAM, latency, disk, and token cost.
Most of what a general harness does is infrastructure for a machine that is long
lived, and this machine lives five minutes.
