# Known defects

Found by auditing the run subsystem and by running the MCP server against a
live cluster. This is the single file for both: it previously existed twice,
`docs/known-defects.md` and `docs/KNOWN_ISSUES.md`, which differ only in case
and therefore collide on a case-insensitive checkout. Fixed items are listed
with the change that fixed them so this file does not become a place where
stale problems go to hide.

Each entry says what is wrong, how it shows up, and what is not yet done.

The adversarial review of 2026-10-01 — five read-only hunters over distinct
subsystems, plus two subsystems reviewed directly — is written up in
[`bug-hunt-2026-10-01.md`](bug-hunt-2026-10-01.md). Nineteen defects were
confirmed and fixed there with the test each fix was watched failing for, and
seven findings are recorded there as deferred with the reason each was not
changed. The items below are the ones this file already tracked.

## Resolved against a live cluster

### Docker outbound egress and workspace snapshot restore

**Status:** resolved on `192.168.1.250` by the deployed runtime/API fixes.
`benchmarks/runtime-rootfs-docker-live-2026-09-30.json` records:

- A network-enabled worker-created Docker guest fetched `https://example.com`
  with certificate verification and received HTTP 200.
- A Run cloned pinned `octocat/Hello-World`, edited tracked `README`, and
  persisted the exact nonempty diff, ` M README` status and changed-file list.
- A workspace snapshot was captured, its original guest destroyed, restored
  into a distinct new Docker guest, and the exact marker read successfully.
  The restored guest and snapshot were then deleted.

The earlier DNS/connectivity observations apply to the previous deployment, not
the current one. Firecracker networking remains a separate host-permission
limitation: the worker lacks the capability needed to create a TAP device.
Network-disabled Firecracker create/first-exec/destroy is verified.

### A destroyed sandbox could be reported as destroyed when it was not

**Status:** fixed. Kept because the shape of the bug is worth remembering.

A `aiec_run_repo_task` that ended in a failing command left its sandbox running:
`aiec_list_sandboxes` still showed it after the tool returned, holding capacity
the caller believed had been released.

Two defects compounded:

- **The cleanup failure was invisible.** `SandboxGuard::release` logged a
  warning and dropped the error, so the tool returned a result that read as
  "the machine is gone". A cleanup failure is now reported in the result as
  `cleanup_failed`, with the sandbox id and the reason, and the run's
  measurements are still returned.
- **The destroy was racy.** Issued immediately after a failed task it could come
  back `conflict: worker lease generation or status changed`, because the worker
  was still resyncing its lease. The identical call a minute later succeeded
  against the same sandbox with an `active` lease, which is what identified it as
  transient rather than a state error. Destroy is now retried briefly on that
  specific conflict.

A related honesty fix: `destroy_sandbox` used to give up after a two-second poll
and return `"destroyed"` whether or not it had seen the sandbox disappear. It now
reports the state it actually observed and fails if the machine is still there.


## Fixed

| Defect | Cause | Fix |
|---|---|---|
| Every run leaked its machine | `cleanup` called `repository().delete_sandbox`, which flips the row and credits capacity but never calls `runtime.destroy` or `scheduler.release` | `983debf` |
| Capacity was only reclaimed by a human | `POST /v1/reconcile` existed and nothing called it on a timer, so each leak was a permanent reduction | `983debf` |
| A kept machine leaked and was never reported | retention was set in memory; `record_run_results` never wrote `retained_sandbox_id`/`retained_until`, which is what the sweeper selects on | `b3c2953` |
| A finished run could outlive its machine on a database deadlock | destroy gave up because the retry matched prose, not SQLSTATE | `a5737da`, `d0a52d6` |
| Guaranteed deadlock destroying a sandbox | `delete_sandbox` locked sandbox-then-lease while every other path locked lease-then-sandbox | `8a9cc7a` |
| A failed run's machine was destroyed anyway | `cleanup` ran before the outcome was decided, so retention saw a failure as success | `8614e40` |
| Machines leaked on eight exit paths after placement | `execute` reached cleanup on two paths; the rest returned past it with `?` | `5b40d36` |
| Stranded sandboxes exhausted a tenant's quota forever | nothing selected a non-terminal sandbox with no live lease and no unfinished run | `5b40d36` |
| The control plane logged nothing at all | `EnvFilter::from_default_env` with no `RUST_LOG` means no directives, so every `tracing::` line was discarded | `5b40d36` |
| A retried idempotency key ran the workload twice | the guard asked whether the run was finished, not whether this call created it | `e4275c6` |
| Every fully-budgeted run was dropped by the client | SDK timeout `stated + 60s` was shorter than the server's `stated + 120s` budget | `e4275c6` |
| A quota refusal cost five placement attempts and read as an outage | `acquire_sandbox` mapped every placement failure to `Unavailable`, the one kind the run loop retries | "Stop calling a quota refusal an outage" |
| Sandboxes could not resolve names, or could not resolve at all | the container spec set no resolvers and let the daemon pick a public one the network blocks | `e975003` |

## Fixed in the 2026-10-02 audit

The findings below were confirmed against the current source, fixed, and pinned
by a regression that was watched failing first. They are recorded here rather
than deleted because their shapes recur: two of them are the same "one fact
wrote in two places" mistake.

### `set_run_failure` had no compare-and-set

`set_run_failure` wrote `state` and `failure_reason` unconditionally, so a
cancelled run whose synchronous `execute` then failed was rewritten from
`cancelled` to `failed` and a caller that had already been told `200 OK /
cancelled` later read a run that said `failed`. It now keeps a terminal state and
still records the reason on the losing write, and `advance` returns `Conflict`
on a terminal transition instead of adopting it.

### `record_run_results` lost results on the final failure

The last `fail()` passed the pre-execution snapshot, whose state was `Queued`, so
writing results in that state was rejected and `phase_ms` and `cleanup_failed`
were silently dropped for every run that failed after placement. Failure
settlement no longer routes through a lifecycle-checked results write.

### Results were lost when settling failed

`fail()` returned `Ok(())` whether or not either of its two writes succeeded, and
both were warn-only, so a database blip during settlement left a run permanently
non-terminal with a `run.failed` event already in the log - a terminal event for
a run that never became terminal.

Settlement is now one atomic write (`MetadataStore::record_run_failure`) that
records results, reason, terminal state and `completed_at` together. The
`run.failed` event is emitted only after that write succeeds, and a refused
settlement is reported to the caller instead of swallowed.

### `register_worker` could wedge a worker permanently

The upsert updated `total_*` but omitted `available_*`, so a worker
re-registering after being reprovisioned smaller tripped the
`nodes_capacity_within_total` check, which surfaced as a conflict; a worker that
cannot register cannot heartbeat, and one that cannot heartbeat is never
recovered.

The upsert now derives each `available_*` from the capacity actually committed
(`total - available` before the change) subtracted from the new total and floored
at zero, so a resize preserves in-use capacity, never exceeds the new total, and
cannot violate the check constraint.

### A worker's `available_*` did not follow a capacity change

Raising a worker's `--capacity` updated `total_*` through the registration
upsert, but `available_vcpus` / `available_memory_bytes` /
`available_disk_bytes` were left alone, so they kept the old value. A worker
taken from 3 to 8 vCPU still advertised 3 available, and concurrent work was
refused with `LOCAL_CAPACITY_UNAVAILABLE` even though the cluster was idle.

The upsert was right not to clobber those columns outright - they are a running
reservation, and overwriting them would hand the same vCPU to two sandboxes.
What was missing was reconciliation of "reserved" against "in use", which is
what `register_worker` now does. No manual reconciliation is needed after a
capacity change.

The mechanism is the registration upsert, not the heartbeat as originally
recorded: `heartbeat_worker` deliberately leaves `total_*` and `available_*`
untouched, which `heartbeat_preserves_scheduler_capacity_and_refreshes_same_version`
pins.

### An operator's tool lists were silently unenforced

**Severity:** authorization, fail-open. `governs_bodies` decided whether to
inspect a request body by keying on `mcp.allowed_methods` alone, but `McpRules`
defaults every list to empty and validation checks only bounds, name format and
allow/deny overlap - it never requires `allowed_methods` to be non-empty. A
policy of `allowed_methods: []` with a `denied_tools` list therefore validated
cleanly, was judged to have nothing to say about any body, and every body rule
in the policy was skipped at once.

Measured before the fix, through the real gateway: a `tools/call` for the
explicitly denied `delete_repository` returned **200** and reached the upstream.
Not refused and not warned - forwarded. The same held for a tool outside an
allow list. The method gate does not rescue it either: that allow-list is
evaluated inside the body-inspection path, so skipping the body skips the gate
with it, which is why the call came back 200.

The predicate now also keys on `allowed_tools` and `denied_tools`, since both
are rules about the body independent of the method list.

**Operator-visible:** a deny-only policy now inspects request bodies, so it
inherits the pre-existing refusal of a body whose `content-length` is not
declared. A chunked `tools/call` that used to be forwarded unchecked under such
a policy now gets `400 l7: request body length is not declared and cannot be
inspected`. That is the fail-closed direction - an unbounded body cannot be
read for the denied tool - but a client that streams its MCP requests without a
declared length will see the new 400.

## Fixed in the 2026-10-03 audit

### A restore booted an image no resolver had admitted

`restore_snapshot` took the caller's replacement image verbatim. `create_sandbox`
resolves every image through the signed-manifest resolver first, so the
admission that decides what this deployment serves was missing from the one
path that starts a machine out of a stored snapshot. Both now go through one
`admit_image`, and the fallback to the snapshot's own `image_id` applies only
when the caller supplies no replacement. Regression:
`a_restore_may_not_boot_an_image_the_deployment_does_not_serve` asks the
resolver whether it was consulted, which is what distinguishes admission from
taking the string.

### `git_diff` ran on the wrong machine

Every other sandbox verb dispatches through `runtime_for(&sandbox)`; `git_diff`
used the deployment's primary runtime. On a deployment whose primary is Docker,
a Firecracker sandbox had its diff executed by the Docker path — a different
machine from the one holding the repository. Regression:
`a_git_diff_executes_in_the_runtime_the_sandbox_lives_on`.

### A snapshot of a kind the control plane cannot store

`POST /v1/sandboxes/{id}/snapshots` chose its kind from the runtime's own
capabilities, so on the microVM runtime an unqualified request took the
`VirtualMachine` branch: it ran a whole-machine capture, left the provider's
snapshot on the worker's disk, and then failed the metadata row, because
completing a VM snapshot needs a memory object, a disk object and a workspace
object and `CapturedSnapshot` carries none of them. The only capture path that
stores bytes is the workspace one, so the API now defaults to that kind and
refuses the others with `409 unsupported_snapshot_kind` *before* the provider is
asked to do anything. Regression:
`a_snapshot_is_captured_in_the_kind_the_control_plane_can_finish`.

**Operator-visible:** `kind: "virtual_machine"` and `kind: "memory"` are
refused on every deployment, including one whose runtime advertises those
capabilities. There is no code path that can finish such a snapshot, so
accepting one produced a failure after the work rather than an answer.

### A refused worker heartbeat still refreshed its row

`heartbeat_worker` updated `nodes` first and checked active-lease ownership
afterwards. A worker whose leases had all expired or been released — whose
capacity the control plane had already taken back — got a fresh
`last_heartbeat` and stayed healthy in the placement pool, and the CLI keeps
beating every five seconds after a `409`. Ownership is now answered first, in
the same transaction as the update, and a refusal leaves the row exactly as it
was. Regression:
`a_heartbeat_claiming_sandboxes_without_a_lease_leaves_the_row_alone`, which
ages the node by an hour first so it can tell "left alone" from "written anyway".

### A worker claim could hand back a lease the control plane had taken back

`claim_worker_assignments` renewed `sandbox_leases` with `WHERE id=$2 AND
status='active'` and discarded the result. A reconciler that had expired the
lease between the claim's `SELECT` and that `UPDATE` left the update matching
zero rows, nothing raised, and the worker was handed a reservation the control
plane no longer owned: it built a machine against it, every fencing call was
then refused, and the node was advertising capacity already handed out. The
renewal is fenced like `renew_worker_lease` (`status='active' AND expires_at >
now()`) and a claim that renews nothing leaves its assignment `reserved`.

The same function also locked `sandbox_assignments` before `sandbox_leases`,
the exact inverse of `release_capacity`, which every capacity-releasing path
funnels through. A claim racing a sweep is an ABBA cycle, and PostgreSQL aborts
one side with `40P01` — on the reconciler that is the whole `FOR UPDATE` page it
was sweeping, so one concurrent claim defers every other expiry in the batch.
The lease row is now locked first, matching the order the releasing paths use.

**Not regression-tested.** Both defects need a claim and a reconciler to
interleave between two adjacent statements inside one transaction. The fixes are
verified by the storage suite, review and the ordered `SELECT`s above, not by a
test that fails on the old code: a fault-injection seam at that point does not
exist, and a timing-dependent test would be a test that lies.

### Lease recovery could resurrect a sandbox that was being stopped

`reassign_expired_lease` read the sandbox with a plain `SELECT` and wrote it back
with no expected-state predicate, holding only the expired lease's lock. The
ordinary stop path holds only the sandbox row, so a sandbox read as `running`
could be stopped by a concurrent request a moment later and then moved back to
`creating` by recovery, with a fresh live lease and debited capacity, for a
caller who had just been told the sandbox was going away. The sandbox row is now
locked for the whole transaction and the write is predicated on the state that
was validated, so the check and the write describe the same row. A state that
moved under the recovery rolls the new lease, the debited node and the
retargeted assignment back with it.

**Not regression-tested:** as above, the interleaving is not reproducible
without a fault-injection seam.

## Fixed in the 2026-10-03 audit: the agent harness

### Compaction could write a request no provider accepts

`compact` built its digest from `describe`, which returns nothing for a
contentless assistant turn, and then wrote it as a `user` message. A run whose
drained turns were all tool-call-only turns produced
`Message::User { content: "" }` — an empty user turn on the wire, which a
provider that validates content rejects by refusing the *whole* request. The
digest now falls back to naming what was dropped (`Earlier in this run (N
exchanges, compacted)`), which is never empty.

The second half of the same defect: the digest was unconditionally inserted at
the front, so a kept window that already began with a `User` message (a pushed
context note, or a digest left by an earlier compaction) produced two
consecutive `user` messages, which a provider requiring alternating roles also
refuses. A leading kept `User` is now folded into the digest, keeping both texts.

### Tool-call arguments were not charged to the ledger

`push_assistant` charged the assistant *text*; the tool calls attached
afterwards were never charged at all. A `write` call carries a whole file in its
arguments, so the ledger reported a conversation as comfortably inside its
window while the provider rejected it for being over — the one failure the
ceiling exists to prevent. They are now serialised exactly as `as_wire`
serialises them and charged under bucket `tool_calls`.

### `max_tool_output_bytes` was never read

`push_tool_result` compressed to `DEFAULT_TOOL_OUTPUT_BYTES.min(4096)` and
ignored the task's own ceiling entirely: a task asking for a kilobyte was sent
four. The effective limit is now
`min(DEFAULT_TOOL_OUTPUT_BYTES, 4096, task.max_tool_output_bytes)`.

The compressor itself undercounted: the truncation marker was appended *after*
the limit was met. It now reserves the longest possible marker before splitting
the remaining head/tail budget on UTF-8 boundaries. A nonzero limit smaller
than the descriptive marker keeps a UTF-8-safe prefix followed by `~`; a zero
limit produces no output. Neither marker can exceed the caller's byte ceiling.

### Every result document reported `head_before: null`

`collect_after` runs once, at the end, and cannot know what the repository
looked like before the run — and `execute` assigned it over `outcome.git`
entirely, so the field the evidence exists to answer was always null. `execute`
now captures head/branch/status before the run and merges, with
`merge_git_evidence`: only `head_before` comes from the earlier observation,
`branch` falls back to it only when the after-collection could not read one,
and everything describing the tree the run left behind is the
after-collection's.

### Git evidence adopted an enclosing checkout

`Repository::open` took `rev-parse --show-toplevel`, which names the *nearest
enclosing* checkout. A task directory that happens to sit inside an unrelated
repository therefore reported that repository's head, branch, status and diff as
the run's evidence — a tree the agent's tools, confined to `task.repo()`, were
never allowed to touch. `open` now canonicalises the task path and refuses a
toplevel that is not the task's own directory, failing closed: such a task
reports no repository at all rather than another tree's state. The meaning of
`task.repo_path` is narrowed accordingly — it must be the checkout root.

### A failed git collection was reported as a clean tree

`diff` and `status` were `unwrap_or_default()`, so a git that would not run (an
unborn repository, an unreadable index) produced byte-for-byte what a clean
working tree produces: "the agent changed nothing", asserted as evidence.
Failures now propagate, and `collect_after` records each one in the new
`GitEvidence.errors` field instead of defaulting. The `changed_files` fallback
now requests NUL-separated `--name-only -z` output, preserving paths that Git
would otherwise C-quote, including filenames containing newlines.

### Permanent provider refusals were retried

Every non-success response became `HarnessError::Model`, which
`Client::complete` retries with bounded backoff for three total attempts.
Permanent request refusals now become `HarnessError::ModelRefused` and return
after one attempt. HTTP 429, 5xx and 3xx remain retryable. Loopback tests observe
one request for 401 and three for 503; no provider billing claim is made.

### Truncated validation evidence ended in a formatted boolean

`tail` appended `text[..start].is_empty()` into the formatted string, adding
the literal word `false` to truncated output. The result now contains only the
ellipsis and retained validation output.

### A result document that could not be saved still returned the earned code

`run` did `let _ = outcome.save(...)` and then returned the exit code the run
earned, so a write failure — an unwritable result directory — was invisible:
the harness exited 0 with no result document anywhere. `publish` now writes the
document and returns 2 when the save fails, and the task's own error is printed
to stderr *before* the save is attempted, so an unwritable directory cannot
replace the only complaint the operator gets to read.

Regressions exercise compaction, ledger accounting, output ceilings, Git
collection, retry classification, validation output and result-save failures.
The retry test observes one request for 401 and three for 503.

### Comparison summaries discarded successful task output

`SideSummary::from_runs` now includes setup, task and validation stdout/stderr
in `last_output`, followed by any failure reason. The existing
`successful_task_and_failed_validation_outputs_remain_visible` regression
asserts both `TASK_REACHED` and `CHECK_FAILED`. The previously recorded
observation of empty comparison output described an older build.

## Fixed in the 2026-10-03 audit: ownership boundaries

### A retried provisioning request could destroy the original request's machine

The rollback's state check was not an ownership check. `Creating` is exactly the
state a retry finds the row in, the read and the destroy were separate
statements, and both requests carry the same idempotency key, so nothing
distinguished the winner from the retry that failed its way into teardown.

Ownership is now established and checked atomically:

- `Scheduler::schedule_for_provision` returns `ProvisionAdmission { scheduled,
  acquired }`, decided inside the store's admission transaction. The default
  trait implementation answers `Unsupported`: a scheduler that cannot prove who
  owns a row fails provisioning closed instead of guessing.
- A replay (`acquired == false`) is refused with `409 sandbox_provisioning`
  while the row is still `Creating`/`Starting`, and returns the completed
  sandbox otherwise. It never reaches create/start, so it cannot fail its way
  into a rollback.
- Rollback begins teardown with one compare-and-set that moves
  `Creating`/`Starting` to `Destroying` and is fenced on the lease this call
  acquired. A lost race destroys nothing and is reported as
  `409 sandbox_not_owned`. `Destroying` is refused by admission and by lease
  recovery, so once teardown has started no other path can install a
  replacement owner.
- Runtime dispatch inside that call carries the originally acquired
  `WorkerDispatch` through a task-local provisioning scope rather than
  re-resolving the current owner, so teardown cannot be delivered to the
  worker that replaced this attempt.
- State commits use `update_state_with_lease` with the original lease id.
  Renewals on the same lease advance the generation and are still accepted, so
  a machine that is legitimately claimed mid-start is not refused by its owner.

Reproduced against `13f7d3e` with a real PostgreSQL store, the real
`WorkerRuntime` over a gated worker double, and two concurrent provisions
sharing one idempotency key while the first was blocked in `create`: the retry
was refused and still dispatched a `destroy` for the winner's lease.

### Runs could record another tenant's machine

`append_run_event`, `link_run_sandbox` and `record_run_attempt` took no tenant.
Each was scoped by its run id alone, so the sandbox id they recorded was never
checked against the run's own tenant: an event, a link or an attempt could name
another tenant's machine, and `link_run_sandbox` is the list cleanup tears
down. The three now take the tenant and refuse, atomically and with no row
written, when the named machine is not that tenant's own. `retain_run_sandbox`
requires the run to have used the machine before it may keep it.

Reproduced against the pushed revision `13f7d3e` with two PostgreSQL tests
(`crates/aiec-storage/src/postgres.rs`, run in a worktree at that commit): a run
accepted tenant B's machine and its link list then held the foreign id, and a
run retained a machine it had never used.

### Deleting a run stranded the machines it still held

`delete_run` was `DELETE FROM runs WHERE tenant_id = $1 AND id = $2` with one
refusal, the append-only `run_events` trigger. It had no opinion about
machines, and the run row plus its `run_sandboxes` links are the only indexes
that lead to them: the sweeper selects on `retained_until` to know what it owes
a reclaim, and cleanup reads the links to know what to tear down. Deleting a
run that still held a machine cascaded the links away and took the retention
pointer with them, so the machine kept its vCPUs debited and its container
running with nothing left pointing at it — the same end state as the retention
displacement above, reached by a different statement.

The delete now refuses, in the same statement that deletes, while the run
retains a machine or names one, and distinguishes refused from absent so a
caller that already deleted its run still gets `NotFound`. Reproduced against
`13f7d3e`: the delete returned `Ok` and the link list read `[]`.

### Retention could be handed to another machine

`retain_run_sandbox` set `retained_sandbox_id` unconditionally after checking
the run. A second retention for the same run replaced the first, leaving the
earlier machine with no `retained_until` anywhere: never reclaimed, never
destroyed, holding its capacity for as long as the process lived. Retention is
reachable more than once for one run because `allow_retention` is set by
per-attempt outcome, so an attempt that failed during setup retains, and a
later attempt can retain its own machine. The decision is now one statement:
only a machine the run linked may be retained, restating the same retention is
a retry that takes the later expiry, and a different machine is refused with
the first retention untouched.

### Lease recovery rebuilt a run's machines

`reassign_expired_lease` is generic lease recovery: it expires a lease and
rebuilds the sandbox. A run's attempt executor and cleanup own their machines
and re-places them on retry, so recovery and the executor were two writers for
one machine — and the six containers observed reappearing with unchanged
sandbox ids after their runs finished have a path in the repository:
`crates/aiec-cli` posts `/v1/workers/reconcile` on startup and every ten
seconds, which reached `recover_expired_leases` and issued runtime
create/start. Recovery now refuses any sandbox that appears in `run_sandboxes`, under the
same sandbox row lock that link installation takes, so eligibility and
association cannot change independently. It remains available for a machine
whose worker died, which is what it is for. The regression covers both a
`Running` and a `Succeeded` run: no replacement, and no debit of the candidate
worker's capacity.

### A dead API could have cleared a node's health

`MetadataStore::heartbeat` issued `UPDATE nodes SET healthy = true ...` with no
ownership check and no check that the caller still reports anything. Nothing
called it — not a route, not the scheduler, not the worker — but it was public
trait surface that any new caller would have got wrong, in the one direction
that makes a node schedulable again. It and its four implementations are
removed rather than left as a trap. `register_node` and `list_nodes` stay;
`list_nodes` backs `/metrics`.

### A healthy heartbeat could refresh a node after its leases were revoked

The refused-heartbeat fix checked lease ownership inside a transaction but
counted the leases with a plain `SELECT`, which takes no lock. At READ
COMMITTED a revocation that commits between that count and the node `UPDATE`
is invisible to the count, so a worker whose leases had just been taken back
still wrote `healthy = true` and a fresh `last_heartbeat`. The heartbeat now
locks the node's active lease rows before deciding, in the same lease-then-node
order `release_capacity` uses, and the interleaving is reproduced with two real
database backends: one holds the revocation open while the heartbeat is
observed waiting on the lock in `pg_stat_activity`, and the refused heartbeat
must leave `healthy` false and the observed count at zero.

## Open

### Accepted, not fixed: placement holds a worker row lock while it waits

`select_schedulable_node` selects its candidate `FOR UPDATE SKIP LOCKED` and then
waits, inside that lock, for the host's advisory lock — up to 40 attempts of
5 ms. For that window every `debit_capacity`, `release_capacity`,
`heartbeat_worker` and `revoke_worker` on that node waits behind the placement.
The wait is deliberate: it is what stops a colliding placement being refused as
`no schedulable worker has capacity` when the host has room in it, which was a
measured failure mode. Reordering it means taking the host lock before the node
lock, which is not possible without knowing which host the candidate is on, so
the candidate would have to be re-selected and re-validated after the host lock —
the reservation path this audit has already measured end to end. The bound is
200 ms and it only occurs when two placements contend for one host, so this is
recorded as a deliberate trade-off rather than fixed.

### The `initialize` handshake never answers `2026-07-28`

**Status:** SDK behaviour, not a defect. Recorded so nobody re-investigates it.

A client that asks for `2026-07-28` on `initialize` is answered `2025-11-25`:

```
client asks 2026-07-28 -> server answers 2025-11-25
client asks 2025-11-25 -> server answers 2025-11-25
client asks 2025-06-18 -> server answers 2025-06-18
```

This is what rmcp 3.4.1 does on purpose. Its own comment on
`negotiate_protocol_version` says that `2026-07-28` replaced the handshake with
per-request metadata, so a client naming that revision "is answered with the
server's newest legacy version instead". `ProtocolVersion::LATEST` in the SDK is
still `2025-11-25`, and `2026-07-28` is a known version used on the modern path.

So the transport is current — Streamable HTTP — and the SDK is the official Rust
implementation, which is what the milestone asked for. Setting
`ServerConfig.protocol_version` to `V_2026_07_28` was tried and changed nothing,
because the fallback is computed from the newest *legacy* version the server
supports. It was reverted rather than left in, because it would have made
`serverInfo` advertise a version the handshake does not answer.

A `2026-07-28` client talks to this server over per-request metadata instead of
the legacy handshake; that path is the SDK's, not ours.

## Verification notes

Two things about this cluster that cost time and will again.

**A sandbox with no network cannot resolve anything.** `NetworkPolicy::Disabled`
maps to Docker's `network_mode: none`, so a run that does not ask for network
gets no interface, no resolver, and fails every lookup with "could not resolve
host" - which reads like a broken image. A workload that clones a repository or
installs anything needs `"resources": {"network": {"enabled": true}}`, and the
failure otherwise surfaces as a bare `exit 128` from the setup step.

**The resolvers a sandbox can use come from the worker, not the host.** The
runtime reads `/etc/resolv.conf` as seen by the worker process. On this host
that file lists only `127.0.0.53`, systemd-resolved's loopback stub, which is
filtered because a container cannot use it; the nameservers a sandbox actually
receives (`169.254.1.1`, `192.168.1.1`) come from the worker's own container
configuration. That is why the change is a no-op when read from the host and a
fix when read from the worker.
