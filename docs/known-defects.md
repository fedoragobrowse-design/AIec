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

### Restoring a machine snapshot tore a machine down it never owned

`restore_snapshot` branched on the stored snapshot's kind. For a
`virtual_machine` or `memory` row it allocated a machine, handed the worker's
own provider snapshot to it, and then destroyed what it had just built. That
teardown went through `schedule`, not through `provision_sandbox`, so the
admission that decides whether a request owns the lease and the lease fencing
every other dispatch uses were both absent from the one path that allocated and
released a machine inside a single request. The bytes such a row names are not
recorded anywhere the control plane can read, so there was nothing to restore
either.

Restore is now workspace-only: any other stored kind is refused with `409
unsupported_snapshot_kind` before a machine is allocated, and a workspace
restore is provisioned by `provision_sandbox`, so it holds the same admission
and the same fencing as `POST /v1/sandboxes`. Rows of the older kinds exist in
databases deployed before the cutover; the refusal is explicit rather than an
assumption that they do not. Regression:
`a_machine_kind_restore_is_refused_before_anything_is_allocated`, which plants a
complete `virtual_machine` row and asserts the refusal, that the tenant's
machine list still holds only the source machine, and that nothing was
destroyed. The two unit tests that covered the removed branch are gone with it;
the isolation-boundary check moved onto the surviving branch as
`workspace_restore_respects_the_deployment_isolation_boundary`.

**Operator-visible:** restoring a `virtual_machine` or `memory` snapshot now
fails with `409 unsupported_snapshot_kind`. Recapture it as a workspace
snapshot.

Reproduced against `13f7d3e`, in that worktree with its own target directory, by
`f4_baseline_a_stored_machine_snapshot_restore_is_refused`: the restore
allocated a second machine in state `Restoring`, the runtime lookup for it
failed, and the response was a `503 runtime_unavailable` whose message ended
`cleanup failed`, with the new machine still in the store beside the source.

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

Reproduced against `13f7d3e`, in a worktree at that commit with its own target
directory, by two PostgreSQL tests:


The reproductions named below were run in a throwaway worktree that was
removed afterwards, so they are not in the tree and cannot be re-run as
written. They are recorded for what they observed, not as gates. The behaviour
each one describes is instead covered by these permanent PostgreSQL
regressions:

- `a_run_only_links_keeps_and_records_machines_from_its_own_tenant` — refuses a
  link to another tenant's machine, and refuses retention of a machine the run
  never used.
- `a_run_that_still_holds_a_machine_cannot_be_deleted_out_from_under_it` —
  refuses the delete while the run retains or names a machine.
- `a_released_machine_leaves_no_cleanup_report_and_cannot_be_reported_afterwards`
  — covers the displacement case, where a second retention replaced the first.

- `f4_baseline_a_run_links_a_machine_from_another_tenant` — the link was
  accepted and the run's link list then held the foreign id.
- `f4_baseline_a_run_only_keeps_a_machine_it_used_once` — a run retained a
  machine it had never used, and a second machine displaced the one already
  retained.

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
retains a machine or names one. The two are separate predicates rather than
one: `runs.retained_sandbox_id` has no foreign key and no trigger tying it to
`run_sandboxes`, so a row that retains a machine without the link would
otherwise delete the sweeper's only index onto it. It also distinguishes
refused from absent so a caller that already deleted its run still gets
`NotFound`. Reproduced against `13f7d3e`, in that worktree with its own target
directory, by
`f4_baseline_deleting_a_run_keeps_the_machine_it_holds`: the delete succeeded,
the link list read `[]` afterwards and the machine was still in the store.

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

## Fixed in the 2026-10-03 audit: runtimes and networking

### Two live sandboxes could share one `/30`

`tap_address_plan` was a pure modulo of the sandbox id over 1024 slots, so two
ids sharing a slot were handed the same `/30`: both guests configured the same
address and the kernel held two identical connected routes whose selection
depended on insertion order. With random identifiers this is a birthday
collision, not a rare event — measured at 86.7% of 64-sandbox runs sharing a
subnet — so it was a property of the allocator being stateless, not of the pool
being too small. Allocation now probes the pool cyclically from the id's own
slot and refuses with `LimitExceeded` when all 1024 are in use, with occupancy
read from the host's own address inventory (`ip -j -4 addr show`) rather than
from process-local state. Regressions cover an occupied slot, a pool that is
occupied except for the last slot, and exhaustion.

### A superseded recovery pass could write state and release another owner's lease

Recovery is handed a `Reassignment` — one lease, one generation — but placed the
sandbox through `commit_state`, which looks up *who owns the sandbox now* and
fences against that. A sandbox reassigned again while its runtime was starting
was therefore marked `Running`, then `Failed`, under the **new** owner's lease,
by a pass that no longer held the sandbox. `abandon_recovery` then released
through `Scheduler::release`, which takes only a tenant and a sandbox id and so
cannot name a lease — the store picks whichever is newest, releasing capacity
the new owner was still using while its sandbox was still live. Both paths now
fence on the lease recovery holds (`update_state_with_lease`,
`release_worker_lease`). Regression:
`a_superseded_recovery_pass_neither_writes_state_nor_releases_a_lease`, which
failed first with the superseded pass reporting `"recovered"`.

### A failed Firecracker capture left half a snapshot at the key

`snapshot` wrote into `snapshots/<digest>` directly. A capture that failed partway
left a directory holding `vmstate` and no `memory`, no `rootfs.ext4` and no
manifest, with nothing to mark it as half. Worse, a *recapture* overwrote
`rootfs.ext4` in place while the previous `manifest.json` stayed put: if it
failed between overwriting the disk and writing the new manifest, the key held a
manifest whose `rootfs_sha256` describes a disk that no longer existed. Restore
checks that digest, so the outcome is a refused restore rather than a wrong
boot — but the key was broken and the one good snapshot destroyed to break it.
Capture now stages into a uniquely-named directory and publishes by rename, with
the previous snapshot moved aside first and only unlinked once the new one is in
place. Regressions:
`a_snapshot_key_is_never_left_holding_a_half_written_capture` and
`a_publish_that_cannot_complete_leaves_the_previous_snapshot_readable`.

### A wedged Firecracker API blocked every operation on its sandbox

The five-second deadline in `api_response` covered the connect loop only.
Writing the request, reading headers and reading the body were all unbounded,
and every caller runs while holding the sandbox's lifecycle gate — so one VM that
accepted the connection and stopped responding froze that sandbox entirely,
including its destroy. Separately, `Content-Length` was read off the wire and
used to size a `Vec`, so a response claiming a large body reserved that memory
before a byte arrived. The deadline now covers the whole exchange, and the body
is checked against a bound before it is allocated.

### A symlink in a sandbox's workspace was a way out of it

`path_for` normalized the *request* path lexically, which stops `..` in the
request and nothing else. The guest can create links inside its own workspace via
`exec`, and every host-side file operation then followed them: a guest that ran
`ln -s /etc /workspace/etc` had `put_file("/workspace/etc/passwd")` write the
host's `/etc/passwd`, and `get_file` read host files back. `put_file`,
`get_file`, `list_files`, `delete_file` and `make_directory` now resolve each
component with `symlink_metadata` and refuse one that resolves outside the
workspace; a link pointing *within* the workspace is still allowed, because that
is a guest arranging its own files. The Docker runtime already did this — its
`read_workspace` opens with `O_NOFOLLOW` — so this was the bubblewrap path only.
Regression:
`a_symlink_planted_in_the_workspace_cannot_be_used_to_leave_it`, which failed
first with the write returning `Ok(())`.

### Smaller defects from the same audit

- `POST /v1/keys` and `POST /v1/account` reported scopes as `sandboxesread` —
  the Debug formatting of `Scope`, not the `scope_wire_name` the API parses.
- A repetition count was expanded before it was validated, in three places
  rather than one: `run_repetitions`, `omp::compare` (two runs per repetition),
  and the MCP comparison tool, which reserves capacity for both sides before
  expanding anything. `u32::MAX` requested a multi-terabyte allocation and
  aborted the process. All three now share `MAX_EVAL_REPETITIONS`. Of the
  three, the MCP tool (`aiec_compare_omp`) and the `/v1/eval/repetitions` route
  are reachable from a caller today; `omp::compare` is currently unrouted, so
  its share of the fix is defence in depth on a public function rather than a
  closed hole. Worth keeping anyway — the function is `pub` and a suite file is
  caller-authored — but it should not be read as the route an attacker took.
- The CLI created Firecracker and Docker sandboxes through a bare
  `reqwest::Client::new()`, bypassing `AIEC_TLS_CA_CERT` and the 60 s timeout.
- The worker skipped its heartbeat entirely when its own health probe failed,
  so a running worker was reaped as dead. It now heartbeats `healthy: false`
  with the probe error in `last_error`.
- The MCP server inferred a 404 from formatted error text rather than matching
  `ClientError::Api { status: 404 }`.
- **Monitoring was silently dead in the compose deployment, for three
  independent reasons.** `deploy/prometheus.yml` scraped
  `host.docker.internal:8080` over plain `http`, but the production listener
  (`aiec-server`, `crates/aiec-api/src/main.rs`) terminates TLS and has no
  plaintext listener at all, and it binds `127.0.0.1` by default — which
  `host.docker.internal` (the docker bridge gateway, `172.17.0.1` /
  `172.18.0.1`) cannot reach. An earlier pass fixed only the name resolution by
  adding `extra_hosts: ["host.docker.internal:host-gateway"]`, which made the
  scrape resolve and then fail on protocol and reachability instead; it never
  made it work. Reproduced end to end against the real `aiec-server` binary and
  a real Prometheus:
  - name only: `health: down`, `no such host`.
  - scheme only, target reachable: `down`,
    `malformed HTTP response "\x15\x03\x03..."` — `\x15` is a TLS alert record
    arriving where Prometheus expected HTTP.
  - fixed: `health: up`, `lastError: (none)`, and
    `aiec_node_available_memory_bytes` queryable.
  Fixed by scraping `https://127.0.0.1:8080` with `insecure_skip_verify` (the
  operator certificate is self-signed and distributed as no CA) and by putting
  Prometheus in the host network namespace. Host networking rather than a wider
  API bind is the deliberate choice: `/metrics` sits outside the authentication
  layer by design (`GET /metrics` is 200 unauthenticated, `GET /v1/sandboxes`
  is 401), so binding the API to the bridge network to make scraping work would
  publish operational metrics to anything that can route to the host. The
  image was also floating on `latest` while `postgres` and `minio` are pinned;
  it is now `prom/prometheus:v3.15.0`, overridable as `AIEC_PROMETHEUS_IMAGE`.
- The guard gateway bound its DNS listener twice — TCP, then UDP on whatever
  port the TCP half had drawn — so a port taken in between failed the whole
  gateway at startup with `AddrInUse`, on a correctly configured host. It now
  redraws, bounded, and says so in the error rather than retrying forever.
  Regressions: `a_dns_port_taken_between_the_two_binds_is_drawn_again` and
  `a_dns_port_that_is_never_free_still_refuses`; removing the retry fails both.

### The TAP allocation was still racy between two placements in one worker

The occupancy-aware allocator reads the host's address inventory and then runs
`ip addr add` as separate steps, so two placements overlapping exactly there —
the normal case when a batch is admitted at once — could both see a slot free
and both take it. The kernel does not reject the second: a second interface may
carry an address already in use, so the duplicate becomes two live sandboxes on
one subnet with no error raised anywhere. The probe and the assignment are now
serialized within a worker. **Partially fixed, and the scope is worth being
precise about:** the existing placement advisory lock does **not** already cover
this. Network attachment happens in the runtime at microVM creation, long after
placement returns, and in the legacy guard fallback; the placement lock is a
PostgreSQL advisory lock held inside `select_schedulable_node` and it does not
span any of it. So this needed its own lock, taken as a `static` so it holds
across every call site without giving `LinuxNetworkManager` interior
mutability. What that lock does **not** cover is a second worker process on the
same host: cross-process, the reservation is still the inventory probe rather
than an atomic claim. Closing that needs a lockfile or a kernel-side
reservation, which is not built.

Regressions, each verified by breaking the thing it describes:
`concurrent_placements_never_share_a_subnet` drives the real reservation with
eight identifiers that all start on the same slot, and yields between the probe
and the claim so the window is actually open. Deleting the reservation makes it
fail with `the reservation let two placements take 172.30.8.5`.
`a_refused_placement_releases_the_reservation_for_the_next_one` covers the
other direction: a full pool refuses, and the guard has to be released anyway
or every later placement on that worker blocks forever. Forgetting the guard on
the error path makes it fail with `the reservation wedged`.

### The legacy TAP ruleset contained no IPv6

`firewall_rules` in `crates/aiec-network-linux` builds an `inet` table. Every
rule in it matches on `ip saddr`/`ip daddr`, and the input and forward chains
are both `policy accept`. An IPv6 packet from the guest matches none of them, so
it was accepted by both chains: the guest could send to anything the host binds
on `::` — host-local IPv6 listeners and link-local neighbours on the host's
interfaces — and anything forwarded to it, with the masquerade rule
(`ip saddr`-only) leaving that egress un-NATed.
It was reachable without the guest doing anything deliberate. The Firecracker
guest is given only the IPv4 `ip=` boot argument, so it autoconfigures a
link-local `fe80::` on its NIC and has a working IPv6 stack.

The Guard renderer already refused IPv6 (`permits_ipv6()` returns false,
`render_ipv6` drops unconditionally). This was the legacy path — the one taken
when a sandbox runs without a guard policy — so the two disagreed about what
the guarantee is.

Both chains now drop IPv6 with `meta nfproto ipv6 drop`, placed **ahead of**
every accept in their chain, so a later widening of a permit cannot admit IPv6
in front of the drop. Verified by applying the production output verbatim:

```
$ unshare -rn -- sh -c 'nft -f /tmp/aiec-real-rules.nft && nft list table inet aieccheck'
FULL RULESET APPLIED OK
table inet aieccheck {
	chain input {
		type filter hook input priority filter - 10; policy accept;
		iifname "af0123456789ab" meta nfproto ipv6 drop
		iifname "af0123456789ab" ip saddr 172.30.8.0/30 ip daddr 172.30.8.0/30 accept
...
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname "af0123456789ab" meta nfproto ipv6 drop
```

Regression: `ipv6_from_the_guest_is_dropped_in_both_chains_before_their_accepts`
asserts both drops exist and that neither chain accepts ahead of them. Deleting
the two rules from `firewall_rules` makes it fail.

### The forward chain granted nothing inbound, so one tenant could reach another

The same ruleset, and the more serious of the two. Every forward rule granted
egress from the guest or the replies to it:

```
forward iifname "af0123456789ab" ip saddr 172.30.8.0/30 accept
forward oifname "af0123456789ab" ip daddr 172.30.8.0/30 ct state established,related accept
(nothing after this)
```

The chain policy is `accept`, so a packet arriving on some *other* interface and
bound for the tap matched neither rule and fell off the end — accepted. That is
not a theoretical gap between siblings: another tenant's sandbox on the same
host satisfies its own egress rule (`iifname` is its tap, source is its subnet),
and the return rule requires `ct state established,related`, but a connection
the far side **initiated** matches neither and was forwarded in. The per-sandbox
`/30` subnets imply an isolation boundary and the ruleset did not enforce one.

The chain now ends with `forward oifname "{tap}" drop`, after the
established-return allow so the guest keeps the replies to everything it
legitimately sent. This also closes the inbound IPv6 direction in one rule,
since it is protocol-agnostic. Guard states the same intent with its
`forward_to_guest` chain.

Verified against real nft by applying the production output verbatim — the
applied forward chain, in order:

```
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname "af0123456789ab" meta nfproto ipv6 drop
		iifname "af0123456789ab" ip daddr 169.254.169.254 drop
		iifname "af0123456789ab" ip daddr 10.0.0.0/8 drop
		iifname "af0123456789ab" ip daddr 172.16.0.0/12 drop
		iifname "af0123456789ab" ip daddr 192.168.0.0/16 drop
		iifname "af0123456789ab" ip daddr 127.0.0.0/8 drop
		iifname "af0123456789ab" ip saddr 172.30.8.0/30 accept
		oifname "af0123456789ab" ip daddr 172.30.8.0/30 ct state established,related accept
		oifname "af0123456789ab" drop
	}
```

Regression:
`traffic_bound_for_the_guest_is_dropped_after_the_return_traffic_is_allowed`
asserts the drop exists, follows the established-return allow, and that **no
forward rule at all follows it**. Checking position and a rule count separately
would both still pass with an accept appended after the drop, which is
precisely the way this defect came back; appending
`forward iifname != tap oifname tap ip saddr 10.99.0.0/16 accept` after the drop
makes the test fail, and so does deleting it.

### A guest could send with any IPv4 source it liked

Both legacy TAP chains carry `policy accept`, so the rules only ever described
what was *permitted*. The `ip saddr {subnet}` accepts were one permit among
destination-keyed drops, which means a packet from the tap carrying *any*
source at all — not merely one inside its `/30` — matched no drop and no
accept, fell off the end of the chain and was accepted by the policy.

In the forward chain that was arbitrary-source IPv4 egress to any destination
outside the blocked ranges, forwarded **without masquerade**, because the
postrouting rule was subnet-keyed too. A guest could therefore emit traffic
that appeared to originate from any address on the internet, with replies
discarded by the terminal inbound drop — a reflection primitive pointed at a
third party, not a way to impersonate the host. In the input chain the same
fallthrough meant arbitrary-source traffic to the host itself was accepted at
the input hook.

Sourcing as `.1`, the host side of the `/30`, was the one forged case that was
also masqueraded, and conntrack sent its replies to the host address rather
than the guest's. That is worth noting but is *not* what distinguishes the
abuse: masquerading to the host's egress address is what ordinary guest egress
does too, so "looks host-originated" is not the impact. The impact is that the
guest was its own source authority.

Fix: every source match is pinned to `plan.guest`, and each chain enforces it
with `ip saddr != {guest} drop` placed directly after the IPv6 drop, ahead of
every accept so no destination rule can run first. Destination matches stay on
the subnet, because that is about which hosts are on the link rather than who
may be the sender. This is the structure Guard already renders
(`crates/aiec-guard/src/enforcement/render.rs:391` and `:404`), so the two paths
now agree and the legacy one is the stricter-correct of the pair.

Regression: `a_forged_source_from_the_guest_is_dropped_before_any_accept_runs`
asserts the refusal exists in both chains and precedes every accept in them.
Deleting the forward drop fails it with "forward refuses a forged source";
moving that drop after the `ip saddr` accept fails it with "forward accepts
before refusing a forged source". A separate assertion in
`firewall_masquerades_guest_traffic_and_keeps_guest_subnet_reachable` rejects
any rule keyed on the subnet as a source at all, and was checked against a
freshly added subnet-wide permit that the specific string matches cannot see.

Evidence: the ruleset rendered by `firewall_rules` was applied verbatim under
`unshare -rn -- nft -f`, accepted by real nft, and `nft list table` shows both
chains with the IPv6 drop and the anti-spoof drop ahead of every accept and the
metadata drop restored in the forward chain.

### `find` re-walked the tree through a symlink that pointed at it

The agent's `walk` pushed a path whenever `Path::is_dir` resolved true, and
`is_dir` follows symlinks. A `loop -> .` entry inside the searched tree
therefore produced `root/loop`, `root/loop/loop`, and on, with no visited set
and no depth cap.

The result limit could not catch it: `out` only grows when the glob matches, so
a pattern matching nothing kept descending until the kernel refused the
too-long path, and a pattern that did match reported the same file once per
depth reached. The damage is to the worker process rather than to one sandbox,
and the tree it walks — a repository checked out for an eval — is
attacker-supplied, so the link is planted long before it is walked.

The walk now reads `entry.file_type()`, which does not follow, and refuses to
descend through a symlinked directory. A symlink to a *file* is still a file to
a glob and is left to match.

`MAX_WALK_DIRECTORIES = 50_000` bounds the walk unconditionally, which the
result limit never did. **Reaching that cap is an error, not a short answer.**
Returning the partial list would present it as the complete set of matches,
which is the one thing a `find` result cannot be: the caller has no way to tell
the tree was bigger than the bound, so a file they asked for and did not get
looks like a file that does not exist. `find` propagates the error to the
model, which reads the search as unfinished. The bound is not expected to fire
— refusing to descend through a symlink is what stops the loop, and this is
defence in depth against a hostile tree that is wide rather than deep.

`walk` takes the bound as a parameter so a test can exercise the cap without
creating fifty thousand directories; `find` passes the constant.

Regression:
`a_symlink_pointing_back_at_its_own_directory_terminates_the_find_walk`. Run on
its own thread with a receive timeout so a walk that never returns fails the
assertion instead of hanging the suite. Against the old walker it fails with

```
left:  ["nested/keep.txt", "loop/nested/keep.txt", "loop/loop/nested/keep.txt",
        "loop/loop/loop/nested/keep.txt", ...]
right: ["nested/keep.txt"]
```

`a_tree_larger_than_the_directory_bound_is_an_error_not_a_short_list` covers the
cap: a tree of eight directories against a bound of three must be an error
naming the bound, and the same tree inside the bound is searched fully.
Restoring the silent truncation makes it fail.

### The Python SDK returned a capped run page as if it were the whole answer

`GET /v1/runs` clamps `limit` to `MAX_RUN_PAGE` (200) and answers with a bare
`Vec<Run>` — no cursor, no total, nothing that distinguishes a capped page from
a complete one. `Runs.list(limit=1000)` sent 1000, got 200, raised nothing, and
returned a list its docstring called "the caller's runs".

The wire shape is not changed here; adding a cursor is an API decision with
its own compatibility cost. What is fixed is the SDK's part of it: it now
refuses a `limit` the control plane cannot honour (`MAX_LIST_LIMIT = 200`,
validated by `_listed`, matching the existing `_bounded` idiom) instead of
quietly answering with two hundred runs. The docstring now says it is one page
and cannot tell a short history from a capped one.

Regressions: `test_a_page_beyond_what_the_control_plane_will_give_is_refused`
and `test_the_page_the_control_plane_will_still_give_is_accepted`; both fail
when `_listed` is bypassed.

### Checked, and not defects

Three findings from the sweep did not survive inspection. Recording why, so
they are not re-raised.

**`sandbox_ownership` returns an expired lease.** It filters `status='active'`
but not `expires_at`, so it can hand back a lease that has lapsed. That is not a
hole, and the reason is worth recording because the first reading of it is
wrong.

`sandbox_ownership` is used in `AppState::commit_state` only to decide *which*
fenced call to make, and the call in the `Some` branch is
`Repository::update_state_with_lease`. That is the authoritative check, and it
enforces the invariant itself: `update_state_with_lease_transaction` reads
`active_lease()`, whose query is

```
WHERE tenant_id=$1 AND sandbox_id=$2 AND status='active' AND expires_at > now()
```

so an expired lease yields `None` and the transition is refused with
`"sandbox has no active unexpired lease"` — the exact condition the message in
`commit_state`'s `None` branch claims. The expiry filter the first lookup lacks
is applied by the second, so choosing the branch cannot bypass it.

The trait states the same contract (`crates/aiec-core/src/storage.rs`): "the
transition is rejected unless the sandbox's current active, unexpired lease
*is* `lease_id`: a worker that lost its lease can never commit state, whatever
generation it presents."

This is pinned by a database-backed regression,
`an_expired_or_absent_lease_cannot_commit_and_says_which_it_was`
(`crates/aiec-storage/src/postgres.rs`): it leaves the row `status='active'`,
expires its timestamp, attempts the fenced transition, and asserts both the
refusal and that the sandbox's state is unchanged.

There is no ambiguous middle case. `sandbox_leases_one_active_per_sandbox` is a
partial UNIQUE index on `sandbox_id WHERE status='active'`
(`migrations/0002_control_plane.sql`), so a sandbox has at most one active
lease, and the two lookups cannot disagree about *which* active row they mean:
`sandbox_ownership` finds that row, and `active_lease()` either returns the
same one (the transition proceeds) or `None` because it has lapsed (the
transition is refused).

An earlier note in this file claimed the opposite — that a worker could commit
state between expiry and reassignment because it still physically held the
machine. That was reasoned from `update_state_with_lease` at
`crates/aiec-api/src/lib.rs`, which is a **test double** (`LeasedRepository`),
not the production implementation. Corrected here.

**`reclaim_run` early-returns on a non-terminal run.** Its only production
caller is `reclaim_owned`, reached only after `fail_run_queue` returned `true`,
and `fail_run_queue` calls `retire_run` — which sets the run to `failed` — in
the same transaction that moves the queue row to `reclaiming`, before
`reclaim_run` reads the run back. The guard therefore holds by construction.
`finish_run_queue` independently requires `r.state IN
('succeeded','failed','cancelled')`, so even a run that slipped through keeps
its `reclaiming` row and its lease for durable recovery rather than being
finished away while holding compute.

**A `Retry-After` is missing from quota 429s.** The rate-limit path emits a real
value computed from the token bucket. The quota path returns
`quota_exceeded` for a tenant concurrency limit and for disk quota
(`runs.rs`, `"disk quota exceeded"`), neither of which has an honest retry
window — there is no computable moment to retry at, and a fabricated number
would be worse than none. The retry queue also already treats `QuotaExceeded`
as non-retryable (`runs.rs`, `is_retryable`). Supplying a header here is a
product decision, not a defect fix.

## Fixed in the 2026-10-03 audit: lifecycle and rollback

### A teardown that found no lease to release never deleted its row

`tear_down_sandbox` stops the machine, hands the capacity back, and only then
deletes the row, and that order is the point: capacity must not be credited
against a machine that is still running. But the release step propagated
`CoreError::NotFound`, and that is the *ordinary* answer when the lease already
expired and the sweeper returned its capacity, or when a concurrent teardown got
there first. The `?` aborted before `delete_sandbox`, so a machine that was
genuinely gone kept a row in `Running` — and the quota counts
`state NOT IN ('destroyed','failed')`, so that row consumed the tenant's
active-sandbox budget until an operator noticed. `destroy_with_retry` could not
cover it either: `NotFound` is not in `is_transient_destroy_error`, so the retry
loop gave up on the first attempt and recorded `cleanup_failed` for a sandbox
that was already stopped.

`NotFound` is now treated as "already released" and the deletion proceeds. Any
other release error still propagates, because a genuine failure to release must
not be recorded as a clean teardown. Regression:
`a_teardown_still_deletes_its_row_when_there_is_no_lease_left_to_release`, built
on `AppState::new` because `AppState::development` skips the release branch
entirely. It asserts the final state is `Destroyed` rather than that the row is
absent, since `delete_sandbox` is a state transition and not a physical delete —
asserting absence would have been a test that passes for the wrong reason.

### The agent's `bash` tool leaked its process group when `wait` failed

The function's own doc comment states the property: the command runs in its own
process group so a timeout kills everything it started, because killing only the
shell leaves a backgrounded grandchild running for the rest of the run. The
timeout arm did that correctly. The `Ok(Err(_))` arm — `wait` itself failing —
returned straight out, which meant the whole process group survived, neither
drain task was awaited (dropping a `JoinHandle` detaches rather than cancels, so
the bounded read silently stopped being bounded exactly when the tool failed),
and the shell was never reaped. `kill_on_drop(true)` was absent, unlike the
other four spawn sites in the tree.

Both arms now run one `kill_group` helper that signals the group, reaps the
shell and lets the caller drain the pipes. Regressions:
`tearing_down_a_command_kills_what_it_backgrounded` drives the real helper
against a shell that backgrounds a `sleep`; removing the group signal — so
`start_kill` alone kills the shell and nothing else — makes it fail with
`process N outlived the teardown`.

### A failed Firecracker create left its VM directory and owner record

`create` makes the per-sandbox directory and plants `owner.json` in it before it
copies anything. When `resize2fs` or the control-identity install then failed,
`rootfs::discard` removed the image and nothing else — leaving a directory that
`reconcile_local` reads, so the host kept reporting an orphan candidate for a
sandbox that was never created, and nothing revisited it because the row was
destroyed by then. `discard_vm` now removes both. The directory is a parameter
rather than the image's parent, because removing an inferred parent is how a
shared base image sitting beside the sandbox gets deleted with it. Regression:
`discarding_a_failed_create_takes_the_directory_and_spares_the_base`.

### A reclaim that failed on the VM directory skipped the socket directory

`reclaim` runs at the end of destroy, so the machine is already gone by the
time it removes the two per-sandbox directories. Returning on the first failure
left the Firecracker API socket directory behind with no later `destroy`
guaranteed to revisit it. Both are now attempted and the first error is still
the one returned, so the caller's retry sees the real failure.

### A Guard release that could not stop the gateway stranded its interface

`GuardNetworkManager::release` cuts the network, sets the interface down, stops
the gateway, and only then deletes the `ag*` interface and its nftables table.
A gateway that failed to shut down returned between those steps, leaving the
interface and its policy on the host with nothing holding the attachment — the
`running` entry had already been removed two statements earlier, and `prepare`
gates only on that map. The network is cut by then, so what leaks is the
interface and the rules rather than guest traffic, which is why this was a host
hygiene defect rather than an isolation one. The shutdown error is now deferred
and returned after the host cleanup completes, so a caller still learns the
gateway did not stop cleanly but nothing is stranded. Not covered by a
regression: reaching this arm needs a live Guard gateway and root-level `ip` and
`nft`, so there is no deterministic seam to drive it from a test.

## Fixed in the 2026-10-03 audit: unbounded list reads

### `GET /v1/sandboxes` returned the tenant's entire history in one response

Destroying a sandbox transitions its row rather than deleting it, and nothing
reclaims it, so a tenant's sandbox list is their whole history and only grows.
The route called `list_sandboxes(tenant)`, the store ran `SELECT * FROM sandboxes
WHERE tenant_id = $1` with no `LIMIT`, and the whole thing was serialised into one
response. Any tenant could therefore decide how much the control plane held in
memory and on the wire, and the cost rose with tenure rather than with anything
the caller asked for.

Capping the list without a successor would have been worse than the original
defect rather than better: a truncated list is indistinguishable from a complete
one, so the older rows would be unreachable rather than merely slow, and no
caller could get past the cap. The route now mirrors the matrix listing that
already exists in this codebase:

- `limit` plus paired `after_created_at` / `after_id`. Both halves or neither: a
  cursor with only a timestamp has no sandbox to start after, and one with only
  an id cannot order a page that has not been read.
- The response is `{ "sandboxes": [...], "next": {...} }` rather than a bare
  array, so a page says whether it truncated. `next` is `null` exactly on the
  last page.
- Newest first, `ORDER BY created_at DESC, id DESC`, with the keyset predicate
  `(created_at, id) < ($cursor_ts, $cursor_id)` so the boundary is a value that
  already exists rather than an offset a reader has to keep consistent against
  rows created or destroyed meanwhile.
- The ceiling is `aiec_core::storage::MAX_SANDBOX_PAGE` (200), declared once in
  core because the route and both stores clamp to it; two copies would drift and
  the drift would show up as an in-process caller asking the database for more
  rows than the route would have returned.

The cursor names the last sandbox the page **returned**, not the row held back
to prove another page exists. That is the one detail this could easily have got
wrong, and a cursor pointing at the held-back row pages past it: the walk ends
with that sandbox silently missing.

`limit + 1` is fetched and the extra row trimmed, so `next` reflects the real
answer rather than being inferred from a page that happened to come back full.

Migration: the Rust client gained `list_sandboxes_page`, `list_sandboxes_after`
and `list_all_sandboxes`; `aiec sandbox list` follows the cursor by default and
prints one page with `--page`; the Python SDK returns a `SandboxPage` and gained
`list_after` / `list_all`, and refuses a `limit` the control plane would clamp.
One defect was introduced by the migration and caught by its own regression,
which is worth recording because it is invisible in review: the Rust client
first built the cursor query with `format!`, and `DateTime<Utc>::to_rfc3339()`
ends in `+00:00`. A bare `+` in a query string decodes as a space, so the route
received `2026-10-03T12:00:00 00:00` and refused every page after the first — for
a cursor the caller had never got wrong, and only when the tenant's history
exceeded one page. The client now uses the same `.query(&[...])` the matrix
cursor above it uses, and the regression reads the raw query off the wire and
decodes it the way a server does rather than trusting the client to have encoded
it.

Paginating the route broke the leak census in `benchmarks/aiecbench`, which
checked `isinstance(response.body, list)` and therefore reported
`{"available": false}` for every sandbox reading from then on — the exact
signal the soak tooling exists to distinguish from "nothing leaked". Its tests
stayed green through the whole of it, because the fixture they fed it was a
hand-written bare list rather than a page. The census now walks every page and
refuses rather than reporting a partial count, and the fixture is the shape the
control plane actually sends.

Three things in the same area are worth stating because each was a real defect
rather than a style:

- **The census interpolated its cursor into the path**, reproducing the `+00:00`
  bug one layer over. It percent-encodes now, and a mutation run confirms the
  test fails when it does not.
- **The sandbox list index did not carry the tie-breaker.** `0001` built
  `(tenant_id, created_at DESC)`; the keyset page orders and filters on
  `(tenant_id, created_at DESC, id DESC)`. The plan then reads the index in
  `created_at DESC` order and sorts whatever falls out of it before `LIMIT`
  applies, so a burst — and a soak creates sandboxes in bursts — puts the whole
  history in one timestamp bucket. `0026` replaces the index rather than adding
  beside it, because this table takes an index write on every placement, pause,
  resume and teardown. No behavioural test can catch this: the page reads
  correctly from the old index too, only slower, so the index definition itself
  is asserted.
- **`list_all_sandboxes` had no termination guarantee.** It ends when the server
  stops naming a successor, which makes an unbounded fetch loop out of a control
  plane that does not — the same defect the paging was added to remove, one
  layer down. It now refuses on a repeated cursor and on an empty page that
  still claims a successor. The first of those is caught by the test hanging to
  its timeout with the guard removed, which is the point.

Paginating it broke three more consumers, and the pattern is worth recording
because it repeated almost verbatim each time: a script asks the route for a
list, gets a page, and either raises or unwraps one page and calls the result
complete.

- `benchmarks/aiecbench/observe.py::sandbox_census` reported
  `{"available": false}` for every sandbox reading — the one signal the soak
  tooling keeps distinct from "nothing leaked".
- `benchmarks/bug-hunt-live.py::check_no_residue` asked for `limit=256` and was
  served 200, then read only that page. Verified directly: with a live sandbox on
  page two, the old check reports clean. It now walks the cursor, percent-encodes
  it, and reports how many pages it read.
- `scripts/guard-phase2-acceptance.py` iterated the body directly, so a page
  object yielded its *keys* and `row.get("id")` raised on a string. The
  surrounding `except Exception` turned that into a `census_error` row, which
  then failed the quarantine assertion — so that acceptance case was failing for
  a reason that had nothing to do with quarantine.

Two of these were invisible to their own test suites, because the fixtures fed
them a hand-written bare list. The fixture is the page object now. Any future
response-shape change needs `benchmarks/tests/support.py` and
`benchmarks/bug-hunt-live.py` in the same commit as the route, or the tooling
will keep reporting the *measurement* as broken while the thing being measured
is fine.

The Python SDK's cursor regression used `Z`-suffixed timestamps throughout,
which pass through the encoder without touching the defect: the bug needs a
positive offset. A regression now walks a `+00:00` cursor and fails if a raw
`+` reaches the query string.

The MCP server no longer reads this route at all — it fetched the tenant's list
and intersected it with its own ownership set, which under paging would have
hidden any owned sandbox older than the first page, so it now fetches each owned
sandbox by id.

Evidence. Three Rust regressions and one DB-backed SQL regression. Every one of
these mutations was applied and confirmed to fail:

| mutation | caught by |
|---|---|
| cursor names the held-back row (in-memory and SQL) | both the API walk and the SQL walk |
| no sort: hash order decides the page | both |
| cursor compares `created_at` alone, dropping the id tiebreak | the shared-timestamp tests only |
| no page-size clamp | the ceiling assertions only |
| no cursor predicate: every page is the first page | the SQL walk |
| `ORDER BY` loses the id tiebreak | the SQL walk |

The tie is placed where the walk rests on it — with a page of four, the first
page ends on the tied pair's higher id — because a tie at either end of the
history passes under a timestamp-only comparison by luck.

### Not proven: the statement-level `LIMIT` is not observable from a test

The rows are trimmed in Rust as well as in SQL, so deleting `LIMIT` from the
query leaves the page-length assertions green while the database goes on
transferring and parsing every row the tenant owns. The SQL bound is there to
keep the transfer small; the page bound itself is what the tests pin, and it
holds either way. Asserting the statement-level bound would need a row count the
store does not expose, so it is recorded here rather than tested.

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

### Investigated and deliberately left alone: a rollback that lost its state CAS

The rollback's first step is a fenced state CAS marking the sandbox
`Destroying`. When that CAS is refused the path returns without stopping
anything, and `create` completes before `start` and before
`prepare_environment`, so a failure in either leaves a materialised machine
running on the worker. That reads like a leak, and it was worth the
investigation — but closing it here is a fencing bug, not a fix.

The instinct to close it here is to destroy on the way out, and that is exactly
what the regression in the tree forbids:
`replaced_owner_failure_never_destroys_the_new_lease_machine` fails with
`stale owner dispatched teardown` if the rollback destroys unconditionally.

The first draft of this entry blamed the worker for acting on an unfenced
`Destroy` — "`Destroy` carries a sandbox id and nothing else, and the worker
acts on it without checking the lease." **That was wrong**, and it was wrong in
the direction that would have justified the unsafe fix. `Destroy` does carry a
lease id and generation: `WorkerRequest` has `lease_id` and `lease_generation`
on every operation, `lifecycle_sandbox` classifies `Destroy` as a lifecycle
operation, and the handler calls `authorize` for those under the same
per-sandbox guard that keeps a destroy behind a create. `authorize` re-asks the
control plane who owns the sandbox *at the moment it runs* and refuses with
`stale sandbox lease generation` unless the dispatched `lease_id` matches the
current owner's. So a stale owner's destroy is rejected at the worker; the
existing test asserts that, using a per-lease-keyed fake that mirrors it.

The early return is therefore correct rather than merely tolerable: the original
owner cannot destroy its machine, because doing so safely requires the worker to
confirm the machine is still the one it created, and `Destroy` is addressed by
sandbox. Cleanup for that machine belongs to recovery, which fences on the lease
it holds. Recorded so the early return is a decision rather than an oversight,
and so the claim above is not re-derived wrongly a third time.

### A Docker exec that times out keeps running until its sandbox is destroyed

`exec_raw` returns `exit_code: 124` with `timed_out: true` when its read loop
expires, but the exec itself is left running inside the container — so a command
that ignores its own timeout keeps consuming the sandbox's CPU and memory until
the sandbox is destroyed. **Not fixed.** The Docker Engine API exposes no
exec-kill endpoint at all (`bollard 0.21.1` has no `kill_exec`, and the daemon
offers nothing to map it to), so closing this means either killing the whole
container, which discards the sandbox a caller is still using, or driving the
kill through the guest's own process group, which is a change to every exec's
signal handling rather than a fix to the timeout path. Recorded because the
bounded lifetime of the sandbox bounds this too, and because a caller reading
exit code 124 should know the process it describes may still be there.

### The worker ownership route is not tenant-scoped

`GET /v1/workers/{node}/ownership/{sandbox_id}` resolves the sandbox by id
alone — `sandbox_leases` is looked up with `WHERE sandbox_id=$1 AND
status='active'`, with no `tenant_id` predicate. The handler then compares the
returned `node_id` against the `{node}` path segment and returns
`409 sandbox is owned by another worker` on a mismatch, so a caller who names
the wrong node learns nothing; naming the right node returns that tenant's
`lease_id`, `generation` and `expires_at`.

**Not fixed, and the reason is the authentication model rather than the query.**
Worker routes are authenticated by one shared control token with no tenant
claim, so the handler has no tenant to scope the lookup with — adding a
predicate would need a credential that does not exist yet. The practical
exposure is correspondingly narrow: it requires already knowing both a
v7 sandbox UUID and the UUID of the node holding it, and the response is lease
bookkeeping rather than anything about the sandbox or its guest. This is
recorded so the gap is a decision rather than an oversight; the fix belongs
with per-tenant worker credentials.

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

### `GET /v1/sandboxes/{id}/artifacts` read the whole prefix and hashed it

**Fixed.** The route lists one sandbox's artifacts under
`tenants/{tenant}/sandboxes/{id}/artifacts/`, and `FilesystemObjectStore::list`
walked that tree with no bound — and it returned a size and a SHA-256 for every
object it found, which it computes by reading each file end to end. So the cost
of asking for a listing of object *metadata* was the bytes of every object in
the prefix.

What made it reachable is that `MAX_ARTIFACTS = 64` does not cover it. That
constant bounds `WorkloadSpec.artifacts` — the paths a *run* collects. The
direct upload route `PUT /v1/sandboxes/{id}/artifacts/{name}` is separately
tenant-callable, accepts any distinct `name` (up to 128 characters from a fixed
alphabet), and has no cap on how many. An ordinary tenant could therefore store
as many objects as it liked under one sandbox and make each subsequent listing
read all of them.

`MAX_LISTED_OBJECTS = 1000` now bounds the walk, checked *before* each file is
opened rather than after, so a prefix just over the bound does not cost one
whole file more than the bound allows. Past the bound the call is refused with
`StoreError::ListingLimitExceeded` → `CoreError::LimitExceeded`, which the API
already maps to `413 limit_exceeded`. Refused rather than truncated on purpose:
a short listing is indistinguishable from a complete one, and a caller that
cannot distinguish them will treat a partial answer as the truth.

The S3 backend is unaffected — its `list` is `Unsupported` and returns
`501`. This bound is on the filesystem backend, which is what a self-hosted or
development deployment actually runs.

Regression: `a_listing_too_large_to_describe_is_refused_rather_than_truncated`,
which puts exactly `MAX_LISTED_OBJECTS` objects under a prefix and requires a
complete listing, adds one more and requires a refusal, and requires a small
listing to still answer while the store holds more. Removing the bound check
fails it at the refusal assertion.

### Checked and not defects: the three unbounded run-history reads

`list_run_events`, `list_run_attempts` and `list_run_artifacts` are complete
per-Run reads with no `LIMIT`, which looks like the same defect as the sandbox
list. They are not: each is bounded by a constant enforced on the write path,
so the response size cannot grow with tenant tenure the way `GET /v1/sandboxes`
did.

- **`run_attempts` ≤ `MAX_RUN_ATTEMPTS` = 10.** `validate` refuses anything
  outside `1..=MAX_RUN_ATTEMPTS` (`crates/aiec-api/src/runs.rs:186`), the loop
  is `for number in 1..=request.max_attempts` (`runs.rs:225`), and the table
  adds `UNIQUE (run_id, attempt_number)` with `CHECK (attempt_number > 0)`.
- **`run_artifacts` ≤ `MAX_ARTIFACTS` = 64.** Enforced in
  `WorkloadSpec::validate` (`crates/aiec-core/src/run.rs:237`), and
  `put_run_artifacts` replaces the run's artifact set rather than appending to
  it.
- **`run_events`** is the only one that is not capped by a single constant, and
  it is still bounded: the events a run accumulates are a function of its
  attempts. Roughly 700 rows in the worst case, from one `run.created`, per
  attempt one `sandbox.assigned`, at most `MAX_SETUP_COMMANDS` (32)
  `task.started`, 32 validation `task.started`, one `task.finished`, one settled
  event, and at most one `sandbox.destroyed`.

The part worth stating because it looked like the opposite: the cleanup loop at
`runs.rs:1965` emits one `sandbox.destroyed` per sandbox, so events scale with
sandboxes per run. There is no named cap on sandboxes per run, but
`run_sandboxes` is written only by `link_attempt_sandbox`
(`crates/aiec-storage/src/postgres.rs:516`), which is one row per attempt and
is guarded by `sandbox_id IS NULL` on a `running` attempt. So the bound is
`MAX_RUN_ATTEMPTS`, transitively. `link_run_sandbox` — the public trait method
that would write a row not tied to an attempt — has no production caller.

Eval matrix and repetitions do not change this: they create many *runs*, each
with one sandbox, not many sandboxes in one run.

### Checked and not defects: source-address spoofing on every guest path

`c839bab` fixed the legacy TAP path, and the open question was whether it also
covered Firecracker. It does. There are exactly two nftables builders in the
tree and both refuse a forged source:

| Guest path | Verdict | Decisive rule |
|---|---|---|
| Firecracker with a Guard policy | covered | `crates/aiec-guard/src/enforcement/render.rs:391` — `input iifname "{iface}" ip saddr != {guest} counter … drop` |
| Firecracker without one (`AIEC_ALLOW_LEGACY_NETWORK=1`) | covered | `crates/aiec-network-linux/src/lib.rs:445` and `:453` — `input`/`forward iifname "{tap}" ip saddr != {guest} drop` |
| Docker | not applicable | it never builds a host-side policy at all; policy becomes a Docker network-mode string (`crates/aiec-runtime/src/docker.rs:131-139`) |
| `NetworkPolicy::Disabled` | not applicable | no interface is created, so there is no link to source from |
| host-network mode | does not exist | `NetworkPolicy` has three variants and none maps to `"host"` |

`FirecrackerRuntime::new` builds a `GuardNetworkManager`
(`crates/aiec-runtime/src/lib.rs:2069`), which dispatches on whether the sandbox
carries a policy (`crates/aiec-network-linux/src/guard.rs:1196`) — so the
shipped worker takes one of the two covered branches, never a third.

Two details that make the legacy rules hold rather than merely exist. The only
`ct state` accept is keyed `oifname "{tap}" ip daddr {guest}` (`lib.rs:460`) —
inbound *to* the guest, so a guest cannot reach it with a forged source. And the
masquerade (`:462`) is keyed `ip saddr {guest}`, so a forged source is not even
NATed. Guard renders no masquerade and no `ct state` at all: its egress
terminates at an in-host gateway (`forward iifname "{iface}" … drop`,
`render.rs:405`).

Each builder has its own anti-spoof regression rather than one shared test:
`a_forged_source_from_the_guest_is_dropped_before_any_accept_runs`
(`crates/aiec-network-linux/src/lib.rs:1032`) and
`the_generated_ruleset_enforces_the_model_it_was_built_from`
(`crates/aiec-guard/src/enforcement.rs:1598`). Both assert *ordering* — that the
drop precedes every `accept` — which is the property that matters. There is no
single test asserting both, and no unit-level Firecracker end-to-end check: that
proof needs real nft and KVM and lives in the acceptance harness.

One adjacent fact, recorded so it is not re-audited as a new finding: the
`bwrap-dev` runtime gives the guest the host network namespace whenever network
is enabled — no `--unshare-net`, no nft (`crates/aiec-runtime/src/lib.rs:623`).
That is the one place a guest shares the host's stack outright. It is outside
the production boundary and is documented as such in `docs/SECURITY.md:3`.

### The MCP server's sandbox list never shrank, and cost one request each

**Fixed.** `LocalAiec` keeps its own `owned` map of the sandboxes the MCP server
created, and `list_owned_sandboxes` walked it with one `get_sandbox` request per
machine, in series. Two separate problems:

- **It grew without bound.** `forget` runs only from an explicit
  `destroy_sandbox` (`crates/aiec-mcp/src/sandbox.rs:636`). A machine that
  timed out, failed, or aged past retention stayed in the map for the life of
  the process, so a long-running MCP server accumulated every sandbox it had
  ever made and fetched all of them on every listing.
- **A health poll paid for it.** `health_report` calls the same listing
  (`crates/aiec-mcp/src/server.rs:784`), so the cost of asking the server if it
  was alive was one round trip per sandbox it had ever created — on the path a
  client reaches repeatedly, and grows without limit. `aiec://sandboxes` and the
  `list_sandboxes` tool had the same exposure.

The listing now fetches concurrently with `OWNED_FETCH_CONCURRENCY = 8` so a few
hundred machines do not open a few hundred sockets, drops any machine that is
terminal or that the control plane no longer has — neither is something this
server can clean up or hand back — and refuses past `MAX_OWNED_SANDBOXES = 200`.
Refused rather than truncated, for the same reason as everywhere else in this
file: a shorter list is indistinguishable from a complete one, and a caller
acting on "these are my machines" would leave the rest running without ever
learning of them.

Regression: `the_owned_listing_forgets_finished_machines_and_refuses_past_its_bound`
checks all three properties — a destroyed machine is not handed back, it leaves
the map, and a 404 for a retention-expired one prunes it too, and a server past
the bound is refused. Removing the prune fails on the ownership-map assertion;
removing the bound fails on the refusal.

### The Python SDK's `list_all` had no way to stop

**Fixed.** The Rust client gained two guards when the sandbox list was
paged — a cursor already followed stops the walk, and an empty page carrying a
cursor is refused. The Python SDK's `list_all`, which walks the same route, had
neither: it ended only when the server said there was no next page, so a
control plane that kept offering a cursor made it request forever.

Both guards are now in `sdk/python/agentforge/client.py`, raising `ValueError`.
Regressions: `test_a_control_plane_that_repeats_a_cursor_cannot_walk_forever`
and `test_an_empty_page_with_a_cursor_is_refused_not_repeated`.

Both stubs refuse past five requests, so a walk that does not stop fails in
about a second rather than spinning until the suite is killed — the first
version of these tests hung, which proved the defect and made for a worse
regression.

### The guest agent's directory listing was the one unbounded one

**Fixed.** Three runtimes serve a directory listing and two of them already
bounded it. Docker refuses a directory holding more than `MAX_LIST_ENTRIES =
10_000` entries, and says why in the code: a silent truncation there would
archive a workspace that is missing files (`crates/aiec-runtime/src/docker.rs:382`).
e2b bounds the same way. The Firecracker path went through the guest agent, and
`guest/aiec-guest/src/main.rs` read the whole directory into a `Vec` with no
ceiling at all.

The host's bound did not cover it. Both Firecracker workspace walks cap
`total` against `MAX_WORKSPACE_ARCHIVE_BYTES` (`crates/aiec-runtime/src/lib.rs:3711`
and `:3842`) — total *bytes*. A directory of a million empty files is a few
megabytes and never approaches it, while still costing a million-entry vector
in the guest, a million-entry response frame over vsock, and a million-entry
`Vec<FileEntry>` on the host.

The listing is now `list_directory`, extracted from the request match and
bounded at the same 10,000, refusing rather than shortening — same reason, same
number as the other two runtimes. Regression:
`a_directory_too_large_to_list_is_refused_rather_than_shortened` requires one
entry past the bound to be a refusal, the bound itself to list whole with every
entry described, and removing the bound check fails the refusal.

### Bubblewrap's directory listing was the last one with no ceiling

**Fixed.** Four runtimes serve `files.list`. Docker bounds it, e2b bounds it,
and the guest agent now bounds it. Bubblewrap's
`list_files` (`crates/aiec-runtime/src/lib.rs:688`) read `read_dir` into a
`Vec<FileEntry>` with no limit at all, so a tenant decided how much of the
worker's heap one listing allocated — the workspace is theirs to fill.

The bound existed three times over in that file's neighbourhood, as a private
constant in each backend, and that is how the fourth went missing: it was not a
decision that Bubblewrap lacked, it was a decision Bubblewrap never got to
make. `MAX_LIST_ENTRIES` is now one `pub(crate)` constant in `aiec-runtime`,
used by docker and e2b as well, so the next backend cannot pick a different
number by omission. The guest agent keeps its own copy because it is a separate
crate that does not link the runtime.

Regression: `a_directory_too_large_to_list_is_refused_rather_than_shortened`
requires 10,000 to list whole and 10,001 to be a `LimitExceeded` refusal.
Removing the bound makes it return `Ok` with a short listing.

### Candidates audited and deliberately not changed

- **`restore_owner_access`** (`crates/aiec-runtime/src/docker.rs:1119`) walks a
  guest-created tree into an explicit stack with no entry ceiling. Bounding it
  would leave the tree half-restored and the files owned by the wrong user, so
  a slow walk is the correct trade on a cleanup path. The comment already
  records that depth is the guest's to choose.
- **Firecracker's `list_files`** carries no local check because its source is
  the guest agent, which now refuses. The transport is bounded independently:
  `read_frame_async_bounded` rejects any frame over `MAX_FRAME = 2 MiB` before
  allocating it, and the frame is HMAC-authenticated with the per-sandbox guest
  secret, so a guest process cannot forge a larger response.
- **SDK and client `list_all` walks** accumulate into the caller's own heap
  with a repeat-cursor guard but no total ceiling. That is a large tenant
  listing to their own process, not a shared server; bounding it would make
  the walk return an incomplete answer, which is the failure mode pagination
  was introduced to avoid.
- **Daemon loops** in the worker claim, heartbeat, lease-renewal and
  `aiec-guard-watcher` incident polling run forever by design, are driven by
  fixed operator intervals, and propagate errors rather than spinning.
- **e2b's `bindings` map** grows one entry per created sandbox and is only
  removed on `destroy`. Worker-lifetime and a few hundred bytes per entry.

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

### The Guard history tables were the last unbounded tenant reads

**Fixed.** Two more listings had the defect the sandbox list had. Neither
`guard_proposals` nor `guard_tool_approvals` is ever pruned — a decided
approval is deliberately retained as history — and both were read whole into a
`Vec` and returned as a JSON array. The response size was a function of how
long the sandbox had been running.

The approval queue is the more exposed of the two. A row is created by
`POST /v1/sandboxes/{id}/guard/approval`, which a sandbox reaches with nothing
but `sandboxes:write`, so the growth is driven from inside the sandbox rather
than by an operator. `guard_proposals` is bounded only by what a
`guard:propose` key chooses to send.

Both are now keyset pages on `(created_at DESC, id DESC)`, mirroring the
sandbox list: `limit` default 50 clamped to `MAX_GUARD_PAGE = 200`, a paired
`after_created_at`/`after_id` cursor that must be given together or refused,
`LIMIT limit + 1` in the query with the extra row trimmed in Rust, and `next`
naming the last row *returned*. Migration `0027_guard_history_keyset_index.sql`
replaces both indexes with `(tenant_id, sandbox_id, created_at DESC, id DESC)`.

`SandboxCursor` is now `PageCursor`, shared by all three listings, because they
order on the same tuple and three copies of one page shape is how the missing
index happened in the first place. `MatrixCursor` stays separate: it keys on
`requested_at`, which is a different column and a different order.

Regressions:

- `a_sandbox_proposal_history_is_paged_and_says_where_it_stopped` and
  `the_approval_queue_is_paged_and_says_where_it_stopped` write five rows
  sharing one timestamp, so the id tie-breaker is what makes the page boundary
  a value rather than a guess, then page at 2 and require every row exactly
  once. Both fail if the cursor names the held-back row instead of the last
  returned one — the mutation that silently skips one row per page.
- `the_guard_history_indexes_carry_the_keyset_tie_breaker` asserts both index
  definitions directly, because nothing about the returned page detects a
  missing tie-breaker: the page reads correctly from the shorter index too,
  just by sorting every tied row before the `LIMIT` applies.
- `the_proposal_page_bound_is_pushed_down_to_the_database` `EXPLAIN`s both
  statements and requires a top-level `Limit` node. It exists because the
  behavioural tests cannot see this: the rows are trimmed in Rust after the
  fetch, so deleting `LIMIT` from the SQL leaves every one of them passing
  while the database materialises the whole history. Confirmed — with `LIMIT`
  removed the root plan node is `Index Scan` and the behavioural tests still
  passed.
