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

`GET /v1/runs` previously clamped `limit` to `MAX_RUN_PAGE` (200) and answered
with a bare `Vec<Run>` and no cursor. `Runs.list(limit=1000)` sent 1000, got
200, and returned a list its docstring called "the caller's runs".

The SDK now refuses a page size the control plane cannot honour
(`MAX_LIST_LIMIT = 200`, validated by `_listed`) and documents a one-page read.
The subsequent API fix adds an exclusive `after_requested_at` + `after_id`
keyset cursor without changing the array response shape; older callers remain
valid. Histories beyond 200 are now reachable. See the run keyset evidence below.

Regressions: `test_a_page_beyond_what_the_control_plane_will_give_is_refused`
and `test_the_page_the_control_plane_will_still_give_is_accepted`; both fail
when `_listed` is bypassed.

### Checked, and not defects

Four findings from the sweep did not survive inspection. Recording why, so
they are not re-raised.

**A sandbox key can mint a key that outlives its own revocation.** Re-checked,
and the alarming half of it is not reachable. There is one authentication
mechanism in the control plane: a Bearer token resolved against `api_keys`. A
"sandbox key" is an ordinary tenant credential that gets written into the
sandbox, not a separate principal with its own route access, so it reaches
`POST /v1/keys` only as itself — and `create_key` now authorizes every scope it
issues against the scopes the caller holds, defaults included. A caller holding
`sandboxes:write` can mint a key, but only carrying `sandboxes:write`, which is
authority it already had.

What is true, and is left as is: `expires_in_days: null` is a permanent key, so
the minted credential survives revocation of the credential that minted it.
Revocation is per-key and there is no parent/child cascade. Capping a minted
key's lifetime at its parent's would break the rotation this API exists for —
the replacement credential has to be able to outlive the one being replaced —
so the bound is deliberately not there. The mitigating property is that `POST
/v1/keys` writes an `api_key.created` audit event naming the actor key and the
subject key, so the sibling a compromised credential minted is discoverable in
the database. Residual limit, recorded honestly: there is no HTTP surface for
querying that audit trail, so finding it means an operator goes to the database
directly.

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

### The key routes enforced one rule in one branch and a different one in the other

**Fixed.** Two authorization defects on `/v1/keys`, found by reading the
handlers rather than the routes. Neither had any test coverage: the rules were
written down in comments and never exercised, so nothing said whether they held.

**Minting.** `POST /v1/keys` decided the grant inside an `if`:

```rust
let scopes = if body.scopes.is_empty() {
    account::DEFAULT_KEY_SCOPES.to_vec()   // granted, unchecked
} else {
    /* parse, then */ p.authorize(scope)?  // checked
};
```

The check that a key cannot grant a privilege it does not hold was inside the
`else`. So the convenient branch was the unguarded one: a key holding
`sandboxes:read` and nothing else could omit `scopes` and be handed a key with
`sandboxes:read`, `sandboxes:write`, `snapshots:read` and `snapshots:write`.
Reproduced against the handler before the fix - HTTP 200 and
`"scopes":["sandboxes:read","sandboxes:write","snapshots:read","snapshots:write"]`.
That is the scope that places machines and runs code in them, so the gap
between the two branches is the gap between a scoped credential and an
arbitrary-code-execution one.

**Revoking.** `DELETE /v1/keys/{id}` had one rule, and it was the wrong one for
the threat: not the key you are authenticating with. That prevents
self-lockout. It says nothing about authority, so any key could revoke any
other key in the tenant, including the tenant's `admin` key. Revocation has no
inverse and a tenant gets back in with an invite, so this was a permanent
denial of service available to the least privileged credential in the tenant,
including a scoped credential a caller supplies to a sandbox.

Both now answer to the same rule as each other, and as the mint check was
always meant to: **a key may not grant or destroy a privilege it does not hold.**
`revoke_key` reads the target first and refuses any scope the caller lacks,
which needed a `get_key(tenant, id)` on the store rather than listing the
tenant's key set to find one row - a revocation should not cost what the
tenant's largest key set ever did.

Regression: `the_default_scopes_are_granted_only_to_a_key_that_holds_them` and
`a_key_may_not_revoke_one_that_outranks_it`. Both were confirmed to fail when
the corresponding check is removed, and `a_key_may_not_revoke_one_that_outranks_it`
also asserts the reverse direction still works, because the failure mode of a
fix like this is locking the tenant out of its own credentials.

Revoking a key that is not in the caller's tenant still answers 404. That did
not change: `revoke_key` in the store scopes its update by tenant and reports
`NotFound` when nothing matched. The handler now rejects earlier, on the
authority check, but it does not reject differently, and a key in another
tenant is still indistinguishable from one that does not exist.

### The snapshot listing, and the index convention behind it

**Fixed.** `GET /v1/sandboxes/{id}/snapshots` returned `Vec<Snapshot>`. A
snapshot is retained until somebody deletes it, nothing prunes them
automatically, and `POST /v1/sandboxes/{id}/snapshots` is repeatable, so the
response was a function of how many times the sandbox had been snapshotted.

It is now the same keyset page as the sandbox list and the two Guard
histories: `limit` default 50 clamped to `MAX_SNAPSHOT_PAGE`, the paired
`after_created_at`/`after_id` cursor refused unless both halves are present,
`LIMIT limit + 1` in the query with the extra row trimmed in Rust, and `next`
naming the last row returned. The paging-parameter parsing and the
half-cursor refusal moved to one `page_cursor` helper shared by all three
routes, because three copies of a rule is how it ends up enforced in two of
them.

Migration `0028` replaces `snapshots_tenant_sandbox_idx`, which was
`(tenant_id, sandbox_id, created_at)`. That is the third table in this
repository carrying the same missing tie-breaker, after the sandbox list in
0026 and the two Guard histories in 0027. Three instances is the evidence that
it was a convention rather than an oversight. The query also ordered
`created_at DESC, id` - descending by one column, ascending by the other -
which is a stable order, so nothing read out of it was wrong, but not the
order a descending keyset walks.

### Recovery read a sandbox's whole snapshot history to find one archive

**Fixed.** `restore_workspace` listed every stored snapshot for the sandbox,
filtered to complete workspace captures in Rust, and took the newest. On the
recovery path, for every sandbox that came back on a dead worker, the cost was
the sandbox's entire snapshot history to find one row.

Replaced with `latest_stored_snapshot(tenant, sandbox, kind)`, which names the
kind and takes `ORDER BY created_at DESC, id DESC LIMIT 1` in the database. The
kind filter moves into the query, so the rows that were being read and then
discarded are not read at all. `list_stored_snapshots` had no other production
caller, so it is gone rather than left as an unused way to ask the old
question.

Regressions: `a_snapshot_history_is_paged_and_says_where_it_stopped`,
`the_snapshot_list_index_carries_the_keyset_tie_breaker` and
`the_snapshot_page_bound_is_pushed_down_to_the_database`. The first is caught
by a cursor aimed at the held-back row; the third by removing `LIMIT` from the
SQL, which the behavioural test survives. That second point is worth stating
plainly because it was the surprise: an earlier version of the plan test
carried its own copy of the query string, and mutating the real `LIMIT` left it
green. It now `EXPLAIN`s `LIST_SNAPSHOTS_SQL`, the constant the store actually
executes, for the same reason the Guard plan tests do.

## Collection-read census: what was checked and deliberately left alone

The unbounded-read audit did not end at the listings that were fixed. These are
the remaining collections that are read whole, with the reason each one is
accepted rather than overlooked. Recorded so a later reader does not have to
re-derive them, and does not mistake an assessment for an oversight.

- **Worker nodes and workers.** No longer read whole. `/ready` used to call
  `list_workers(true)` and discard the result, and `/metrics` materialised
  every node before summing it, so an unauthenticated request paid a full-table
  scan on every scrape and every readiness poll. `/ready` now asks the store
  `ping()` and `/metrics` asks for `node_capacity_totals()`, an aggregate that
  returns two numbers and counts rows inside the database. The aggregate keeps
  `list_nodes`' semantics exactly — only `healthy` nodes, only heartbeats inside
  `NODE_HEARTBEAT_TTL_SECONDS` — and a mutation of that predicate fails the
  parity test. Neither route gained a rate limiter: a load balancer polling
  readiness is not an abusive caller, and 429-ing a probe is worse than the
  scan was.
- **API keys** (`GET /v1/keys`). The tenant's own credential set, read whole.
  Creating one is now bounded by the authorization rule that was missing, so a
  caller must already hold every scope it grants, and each key is a metadata
  row with no per-row work behind it. Reaching the point where the response
  mattered would take thousands of `POST /v1/keys`, which is a worse
  amplification ratio than it looks and a real ergonomic cost to cap. If a cap
  is wanted later, that is a product decision about how many credentials a
  tenant may hold, not a defect in the read.
- **Run-scoped reads** (`list_run_events`, `list_run_attempts`,
  `list_run_artifacts`). Already checked and bounded by the write-path
  constants: `MAX_RUN_ATTEMPTS = 10`, `MAX_ARTIFACTS = 64`, and events
  transitively around 700 rows. They are complete per-Run reads by design and
  are not tenant-growable, because the write paths refuse past the bound.

### MCP and the CLI: no remaining unbounded collection read

The MCP server reaches exactly seven route shapes, and each was checked against
the store call behind it: `/v1/sandboxes` (keyset-paginated, capped at
`MAX_SANDBOX_PAGE`), `/v1/runs` (`list_runs` clamps to `DEFAULT_RUN_PAGE` = 50
and `MAX_RUN_PAGE` = 200), `/v1/runs/{id}` (one row), and the three run-scoped
collections already bounded by their write-path constants. The sandbox-history
call that walks owned sandboxes is capped at `MAX_OWNED_SANDBOXES = 200` with
concurrency 8. There is no MCP route that reads a collection whole.

The CLI's `guard proposals` prints the response body verbatim, which after the
Guard pagination work is the `{proposals, next}` envelope. It fetches one page
rather than looping, so a tenant with more than `MAX_GUARD_PAGE` proposals sees
the first page only — but the `next` cursor it does not follow is printed
alongside it, so the truncation is visible rather than silent. A human-facing
print command that followed cursors until exhausted would be a different
command, and changing this one to do it would bury the useful page under paging
noise. Left as is, deliberately.

## Fixed in the 2026-10-03 audit: the Guard budget reaper could starve

### A full window of budgets it had already handled

`reap_guard_budgets` bounds its work with `.take(64)`, and the store it reads
from sorted by `sandbox_id`. Those two composed badly. A quarantined sandbox is
not destroyed until an operator releases it, so its budget row is still in
`guard_budgets` indefinitely; both the SQL predicate and the in-memory
`expired()` helper reported those rows as expired; and the reaper then skipped
every one of them. Because sandbox ids are time-ordered, the handled rows were
the oldest and sorted to the front of the window.

So the window filled with work the reaper had no action for. Sixty-four
quarantined-but-unreleased sandboxes were enough to make every subsequent tick
sixty-four no-ops, and a budget that genuinely needed enforcement would never be
reached. This is the control that stops a guarded machine running past its
lifetime or its budget, so it is a liveness property of a security control
rather than a throughput question. The `.take(64)` also read as a bound on the
query while the query itself was unbounded.

Three changes, in `aiec_core::storage` and both stores:

- `list_expired_guard_budgets` now takes a `limit` and the stores apply it —
  `LIMIT` in the query, `truncate` after an explicit sort in memory. The bound
  is on the read, not on a `take` after it.
- Already-quarantined budgets are excluded rather than returned-and-skipped.
  The store's contract is now "budgets that still need quarantine", and the
  reaper's `continue` is kept only as a defensive check.
- The window is `aiec_core::storage::REAPER_GUARD_WINDOW`, declared beside the
  trait method it bounds so the caller and the contract cannot drift apart.

Regressions, in both stores: `handled_guard_budgets_cannot_fill_the_reapers_window`
puts a full window of already-handled budgets in front of one that needs work
and asserts the window holds the latter; mutating the memory filter to
`state.quarantined || ...` reproduces the original bug exactly (`left: 64,
right: 1`), and removing the SQL `NOT COALESCE(...)` predicate fails the
PostgreSQL parity test. `guard_budgets_beyond_the_window_come_back_on_the_next_tick`
drives the same window repeatedly, quarantining each tick's budgets through the
production `mark_guard_quarantined` path, and asserts the backlog drains with
each budget reached exactly once — the window bounds a tick, it does not
discard work. `the_guard_reaper_window_is_pushed_down_to_the_database` `EXPLAIN`s
the production `EXPIRED_GUARD_BUDGETS_SQL` constant and asserts the plan root is
`Limit`; deleting `LIMIT $2` changes the root to `Sort`. The constant is
re-exported for the same reason as `LIST_SNAPSHOTS_SQL`: a test carrying its own
copy of the SQL proves the copy has a `LIMIT`, which is not the question.

Not claimed: an end-to-end reaper test that drives `quarantine()` itself was
attempted and abandoned. `current_fence` requires a scheduler, and
`DevelopmentScheduler::dispatch_target` returns `Unsupported` unconditionally,
so the development path cannot reach quarantine at all; exercising it needs a
scheduler stub, a matching lease and a Guard journal, which is fixture weight
well beyond the property being pinned. The store-level tests above pin the
selection that the reaper's window depends on, which is where the defect was.

## Fixed in the 2026-10-03 audit: the snapshot history was bounded in the store
and not at the route

`list_snapshots` in the HTTP layer passed `query.limit.unwrap_or(50)` straight
through, relying on the store to clamp. The store does clamp, so this was never
an unbounded read — but it left the route's response contract decided by an
implementation detail of the store rather than by the route, which is the
inversion that let `list_runs` and `list_snapshots` disagree about the same
concept. The route now clamps to `MAX_SNAPSHOT_PAGE`, as `list_runs` clamps to
`MAX_RUN_PAGE`.

The regression is
`a_snapshot_history_is_paged_at_the_route_with_a_clamped_bound`: sixty seeded
snapshots, read through the real router. It asserts the default page holds
fifty, walks the cursor to exhaustion and checks that all sixty arrive exactly
once, then asks for `?limit=100000` and requires a `200` carrying all sixty and
a null `next` — a clamp rather than a refusal.

Two mutations were checked against it. Replacing the default with `100_000`
fails on the default-page assertion. Ignoring the parsed cursor — keeping the
parse and discarding the value — makes the walk re-serve the first page and is
caught by the walk's own bound; that bound exists because without it the failure
arrived as a `429` from the rate limiter rather than as an assertion about
duplicates, which is a worse signal about what broke.

The snapshots are seeded through `MetadataStore::put_snapshot` rather than
`POST /v1/sandboxes/{id}/snapshots`. Sixty captures is sixty archives, and the
capture route is rate limited per tenant, so the listing would have been
refused before it was ever asked. What is under test is the listing route, and
it reads the same rows either way.

## Fixed in the 2026-10-04 audit: run histories beyond the page ceiling

`GET /v1/runs` returned at most 200 rows with no continuation parameter. Older
rows were unreachable through that listing. It now accepts the paired
`after_requested_at` + `after_id` cursor, ordered and filtered exclusively by
`(requested_at DESC, id DESC)`. Tenant and state filters remain in the same SQL
statement. Both cursor fields are required; a half cursor is HTTP 400. Default
50 and clamped 1–200 limits, and the bare array response, remain compatible.
The last returned run supplies the next cursor; continue until a short or empty
page. An exactly full final page needs an extra request because there is no
`next` envelope.

Migration `0029_run_list_keyset_index.sql` replaces the existing tenant/time
index with `(tenant_id, requested_at DESC, id DESC)` without modifying published
migrations. An index ending at the timestamp required PostgreSQL to sort tied
groups before applying the limit. The production `LIST_RUNS_SQL` plan regression
now checks the actual `plan[0]["Plan"]` root is `Limit` and recursively rejects
both `Sort` and `Incremental Sort`; a substring check for `"Sort"` alone missed
the latter. Restoring the old index failed with
`["Limit", "Incremental Sort", "Index Scan"]`. The full ordering index passed.

Evidence:

- `a_tenant_can_page_past_the_run_page_ceiling` traverses timestamp ties across
  page boundaries and checks exact descending order, exhaustion, state-filtered
  continuation and tenant isolation.
- PostgreSQL-backed API regressions cover a 210-run history, default 50,
  continuation past 200, a true 200-row clamp, exhaustion, both half cursors and
  another tenant's newer run. Replacing `<` with `<=` failed traversal; making
  the half-cursor guard guess values failed the HTTP 400 regression. Both
  mutations were restored.
- A throwaway live loopback HTTP smoke served the production router over
  PostgreSQL, walked 210 tied-timestamp runs exactly once in 14 requests,
  observed the 200-row clamp and both half-cursor HTTP 400 responses, then
  removed its scratch schema.
- The Rust client regression traverses all 210 rows over a real TCP listener,
  production router and PostgreSQL, comparing exact seeded order and checking
  the state filter. Removing timestamp URL encoding failed continuation;
  restoring it passed. Mock query-string echoes were replaced by this
  consumer-visible regression.
- A second throwaway live smoke used the actual Python SDK to traverse all 210
  rows exactly once in 14 HTTP requests, then exercised CLI exclusive
  continuation and both CLI/Python half-cursor guards. The smoke script and
  temporary fixture entry point were removed after verification.
- Python's retained HTTP behavioral regression uses isolated rows with a
  filtered-out newer run and tied timestamps. It checks exact exclusive pages,
  exhaustion and equivalent `+02:00`/`+00:00` cursor instants through the real
  SDK transport. This fixture models the listing boundary; production SQL is
  exercised separately above. Replacing encoded `%2B` with a raw `+` failed
  continuation with HTTP 400. The mutation was restored.

The memory repository deliberately does not implement run storage; no memory
run-pagination parity is claimed. This is a keyset traversal, not a transaction
snapshot: concurrent writes or state changes can change later filtered pages.

### Probe capacity follow-up

The memory capacity aggregate and `list_nodes` now use the shared
`NODE_HEARTBEAT_TTL_SECONDS` rather than literal 30-second durations.
`the_public_probe_routes_report_the_fleet_without_listing_it` includes both
an unhealthy fresh node and a healthy stale node, and checks complete gauge
lines rather than numeric prefixes. Removing either aggregate filter failed
with 44 available vCPUs instead of 4, and 8,589,934,692 memory bytes instead of
8,589,934,592. Both guards were restored.

## Fixed in the 2026-10-04 audit: packaged worker state placement

The packaged worker unit supplied neither `WorkingDirectory` nor `--state-dir`.
The CLI defaults its identity and disk-pressure directory to relative `.aiec`,
which resolves under `/` for a system service and lies outside the unit's
`ProtectSystem=strict` writable paths. `AIEC_STATE_DIR` configures Firecracker
VM/snapshot storage, not the worker identity directory; the documented export
did not repair this startup path.

The unit now declares `StateDirectory=aiec`, `WorkingDirectory=/var/lib/aiec`
and `--state-dir /var/lib/aiec/worker`. Deployment guidance distinguishes the
two state directories, specifies systemd's environment file and HTTPS/token
configuration, and states the absence of explicit cgroup/resource ceilings.
Admission pressure checks are not `MemoryMax`/`CPUQuota` enforcement. KVM access
still requires actual device permissions; `ReadWritePaths` is not a device ACL.
Proxy timeouts must cover queue wait, execution and settlement; a disconnected
synchronous request does not cancel durable work.

Evidence: after rebuilding the current CLI, starting it from `/` with the
default relative directory failed with permission denied before registration.
An explicit writable scratch state directory reached registration, published
disk pressure from that filesystem and retained the same node-ID SHA-256
across two starts. Registration deliberately targeted a refused local port;
no full worker registration or Firecracker execution is claimed.
`systemd-analyze verify` passed for a temporary worker-unit copy using the
built executable (only executable path changed; comments omitted). Verification
of the packaged paths cannot pass locally because `/usr/local/bin/aiec` and
`/usr/local/bin/aiec-server` are not installed. No installed privileged systemd
service, KVM/device confinement, proxy, or whole-deployment recovery run was
exercised by this follow-up.

The local development database had recorded a stale row for unpublished migration
0029, so that row was deleted and both 0029 and 0030 were applied fresh: the
keyset index was built concurrently and the legacy index was dropped. Fresh
schema migrations are exercised by the run regressions. Published migration
bytes and production migration metadata were not changed.

## Fixed in the 2026-10-04 audit: durable worker identity refuses corruption

The worker previously treated every identity read/parse failure as a first
start. A corrupted `node-id` was silently replaced with a new UUID, and the
worker proceeded to registration under that identity. A direct pre-fix CLI
reproduction observed that replacement and registration attempt.

`durable_node_id` now mints automatically only on `NotFound`; corruption and
other read errors propagate without changing the stored state. Initial
publication writes and syncs an exclusive same-directory temporary file,
publishes it without clobbering a concurrent winner, and adopts that winner.
Control-plane-assigned replacements use atomic rename rather than truncating
the old identity. Unix publication syncs the state directory and its ancestry,
including entries introduced by recursive directory creation. New identity
files use `0600`; newly created directories use `0700`.

Evidence:

- Eight filesystem regressions passed: restart stability, independent state
  directories, empty/malformed/invalid-UTF-8 refusal, unreadable-file refusal,
  deterministic directory-at-identity-path refusal, eight simultaneous first
  starts, assigned-ID persistence/permissions, and complete visibility during
  200 concurrent replacements.
- Restoring the old fallback-mint behavior failed both corruption and
  unreadable-file regressions. The mutation was restored; the expanded
  eight-test suite passed.
- The rebuilt CLI refused empty, malformed, invalid-UTF-8 and directory
  identity states before registration. Each original file or directory marker
  remained unchanged.

The concurrency checks prove atomic visibility and restart behavior, not
simulated power-loss recovery or every filesystem's durability semantics.
An explicit `--node-id` is still an intentional operator override; recovery
guidance says to restore the original identity rather than delete it while
the node owns work.

## Fixed in the 2026-10-04 audit: the worker generation ledger is fail-closed

The durable generation floor was advisory. `GenerationLedger::load` treated any
read or parse failure as a first start, so a truncated or unreadable ledger was
silently replaced by empty state and the worker would learn generations again
from zero, losing the fencing floor exactly when the file was damaged. Record
and forget also mutated the in-memory map before persistence, so a failed write
left memory ahead of durable evidence.

`GenerationLedger::load` now accepts only a genuine `NotFound` as empty state
and returns `InvalidData` for malformed UTF-8 or JSON, propagating other I/O
errors. `WorkerService::with_state_dir` is fallible, and startup refuses a
corrupt, unreadable or directory-shaped ledger without touching it. `record`
rolls the map back when persistence fails and `forget` restores a removed
record. Publication uses an exclusive same-directory temporary file with
`0600`, file and parent-directory sync, atomic rename, and cleanup limited to
the caller's own temporary. `learn_generation` returns
`CoreError::Unavailable` when the floor cannot be published, and authorized
dispatch propagates that as a rejected worker error instead of running the
runtime on memory-only state.

Evidence: `worker::tests` passed 33 tests, including
`worker_service_refuses_a_corrupt_or_unreadable_generation_ledger` and
`worker_service_refuses_generation_ledger_publication_failure_until_persisted`.
Before the repair both failed, the publication case reporting a null error field
where a `runtime_unavailable` rejection was required, which is direct evidence
that dispatch proceeded on unpersisted state. The rebuilt CLI refused empty,
malformed, invalid-UTF-8 and directory ledger states before registration, with
the original bytes or directory marker preserved. These checks cover
visibility, refusal and rollback; they do not simulate power loss or every
filesystem's durability semantics.

## Fixed in the 2026-10-04 audit: migration 0029/0030 and the migration lock

The run-list keyset cutover shipped as two `-- no-transaction` files. SQLx 0.8.6
executes a whole migration file as one simple-query message, so a file
containing more than one statement is wrapped in an implicit transaction and
`CREATE/DROP INDEX CONCURRENTLY` fails. Each file now contains exactly one
statement, and 0029 builds `runs_tenant_created_keyset_idx` on
`(tenant_id, requested_at DESC, id DESC)` before 0030 concurrently drops
`runs_tenant_created_idx`. 0029 deliberately has no `IF NOT EXISTS`: an
interrupted concurrent build can leave an invalid index, and a retry that
silently accepted it would publish an unvalidated index. Published migrations
0001-0028 are unchanged.

SQLx's own migration lock then deadlocked the concurrent DDL. The migrator takes
a blocking `pg_advisory_lock` on a pooled session and holds a transaction
snapshot; `CREATE INDEX CONCURRENTLY` then waits for a snapshot that cannot be
granted, while the lock wait blocks every other migrator. Three of four
concurrent fresh-schema fixtures failed this way. Migrations now run on one
dedicated connection that is closed on drop, keyed by
`0x3d32ad9e * crc32(current_database())` to reproduce SQLx 0.8's derivation, and
the lock is acquired by polling `pg_try_advisory_lock` every 100 ms. This keeps
migration serialization without holding a blocking-lock snapshot across
concurrent DDL. The compatibility constant duplicates SQLx internals and must be
re-audited if SQLx is upgraded.

Evidence: all four concurrent run-route fixtures pass on fresh schemas.
`the_run_page_bound_is_pushed_down_to_the_database` asserts the exact production
statement with a root `Limit` and rejects every Sort variant; restoring the
legacy timestamp-only index produced `["Limit", "Incremental Sort", "Index
Scan"]`. On the local development database the current 0029 and 0030 both apply
successfully, leaving `runs_tenant_created_keyset_idx` with `indisvalid` and
`indisready` true and `runs_tenant_created_idx` absent. Only the local
development database's record for unpublished migration 0029 was deleted to
let the current chain reapply; published migration bytes and production
migration metadata were not changed. No production database was migrated.

## Fixed in the 2026-10-04 audit: the Guard reaper window holds only actable work

`list_expired_guard_budgets` took a bounded window of expired or quarantined
budgets ordered by ID. Released and stopped machines, and rows whose sandbox no
longer has a live lease, permanently occupied that window. A tenant that had
quarantined a machine and then released it could evict every actionable
quarantine ahead of it, and unowned rows were retried forever without ever
being fenced.

`SandboxState::consumes()` names the states that are actually running
(`creating`, `starting`, `running`, `stopping`, `snapshotting`, `restoring`).
Both stores now return a row only when its sandbox is in one of those states and
holds an active, unexpired lease for the same tenant and sandbox. Spent budgets
are still retained, so restarting a released machine makes it immediately
eligible again rather than refilling it. The deterministic ordering and the
pushed-down `LIMIT` are unchanged, and the consumer keeps its defensive
quarantine guard.

Evidence: the memory and PostgreSQL suites agree, 15 tests including
`a_released_budget_is_not_reaped_until_the_sandbox_runs_again`,
`an_unowned_budget_does_not_consume_the_reapers_window` and
`only_actable_guard_budgets_reach_the_reaper_window`. Three mutations each
failed with the released or unowned sandbox appearing in the window: adding
`'paused'` to the SQL state list, dropping the lease expiry predicate, and
relaxing the memory store's state filter. All were restored.

The quarantine event previously recorded `"watchdog quarantine"` as its reason
on every path, including durable-budget and lifetime reaping. An incident reader
was sent to a subsystem that had not triggered it. The event now names the rule
that triggered the cut. The literal had no other consumer in the API, its tests
or the Python SDK.

## Hardened in the 2026-10-04 audit: acceptance launchers cannot touch a deployment

`scripts/acceptance-db.sh`, `scripts/firecracker-coding-dogfood.sh` and
`scripts/worker-recovery-validation.sh` run next to a live deployment and
previously inherited patterns suited to a dedicated machine: a fixed output
directory that was cleared on entry, process sweeps by command-line substring,
a database chosen from `DATABASE_URL`, and a Firecracker path that assumed its
own TAP devices, nftables tables and masquerade rules were harmless in the host
network namespace.

A run now owns exactly three things and refuses everything else: a per-run
identifier minted before any process starts, a scratch directory that must not
already exist, and either a private cluster it builds and stops or a database
the caller confirms it owns alone. `DATABASE_URL` is no longer consulted, and
the deployment's own `aiec` database is refused by name. A run-tagged database
may be created and dropped only where the operator names the server and
consents, and a name carrying a quote, a semicolon or more than 63 characters is
refused before it reaches `CREATE` or `DROP` DDL. Process sweeps require the
exact inherited identifier in `/proc/<pid>/environ` and exclude the sweeping
shell's own ancestry; without an identifier the scan refuses rather than
degrading to a command-line match. Firecracker runs refuse to start unless the
caller supplies the network namespace to have left behind, with no host-network
fallback. TAP censuses are now reported as this run's namespace rather than
claimed as a host-wide census.

Evidence, exercised directly against the sourced helpers on this host:
a fresh scratch path is claimed; an existing directory, a symlink to another
run's directory with its target preserved, the checkout root, an empty path and
`/` are all refused; a process started by this run is found while a process
carrying an identical command line with a stripped environment is not; the scan
refuses when no identifier is present; the host network namespace is refused; a
percent-encodable socket URL yields the database name rather than the socket
path's last component; a name carrying `"` and `;` is refused; and `aiec` is
refused as an isolated database. `bash -n` passes on all three scripts.

No launcher was executed end to end: each requires a staged deployment, an
isolated database and, for Firecracker, KVM. The recovery scenario's SIGKILL
orphan and graceful-reclaim assertions therefore remain unexercised.

## Fixed in the 2026-10-04 audit: migration lock acquisition is bounded

The non-blocking migration lock polled `pg_try_advisory_lock` with no deadline.
That trades SQLx's blocking lock, which deadlocks startup against itself, for a
poller that never returns: a session holding the lock — a stuck old binary, a
`sqlx-cli`, or a peer wedged in its own concurrent index build — turned every
subsequent startup into an indefinite hang with no log line and no error. That
is the same availability failure with strictly worse diagnostics.

Acquisition is now bounded at 60 seconds and the timeout names the database it
was waiting on. The bound is on waiting for a *peer*, not on this migration's
own runtime, so the constant has to exceed the slowest migration a peer might
be running. Nothing bounds it from above: no unit in `deploy/` sets a
`TimeoutStartSec`, so a caller waiting here is not racing an external kill.
Every statement in `migrations/` is DDL — 28 `CREATE TABLE`, 71 `ALTER TABLE`,
one `CREATE INDEX CONCURRENTLY` — so 60s is ample, and it is the value to
revisit if a data-heavy migration is added.

The timeout is reported as `StoreError::Transient`, which maps to
`CoreError::Transient`. It is not a migration failure: no broken database is
involved, a peer is mid-migration and this process lost the race for a bounded
window. `StoreError::Migration` maps to `CoreError::Backend`, which names the
wrong condition.

This changes no current behaviour, and the ledger should say so rather than
imply otherwise. Both production call sites — `crates/aiec-api/src/main.rs:135`
and `crates/aiec-cli/src/main.rs:1773` — are startup paths that propagate with
`?`, so the class is never read. It is a correctness fix to the reported error,
not a behaviour fix today. It would matter wherever the class is observed:
`crates/aiec-api/src/lib.rs:537` answers `CoreError::Transient` with 409
`transient` where `CoreError::Backend` becomes 500, and
`is_transient_destroy_error` in `crates/aiec-api/src/runs.rs` retries a
`Transient` but treats a `Backend` as permanent. Note that the other retry
policy in the same file, `is_retryable`, does accept `Backend`, so "permanent"
is specific to the destroy path.

The deadline is exercised directly. `the_migration_lock_gives_up_on_a_peer_that_keeps_it`
opens a second session, takes the same advisory lock on the real key and leaves
it held, then calls the migrator with an injected 300 ms budget: the call fails,
the error is `StoreError::Transient`, and the message carries both the phrase
`waiting for the migration lock` and the database name. The test then unlocks and
calls the migrator again, so the timeout is also shown to leave the pool in a
state a retry recovers from — the bound is a wait, not a wedge. The 60-second
production value is never waited out; only the branch is.

The lock key itself is pinned by `the_migration_lock_key_matches_sqlx`. Nothing
in the timeout test could catch a change to it, because the test takes the lock
through the same helper the migrator uses — a mutated key still contends with
itself and the test passes. That is verified: changing the multiplier to
`0x3d32ad9f` left the contention test green and failed the pinned-key test. The
pinned value is `0x3d32ad9e * 0x29e910d5`, where `0x29e910d5` is
CRC-32/ISO-HDLC of `"aiec"`.

The multiplier is a bare literal in SQLx's own source, not a named constant —
`sqlx-postgres-0.8.6/src/migrate.rs::generate_lock_id` reads
`0x3d32ad9e * CRC_32_ISO_HDLC(database_name)` under the comment "chosen by fair
dice roll". It was checked against the vendored crate rather than recalled, so
there is no `MIGRATION_LOCK_ID` symbol to grep for; `MIGRATION_LOCK_TIMEOUT` is
the only lock-related constant in this tree.

The concurrency fixtures continue to prove that four processes migrating at once
serialize safely; neither test replaces them.

The fixture polls for the lock instead of taking it once. The first version
called `pg_try_advisory_lock` a single time and passed in isolation, then failed
in the full suite with `the fixture must hold the lock it is testing contention
for` — the concurrency fixtures migrate against the same database at the same
time and hold this exact key for a moment. The fix waits for the lock to be
free, which is what the test actually needs; the failure was in the fixture, not
in the behavior under test.

## Fixed in the 2026-10-04 audit: the CLI's Guard bodies are tested as bodies

`aiec guard release` sent `operator` to a route that requires
`operator_label`, so the command always answered 400. The regression added for
it asserted against a body hardcoded in the test, which proved the server
accepts a body the CLI does not send and could not catch the defect it was
written for. The same held for the proposal and quarantine bodies, whose field
names had no client-side coverage at all.

The three request bodies are now built by named functions that are the only
construction path, and two tests run their output through the server's real
deserializers — `ReleaseBody`, `ReviewProposalBody` and
`QuarantineRequest`, which are re-exported from `aiec-api` for that purpose — and
assert the exact key sets. Renaming a field on either side now fails here rather
than in production.

While verifying this I checked a claim that the CLI's quarantine body always
failed to deserialize because `RuleTrigger::first_event_sequence` is an
`Option` without `#[serde(default)]`. It does not: serde treats a missing
`Option` field as `None`, confirmed by deserializing that exact struct shape.
The test now proves it in-tree instead of leaving it as an assumption.

Note that `serde_json::Value` objects are key-sorted without the
`preserve_order` feature, so the key-set assertions sort rather than depend on
serializer order: the wire contract is the set of names, not their sequence.

Mutation evidence: reverting the release builder to the `operator` spelling that
shipped fails both tests, the deserialization one with
`unknown field 'operator', expected 'operator_label' or 'note'` — the exact
error an operator received — and the key-set one with `["operator"]` against
`["operator_label"]`. Restored.

## Clarified in the 2026-10-04 audit: a lapsed lease was never a reaper case

Narrowing the window to sandboxes holding an active, unexpired lease raises the
question of whether it removes enforcement for a machine whose lease lapsed
while the workload kept running — the runaway-spend case Guard exists for. It
does not, because that enforcement was never in this path. The reaper resolves
the fence before doing anything, `current_fence` calls `dispatch_target`, and
that requires `status = 'active' AND expires_at > now()`; a sandbox whose lease
lapsed yields `NotFound` and the loop logs "no current owner; leaving it to
lease reconciliation" and continues without quarantining. The new SQL predicate
matches that decision exactly.

So a lapsed lease was never a budget-enforcement case in the reaper. It spent a
slot in the bounded window, was fetched, failed the fence check, and was
discarded — a no-op that could evict every actionable quarantine ahead of it.
Reclaiming a machine whose lease lapsed is the lease reconciler's job, which is
why that log line names it.

## Fixed in the 2026-10-04 audit: a paused machine could still spend budget

Restricting the reaper window to consuming sandboxes is only half a rule. The
other half is the debit path, and it did not agree with it.

`crates/aiec-storage/src/guard.rs::reserve` enumerated the states it would
refuse by hand:

```rust
if matches!(
    sandbox.state,
    SandboxState::Destroying
        | SandboxState::Destroyed
        | SandboxState::Failed
        | SandboxState::Stopped
        | SandboxState::Stopping
) {
    return Err(StoreError::Conflict("Guard sandbox is not active".into()));
}
```

`Paused` is not in that list. `SandboxState::consumes()` — the predicate the
reaper's window is filtered by — does not include it either, so the two were
already divergent before the window was narrowed. An operator who paused a
machine stopped the reaper from watching it *and* left the worker free to debit
against it. The spent budget row survives the pause, so the next reaper tick
would pick the sandbox up again; but the debit has already been admitted, and
the reserve route commits the debit before the gateway forwards the traffic it
was taken for.

The fix is not a second enumeration but the same predicate the reaper uses:

```rust
if !sandbox.state.consumes() {
    return Err(StoreError::Conflict("Guard sandbox is not active".into()));
}
```

`reserve` is the single shared helper both stores go through — `MemoryRepository`
and `PostgresRepository::reserve_guard_budget` each call it — so one predicate
now governs the memory path, the PostgreSQL path and the reaper window, and a
state added to `consumes` later cannot silently be missed by one of them.

`Stopping` is deliberately still consuming, which is a behaviour change in the
other direction: `reserve` previously refused a stopping machine and now
permits it. A machine being stopped is still running until `stopped` is
committed and keeps spending until then, and the reaper window has always
included `stopping` — so the two now agree instead of the debit path being
stricter than the reaper it answers to. `Paused` was the state actually missing
from the debit path; `stopping` was missing from nothing.

The route in `aiec-api` keeps only the ownership check it owns and deliberately
does not repeat either the state rule or the latch. Two copies of one predicate
is two things that can drift from each other, which is how this defect existed.

Regression `only_a_consuming_machine_can_debit_its_durable_budget` drives every
case through `MemoryRepository::reserve_guard_budget` — the path the worker's
reserve request actually takes, including the fence — rather than calling the
shared helper directly. It admits a real debit on a running machine, asserts
each non-consuming state is refused, asserts the counters are untouched after
each refusal, and then latches the stored budget against a `running` sandbox.

Mutation evidence, both arms:

- restoring the previous hand-written list fails with `Paused accepted a debit
  against a budget nothing enforces`;
- removing the `state.quarantined` arm fails with `a latched budget accepted a
  debit from a running machine`.

Both mutations were reverted and the test passes again. The latch arm was
dropped by the first cut of this fix while replacing the enumerated list, which
is why it has its own case: the sandbox-state loop would still have passed
without it, because `Quarantined` is refused by `consumes()` either way. The
latch cannot be folded into `consumes()` — it stays set while the sandbox is
`running`, and only an authorized release clears it, so it is a property of the
budget row rather than of the machine.

## Fixed in the 2026-10-04 audit: an ancestor's permissions could stop a worker starting

`sync_node_id_directory` opened and `fsync`ed every ancestor of the state
directory, up to `/`, and propagated any failure. Ancestors are synced for a
real reason — `create_dir_all` may have just created the state directory, and a
new directory's own entry lives in its parent — but they are pre-existing system
directories that belong to someone else, and their failure mode does not belong
to this write.

A directory can be entirely usable for its purpose while refusing to be opened
for reading. Mode `0300` is write-and-traverse with no read: files can be created
inside it, and the identity file can be written and read back through a path
traversal, but `File::open` on the directory itself fails with `EACCES`. Any
worker whose state directory sat below such a directory refused to start at all,
reporting `persist worker node identity: Permission denied (os error 13)` — a
failure caused by a directory the worker never needed to touch. `fsync` on a
directory is also not universally supported and can report `EINVAL`, with the
same consequence.

The directory that actually received the entry is still synced strictly: it is
the one whose durability matters and the one this code creates. Ancestors are now
synced on a best-effort basis with a warning naming the directory and the error,
so a lost parent entry is diagnosable instead of silently skipped.

Regression `an_unreadable_ancestor_does_not_block_identity_publication` builds
the fixture, asserts up front that the ancestor really cannot be opened, then
mints and re-reads an identity underneath it.

Mutation evidence: restoring the unconditional `?` on the ancestor loop fails
with `Permission denied (os error 13)`, reproduced through the real publication
path. Restored.

### Audited and found clean: reachable panics in shipping code

Every `.unwrap()`, `.expect()`, `panic!`, `unreachable!` and literal index in
`crates/*/src/**` was enumerated, with each file truncated at its first
`#[cfg(test)]` or `mod tests` so test code was excluded, and integration-test
directories excluded separately. Each surviving production site was read in
context rather than pattern-matched. The result is no reachable panic.

- `aiec-mcp/src/eval.rs:1282` indexes `command[0]`; `validate_command` rejects an
  empty command first, and `explicit_shell_script` — which also indexes `[0]` —
  has exactly one caller, inside that function.
- `aiec-guard/src/policy.rs:216` indexes `bytes[0]` and `bytes[len-1]`; an empty
  label is rejected on the line above.
- `aiec-guard/src/dns.rs:103` indexes `bytes[0..1]` under `len() >= 2`;
  `dns.rs:229`'s `port.expect` is reached only past a `port.is_none()` refusal.
- `aiec-guard/src/watcher.rs:1094` and `1340` index `batch[0]`; `review_batch`
  rejects an empty batch before the first, and the `1340` loop body cannot run
  on an empty slice.
- `aiec-guard/src/canaries.rs:720` indexes `request.rules[0]`; the vector is a
  literal `vec![RuleTrigger { .. }]` two lines earlier.
- `aiec-guard/src/gateway.rs:1666`'s `scheme_str().expect` is preceded by a
  `matches!(.., Some("http" | "https"))` check; `gateway.rs:1648`'s
  `HeaderName::from_bytes` is fed a value already constrained to
  `ALLOWED_CREDENTIAL_HEADERS` at `policy.rs:831`; `gateway.rs:1339` builds a
  response from a constant status and header.
- `aiec-runtime/src/e2b.rs:1279-1284` indexes a 5-byte frame header under
  `buffer.len() < ENVELOPE_HEADER` returning early.
- The remaining `expect`s are HMAC key construction (`new_from_slice` accepts any
  length), a constant-path `parent()`, and MCP ownership locks whose critical
  sections are a `Vec::push` and an `iter().map().collect()`, so no user code
  runs under the lock and poisoning is not reachable.

This is a negative result over the sites enumerated, not a proof that no panic
is reachable. It says only that every `unwrap`/`expect`/index in non-test code
was located and had its guard read.

### Correction: "60s is ample" was not supported by what was checked

The `MIGRATION_LOCK_TIMEOUT` rationale originally argued the bound was sufficient
from the *kinds* of statement in `migrations/`. That is the same unverified
inference as an earlier "verified against the real database" claim, corrected
once already in this ledger.

Measured instead: `0029_run_list_keyset_index.sql` is the only
`CREATE INDEX CONCURRENTLY` in the tree and the only statement that holds the
lock for a non-trivial time. Building it against the real database on a
3446-row copy of `runs` took 5ms, three consecutive times. The rationale now
says exactly that, and states its limit rather than generalising from it:
three orders of magnitude of headroom for this dataset, and no evidence at all
about a large one, since `CREATE INDEX CONCURRENTLY` scans twice and is
`O(n log n)`. The bound is documented as a tunable whose correct response to a
larger table is to raise it, with the caller naming the database in the
`StoreError::Transient` it raises.

## Audited and found clean in the 2026-10-04 round 3 sweep

Three whole-tree sweeps, all over non-test code (each file truncated at its test
module, integration-test directories excluded). All three came back with no
defect. They are recorded because coverage that was not performed is
indistinguishable from coverage that found nothing, and the next round should
not repeat them.

**Dynamic SQL.** Every query built with `format!`, `push_str` or an inline
interpolation. Only three sites build SQL text at all, and all three are test
fixtures: `CREATE SCHEMA`/`DROP SCHEMA` in `run_paging_tests.rs:43,204` and
`provision_ownership_tests.rs:147,332`, all named from `new_id().simple()` —
an internally generated hex string, never caller input. Production code
interpolates no SQL text at all; every value is a bind parameter. The one
production command-line interpolation, `nft delete table inet aiec_{suffix}` at
`aiec-network-linux/src/lib.rs:293`, takes `suffix` from the first 12 characters
of a sandbox UUID and passes it as a single argv element, so neither the
characters nor a second argument can be injected.

**Integer overflow and underflow.** 24 sites where a length, offset or size
participates in arithmetic. The two that looked live were both already guarded:
`aiec-runtime/src/e2b.rs:883` computes `request.length * 4 + 4096`, but
`request.validate()?` runs at line 818 of the same function and rejects anything
above `FILE_CHUNK_BYTES` (64 KiB), so the product cannot wrap; and
`object_store.rs:73` subtracts only inside `while bytes.len() < length`.
`crates/aiec-core/src/protocol.rs:284` allocates `vec![0; length]` from a
wire-supplied u32, refused first by `length > MAX_FRAME`.

**Allocation from untrusted sizes.** 78 allocation sites. The only one sized by
something outside the process is
`object_store.rs:collect_download`'s `Vec::with_capacity(size_bytes)`, where
`size_bytes` is object-store metadata — worth checking, because a remote
`Content-Length` driving an allocation is the classic no-bytes-sent OOM. It is
not reachable as one: `size_bytes` is never taken from a response header, it is
produced by `hash_reader(&mut file, Some(&mut spool), max_bytes)`, which measures
the bytes as they are received and refuses past `max_bytes`, and the object is
spooled before the vector is built. Both call sites pass
`LEGACY_DOWNLOAD_LIMIT`. The capacity is therefore proportional to bytes already
read and bounded, not to a claim.
