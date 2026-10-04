# REST API

Base path `/v1`. Except health/metrics, send `Authorization: Bearer af_live_...`. JSON uses `snake_case`; errors are `{"error":{"code":"...","message":"...","request_id":"..."}}`. Every response includes `x-operation-id`; clients may supply a UUID in that header, otherwise the server generates one. This correlation header is not yet propagated into structured logs.

## Sandboxes

- `POST /v1/sandboxes` — create. Body: `image`, `cpu`, `memory_mb`, `disk_mb`, `timeout_seconds`, `network.enabled`.
  `environment.workspace` accepts `{"type":"empty"}` or `{"type":"git","repo":"https://...","reference":"main","shallow":true}`. Repository credentials in URLs are rejected. `environment.toolkits` is a bounded list of named `setup_commands` argv arrays.
  `environment.guard` selects an out-of-guest policy, with the same shape as `resources.guard` below. It replaces `network.enabled` rather than accompanying it. A Firecracker request with no `environment.guard` gets the default no-network policy; a request that asks for `network.enabled` without selecting a policy is refused unless the operator has set `AIEC_ALLOW_LEGACY_NETWORK=1`. Model credentials are configured on the worker and never travel in this document; the guest receives `placeholder://<binding>` instead.
- `GET /v1/sandboxes` — one bounded page of the tenant's sandbox history, newest first: `limit` (default 50, store-clamped to 200) and the optional `after_created_at` + `after_id` cursor, which must be given together. It returns `{sandboxes, next}`, ordered `created_at DESC, id DESC`; `next` is the cursor for the following page and is `null` exactly on the last one, so a page says whether it truncated rather than looking complete. A destroyed sandbox stays in the history — teardown is a state transition, not a delete — so this is the tenant's whole history and it grows with tenure. Exposed as `client.list_all_sandboxes(...)` and `client.list_sandboxes_after(...)` in the Rust client, and as `sandboxes.list_all()` and `sandboxes.list_after(...)` in the Python SDK.
- `GET /v1/sandboxes/{id}` — tenant-scoped detail.
- `DELETE /v1/sandboxes/{id}` — destroy.
- `POST /v1/sandboxes/{id}/start|pause|stop|resume` — explicit lifecycle operations. `pause` is supported by Firecracker PATCH semantics; development Bubblewrap returns `501`.
  Rust SDK: `AIecClient::pause(id)` (crate `aiec-client`) / `resume(id)`; Python SDK: `Sandbox.pause()` / `Sandbox.resume()`.
- `POST /v1/sandboxes/{id}/git/diff` — return bounded `git diff --binary` for a running Git workspace.
- `POST /v1/sandboxes/{id}/exec` — body `command` argv, `working_directory`, `environment`, `timeout_seconds`, `stdin`. Returns exit code, bounded stdout/stderr, duration, timeout flag.
- `PUT /v1/sandboxes/{id}/files` — body `path`, `content_base64`, optional `mode`.
- `PUT|DELETE /v1/sandboxes/{id}/secrets/{name}` and `GET /v1/sandboxes/{id}/secrets` manage one-hour, per-sandbox process environment secrets. Values are never returned by metadata endpoints.
- `GET /v1/sandboxes/{id}/files?path=/workspace` — list.
- `GET /v1/sandboxes/{id}/files/content?path=/workspace/x` — download.
- `POST /v1/sandboxes/{id}/files/mkdir` — create directory.
- `DELETE /v1/sandboxes/{id}/files` with JSON `{path}` — delete file.
- `POST /v1/sandboxes/{id}/snapshots`, `GET /v1/sandboxes/{id}/snapshots`.
- `POST /v1/snapshots/{id}/restore` — creates a new sandbox and returns it.
- `DELETE /v1/snapshots/{id}`.
- `POST|GET|DELETE /v1/sandboxes/{id}/artifacts/{name}` provides tenant-scoped upload/download/delete with a 64 MiB decoded-size limit. `GET /v1/sandboxes/{id}/artifacts` lists sorted object metadata for the development filesystem backend. The production S3 backend returns a typed `501` for listing until ListObjectsV2 support is implemented and verified.

  The listing is bounded by `MAX_LISTED_OBJECTS` (1000) objects under the sandbox's prefix, and is **refused with `413 limit_exceeded`** past that rather than truncated — a shorter list would be indistinguishable from a complete one. The bound is on the walk rather than on uploads: `PUT` of distinct names is uncapped, so a sandbox can hold more than one listing will describe. On the filesystem backend the listing also computes each object's size and SHA-256 by reading it, so its cost is the bytes of the prefix, not just its directory entries; the bound exists to keep that proportional to the platform rather than to tenant storage.

- `GET /v1/usage` — metric totals for current tenant.

The Python SDK exposes the same size-guarded partial path as `Sandbox.upload_artifact`, `download_artifact`, and `delete_artifact`; listing remains unsupported, and the production S3 path remains unverified.

## Runs

- `POST /v1/runs` — create and drive a run to a terminal state, returning the settled run. Body: `workload` (`image`, `command`, `setup`, `validations`, `artifacts`, `environment`, `secrets`, `timeout_seconds`, `git_evidence`, `repo`), `resources`, `requirements`, `retention`, `max_attempts`, `idempotency_key`, `requested_runtime`, `retained_seconds`. The handler is synchronous on purpose: it places a machine, runs the work, collects artifacts and reclaims the machine before answering, so the response is the record of what happened.

  High-risk tool calls are approved in two phases by different principals.
`POST /v1/sandboxes/{id}/guard/approval` (scope `SandboxesWrite`) asks about
one call and always answers immediately with `approved: false` when nothing has
decided it, recording the request as `pending`. `GET` and `POST
/v1/sandboxes/{id}/guard/tool-approvals` (scope `GuardApprove`) are the
operator's queue and the decision itself. The ask carries `digest`, a SHA-256
over the canonical JSON of the call's arguments; it is required, because an
approval that is not bound to one call is a capability rather than an approval.
A grant is spendable once, only for the digest it was made for, and only by the
key that asked. Self-approval is refused however much authority the key holds.
See [GUARD.md](GUARD.md#approving-a-high-risk-call).

Both Guard history listings are paged the same way, for the same reason. A
proposal row is never reclaimed, and a decided tool approval is deliberately
retained, so a sandbox left running grows both without bound. `GET
/v1/sandboxes/{id}/guard/proposals` (scope `GuardRead`) and `GET
/v1/sandboxes/{id}/guard/tool-approvals` (scope `GuardApprove`) take the same
`limit` (default 50, store-clamped to 200) and the same paired
`after_created_at` + `after_id` cursor, and return `{proposals, next}` and
`{approvals, next}` respectively, ordered `created_at DESC, id DESC`, with
`next` non-null exactly when another page follows. The id half of the cursor is
not decoration: `created_at` is not unique, and a keyset that cannot break a
tie either re-reads or skips the rows sharing a timestamp.

`resources.guard` selects an out-of-guest policy: either
  `{"policy_template": "no-network" | "model-only" | "model-plus-allowlist" | "read-only-api"}`
  with optional `model_endpoint` and `allowlist` inputs, or a full
  `{"policy": {...}}` document. It replaces `resources.network` rather than
  accompanying it — two descriptions of one egress would be two paths to the
  internet — and it is enforced by the worker's Guard gateway, not by the
  guest. A guarded run is placed on a microVM runtime; there is no weaker
  fallback. Model credentials are configured on the worker and never travel in
  this document; the guest receives a `placeholder://<binding>` instead. See
  `GUARD_POLICY.md`.

- `GET /v1/runs`, `GET /v1/runs/{id}` — tenant-scoped list (filterable by `state`, paginated by `limit`) and detail.
- `GET /v1/runs/{id}/events`, `GET /v1/runs/{id}/attempts` — the run's history and its attempts.
- `POST /v1/runs/{id}/cancel` — stop a run and reclaim its machine. Cancelling a finished run returns it unchanged.
- `POST /v1/eval/batch`, `POST /v1/eval/repetitions`, `POST /v1/eval/matrix` — bounded parallel evaluation. `batch` takes `{requests, options}` and returns `Vec<Run>`; `repetitions` takes `{request, repetitions, options}` and returns `Vec<Run>`; `matrix` takes `{cells: [{axis, request}], options}` and returns `{matrix_id, requested_at, max_parallel, results: [{axis, run?, error?}]}`. Every submitted cell appears in `results`: a cell that was refused before it ran comes back with its `axis` and an `error` and no `run`, beside the cells that did run, so a partial failure never hides the runs that were executed and billed — and never costs the caller the `matrix_id` that is the only way to find them. A matrix must also be keyed throughout or not at all; a partly-keyed matrix is `400` before anything is admitted, because keyed cells keep their keys across a retry and unkeyed cells do not, and the clash between those two is only visible after the batch has been spent. `repetitions` must be at least 1 and `max_parallel` is bounded; every evaluation route needs the sandbox write scope. The Python SDK exposes these as `af.evals.batch(...)`, `.repetitions(...)` and `.matrix(...)`, and expands a suite document into the `matrix` request with `af.evals.run_suite(...)` and `.compare(...)`; `af.evals.compare` reports both revisions' outcomes and picks no winner.
  `GET /v1/eval/matrix/{matrix_id}` reads one bounded page back, for a caller that lost the submission response: `limit` (default 50, store-clamped) and the optional `after_requested_at` + `after_id` cursor, which must be given together. It returns `{matrix_id, cells: [{run, index, axis}], successes, by_axis, next}`. `successes` and `by_axis` describe **that page only**, and `next` is the cursor for the following one; `cells` keep the labels the cell was submitted under, which are stored on the run at admission. `GET` needs the sandbox read scope and is tenant-scoped, so another tenant's matrix is a `404`, not an empty page. Exposed as `af.evals.matrix_page(...)` and `client.eval_matrix_page(...)`.
  A run's stored evidence is bounded: `setup` and `validations` accept at most 32 commands each, and the previews kept in the run row are clipped (task 128 KiB, setup and validations 32 KiB each, git evidence 64 KiB), keeping the head and the tail. `results.task.output_preview_truncated` and `results.git_evidence_truncated` say so explicitly and are distinct from `truncated` and from `ok`: a command that ran to completion and exited zero is a pass whether or not its output fitted. Full output is collected as a Run artifact when the workload asks for it. Captured stdout, stderr and git evidence are scrubbed of any resolved `workload.secrets` values before being stored.
  `results.phase_ms` decomposes a run. `placement` is the whole of getting a
  machine, and `placement.scheduler`, `placement.allocation`, `placement.boot`
  and `placement.workspace` are its parts: reservation, runtime
  `create`, runtime `start` (for Firecracker, rootfs materialization plus VM
  boot), and workspace preparation (clone or cache import) respectively. A
  dotted name is a subset of its top-level phase, so a tool that adds up
  unaccounted client wait must exclude them rather than count the same interval
  twice. `attempts` is the only entry in that map that is a count rather than a
  duration.


`GET /v1/sandboxes/{id}/snapshots` (scope `SnapshotsRead`) is paged the same way
and returns `{snapshots, next}`. Snapshots are retained until one is deleted
and nothing prunes them automatically, so a sandbox that is snapshotted
repeatedly grows that list for as long as it lives. It was the third listing
with the same missing index tie-breaker, after the sandbox list and the two
Guard histories, which is what suggests the shape is now shared deliberately
rather than reproduced.

### Run queue

Every `POST /v1/runs` (and matrix/evaluation submission) is admitted to the durable
run queue first and the handler still answers with the settled run, so the response
is unchanged for existing clients. Admission and idempotency are resolved in one
transaction; a full queue is `429 quota exceeded`, and a reused
`idempotency_key` returns the original run without a second execution. The HTTP
connection is not part of run ownership: dropping it stops the waiting, not the
work, and execution continues against the durable run. Limits default to 4
concurrent runs cluster-wide (`AIEC_RUN_QUEUE_MAX_ACTIVE`), 1024 pending runs
cluster-wide (`AIEC_RUN_QUEUE_GLOBAL_PENDING`), 128 per tenant
(`AIEC_RUN_QUEUE_TENANT_PENDING`), a 300 s queue deadline
(`AIEC_RUN_QUEUE_TIMEOUT_SECONDS`) and a 30 s renewable executor lease
(`AIEC_RUN_QUEUE_LEASE_SECONDS`). A run that cannot start before its queue
deadline settles `failed` with `Run queue deadline exceeded`, and any run whose
executor loses ownership is failed and reclaimed by recovery, never restarted.

A handler waits for the run to settle **and** for its queue row to reach
`finished`, so the response carries the persisted cleanup evidence. That second
wait is bounded at 30 s: a teardown that keeps failing repopulates
`results.cleanup_failed`, which is exactly what keeps the queue row out of
`finished`, so an unbounded wait would never return. When the bound expires the
run is returned as it stands — outcome known, `results.cleanup_failed` saying
that teardown is still outstanding — rather than holding the connection open
with no run, no id and no error.

### Run secrets

`workload.secrets` is a list of secret **names**, not values. Names are stored
with the run; values are resolved from the operator-configured tenant secret
store (`AIEC_RUN_SECRETS_DIR`) immediately before each command is executed and
are injected through the command's `environment`. They are never returned,
persisted, logged or written to a snapshot — see the deployment format in
[SECURITY.md](../SECURITY.md#secrets).

- A run with no `secrets` needs no store and works unchanged.
- A requested name the tenant has no value for fails the run before a machine
  is placed, naming the reference (`404`/`not_found`). No placeholder and no
  empty value is ever substituted.
- A name that is not a valid environment variable (uppercase ASCII, digits and
  underscores, up to 64 characters) is rejected the same way.
- A name present in both `workload.environment` and `workload.secrets` is
  rejected, so a literal in the run document cannot silently shadow a secret.
- Names appear in `workload.secrets` on `GET /v1/runs/{id}`. **There is no
  endpoint that returns a run secret's value.**
- Captured command output is scrubbed of resolved values before it is stored,
  bounded to 8 KiB per stream; error text is scrubbed while keeping its error
  type.

### Run artifacts

`workload.artifacts` names paths inside the sandbox — `/workspace/report.txt` — collected once the task is done. They are collected into object storage under a server-generated key derived from a digest of the name, so a caller's path never becomes a key and a re-collection overwrites rather than duplicates.

Collection is streamed in binary 64 KiB chunks from the runtime (sandbox → worker → control plane → object store), and the object store writes them incrementally, so no stage holds the whole file or a base64 copy of it in memory. Every chunk read is authorized against the sandbox's active lease generation, and each read revalidates the file's identity (device/inode/size/mtime), so an artifact is never a concatenation of two file generations. A file over the 16 MiB per-file limit is refused and fails the run.

- `GET /v1/runs/{id}/artifacts` — every collected artifact, each with its recorded `name` (the path as it appeared in the sandbox), `object_key`, `size_bytes`, `checksum_sha256`, `content_type` and a `download_url`.
- `GET /v1/runs/{id}/artifacts/{name}` — the bytes, streamed. The object is read under the checksum recorded at collection and the whole body is verified before the response starts, so a corrupted or overwritten object is refused rather than served; a caller never receives bytes whose digest does not match what was recorded.

The stored object is the file's own bytes: `size_bytes` and `checksum_sha256` describe the file. The public sandbox artifact API (`/v1/sandboxes/{id}/artifacts/{name}`) still answers in the same JSON shape with `content_base64`, but it too encodes from the bounded verified stream. `download_url` percent-encodes the name, so an absolute or nested name round-trips exactly; a hand-written path still has to name an artifact this run collected, and cross-tenant reads are `404`.

Collection failures fail the run rather than returning a shorter list than was asked for. A requested artifact that cannot be read, exceeds the limit, changes while it is being read, or cannot be stored sets `failure_reason` naming the artifact, and the run settles `failed`. Artifacts collected before the failure are still recorded and downloadable, because a failed run is the one whose evidence somebody opens.

Operational endpoints: `/health`, `/ready`, `/metrics`.

### API keys

Three routes, and only three: `GET /v1/keys` lists the caller's own tenant's
keys; `POST /v1/keys` mints one; `DELETE /v1/keys/{id}` revokes one. There is no
rotate route and there is no `POST /v1/keys/{id}/revoke` — revocation is the
`DELETE` verb on the key itself.

Key management is the one place where **omitting a field grants authority**, so
it is worth being explicit. `POST /v1/keys` with no `scopes` is a request for
the default set — `sandboxes:read`, `sandboxes:write`, `snapshots:read`,
`snapshots:write` — and that is a grant, not a shortcut. Every scope that would
be granted, defaulted or explicit, must be held by the calling credential, so a
key carrying only `sandboxes:read` is refused both an omitted `scopes` field and
an explicit `["sandboxes:write"]`. The rule is the same on both paths on purpose:
the default is a way of asking for four scopes, not a way around needing them.

Revocation follows the same principle, because destroying a credential is a use
of authority. To revoke a key, the caller must hold **every** scope the target
holds. A `sandboxes:read` key cannot revoke a key that can write, and neither
can it revoke a tenant admin key. A key from another tenant, or one that does
not exist, is `404` — a key's existence is not disclosed across a tenant
boundary. Revoking a key revokes it immediately; there is no grace period.

## Status codes

`400` invalid JSON/path/argv/image; `401` missing/invalid/expired/revoked key; `403` missing scope or cross-tenant access (cross-tenant resources are not disclosed); `404` tenant-scoped missing resource; `409` invalid state/race; `413` upload/resource limit too large; `422` semantic validation; `429` PostgreSQL tenant quota exceeded; `500` internal; `503` runtime/dependency unavailable.
