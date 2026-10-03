# AFTER — final build

Everything below was measured on the deployment at the end of this round:
`aiec-server` sha256 `ab17097283cb838d…`, `aiec` sha256 `bb4e1e60e060ad82…`,
guest rootfs sha256 `195983e85e3ed9645…` with `guest_protocol_version: 2`,
admission manifest signature `7d99393e103daaa7…`. Every workload ran through the
durable Run API under `flock /tmp/aiec-acceptance.lock`, against
`https://127.0.0.1:18443` with the private CA, never `--insecure`.

## Matched benchmark, identical conditions fingerprint

`602f511b90348c50` on both sides — scenarios `control-plane` + `empty-exec`,
25 samples, `runtime_requested: null`, `python:3.13`, cpu 1 / 512 MiB /
2048 MiB, command `true`. The baseline file is unmodified.

| empty-exec | baseline (n=22) | after (n=25) | change |
|---|---:|---:|---:|
| run_total p50 | 25.58 s | 14.56 s | **−43.1 %** |
| wall_time p50 | 23.78 s | 12.71 s | **−46.5 %** |
| queue_wait p50 | 8.27 s | 7.63 s | −7.8 % |
| residual unattributed p50 | 6.00 s | 5.96 s | −0.8 % |
| runs succeeded | 22 / 25 | **25 / 25** | +3 |

Where the wall time went, phase by phase, same run:

| phase | baseline | after | change |
|---|---:|---:|---:|
| `phase_placement` | 5.12 s | 4.70 s | −8.1 % |
| `phase_task` | 0.87 s | 0.70 s | −19.2 % |
| `phase_cleanup` | **13.35 s** | **3.13 s** | **−76.5 %** |
| `queue_wait` | 8.27 s | 7.63 s | −7.8 % |

Cleanup is the whole story of the run-level improvement: it was three quarters
of the tail and is now a small part of it. Placement barely moved, which is
what the decomposition is for — it shows that of the 4.70 s, 1.95 s is
reservation and the rest is the machine actually being built.

The three baseline failures were stale-generation placement errors and none
recurred. `residual_unattributed` — what the client waited for that no phase
claims — is flat, so the gain is inside accounted phases rather than moved into
the unaccounted bucket.

Control-plane endpoint medians, same run: `/health` 0.0027 s → 0.0024 s,
`/ready` 0.1616 s → 0.1625 s, `usage` 0.3172 s → 0.3250 s,
`current_account` 0.3247 s → 0.3718 s. The two that grew —
`/v1/sandboxes` +17.0 % and `/v1/runs` +23.0 % — are the two endpoints that
return a tenant's accumulated rows, and the database now holds roughly a
thousand sandboxes and a thousand Runs against a nearly empty one at baseline.
That is data volume, not a regression, and no claim is made from it.

## Placement is decomposed, and the decomposition is the new information

`phase_placement` is now reported with its parts, so a slow reservation is no
longer indistinguishable from a slow boot:

| phase | median |
|---|---:|
| `placement` | 4.70 s |
| `placement.scheduler` | 1.95 s |
| `placement.allocation` | 0.52 s |
| `placement.boot` | 0.53 s |
| `placement.workspace` | 0.00 s |

`workspace` is 0 because this workload has no repository. On a Run that clones
one it is 1.2–1.3 s, which is the number the cache was supposed to attack.

A dotted name is a subset of its top-level phase, so a tool that adds up
unaccounted client wait must exclude them; `benchmarks/aiecbench/harness.py`
does, and `residual_unattributed` above is computed that way.

## Soaks

| | sequential | parallel |
|---|---|---|
| requested | 100 | 80 (20 batches of 4) |
| succeeded | **100** | 77 |
| failed | 0 | 3, all `backend unavailable: transient: no schedulable worker has capacity` |
| wall clock | 1 535 s | 453 s |
| run_total p50 / p95 / p99 | 15.12 / 17.81 / 19.74 s | 15.59 / 20.04 / 23.93 s |
| non-terminal sandboxes at the end | **0** | **0** |
| new non-terminal sandbox ids | none | none |
| free vCPUs before → after | 12.0 → 12.0 | 12.0 → 12.0 |
| run cleanup failures | none | none |

Every checkpoint is the baseline, and the final observation is taken before any
cleanup, so a leak could not be hidden by the measuring. The three parallel
failures are a capacity refusal at four-way concurrency, not an accumulation:
the census is identical afterwards. Their cause is not established. A refusal
path that could refuse without cause was found later - the scheduler excluded a
host for the rest of a call when it lost that host's advisory headroom lock to
a concurrent placement - and is fixed with a bounded wait, but a probe at this
soak's own concurrency reproduced no capacity refusal either way, so it is not
shown to be what happened here.

## Repository object cache: OFF against ON

Six samples each, one worker, pinned commit, every sample asserting a clean
checkout, no private mirror left behind, the pinned `HEAD`, the marker in the
captured diff, and a terminal sandbox.

| | cache OFF | cache ON (warm) | bypass run (ON, cache skipped) |
|---|---:|---:|---:|
| guest receive bytes, first | 9 280 | 260 690 | — |
| guest receive bytes, median of rest | 9 654 | **253 223** | 9 496 |
| placement, median of rest | 6 963 ms | 9 076 ms | 6 860 ms |

Calibrated in the same guest on the same repository, counter read either side of
the command: `git clone --depth 1` moves **8 580** bytes,
`git ls-remote -- <url> HEAD` moves **250 950**. The cache re-resolves the ref
on every Run — including a hit — to re-check anonymous access, and that single
check costs 29× the shallow clone it is meant to avoid. The cache is 26× worse
on network bytes and about two seconds slower per Run.

Two real defects were found and fixed on the way: the Docker directory listing
dropped every subdirectory (a tar names a directory with a trailing slash and
the one-level test ran before stripping it) and matched only the workspace-
relative spelling of entry names while the daemon names copied entries after
the directory it was asked for. A recursive walk over a Git mirror stopped after
one level, so the archive captured no objects and the first live hit failed with
git's exit 128. The same defect was in `GET /v1/sandboxes/{id}/files`. Both are
fixed, with regression tests.

The cache stays off. Bounding its re-check by an interval is a real weakening of
the property that a repository which has become private stops being served from a
shared store, and that bound is a threat-model decision, not a performance one.

## Artifact collection, before and after the group read

| | one read per 64 KiB | bounded groups of 32 |
|---|---:|---:|
| 1 MiB collected | 8 775 ms | 1 965 ms |
| 16.8 MiB collected | 129 360 ms | **8 945 ms** |
| per-chunk slope | 459.8 ms | flat |

The cause was measured, not guessed: one 1 MiB collection produced 39
`GET /v1/workers/{id}/ownership/{sid}` calls, because the chunk endpoint brackets
every read with two ownership verifications and each is an HTTPS round trip. One
authorized read now serves a bounded group, read between the same two checks and
buffered until the second one passes, so a lease replaced mid-group still stops
every byte of it. Correctness is unchanged: the empty file, a 66 770-byte file
and a 16 777 216-byte file were each collected and then downloaded, and every
served byte hashed to the digest recorded at collection.

## OMP through the generic Run path

`benchmarks/omp-after-2026-09-30.json`, nonce `final-20261001T0635Z`, both
revisions, Docker runtime, credentials delivered over the ordinary authenticated
file route. **Proven**: both sides settled `succeeded` with 3/3 validations,
`?? PROOF.md` and `changed_files: ['PROOF.md']` recorded, 192 KB and 328 KB agent
transcripts collected with recorded digests, and cleanup reported.

The first AFTER sample (`benchmarks/omp-after-first-sample-2026-09-30.json`) did
**not** pass: 2/3 validations on both sides. The third validation is
`test "$(wc -l < PROOF.md)" -eq 1`, and the agent's own closing message says it
left the file at 15 bytes with no trailing newline, which `wc -l` counts as zero
lines. The BEFORE transcript shows the same agent being walked through a
`printf …\n` before it finished. Both revisions behaved identically in both
samples, so nothing separates `v9.7.0` from `v9.8.0`; what moved is the model's
answer to an ambiguous instruction, on one sampling. One repetition per side is
an anecdote, which is what the harness says about itself.

## Not measured

- Network-enabled Firecracker: the worker still lacks the capability to create a
  TAP device, so microVM Runs are exercised with networking off.
- The hosted E2B path was not exercised against a real provider.
- The repository cache on Firecracker and on a hosted runtime.
- `pressure.observed_at` staleness is recorded as accepted and unproven; the
  admission gate uses `last_heartbeat` freshness, which is the documented
  contract.
