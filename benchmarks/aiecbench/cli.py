"""The command line.

Credentials come from a file, the environment, or a prompt. Not from a flag,
because a flag is in every process listing on the host and in every shell
history that ran the benchmark. ``--api-key`` still works, and warns.

Every scenario's measurements land in one JSON document on stdout, whether the
run worked or not. An empty document is a bug in a benchmark, not a result - it
is the failure mode ``benchmarks/BASELINE.md`` records having cost somebody an
afternoon.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

from . import VERSION
from .client import Client, TransportError
from .harness import Bench
from .report import build, compare, render
from .scenarios import DEFAULT_SCENARIOS, REGISTRY

#: The control plane admits 20 rps sustained per tenant by default. The harness
#: runs slower than that so a latency sample is a latency sample and not a
#: measurement of the limiter.
DEFAULT_RPS = 5.0

#: Same ceiling as scripts/load-soak-test.sh.
HARD_PARALLELISM_CAP = 64

#: The local MCP server clamps its own concurrency to this.
MCP_PARALLELISM_CAP = 16

API_KEY_ENV = "AIEC_API_KEY"


def _vectors(values: list[str] | None) -> list[list[str]]:
    """Command lines, split like a shell would, into argument vectors.

    The API takes argument vectors and never a shell string, so a benchmark that
    passed a string would be measuring a different thing from what it claims to.
    """
    vectors: list[list[str]] = []
    for value in values or []:
        parts = shlex.split(value)
        if not parts:
            raise SystemExit(f"empty command in --setup/--validation: {value!r}")
        vectors.append(parts)
    return vectors


def _resolve_api_key(args: argparse.Namespace) -> tuple[str, str]:
    """The key, and a description of where it came from (never the key itself)."""
    if args.api_key:
        print(
            "WARNING: --api-key puts the credential in this process's command line. Prefer "
            "--api-key-file or the AIEC_API_KEY environment variable.",
            file=sys.stderr,
        )
        key, source = args.api_key, "flag (visible in process listings)"
    elif args.api_key_file:
        path = Path(args.api_key_file).expanduser()
        try:
            key, source = path.read_text(encoding="utf-8").strip(), f"file:{path}"
        except OSError as error:
            raise SystemExit(f"cannot read --api-key-file {path}: {error}")
    elif os.environ.get(API_KEY_ENV, "").strip():
        key, source = os.environ[API_KEY_ENV].strip(), f"env:{API_KEY_ENV}"
    elif sys.stdin.isatty():
        key, source = getpass.getpass("AIec API key: "), "interactive prompt"
    else:
        raise SystemExit(
            f"no API key: set {API_KEY_ENV}, pass --api-key-file, or run this from a terminal"
        )
    # Every message the harness prints is scrubbed of the key before it is
    # stored. A very short key would make that scrub corrupt unrelated text -
    # replacing every "x" in an error message - so it is refused instead.
    if len(key) < 16:
        raise SystemExit(
            f"the API key from {source} is {len(key)} characters long, which cannot be an AIec "
            "key (they are af_live_ plus at least 48 hex characters) and is too short to be "
            "scrubbed out of messages safely"
        )
    if not key.startswith("af_live_"):
        print(
            "note: the API key does not look like an af_live_ key; if the control plane "
            "rejects it, check the key before reading anything into the results",
            file=sys.stderr,
        )
    return key, source


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bench.py",
        description="Measure a live AIec control plane. Prints JSON on stdout.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Scenarios:\n"
            "  control-plane  read-only endpoint latency\n"
            "  empty-exec     end-to-end run cost and per-phase breakdown\n"
            "  matrix         server-side repetitions and matrices, under a bound\n"
            "  soak           bounded repeated runs, watching for accumulated state\n"
            "  snapshot       snapshot and workspace-restore latency\n"
            "  omp            baseline versus candidate OMP revision, via the local MCP server\n"
            "\n"
            "Environment:\n"
            "  AIEC_API_KEY                 control-plane credential (preferred)\n"
            "  AIEC_BENCH_DATABASE_URL      enables the PostgreSQL observations; the URL\n"
            "                               reaches psql through PGDATABASE, never argv\n"
            "  AIEC_MCP_TOKEN               local MCP token, if not using the default file\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"aiec-bench {VERSION}")

    # -- target ---------------------------------------------------------
    parser.add_argument("--base-url", default="https://127.0.0.1:18443")
    parser.add_argument("--ca", default=None, help="CA bundle for a TLS endpoint")
    parser.add_argument(
        "--insecure", action="store_true",
        help="skip TLS verification (throwaway test clusters only)",
    )
    parser.add_argument("--api-key", default=None, help="discouraged: visible in process listings")
    parser.add_argument("--api-key-file", default=None)
    parser.add_argument("--request-timeout", type=float, default=120.0)
    parser.add_argument(
        "--rps", type=float, default=DEFAULT_RPS,
        help="maximum request rate, to stay under the tenant rate limiter",
    )

    # -- selection ------------------------------------------------------
    parser.add_argument(
        "scenarios", nargs="*", metavar="SCENARIO",
        help=f"any of: {', '.join(REGISTRY)}, or 'all'. Default: {' '.join(DEFAULT_SCENARIOS)}",
    )
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--label", default="run", help="a name for this run, for the report")
    parser.add_argument("--out", default=None, help="also write the JSON report here")
    parser.add_argument(
        "--compare", default=None, metavar="REPORT.json",
        help="compare against a previous report, refusing if the conditions differ",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress the human summary")
    parser.add_argument(
        "--skip-runs", action="store_true",
        help="measure the control plane only (the old name for naming no scenario "
             "besides control-plane)",
    )

    # -- workload -------------------------------------------------------
    parser.add_argument("--image", default="python:3.13")
    parser.add_argument("--runtime", default=None, help="requested runtime, e.g. docker")
    parser.add_argument("--cpu", type=int, default=1)
    parser.add_argument("--memory-mb", type=int, default=512)
    parser.add_argument("--disk-mb", type=int, default=2048)
    parser.add_argument("--command", default="true", help="the task, as a shell-quoted command line")
    parser.add_argument("--setup", action="append", default=None, help="repeatable setup step")
    parser.add_argument("--validation", action="append", default=None, help="repeatable validation")
    parser.add_argument("--artifact", action="append", default=None, help="path to collect")
    parser.add_argument(
        "--workload-timeout", type=int, default=None,
        help="the run's own timeout; the control plane defaults it to 600s",
    )
    parser.add_argument(
        "--run-timeout", type=float, default=900.0,
        help="HTTP timeout for a run submission, which blocks until the run settles",
    )
    parser.add_argument(
        "--event-samples", type=int, default=3,
        help="how many runs to read an event log back for (0 disables)",
    )

    # -- repository -----------------------------------------------------
    parser.add_argument("--repo", default=None, help="repository URL for the repo scenario")
    parser.add_argument(
        "--ref", default=None,
        help="commit, tag or branch. Pin a commit: a branch is not reproducible",
    )

    # -- soak -----------------------------------------------------------
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument(
        "--max-parallel", type=int, default=1,
        help=f"soak concurrency; refused above {HARD_PARALLELISM_CAP}",
    )
    parser.add_argument("--max-duration", type=float, default=0.0,
                        help="stop the soak after this many seconds (0 means no limit)")
    parser.add_argument("--checkpoint-every", type=int, default=5)
    parser.add_argument(
        "--reclaim-leaked", action="store_true",
        help="after reporting them, destroy sandboxes the platform leaked (off by default: "
             "a leaked machine is the evidence)",
    )

    # -- snapshot -------------------------------------------------------
    parser.add_argument("--snapshot-kind", default="workspace",
                        choices=["workspace", "virtual_machine", "memory"])
    parser.add_argument("--sandbox-ttl", type=int, default=300)
    parser.add_argument("--exec-timeout", type=int, default=60)
    parser.add_argument("--snapshot-timeout", type=int, default=300)

    # -- matrix ---------------------------------------------------------
    parser.add_argument(
        "--matrix-parallel", type=int, default=2,
        help="the batch max_parallel the evaluation routes are asked for",
    )
    # -- OMP ------------------------------------------------------------
    parser.add_argument("--mcp-url", default="http://127.0.0.1:8765/mcp")
    parser.add_argument("--mcp-token-file", default=None)
    parser.add_argument("--omp-repo", default=None)
    parser.add_argument("--baseline-ref", default=None)
    parser.add_argument("--candidate-ref", default=None)
    parser.add_argument("--target-repo", default=None)
    parser.add_argument("--target-ref", default=None)
    parser.add_argument("--task", default=None)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--omp-parallel", type=int, default=2)
    parser.add_argument("--omp-timeout", type=int, default=None,
                        help="the agent's own timeout, in seconds")
    parser.add_argument("--omp-tool-timeout", type=float, default=5400.0,
                        help="HTTP timeout for the comparison tool call")
    return parser


def _prepare(args: argparse.Namespace) -> argparse.Namespace:
    """Validate, and turn command-line strings into the shapes the API takes."""
    if args.samples < 1:
        raise SystemExit("--samples must be at least 1")
    if args.max_parallel < 1 or args.max_parallel > HARD_PARALLELISM_CAP:
        raise SystemExit(
            f"--max-parallel must be between 1 and {HARD_PARALLELISM_CAP}: asking for more "
            "machines than a cluster can serve measures the cluster falling over"
        )
    if args.omp_parallel < 1:
        raise SystemExit("--omp-parallel must be at least 1")
    if args.omp_parallel > MCP_PARALLELISM_CAP:
        print(
            f"note: --omp-parallel {args.omp_parallel} exceeds the local MCP server's own "
            f"cap of {MCP_PARALLELISM_CAP}; the server will clamp it",
            file=sys.stderr,
        )
    if args.matrix_parallel < 1 or args.matrix_parallel > HARD_PARALLELISM_CAP:
        raise SystemExit(
            f"--matrix-parallel must be between 1 and {HARD_PARALLELISM_CAP}: a matrix "
            "asking for more machines than the cluster can serve measures the queue"
        )
    if args.rps <= 0:
        raise SystemExit("--rps must be positive")
    if args.rps > 20:
        print(
            "note: --rps is above the control plane's default sustained limit of 20 rps; "
            "latency samples may then include rate-limit back-off",
            file=sys.stderr,
        )
    args.command_vector = shlex.split(args.command)
    if not args.command_vector:
        raise SystemExit("--command produced an empty argument vector")
    args.setup_vectors = _vectors(args.setup)
    args.validation_vectors = _vectors(args.validation)
    args.artifacts = list(args.artifact or [])
    return args


def _selected(args: argparse.Namespace) -> list[str]:
    if not args.scenarios:
        # Naming no scenario is the historical default, and `--skip-runs` is the
        # flag this harness used before scenarios existed.
        return ["control-plane"] if args.skip_runs else list(DEFAULT_SCENARIOS)
    if args.scenarios == ["all"]:
        return list(REGISTRY)
    unknown = [name for name in args.scenarios if name not in REGISTRY]
    if unknown:
        raise SystemExit(
            f"unknown scenario(s): {', '.join(unknown)}. Known: {', '.join(REGISTRY)}"
        )
    # Preserve the registry's order so a report reads the same way twice.
    return [name for name in REGISTRY if name in set(args.scenarios)]


def main(argv: list[str] | None = None) -> int:
    args = _prepare(_parser().parse_args(argv))
    names = _selected(args)

    missing = {
        name: f"scenario `{name}` needs --{requirement}"
        for name in names
        for requirement in REGISTRY[name][1]
        if getattr(args, requirement, None) in (None, "")
    }
    if missing:
        for scenario, reason in missing.items():
            print(f"{reason}", file=sys.stderr)
        raise SystemExit(2)

    api_key, credential_source = _resolve_api_key(args)
    client = Client(
        args.base_url,
        api_key,
        ca=args.ca,
        insecure=args.insecure,
        timeout=args.request_timeout,
        min_interval=1.0 / args.rps,
    )
    bench = Bench(client=client, label=args.label)

    blocks: dict[str, Any] = {}
    errors: dict[str, str] = {}
    try:
        # One baseline observation for the whole invocation, whatever runs: the
        # leak comparison is against the state the cluster was in before the
        # harness touched anything.
        try:
            bench.observe("harness-baseline", full=True)
        except (TransportError, OSError) as error:
            # An unreachable control plane is the most common way to run this
            # wrongly - wrong port, untrusted certificate, key not accepted - and
            # it still produces a report saying so. A benchmark that prints
            # nothing has failed in the most confusing way available.
            reason = client.redact(str(error))
            errors["harness-baseline"] = reason
            bench.limit(f"the control plane at {args.base_url} could not be reached: {reason}")
        for name in names:
            _, _, entry = REGISTRY[name]
            try:
                blocks[name] = entry(bench, args)
            except TransportError as error:
                errors[name] = client.redact(str(error))
            except Exception as error:  # noqa: BLE001 - a scenario must not lose the report
                errors[name] = f"{type(error).__name__}: {client.redact(str(error))}"
    finally:
        # The last observation happens before any cleanup, so what the platform
        # left behind is measured rather than tidied away. Cleanup then destroys
        # only what this harness itself created.
        try:
            bench.observe("harness-final", full=True)
        except Exception as error:  # noqa: BLE001 - the report still has to be written
            bench.limit(f"the final observation failed: {type(error).__name__}: {error}")
        try:
            cleanup = bench.cleanup_owned(reclaim_leaked=args.reclaim_leaked)
        except (TransportError, OSError) as error:
            cleanup = {
                "owned_at_end": len(bench.owned),
                "destroyed": 0,
                "already_gone": 0,
                "failed": [{"sandbox_id": sandbox_id, "why": why,
                            "status": None, "code": "unreachable",
                            "message": client.redact(str(error))}
                           for sandbox_id, why in sorted(bench.owned.items())],
                "leaked_sandboxes_reported": [leak["sandbox_id"] for leak in bench.leaked],
                "leaked_sandboxes_reclaimed": [],
                "note": "cleanup could not reach the control plane",
            }
            bench.owned.clear()
        if cleanup["failed"]:
            bench.limit(
                f"{len(cleanup['failed'])} sandbox(es) this harness created could not be "
                "destroyed; they are listed in harness_cleanup.failed and are still running"
            )
        if bench.leaked and not args.reclaim_leaked:
            bench.limit(
                "machines that outlived their run are reported, not destroyed; re-run with "
                "--reclaim-leaked to clear them once the result has been read"
            )

    document = build(
        args=args,
        client_description=client.describe(),
        credential_source=credential_source,
        scenario_blocks=blocks,
        scenario_errors=errors,
        observations=bench.observations,
        leak_report=bench.leak_report(),
        cleanup=cleanup,
        limitations=bench.limitations,
    )

    if args.compare:
        try:
            previous = json.loads(Path(args.compare).expanduser().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"cannot read --compare {args.compare}: {error}", file=sys.stderr)
            return 3
        document["comparison"] = compare(previous, document)

    rendered = json.dumps(document, indent=2, default=str)
    print(rendered)
    if args.out:
        Path(args.out).expanduser().write_text(rendered + "\n", encoding="utf-8")
    if not args.quiet:
        render(document)

    if "harness-baseline" in errors:
        # Reachable enough to try, not reachable enough to measure. Non-zero, so a
        # pipeline does not record a failed benchmark as a successful run.
        print("the control plane was never reached; the report says why", file=sys.stderr)
        return 1
    if not blocks:
        print("no scenario produced a measurement; see scenario_errors above", file=sys.stderr)
        return 1
    return 0
