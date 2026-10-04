"""What the harness can see, and what it cannot.

The specification asks for CPU, memory, disk, write volume, active sandboxes,
queued runs and PostgreSQL connection usage. The control plane exposes some of
that, the worker host exposes more, and the database exposes the rest - each
behind a different door, and most of those doors are closed by default.

So every function here returns either an observation or an explicit refusal
naming the door:

* the tenant's own sandbox census and node capacity, from the API;
* the harness host's load, memory and free disk, from ``/proc``;
* the local Docker daemon's container count, when the harness runs on the
  worker host and Docker is there;
* PostgreSQL connection and run-table counts, when a database URL is configured
  and ``psql`` is installed.

An observation that could not be taken is ``{"available": false, "reason":
...}``. It is never ``0``, because ``0`` is a number somebody will optimise
against, and a missing metric must never become a claim.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import quote
from typing import Any

from .stats import unavailable

#: Sandbox states from which a machine is gone. Everything else is still
#: holding, or expected to hold, capacity.
TERMINAL_SANDBOX_STATES = frozenset({"destroyed", "failed"})

#: How many non-terminal sandbox ids a census carries. The full count is
#: always reported; the ids are a sample, and anything derived from them is
#: refused when the sample is short.
CENSUS_ID_CAP = 50

#: Pages a census will walk before it refuses rather than loops. The sandbox
#: list is paginated, and a census that read one page of many and still claimed
#: completeness would be the silent undercount this module exists to refuse.
#: The bound is a backstop against a control plane that never stops handing out
#: cursors, not a claim about how many sandboxes a tenant may own.
CENSUS_PAGE_LIMIT = 500

#: Page size the census asks for; the control plane clamps to its own ceiling.
CENSUS_PAGE_SIZE = 200

#: Environment variable holding the database connection string. Read from the
#: environment rather than a flag so the password never reaches a process
#: listing.
DATABASE_URL_ENV = "AIEC_BENCH_DATABASE_URL"

_SUBPROCESS_TIMEOUT = 15


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# -- through the API ---------------------------------------------------------


def sandbox_census(client: Any) -> dict[str, Any]:
    """Every sandbox this tenant owns, by state.

    The leak question is answered here: a non-terminal sandbox whose run has
    finished is a machine the platform still believes is running.

    The route is paginated, so every page is walked rather than the first one
    measured and forgotten. A census that stopped at the first page would report
    a *complete* count drawn from an arbitrary slice, which is worse than a
    refusal: the leak tooling prints these numbers beside a container census,
    and a short sandbox list reads as "nothing leaked".
    """
    states: Counter[str] = Counter()
    live: list[str] = []
    total = 0
    after: dict[str, str] | None = None
    seen_cursors: set[tuple[str, str]] = set()
    for page_number in range(CENSUS_PAGE_LIMIT):
        path = f"/v1/sandboxes?limit={CENSUS_PAGE_SIZE}"
        if after is not None:
            # Percent-encoded, not interpolated. The cursor's timestamp ends in
            # "+00:00", and a bare "+" in a query string decodes as a space, so
            # the control plane would refuse a cursor the harness never got
            # wrong on every page after the first.
            path += f"&after_created_at={quote(after['created_at'], safe='')}"
            path += f"&after_id={quote(after['id'], safe='')}"
        response = client.request("GET", path, timeout=30)
        if not response.ok:
            return unavailable(
                "sandboxes",
                f"GET {path} returned {response.status} ({response.error_code()})",
            )
        body = response.body
        if not isinstance(body, dict) or not isinstance(body.get("sandboxes"), list):
            # A bare list is the pre-pagination shape. Refusing is still right,
            # but name the shape that arrived so the reader can tell an older
            # control plane from a malformed response.
            return unavailable(
                "sandboxes",
                f"GET {path} did not return a sandbox page "
                f"(body was {type(body).__name__}, not a page object)",
            )
        rows = [row for row in body["sandboxes"] if isinstance(row, dict)]
        states.update(str(row.get("state", "unknown")) for row in rows)
        live.extend(
            str(row.get("id"))
            for row in rows
            if str(row.get("state", "")) not in TERMINAL_SANDBOX_STATES
        )
        total += len(rows)
        nxt = body.get("next")
        if nxt is None:
            return {
                "available": True,
                "at": now_iso(),
                "total": total,
                "pages": page_number + 1,
                "by_state": dict(sorted(states.items())),
                "nonterminal_count": len(live),
                "nonterminal_sandbox_ids": live[:CENSUS_ID_CAP],
                "nonterminal_truncated": len(live) > CENSUS_ID_CAP,
            }
        if not isinstance(nxt, dict) or "created_at" not in nxt or "id" not in nxt:
            return unavailable(
                "sandboxes", f"GET {path} returned a page with an unusable cursor"
            )
        cursor = (str(nxt["created_at"]), str(nxt["id"]))
        if cursor in seen_cursors:
            # A repeated cursor means a repeated page. Continuing would inflate
            # the count with duplicates until the backstop above fired, and a
            # doubled total is a number somebody would optimise against.
            return unavailable(
                "sandboxes",
                f"GET /v1/sandboxes repeated cursor {cursor[1]} after "
                f"{page_number + 1} pages",
            )
        seen_cursors.add(cursor)
        after = {"created_at": cursor[0], "id": cursor[1]}
    return unavailable(
        "sandboxes",
        f"GET /v1/sandboxes still offered a next cursor after {CENSUS_PAGE_LIMIT} "
        "pages; the census is refused rather than reported as a partial count",
    )


def capacity(client: Any) -> dict[str, Any]:
    """Free node capacity and the control plane's request counter.

    ``/metrics`` is unauthenticated Prometheus text, and it reports what the
    scheduler has reserved rather than what the host has free. Both facts
    matter, and the gap between them is a real finding rather than a missing
    metric.
    """
    response = client.request("GET", "/metrics", timeout=30, text=True)
    if not response.ok:
        return unavailable("node_capacity", f"GET /metrics returned {response.status}")
    values: dict[str, float] = {}
    for line in (response.text or "").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        name, _, value = line.partition(" ")
        try:
            values[name] = float(value.strip())
        except ValueError:
            continue
    if "aiec_node_available_vcpus" not in values:
        return unavailable("node_capacity", "GET /metrics exposed no aiec_node_* gauges")
    return {
        "available": True,
        "at": now_iso(),
        "scope": "reserved by the scheduler, not measured on the host",
        "available_vcpus": values.get("aiec_node_available_vcpus"),
        "available_memory_bytes": values.get("aiec_node_available_memory_bytes"),
        "api_requests_total": values.get("aiec_api_requests_total"),
    }


def accounting(client: Any) -> dict[str, Any]:
    """The tenant's own usage counters."""
    response = client.request("GET", "/v1/usage", timeout=30)
    if not response.ok:
        return unavailable("usage", f"GET /v1/usage returned {response.status}")
    if not isinstance(response.body, list):
        return unavailable("usage", "GET /v1/usage did not return a list")
    totals: dict[str, float] = {}
    for item in response.body:
        if isinstance(item, dict) and "metric" in item:
            try:
                totals[str(item["metric"])] = float(item.get("quantity", 0))
            except (TypeError, ValueError):
                continue
    return {"available": True, "at": now_iso(), "by_metric": totals}


def run_states(client: Any, state: str | None = None, limit: int = 100) -> dict[str, Any]:
    """How many runs the tenant has in a state, at most ``limit`` deep.

    A page, not a census: the API caps the page size, so a tenant with ten
    thousand queued runs is reported as "at least ``limit``" rather than as a
    number this harness invented.
    """
    path = f"/v1/runs?limit={int(limit)}"
    if state:
        path += f"&state={state}"
    response = client.request("GET", path, timeout=30)
    label = f"runs[{state or 'all'}]"
    if not response.ok:
        return unavailable(label, f"GET {path} returned {response.status}")
    if not isinstance(response.body, list):
        return unavailable(label, f"GET {path} did not return a list")
    states = Counter(
        str(run.get("state", "unknown")) for run in response.body if isinstance(run, dict)
    )
    return {
        "available": True,
        "at": now_iso(),
        "page_limit": limit,
        "at_least": len(response.body),
        "may_be_truncated": len(response.body) >= limit,
        "by_state": dict(sorted(states.items())),
    }


# -- the harness host --------------------------------------------------------


def harness_host() -> dict[str, Any]:
    """Load, memory and free disk of the machine running the harness.

    This is the *benchmark host*. When the control plane and its workers are
    elsewhere - the normal self-hosted case - these numbers describe the
    observer and nothing else, so the scope is written into the result rather
    than assumed.
    """
    if not sys.platform.startswith("linux"):
        return unavailable("harness_host", f"no /proc on {sys.platform}")
    result: dict[str, Any] = {
        "available": True,
        "at": now_iso(),
        "scope": "the harness host itself, not the worker or the control plane",
    }
    try:
        with open("/proc/loadavg", encoding="utf-8") as handle:
            result["loadavg"] = [float(part) for part in handle.read().split()[:3]]
    except (OSError, ValueError) as error:
        result["loadavg"] = unavailable("loadavg", str(error))
    try:
        available_kb = 0
        total_kb = 0
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                key, _, rest = line.partition(":")
                value = rest.strip().split(" ")[0]
                if not value.isdigit():
                    continue
                if key == "MemAvailable":
                    available_kb = int(value)
                elif key == "MemTotal":
                    total_kb = int(value)
        result["memory_available_bytes"] = available_kb * 1024
        result["memory_total_bytes"] = total_kb * 1024
    except (OSError, ValueError) as error:
        result["memory_available_bytes"] = unavailable("memory", str(error))
    try:
        usage = shutil.disk_usage(tempfile.gettempdir())
        result["temp_disk_free_bytes"] = usage.free
        result["temp_disk_total_bytes"] = usage.total
    except OSError as error:
        result["temp_disk_free_bytes"] = unavailable("temp_disk", str(error))
    return result


def local_containers() -> dict[str, Any]:
    """Running containers on the harness host's Docker or Podman daemon.

    Run the harness on the worker host; this is not a remote daemon census.
    """
    engine = shutil.which("docker") or shutil.which("podman")
    if not engine:
        return unavailable("containers", "neither docker nor podman is installed on the harness host")
    try:
        finished = subprocess.run(
            [engine, "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return unavailable("containers", f"{engine} ps failed: {error}")
    if finished.returncode != 0:
        return unavailable(
            "containers",
            f"{engine} ps exited {finished.returncode}: {finished.stderr.strip()[:200]}",
        )
    names = [line for line in finished.stdout.splitlines() if line.strip()]
    return {
        "available": True,
        "at": now_iso(),
        "scope": f"the {os.path.basename(engine)} daemon on the harness host",
        "running": len(names),
        "names": names[:25],
        "names_truncated": len(names) > 25,
    }


# -- PostgreSQL --------------------------------------------------------------

_CONNECTION_QUERY = (
    "select coalesce(state, 'unknown') as state, count(*) "
    "from pg_stat_activity where backend_type = 'client backend' group by 1 order by 1"
)

_RUN_TABLE_QUERY = "select state::text, count(*) from runs group by 1 order by 1"


def postgres(redact=None) -> dict[str, Any]:
    """Connection and run-row counts, read directly from PostgreSQL.

    Opt-in through ``AIEC_BENCH_DATABASE_URL`` in the environment. The URL
    reaches ``psql`` through ``PGDATABASE`` - libpq accepts a connection string
    there - so the password is never a command-line argument, and it is scrubbed
    out of any error text before it is stored.
    """
    scrub = redact or (lambda text: text)
    url = os.environ.get(DATABASE_URL_ENV, "").strip()
    if not url:
        return unavailable(
            "postgres", f"not measured: set {DATABASE_URL_ENV} in the environment to enable it"
        )
    psql = shutil.which("psql")
    if not psql:
        return unavailable("postgres", "not measured: psql is not installed on the harness host")

    result: dict[str, Any] = {
        "available": True,
        "at": now_iso(),
        "scope": "the control plane's PostgreSQL",
    }
    failed: list[str] = []
    for key, query in (
        ("backend_connections_by_state", _CONNECTION_QUERY),
        ("run_rows_by_state", _RUN_TABLE_QUERY),
    ):
        outcome = _psql(psql, url, query, scrub)
        if outcome.get("available"):
            result[key] = outcome["rows"]
        else:
            result[key] = unavailable(key, str(outcome.get("reason", "query failed")))
            failed.append(key)
    if failed:
        result["available"] = False
        result["reason"] = f"unavailable: {', '.join(failed)}"
    return result


def _psql(psql: str, url: str, query: str, scrub) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["PGDATABASE"] = url
    environment["PGCONNECT_TIMEOUT"] = "5"
    try:
        finished = subprocess.run(
            [psql, "-X", "-q", "-t", "-A", "-F", "|", "-c", query],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            env=environment,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return {"available": False, "reason": scrub(str(error))}
    if finished.returncode != 0:
        return {"available": False, "reason": scrub(finished.stderr.strip())[:300]}
    rows: dict[str, int] = {}
    for line in finished.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 2:
            continue
        try:
            rows[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return {"available": True, "rows": rows}


# -- the whole picture -------------------------------------------------------


def take(client: Any, *, full: bool) -> dict[str, Any]:
    """One observation pass.

    ``full`` adds the doors that cost a subprocess or a disk stat - the host, the
    local Docker daemon and PostgreSQL. Soak checkpoints take the cheap pass and
    the first and last sample take the full one.
    """
    snapshot: dict[str, Any] = {
        "at": now_iso(),
        "sandboxes": sandbox_census(client),
        "node_capacity": capacity(client),
        "accounting": accounting(client),
        "queued_runs": run_states(client, "queued"),
    }
    if full:
        snapshot["harness_host"] = harness_host()
        snapshot["containers"] = local_containers()
        snapshot["postgres"] = postgres(getattr(client, "redact", None))
    return snapshot


def leak_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """What is still held now that was not held before.

    Reported, never cleaned. A soak that destroys the sandboxes it finds at the
    end has destroyed its own evidence.
    """
    before_sandboxes = before.get("sandboxes", {})
    after_sandboxes = after.get("sandboxes", {})
    if not (before_sandboxes.get("available") and after_sandboxes.get("available")):
        return unavailable(
            "leak_accounting", "the sandbox census was unavailable at one end of the run"
        )
    before_ids = set(before_sandboxes.get("nonterminal_sandbox_ids", []))
    after_ids = set(after_sandboxes.get("nonterminal_sandbox_ids", []))
    before_capacity = before.get("node_capacity", {})
    after_capacity = after.get("node_capacity", {})
    delta: dict[str, Any] = {
        "available": True,
        "pre_existing_nonterminal": before_sandboxes.get("nonterminal_count"),
        "nonterminal_at_end": after_sandboxes.get("nonterminal_count"),
        "by_state_at_end": after_sandboxes.get("by_state"),
    }
    # The id lists are capped, so a difference between two truncated lists is
    # not a set of new sandboxes - it is whatever survived the cap. Reported as
    # unavailable rather than as a count, because "0 new" beside "70 at the
    # end" is a claim the data cannot support.
    truncated = [
        label
        for label, census in (("before", before_sandboxes), ("after", after_sandboxes))
        if census.get("nonterminal_truncated")
    ]
    if truncated:
        delta["new_nonterminal_sandbox_ids"] = unavailable(
            "new_nonterminal_sandbox_ids",
            f"the sandbox census was truncated to {CENSUS_ID_CAP} ids "
            f"{' and '.join(truncated)}, so the new-leak set cannot be derived "
            f"from it",
        )
    else:
        delta["new_nonterminal_sandbox_ids"] = sorted(after_ids - before_ids)
    if before_capacity.get("available") and after_capacity.get("available"):
        delta["available_vcpus_before"] = before_capacity.get("available_vcpus")
        delta["available_vcpus_after"] = after_capacity.get("available_vcpus")
        delta["vcpus_returned_to_baseline"] = (
            before_capacity.get("available_vcpus") == after_capacity.get("available_vcpus")
        )
    else:
        delta["vcpus_returned_to_baseline"] = unavailable(
            "vcpus_returned_to_baseline", "node capacity was unavailable at one end of the run"
        )
    return delta
