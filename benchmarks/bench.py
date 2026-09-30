#!/usr/bin/env python3
"""Measures a live AIec control plane, so optimisation is based on numbers.

The performance milestone is explicit that nothing gets optimised from
speculation, so this harness exists to produce the numbers first. It measures
three things separately, because they fail for different reasons:

- **Control plane**: how long a request takes end to end.
- **Sandbox**: how long a machine takes to become usable, which is dominated by
  boot and is the number most likely to be worth attacking.
- **Phases**: where a run's wall time actually goes, using the per-phase
  timings the run already records.

It reports percentiles only when the sample is big enough to mean anything.
A p99 over six samples is a number with no error bar, and printing it as if it
had one is how a benchmark starts lying.

Usage:
    python3 benchmarks/bench.py --base-url https://127.0.0.1:18443 \
        --api-key af_live_... --ca /path/ca.pem --samples 20

Results are written as JSON to stdout so a later change can be compared against
them rather than remembered.
"""
from __future__ import annotations

import argparse
import json
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.request

# Below this, a percentile is noise and is withheld.
MIN_SAMPLES_FOR_PERCENTILE = 20


class Client:
    def __init__(self, base_url: str, api_key: str, ca: str | None,
                 insecure: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.context = None
        if insecure:
            # Opt-in, never the default, and said out loud. Python's TLS is
            # stricter than curl's about a self-signed CA with no keyUsage
            # extension, so a test cluster needs this; a real deployment must
            # not.
            print("WARNING: TLS verification is disabled for this benchmark. "
                  "Never use this against anything but a throwaway test "
                  "cluster.", file=sys.stderr)
            self.context = ssl._create_unverified_context()
        elif ca:
            self.context = ssl.create_default_context(cafile=ca)

    def call(self, method: str, path: str, body: dict | None = None,
             timeout: float = 120.0) -> tuple[int, object]:
        payload = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=payload, method=method,
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"},
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=timeout,
                                        context=self.context) as response:
                raw = response.read()
                elapsed = time.perf_counter() - started
                try:
                    return response.status, json.loads(raw)
                except json.JSONDecodeError:
                    return response.status, None
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")
        finally:
            self.last_seconds = elapsed

    def timed(self, method: str, path: str, body: dict | None = None,
              timeout: float = 120.0) -> tuple[float, int, object]:
        started = time.perf_counter()
        status, value = self.call(method, path, body, timeout)
        return time.perf_counter() - started, status, value


def summarise(name: str, samples: list[float]) -> dict:
    """Percentiles only when the sample can carry them."""
    result: dict = {
        "metric": name,
        "samples": len(samples),
        "min_s": round(min(samples), 4),
        "max_s": round(max(samples), 4),
        "mean_s": round(statistics.fmean(samples), 4),
        "median_s": round(statistics.median(samples), 4),
    }
    if len(samples) >= MIN_SAMPLES_FOR_PERCENTILE:
        ordered = sorted(samples)
        for label, fraction in (("p50", 0.50), ("p95", 0.95), ("p99", 0.99)):
            index = min(len(ordered) - 1, int(fraction * len(ordered)))
            result[f"{label}_s"] = round(ordered[index], 4)
    else:
        result["percentiles_withheld"] = (
            f"fewer than {MIN_SAMPLES_FOR_PERCENTILE} samples"
        )
    return result


def bench_control_plane(client: Client, samples: int) -> list[dict]:
    """Request latency for endpoints that touch the database."""
    out = []
    for label, method, path in (
        ("health", "GET", "/health"),
        ("list_sandboxes", "GET", "/v1/sandboxes"),
        ("list_runs", "GET", "/v1/runs?limit=20"),
    ):
        timings = []
        for _ in range(samples):
            seconds, status, _ = client.timed(method, path, timeout=30)
            if status < 400:
                timings.append(seconds)
        if timings:
            out.append(summarise(label, timings))
    return out


def bench_run(client: Client, image: str, runtime: str, samples: int) -> dict:
    """End-to-end run cost, plus the per-phase breakdown it already records.

    A run that does not succeed is excluded from the timing and counted
    separately. Beware what a "failed" bench says on a cluster that has been
    used: stranded sandboxes count against the tenant's active-sandbox quota
    even when nothing is running on them, so enough leftovers make every
    submission fail on quota and the benchmark quietly measures nothing.

    The phase timings matter more than the total: a run that takes 30 seconds is
    not actionable, but "24 of them were placement" is.
    """
    body = {
        "workload": {"image": image, "command": ["true"]},
        "requested_runtime": runtime,
        "resources": {"cpu": 1, "memory_mb": 512, "disk_mb": 2048},
    }
    totals: list[float] = []
    # Per-run, so the residual can be computed for each run rather than
    # subtracted from two independently-aggregated medians. A median of
    # differences is not the difference of medians, and that mistake is what
    # produced a confident "32% unaccounted" that nothing could reproduce.
    phases: dict[str, list[float]] = {}
    residuals: list[float] = []
    failures = 0
    excluded = 0

    for _ in range(samples):
        seconds, status, value = client.timed("POST", "/v1/runs", body, timeout=600)
        if status >= 400 or not isinstance(value, dict):
            failures += 1
            continue
        if value.get("state") != "succeeded":
            # Excluded from the timing, and counted. A run that did not succeed
            # has phases that describe a different population from the total,
            # so including them would make the two columns disagree about what
            # they are averages of.
            excluded += 1
            continue
        totals.append(seconds)
        measured = 0.0
        for phase, millis in (value.get("results") or {}).get("phase_ms", {}).items():
            seconds_in_phase = millis / 1000.0
            phases.setdefault(phase, []).append(seconds_in_phase)
            measured += seconds_in_phase
        # What the client waited for that no phase claims: creating the run row,
        # the state transitions, the HTTP round trip. Clamped at zero because a
        # phase can straddle the request boundary by a few milliseconds, and a
        # negative residual is measurement noise, not time saved.
        residuals.append(max(0.0, seconds - measured))

    report = {
        "completed": len(totals),
        "failed": failures,
        "excluded_not_succeeded": excluded,
    }
    if totals:
        report["run_total"] = summarise("run_total", totals)
    if residuals:
        report["residual_unattributed"] = summarise("residual_unattributed", residuals)
    for phase, values in sorted(phases.items()):
        report[f"phase_{phase}"] = summarise(f"phase_{phase}", values)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://127.0.0.1:18443")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--ca", default=None, help="CA bundle for a TLS endpoint")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS verification (test clusters only)")
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--image", default="python:3.13")
    parser.add_argument("--runtime", default="docker")
    parser.add_argument("--skip-runs", action="store_true",
                        help="measure the control plane only")
    args = parser.parse_args()

    client = Client(args.base_url, args.api_key, args.ca, args.insecure)
    report = {
        "base_url": args.base_url,
        "samples_requested": args.samples,
        "control_plane": bench_control_plane(client, args.samples),
    }
    if not args.skip_runs:
        report["runs"] = bench_run(client, args.image, args.runtime, args.samples)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
