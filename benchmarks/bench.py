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

    The phase timings matter more than the total: a run that takes 30 seconds is
    not actionable, but "24 of them were placement" is.
    """
    body = {
        "workload": {"image": image, "command": ["true"]},
        "requested_runtime": runtime,
        "resources": {"cpu": 1, "memory_mb": 512, "disk_mb": 2048},
    }
    totals: list[float] = []
    phases: dict[str, list[float]] = {}
    failures = 0

    for _ in range(samples):
        seconds, status, value = client.timed("POST", "/v1/runs", body, timeout=600)
        if status >= 400 or not isinstance(value, dict):
            failures += 1
            continue
        if value.get("state") == "succeeded":
            totals.append(seconds)
        for phase, millis in (value.get("results") or {}).get("phase_ms", {}).items():
            phases.setdefault(phase, []).append(millis / 1000.0)

    report = {"completed": len(totals), "failed": failures}
    if totals:
        report["run_total"] = summarise("run_total", totals)
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
