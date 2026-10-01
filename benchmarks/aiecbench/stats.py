"""Summaries that refuse to overstate what a sample can carry.

Three rules, all of them learned the hard way by the benchmark that produced
``benchmarks/BASELINE.md``:

* A percentile over a handful of samples has no error bar. Below
  :data:`MIN_SAMPLES_FOR_PERCENTILE` the percentile keys are withheld and the
  reason is written into the report, so nobody has to remember the threshold.
* No samples is not a zero. A metric nothing was observed for is reported as
  unavailable with a reason.
* A residual is computed per sample and then summarised. Subtracting two
  independently aggregated medians is a different number, and it is how this
  harness once produced a confident "32% unaccounted" that nothing could
  reproduce.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from typing import Any, Iterable, Sequence

#: Below this many samples a p95 or p99 is noise, so it is not printed.
MIN_SAMPLES_FOR_PERCENTILE = 20

#: The percentiles worth reporting, and where they sit in the sample.
PERCENTILES: tuple[tuple[str, float], ...] = (("p50", 0.50), ("p95", 0.95), ("p99", 0.99))


def unavailable(metric: str, reason: str) -> dict[str, Any]:
    """A metric that was not observed, with the reason it was not.

    The shape is deliberately not ``0``. Zero is a measurement; this is the
    absence of one, and a report that cannot tell the two apart is a report
    nobody can act on.
    """
    return {"metric": metric, "available": False, "reason": reason}


def percentile(ordered: Sequence[float], fraction: float) -> float:
    """Nearest-rank percentile of an already-sorted sample.

    Nearest-rank rather than interpolated: with twenty samples an interpolated
    p99 is a number between two observations that nobody actually measured.
    """
    if not ordered:
        raise ValueError("percentile of an empty sample")
    rank = max(1, min(len(ordered), math.ceil(fraction * len(ordered))))
    return ordered[rank - 1]


def summarise(
    metric: str,
    samples: Iterable[float],
    *,
    unit: str = "s",
    note: str | None = None,
) -> dict[str, Any]:
    """Describe a sample, withholding percentiles it cannot carry.

    ``unit`` becomes the key suffix (``median_s``, ``median_ms``), which is what
    the historical baseline document quotes, so old and new reports can be read
    with the same eye.
    """
    values = sorted(float(value) for value in samples)
    if not values:
        return unavailable(metric, note or "no samples were observed")

    result: dict[str, Any] = {"metric": metric, "available": True, "unit": unit,
                              "samples": len(values)}
    result[f"min_{unit}"] = round(values[0], 4)
    result[f"max_{unit}"] = round(values[-1], 4)
    result[f"mean_{unit}"] = round(statistics.fmean(values), 4)
    result[f"median_{unit}"] = round(statistics.median(values), 4)
    if len(values) >= MIN_SAMPLES_FOR_PERCENTILE:
        for label, fraction in PERCENTILES:
            result[f"{label}_{unit}"] = round(percentile(values, fraction), 4)
    else:
        result["percentiles_withheld"] = (
            f"{len(values)} samples is below the {MIN_SAMPLES_FOR_PERCENTILE} needed "
            f"for a p50/p95/p99"
        )
    if note:
        result["note"] = note
    return result


def histogram(values: Iterable[Any]) -> dict[str, int]:
    """Counts per distinct value, most frequent first.

    Failure reasons are the interesting part of a soak, and a median over exit
    codes says nothing about which failure is eating the cluster.
    """
    counts = Counter(str(value) for value in values)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))



def collect_summaries(node: Any, path: str = "") -> dict[str, dict[str, Any]]:
    """Every summary in a report, keyed by its JSON path.

    Used by the before/after comparison: two reports are compared metric by
    metric only where both of them actually measured something.
    """
    found: dict[str, dict[str, Any]] = {}
    if isinstance(node, dict):
        if "metric" in node and "samples" in node:
            found[path] = node
        for key, value in node.items():
            found.update(collect_summaries(value, f"{path}.{key}" if path else str(key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.update(collect_summaries(value, f"{path}[{index}]"))
    return found
