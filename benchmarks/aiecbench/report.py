"""Assembling the report, printing it, and comparing two of them.

The report is JSON on stdout, because the next step is a machine reading it. A
short human summary goes to stderr, because the next step is usually a person.

The comparison is the part with teeth. Two reports are only compared when their
conditions match - same repository commit, same resources, same runtime, same
command, same task, same repetitions - and when they do not, the report says
which condition differs and prints no delta at all. A speedup measured against a
different workload is not a speedup, and the cheapest way to stop that number
circulating is to refuse to print it.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from typing import Any

from . import SCHEMA, VERSION
from .stats import collect_summaries


def conditions(args: Any, scenarios: list[str]) -> dict[str, Any]:
    """Everything that must match before two reports may be compared.

    Sample count is here but is *not* part of the fingerprint: changing how many
    samples were taken changes precision, not what was measured, and demanding
    an identical sample count would refuse a legitimate re-run at a different
    size.
    """
    return {
        "scenarios": sorted(scenarios),
        "image": args.image,
        "runtime_requested": args.runtime,
        "resources": {"cpu": args.cpu, "memory_mb": args.memory_mb, "disk_mb": args.disk_mb},
        "command": list(args.command_vector),
        "setup": [list(step) for step in args.setup_vectors],
        "validations": [list(step) for step in args.validation_vectors],
        "artifacts": list(args.artifacts),
        "workload_timeout_seconds": args.workload_timeout,
        "repo": {
            "url": args.repo,
            "ref": args.ref,
            # Recorded rather than assumed, so a comparison between a pinned
            # commit and a moving branch is refused rather than believed.
            "ref_kind": _ref_kind(args.ref),
        },
        "soak": {
            "iterations": args.iterations,
            "parallelism": args.max_parallel,
            "checkpoint_every": args.checkpoint_every,
        },
        "snapshot": {"kind": args.snapshot_kind},
        "matrix": {"max_parallel": args.matrix_parallel},
        "omp": {
            "omp_repo": args.omp_repo,
            "baseline_ref": args.baseline_ref,
            "candidate_ref": args.candidate_ref,
            "target_repo": args.target_repo,
            "target_ref": args.target_ref,
            "task": args.task,
            "repetitions": args.repetitions,
            "max_parallel": args.omp_parallel,
        },
        "samples_requested": args.samples,
    }


#: Conditions that must be identical for two reports to be comparable.
FINGERPRINT_KEYS = (
    "scenarios",
    "image",
    "runtime_requested",
    "resources",
    "command",
    "setup",
    "validations",
    "artifacts",
    "workload_timeout_seconds",
    "repo",
    "soak",
    "snapshot",
    "matrix",
    "omp",
)


def fingerprint(condition_block: dict[str, Any]) -> str:
    """A short digest of the comparable conditions."""
    material = {key: condition_block.get(key) for key in FINGERPRINT_KEYS}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def _ref_kind(reference: str | None) -> str:
    from .harness import ref_kind

    return ref_kind(reference or "")


def build(
    *,
    args: Any,
    client_description: dict[str, Any],
    credential_source: str,
    scenario_blocks: dict[str, Any],
    scenario_errors: dict[str, str],
    observations: list[dict[str, Any]],
    leak_report: dict[str, Any],
    cleanup: dict[str, Any],
    limitations: list[str],
) -> dict[str, Any]:
    condition_block = conditions(args, list(scenario_blocks))
    return {
        "schema": SCHEMA,
        "harness_version": VERSION,
        "label": args.label,
        "generated_at": _now(),
        "target": {**client_description, "credential_source": credential_source},
        "conditions": condition_block,
        "conditions_fingerprint": fingerprint(condition_block),
        "scenarios": scenario_blocks,
        "scenario_errors": scenario_errors,
        "observations": observations,
        "leak_accounting": leak_report,
        "harness_cleanup": cleanup,
        "limitations": limitations,
        "harness": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
    }


def _now() -> str:
    from .observe import now_iso

    return now_iso()


# -- before and after --------------------------------------------------------


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two reports, or explain why they may not be compared."""
    before_conditions = before.get("conditions") or {}
    after_conditions = after.get("conditions") or {}
    differing = [
        key
        for key in FINGERPRINT_KEYS
        if before_conditions.get(key) != after_conditions.get(key)
    ]
    block: dict[str, Any] = {
        "before": {
            "label": before.get("label"),
            "generated_at": before.get("generated_at"),
            "fingerprint": before.get("conditions_fingerprint"),
        },
        "after": {
            "label": after.get("label"),
            "generated_at": after.get("generated_at"),
            "fingerprint": after.get("conditions_fingerprint"),
        },
    }
    if differing:
        block["comparable"] = False
        block["differing_conditions"] = {
            key: {"before": before_conditions.get(key), "after": after_conditions.get(key)}
            for key in differing
        }
        block["reason"] = (
            "the two reports were produced under different conditions, so no delta is "
            "reported; a number computed across them would describe neither run"
        )
        return block

    block["comparable"] = True
    before_metrics = collect_summaries(before.get("scenarios"))
    after_metrics = collect_summaries(after.get("scenarios"))
    deltas: dict[str, Any] = {}
    for path in sorted(set(before_metrics) & set(after_metrics)):
        first, second = before_metrics[path], after_metrics[path]
        unit = first.get("unit", "s")
        median_key = f"median_{unit}"
        if median_key not in first or median_key not in second:
            continue
        first_median = float(first[median_key])
        second_median = float(second[median_key])
        entry: dict[str, Any] = {
            "before": first_median,
            "after": second_median,
            "delta": round(second_median - first_median, 4),
            "before_samples": first.get("samples"),
            "after_samples": second.get("samples"),
        }
        if first_median:
            entry["change_fraction"] = round(
                (second_median - first_median) / first_median, 4
            )
        deltas[path] = entry
    block["metric_deltas"] = deltas
    block["evidence"] = {
        "before_successful_runs": _success_counts(before),
        "after_successful_runs": _success_counts(after),
        "note": "a latency delta next to a drop in successful runs is not an improvement; "
                "read the counts first",
    }
    return block


def _success_counts(report: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, Any] = {}
    for name, block in (report.get("scenarios") or {}).items():
        if isinstance(block, dict) and "succeeded" in block:
            counts[name] = {
                "succeeded": block.get("succeeded"),
                "not_succeeded": block.get("not_succeeded"),
                "rejected_before_execution": block.get("rejected_before_execution"),
            }
    return counts


# -- human output ------------------------------------------------------------


def render(report: dict[str, Any], stream: Any = None) -> None:
    """A short readable summary. The JSON above it stays the real output."""
    out = stream or sys.stderr
    target = report.get("target", {})
    write = lambda line="": print(line, file=out)  # noqa: E731 - a local shorthand
    write(f"== AIec benchmark [{report.get('label')}] {report.get('generated_at')}")
    write(f"   target      : {target.get('base_url')} (tls: {target.get('tls')})")
    write(f"   conditions  : fingerprint {report.get('conditions_fingerprint')}")
    write()

    for name, block in (report.get("scenarios") or {}).items():
        summary = _scenario_lines(name, block)
        if summary:
            write(f"-- {name}")
            for line in summary:
                write(f"   {line}")
            write()
    for name, error in (report.get("scenario_errors") or {}).items():
        write(f"-- {name}: not run: {error}")
    if report.get("scenario_errors"):
        write()

    leak = report.get("leak_accounting") or {}
    census = leak.get("sandbox_census_delta") or {}
    write("-- leak accounting")
    if census.get("available"):
        write(f"   non-terminal sandboxes: {census.get('pre_existing_nonterminal')} before, "
              f"{census.get('nonterminal_at_end')} after")
        new_ids = census.get("new_nonterminal_sandbox_ids")
        if isinstance(new_ids, dict):
            write(f"   new non-terminal sandboxes: not computed ({new_ids.get('reason')})")
        else:
            new_ids = new_ids or []
            write(f"   new non-terminal sandboxes: {len(new_ids)}"
                  + (f" ({', '.join(new_ids[:5])})" if new_ids else ""))
        vcpus = census.get("vcpus_returned_to_baseline")
        if isinstance(vcpus, bool):
            write(f"   free vCPUs back to baseline: {'yes' if vcpus else 'no'}")
    else:
        write(f"   {census.get('reason', 'no census was taken')}")
    for failure in leak.get("run_cleanup_failures") or []:
        write(f"   run {failure.get('run_id')} left sandbox {failure.get('sandbox_id')} alive: "
              f"{failure.get('error')}")
    cleanup = report.get("harness_cleanup") or {}
    write(f"   harness-owned sandboxes: {cleanup.get('destroyed')} destroyed, "
          f"{len(cleanup.get('failed') or [])} could not be")
    write()

    unavailable_metrics = _unavailable(report)
    if unavailable_metrics:
        write("-- not measured here")
        for line in unavailable_metrics:
            write(f"   {line}")
        write()
    limitations = report.get("limitations") or []
    if limitations:
        write("-- limitations")
        for item in limitations:
            write(f"   {item}")
        write()
    comparison = report.get("comparison")
    if comparison:
        write("-- before/after")
        if not comparison.get("comparable"):
            write(f"   withheld: {comparison.get('reason')}")
            for key, values in (comparison.get("differing_conditions") or {}).items():
                write(f"   {key}: before={values.get('before')} after={values.get('after')}")
        else:
            for path, delta in (comparison.get("metric_deltas") or {}).items():
                write(f"   {path}: {delta.get('before')} -> {delta.get('after')} "
                      f"({delta.get('change_fraction')})")
        write()


def _scenario_lines(name: str, block: Any) -> list[str]:
    if not isinstance(block, dict):
        return []
    if block.get("available") is False:
        return [f"not measured: {block.get('reason', 'no reason given')}"]
    lines: list[str] = []
    if "endpoints" in block:
        for entry in block["endpoints"]:
            latency = entry.get("latency", {})
            if latency.get("available"):
                lines.append(
                    f"{entry['endpoint']:<18} median {latency.get('median_s')}s over "
                    f"{latency.get('samples')} requests"
                )
            else:
                lines.append(f"{entry['endpoint']:<18} {latency.get('reason')}")
        return lines
    shape = block.get("shape")
    if isinstance(shape, dict):
        lines.append(
            f"shape: {shape.get('iterations_executed')} of {shape.get('iterations_requested')} "
            f"iterations, {shape.get('mode')}, {shape.get('wall_clock_s')}s; "
            f"stopped early: {shape.get('stopped_early')}"
        )
    succeeded = block.get("succeeded")
    if succeeded is not None:
        lines.append(
            f"succeeded {succeeded}, not succeeded {block.get('not_succeeded')}, "
            f"rejected before execution {block.get('rejected_before_execution')}"
        )
    cold = block.get("cold_versus_warm")
    if isinstance(cold, dict) and cold.get("available", True):
        steady = cold.get("steady_state")
        if isinstance(steady, dict) and steady.get("run_total", {}).get("available"):
            lines.append(
                f"first run {cold['first_run']['run_total'].get('median_s')}s vs steady state "
                f"{steady['run_total'].get('median_s')}s over {cold.get('steady_state_runs')} runs"
            )
    for key in ("run_total", "create_to_running", "first_exec", "snapshot", "destroy",
                "workspace_restore", "wall_time"):
        metric = block.get(key)
        if isinstance(metric, dict) and metric.get("available"):
            lines.append(f"{key:<20} median {metric.get('median_s')}s over {metric.get('samples')}")
    for key, value in block.items():
        if key.startswith("phase_") and isinstance(value, dict) and value.get("available"):
            lines.append(f"{key:<20} median {value.get('median_s')}s over {value.get('samples')}")
    if "comparable" in block:
        lines.append(f"comparable: {block['comparable']}")
        for check in block.get("comparability") or []:
            if not check.get("passed"):
                lines.append(f"  failed check: {check.get('check')} ({check.get('detail')})")
    if block.get("comparison_withheld"):
        lines.append(block["comparison_withheld"])
    return lines


def _unavailable(report: dict[str, Any]) -> list[str]:
    """Every metric that was not measured, with the reason it was not."""
    found: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            if node.get("available") is False and node.get("reason"):
                found.append(f"{path or 'report'}: {node['reason']}")
                return
            for key, value in node.items():
                walk(value, f"{path}.{key}" if path else key)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    for observation in report.get("observations") or []:
        label = observation.get("label", "observation")
        for key, value in observation.items():
            if isinstance(value, dict) and value.get("available") is False and value.get("reason"):
                found.append(f"{label}.{key}: {value['reason']}")
    walk(report.get("scenarios"), "")
    seen: set[str] = set()
    unique: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
