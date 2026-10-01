"""A real repository, cloned on every run, measured run by run.

This is the scenario the specification's workspace-preparation cache question
needs: the *same* repository at the *same* commit, repeatedly, so the difference
between the first run and the rest is what a cache is worth - or what it would
be worth if the control plane had one.

Three properties make the measurement mean something, and the harness checks all
three rather than assuming them:

* **The reference is pinned.** ``--ref`` is meant to be a commit. A branch is
  accepted and reported as ``branch-or-tag``, because a benchmark that quietly
  measured whatever landed on a branch this morning is not reproducible.
* **The commit is verified, not requested.** Every run records the commit it
  actually got, and the scenario refuses to call a set of samples consistent if
  they disagree.
* **The repository is proven present.** A default validation runs ``git rev-parse
  --verify HEAD`` inside the workspace, so a run that "succeeded" without a
  checkout is a failure with evidence, not a fast success.
"""

from __future__ import annotations

from typing import Any

from ..harness import (
    Bench,
    describe_outcomes,
    phase_durations,
    ref_kind,
    run_request,
    submit_run,
)
from ..stats import histogram, summarise, unavailable

NAME = "repo"
SUMMARY = "repeated runs against one pinned repository commit"
REQUIRES: tuple[str, ...] = ("repo",)

#: Proves the workspace really holds a git checkout. `git` is the one tool the
#: platform itself uses to prepare a workspace, so it is present wherever a
#: repository run is meaningful.
DEFAULT_VALIDATION: list[list[str]] = [
    ["/bin/sh", "-c", "git -C /workspace/repository rev-parse --verify HEAD"]
]


def run(bench: Bench, args: Any) -> dict[str, Any]:
    kind = ref_kind(args.ref)
    validations = args.validation_vectors or [list(step) for step in DEFAULT_VALIDATION]
    body = run_request(
        image=args.image,
        command=args.command_vector,
        cpu=args.cpu,
        memory_mb=args.memory_mb,
        disk_mb=args.disk_mb,
        # A clone needs a network. Saying so explicitly keeps the measurement
        # from silently changing shape when the default policy moves.
        network=True,
        repo=args.repo,
        ref=args.ref,
        setup=args.setup_vectors,
        validations=validations,
        artifacts=args.artifacts,
        timeout_seconds=args.workload_timeout,
        git_evidence=True,
        runtime=args.runtime,
        retention="destroy",
    )

    outcomes = [
        submit_run(bench, body, timeout=args.run_timeout) for _ in range(max(1, args.samples))
    ]
    report = describe_outcomes(outcomes)
    report["workload"] = {
        "image": args.image,
        "command": args.command_vector,
        "setup": args.setup_vectors,
        "validations": validations,
        "artifacts": args.artifacts,
        "repo": args.repo,
        "ref": args.ref,
        "ref_kind": kind,
        "resources": {"cpu": args.cpu, "memory_mb": args.memory_mb, "disk_mb": args.disk_mb},
        "network": {"enabled": True},
        "retention": "destroy",
    }
    evidence = _git_evidence(outcomes)
    report["git_evidence"] = evidence
    report["cold_versus_warm"] = _cold_versus_warm(outcomes)
    report["rate_limit_429s"] = bench.client.denials

    if kind != "commit":
        bench.limit(
            f"the repository reference `{args.ref}` is a {kind}, not a commit: repeated "
            "runs are only reproducible while it stays where it is"
        )
    # Read off the evidence, not off the aggregate: this is the check that says
    # the runs really did measure the same checkout, and it has to notice a run
    # that succeeded without recording a commit at all.
    if not evidence.get("commit_consistent", False) or evidence.get(
        "runs_succeeded_without_a_commit"
    ):
        bench.limit(
            "the runs in this scenario did not all check out the same commit, so their "
            "setup times are not comparable to each other and this report may not be used "
            "as one side of a before/after comparison"
        )
    return report


def _git_evidence(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    """What the runs actually proved about the checkout.

    The commit each run resolved, the diff it left behind, and whether the
    validations passed - the correctness evidence a before/after comparison has
    to be allowed to rely on.
    """
    commits: list[str] = []
    missing_commit: list[str] = []
    validations_passed = 0
    validations_total = 0
    changed_files: dict[str, int] = {}
    for outcome in outcomes:
        run = outcome.get("run") or {}
        results = run.get("results") or {}
        commit = results.get("commit")
        if isinstance(commit, str) and commit:
            commits.append(commit)
        elif outcome.get("state") == "succeeded":
            missing_commit.append(str(run.get("id", "")))
        for check in results.get("validations") or []:
            if isinstance(check, dict):
                validations_total += 1
                validations_passed += 1 if check.get("ok") else 0
        files = results.get("changed_files") or []
        if files:
            changed_files[str(run.get("id", ""))] = len(files)

    evidence: dict[str, Any] = {
        "available": bool(commits) or not missing_commit,
        "commits_observed": sorted(set(commits)),
        "commit_consistent": len(set(commits)) == 1 if commits else False,
        "runs_succeeded_without_a_commit": missing_commit,
        "validations_passed": validations_passed,
        "validations_total": validations_total,
        "changed_file_counts": changed_files,
    }
    if not commits:
        evidence["available"] = False
        evidence["reason"] = "no run recorded a resolved commit, so nothing about the "\
                             "checkout could be verified"
    return evidence


def _cold_versus_warm(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    """First run against the rest, phase by phase.

    This is the whole point of running the same commit repeatedly: the first
    clone pays for the network and the last one may not. Both populations are
    reported; neither is dropped, because which of them a caller experiences
    depends on whether the control plane caches anything at all.
    """
    succeeded = [item for item in outcomes if item.get("state") == "succeeded"]
    if not succeeded:
        return unavailable("cold_versus_warm", "no run reached `succeeded`")
    first, rest = succeeded[0], succeeded[1:]
    block: dict[str, Any] = {
        "first_run": {
            "run_total": summarise("first_run_total", [first["seconds"]]),
            "phases": {
                name: summarise(f"first_{name}", [value])
                for name, value in sorted(phase_durations(first["run"]).items())
            },
        },
        "steady_state_runs": len(rest),
    }
    if rest:
        block["steady_state"] = {
            "run_total": summarise("steady_state_total", [item["seconds"] for item in rest]),
            "phases": {
                name: summarise(name, values)
                for name, values in sorted(_phase_samples(rest).items())
            },
        }
        placement_first = phase_durations(first["run"]).get("placement")
        placement_rest = _phase_samples(rest).get("placement")
        if placement_first is not None and placement_rest:
            block["placement_delta_first_vs_steady"] = {
                "first_run_s": round(placement_first, 4),
                "steady_state_median_s": summarise(
                    "steady_state_placement", placement_rest
                ).get("median_s"),
                "note": "placement includes repository preparation, allocation and boot; "
                        "this difference does not isolate cache or clone cost",
            }
    else:
        block["steady_state"] = unavailable(
            "steady_state", "only one run succeeded, so there is no steady state to compare"
        )
    block["states"] = histogram(str(item.get("state")) for item in outcomes)
    return block


def _phase_samples(runs: list[dict[str, Any]]) -> dict[str, list[float]]:
    """Phase durations across several runs, keyed by phase name.

    Collected from every run rather than from the first one, so a phase a
    particular run did not reach does not silently drop out of the comparison.
    """
    collected: dict[str, list[float]] = {}
    for item in runs:
        for name, value in phase_durations(item["run"]).items():
            collected.setdefault(name, []).append(value)
    return collected
