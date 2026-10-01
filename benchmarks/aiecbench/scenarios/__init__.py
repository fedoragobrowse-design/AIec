"""The measurements, one module per question.

Each scenario module exposes the same three names:

``NAME``
    what it is called on the command line;
``REQUIRES``
    the arguments it cannot run without, so the CLI can refuse clearly rather
    than half-running;
``run(bench, args)``
    the measurement, returning a JSON-ready dict.

Every scenario returns something for every metric it looked at. A metric it
could not measure comes back as ``{"available": false, "reason": ...}`` - never
as a zero, and never as a silently absent key.
"""

from __future__ import annotations

from typing import Any, Callable

from . import control_plane, empty_exec, matrix, omp, repo, snapshot, soak

#: Scenario name -> (module summary, required argument names, entry point).
REGISTRY: dict[str, tuple[str, tuple[str, ...], Callable[[Any, Any], dict[str, Any]]]] = {
    control_plane.NAME: (control_plane.SUMMARY, control_plane.REQUIRES, control_plane.run),
    empty_exec.NAME: (empty_exec.SUMMARY, empty_exec.REQUIRES, empty_exec.run),
    repo.NAME: (repo.SUMMARY, repo.REQUIRES, repo.run),
    matrix.NAME: (matrix.SUMMARY, matrix.REQUIRES, matrix.run),
    soak.NAME: (soak.SUMMARY, soak.REQUIRES, soak.run),
    snapshot.NAME: (snapshot.SUMMARY, snapshot.REQUIRES, snapshot.run),
    omp.NAME: (omp.SUMMARY, omp.REQUIRES, omp.run),
}

#: What runs when the caller names no scenario. The historical default: the
#: control plane, then a run that does nothing.
DEFAULT_SCENARIOS = ("control-plane", "empty-exec")

__all__ = ["REGISTRY", "DEFAULT_SCENARIOS"]
