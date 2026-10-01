#!/usr/bin/env python3
"""Measures a live AIec control plane, so optimisation is based on numbers.

The performance milestone is explicit that nothing gets optimised from
speculation, so this harness exists to produce the numbers first. The
implementation lives in the ``aiecbench`` package next to this file; this script
is the entry point and the documentation of what the scenarios are.

    # the historical default: control-plane reads, then runs that do nothing
    python3 benchmarks/bench.py --api-key-file /run/secrets/aiec-key --samples 20

    # every scenario, against a private CA
    python3 benchmarks/bench.py all --ca /etc/aiec/ca.pem --api-key-file key.txt

    # a bounded leak watch
    python3 benchmarks/bench.py soak --iterations 40 --max-parallel 4

Results are JSON on stdout, so a later run can be compared against this one
rather than remembered, with ``--compare``. A short readable summary goes to
stderr. Nothing is mocked: every scenario drives the real API, the real workers
and, for the OMP comparison, the real local MCP server.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aiecbench.cli import main  # noqa: E402 - the path has to be set first

if __name__ == "__main__":
    sys.exit(main())
