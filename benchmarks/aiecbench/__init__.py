"""A reproducible measurement harness for a live AIec control plane.

The performance specification says to optimise from measurements, and a
measurement nobody can reproduce is an anecdote. This package is the
reproducible half: one HTTP client, one set of statistics with a stated sample
rule, one set of observations, and the scenarios that combine them.

Two properties are deliberate and load-bearing:

* **Nothing is mocked.** Every scenario drives the same HTTPS API, worker
  endpoints and local MCP server a real caller drives. A harness that stubs the
  control plane measures the stub.
* **Absence is reported, never invented.** A metric the deployment does not
  expose - host CPU, PostgreSQL connections, a snapshot the runtime cannot take
  - comes back as ``{"available": false, "reason": ...}``. It is never zero,
  because a zero here would be read as "we looked and there was none".

Importing this module has no side effects and needs no third-party package, so
the harness runs on a stock CPython next to a deployed control plane.
"""

SCHEMA = "aiec-bench/1"
VERSION = "1.0.0"

__all__ = ["SCHEMA", "VERSION"]
