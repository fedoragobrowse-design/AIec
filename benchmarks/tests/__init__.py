"""Tests for the benchmark harness, run from the repository root.

    python3 -m unittest discover -s benchmarks

These are the harness's own tests, and they are about one thing: a number in a
report has to mean what the prose says it means. A refusal that is counted as a
task failure, a latency sample that hides the retries behind it, a leak count
computed from a truncated list and a fabricated 0.0 s are all the same class of
bug - a report that is confidently wrong - and each of them has a test here.
"""
