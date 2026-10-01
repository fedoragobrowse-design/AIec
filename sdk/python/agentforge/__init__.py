"""Minimal synchronous AIec SDK.

The import path is deliberately `agentforge` while the client class is `AIec`,
so the documented first line stays `from agentforge import AIec`.
"""
from .client import AIec, AIecError, Sandbox
from .runs import Runs
from .evals import Comparison, Evals, Suite, SuiteTask

__all__ = ["AIec", "AIecError", "Comparison", "Evals", "Runs", "Sandbox", "Suite", "SuiteTask"]
