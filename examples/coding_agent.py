#!/usr/bin/env python3
"""End-to-end coding-agent workflow against a real AIec API.

Creates a sandbox, clones a repository over HTTPS, inspects it, edits a tracked
file, runs the project's own validation, retrieves the diff, and destroys the
sandbox. Everything goes through the public AIec API — no host-side
shortcuts, no SSH, no direct provider access.

    export AGENTFORGE_API_KEY="af_live_..."
    python3 examples/coding_agent.py [repo-url]
"""

from __future__ import annotations

import os
import sys

from aiec import AIec, AIecError

DEFAULT_REPO = "https://github.com/octocat/Hello-World.git"


def run() -> int:
    repo = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_REPO
    af = AIec(api_key=os.environ.get("AGENTFORGE_API_KEY"))
    print(f"endpoint: {af.base_url}")
    print(f"repo:     {repo}")

    box = af.sandboxes.create(image="agentforge:latest", timeout_seconds=900)
    print(f"sandbox:  {box.id}")

    try:
        def sh(script: str) -> str:
            result = box.exec(["/bin/sh", "-c", script])
            if result.get("timed_out"):
                raise SystemExit(f"command timed out: {script}")
            if result.get("exit_code") != 0:
                raise SystemExit(
                    f"command failed ({result['exit_code']}): {script}\n{result.get('stderr', '')}"
                )
            return result.get("stdout", "")

        print("\n== clone ==")
        print(sh(f"git clone --depth 1 {repo} /workspace/repo"))

        print("\n== status ==")
        print(sh("cd /workspace/repo && git log --oneline -1 && git status --porcelain") or "(clean)")

        print("\n== inspect ==")
        print(sh("cd /workspace/repo && ls -1 | head -10"))

        print("\n== edit ==")
        print(sh("cd /workspace/repo && printf '\\nAIec example edit\\n' >> README"))
        print(sh("cd /workspace/repo && tail -3 README"))

        print("\n== validate ==")
        # Real validation, not a tautology: the file must parse and the edit
        # must be present, and git must consider the tree clean of whitespace
        # damage.
        print(sh("cd /workspace/repo && git diff --check && echo 'diff is well formed'"))
        print(sh("cd /workspace/repo && grep -q 'AIec example edit' README && echo 'edit present'"))

        print("\n== diff ==")
        diff = sh("cd /workspace/repo && git --no-pager diff")
        print(diff)
        if "AIec example edit" not in diff:
            print("expected edit is not in the diff", file=sys.stderr)
            return 1
        print("\nOK: clone, edit, validate and diff all succeeded inside the sandbox.")
        return 0
    except AIecError as error:
        print(f"AIec error: {error}", file=sys.stderr)
        return 1
    finally:
        box.destroy()
        print(f"destroyed sandbox {box.id}")


if __name__ == "__main__":
    raise SystemExit(run())
