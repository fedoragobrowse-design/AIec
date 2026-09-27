#!/usr/bin/env bash
# The project's quality gate.
#
# The verdict comes from cargo's exit status, not from summing "N passed" lines:
# a text summary can report 0 failures while a suite has already FAILED, so the
# exit code is the only trustworthy signal.
set -uo pipefail
cd "$(dirname "$0")/.."

export DATABASE_URL="${DATABASE_URL:-postgresql://aiec:aiec-dev-only@127.0.0.1:5432/aiec}"

status=0

run_gate() {
  local name="$1"; shift
  if "$@"; then
    printf '  %-22s ok\n' "$name"
  else
    printf '  %-22s FAILED\n' "$name"
    status=1
  fi
}

echo "quality gate"

run_gate "cargo fmt --check" cargo fmt --all --check
run_gate "clippy (-D warnings)" cargo clippy --workspace --all-targets --all-features -- -D warnings
run_gate "cargo test --workspace" cargo test --workspace --all-targets --all-features

# The documented Python import is `from agentforge import AIec`; this keeps the
# site, the README and the SDK from drifting apart.
run_gate "sdk import contract" python3 scripts/check-sdk-contract.py

if [ "$status" -eq 0 ]; then
  echo "gate passed"
else
  echo "gate FAILED"
fi
exit "$status"
