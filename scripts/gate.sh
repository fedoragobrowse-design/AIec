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
  local output
  # A gate that quietly degrades to a no-op is a gate that reports a pass it
  # did not earn, so a step that skips says so instead of saying ok.
  if output="$("$@" 2>&1)"; then
    case "$output" in
      *skipped*) printf '  %-22s SKIPPED\n' "$name" ;;
      *) printf '  %-22s ok\n' "$name" ;;
    esac
  else
    printf '%s\n' "$output"
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
run_gate "acceptance host helpers" python3 -m unittest discover -s scripts/tests

# The import contract only checks one line, so a suite that cannot even be
# collected - a stale import, a syntax error - left the gate green. That is
# exactly what happened once, so the suite itself is part of the gate now.
run_gate "python sdk tests" bash -c 'cd sdk/python && python3 -m pytest -q'

# Guard is documented as hardware-agnostic, and the only way that claim stays
# true is if something checks it. An x86_64 build cannot catch an aarch64-only
# type error - `c_char` is `i8` on one and `u8` on the other - so the second
# architecture is compiled, not assumed.
#
# It runs in the cross image because the C toolchain aarch64 needs (two crates
# compile C in their build scripts) is not installable on the host without
# root. Set AIEC_SKIP_CROSS=1 to skip where Docker is unavailable; the skip is
# reported as a skip, never as a pass.
cross_check() {
  if [ "${AIEC_SKIP_CROSS:-0}" = "1" ]; then
    echo "skipped (AIEC_SKIP_CROSS=1)"
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "skipped (no usable docker daemon)"
    return 0
  fi
  rustup target list --installed 2>/dev/null | grep -qx aarch64-unknown-linux-gnu || {
    rustup target add aarch64-unknown-linux-gnu >/dev/null 2>&1
  }
  local root="${CARGO_HOME:-$HOME/.cargo}"
  # The container builds as root against a mount of this repository, so it
  # gets a target directory of its own: writing into the host's `target` leaves
  # root-owned artefacts behind, and the next non-root build then fails on them
  # with a permission error rather than a compile error.
  docker run --rm \
    -v "$PWD":/src \
    -v "${RUSTUP_HOME:-$HOME/.rustup}":/rustup:ro \
    -v "$root":/cargo \
    -w /src \
    -e RUSTUP_HOME=/rustup -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/cross-target \
    -e PATH=/cargo/bin:/usr/local/bin:/usr/bin:/bin \
    ghcr.io/cross-rs/aarch64-unknown-linux-gnu:main \
    cargo check --workspace --all-targets --target aarch64-unknown-linux-gnu
}

run_gate "aarch64 cross-check" cross_check

if [ "$status" -eq 0 ]; then
  echo "gate passed"
else
  echo "gate FAILED"
fi
exit "$status"
