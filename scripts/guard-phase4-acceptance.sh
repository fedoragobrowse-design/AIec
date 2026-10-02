#!/usr/bin/env bash
# Reuse the existing real namespace/isolated PostgreSQL launcher, not its driver.
# No deployment images or network rules are changed outside that namespace.
set -euo pipefail
scripts=$(dirname "$(realpath "$0")")
export P2_BIN=${P4_BIN:-${P2_BIN:-$(realpath "$scripts/../target/release")}}
[[ -x "$P2_BIN/aiec-guard-watcher" ]] || { printf '%s\n' 'build the shipped aiec-guard-watcher binary first' >&2; exit 2; }
export P4_REPORT=${P4_REPORT:-$(realpath "$scripts/../benchmarks")/guard-phase4-acceptance.json}
export P2_ROOT=${P4_ROOT:-$(mktemp -d /tmp/aiec-p4.XXXXXX)}
export P2_DRIVER=$scripts/guard-phase4-acceptance.py
export P2_CP_PORT=${P4_CP_PORT:-18446}
export P2_WORKER_PORT=${P4_WORKER_PORT:-19446}
export P2_WATCHDOG_TIMEOUT_MS=10000
# The existing launcher otherwise inherits provider proxy variables. The driver
# passes an allowlisted environment to every production process as well.
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
exec bash "$scripts/guard-phase2-acceptance.sh"
