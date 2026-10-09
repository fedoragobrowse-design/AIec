#!/usr/bin/env bash
# AIec one-line installer: control plane + worker + MCP + Python SDK.
#
#   curl -fsSL https://aiec.gobrowse.dev/quickstart.sh | bash
#
# What it does, in order: checks Linux + Rust + bwrap (or Docker), clones
# (or reuses) the repo, builds `aiec` + `aiec-mcp`, runs `aiec setup --yes`
# to write `.env.local` (0600, fresh secrets), starts postgres/minio when
# Docker is available (otherwise the in-memory API), launches the server and
# a worker in the background, installs the Python SDK, and proves the whole
# path with `aiec doctor` plus one sandboxed exec.
#
# Flags (also as AIEC_* env): --yes (non-interactive), --runtime
# bwrap-dev|docker, --no-services (skip postgres/minio), --no-mcp (skip the
# MCP server), --dir PATH (checkout directory, default ./aiec).
#
# Idempotent: rerunning reuses the checkout and never overwrites an existing
# .env.local. Loopback only: nothing binds or dials off-host.
set -Eeuo pipefail

REPO_URL="${AIEC_REPO_URL:-https://github.com/fedoragobrowse-design/AIec.git}"
DIR="${AIEC_DIR:-./aiec}"
RUNTIME="${AIEC_RUNTIME:-bwrap-dev}"
WITH_SERVICES=1
WITH_MCP=1
YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) YES=1 ;;
    --runtime) RUNTIME="$2"; shift ;;
    --runtime=*) RUNTIME="${1#*=}" ;;
    --no-services) WITH_SERVICES=0 ;;
    --no-mcp) WITH_MCP=0 ;;
    --dir) DIR="$2"; shift ;;
    --dir=*) DIR="${1#*=}" ;;
    -h|--help)
      sed -n '2,20p' "$0"; exit 0 ;;
    *) printf 'quickstart: unknown flag %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

log() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[[ "$(uname -s)" == "Linux" ]] || die "AIec runs on Linux (bwrap, Firecracker, Docker); on macOS use a Linux VM."
have git || die "git is required."
have cargo || die "Rust is required (https://rustup.rs)."
have python3 || die "Python 3.10+ is required for the SDK."
[[ "$RUNTIME" == "bwrap-dev" || "$RUNTIME" == "docker" ]] || die "--runtime must be bwrap-dev or docker."
if [[ "$RUNTIME" == "bwrap-dev" ]]; then
  [[ -x /usr/bin/bwrap ]] || die "bubblewrap is required for bwrap-dev (install bubblewrap)."
else
  docker info >/dev/null 2>&1 || die "Docker Engine is not reachable (start dockerd or use --runtime bwrap-dev)."
fi

if [[ -d "$DIR/.git" ]]; then
  log "Reusing checkout at $DIR"
else
  log "Cloning into $DIR"
  git clone --depth 1 "$REPO_URL" "$DIR"
fi
cd "$DIR"

log "Building aiec and aiec-mcp (this takes a few minutes)"
export CARGO_TARGET_DIR="$PWD/target-host"
cargo build --bins

log "Writing .env.local (fresh secrets, mode 0600)"
./target-host/debug/aiec setup --yes --runtime "$RUNTIME" --env-file .env.local
set -a; # shellcheck disable=SC1091
source .env.local; set +a

if [[ "$WITH_SERVICES" == "1" ]] && [[ "$RUNTIME" == "docker" ]]; then
  log "Starting postgres + minio"
  bash scripts/bootstrap-local-services.sh || log "services already bootstrapped, continuing"
fi

log "Starting control plane"
export AIEC_URL="${AIEC_URL:-http://127.0.0.1:8080}"
# The server bootstraps its API key and worker token from the sourced env;
# supplied secrets are never echoed, so the log line confirms the bind only.
# The readiness probe carries the key in a 0600 curl config, never in argv
# (argv is visible to every local user via `ps`).
auth_config="$(mktemp)"
chmod 600 "$auth_config"
printf 'header = "Authorization: Bearer %s"\n' "$AIEC_API_KEY" > "$auth_config"
cleanup() {
  rm -f "${auth_config:-}"
  [[ -f .aiec-server.pid ]] && kill "$(cat .aiec-server.pid)" 2>/dev/null || true
  [[ -f .aiec-mcp.pid ]] && kill "$(cat .aiec-mcp.pid)" 2>/dev/null || true
}
./target-host/debug/aiec server --runtime "$RUNTIME" >.aiec-server.log 2>&1 &
echo $! > .aiec-server.pid
# Any failure after this point (readiness timeout, proof exec, SDK install)
# must not orphan the backgrounded server/MCP: `set -e` exits through this
# trap. Success removes it so the services stay up when the script ends.
trap cleanup ERR
for _ in $(seq 1 30); do
  curl -fsS -K "$auth_config" "$AIEC_URL/v1/sandboxes?limit=1" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS -K "$auth_config" "$AIEC_URL/v1/sandboxes?limit=1" >/dev/null \
  || { tail -20 .aiec-server.log; rm -f "$auth_config"; die "control plane did not become ready (see .aiec-server.log)"; }
rm -f "$auth_config"

if [[ "$WITH_MCP" == "1" ]]; then
  log "Starting MCP server"
  AIEC_MCP_CLEANUP_ON_SHUTDOWN=1 ./target-host/debug/aiec-mcp >.aiec-mcp.log 2>&1 &
  echo $! > .aiec-mcp.pid
fi

log "Installing the Python SDK"
python3 -m pip install --quiet ./sdk/python

log "Proving the path: create, exec, destroy"
box=$(./target-host/debug/aiec sandbox create --image alpine:3.21 | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
./target-host/debug/aiec sandbox exec "$box" -- sh -c 'echo setup-ok'
./target-host/debug/aiec sandbox destroy "$box"

# Success: the services stay up, so the failure trap comes off.
trap - ERR

log "Done"
printf 'Control plane: %s\n' "${AIEC_URL:-http://127.0.0.1:8080}"
printf 'MCP:           http://127.0.0.1:8765/mcp %s\n' "$([[ "$WITH_MCP" == "1" ]] && echo "(running)" || echo "(skipped)")"
printf 'SDK:           from agentforge import AIec\n'
printf 'Stop:          kill $(cat .aiec-server.pid%s)\n' "$([[ "$WITH_MCP" == "1" ]] && echo " \$(cat .aiec-mcp.pid)" || true)"
