#!/usr/bin/env bash
# Disposable reaper acceptance: control plane, worker, guest and database in one
# private user+network namespace, with no watchdog process at all.
#
# The absence of a watchdog is the point. Nothing in this run calls the guard
# quarantine API, so the only component that can quarantine a spent budget is the
# control plane's own durable reaper.
set -euo pipefail

# Shared with the other launchers: an isolated database for this run, either a
# private cluster or one the caller names and owns alone.
source "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/acceptance-db.sh"

self=$(realpath "$0")
host_netns=$(readlink /proc/self/ns/net)
[[ $host_netns == net:* ]] || { printf '%s\n' 'cannot read the host network namespace' >&2; exit 2; }

if [[ ${1:-} != --inside ]]; then
  bin=${RP_BIN:-$HOME/aiec/phase2-bin}
  [[ -x "$bin/aiec-server" && -x "$bin/aiec" ]] || {
    printf '%s\n' 'prebuilt acceptance binaries required in RP_BIN' >&2
    exit 2
  }
  for tool in unshare ip python3; do command -v "$tool" >/dev/null; done
  : "${AIEC_FIRECRACKER_BIN:?load the Firecracker environment first}"
  : "${AIEC_KERNEL:?}" "${AIEC_ROOTFS:?}" "${AIEC_GUEST_SECRET:?}"
  root=${RP_ROOT:-$HOME/aiec/reaper}
  mkdir -p "$root"
  chmod 700 "$root"
  root=$(realpath -m "$root")
  export RP_ROOT=$root RP_BIN=$bin
  export AIEC_GUARD_ACCEPTANCE_HOST_NETNS=$host_netns
  pg=$root/pg
  sock=$root/s
  if ! mkdir "$root/.lock" 2>/dev/null; then
    printf '%s\n' 'another reaper acceptance run holds the lock; wait for it' >&2
    exit 2
  fi
  pg_bin=${RP_PG_BIN:-$HOME/.paperclip/cli/installs/npm/2026.916.1/node_modules/@embedded-postgres/linux-x64/native/bin}
  acceptance_prepare_database "$root" "$pg" "$sock" "$pg_bin"
  stop_db() {
    acceptance_stop_database "$root" "$pg" "$pg_bin"
  }
  trap stop_db EXIT
  unshare --user --map-root-user --net --fork --kill-child=KILL bash "$self" --inside
  exit $?
fi
shift

[[ $(id -u) == 0 ]] || { printf '%s\n' 'acceptance must run root-mapped' >&2; exit 2; }
[[ $(readlink /proc/self/ns/net) != "${AIEC_GUARD_ACCEPTANCE_HOST_NETNS:?}" ]] || {
  printf '%s\n' 'refusing to run in the host network namespace' >&2
  exit 2
}

root=$RP_ROOT
bin=$RP_BIN
state=$root/state
mkdir -p "$state"

key=$(python3 -c 'import secrets;print(secrets.token_hex(24))')

cp_port=${RP_CP_PORT:-18544}
worker_port=${RP_WORKER_PORT:-19544}
export RP_CP="https://127.0.0.1:$cp_port"
export RP_CP_BIND=127.0.0.1:$cp_port
export RP_WORKER="https://127.0.0.1:$worker_port"
export RP_WORKER_BIND=127.0.0.1:$worker_port
export RP_TENANT=$(cat /proc/sys/kernel/random/uuid)
export RP_API_KEY="af_live_$key"
export RP_WORKER_TOKEN="af_live_$key"
export RP_CA=$HOME/aiec/tls/ca.crt
export RP_TLS_CERT=$HOME/aiec/tls/api.crt
export RP_TLS_KEY=$HOME/aiec/tls/api.key
export RP_S3_ENDPOINT=http://127.0.0.1:9000
export RP_S3_ACCESS_KEY_ID=acceptance
export RP_S3_SECRET_ACCESS_KEY="acceptance-secret-$key"
export AIEC_STATE_DIR=$root/state-vms
export AIEC_IMAGE_MANIFEST=${AIEC_IMAGE_MANIFEST:-${AGENTFORGE_IMAGE_MANIFEST:-$HOME/aiec/imgbuild/.aiec/images/manifest.json}}
export AIEC_IMAGE_MANIFEST_SECRET=${AIEC_IMAGE_MANIFEST_SECRET:-${AGENTFORGE_IMAGE_MANIFEST_SECRET:-}}

ip link set lo up
sysctl -qw net.ipv4.ip_forward=1

set +e
python3 "$root/driver.py" 2>&1 | tee "$root/driver.log"
status=${PIPESTATUS[0]}
set -e
exit "$status"
