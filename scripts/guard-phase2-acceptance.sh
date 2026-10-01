#!/usr/bin/env bash
# Disposable phase 2 acceptance: the whole stack - control plane, worker, guest,
# watchdog, database - runs inside one private user+network namespace.
#
# The namespace is what makes the kernel part of this honest: nftables, TAP
# devices and routes are real, enforced by the shipped Guard backend, and they
# exist only for the duration of the run. The host's own ruleset is never read
# for a decision, never flushed and never modified.
set -euo pipefail

self=$(realpath "$0")
host_netns=$(readlink /proc/self/ns/net)
[[ $host_netns == net:* ]] || { printf '%s\n' 'cannot read the host network namespace' >&2; exit 2; }

if [[ ${1:-} != --inside ]]; then
  bin=${P2_BIN:-$HOME/aiec/phase2-bin}
  [[ -x "$bin/aiec-server" && -x "$bin/aiec" && -x "$bin/aiec-guard-watchdog" ]] || {
    printf '%s\n' 'prebuilt phase 2 binaries required in P2_BIN' >&2
    exit 2
  }
  for tool in unshare ip nft python3 setsid; do command -v "$tool" >/dev/null; done
  : "${AIEC_FIRECRACKER_BIN:?load the Firecracker environment first}"
  : "${AIEC_KERNEL:?}" "${AIEC_ROOTFS:?}" "${AIEC_GUEST_SECRET:?}"
  : "${P2_DRIVER:?set P2_DRIVER to scripts/guard-phase2-acceptance.py}"
  root=${P2_ROOT:-$HOME/aiec/phase2}
  mkdir -p "$root"
  chmod 700 "$root"
  # A short path: a Unix socket path is limited to about a hundred bytes, and
  # the database and every other path inside are derived from this one.
  root=$(realpath -m "$root")
  export P2_ROOT=$root P2_BIN=$bin P2_DRIVER
  export AIEC_GUARD_ACCEPTANCE_HOST_NETNS=$host_netns
  # The database runs outside the namespace and is reached over a Unix socket:
  # a socket has no network namespace, so the store inside is the same store
  # outside while `initdb`, which refuses to run as a mapped root, still runs as
  # the operator who owns it.
  pg=$root/pg
  sock=$root/s
  # One run at a time: two runs share this database and this directory, and the
  # first to exit would stop the server the second is still using.
  if ! mkdir "$root/.lock" 2>/dev/null; then
    printf '%s\n' 'another phase 2 acceptance run holds the lock; wait for it' >&2
    exit 2
  fi
  trap 'rmdir "$root/.lock" 2>/dev/null || true' EXIT
  mkdir -p "$pg" "$sock"
  chmod 700 "$root"
  pg_bin=${P2_PG_BIN:-$HOME/.paperclip/cli/installs/npm/2026.916.1/node_modules/@embedded-postgres/linux-x64/native/bin}
  # A fresh cluster per run: capacity, leases and quarantined sandboxes from an
  # earlier run would otherwise make this one start against a host that is
  # already full, which is a stale-fixture failure rather than a product one.
  # A run that was interrupted leaves its postmaster holding this directory and
  # its socket lock; a fresh acceptance must not inherit either.
  "$pg_bin/pg_ctl" -D "$pg" -m immediate stop >/dev/null 2>&1 || true
  rm -rf -- "$sock"
  mkdir -p "$sock"
  rm -rf -- "$pg"
  "$pg_bin/initdb" -D "$pg" -U aiec -A trust --no-sync >"$root/initdb.log" 2>&1
  "$pg_bin/pg_ctl" -D "$pg" -o "-k $sock -h ''" -l "$root/postgres.log" -w start >/dev/null
  # The bundled server has no client binaries, so the acceptance uses the
  # database `initdb` already created rather than one it cannot ask for.
  export DATABASE_URL="postgresql://aiec@localhost/postgres?host=$sock"
  stop_db() { "$pg_bin/pg_ctl" -D "$pg" -m immediate stop >/dev/null 2>&1 || true; }
  trap stop_db EXIT
  unshare --user --map-root-user --net --fork --kill-child=KILL bash "$self" --inside
  status=$?
  exit $status
fi
shift

[[ $(id -u) == 0 ]] || { printf '%s\n' 'acceptance must run root-mapped' >&2; exit 2; }
[[ $(readlink /proc/self/ns/net) != "${AIEC_GUARD_ACCEPTANCE_HOST_NETNS:?}" ]] || {
  printf '%s\n' 'refusing to run in the host network namespace' >&2
  exit 2
}

root=$P2_ROOT
bin=$P2_BIN
state=$root/state
mkdir -p "$state"

key=$(python3 -c 'import secrets;print(secrets.token_hex(24))')

export P2_CP="https://127.0.0.1:18444"
export P2_CP_BIND=127.0.0.1:18444
export P2_WORKER="https://127.0.0.1:19444"
export P2_WORKER_BIND=127.0.0.1:19444
export P2_WORKER_BIND2=127.0.0.1:19445
export P2_TENANT=$(cat /proc/sys/kernel/random/uuid)
export P2_API_KEY="af_live_$key"
export P2_WORKER_TOKEN="af_live_$key"
export P2_CA=$HOME/aiec/tls/ca.crt
export P2_TLS_CERT=$HOME/aiec/tls/api.crt
export P2_TLS_KEY=$HOME/aiec/tls/api.key
export P2_S3_ENDPOINT=http://127.0.0.1:9000
export P2_S3_ACCESS_KEY_ID=acceptance
export P2_S3_SECRET_ACCESS_KEY="acceptance-secret-$key"
export P2_WATCHDOG_TIMEOUT_MS=${P2_WATCHDOG_TIMEOUT_MS:-3000}
# The Firecracker runtime places VMs and Guard attachments under AIEC_STATE_DIR.
# It is set explicitly here so a loaded operator environment cannot put
# acceptance machines next to a running deployment's own.
export AIEC_STATE_DIR=$root/state-vms

ip link set lo up
# Namespace-scoped forwarding. A fresh network namespace has this off, and a
# packet leaving the guest is dropped before it reaches any hook Guard counts -
# which reads as "the guest has no link" rather than as a policy decision.
sysctl -qw net.ipv4.ip_forward=1

set +e
python3 "$P2_DRIVER" 2>&1 | tee "$root/driver.log"
status=${PIPESTATUS[0]}
set -e
exit "$status"