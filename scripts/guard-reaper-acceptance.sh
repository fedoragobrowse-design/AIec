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
  # The driver travels with the launcher rather than being staged by hand: a
  # run that could only work after an operator copied a file into the scratch
  # directory is a run whose evidence depends on what that operator did.
  export RP_ROOT=$root RP_BIN=$bin
  export RP_DRIVER=${RP_DRIVER:-$(dirname "$self")/guard-reaper-acceptance.py}
  export AIEC_GUARD_ACCEPTANCE_HOST_NETNS=$host_netns
  pg=$root/pg
  sock=$root/s
  if ! mkdir "$root/.lock" 2>/dev/null; then
    printf '%s\n' 'another reaper acceptance run holds the lock; wait for it' >&2
    exit 2
  fi
  pg_bin=${RP_PG_BIN:-$HOME/.paperclip/cli/installs/npm/2026.916.1/node_modules/@embedded-postgres/linux-x64/native/bin}
  # Armed before the database is prepared: a launcher pointed at missing
  # binaries exits from inside that call, and a lock left behind by a
  # misconfiguration makes every later run report that another run holds it.
  stop_db() {
    acceptance_stop_database "$root" "$pg" "$pg_bin"
  }
  trap stop_db EXIT
  acceptance_prepare_database "$root" "$pg" "$sock" "$pg_bin"
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
# Per-run TLS, independent of any operator or deployment certificate. The
# servers present an end-entity certificate, so it cannot also be the trust
# anchor: a self-signed leaf used as its own CA is refused by any client that
# checks basic constraints, and reads as an untrustworthy server rather than as
# a misconfigured anchor. `keyUsage=keyCertSign` is not decoration either -
# OpenSSL 3 refuses a CA certificate without it. The deployment CA under
# ~/aiec/tls has no key usage extension at all, so pointing at it fails here for
# a reason that has nothing to do with the reaper.
tls=$root/tls
mkdir -p "$tls"
chmod 700 "$tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=aiec-reaper-acceptance-ca' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$tls/ca.key" -out "$tls/ca.crt" 2>/dev/null
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth,clientAuth' \
  'subjectAltName=IP:127.0.0.1' >"$tls/leaf.ext"
openssl req -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' \
  -keyout "$tls/leaf.key" -out "$tls/leaf.csr" 2>/dev/null
openssl x509 -req -in "$tls/leaf.csr" -CA "$tls/ca.crt" -CAkey "$tls/ca.key" \
  -CAcreateserial -days 1 -extfile "$tls/leaf.ext" -out "$tls/leaf.crt" 2>/dev/null
chmod 600 "$tls/ca.key" "$tls/leaf.key"
export RP_CA=$tls/ca.crt
export RP_TLS_CERT=$tls/leaf.crt
export RP_TLS_KEY=$tls/leaf.key
export RP_S3_ENDPOINT=http://127.0.0.1:9000
export RP_S3_ACCESS_KEY_ID=acceptance
export RP_S3_SECRET_ACCESS_KEY="acceptance-secret-$key"
export AIEC_STATE_DIR=$root/state-vms
# The guest capability metadata the runtime verifies a guest against travels
# with the artifact directory the image was built into, which is not necessarily
# the directory the rootfs is named in - a symlinked rootfs is not next to it.
artifact_dir=${AIEC_GUEST_ARTIFACT_DIR:-$(dirname "$(realpath "$AIEC_ROOTFS")")}
# An operator-supplied manifest is used as given; with none supplied the run
# mints its own, so this suite never depends on a deployment path it does not
# own. The previous default pointed into the deployment's image directory and
# did not exist, which the control plane reports only as an opaque
# file-not-found at startup.
acceptance_prepare_image_manifest "$root" aiec/firecracker-acceptance \
  "$artifact_dir/guest-capabilities.json"
export AIEC_GUEST_ARTIFACT_DIR=$artifact_dir

ip link set lo up
sysctl -qw net.ipv4.ip_forward=1

set +e
python3 "$RP_DRIVER" 2>&1 | tee "$root/driver.log"
status=${PIPESTATUS[0]}
set -e
exit "$status"
