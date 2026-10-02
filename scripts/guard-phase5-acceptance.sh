#!/usr/bin/env bash
# Disposable phase 5 acceptance: signed-image admission and per-VM control
# identities run against real local Firecracker guests, and the credential,
# file and hostname canaries run through the shipped control plane and worker
# with the worker-authenticated quarantine endpoint enabled.
#
# The namespace is what makes the kernel part of this honest: nftables, TAP
# devices and routes are real, enforced by the shipped Guard backend, and they
# exist only for the duration of the run. The host's own ruleset is never read
# for a decision, never flushed and never modified.
#
# Nothing here writes a deployed guest image. The image/identity harness copies
# kernel and rootfs bytes into its own scratch directory to produce tampered
# variants, and re-verifies the source digests afterwards.
set -euo pipefail

# Shared with the other launchers: an isolated database for this run, either a
# private cluster or one the caller names and owns alone.
source "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/acceptance-db.sh"

self=$(realpath "$0")
host_netns=$(readlink /proc/self/ns/net)
[[ $host_netns == net:* ]] || { printf '%s\n' 'cannot read the host network namespace' >&2; exit 2; }

if [[ ${1:-} != --inside ]]; then
  bin=${P5_BIN:-$HOME/aiec/phase2-bin}
  [[ -x "$bin/aiec-server" && -x "$bin/aiec" && -x "$bin/examples/guard_phase5_acceptance" \
     && -x "$bin/aiec-guard-watchdog" ]] || {
    printf '%s\n' 'prebuilt phase 5 binaries required in P5_BIN' >&2
    exit 2
  }
  for tool in unshare ip nft python3 setsid; do command -v "$tool" >/dev/null; done
  : "${AIEC_FIRECRACKER_BIN:?load the Firecracker environment first}"
  : "${AIEC_KERNEL:?}" "${AIEC_ROOTFS:?}" "${AIEC_GUEST_SECRET:?}"
  : "${P5_DRIVER:?set P5_DRIVER to scripts/guard-phase5-acceptance.py}"
  root=${P5_ROOT:-$HOME/aiec/phase5}
  mkdir -p "$root"
  chmod 700 "$root"
  # A short path: a Unix socket path is limited to about a hundred bytes, and
  # the database and every other path inside are derived from this one.
  root=$(realpath -m "$root")
  export P5_ROOT=$root P5_BIN=$bin P5_DRIVER
  export AIEC_GUARD_ACCEPTANCE_HOST_NETNS=$host_netns
  pg=$root/pg
  sock=$root/s
  # One run at a time: two runs share this database and this directory, and the
  # first to exit would stop the server the second is still using.
  if ! mkdir "$root/.lock" 2>/dev/null; then
    printf '%s\n' 'another phase 5 acceptance run holds the lock; wait for it' >&2
    exit 2
  fi
  pg_bin=${P5_PG_BIN:-$HOME/.paperclip/cli/installs/npm/2026.916.1/node_modules/@embedded-postgres/linux-x64/native/bin}
  acceptance_prepare_database "$root" "$pg" "$sock" "$pg_bin"
  stop_db() {
    acceptance_stop_database "$root" "$pg" "$pg_bin"
  }
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

root=$P5_ROOT
bin=$P5_BIN
state=$root/state
mkdir -p "$state"
chmod 700 "$state"

key=$(python3 -c 'import secrets;print(secrets.token_hex(24))')

# Ports are overridable so a second acceptance suite can run against the same
# binaries on the same host without colliding with a suite already in flight.
cp_port=${P5_CP_PORT:-18445}
worker_port=${P5_WORKER_PORT:-19445}
export P5_CP="https://127.0.0.1:$cp_port"
export P5_CP_BIND=127.0.0.1:$cp_port
export P5_WORKER="https://127.0.0.1:$worker_port"
export P5_WORKER_BIND=127.0.0.1:$worker_port
export P5_TENANT=$(cat /proc/sys/kernel/random/uuid)
export P5_API_KEY="af_live_$key"
export P5_WORKER_TOKEN="af_live_$key"
export P5_TLS_DIR=${P5_TLS_DIR:-$root/tls}
if [[ ! -f $P5_TLS_DIR/ca.crt ]]; then
  mkdir -p "$P5_TLS_DIR"
  chmod 700 "$P5_TLS_DIR"
  # Generated per run, with the extensions a TLS client in strict mode actually
  # requires: a CA without keyCertSign, or a leaf without a SAN for the address
  # this run binds, is refused by the very client that is supposed to prove the
  # control plane is the one under test. The window starts a day early so a host
  # whose clock is slightly behind cannot produce an expired-looking failure.
  # `-not_before` exists only in newer OpenSSL; without it the window starts
  # now, which is what those versions give anyway.
  openssl req -x509 -newkey rsa:2048 -nodes -days 3 -sha256 \
    -subj "/CN=AIEC phase 5 acceptance CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -not_before "$(date -u -d '-1 day' '+%Y%m%d%H%M%SZ')" \
    -keyout "$P5_TLS_DIR/ca.key" -out "$P5_TLS_DIR/ca.crt" >/dev/null 2>&1 \
    || openssl req -x509 -newkey rsa:2048 -nodes -days 3 -sha256 \
      -subj "/CN=AIEC phase 5 acceptance CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -keyout "$P5_TLS_DIR/ca.key" -out "$P5_TLS_DIR/ca.crt" >/dev/null 2>&1
  openssl verify -CAfile "$P5_TLS_DIR/ca.crt" "$P5_TLS_DIR/ca.crt" >/dev/null 2>&1 \
    || { printf 'the acceptance CA could not be generated\n' >&2; exit 2; }
  openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=127.0.0.1" \
    -keyout "$P5_TLS_DIR/api.key" -out "$P5_TLS_DIR/api.csr" >/dev/null 2>&1
  printf '%s\n' "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    "extendedKeyUsage=serverAuth" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "basicConstraints=critical,CA:FALSE" > "$P5_TLS_DIR/leaf.ext"
  openssl x509 -req -in "$P5_TLS_DIR/api.csr" -CA "$P5_TLS_DIR/ca.crt" \
    -CAkey "$P5_TLS_DIR/ca.key" -CAcreateserial -days 3 -sha256 \
    -extfile "$P5_TLS_DIR/leaf.ext" -out "$P5_TLS_DIR/api.crt" >/dev/null 2>&1
  rm -f "$P5_TLS_DIR/api.csr" "$P5_TLS_DIR/leaf.ext" "$P5_TLS_DIR/ca.srl"
  chmod 600 "$P5_TLS_DIR"/*.key
fi
export P5_CA=$P5_TLS_DIR/ca.crt
export P5_TLS_CERT=$P5_TLS_DIR/api.crt
export P5_TLS_KEY=$P5_TLS_DIR/api.key

# A Guard policy that binds a model credential refuses to start an attachment
# whose gateway cannot present it - fail-closed, and correct. The binding is
# operator material, so the launcher mints it: one owner-only file, one random
# secret, never printed and never reused.
P5_GUARD_CREDENTIALS=$root/guard-credentials.json
if [[ ! -f $P5_GUARD_CREDENTIALS ]]; then
  umask 077
  python3 - "$P5_GUARD_CREDENTIALS" <<'PY'
import json, secrets, sys
with open(sys.argv[1], "w") as handle:
    json.dump({"model-main": secrets.token_hex(32)}, handle)
PY
  chmod 600 "$P5_GUARD_CREDENTIALS"
fi
export AIEC_GUARD_CREDENTIALS_FILE=$P5_GUARD_CREDENTIALS
export P5_S3_ENDPOINT=http://127.0.0.1:9000
export P5_S3_ACCESS_KEY_ID=acceptance
export P5_S3_SECRET_ACCESS_KEY="acceptance-secret-$key"
# The Firecracker runtime places VMs and Guard attachments under AIEC_STATE_DIR.
# It is set explicitly here so a loaded operator environment cannot put
# acceptance machines next to a running deployment's own.
export AIEC_STATE_DIR=$root/state-vms
# The control plane resolves every sandbox image reference through a signed
# manifest and checks the rootfs digest in it, so the run needs a manifest that
# names this run's rootfs. An operator-supplied one is used as given and must
# exist; with none supplied the run mints its own, signed with a per-run secret
# in the scratch directory.
acceptance_prepare_image_manifest "$root" "${P5_IMAGE:-python:3.13}" \
  "$(dirname "$(realpath "$AIEC_ROOTFS")")/guest-capabilities.json"
# A distinct key per run for the image harness's own scratch trust store; it
# never leaves the scratch directory and is not the deployment signing key.
export P5_IDENTITY_SIGNING_KEY=$key

# A guarded sandbox is admitted against a signed manifest, so the worker needs
# a trust store that admits the images it is about to boot. The signing key and
# the manifest are generated per run inside the scratch directory: nothing is
# written into the deployment's image directory, and no run can inherit
# another's key. The metadata the runtime verifies the guest against travels
# with the manifest, because both are read from the artifact directory.
p5_artifact=${AIEC_GUEST_ARTIFACT_DIR:-$(dirname "$(realpath "$AIEC_ROOTFS")")}
p5_trust=$root/image-trust
mkdir -p "$p5_trust"
cp "$p5_artifact/guest-capabilities.json" "$p5_trust/" \
  || { echo "guest-capabilities.json is missing from $p5_artifact" >&2; exit 2; }
python3 -c 'import secrets,sys;sys.stdout.write(secrets.token_hex(32))' > "$root/image-signing.key"
chmod 600 "$root/image-signing.key"
"$P5_BIN/aiec" image sign \
  --key-file "$root/image-signing.key" \
  --key-id "acceptance-$key" \
  --out-dir "$p5_trust" \
  --keys-out "$root/image-signing-keys" \
  --reference "aiec/firecracker-acceptance" \
  --kernel "$AIEC_KERNEL" \
  --rootfs "$AIEC_ROOTFS" \
  --expires-in-hours 24 >/dev/null \
  || { echo "signing the acceptance image manifest failed" >&2; exit 2; }
export AIEC_GUEST_ARTIFACT_DIR=$p5_trust
export AIEC_REQUIRE_SIGNED_IMAGE=required
export AIEC_IMAGE_SIGNING_KEYS=$root/image-signing-keys

ip link set lo up
# Namespace-scoped forwarding. A fresh network namespace has this off, and a
# packet leaving the guest is dropped before it reaches any hook Guard counts -
# which reads as "the guest has no link" rather than as a policy decision.
sysctl -qw net.ipv4.ip_forward=1

set +e
python3 "$P5_DRIVER" 2>&1 | tee "$root/driver.log"
status=${PIPESTATUS[0]}
set -e
exit "$status"