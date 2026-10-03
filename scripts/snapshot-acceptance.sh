#!/usr/bin/env bash
# Workspace snapshot round-trip acceptance: capture a snapshot from a real
# Firecracker guest, destroy the machine it came from, restore it into a fresh
# one, and read the original file back out.
#
# This is the one integration item with no live artifact behind it. The bench
# harness has a `snapshot` scenario that does exactly this cycle, and its
# recorded run reports the snapshot failing - a real failure, not an
# unsupported-runtime 501, and therefore something to prove rather than to
# explain away.
#
# Isolation is a private user+network namespace, as in phase 2: the guest is a
# real microVM on a real TAP, Guard's nftables and TAP devices are real and
# enforced by the shipped backend, and none of it exists outside the run. The
# run brings its own object store inside that namespace rather than reaching
# the deployment's, because the product's only store is an S3 endpoint and a
# fresh namespace cannot reach a loopback MinIO on the host.
set -euo pipefail

self=$(realpath "$0")
host_netns=$(readlink /proc/self/ns/net)
[[ $host_netns == net:* ]] || { printf '%s\n' 'cannot read the host network namespace' >&2; exit 2; }

# Shared with the other launchers: an isolated database for this run, either a
# private cluster or one the caller names and owns alone.
source "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/acceptance-db.sh"

if [[ ${1:-} != --inside ]]; then
  bin=${SN_BIN:-$HOME/aiec/phase2-bin}
  [[ -x "$bin/aiec-server" && -x "$bin/aiec" ]] || {
    printf '%s\n' 'prebuilt acceptance binaries required in SN_BIN' >&2
    exit 2
  }
  for tool in unshare ip nft python3 setsid; do command -v "$tool" >/dev/null; done
  : "${AIEC_FIRECRACKER_BIN:?load the Firecracker environment first}"
  : "${AIEC_KERNEL:?}" "${AIEC_ROOTFS:?}" "${AIEC_GUEST_SECRET:?}"
  : "${SN_DRIVER:?set SN_DRIVER to scripts/snapshot-acceptance.py}"
  root=${SN_ROOT:-$HOME/aiec/snapshot}
  mkdir -p "$root"
  chmod 700 "$root"
  # A short path: a Unix socket path is limited to about a hundred bytes, and
  # the database and every other path inside are derived from this one.
  root=$(realpath -m "$root")
  export SN_ROOT=$root SN_BIN=$bin SN_DRIVER
  export AIEC_GUARD_ACCEPTANCE_HOST_NETNS=$host_netns
  pg=$root/pg
  sock=$root/s
  # One run at a time: two runs share this database and this directory, and the
  # first to exit would stop the server the second is still using. Armed before
  # the fallible database preparation below, so a launcher pointed at missing
  # binaries exits without leaving a lock nobody holds.
  if ! mkdir "$root/.lock" 2>/dev/null; then
    printf '%s\n' 'another snapshot acceptance run holds the lock; wait for it' >&2
    exit 2
  fi
  pg_bin=${SN_PG_BIN:-$HOME/.paperclip/cli/installs/npm/2026.916.1/node_modules/@embedded-postgres/linux-x64/native/bin}
  stop_db() {
    rmdir "$root/.lock" 2>/dev/null || true
    acceptance_stop_database "$root" "$pg" "$pg_bin"
  }
  trap stop_db EXIT
  acceptance_prepare_database "$root" "$pg" "$sock" "$pg_bin"
  # Reap anything this run started before stopping the database. The driver
  # launches a control plane and a worker, and `unshare --kill-child` only kills
  # the direct child, so an interrupted run otherwise leaves servers bound to
  # this run's directory and ports. Matching is on this run's own root, which is
  # unique per run, so nothing belonging to another run can be caught by it.
  unshare --user --map-root-user --net --fork --kill-child=KILL bash "$self" --inside
  status=$?
  exit $status
fi
shift

[[ $(id -u) == 0 ]] || { printf '%s\n' 'acceptance must run root-mapped' >&2; exit 2; }
if [[ ${SN_NETNS:-0} == 1 ]]; then
  [[ $(readlink /proc/self/ns/net) != "${AIEC_GUARD_ACCEPTANCE_HOST_NETNS:?}" ]] || {
    printf '%s\n' 'the acceptance namespace was not created' >&2
    exit 2
  }
fi

root=$SN_ROOT
bin=$SN_BIN
state=$root/state
mkdir -p "$state"

key=$(python3 -c 'import secrets;print(secrets.token_hex(24))')

# Ports are overridable so this suite can run beside another acceptance suite
# on the same host without colliding with it.
cp_port=${SN_CP_PORT:-18644}
worker_port=${SN_WORKER_PORT:-19644}
export SN_CP="https://127.0.0.1:$cp_port"
export SN_CP_BIND=127.0.0.1:$cp_port
export SN_WORKER="https://127.0.0.1:$worker_port"
export SN_WORKER_BIND=127.0.0.1:$worker_port
export SN_TENANT=$(cat /proc/sys/kernel/random/uuid)
export SN_API_KEY="af_live_$key"
export SN_WORKER_TOKEN="af_live_$key"
# A certificate authority of its own, minted for this run, for the same reason
# phase 2 does: borrowing an operator's long-lived key material to prove a test
# suite works would be a poor trade for files that cost nothing to regenerate.
export SN_CA=$root/tls/ca.crt
export SN_TLS_CERT=$root/tls/api.crt
export SN_TLS_KEY=$root/tls/api.key
mkdir -p "$root/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$root/tls/ca.key" -out "$SN_CA" \
  -subj "/CN=aiec-snapshot-acceptance-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$SN_TLS_KEY" -out "$root/tls/api.csr" \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=IP:127.0.0.1' >"$root/tls/ext.cnf"
openssl x509 -req -in "$root/tls/api.csr" -CA "$SN_CA" -CAkey "$root/tls/ca.key" \
  -CAcreateserial -out "$SN_TLS_CERT" -days 2 -sha256 \
  -extfile "$root/tls/ext.cnf" >/dev/null 2>&1
# The workspace archive is what a restore reads back, so the run needs object
# storage to put it in, and it has to be a real one: a snapshot the control
# plane cannot store is not a snapshot, and an in-process stub would prove the
# stub rather than the product.
#
# The product's only store is an S3 endpoint, and a fresh network namespace
# cannot reach the deployment's loopback MinIO - the first attempt at this suite
# failed with the capture call returning 500 because of exactly that. So the
# run starts its own MinIO inside the namespace, on its own port, with its own
# data directory and credentials minted for this run. That keeps the namespace
# (and therefore Guard's nftables and TAP devices) real and untouched by the
# host's own state, while the store the snapshot path uses is a genuine S3
# service rather than something this suite made up.
if [[ -z ${SN_S3_ENDPOINT:-} ]]; then
  minio_bin=${SN_MINIO_BIN:-$HOME/aiec/bin/minio}
  [[ -x "$minio_bin" ]] || {
    printf 'a MinIO server binary is required in SN_MINIO_BIN (%s)\n' "$minio_bin" >&2
    exit 2
  }
  s3_port=${SN_S3_PORT:-19000}
  export SN_S3_ENDPOINT="http://127.0.0.1:$s3_port"
  export SN_S3_ACCESS_KEY_ID="snapshot$key"
  export SN_S3_SECRET_ACCESS_KEY="snapshot-secret-$key"
  mkdir -p "$root/minio-data"
  # Bound by port rather than by address: inside the namespace MinIO refuses a
  # literal 127.0.0.1 ("host in server address should be this server"), since
  # the name it resolves that against is the namespace's own. The namespace has
  # no route off it, so an all-interfaces bind reaches nothing but this run.
  # The server also panics printing its startup banner when it can enumerate no
  # usable address, and a fresh namespace has none until loopback is up.
  ip link set lo up
  MINIO_ROOT_USER=$SN_S3_ACCESS_KEY_ID MINIO_ROOT_PASSWORD=$SN_S3_SECRET_ACCESS_KEY \
    setsid "$minio_bin" server "$root/minio-data" --address ":$s3_port" \
    --console-address ":$((s3_port + 1))" --quiet >"$root/minio.log" 2>&1 &
  minio_pid=$!
  for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null --max-time 2 "$SN_S3_ENDPOINT/minio/health/live"; then break; fi
    kill -0 "$minio_pid" 2>/dev/null || { printf '%s\n' 'the run object store exited' >&2; exit 2; }
    sleep 1
  done
  curl -fsS -o /dev/null --max-time 2 "$SN_S3_ENDPOINT/minio/health/live" || {
    printf '%s\n' 'the run object store did not become healthy' >&2
    exit 2
  }
  # The bucket is created over the real S3 API rather than by writing into the
  # store's directory: signing a CreateBucket is ordinary S3 traffic, so this
  # exercises the same protocol the product's store does rather than reaching
  # around it.
  SN_S3_BUCKET=aiec python3 - <<'PY' || { printf '%s\n' 'could not create the run bucket' >&2; exit 2; }
import datetime, hashlib, hmac, os, urllib.error, urllib.request

endpoint, access, secret, bucket = (
    os.environ["SN_S3_ENDPOINT"], os.environ["SN_S3_ACCESS_KEY_ID"],
    os.environ["SN_S3_SECRET_ACCESS_KEY"], os.environ["SN_S3_BUCKET"])
host = endpoint.split("://", 1)[1]
now = datetime.datetime.now(datetime.timezone.utc)
amz_date, stamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
payload_hash = hashlib.sha256(b"").hexdigest()
# The canonical request ends its headers block with a newline before the
# signed-header list; joining fields without that produces a signature the
# server rejects with 403.
signed_headers = "host;x-amz-content-sha256;x-amz-date"
canonical_headers = (
    f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n")
canonical = "\n".join(["PUT", f"/{bucket}", "", canonical_headers, signed_headers, payload_hash])
scope = f"{stamp}/us-east-1/s3/aws4_request"
string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                            hashlib.sha256(canonical.encode()).hexdigest()])
signing = ("AWS4" + secret).encode()
for part in (stamp, "us-east-1", "s3", "aws4_request"):
    signing = hmac.new(signing, part.encode(), hashlib.sha256).digest()
headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date,
           "authorization": f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
                            f"SignedHeaders={signed_headers}, "
                            f"Signature={hmac.new(signing, string_to_sign.encode(), hashlib.sha256).hexdigest()}"}
try:
    urllib.request.urlopen(urllib.request.Request(f"{endpoint}/{bucket}", method="PUT", headers=headers))
except urllib.error.HTTPError as error:
    # 409 Conflict means the bucket is already there, which is the same state
    # this call was asking for.
    if error.code != 409:
        raise
PY
else
  export SN_S3_ACCESS_KEY_ID=${AIEC_S3_ACCESS_KEY_ID:?set the object store credentials}
  export SN_S3_SECRET_ACCESS_KEY=${AIEC_S3_SECRET_ACCESS_KEY:?set the object store credentials}
fi
# The Firecracker runtime places VMs under AIEC_STATE_DIR. It is set explicitly
# here so a loaded operator environment cannot put acceptance machines next to
# a running deployment's own.
export AIEC_STATE_DIR=$root/state-vms
# The guest capability metadata the runtime verifies a guest against travels
# with the artifact directory the image was built into.
artifact_dir=${AIEC_GUEST_ARTIFACT_DIR:-$(dirname "$(realpath "$AIEC_ROOTFS")")}
acceptance_prepare_image_manifest "$root" aiec/firecracker-acceptance \
  "$artifact_dir/guest-capabilities.json"
export AIEC_GUEST_ARTIFACT_DIR=$artifact_dir

if [[ ${SN_NETNS:-0} == 1 ]]; then
  ip link set lo up
  sysctl -qw net.ipv4.ip_forward=1
fi

set +e
python3 "$SN_DRIVER" 2>&1 | tee "$root/driver.log"
status=${PIPESTATUS[0]}
set -e
exit "$status"
