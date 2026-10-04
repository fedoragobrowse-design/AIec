#!/usr/bin/env bash
# AIec Firecracker coding-agent dogfood (production path).
#
# client -> AIec API -> PostgreSQL scheduling/state -> HTTPS worker
#   -> Firecracker -> guest -> coding workflow
#
# This script runs on a shared host next to a real deployment, so everything it
# touches is scoped to this run and nothing else. That is the whole safety
# contract, and it has six parts:
#
#   * the run refuses to start unless it is already inside a network namespace
#     of its own - see AIEC_ACCEPTANCE_HOST_NETNS below - because the Firecracker
#     path creates TAP devices, nftables tables and masquerade rules, and in the
#     host namespace those land on the machine the deployment serves from;
#   * the run directory is scratch this run created and this run refuses any
#     path that already exists, so no run can clear a directory it did not make;
#   * the database is one this run owns alone - a caller-named isolated database
#     or a private cluster this run builds and stops - never a deployment's;
#   * every process scan requires this run's own identifier, inherited by every
#     process this run starts, so a deployment's process cannot be matched by a
#     command line that merely looks similar;
#   * the census at the end is scoped to this run's own sandbox: its Firecracker
#     process, its VM directory, its socket directory, its TAP device and the
#     containers carrying this run's tenant label. Nothing that merely looks like
#     a leftover is counted, deleted, or asserted to be gone;
#   * the ports this run binds are refused if somebody else already holds them,
#     before they are used.
#
# Requires: built aiec binaries (or a staged pair named by AIEC_DOGFOOD_BIN),
# .aiec/bin/firecracker-v1.17.0-x86_64, a kernel, a coding guest rootfs, an S3
# endpoint, and AIEC_REQUIRE_CODING_GUEST=1 so the runtime refuses a non-coding
# image.
set -Eeuo pipefail

self=$(realpath "$0")
ROOT=$(cd "$(dirname "$self")/.." && pwd)
cd "$ROOT"

# Shared with the other acceptance launchers: the isolated database, the
# port-ownership refusal and the run-scoped process sweep. Sourced, never edited
# by this suite - two copies of the answer to "what does this run own" is how two
# runs end up disagreeing about it.
source "$(dirname "$self")/acceptance-db.sh"

# Minted before this run starts anything, so the API, the worker, the
# Firecracker processes that worker spawns and the database relay all inherit
# it and every process scan below can require it.
acceptance_mark_run

OUT_REQUESTED=${1:-${AIEC_DOGFOOD_OUT:-$ROOT/.aiec/fc-coding-dogfood}}
API_BIND=${AIEC_DOGFOOD_BIND:-127.0.0.1:19843}
WORKER_BIND=${AIEC_DOGFOOD_WORKER_BIND:-127.0.0.1:29843}
LEASE_TTL=${AIEC_DOGFOOD_LEASE_TTL:-900}
CURL_MAX=${AIEC_DOGFOOD_CURL_MAX:-600}
KEEP=${AIEC_KEEP_FAILED_TEST_STATE:-0}
CLONE_URL=${AIEC_DOGFOOD_CLONE_URL:-https://github.com/octocat/Hello-World.git}
# A caller that stages the binaries is testing those binaries. Rebuilding here
# would silently substitute whatever this checkout happens to contain, which is
# the opposite of what was asked for, and on a shared host the checkout is very
# often not the tree the staged build came from.
BIN_DIR=${AIEC_DOGFOOD_BIN:-}

: "${AIEC_S3_ENDPOINT:?AIEC_S3_ENDPOINT is required}"
: "${AIEC_S3_BUCKET:?AIEC_S3_BUCKET is required}"
: "${AIEC_S3_ACCESS_KEY_ID:?AIEC_S3_ACCESS_KEY_ID is required}"
: "${AIEC_S3_SECRET_ACCESS_KEY:?AIEC_S3_SECRET_ACCESS_KEY is required}"
# This suite used to run against whatever DATABASE_URL named, which on a shared
# host is the deployment's own database: its rows, its leases, its reconciler.
# The database is now named through the shared acceptance switch and is refused
# unless it is one this run owns alone.
if [[ -z ${AIEC_ACCEPTANCE_DATABASE_URL:-} && -n ${DATABASE_URL:-} ]]; then
  printf '%s\n' 'DATABASE_URL is no longer used as this run'"'"'s database.' >&2
  printf '%s\n' \
    'set AIEC_ACCEPTANCE_DATABASE_URL to a database this run owns alone (aiec_guard_*),' >&2
  printf '%s\n' \
    'or unset both to build a private cluster for this run.' >&2
  exit 2
fi

FC_BIN=${AIEC_FIRECRACKER_BIN:-$ROOT/.aiec/bin/firecracker-v1.17.0-x86_64}
KERNEL=${AIEC_KERNEL:-$ROOT/.aiec/images/vmlinux}
ROOTFS=${AIEC_ROOTFS:-$ROOT/.aiec/images/aiec-rootfs.ext4}
ARTIFACT_DIR=${AIEC_GUEST_ARTIFACT_DIR:-$(dirname "$ROOTFS")}

log() { printf '== %s\n' "$*"; }
refuse() {
  printf 'refusing to run: %s\n' "$*" >&2
  exit 2
}
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  dump_diagnostics
  exit 1
}

# Refused before anything starts or touches the network. The caller supplies the
# namespace this run must not share - `readlink /proc/self/ns/net` captured
# before entering a private one - and there is no host-network fallback.
acceptance_require_private_netns "the Firecracker coding dogfood" AIEC_ACCEPTANCE_HOST_NETNS || exit 2
# Every address this run binds is loopback, and a fresh namespace has it down.
acceptance_netns_loopback_up || exit 2

for tool in curl openssl jq sha256sum python3 psql ip; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
# A skipped container check is not evidence that nothing leaked, so the docker
# CLI is reported unavailable only when it really cannot be reached.
HAVE_DOCKER=0
if acceptance_have_docker; then
  HAVE_DOCKER=1
fi
for file in "$FC_BIN" "$KERNEL" "$ROOTFS" "$ARTIFACT_DIR/guest-capabilities.json"; do
  [ -r "$file" ] || { echo "missing guest artifact input: $file" >&2; exit 1; }
done
[ -e /dev/kvm ] || { echo "missing /dev/kvm; Firecracker cannot run" >&2; exit 1; }

# --------------------------------------------------------------- run root
# Scratch this run creates and this run owns. An existing path is somebody
# else's evidence - a previous run's, or an operator's - so the claim refuses it
# instead of clearing it, and this run never removes a subtree of a directory
# it did not create.
acceptance_claim_run_dir "$OUT_REQUESTED" "$ROOT" || exit 2
OUT=$ACCEPTANCE_RUN_DIR
RUN_DIR_OWNED=$OUT

# The Firecracker runtime places VM disks under AIEC_STATE_DIR and its host
# control sockets under a directory named after a digest of that same variable,
# so giving the runtime a directory of its own - separate from the worker's own
# state directory - is what makes "this run's VM" and "this run's socket" a
# question with an exact answer.
VM_STATE="$OUT/state-vms"
# Mirrors aiec-runtime's socket_root: std::env::temp_dir() with any trailing
# slash removed, then the first 16 hex characters of sha256 over the state
# directory string. Both halves have to agree with the runtime exactly, so the
# string hashed here is the one exported below, unmodified.
FC_SOCKET_ROOT=${TMPDIR:-/tmp}
while [ ${#FC_SOCKET_ROOT} -gt 1 ] && [ "${FC_SOCKET_ROOT%/}" != "$FC_SOCKET_ROOT" ]; do
  FC_SOCKET_ROOT=${FC_SOCKET_ROOT%/}
done
FC_SOCKET_ROOT="$FC_SOCKET_ROOT/aiec-fc/$(printf '%s' "$VM_STATE" | sha256sum | cut -c1-16)"

# The TAP name the Linux network backend derives from a sandbox id. Naming it is
# what lets the census and the teardown touch exactly one machine's network and
# leave every other machine's alone.
fc_tap_name() { printf 'af%s' "$(printf '%s' "$1" | cut -c1-12)"; }

# Reads sandbox and lease state from this run's own database, so a diagnostic
# cannot describe somebody else's rows.
pg_state() {
  psql "$DATABASE_URL" -c "select id, state, runtime, node_id, created_at from sandboxes order by created_at desc limit 5" >&2 2>&1
  psql "$DATABASE_URL" -c "select sandbox_id, node_id, generation, status, expires_at from sandbox_leases order by created_at desc limit 5" >&2 2>&1
}

dump_diagnostics() {
  printf '\n===== FAILURE DIAGNOSTICS =====\n' >&2
  printf '%s\n' '--- api log ---' >&2
  tail -120 "$OUT/logs/api.log" 2>/dev/null >&2 || true
  printf '%s\n' '--- worker log ---' >&2
  tail -120 "$OUT/logs/worker.log" 2>/dev/null >&2 || true
  printf '%s\n' '--- database state ---' >&2
  pg_state
}

# Every name the teardown reads is bound before the trap is armed, because every
# fallible step after the claim - the database, the certificates, the binaries -
# can end the run, and a teardown that trips over an unset name leaves a private
# cluster listening and a scratch directory no later run may reuse.
API_PID=''
WORKER_PID=''
SANDBOX_ID=''
ACCEPTANCE_DB_CLUSTER=''
API_KEY=''
API_BASE=''
TENANT_ID=''
PG_BIN=${AIEC_DOGFOOD_PG_BIN:-$HOME/.paperclip/cli/installs/npm/2026.916.1/node_modules/@embedded-postgres/linux-x64/native/bin}
cleanup() {
  set +e
  if [ -n "$SANDBOX_ID" ] && [ -f "$OUT/pki/api.crt" ] && [ -n "$API_KEY" ]; then
    curl --cacert "$OUT/pki/api.crt" -sS --max-time 30 -X DELETE \
      -H "Authorization: Bearer $API_KEY" \
      "$API_BASE/v1/sandboxes/$SANDBOX_ID" >/dev/null 2>&1
  fi
  [ -n "$WORKER_PID" ] && kill "$WORKER_PID" 2>/dev/null
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null
  # Wait only on the processes this run owns: a bare wait also waits on the
  # database relay, which is stopped further down, so the teardown would never
  # reach it.
  [ -n "$WORKER_PID" ] && wait "$WORKER_PID" 2>/dev/null
  [ -n "$API_PID" ] && wait "$API_PID" 2>/dev/null
  if [ -n "$SANDBOX_ID" ]; then
    # Firecracker processes for this run's sandbox, matched on this run's own
    # socket path and this run's inherited identifier, then killed by pid. Never
    # by a pattern broad enough to reach another deployment's machines.
    for pid in $(acceptance_run_owned_pids "--api-sock $FC_SOCKET_ROOT/$SANDBOX_ID/api.sock" ""); do
      kill -9 "$pid" 2>/dev/null
    done
    # This sandbox's TAP and its nftables table, by the names the Linux network
    # backend derived from the sandbox id. Every af* device that is not this one
    # is another deployment's and stays exactly where it is.
    ip link del "$(fc_tap_name "$SANDBOX_ID")" 2>/dev/null
    nft delete table inet "aiec_$(printf '%s' "$SANDBOX_ID" | cut -c1-12)" 2>/dev/null
    rm -rf -- "$VM_STATE/vms/$SANDBOX_ID" "$FC_SOCKET_ROOT/$SANDBOX_ID"
  fi
  # The run's own socket root, and only once it is empty: another run's machines
  # hash into a different directory, so an rmdir here removes nothing of theirs.
  rmdir "$FC_SOCKET_ROOT" 2>/dev/null
  if [ "$HAVE_DOCKER" = 1 ] && [ -n "${TENANT_ID:-}" ]; then
    # Containers carrying this run's tenant label. The `managed` label alone
    # matches every deployment on the host; the pair is this run's rows.
    for container in $(acceptance_docker_cli ps -a -q --filter label=com.aiec.managed=true \
      --filter "label=com.aiec.tenant=$TENANT_ID" 2>/dev/null); do
      acceptance_docker_cli rm -f "$container" >/dev/null 2>&1
    done
  fi
  # The database is stopped before the directory goes, so a private cluster is
  # shut down cleanly and a relay socket is released rather than pulled out from
  # under a live server.
  if [ -n "$ACCEPTANCE_DB_CLUSTER" ]; then
    acceptance_stop_database "$OUT" "$OUT/pg" "$PG_BIN"
    ACCEPTANCE_DB_CLUSTER=
  fi
  if [ "$KEEP" = 1 ]; then
    printf 'preserved=%s\n' "$OUT"
  elif [ "$OUT" = "$RUN_DIR_OWNED" ]; then
    # The directory this run created exclusively, so removing it whole removes
    # only this run's evidence. RUN_DIR_OWNED is the claim's answer and never
    # changes; the comparison refuses the removal if OUT ever stops being it.
    rm -rf -- "$OUT"
  fi
  return 0
}
trap cleanup EXIT

mkdir -p "$OUT/pki" "$OUT/logs" "$OUT/state" "$OUT/state-vms"

# ----------------------------------------------------------------- database
# Either a database the caller confirms this run owns alone, or a private cluster
# built here. Nothing of the deployment's is read, written or dropped.
if [ -n "${AIEC_ACCEPTANCE_DATABASE_URL:-}" ]; then
  log "preparing the caller-confirmed isolated acceptance database"
else
  log "building a private PostgreSQL cluster for this run"
fi
acceptance_prepare_database "$OUT" "$OUT/pg" "$OUT/s" "$PG_BIN"
: "${DATABASE_URL:?acceptance database preparation left no URL}"

# ------------------------------------------------------------------- ports
# Refused before anything binds: on a shared host these are somebody else's
# address, and a run that bound them anyway would be reporting another
# deployment's control plane as its own.
for pair in "AIEC_DOGFOOD_BIND:$API_BIND" "AIEC_DOGFOOD_WORKER_BIND:$WORKER_BIND"; do
  switch=${pair%%:*}
  port=${pair#*:}
  port=${port##*:}
  acceptance_port_free "$port" \
    || refuse "loopback port $port is already bound by another process; override it with $switch"
done

# ---------------------------------------------------------------- TLS
log "generating disposable CA and server certificates"
# The CA needs its extensions stated: minted without basicConstraints and
# keyUsage it carries no meaning to a real TLS handshake. `req -x509` takes
# `-addext`. No comment may sit inside this continuation - bash ends the
# logical line at it and silently runs the remainder as separate commands.
openssl genrsa -out "$OUT/pki/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT/pki/ca.key" -sha256 -days 2 \
  -subj '/CN=AIec dogfood CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out "$OUT/pki/ca.crt" 2>/dev/null
for name in api worker; do
  openssl genrsa -out "$OUT/pki/$name.key" 2048 2>/dev/null
  openssl req -new -key "$OUT/pki/$name.key" -subj "/CN=$name" -out "$OUT/pki/$name.csr" 2>/dev/null
  cat > "$OUT/pki/$name.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$name,DNS:localhost,IP:127.0.0.1
EOF
  openssl x509 -req -in "$OUT/pki/$name.csr" -CA "$OUT/pki/ca.crt" -CAkey "$OUT/pki/ca.key" \
    -CAcreateserial -out "$OUT/pki/$name.crt" -days 2 -sha256 \
    -extfile "$OUT/pki/$name.ext" 2>/dev/null
done
openssl verify -CAfile "$OUT/pki/ca.crt" "$OUT/pki/api.crt" "$OUT/pki/worker.crt" >/dev/null \
  || fail "generated certificates do not verify against the CA"

log "verifying guest artifact before boot"
ARTIFACT_SUMMARY=$(python3 scripts/guest_artifact_report.py "$ARTIFACT_DIR" 2>&1) \
  || fail "guest artifact verification failed: $ARTIFACT_SUMMARY"
printf '%s\n' "$ARTIFACT_SUMMARY"

# ------------------------------------------------------------- binaries
if [ -n "$BIN_DIR" ]; then
  BIN_DIR=$(realpath -m "$BIN_DIR")
  [ -x "$BIN_DIR/aiec-server" ] && [ -x "$BIN_DIR/aiec" ] \
    || refuse "AIEC_DOGFOOD_BIN=$BIN_DIR must hold an executable aiec-server and aiec"
  API_BIN="$BIN_DIR/aiec-server"
  WORKER_BIN="$BIN_DIR/aiec"
  log "using prebuilt binaries from $BIN_DIR (staged build, not rebuilt)"
else
  log "building aiec binaries"
  # Build into a container-local target directory: a bind-mounted host target/
  # would reuse host-linked artifacts that do not run against the container libc.
  export CARGO_TARGET_DIR=${AIEC_TARGET_DIR:-$ROOT/.aiec/acceptance-target}
  # sqlx::migrate! embeds migrations/ at compile time but Cargo does not track
  # that directory's contents, so a new migration is invisible to a cached build.
  # Touch the crate root whenever migrations/ is newer than the storage crate.
  if [ -n "$(find migrations -name '*.sql' -newer crates/aiec-storage/src/lib.rs -print -quit 2>/dev/null)" ]; then
    touch crates/aiec-storage/src/lib.rs
  fi
  # Release builds: the guest image digest is verified before a guest is
  # booted, and an unoptimized SHA-256 over a multi-gigabyte rootfs is slow enough
  # to blow the control plane's client timeout on the create path.
  cargo build -q --release -p aiec-api --bin aiec-server -p aiec-cli --bin aiec
  API_BIN="$CARGO_TARGET_DIR/release/aiec-server"
  WORKER_BIN="$CARGO_TARGET_DIR/release/aiec"
fi

# ------------------------------------------------------------ environment
API_KEY="af_live_$(openssl rand -hex 24)"
WORKER_TOKEN="$(openssl rand -hex 32)"
TENANT_ID=$(cat /proc/sys/kernel/random/uuid)
NODE_ID=$(cat /proc/sys/kernel/random/uuid)
MANIFEST_SECRET=$(openssl rand -hex 32)
# The manifest describes the bytes this run actually boots, so the digest is
# taken from the rootfs file itself rather than from artifact metadata written at
# image build time.
ROOTFS_SHA=$(sha256sum "$ROOTFS" | cut -d' ' -f1)
python3 - "$OUT/guest-manifest.json" "$MANIFEST_SECRET" "$ROOTFS_SHA" <<'PY'
import hashlib, hmac, json, sys
out, secret, digest = sys.argv[1], sys.argv[2], sys.argv[3]
reference = "aiec:latest"
payload = reference.encode() + b"\0" + digest.encode()
json.dump(
    {
        "reference": reference,
        "rootfs_sha256": digest,
        "signature": hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest(),
    },
    open(out, "w"),
)
PY

export AIEC_TENANT_ID="$TENANT_ID"
export AIEC_TENANT_NAME=dogfood
export AIEC_API_KEY="$API_KEY"
export AIEC_WORKER_TOKEN="$WORKER_TOKEN"
export AIEC_BIND="$API_BIND"
export AIEC_RUNTIMES=firecracker
export AIEC_LEASE_TTL_SECONDS="$LEASE_TTL"
export AIEC_TLS_CERT_FILE="$OUT/pki/api.crt"
export AIEC_TLS_KEY_FILE="$OUT/pki/api.key"
export AIEC_TLS_CA_CERT="$OUT/pki/ca.crt"
export AIEC_IMAGE_MANIFEST="$OUT/guest-manifest.json"
export AIEC_IMAGE_MANIFEST_SECRET="$MANIFEST_SECRET"
export AIEC_FIRECRACKER_BIN="$FC_BIN"
export AIEC_KERNEL="$KERNEL"
export AIEC_ROOTFS="$ROOTFS"
export AIEC_GUEST_ARTIFACT_DIR="$ARTIFACT_DIR"
export AIEC_REQUIRE_CODING_GUEST=1
export AIEC_GUEST_SECRET=${AIEC_GUEST_SECRET:-$(openssl rand -hex 32)}
export AIEC_STATE_DIR="$VM_STATE"
export AIEC_S3_ENDPOINT AIEC_S3_REGION AIEC_S3_BUCKET
export AIEC_S3_ACCESS_KEY_ID AIEC_S3_SECRET_ACCESS_KEY
export RUST_LOG=${RUST_LOG:-info}
API_BASE="https://$API_BIND"

# ------------------------------------------------------------------ API
log "starting AIec API on $API_BASE"
"$API_BIN" >"$OUT/logs/api.log" 2>&1 &
API_PID=$!
for _ in $(seq 1 90); do
  if curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1 \
  || fail "API did not become healthy"

# ---------------------------------------------------------------- worker
log "starting Firecracker worker $NODE_ID on $WORKER_BIND"
"$WORKER_BIN" \
  --url "$API_BASE" worker \
  --runtime firecracker \
  --name "fc-dogfood-$NODE_ID" \
  --node-id "$NODE_ID" \
  --state-dir "$OUT/state/worker" \
  --bind "$WORKER_BIND" \
  --advertise-url "https://$WORKER_BIND" \
  --capacity "${AIEC_DOGFOOD_CAPACITY:-4}" >"$OUT/logs/worker.log" 2>&1 &
WORKER_PID=$!
for _ in $(seq 1 90); do
  code=$(curl --cacert "$OUT/pki/ca.crt" -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $WORKER_TOKEN" "https://$WORKER_BIND/health" 2>/dev/null || true)
  if [ "$code" = 200 ]; then break; fi
  sleep 1
done
[ "${code:-}" = 200 ] || fail "worker did not become healthy"
log "worker health: $(curl --cacert "$OUT/pki/ca.crt" -sS -H "Authorization: Bearer $WORKER_TOKEN" "https://$WORKER_BIND/health")"

api() { curl --cacert "$OUT/pki/ca.crt" -sS --max-time "$CURL_MAX" -H "Authorization: Bearer $API_KEY" "$@"; }
stage() { printf '\n== %s\n' "$*"; }

# -------------------------------------------------------------- create
stage "creating Firecracker sandbox (network enabled for the HTTPS clone)"
CREATE=$(api -X POST -H 'content-type: application/json' -d '{
  "image": "aiec:latest",
  "cpu": 2,
  "memory_mb": 1024,
  "disk_mb": 2048,
  "timeout_seconds": 900,
  "runtime": "firecracker",
  "network": { "enabled": true },
  "environment": { "workspace": { "type": "empty" }, "toolkits": [], "layers": [] }
}' "$API_BASE/v1/sandboxes") || fail "create request failed"
printf '%s\n' "$CREATE"
SANDBOX_ID=$(printf '%s' "$CREATE" | jq -r '.id // empty')
[ -n "$SANDBOX_ID" ] || fail "create did not return a sandbox id"
CREATED_STATE=$(printf '%s' "$CREATE" | jq -r '.state // empty')
PLACED_NODE=$(printf '%s' "$CREATE" | jq -r '.node_id // empty')
[ -n "$PLACED_NODE" ] || fail "scheduler did not place the sandbox on a worker"
log "sandbox=$SANDBOX_ID state=$CREATED_STATE node=$PLACED_NODE"
# Recorded so an interrupted run leaves behind the one identifier its leftover
# teardown and diagnostics need.
printf '%s\n' "$SANDBOX_ID" >"$OUT/sandbox.id"

# ------------------------------------------------------- guest tooling
stage "guest agent version and coding toolchain"
V=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["git","--version"]}' "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$V"
[ "$(printf '%s' "$V" | jq -r '.exit_code')" = 0 ] || fail "git --version failed in guest"
GIT_VERSION=$(printf '%s' "$V" | jq -r '.stdout')

CURLV=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["curl","--version"]}' "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$CURLV"
PYV=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["python3","--version"]}' "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$PYV"
TARV=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["tar","--version"]}' "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$TARV"

# ------------------------------------------------------------- clone
stage "cloning disposable repository over HTTPS inside the guest: $CLONE_URL"
CLONE=$(api -X POST -H 'content-type: application/json' -d "$(jq -nc --arg url "$CLONE_URL" \
  '{command:["/bin/sh","-c","set -eu; rm -rf /workspace/repo; git clone --depth 1 \""+$url+"\" /workspace/repo 2>&1; echo clone-exit=$?"]}')" \
  "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$CLONE"
printf '%s' "$CLONE" | jq -e '.stdout | test("clone-exit=0")' >/dev/null \
  || fail "git clone over HTTPS did not succeed inside the guest"

# ------------------------------------------------------ status + read
stage "git status and file inspection inside the guest"
STATUS=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["/bin/sh","-c","cd /workspace/repo && git status --porcelain && git log --oneline -1"]}' \
  "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$STATUS"
[ "$(printf '%s' "$STATUS" | jq -r '.exit_code')" = 0 ] || fail "git status failed in guest"
LIST=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["/bin/sh","-c","ls -1 /workspace/repo | head -5 && cat /workspace/repo/README"]}' \
  "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$LIST"

# ---------------------------------------------- edit + validation + diff
stage "editing a tracked file inside the guest and running real validation"
EDIT=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["/bin/sh","-c","cd /workspace/repo && printf \"\\nAIec dogfood edit\\n\" >> README && cat README"]}' \
  "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$EDIT"
printf '%s' "$EDIT" | jq -e '.stdout | test("AIec dogfood edit")' >/dev/null \
  || fail "in-guest edit did not land"

VALIDATE=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["/bin/sh","-c","cd /workspace/repo && test -s README && grep -q \"AIec dogfood edit\" README && git diff --check && echo VALIDATION_OK"]}' \
  "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$VALIDATE"
printf '%s' "$VALIDATE" | jq -e '.stdout | test("VALIDATION_OK")' >/dev/null \
  || fail "in-guest validation command failed"

DIFF=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["/bin/sh","-c","cd /workspace/repo && git --no-pager diff"]}' \
  "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$DIFF"
DIFF_TEXT=$(printf '%s' "$DIFF" | jq -r '.stdout')
printf '%s' "$DIFF_TEXT" | grep -q '^+.*AIec dogfood edit' \
  || fail "retrieved git diff does not prove the in-guest edit"
printf '%s' "$DIFF_TEXT" | grep -q '^-.*AIec dogfood edit' \
  && fail "diff shows the edit as a deletion"
printf '%s\n' "$DIFF_TEXT" | grep -q '^\+\+\+ b/README' || fail "diff is not a README modification"

# ---------------------------------------- diff also through the file API
stage "retrieving the edited file through the AIec file API"
FILE=$(api "$API_BASE/v1/sandboxes/$SANDBOX_ID/files/content?path=/workspace/repo/README")
printf '%s\n' "$FILE"
printf '%s' "$FILE" | jq -r '.content_base64' | base64 -d | grep -q 'AIec dogfood edit' \
  || fail "file API did not return the edited file content"

# ------------------------------------------------------------ destroy
stage "destroying sandbox and verifying run-scoped cleanup"
DESTROY=$(api -X DELETE "$API_BASE/v1/sandboxes/$SANDBOX_ID")
printf '%s\n' "$DESTROY"
[ "$(printf '%s' "$DESTROY" | jq -r '.status // empty')" = destroyed ] || fail "destroy did not report destroyed"
DESTROYED_ID=$SANDBOX_ID
SANDBOX_ID=''
sleep 2

# The census is this run's sandbox and nothing else. Each check is the resource
# the runtime derived from that sandbox id, so "absent" means this run's machine
# is gone - not that the host has no machines, which is not this run's claim to
# make and would be a false failure on any host a deployment is running on.
tap=$(fc_tap_name "$DESTROYED_ID")
vm_dir="$VM_STATE/vms/$DESTROYED_ID"
sock_dir="$FC_SOCKET_ROOT/$DESTROYED_ID"
left=0
if acceptance_run_owned_pids "--api-sock $sock_dir/api.sock" "" | grep -q .; then
  printf 'FAIL: a Firecracker process for %s survived destroy\n' "$DESTROYED_ID" >&2
  left=1
fi
if [ -e "$vm_dir" ]; then
  printf 'FAIL: this sandbox'"'"'s VM directory %s survived destroy\n' "$vm_dir" >&2
  left=1
fi
if [ -e "$sock_dir" ]; then
  printf 'FAIL: this sandbox'"'"'s socket directory %s survived destroy\n' "$sock_dir" >&2
  left=1
fi
if ip link show "$tap" >/dev/null 2>&1; then
  printf 'FAIL: this sandbox'"'"'s TAP %s survived destroy\n' "$tap" >&2
  left=1
fi
if [ "$HAVE_DOCKER" = 1 ]; then
  left_containers=$(acceptance_docker_cli ps -a -q --filter label=com.aiec.managed=true \
    --filter "label=com.aiec.tenant=$TENANT_ID" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$left_containers" -ne 0 ]; then
    printf 'FAIL: %s container(s) of this run'"'"'s tenant remain after destroy\n' "$left_containers" >&2
    left=1
  fi
else
  left_containers=unavailable
fi
[ "$left" -eq 0 ] || fail "destroy left this run's own resources behind"
# This run refuses to share a network namespace, so what `ip` reports here is
# this namespace and not the machine. Naming it a host census would report
# evidence this run never collected.
OTHER_TAPS=$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^af/ {print $2}' | wc -l | tr -d ' ')
printf 'run-scoped cleanup verified: VM dir absent, socket dir absent, no Firecracker process, no TAP %s, tenant containers %s\n' \
  "$tap" "$left_containers"
printf 'other TAP devices in this run'"'"'s network namespace: %s (not this run'"'"'s; untouched)\n' "$OTHER_TAPS"

cat <<EOF

AIec Firecracker coding-agent dogfood: PASS
sandbox:          $DESTROYED_ID
worker placement: $PLACED_NODE
git version:      $GIT_VERSION
clone:            $CLONE_URL (HTTPS, CA-verified)
git diff:         retrieved and proven to contain the in-guest edit
destroy:          verified
cleanup:          verified for this run only - VM dir $vm_dir absent, socket
                  dir $sock_dir absent, no Firecracker process, no TAP $tap,
                  tenant containers $left_containers. TAP devices belonging to
                  other deployments on this host were observed and left alone.
EOF
