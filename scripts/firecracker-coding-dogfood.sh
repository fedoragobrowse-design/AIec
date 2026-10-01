#!/usr/bin/env bash
# AIec Firecracker coding-agent dogfood (production path).
#
# client -> AIec API -> PostgreSQL scheduling/state -> HTTPS worker
#   -> Firecracker -> guest -> coding workflow
#
# Requires: built aiec binaries, .aiec/bin/firecracker-v1.17.0-x86_64,
# a kernel, a coding guest rootfs, docker services (postgres, minio), and
# AIEC_REQUIRE_CODING_GUEST=1 so the runtime refuses a non-coding image.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

OUT=${1:-"$ROOT/.aiec/fc-coding-dogfood"}
API_BIND=${AIEC_DOGFOOD_BIND:-127.0.0.1:19843}
WORKER_BIND=${AIEC_DOGFOOD_WORKER_BIND:-127.0.0.1:29843}
LEASE_TTL=${AIEC_DOGFOOD_LEASE_TTL:-900}
CURL_MAX=${AIEC_DOGFOOD_CURL_MAX:-600}
KEEP=${AIEC_KEEP_FAILED_TEST_STATE:-0}
CLONE_URL=${AIEC_DOGFOOD_CLONE_URL:-https://github.com/octocat/Hello-World.git}

: "${DATABASE_URL:?DATABASE_URL must point at a real PostgreSQL}"
: "${AIEC_S3_ENDPOINT:?AIEC_S3_ENDPOINT is required}"
: "${AIEC_S3_BUCKET:?AIEC_S3_BUCKET is required}"
: "${AIEC_S3_ACCESS_KEY_ID:?AIEC_S3_ACCESS_KEY_ID is required}"
: "${AIEC_S3_SECRET_ACCESS_KEY:?AIEC_S3_SECRET_ACCESS_KEY is required}"

FC_BIN=${AIEC_FIRECRACKER_BIN:-$ROOT/.aiec/bin/firecracker-v1.17.0-x86_64}
KERNEL=${AIEC_KERNEL:-$ROOT/.aiec/images/vmlinux}
ROOTFS=${AIEC_ROOTFS:-$ROOT/.aiec/images/aiec-rootfs.ext4}
ARTIFACT_DIR=${AIEC_GUEST_ARTIFACT_DIR:-$(dirname "$ROOTFS")}

for tool in curl openssl jq sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
command -v docker >/dev/null 2>&1 && command -v sg >/dev/null 2>&1 && HAVE_DOCKER=1 || HAVE_DOCKER=0
for file in "$FC_BIN" "$KERNEL" "$ROOTFS" "$ARTIFACT_DIR/guest-capabilities.json"; do
  [ -r "$file" ] || { echo "missing guest artifact input: $file" >&2; exit 1; }
done
[ -e /dev/kvm ] || { echo "missing /dev/kvm; Firecracker cannot run" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT/pki" "$OUT/logs" "$OUT/state"

log() { printf '== %s\n' "$*"; }
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  dump_diagnostics
  exit 1
}
for tool in curl openssl jq sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
# Reads sandbox/lease state from the backing PostgreSQL when the harness runs
# on a host with the docker CLI; a no-op elsewhere.
pg_state() {
  local c=${AIEC_PG_CONTAINER:-deecopensource-postgres-1}
  sg docker -c "docker exec $c psql -U ${PGUSER:-aiec} -d ${PGDATABASE:-aiec} -c \"select id, state, runtime, node_id, created_at from sandboxes order by created_at desc limit 5\"" >&2
  sg docker -c "docker exec $c psql -U ${PGUSER:-aiec} -d ${PGDATABASE:-aiec} -c \"select sandbox_id, node_id, generation, status, expires_at from sandbox_leases order by created_at desc limit 5\"" >&2
}
worker_log() { cat "$OUT/logs/worker.log" 2>/dev/null; }

dump_diagnostics() {
  printf '\n--- api log (tail) ---\n' >&2
  tail -60 "$OUT/logs/api.log" 2>/dev/null >&2 || true
  printf '\n--- worker log (tail) ---\n' >&2
  tail -60 "$OUT/logs/worker.log" 2>/dev/null >&2 || true
  if [ "${HAVE_DOCKER:-0}" = 1 ]; then
    printf '\n--- sandbox + lease state ---\n' >&2
    pg_state >&2 2>&1 || true
  fi
}

API_PID=''
WORKER_PID=''
SANDBOX_ID=''
cleanup() {
  set +e
  if [ -n "$SANDBOX_ID" ] && [ -f "$OUT/pki/api.crt" ]; then
    curl --cacert "$OUT/pki/api.crt" -sS --max-time 30 -X DELETE \
      -H "Authorization: Bearer $API_KEY" \
      "$API_BASE/v1/sandboxes/$SANDBOX_ID" >/dev/null 2>&1
  fi
  [ -n "$WORKER_PID" ] && kill "$WORKER_PID" 2>/dev/null
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null
  wait 2>/dev/null
  # Firecracker VMs and TAP devices created by this harness.
  pkill -f "api-sock $OUT" 2>/dev/null
  for tap in $(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^af/ {print $2}'); do
    ip link del "$tap" 2>/dev/null
  done
  if [ "$KEEP" = 1 ]; then
    printf 'preserved=%s\n' "$OUT"
  else
    rm -rf "$OUT"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- TLS
log "generating disposable CA and server certificates"
openssl genrsa -out "$OUT/pki/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT/pki/ca.key" -sha256 -days 2 \
  # The CA needs its extensions stated. Minted without them it carries no
# basicConstraints and no keyUsage, which OpenSSL's own verify accepts
# but a real TLS handshake rejects - so a CA built that way makes some
# clients (Python 3.13+) unable to reach the control plane while others
# keep working. `req -x509` takes `-addext`; it rejects `-extfile`.
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
log "building aiec binaries"
# Build into a container-local target directory: a bind-mounted host target/ would
# reuse host-linked artifacts that do not run against the container libc.
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

# ------------------------------------------------------------ environment
API_KEY="af_live_$(openssl rand -hex 24)"
WORKER_TOKEN="$(openssl rand -hex 32)"
TENANT_ID=$(cat /proc/sys/kernel/random/uuid)
NODE_ID=$(cat /proc/sys/kernel/random/uuid)
MANIFEST_SECRET=$(openssl rand -hex 32)
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
export AIEC_STATE_DIR="$OUT/state"
export AIEC_S3_ENDPOINT AIEC_S3_REGION AIEC_S3_BUCKET
export AIEC_S3_ACCESS_KEY_ID AIEC_S3_SECRET_ACCESS_KEY
export RUST_LOG=${RUST_LOG:-info}
API_BASE="https://$API_BIND"

# ------------------------------------------------------------------ API
log "starting AIec API on $API_BASE"
"$CARGO_TARGET_DIR"/release/aiec-server >"$OUT/logs/api.log" 2>&1 &
API_PID=$!
for _ in $(seq 1 90); do
  curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1 && break
  sleep 1
done
curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1 \
  || fail "API did not become healthy"

# ---------------------------------------------------------------- worker
log "starting Firecracker worker $NODE_ID on $WORKER_BIND"
"$CARGO_TARGET_DIR"/release/aiec \
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
  [ "$code" = 200 ] && break
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
git --version >/dev/null 2>&1 || true
printf '%s\n' "$DIFF_TEXT" | grep -q '^\+\+\+ b/README' || fail "diff is not a README modification"

# ---------------------------------------- diff also through the file API
stage "retrieving the edited file through the AIec file API"
FILE=$(api "$API_BASE/v1/sandboxes/$SANDBOX_ID/files/content?path=/workspace/repo/README")
printf '%s\n' "$FILE"
printf '%s' "$FILE" | jq -r '.content_base64' | base64 -d | grep -q 'AIec dogfood edit' \
  || fail "file API did not return the edited file content"

# ------------------------------------------------------------ destroy
stage "destroying sandbox and verifying cleanup"
DESTROY=$(api -X DELETE "$API_BASE/v1/sandboxes/$SANDBOX_ID")
printf '%s\n' "$DESTROY"
[ "$(printf '%s' "$DESTROY" | jq -r '.status // empty')" = destroyed ] || fail "destroy did not report destroyed"
SANDBOX_ID=''
sleep 2
pgrep -f "api-sock $OUT" >/dev/null 2>&1 && fail "a Firecracker process survived destroy"
if [ "${HAVE_DOCKER:-0}" = 1 ]; then
  left=$(sg docker -c "docker ps -q --filter label=com.aiec.managed=true" | wc -l)
  [ "$left" -eq 0 ] || fail "managed containers remain after destroy: $left"
fi
leftover_taps=$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^af/ {print $2}' | wc -l)
[ "$leftover_taps" -eq 0 ] || fail "TAP devices remain after destroy: $leftover_taps"

cat <<EOF

AIec Firecracker coding-agent dogfood: PASS
sandbox:          $SANDBOX_ID
worker placement: $PLACED_NODE
git version:      $GIT_VERSION
clone:            $CLONE_URL (HTTPS, CA-verified)
git diff:         retrieved and proven to contain the in-guest edit
destroy:          verified
cleanup:          verified (no VM, no container, no TAP)
EOF
