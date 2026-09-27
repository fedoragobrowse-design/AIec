#!/usr/bin/env bash
# AgentForge Firecracker coding-agent dogfood (production path).
#
# client -> AgentForge API -> PostgreSQL scheduling/state -> HTTPS worker
#   -> Firecracker -> guest -> coding workflow
#
# Requires: built agentforge binaries, .agentforge/bin/firecracker-v1.17.0-x86_64,
# a kernel, a coding guest rootfs, docker services (postgres, minio), and
# AGENTFORGE_REQUIRE_CODING_GUEST=1 so the runtime refuses a non-coding image.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

OUT=${1:-"$ROOT/.agentforge/fc-coding-dogfood"}
API_BIND=${AGENTFORGE_DOGFOOD_BIND:-127.0.0.1:19843}
WORKER_BIND=${AGENTFORGE_DOGFOOD_WORKER_BIND:-127.0.0.1:29843}
LEASE_TTL=${AGENTFORGE_DOGFOOD_LEASE_TTL:-900}
CURL_MAX=${AGENTFORGE_DOGFOOD_CURL_MAX:-600}
KEEP=${AGENTFORGE_KEEP_FAILED_TEST_STATE:-0}
CLONE_URL=${AGENTFORGE_DOGFOOD_CLONE_URL:-https://github.com/octocat/Hello-World.git}

: "${DATABASE_URL:?DATABASE_URL must point at a real PostgreSQL}"
: "${AGENTFORGE_S3_ENDPOINT:?AGENTFORGE_S3_ENDPOINT is required}"
: "${AGENTFORGE_S3_BUCKET:?AGENTFORGE_S3_BUCKET is required}"
: "${AGENTFORGE_S3_ACCESS_KEY_ID:?AGENTFORGE_S3_ACCESS_KEY_ID is required}"
: "${AGENTFORGE_S3_SECRET_ACCESS_KEY:?AGENTFORGE_S3_SECRET_ACCESS_KEY is required}"

FC_BIN=${AGENTFORGE_FIRECRACKER_BIN:-$ROOT/.agentforge/bin/firecracker-v1.17.0-x86_64}
KERNEL=${AGENTFORGE_KERNEL:-$ROOT/.agentforge/images/vmlinux}
ROOTFS=${AGENTFORGE_ROOTFS:-$ROOT/.agentforge/images/agentforge-rootfs.ext4}
ARTIFACT_DIR=${AGENTFORGE_GUEST_ARTIFACT_DIR:-$(dirname "$ROOTFS")}

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
  local c=${AGENTFORGE_PG_CONTAINER:-deecopensource-postgres-1}
  sg docker -c "docker exec $c psql -U ${PGUSER:-agentforge} -d ${PGDATABASE:-agentforge} -c \"select id, state, runtime, node_id, created_at from sandboxes order by created_at desc limit 5\"" >&2
  sg docker -c "docker exec $c psql -U ${PGUSER:-agentforge} -d ${PGDATABASE:-agentforge} -c \"select sandbox_id, node_id, generation, status, expires_at from sandbox_leases order by created_at desc limit 5\"" >&2
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
  -subj '/CN=AgentForge dogfood CA' -out "$OUT/pki/ca.crt" 2>/dev/null
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
log "building agentforge binaries"
# Build into a container-local target directory: a bind-mounted host target/ would
# reuse host-linked artifacts that do not run against the container libc.
export CARGO_TARGET_DIR=${AGENTFORGE_TARGET_DIR:-$ROOT/.agentforge/acceptance-target}
# sqlx::migrate! embeds migrations/ at compile time but Cargo does not track
# that directory's contents, so a new migration is invisible to a cached build.
# Touch the crate root whenever migrations/ is newer than the storage crate.
if [ -n "$(find migrations -name '*.sql' -newer crates/agentforge-storage/src/lib.rs -print -quit 2>/dev/null)" ]; then
  touch crates/agentforge-storage/src/lib.rs
fi
# Release builds: the guest image digest is verified before a guest is
# booted, and an unoptimized SHA-256 over a multi-gigabyte rootfs is slow enough
# to blow the control plane's client timeout on the create path.
cargo build -q --release -p agentforge-api --bin agentforge-server -p agentforge-cli --bin agentforge

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
reference = "agentforge:latest"
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

export AGENTFORGE_TENANT_ID="$TENANT_ID"
export AGENTFORGE_TENANT_NAME=dogfood
export AGENTFORGE_API_KEY="$API_KEY"
export AGENTFORGE_WORKER_TOKEN="$WORKER_TOKEN"
export AGENTFORGE_BIND="$API_BIND"
export AGENTFORGE_RUNTIMES=firecracker
export AGENTFORGE_LEASE_TTL_SECONDS="$LEASE_TTL"
export AGENTFORGE_TLS_CERT_FILE="$OUT/pki/api.crt"
export AGENTFORGE_TLS_KEY_FILE="$OUT/pki/api.key"
export AGENTFORGE_TLS_CA_CERT="$OUT/pki/ca.crt"
export AGENTFORGE_IMAGE_MANIFEST="$OUT/guest-manifest.json"
export AGENTFORGE_IMAGE_MANIFEST_SECRET="$MANIFEST_SECRET"
export AGENTFORGE_FIRECRACKER_BIN="$FC_BIN"
export AGENTFORGE_KERNEL="$KERNEL"
export AGENTFORGE_ROOTFS="$ROOTFS"
export AGENTFORGE_GUEST_ARTIFACT_DIR="$ARTIFACT_DIR"
export AGENTFORGE_REQUIRE_CODING_GUEST=1
export AGENTFORGE_GUEST_SECRET=${AGENTFORGE_GUEST_SECRET:-$(openssl rand -hex 32)}
export AGENTFORGE_STATE_DIR="$OUT/state"
export AGENTFORGE_S3_ENDPOINT AGENTFORGE_S3_REGION AGENTFORGE_S3_BUCKET
export AGENTFORGE_S3_ACCESS_KEY_ID AGENTFORGE_S3_SECRET_ACCESS_KEY
export RUST_LOG=${RUST_LOG:-info}
API_BASE="https://$API_BIND"

# ------------------------------------------------------------------ API
log "starting AgentForge API on $API_BASE"
"$CARGO_TARGET_DIR"/release/agentforge-server >"$OUT/logs/api.log" 2>&1 &
API_PID=$!
for _ in $(seq 1 90); do
  curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1 && break
  sleep 1
done
curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1 \
  || fail "API did not become healthy"

# ---------------------------------------------------------------- worker
log "starting Firecracker worker $NODE_ID on $WORKER_BIND"
"$CARGO_TARGET_DIR"/release/agentforge \
  --url "$API_BASE" worker \
  --runtime firecracker \
  --name "fc-dogfood-$NODE_ID" \
  --node-id "$NODE_ID" \
  --state-dir "$OUT/state/worker" \
  --bind "$WORKER_BIND" \
  --advertise-url "https://$WORKER_BIND" \
  --capacity "${AGENTFORGE_DOGFOOD_CAPACITY:-4}" >"$OUT/logs/worker.log" 2>&1 &
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
  "image": "agentforge:latest",
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
  -d '{"command":["/bin/sh","-c","cd /workspace/repo && printf \"\\nAgentForge dogfood edit\\n\" >> README && cat README"]}' \
  "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$EDIT"
printf '%s' "$EDIT" | jq -e '.stdout | test("AgentForge dogfood edit")' >/dev/null \
  || fail "in-guest edit did not land"

VALIDATE=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["/bin/sh","-c","cd /workspace/repo && test -s README && grep -q \"AgentForge dogfood edit\" README && git diff --check && echo VALIDATION_OK"]}' \
  "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$VALIDATE"
printf '%s' "$VALIDATE" | jq -e '.stdout | test("VALIDATION_OK")' >/dev/null \
  || fail "in-guest validation command failed"

DIFF=$(api -X POST -H 'content-type: application/json' \
  -d '{"command":["/bin/sh","-c","cd /workspace/repo && git --no-pager diff"]}' \
  "$API_BASE/v1/sandboxes/$SANDBOX_ID/exec")
printf '%s\n' "$DIFF"
DIFF_TEXT=$(printf '%s' "$DIFF" | jq -r '.stdout')
printf '%s' "$DIFF_TEXT" | grep -q '^+.*AgentForge dogfood edit' \
  || fail "retrieved git diff does not prove the in-guest edit"
printf '%s' "$DIFF_TEXT" | grep -q '^-.*AgentForge dogfood edit' \
  && fail "diff shows the edit as a deletion"
git --version >/dev/null 2>&1 || true
printf '%s\n' "$DIFF_TEXT" | grep -q '^\+\+\+ b/README' || fail "diff is not a README modification"

# ---------------------------------------- diff also through the file API
stage "retrieving the edited file through the AgentForge file API"
FILE=$(api "$API_BASE/v1/sandboxes/$SANDBOX_ID/files/content?path=/workspace/repo/README")
printf '%s\n' "$FILE"
printf '%s' "$FILE" | jq -r '.content_base64' | base64 -d | grep -q 'AgentForge dogfood edit' \
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
  left=$(sg docker -c "docker ps -q --filter label=com.agentforge.managed=true" | wc -l)
  [ "$left" -eq 0 ] || fail "managed containers remain after destroy: $left"
fi
leftover_taps=$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^af/ {print $2}' | wc -l)
[ "$leftover_taps" -eq 0 ] || fail "TAP devices remain after destroy: $leftover_taps"

cat <<EOF

AgentForge Firecracker coding-agent dogfood: PASS
sandbox:          $SANDBOX_ID
worker placement: $PLACED_NODE
git version:      $GIT_VERSION
clone:            $CLONE_URL (HTTPS, CA-verified)
git diff:         retrieved and proven to contain the in-guest edit
destroy:          verified
cleanup:          verified (no VM, no container, no TAP)
EOF
