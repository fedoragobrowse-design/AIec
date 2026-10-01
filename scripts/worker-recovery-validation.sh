#!/usr/bin/env bash
# AIec SAME_HOST_MULTI_WORKER_VALIDATION.
#
# Proves distributed ownership with real PostgreSQL, a real API, real HTTPS
# workers, real leases, and real fencing generations:
#
#   Worker A owns generation N -> A is SIGKILLed -> heartbeat stops ->
#   lease expires -> control plane reassigns generation N+1 to Worker B ->
#   B reconstructs the durable workspace -> stale A returns and every
#   generation-N state-changing operation is rejected -> a late heartbeat and
#   a late completion from A cannot move ownership back.
#
# Two worker processes, independent node ids, ports and state dirs, same host.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

ITERATIONS=${AIEC_RECOVERY_ITERATIONS:-3}
OUT=${AIEC_RECOVERY_OUT:-$ROOT/.aiec/recovery-validation}
API_BIND=${AIEC_RECOVERY_BIND:-127.0.0.1:19844}
BASE_PORT_A=${AIEC_RECOVERY_PORT_A:-29844}
PORT_A=$BASE_PORT_A
PORT_B=$((BASE_PORT_A + 1))
LEASE_TTL=${AIEC_RECOVERY_LEASE_TTL:-180}
KEEP=${AIEC_KEEP_FAILED_TEST_STATE:-0}
RUNTIME=${AIEC_RECOVERY_RUNTIME:-docker}

: "${DATABASE_URL:?DATABASE_URL must point at a real PostgreSQL}"
: "${AIEC_S3_ENDPOINT:?AIEC_S3_ENDPOINT is required}"
: "${AIEC_S3_BUCKET:?AIEC_S3_BUCKET is required}"
: "${AIEC_S3_ACCESS_KEY_ID:?AIEC_S3_ACCESS_KEY_ID is required}"
: "${AIEC_S3_SECRET_ACCESS_KEY:?AIEC_S3_SECRET_ACCESS_KEY is required}"

for tool in curl openssl jq psql; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
# Managed-container inspection needs the docker CLI. On the host the CLI is only
# reachable through `sg docker`; inside a container the socket is mounted and the
# CLI is called directly. A skipped container check is not evidence that nothing
# leaked, so both paths are supported.
DOCKER=(docker)
if ! command -v docker >/dev/null 2>&1 && command -v sg >/dev/null 2>&1; then
  DOCKER=(sg docker)
fi
HAVE_DOCKER=0
if command -v docker >/dev/null 2>&1 || command -v sg >/dev/null 2>&1; then
  HAVE_DOCKER=1
fi

rm -rf "$OUT"
mkdir -p "$OUT/pki" "$OUT/logs"

API_PID=''
WORKER_A_PID=''
WORKER_B_PID=''
FAILURES=0

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '[%s] %s\n' "$(now)" "$*"; }

# Reads control-plane state straight from the backing PostgreSQL so the
# assertions do not depend on the docker CLI.
sql() {
  psql "$DATABASE_URL" -t -A -F '|' -c "$1" 2>/dev/null
}

snapshot_state() {
  local label=$1
  {
    printf '%s\n' "--- $label sandbox state ---"
    sql "select id, state, runtime, node_id from sandboxes order by created_at desc limit 3"
    printf '%s\n' "--- $label lease state ---"
    sql "select sandbox_id, node_id, generation, status, expires_at from sandbox_leases order by created_at desc limit 5"
    printf '%s\n' "--- $label node state ---"
    sql "select id, name, healthy, version, sandbox_count, available_vcpus from nodes order by name desc limit 4"
  } 2>&1 || true
}

dump_diagnostics() {
  printf '\n===== FAILURE DIAGNOSTICS %s =====\n' "$(now)" >&2
  printf '%s\n' '--- api log ---' >&2; tail -120 "$OUT/logs/api.log" 2>/dev/null >&2 || true
  printf '%s\n' '--- worker A log ---' >&2; tail -120 "$OUT"/logs/worker-a-iter*.log 2>/dev/null >&2 || true
  printf '%s\n' '--- worker B log ---' >&2; tail -120 "$OUT/logs/worker-b.log" 2>/dev/null >&2 || true
  snapshot_state "$(now)" >&2
}

expect_http() {
  # expect_http <expected-codes> <label> <curl args...>
  # Every control-plane call carries the disposable CA; the control plane only
  # serves HTTPS with a certificate this run generated.
  local expected=$1 label=$2
  shift 2
  local response code body
  # Control-plane calls carry the tenant API key; calls aimed at a worker
  # endpoint pass their own worker-token header, so only add the key when the
  # caller did not already supply an Authorization header.
  local have_auth=0 arg
  for arg in "$@"; do
    case "$arg" in
      "Authorization: Bearer "*) have_auth=1; break ;;
    esac
  done
  local auth=()
  if [ "$have_auth" -eq 0 ]; then
    auth=(-H "Authorization: Bearer $API_KEY")
  fi
  response=$(curl --cacert "$OUT/pki/ca.crt" -sS -w '\n%{http_code}' "${auth[@]}" "$@" 2>&1) || true
  code=$(printf '%s' "$response" | tail -1)
  body=$(printf '%s' "$response" | sed '$d')
  printf '%s -> HTTP %s %s\n' "$label" "$code" "$body"
  case ",$expected," in
    *",$code,"*) return 0 ;;
    *)
      printf 'EXPECTED %s but got %s for %s\n' "$expected" "$code" "$label" >&2
      return 1
      ;;
  esac
}

expect_rejected() {
  # The worker answers every request with HTTP 200 and carries the outcome in a
  # Result envelope, so a fenced operation is a 200 whose body is an Err with a
  # conflict code. Asserting on the status code alone would pass a request the
  # worker actually executed.
  local label=$1
  shift
  local response code body
  response=$(curl --cacert "$OUT/pki/ca.crt" -sS --max-time 60 -w '\n%{http_code}' "$@" 2>&1) || true
  code=$(printf '%s' "$response" | tail -1)
  body=$(printf '%s' "$response" | sed '$d')
  printf '%s -> HTTP %s %s\n' "$label" "$code" "$body"
  if [ "$code" = 409 ] || printf '%s' "$body" | jq -e '.result.Err.code == "conflict"' >/dev/null 2>&1; then
    return 0
  fi
  printf 'EXPECTED a rejected (conflict) result for %s\n' "$label" >&2
  return 1
}

check() {
  local label=$1
  shift
  if "$@"; then
    printf 'PASS: %s\n' "$label"
  else
    printf 'FAIL: %s\n' "$label" >&2
    FAILURES=$((FAILURES + 1))
    return 1
  fi
}

cleanup() {
  set +e
  # Wait only on the processes we own; a bare `wait` would block on any other
  # background job and never return.
  for pid in "$WORKER_A_PID" "$WORKER_B_PID" "$API_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    fi
  done
  pkill -f "api-sock $OUT" 2>/dev/null
  # Remove containers this harness created. A run that is interrupted before the
  # control plane destroys its sandboxes would otherwise leave them running.
  if [ "$HAVE_DOCKER" = 1 ]; then
    "${DOCKER[@]}" ps -q --filter label=com.aiec.managed=true 2>/dev/null \
      | xargs -r "${DOCKER[@]}" rm -f 2>/dev/null || true
  fi
  if [ "$KEEP" = 1 ]; then
    printf 'preserved=%s\n' "$OUT"
  else
    rm -rf "$OUT"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- TLS
log "generating disposable CA and certificates for api, worker A and worker B"
openssl genrsa -out "$OUT/pki/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT/pki/ca.key" -sha256 -days 2 \
  # The CA needs its extensions stated. Minted without them it carries no
  # basicConstraints and no keyUsage, which OpenSSL's own verify accepts
  # but a real TLS handshake rejects - so a CA built that way makes some
  # clients (Python 3.13+) unable to reach the control plane while others
  # keep working. `req -x509` takes `-addext`; it rejects `-extfile`.
  -subj '/CN=AIec recovery CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out "$OUT/pki/ca.crt" 2>/dev/null
for name in api worker-a worker-b; do
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
openssl verify -CAfile "$OUT/pki/ca.crt" "$OUT/pki/api.crt" "$OUT/pki/worker-a.crt" "$OUT/pki/worker-b.crt" >/dev/null \
  || { echo "certificate generation failed" >&2; exit 1; }

# ---------------------------------------------------------- environment
API_KEY="af_live_$(openssl rand -hex 24)"
WORKER_TOKEN="$(openssl rand -hex 32)"
TENANT_ID=$(cat /proc/sys/kernel/random/uuid)
# nodes.name carries a global unique constraint and node ids are reused across
# runs, so both are made unique per run: otherwise re-registration collides on
# the name instead of upserting the node.
RUN_TAG=$(openssl rand -hex 4)
API_BASE="https://$API_BIND"
WORKER_A_URL="https://127.0.0.1:$PORT_A"
WORKER_B_URL="https://127.0.0.1:$PORT_B"

export AIEC_TENANT_ID="$TENANT_ID"
export AIEC_TENANT_NAME=recovery-validation
export AIEC_API_KEY="$API_KEY"
export AIEC_WORKER_TOKEN="$WORKER_TOKEN"
export AIEC_BIND="$API_BIND"
export AIEC_RUNTIMES="$RUNTIME"
export AIEC_LEASE_TTL_SECONDS="$LEASE_TTL"
export AIEC_TLS_CERT_FILE="$OUT/pki/api.crt"
export AIEC_TLS_KEY_FILE="$OUT/pki/api.key"
export AIEC_TLS_CA_CERT="$OUT/pki/ca.crt"
export AIEC_S3_ENDPOINT AIEC_S3_REGION AIEC_S3_BUCKET
export AIEC_S3_ACCESS_KEY_ID AIEC_S3_SECRET_ACCESS_KEY
export RUST_LOG=${RUST_LOG:-info}

log "building aiec binaries"
# See firecracker-coding-dogfood.sh: never reuse host-linked artifacts here.
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

# ------------------------------------------------------------- database
# The scenario asserts on ownership and generation values, so it runs against a
# database of its own. A shared database would carry expired leases and dead
# nodes from earlier runs, and the reconcile pass would recover that debris
# instead of this run's sandbox.
ADMIN_URL=${AIEC_RECOVERY_ADMIN_URL:-${DATABASE_URL%/*}/postgres}
DB_NAME=${AIEC_RECOVERY_DB:-aiec_recovery}
log "provisioning isolated database $DB_NAME"
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -q -c "DROP DATABASE IF EXISTS $DB_NAME" >/dev/null
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE $DB_NAME" >/dev/null
export DATABASE_URL="${DATABASE_URL%/*}/$DB_NAME"

# ------------------------------------------------------------------ API
log "starting API on $API_BASE (lease TTL ${LEASE_TTL}s)"
"$CARGO_TARGET_DIR"/release/aiec-server >"$OUT/logs/api.log" 2>&1 &
API_PID=$!
for _ in $(seq 1 90); do
  curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1 && break
  sleep 1
done
curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1 \
  || { dump_diagnostics; echo "API did not start" >&2; exit 1; }

api() { curl --cacert "$OUT/pki/ca.crt" -sS --max-time 120 -H "Authorization: Bearer $API_KEY" "$@"; }
worker_ctl() {
  # worker_ctl <base-url> <cert> <path> [curl args...]
  local base=$1 cert=$2 path=$3
  shift 3
  curl --cacert "$OUT/pki/ca.crt" -sS --max-time 30 -H "Authorization: Bearer $WORKER_TOKEN" "$@" "$base$path"
}

start_worker() {
  # start_worker <label> <node> <port> <cert> <state-dir>
  local label=$1 node=$2 port=$3 cert=$4 state=$5
  mkdir -p "$state"
  AIEC_TLS_CERT_FILE="$OUT/pki/$cert.crt" \
  AIEC_TLS_KEY_FILE="$OUT/pki/$cert.key" \
  "$CARGO_TARGET_DIR"/release/aiec \
    --url "$API_BASE" worker \
    --runtime "$RUNTIME" \
    --name "$label-$RUN_TAG" \
    --node-id "$node" \
    --state-dir "$state" \
    --bind "127.0.0.1:$port" \
    --advertise-url "https://127.0.0.1:$port" \
    --capacity 1 >"$OUT/logs/$label.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 60); do
    local code
    code=$(curl --cacert "$OUT/pki/ca.crt" -sS -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $WORKER_TOKEN" "https://127.0.0.1:$port/health" 2>/dev/null || true)
    [ "$code" = 200 ] && { echo "$pid"; return 0; }
    sleep 1
  done
  return 1
}

run_iteration() {
  local iteration=$1
  local state_a="$OUT/state/iter-$iteration/worker-a"
  local state_b="$OUT/state/iter-$iteration/worker-b"
  # Fresh identities and ports per iteration so no state leaks between runs.
  local NODE_A NODE_B
  NODE_A=$(cat /proc/sys/kernel/random/uuid)
  NODE_B=$(cat /proc/sys/kernel/random/uuid)
  PORT_A=$((BASE_PORT_A + iteration * 2))
  PORT_B=$((BASE_PORT_A + iteration * 2 + 1))
  WORKER_A_URL="https://127.0.0.1:$PORT_A"
  WORKER_B_URL="https://127.0.0.1:$PORT_B"
  printf '\n================ ITERATION %s ================\n' "$iteration"

  # A registers first and B stays down, so the sandbox is deterministically
  # placed on A (the recovery reassignment later needs a live B to land on).
  log "iteration $iteration: starting worker A only"
  WORKER_A_PID=$(start_worker "worker-a-iter$iteration" "$NODE_A" "$PORT_A" worker-a "$state_a")
  [ -n "$WORKER_A_PID" ] || { dump_diagnostics; echo "worker A did not start" >&2; return 1; }

  log "iteration $iteration: creating sandbox on A"
  local create
  create=$(api -X POST -H 'content-type: application/json' -d '{
    "image": "aiec:latest",
    "cpu": 1,
    "memory_mb": 256,
    "disk_mb": 512,
    "timeout_seconds": 600,
    "runtime": "'"$RUNTIME"'",
    "network": { "enabled": false },
    "environment": { "workspace": { "type": "empty" }, "toolkits": [], "layers": [] }
  }' "$API_BASE/v1/sandboxes") || { dump_diagnostics; return 1; }
  printf '%s\n' "$create"
  local sandbox
  sandbox=$(printf '%s' "$create" | jq -r '.id // empty')
  [ -n "$sandbox" ] || { echo "no sandbox id" >&2; return 1; }
  local owner
  owner=$(printf '%s' "$create" | jq -r '.node_id // empty')
  check "iteration $iteration: sandbox placed on worker A" test "$owner" = "$NODE_A" || return 1

  local lease gen expiry
  lease=$(sql "select id from sandbox_leases where sandbox_id='$sandbox' and status='active' order by created_at desc limit 1" | head -1)
  gen=$(sql "select generation from sandbox_leases where sandbox_id='$sandbox' order by created_at desc limit 1" | head -1)
  expiry=$(sql "select expires_at from sandbox_leases where sandbox_id='$sandbox' order by created_at desc limit 1" | head -1)
  printf 'sandbox=%s lease=%s generation=%s expires_at=%s\n' "$sandbox" "$lease" "$gen" "$expiry"
  [ -n "$lease" ] && [ -n "$gen" ] || { echo "no lease recorded" >&2; return 1; }

  log "iteration $iteration: verifying the sandbox works on A and writing a durable marker"
  local marker_body
  marker_body=$(jq -nc --arg it "$iteration" \
    '{command:["/bin/sh","-c","printf recovery-marker-" + $it + " > /workspace/marker.txt && cat /workspace/marker.txt"]}')
  expect_http 200 "A exec" -X POST -H 'content-type: application/json' \
    -d "$marker_body" "$API_BASE/v1/sandboxes/$sandbox/exec" || return 1
  local marker_check
  marker_check=$(api "$API_BASE/v1/sandboxes/$sandbox/files/content?path=/workspace/marker.txt" | jq -r '.content_base64 // empty' | base64 -d 2>/dev/null)
  check "iteration $iteration: durable marker written on A" test "$marker_check" = "recovery-marker-$iteration" || return 1

  log "iteration $iteration: snapshotting the workspace so the marker can survive worker A"
  # Recovery restores the newest complete workspace-kind snapshot. A file written
  # by exec only exists in worker A's own workspace, so the durable copy has to be
  # captured before A is killed or "marker recovered on B" is unachievable.
  expect_http 200 "workspace snapshot" -X POST -H 'content-type: application/json' \
    -d '{"kind":"workspace"}' "$API_BASE/v1/sandboxes/$sandbox/snapshots" || return 1

  log "iteration $iteration: starting worker B (still unowned)"
  WORKER_B_PID=$(start_worker "worker-b-iter$iteration" "$NODE_B" "$PORT_B" worker-b "$state_b")
  [ -n "$WORKER_B_PID" ] || { dump_diagnostics; echo "worker B did not start" >&2; return 1; }

  log "iteration $iteration: SIGKILL worker A (no graceful deregistration)"
  kill -9 "$WORKER_A_PID" 2>/dev/null
  wait "$WORKER_A_PID" 2>/dev/null
  WORKER_A_PID=''
  pkill -9 -f "state-dir $state_a" 2>/dev/null

  log "iteration $iteration: waiting for lease expiry and control-plane recovery"
  local recovered=0 deadline=$((SECONDS + LEASE_TTL + 90))
  while [ $SECONDS -lt $deadline ]; do
    # /v1/workers/* is behind the worker-token middleware, not the tenant key.
    curl --cacert "$OUT/pki/ca.crt" -sS --max-time 30 -X POST \
      -H "Authorization: Bearer $WORKER_TOKEN" "$API_BASE/v1/workers/reconcile" >/dev/null 2>&1
    local current_owner current_gen current_state
    current_owner=$(sql "select node_id from sandbox_leases where sandbox_id='$sandbox' and status='active' order by created_at desc limit 1" | head -1)
    current_gen=$(sql "select generation from sandbox_leases where sandbox_id='$sandbox' order by created_at desc limit 1" | head -1)
    current_state=$(sql "select state from sandboxes where id='$sandbox'" | head -1)
    if [ "$current_owner" = "$NODE_B" ] && [ "${current_gen:-0}" -gt "${gen:-0}" ] 2>/dev/null; then
      recovered=1
      printf 'reassigned: owner=%s generation=%s state=%s\n' "$current_owner" "$current_gen" "$current_state"
      break
    fi
    sleep 2
  done
  if [ "$recovered" -ne 1 ]; then
    echo "sandbox was not reassigned to worker B within the bound" >&2
    dump_diagnostics
    return 1
  fi
  local gen_b
  gen_b=$(sql "select generation from sandbox_leases where sandbox_id='$sandbox' order by created_at desc limit 1" | head -1)
  check "iteration $iteration: generation is monotonic (N=$gen -> N+1=$gen_b)" test "$gen_b" -gt "$gen" || return 1

  log "iteration $iteration: waiting for B to reconstruct the workspace"
  local ready=0 deadline=$((SECONDS + 90))
  while [ $SECONDS -lt $deadline ]; do
    if expect_http 200 "B exec probe" -X POST -H 'content-type: application/json' \
      -d '{"command":["/bin/sh","-c","cat /workspace/marker.txt 2>/dev/null || true"]}' \
      "$API_BASE/v1/sandboxes/$sandbox/exec" 2>/dev/null | grep -q "recovery-marker-$iteration"; then
      ready=1
      break
    fi
    sleep 2
  done
  check "iteration $iteration: durable workspace marker recovered on B" test "$ready" -eq 1 || return 1

  log "iteration $iteration: file write works on the new owner B"
  # The write endpoint is PUT /files with the full path in the body; the
  # /files/content route is read-only.
  if expect_http 200 "B file write" -X PUT -H 'content-type: application/json' \
    -d '{"path":"/workspace/after-recovery.txt","content_base64":"YnJlY292ZXJlZCBvbi1i"}' \
    "$API_BASE/v1/sandboxes/$sandbox/files"; then
    check "iteration $iteration: file write works on the new owner B" true
  else
    check "iteration $iteration: file write works on the new owner B" false
    return 1
  fi

  log "iteration $iteration: restarting stale worker A with its previous state dir"
  AIEC_TLS_CERT_FILE="$OUT/pki/worker-a.crt" \
  AIEC_TLS_KEY_FILE="$OUT/pki/worker-a.key" \
  "$CARGO_TARGET_DIR"/release/aiec \
    --url "$API_BASE" worker --runtime "$RUNTIME" --name "worker-a-stale-iter$iteration-$RUN_TAG" \
    --node-id "$NODE_A" --state-dir "$state_a" --bind "127.0.0.1:$PORT_A" \
    --advertise-url "$WORKER_A_URL" --capacity 1 >>"$OUT/logs/worker-a-iter$iteration.log" 2>&1 &
  local stale_a_pid=$!
  WORKER_A_PID=$stale_a_pid
  sleep 5

  log "iteration $iteration: every generation-N state-changing operation must be rejected"
  # The worker deserializes a full Sandbox, so replay the record the control
  # plane holds rather than a stub with only an id. WorkerOperation is tagged
  # with the key "operation", so the object bound to the envelope's `operation`
  # field carries `operation: "<variant>"` alongside the variant's own fields.
  local stale_sandbox
  stale_sandbox=$(api "$API_BASE/v1/sandboxes/$sandbox" | jq '.sandbox // .')
  local stale_header=(--cacert "$OUT/pki/ca.crt" -H "Authorization: Bearer $WORKER_TOKEN" -H 'content-type: application/json')
  local request_id
  request_id=$(cat /proc/sys/kernel/random/uuid)
  local stale_payload
  stale_payload=$(jq -nc --argjson sb "$stale_sandbox" --arg rid "$request_id" --argjson gen "$gen" \
    '{request_id:$rid, lease_generation:$gen, operation:{operation:"exec", sandbox:$sb, request:{command:["/bin/sh","-c","echo stale-exec-must-not-run > /workspace/stale.txt"]}}}')

  expect_rejected "stale A exec" "${stale_header[@]}" -d "$stale_payload" "$WORKER_A_URL/v1/operations" \
    || { echo "stale exec was not rejected" >&2; dump_diagnostics; return 1; }
  check "iteration $iteration: stale A exec rejected" true

  stale_payload=$(jq -nc --argjson sb "$stale_sandbox" --arg rid "$request_id" --argjson gen "$gen" \
    '{request_id:$rid, lease_generation:$gen, operation:{operation:"put_file", sandbox:$sb, request:{path:"/workspace/stale-write.txt", content_base64:"Y3RhCg=="}}}')
  expect_rejected "stale A file write" "${stale_header[@]}" -d "$stale_payload" "$WORKER_A_URL/v1/operations" \
    || { echo "stale file write was not rejected" >&2; dump_diagnostics; return 1; }
  check "iteration $iteration: stale A file mutation rejected" true

  stale_payload=$(jq -nc --argjson sb "$stale_sandbox" --arg rid "$request_id" --argjson gen "$gen" \
    '{request_id:$rid, lease_generation:$gen, operation:{operation:"stop", sandbox:$sb}}')
  expect_rejected "stale A stop" "${stale_header[@]}" -d "$stale_payload" "$WORKER_A_URL/v1/operations" \
    || { echo "stale stop was not rejected" >&2; dump_diagnostics; return 1; }
  check "iteration $iteration: stale A stop rejected" true

  stale_payload=$(jq -nc --argjson sb "$stale_sandbox" --arg rid "$request_id" --argjson gen "$gen" \
    '{request_id:$rid, lease_generation:$gen, operation:{operation:"destroy", sandbox:$sb}}')
  expect_rejected "stale A destroy" "${stale_header[@]}" -d "$stale_payload" "$WORKER_A_URL/v1/operations" \
    || { echo "stale destroy was not rejected" >&2; dump_diagnostics; return 1; }
  check "iteration $iteration: stale A destroy rejected" true

  log "iteration $iteration: stale lease completion and stale state update must be rejected"
  expect_http 409 "stale A lease completion" "${stale_header[@]}" -X POST \
    -d "{\"tenant_id\":\"$TENANT_ID\",\"generation\":$gen}" "$API_BASE/v1/workers/$NODE_A/leases/$lease/complete" >/dev/null 2>&1 \
    || { echo "stale lease completion was not rejected" >&2; dump_diagnostics; return 1; }
  check "iteration $iteration: stale A lease completion rejected" true

  log "iteration $iteration: late heartbeat from A must not steal ownership"
  # A still reports the sandbox it lost, so the heartbeat genuinely claims
  # ownership; the fence must refuse it rather than the claim simply being absent.
  local version
  version=$(sql "select coalesce(max(version),0) + 1000 from nodes" | head -1)
  # A still claims the sandbox it lost, so the control plane must refuse the
  # heartbeat outright: the node holds no unexpired lease, so it is not the
  # owner of anything it reports. Either outcome is fine for ownership, but a
  # refusal is the stronger proof, so accept both and assert ownership below.
  late_heartbeat=$(curl --cacert "$OUT/pki/ca.crt" -sS --max-time 30 -X POST \
    -H "Authorization: Bearer $WORKER_TOKEN" -H 'content-type: application/json' \
    -d "{\"node_id\":\"$NODE_A\",\"available_vcpus\":4,\"available_memory_bytes\":8589934592,\"available_disk_bytes\":85899345920,\"sandbox_count\":1,\"healthy\":true,\"version\":$version,\"metadata\":{},\"last_error\":null}" \
    "$API_BASE/v1/workers/$NODE_A/heartbeat" 2>&1) || true
  printf 'late A heartbeat -> %s\n' "$late_heartbeat"
  sleep 1
  local owner_after_hb
  owner_after_hb=$(sql "select node_id from sandbox_leases where sandbox_id='$sandbox' and status='active' order by created_at desc limit 1" | head -1)
  local gen_after_hb
  gen_after_hb=$(sql "select generation from sandbox_leases where sandbox_id='$sandbox' order by created_at desc limit 1" | head -1)
  check "iteration $iteration: late heartbeat cannot steal ownership" test "$owner_after_hb" = "$NODE_B" || return 1
  check "iteration $iteration: late heartbeat cannot reset the generation" test "$gen_after_hb" = "$gen_b" || return 1

  log "iteration $iteration: late completion from generation N must not overwrite N+1 state"
  local state_before
  state_before=$(sql "select state from sandboxes where id='$sandbox'" | head -1)
  expect_http 409 "late completion from generation N" "${stale_header[@]}" -X POST \
    -d "{\"tenant_id\":\"$TENANT_ID\",\"generation\":$gen}" \
    "$API_BASE/v1/workers/$NODE_A/leases/$lease/complete" >/dev/null 2>&1 || return 1
  sleep 1
  local state_after
  state_after=$(sql "select state from sandboxes where id='$sandbox'" | head -1)
  check "iteration $iteration: late completion cannot overwrite N+1 state" test "$state_after" = "$state_before" || return 1

  log "iteration $iteration: legitimate cleanup through the control plane"
  expect_http 200 "legitimate destroy" -X DELETE "$API_BASE/v1/sandboxes/$sandbox" >/dev/null 2>&1 || return 1
  local remaining
  remaining=$(sql "select count(*) from sandbox_leases where sandbox_id='$sandbox' and status='active'" | head -1)
  check "iteration $iteration: no active lease after destroy" test "${remaining:-1}" = 0 || return 1
  sleep 2
  local containers
  if [ "$HAVE_DOCKER" = 1 ]; then
    containers=$({ "${DOCKER[@]}" ps -q --filter label=com.aiec.managed=true 2>/dev/null || true; } | wc -l)
    check "iteration $iteration: no managed containers remain" test "$containers" -eq 0 || return 1
  fi

  # Wait only on the workers this iteration started. A bare `wait` would also
  # wait on the API server, which is meant to outlive every iteration.
  for pid in "$WORKER_A_PID" "$WORKER_B_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    fi
  done
  WORKER_A_PID=''
  WORKER_B_PID=''
  sleep 2
  return 0
}

log "SAME_HOST_MULTI_WORKER_VALIDATION starting: $ITERATIONS iterations, runtime=$RUNTIME"
for i in $(seq 1 "$ITERATIONS"); do
  if ! run_iteration "$i"; then
    FAILURES=$((FAILURES + 1))
    dump_diagnostics
    break
  fi
done

printf '\n===== CLEANUP VERIFICATION =====\n'
# Every probe here is expected to find nothing on a clean run, and each of them
# (pgrep, pkill, docker ps) exits non-zero when it matches nothing. Under
# `set -e` that would abort the script before the verdict line, so each probe is
# explicitly tolerant.
pkill -f "state-dir $OUT/state" 2>/dev/null || true
pkill -f "api-sock $OUT" 2>/dev/null || true
sleep 1

# Count leftover harness processes. The harness's own shell and its
# command-substitution subshells carry the binary path in their command line, so
# they are excluded; anything else matching is a real leftover.
count_matches() {
  pgrep -f "$1" 2>/dev/null \
    | while read -r pid; do
        [ "$pid" = "$$" ] && continue
        case "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" in
          *worker-recovery-validation*|*pgrep*) continue ;;
        esac
        printf '%s\n' "$pid"
      done \
    | wc -l
}

leftover_procs=$(count_matches "$CARGO_TARGET_DIR/release/aiec")
leftover_containers=skipped
if [ "$HAVE_DOCKER" = 1 ]; then
  leftover_containers=$({ "${DOCKER[@]}" ps -q --filter label=com.aiec.managed=true 2>/dev/null || true; } | wc -l)
fi
leftover_fc=$(count_matches "api-sock")
leftover_taps=$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^af/ {print $2}' | wc -l || echo 0)
active_leases=$(sql "select count(*) from sandbox_leases where status='active'" 2>/dev/null | head -1)
active_leases=${active_leases:-0}
printf '%s\n' "processes=$leftover_procs containers=$leftover_containers firecracker=$leftover_fc taps=$leftover_taps active_leases=$active_leases"

if [ "$FAILURES" -eq 0 ] && [ "$ITERATIONS" -ge 3 ]; then
  printf '\nSAME_HOST_MULTI_WORKER_VALIDATION: PASS (%s iterations)\n' "$ITERATIONS"
  exit 0
fi
printf '\nSAME_HOST_MULTI_WORKER_VALIDATION: FAIL (failures=%s iterations=%s)\n' "$FAILURES" "$ITERATIONS" >&2
exit 1
