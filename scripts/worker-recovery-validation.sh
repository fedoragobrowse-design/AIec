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
#
# This scenario runs next to a real deployment, so:
#
#   * it owns its scratch directory exclusively and refuses any path that already
#     exists, so no run can clear a directory it did not create;
#   * every process sweep requires this run's own inherited identifier, so a
#     deployment's worker cannot be matched by a similar-looking argument;
#   * under the firecracker runtime it refuses to start unless it is already in a
#     network namespace of its own - see AIEC_ACCEPTANCE_HOST_NETNS below -
#     because that runtime creates TAP devices, nftables tables and masquerade
#     rules, and in the host namespace those land on the machine the deployment
#     serves. The docker runtime creates none of them and needs no namespace of
#     its own.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

# Shared with the other acceptance launchers: the isolated database, the
# port-ownership refusal and the run-scoped process sweep. Sourced, never edited
# by this suite.
source "$(dirname "$0")/acceptance-db.sh"

# Minted before this run starts anything, so the API, both workers, the
# Firecracker processes the workers spawn and the database relay all inherit it
# and every sweep below can require it.
acceptance_mark_run

OUT_REQUESTED=${AIEC_RECOVERY_OUT:-$ROOT/.aiec/recovery-validation}
ITERATIONS=${AIEC_RECOVERY_ITERATIONS:-3}
API_BIND=${AIEC_RECOVERY_BIND:-127.0.0.1:19844}
BASE_PORT_A=${AIEC_RECOVERY_PORT_A:-29844}
PORT_A=$BASE_PORT_A
PORT_B=$((BASE_PORT_A + 1))
LEASE_TTL=${AIEC_RECOVERY_LEASE_TTL:-180}
KEEP=${AIEC_KEEP_FAILED_TEST_STATE:-0}
RUNTIME=${AIEC_RECOVERY_RUNTIME:-docker}
# A caller that stages the binaries is testing those binaries. Rebuilding here
# would silently substitute whatever this checkout happens to contain, which is
# the opposite of what was asked for.
RECOVERY_BIN=${AIEC_RECOVERY_BIN:-}

: "${AIEC_S3_ENDPOINT:?AIEC_S3_ENDPOINT is required}"
: "${AIEC_S3_BUCKET:?AIEC_S3_BUCKET is required}"
: "${AIEC_S3_ACCESS_KEY_ID:?AIEC_S3_ACCESS_KEY_ID is required}"
: "${AIEC_S3_SECRET_ACCESS_KEY:?AIEC_S3_SECRET_ACCESS_KEY is required}"

# This scenario used to derive its database from whatever DATABASE_URL named, with
# `DROP DATABASE IF EXISTS aiec_recovery` aimed at a fixed name it also never
# dropped afterwards - on a shared host, another deployment's server and a name two
# runs collide on. Three shapes are accepted now and nothing else:
#   * AIEC_ACCEPTANCE_DATABASE_URL - a database the caller confirms this run owns
#     alone; nothing is created and nothing is dropped.
#   * AIEC_RECOVERY_PROVISION_DATABASE=1 with AIEC_RECOVERY_DB naming a server
#     this operator controls - a database carrying this run's random tag is created
#     and dropped, and only ever that one.
#   * neither - a private cluster this run builds and stops.
if [ -n "${AIEC_RECOVERY_DB:-}" ] && [ "${AIEC_RECOVERY_PROVISION_DATABASE:-0}" != 1 ]; then
  printf '%s\n' 'AIEC_RECOVERY_DB only takes effect with AIEC_RECOVERY_PROVISION_DATABASE=1.' >&2
  exit 2
fi
if [ -z "${AIEC_ACCEPTANCE_DATABASE_URL:-}" ] && [ "${AIEC_RECOVERY_PROVISION_DATABASE:-0}" != 1 ] \
  && [ -n "${DATABASE_URL:-}" ]; then
  printf '%s\n' 'DATABASE_URL is no longer used as this run'"'"'s database.' >&2
  printf '%s\n' \
    'set AIEC_ACCEPTANCE_DATABASE_URL to a database this run owns alone (aiec_guard_*),' >&2
  printf '%s\n' \
    'or set AIEC_RECOVERY_PROVISION_DATABASE=1 to create a run-tagged database,' >&2
  printf '%s\n' 'or unset all three to build a private cluster.' >&2
  exit 2
fi

# Refused before this run starts a process or touches the network. The caller
# supplies the namespace to have left behind - `readlink /proc/self/ns/net`
# captured before entering a private one - and there is no host-network
# fallback. The docker runtime creates no TAP devices, nftables tables or
# masquerade rules, so it is not refused.
if [ "$RUNTIME" = firecracker ]; then
  acceptance_require_private_netns "the firecracker recovery validation" \
    AIEC_ACCEPTANCE_HOST_NETNS || exit 2
  acceptance_netns_loopback_up || exit 2
fi

# This scenario's sandbox policy disables networking, so the Firecracker Linux
# network backend never runs and no TAP device or nftables table is ever
# created. The census reports those two as not-applicable rather than as an
# absent value a green run cannot be told apart from a real reclaim.
RECOVERY_NETWORK=0

# Bound by the EXIT trap before it is assigned at the end of the script.
API_BASE=''
API_KEY=''

for tool in curl openssl jq psql python3 sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
# Managed-container inspection needs the docker CLI: on the host it is only
# reachable through `sg docker`, inside a container the socket is mounted and
# the CLI is called directly. A skipped container check is not evidence that
# nothing leaked, so the CLI counts as available only when a real invocation of
# it answers.
HAVE_DOCKER=0
if acceptance_have_docker; then
  HAVE_DOCKER=1
fi

# --------------------------------------------------------------- run root
# Scratch this run creates and this run owns. An existing path is somebody
# else's evidence, so the claim refuses it rather than clearing it.
acceptance_claim_run_dir "$OUT_REQUESTED" "$ROOT" || exit 2
OUT=$ACCEPTANCE_RUN_DIR
RUN_DIR_OWNED=$OUT

# Everything the teardown reads is bound before the trap is armed, because every
# fallible step after the claim - the certificates, the binaries, the ports, the
# database - can end the run. A teardown that trips over an unset name under
# `set -u` does not fail loudly: it leaves the private cluster listening and the
# scratch directory that no later run may reuse.
API_PID=''
WORKER_A_PID=''
WORKER_B_PID=''
FAILURES=0
TENANT_ID=''
ACCEPTANCE_DB_CLUSTER=
FC_BIN=${AIEC_FIRECRACKER_BIN:-$ROOT/.aiec/bin/firecracker-v1.17.0-x86_64}
WORKER_CMD=''
SERVER_CMD=''
PROVISIONED_DB_CREATED=0
PROVISIONED_DB_NAME=''
PROVISIONED_ADMIN_URL=''

# A worker's Firecracker state directory, given as one function so the worker, the
# stale restart, the teardown sweep and the census all name the same string - the
# socket root below is a hash of exactly this path.
fc_state_dir() { printf '%s/fc\n' "$1"; }


# The Firecracker runtime's host socket directory, derived the way the runtime
# derives it: std::env::temp_dir() with any trailing slash removed, then the
# first 16 hex characters of sha256 over the AIEC_STATE_DIR string. Both halves
# have to agree with the runtime exactly, so the string hashed here is the one
# handed to the worker, unmodified.
fc_socket_root() {
  local root=${TMPDIR:-/tmp}
  while [ ${#root} -gt 1 ] && [ "${root%/}" != "$root" ]; do root=${root%/}; done
  printf '%s/aiec-fc/%s\n' "$root" "$(printf '%s' "$1" | sha256sum | cut -c1-16)"
}

# The TAP name the Linux network backend derives from a sandbox id. Naming it is
# what lets the census and the teardown touch one machine's network and leave
# every other machine's alone.
fc_tap_name() { printf 'af%s' "$(printf '%s' "$1" | cut -c1-12)"; }

# The host TAP inventory, used only to describe this host - never to decide
# whether this run cleaned up after itself. `ip` is optional; a census that
# cannot be taken is reported as unavailable, never as a zero that matches.
HAVE_IP=0
if command -v ip >/dev/null 2>&1; then
  HAVE_IP=1
fi
tap_census() {
  if [ "$HAVE_IP" = 1 ]; then
    ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^af/ {print $2}' | wc -l | tr -d ' '
  else
    printf 'unavailable'
  fi
}
INITIAL_TAPS=$(tap_census)

# Per-run Firecracker accounting for one worker and one sandbox.
#
# Only meaningful when a Firecracker machine was actually started: the docker
# runtime places no VM directory, opens no control socket and creates no TAP, so
# for it every probe below reports "n/a" instead of a zero that would pass
# whether or not anything had leaked.
#
# $1 worker state directory (not the Firecracker one - use fc_state_dir), $2
# sandbox id, $3 label
fc_census() {
  local state sandbox=$2 label=$3 sock procs tap vm_dir sock_dir nft nft_state
  state=$(fc_state_dir "$1")
  # TAP and nftables are reported as not-applicable when this scenario's sandbox
  # policy disables networking, not as "absent". The Linux network backend only
  # runs for an enabled policy, so on that path no TAP and no table is ever
  # created - and printing `absent` there would be a green result produced by
  # never having looked, indistinguishable from a real reclaim.
  if [ "$RECOVERY_NETWORK" != 1 ]; then
    printf '%s firecracker_processes=%s vm_dir=%s socket_dir=%s tap=not-applicable(network-disabled) nft_table=not-applicable(network-disabled)\n' \
      "$label" \
      "$(acceptance_run_owned_pids "--api-sock $(fc_socket_root "$(fc_state_dir "$1")")/$sandbox/api.sock" "$FC_BIN" | wc -l | tr -d ' ')" \
      "$([ -e "$(fc_state_dir "$1")/vms/$sandbox" ] && printf present || printf absent)" \
      "$([ -e "$(fc_socket_root "$(fc_state_dir "$1")")/$sandbox" ] && printf present || printf absent)"
    return 0
  fi
  sock=$(fc_socket_root "$state")
  vm_dir="$state/vms/$sandbox"
  sock_dir="$sock/$sandbox"
  tap=$(fc_tap_name "$sandbox")
  nft="aiec_$(printf '%s' "$sandbox" | cut -c1-12)"
  # Matched on this sandbox's own api.sock path and, when the Firecracker binary
  # is known, on the executable too: the path is derived from this run's state
  # directory and sandbox id, so no other run can produce it.
  procs=$(acceptance_run_owned_pids "--api-sock $sock_dir/api.sock" "$FC_BIN" | wc -l | tr -d ' ')
  # The nftables table is keyed the same way as the TAP - sandbox id, not run -
  # so it is checked by this run's own sandbox and never by a host-wide count.
  if command -v nft >/dev/null 2>&1; then
    nft_state=$(nft list table inet "$nft" >/dev/null 2>&1 && printf present || printf absent)
  else
    nft_state=unavailable
  fi
  printf '%s firecracker_processes=%s vm_dir=%s socket_dir=%s tap=%s nft_table=%s\n' \
    "$label" "$procs" \
    "$([ -e "$vm_dir" ] && printf present || printf absent)" \
    "$([ -e "$sock_dir" ] && printf present || printf absent)" \
    "$([ "$HAVE_IP" = 1 ] && { ip link show "$tap" >/dev/null 2>&1 && printf present || printf absent; } || printf unavailable)" \
    "$nft_state"
}

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
# Runtime labels identify the disposable tenant, not every managed sandbox on
# the user's Docker daemon. Include stopped containers in the leak census.
managed_containers() {
  [ -n "${TENANT_ID:-}" ] || return 0
  acceptance_docker_cli ps -a -q --filter label=com.aiec.managed=true \
    --filter "label=com.aiec.tenant=$TENANT_ID"
}

# Only after the trap is armed, so a failure here leaves an owned directory the
# teardown removes rather than one no later run may reuse.
mkdir -p "$OUT/pki" "$OUT/logs"

cleanup() {
  set +e
  # Wait only on the processes this run owns; a bare `wait` would block on the
  # database relay, which is stopped further down, and never return.
  for pid in "$WORKER_A_PID" "$WORKER_B_PID" "$API_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    fi
  done
  # Firecracker processes belonging to this run: matched on this run's own socket
  # directories and the staged Firecracker executable, and required to carry this
  # run's inherited identifier. `pkill -f "api-sock $OUT"` was the pattern this
  # used, and it signals every process on the host whose arguments contain the
  # string - a deployment pointed at a similar path included.
  if [ "$RUNTIME" = firecracker ]; then
    for state_dir in "$OUT"/state/iter-*/worker-*; do
      [ -d "$state_dir" ] || continue
      sock_root=$(fc_socket_root "$(fc_state_dir "$state_dir")")
      for pid in $(acceptance_run_owned_pids "--api-sock $sock_root/" "$FC_BIN"); do
        kill -9 "$pid" 2>/dev/null
      done
    done
  fi
  # Worker processes left behind by an iteration that died between fork and
  # cleanup. Constrained to this run's own state directory and to the staged
  # binary, so a deployment's worker is not a candidate whatever it is called.
  for pid in $(acceptance_run_owned_pids "--state-dir $OUT/state/" "${WORKER_CMD:-}"); do
    kill -9 "$pid" 2>/dev/null
  done
  # Containers this run created. A run interrupted before the control plane
  # destroys its sandboxes would otherwise leave them running.
  if [ "$HAVE_DOCKER" = 1 ]; then
    for container in $(managed_containers 2>/dev/null); do
      acceptance_docker_cli rm -f "$container" 2>/dev/null
    done
  fi
  # The database is stopped before the directory goes: stopping needs the
  # directory to still be there, and both are cheaper to reason about while the
  # evidence is intact.
  if [ -n "$ACCEPTANCE_DB_CLUSTER" ]; then
    acceptance_stop_database "$OUT" "$OUT/pg" "${AIEC_RECOVERY_PG_BIN:-}"
    ACCEPTANCE_DB_CLUSTER=
  fi
  # The only DROP this scenario issues, and the name can only be this run's:
  # it carries the run's random tag and is dropped only if this run created it.
  if [ -n "${PROVISIONED_DB_NAME:-}" ] && [ "${PROVISIONED_DB_CREATED:-0}" = 1 ]; then
    psql "$PROVISIONED_ADMIN_URL" -v ON_ERROR_STOP=1 -q \
      -c "DROP DATABASE IF EXISTS $PROVISIONED_DB_NAME" >/dev/null 2>&1
    PROVISIONED_DB_CREATED=0
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

# ---------------------------------------------------------------- TLS
log "generating disposable CA and certificates for api, worker A and worker B"
# The CA needs its extensions stated: minted without basicConstraints and
# keyUsage it carries no meaning to a real TLS handshake. `req -x509` takes
# `-addext`. No comment may sit inside this continuation - bash ends the logical
# line at it and silently runs the remainder as separate commands.
openssl genrsa -out "$OUT/pki/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT/pki/ca.key" -sha256 -days 2 \
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

# ------------------------------------------------------------- binaries
# Explicitly staged binaries are used as given. Rebuilding would substitute
# whatever this checkout contains for the build the caller staged, which on a
# shared host is very often not the tree the staged build came from - and the
# fencing assertions below are about the binaries under test, so testing a
# different build would make the whole result meaningless.
if [ -n "$RECOVERY_BIN" ]; then
  RECOVERY_BIN=$(realpath -m "$RECOVERY_BIN")
  [ -x "$RECOVERY_BIN/aiec-server" ] && [ -x "$RECOVERY_BIN/aiec" ] \
    || { echo "AIEC_RECOVERY_BIN=$RECOVERY_BIN must hold an executable aiec-server and aiec" >&2; exit 2; }
  WORKER_CMD="$RECOVERY_BIN/aiec"
  SERVER_CMD="$RECOVERY_BIN/aiec-server"
  log "using prebuilt binaries from $RECOVERY_BIN (staged build, not rebuilt)"
else
  log "building aiec binaries"
  # See firecracker-coding-dogfood.sh: never reuse host-linked artifacts here.
  export CARGO_TARGET_DIR=${AIEC_TARGET_DIR:-$ROOT/.aiec/acceptance-target}
  # sqlx::migrate! embeds migrations/ at compile time but Cargo does not track
  # that directory's contents, so a new migration is invisible to a cached
  # build. Touch the crate root whenever migrations/ is newer than the storage
  # crate.
  if [ -n "$(find migrations -name '*.sql' -newer crates/aiec-storage/src/lib.rs -print -quit 2>/dev/null)" ]; then
    touch crates/aiec-storage/src/lib.rs
  fi
  # Release builds: the guest image digest is verified before a guest is booted,
  # and an unoptimized SHA-256 over a multi-gigabyte rootfs is slow enough to
  # blow the control plane's client timeout on the create path.
  cargo build -q --release -p aiec-api --bin aiec-server -p aiec-cli --bin aiec
  WORKER_CMD="$CARGO_TARGET_DIR/release/aiec"
  SERVER_CMD="$CARGO_TARGET_DIR/release/aiec-server"
fi
# The Firecracker binary, when this run will use the Firecracker runtime. Both
# the runtime and the census need it named identically, and the census uses it
# to prove a machine it is about to kill is this run's and not a deployment's.
if [ "$RUNTIME" = firecracker ]; then
  [ -x "$FC_BIN" ] || { echo "AIEC_RECOVERY_RUNTIME=firecracker needs an executable Firecracker binary at $FC_BIN" >&2; exit 2; }
  : "${AIEC_KERNEL:?AIEC_KERNEL is required for the firecracker runtime}"
  : "${AIEC_ROOTFS:?AIEC_ROOTFS is required for the firecracker runtime}"
  : "${AIEC_GUEST_SECRET:?AIEC_GUEST_SECRET is required for the firecracker runtime}"
fi

# ------------------------------------------------------------- database
# The scenario asserts on ownership and generation values, so it needs a database
# carrying no leases or nodes from earlier runs: a shared database would have the
# reconciler recover that debris instead of this run's sandbox.
if [ "${AIEC_RECOVERY_PROVISION_DATABASE:-0}" = 1 ]; then
  # The caller named a server this operator controls and asked for a database of
  # this run's own. The name carries the run's random tag, so it cannot collide
  # with another run's, and only that name is ever dropped.
  PROVISIONED_ADMIN_URL=${AIEC_RECOVERY_ADMIN_URL:?AIEC_RECOVERY_ADMIN_URL is required to provision a database}
  DB_NAME=${AIEC_RECOVERY_DB:-aiec_recovery_${RUN_TAG}}
  acceptance_check_database_identifier "$DB_NAME" || exit 2
  log "provisioning run-tagged database $DB_NAME"
  PROVISIONED_DB_NAME=$DB_NAME
  PROVISIONED_DB_CREATED=0
  if psql "$PROVISIONED_ADMIN_URL" -t -A -c \
    "select 1 from pg_database where datname='$DB_NAME'" 2>/dev/null | grep -q 1; then
    # A name carrying this run's random tag already existing means another run
    # drew it, which is not a coincidence worth trusting.
    echo "refusing to reuse the existing database $DB_NAME" >&2
    exit 2
  fi
  psql "$PROVISIONED_ADMIN_URL" -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE $DB_NAME" >/dev/null
  PROVISIONED_DB_CREATED=1
  # Only the database component is replaced. `${url%/*}/name` drops the query,
  # and on a Unix-socket URL the query is what says where the server is, so that
  # slice produces a URL that points somewhere else or nowhere at all.
  export DATABASE_URL=$(acceptance_database_url_with_name "$PROVISIONED_ADMIN_URL" "$DB_NAME")
else
  if [ -n "${AIEC_ACCEPTANCE_DATABASE_URL:-}" ]; then
    log "using the caller-confirmed isolated acceptance database"
  else
    log "building a private PostgreSQL cluster for this run"
  fi
  acceptance_prepare_database "$OUT" "$OUT/pg" "$OUT/s" "${AIEC_RECOVERY_PG_BIN:-}"
  : "${DATABASE_URL:?acceptance database preparation left no URL}"
fi

# ------------------------------------------------------------------ ports
# Refused before anything binds. On a shared host these are somebody else's
# addresses, and a run that bound them anyway would be asserting fencing
# against another deployment's control plane.
#
# The worker ports walk forward two per iteration starting at iteration 1, so
# the range this run will actually bind is BASE_PORT_A+2 through
# BASE_PORT_A+2*ITERATIONS-1. Checking BASE_PORT_A itself would test two ports
# this run never uses while leaving every port it does use unchecked. Each
# iteration re-checks its own pair as well, since anything may claim one in
# between.
API_PORT=${API_BIND##*:}
acceptance_port_free "$API_PORT" \
  || { printf 'refusing to run: loopback port %s is already bound by another process\n' "$API_PORT" >&2; exit 2; }
for i in $(seq 1 "$ITERATIONS"); do
  for port in "$((BASE_PORT_A + i * 2))" "$((BASE_PORT_A + i * 2 + 1))"; do
    acceptance_port_free "$port" \
      || { printf 'refusing to run: loopback port %s is already bound by another process\n' "$port" >&2; exit 2; }
  done
done

# ------------------------------------------------------------------ API
log "starting API on $API_BASE (lease TTL ${LEASE_TTL}s)"
"$SERVER_CMD" >"$OUT/logs/api.log" 2>&1 &
API_PID=$!
for _ in $(seq 1 90); do
  if curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl --cacert "$OUT/pki/ca.crt" -fsS "$API_BASE/health" >/dev/null 2>&1 \
  || { dump_diagnostics; echo "API did not start" >&2; exit 1; }

api() { curl --cacert "$OUT/pki/ca.crt" -sS --max-time 120 -H "Authorization: Bearer $API_KEY" "$@"; }

start_worker() {
  # start_worker <label> <node> <port> <cert> <state-dir>
  #
  # AIEC_STATE_DIR is the Firecracker runtime's VM and socket root, and it is
  # given to each worker separately rather than inherited from this script. Two
  # workers sharing one would write their VM directories and control sockets into
  # the same tree, where a VM cannot be attributed to the worker that started it
  # - and attribution is exactly what the SIGKILL and graceful-reclaim checks
  # below turn on. Each worker's socket root is then derived from its own value,
  # so no two workers' sockets can collide either.
  local label=$1 node=$2 port=$3 cert=$4 state=$5
  mkdir -p "$state"
  AIEC_STATE_DIR=$(fc_state_dir "$state") \
  AIEC_TLS_CERT_FILE="$OUT/pki/$cert.crt" \
  AIEC_TLS_KEY_FILE="$OUT/pki/$cert.key" \
  "$WORKER_CMD" \
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
  # Checked here as well as at startup, because each iteration takes a different
  # pair. A single preflight covers only iteration 1's two ports, so without this
  # a later iteration would bind a port another deployment already holds and then
  # assert fencing against somebody else's control plane - failing, or worse,
  # appearing to pass while talking to a neighbour.
  for port in "$PORT_A" "$PORT_B"; do
    acceptance_port_free "$port" || {
      printf 'refusing iteration %s: loopback port %s is already bound by another process\n' \
        "$iteration" "$port" >&2
      return 1
    }
  done
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
    "network": { "enabled": '"$(if [ "$RECOVERY_NETWORK" = 1 ]; then echo true; else echo false; fi)"' },
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
  kill -9 "$WORKER_A_PID" 2>/dev/null || true
  wait "$WORKER_A_PID" 2>/dev/null || true
  WORKER_A_PID=''
  # What SIGKILL leaves behind is recorded, not wished away: the worker never
  # runs its own teardown, so the Firecracker process, its control socket and
  # its VM directory outlive it. The orphan is reported here and reclaimed below
  # as harness cleanup, scoped to worker A's own state directory - never as a
  # product reclaim, which the graceful destroy at the end of this iteration is
  # asserted against separately.
  fc_census "$state_a" "$sandbox" "iteration $iteration after SIGKILL of A"
  for pid in $(acceptance_run_owned_pids \
      "--api-sock $(fc_socket_root "$(fc_state_dir "$state_a")")/$sandbox/" "$FC_BIN"); do
    kill -9 "$pid" 2>/dev/null || true
  done
  rm -rf -- "$(fc_state_dir "$state_a")/vms/$sandbox" \
            "$(fc_socket_root "$(fc_state_dir "$state_a")")/$sandbox"
  [ "$HAVE_IP" = 1 ] && ip link del "$(fc_tap_name "$sandbox")" 2>/dev/null
  # `aiec_` and the first 12 characters of the sandbox id, exactly as
  # aiec-network-linux derives it. A name missing the prefix matches nothing, and
  # with stderr discarded that failure is invisible - the census below would then
  # report a clean table that was simply never named.
  nft delete table inet "aiec_$(printf '%s' "$sandbox" | cut -c1-12)" 2>/dev/null
  fc_census "$state_a" "$sandbox" "iteration $iteration after harness reclaim of A's orphan"

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
  AIEC_STATE_DIR=$(fc_state_dir "$state_a") \
  AIEC_TLS_CERT_FILE="$OUT/pki/worker-a.crt" \
  AIEC_TLS_KEY_FILE="$OUT/pki/worker-a.key" \
  "$WORKER_CMD" \
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
    containers=$(managed_containers | wc -l)
    check "iteration $iteration: no managed containers remain" test "$containers" -eq 0 || return 1
  fi

  # The contrast to the SIGKILL above, and it only means something because the
  # two paths are told apart: the owning worker is alive and runs its own
  # teardown, so worker B's machine must be gone with no harness involvement.
  # The same state surviving here would be a product defect.
  if [ "$RUNTIME" = firecracker ]; then
    local b_sock b_left
    sleep 2
    fc_census "$state_b" "$sandbox" "iteration $iteration after graceful destroy"
    b_sock=$(fc_socket_root "$(fc_state_dir "$state_b")")
    b_left=0
    [ -e "$(fc_state_dir "$state_b")/vms/$sandbox" ] && b_left=$((b_left + 1))
    [ -e "$b_sock/$sandbox" ] && b_left=$((b_left + 1))
    acceptance_run_owned_pids "--api-sock $b_sock/$sandbox/" "$FC_BIN" | grep -q . && b_left=$((b_left + 1))
    [ "$HAVE_IP" = 1 ] && ip link show "$(fc_tap_name "$sandbox")" >/dev/null 2>&1 && b_left=$((b_left + 1))
    check "iteration $iteration: graceful destroy reclaimed worker B's Firecracker resources" \
      test "$b_left" -eq 0 || return 1
  fi

  # Wait only on the workers this iteration started. A bare `wait` would also
  # wait on the API server, which is meant to outlive every iteration.
  for pid in "$WORKER_A_PID" "$WORKER_B_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
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
# Every probe below is scoped to something this run created, and each tolerates
# finding nothing: a probe that exits non-zero on no match would abort the
# script under `set -e` before the verdict line.

# Nothing below sweeps the host. Every probe is scoped to something this run
# created and matched by this run's inherited identifier, so a deployment
# pointed at a similar path is never a candidate.
sweep_run_processes() {
  local pid
  for pid in $(acceptance_run_owned_pids "$1" "${2:-}"); do
    kill -9 "$pid" 2>/dev/null || true
  done
}

leftover_fc=0
leftover_vm_dirs=0
leftover_sock_dirs=0
if [ "$RUNTIME" = firecracker ]; then
  for state_dir in "$OUT"/state/iter-*/worker-*; do
    [ -d "$state_dir" ] || continue
    fc_state=$(fc_state_dir "$state_dir")
    fc_sock_root=$(fc_socket_root "$fc_state")
    sweep_run_processes "--api-sock $fc_sock_root/" "$FC_BIN"
    # Any sandbox directory still present under this worker's own tree belongs
    # to this run; the tree itself lives inside this run's directory.
    [ -d "$fc_state/vms" ] && leftover_vm_dirs=$((leftover_vm_dirs + $(find "$fc_state/vms" -mindepth 1 -maxdepth 1 | wc -l)))
    [ -d "$fc_sock_root" ] && leftover_sock_dirs=$((leftover_sock_dirs + $(find "$fc_sock_root" -mindepth 1 -maxdepth 1 | wc -l)))
  done
  # Counted only after the sweep, so a Firecracker process this run started is
  # still reported if the kill did not take.
  for state_dir in "$OUT"/state/iter-*/worker-*; do
    [ -d "$state_dir" ] || continue
    fc_sock_root=$(fc_socket_root "$(fc_state_dir "$state_dir")")
    leftover_fc=$((leftover_fc + $(acceptance_run_owned_pids "--api-sock $fc_sock_root/" "$FC_BIN" | wc -l)))
  done
  # A socket root is per-worker-state-directory, so emptying this run's does not
  # touch another run's.
  for state_dir in "$OUT"/state/iter-*/worker-*; do
    [ -d "$state_dir" ] || continue
    rmdir "$(fc_socket_root "$(fc_state_dir "$state_dir")")" 2>/dev/null || true
  done
fi
sweep_run_processes "$OUT/state" "$WORKER_CMD"
sleep 1

leftover_procs=$(acceptance_run_owned_pids "state-dir $OUT/state" "$WORKER_CMD" | wc -l)
leftover_containers=skipped
if [ "$HAVE_DOCKER" = 1 ]; then
  leftover_containers=$(managed_containers | wc -l)
fi
# Reported as context only, and never as this run's to account for. Under the
# firecracker runtime this run is confined to a network namespace of its own, so
# the census covers that namespace and not the machine; under docker it runs in
# whatever namespace the caller chose. Either way another party creating or
# destroying a machine in the same scope moves this number without this run doing
# anything, which is why it cannot decide whether this run cleaned up after itself.
visible_taps=$(tap_census)
active_leases=$(sql "select count(*) from sandbox_leases where status='active' and tenant_id='$TENANT_ID'" | head -1)
active_leases=${active_leases:-0}
if [ "$RUNTIME" = firecracker ]; then
  printf '%s\n' "processes=$leftover_procs containers=$leftover_containers firecracker=$leftover_fc vm_dirs=$leftover_vm_dirs socket_dirs=$leftover_sock_dirs active_leases=$active_leases"
  printf '%s\n' "taps_visible=$visible_taps (context only, not this run's to account for; was $INITIAL_TAPS at start, same scope)"
else
  printf '%s\n' "processes=$leftover_procs containers=$leftover_containers firecracker=not-applicable(runtime=$RUNTIME) active_leases=$active_leases"
  printf '%s\n' "taps_visible=$visible_taps (context only, not this run's to account for; was $INITIAL_TAPS at start, same scope)"
fi
check "no harness worker processes remain" test "$leftover_procs" -eq 0 || true
if [ "$HAVE_DOCKER" = 1 ]; then
  check "no harness containers remain" test "$leftover_containers" -eq 0 || true
fi
if [ "$RUNTIME" = firecracker ]; then
  check "no harness Firecracker processes remain" test "$leftover_fc" -eq 0 || true
  check "no Firecracker VM directories remain for this run's workers" test "$leftover_vm_dirs" -eq 0 || true
  check "no Firecracker socket directories remain for this run's workers" test "$leftover_sock_dirs" -eq 0 || true
fi
check "no harness active leases remain" test "$active_leases" -eq 0 || true

if [ "$FAILURES" -eq 0 ] && [ "$ITERATIONS" -ge 3 ]; then
  printf '\nSAME_HOST_MULTI_WORKER_VALIDATION: PASS (%s iterations)\n' "$ITERATIONS"
  exit 0
fi
printf '\nSAME_HOST_MULTI_WORKER_VALIDATION: FAIL (failures=%s iterations=%s)\n' "$FAILURES" "$ITERATIONS" >&2
exit 1
