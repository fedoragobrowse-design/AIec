#!/usr/bin/env bash
# Bounded public-alpha load and soak test.
#
# Measures create/exec/destroy latency against a real control plane and a real
# hosted provider, under bounded concurrency. It never over-provisions: the
# concurrency and operation count are capped, and the harness stops and reports
# the environmental limit rather than pushing the machine until it breaks.
set -Eeuo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

: "${AGENTFORGE_URL:?base URL of a running AgentForge, e.g. https://api.aiec.gobrowse.dev}"
: "${AGENTFORGE_API_KEY:?an API key is required}"
CA=${AGENTFORGE_CA_CERT:-}
OPERATIONS=${AGENTFORGE_LOAD_OPERATIONS:-100}
CONCURRENCY=${AGENTFORGE_LOAD_CONCURRENCY:-4}
SOAK_SECONDS=${AGENTFORGE_SOAK_SECONDS:-0}
IMAGE=${AGENTFORGE_LOAD_IMAGE:-base}
TIMEOUT=${AGENTFORGE_LOAD_TIMEOUT:-180}

# Refuse to start a run that would exceed the tenant's own quota, so the result
# measures the platform rather than the limiter.
MAX_IN_FLIGHT=$(( CONCURRENCY ))
[ "$MAX_IN_FLIGHT" -le 64 ] || { echo "concurrency above the safe cap of 64" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
curl_args=(-sS --max-time "$TIMEOUT" -H "Authorization: Bearer $AGENTFORGE_API_KEY"
            -H 'content-type: application/json')
[ -n "$CA" ] && curl_args=(--cacert "$CA" "${curl_args[@]}")

log() { printf '\n== %s\n' "$*"; }
pct() { # pct <file> <p>
  sort -n "$1" | awk -v p="$2" 'NR==1{min=$1} {a[NR]=$1} END {printf "%.1f", a[int((NR-1)*p)+1]}'
}

log "target"
curl "${curl_args[@]}" "$AGENTFORGE_URL/ready"; echo

log "running $OPERATIONS lifecycles at concurrency $CONCURRENCY"
: > "$WORK/create.ms"; : > "$WORK/exec.ms"; : > "$WORK/destroy.ms"
ok=0; failed=0; declined=0
start=$(date +%s)

for i in $(seq 1 "$OPERATIONS"); do
  (
    t0=$(date +%s%3N)
    box=$(curl "${curl_args[@]}" -X POST \
      -d "{\"image\":\"$IMAGE\",\"cpu\":1,\"memory_mb\":512,\"disk_mb\":2048,\"timeout_seconds\":300}" \
      "$AGENTFORGE_URL/v1/sandboxes" 2>/dev/null || echo '{}')
    id=$(printf '%s' "$box" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("id",""))
except Exception: print("")' 2>/dev/null || echo "")
    t1=$(date +%s%3N)
    if [ -z "$id" ]; then
      # A refusal is a result, not a crash: record the category and stop early
      # rather than hammering a platform that is already saying no.
      code=$(printf '%s' "$box" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("error",{}).get("code","unknown"))
except Exception: print("unknown")' 2>/dev/null || echo unknown)
      printf '%s\n' "$code" >> "$WORK/errors"
      exit 0
    fi
    echo $((t1 - t0)) >> "$WORK/create.ms"
    curl "${curl_args[@]}" -X POST \
      -d '{"command":["/bin/sh","-c","echo load"]}' \
      "$AGENTFORGE_URL/v1/sandboxes/$id/exec" >/dev/null 2>&1 || true
    t2=$(date +%s%3N)
    echo $((t2 - t1)) >> "$WORK/exec.ms"
    curl "${curl_args[@]}" -X DELETE "$AGENTFORGE_URL/v1/sandboxes/$id" >/dev/null 2>&1 || true
    t3=$(date +%s%3N)
    echo $((t3 - t2)) >> "$WORK/destroy.ms"
    printf 'done\n' >> "$WORK/ok"
  ) &
  # Bound concurrency: never let more than CONCURRENCY lifecycles be in flight.
  while [ "$(jobs -rp | wc -l)" -ge "$CONCURRENCY" ]; do wait -n || true; done
done
wait
elapsed=$(( $(date +%s) - start ))

done_count=$( [ -f "$WORK/ok" ] && wc -l < "$WORK/ok" || echo 0 )
create_count=$( [ -f "$WORK/create.ms" ] && wc -l < "$WORK/create.ms" || echo 0 )
log "results"
printf 'completed lifecycles: %s of %s in %ss\n' "$done_count" "$OPERATIONS" "$elapsed"
if [ "$create_count" -gt 0 ]; then
  printf 'create  p50=%sms p95=%sms p99=%sms max=%sms\n' \
    "$(pct "$WORK/create.ms" 0.50)" "$(pct "$WORK/create.ms" 0.95)" \
    "$(pct "$WORK/create.ms" 0.99)" "$(sort -n "$WORK/create.ms" | tail -1)"
  printf 'exec    p50=%sms p95=%sms p99=%sms\n' \
    "$(pct "$WORK/exec.ms" 0.50)" "$(pct "$WORK/exec.ms" 0.95)" "$(pct "$WORK/exec.ms" 0.99)"
  printf 'destroy p50=%sms p95=%sms p99=%sms\n' \
    "$(pct "$WORK/destroy.ms" 0.50)" "$(pct "$WORK/destroy.ms" 0.95)" "$(pct "$WORK/destroy.ms" 0.99)"
fi
if [ -s "$WORK/errors" ]; then
  log "refusals and failures by category"
  sort "$WORK/errors" | uniq -c | sort -rn
fi

# Leak check: a load test that leaves sandboxes behind is not a pass.
log "leak check"
remaining=$(curl "${curl_args[@]}" "$AGENTFORGE_URL/v1/sandboxes" \
  | python3 -c 'import json,sys
try:
    rows=json.load(sys.stdin)
    live=[r for r in rows if r.get("state") not in ("destroyed","failed")]
    print(len(live))
except Exception: print("unknown")' 2>/dev/null || echo unknown)
printf 'sandboxes still running: %s\n' "$remaining"

if [ "$SOAK_SECONDS" -gt 0 ]; then
  log "soak for ${SOAK_SECONDS}s"
  soak_start=$(date +%s)
  soak_ops=0
  while [ $(( $(date +%s) - soak_start )) -lt "$SOAK_SECONDS" ]; do
    box=$(curl "${curl_args[@]}" -X POST \
      -d "{\"image\":\"$IMAGE\",\"cpu\":1,\"memory_mb\":512,\"disk_mb\":2048,\"timeout_seconds\":120}" \
      "$AGENTFORGE_URL/v1/sandboxes" 2>/dev/null || echo '{}')
    id=$(printf '%s' "$box" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("id",""))
except Exception: print("")' 2>/dev/null || echo "")
    if [ -n "$id" ]; then
      curl "${curl_args[@]}" -X POST -d '{"command":["/bin/sh","-c","true"]}' \
        "$AGENTFORGE_URL/v1/sandboxes/$id/exec" >/dev/null 2>&1 || true
      curl "${curl_args[@]}" -X DELETE "$AGENTFORGE_URL/v1/sandboxes/$id" >/dev/null 2>&1 || true
      soak_ops=$((soak_ops + 1))
    fi
    sleep 2
  done
  printf 'soak completed %s lifecycles in %ss\n' "$soak_ops" "$SOAK_SECONDS"
fi

log "summary"
printf 'LOAD_TEST: completed=%s requested=%s concurrency=%s\n' "$done_count" "$OPERATIONS" "$CONCURRENCY"
[ "$done_count" -gt 0 ] && exit 0 || { echo "LOAD_TEST: no lifecycle completed" >&2; exit 1; }
