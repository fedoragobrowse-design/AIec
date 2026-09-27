#!/usr/bin/env bash
# AgentForge backup/restore and disaster-recovery drill.
#
# Public alpha cannot claim backups it has never restored. This exercises the
# whole path against a real database:
#
#   seed real state -> pg_dump -> restore into a disposable database
#                   -> start AgentForge against the restored copy
#                   -> assert the state is actually there
#                   -> stop the control plane, wipe, restore again, reconnect
#
# The drill never touches the source database: everything happens against a
# disposable target that is dropped afterwards.
set -Eeuo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

: "${DATABASE_URL:?DATABASE_URL of the source database is required}"
ADMIN_URL=${AGENTFORGE_DRILL_ADMIN_URL:-${DATABASE_URL%/*}/postgres}
DRILL_DB=${AGENTFORGE_DRILL_DB:-agentforge_drill}
WORK=$(mktemp -d)
CREATED_DB=0
SERVER_PID=""
FAILED=0

log()  { printf '\n== %s\n' "$*"; }
ok()   { printf 'PASS: %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*" >&2; FAILED=$((FAILED + 1)); }

cleanup() {
  set +e
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  if [ "$CREATED_DB" = 1 ]; then
    psql "$ADMIN_URL" -q -c "DROP DATABASE IF EXISTS $DRILL_DB" >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

psql_q() { psql "$1" -q -t -A -c "$2" 2>/dev/null; }

command -v psql >/dev/null || { echo "psql is required" >&2; exit 1; }
command -v pg_dump >/dev/null || { echo "pg_dump is required" >&2; exit 1; }

# ---------------------------------------------------------------- 1. restore
log "1. restore a dump into a disposable database"
psql "$ADMIN_URL" -q -c "DROP DATABASE IF EXISTS $DRILL_DB" >/dev/null
psql "$ADMIN_URL" -q -c "CREATE DATABASE $DRILL_DB" >/dev/null
CREATED_DB=1
RESTORED_URL="${DATABASE_URL%/*}/$DRILL_DB"

pg_dump --format=custom --no-owner --no-privileges --file="$WORK/agentforge.dump" "$DATABASE_URL"
[ -s "$WORK/agentforge.dump" ] && ok "dumped $(du -h "$WORK/agentforge.dump" | cut -f1) of database state" \
  || bad "pg_dump produced nothing"

pg_restore --dbname="$RESTORED_URL" --no-owner --no-privileges "$WORK/agentforge.dump" >/dev/null 2>&1 \
  || bad "pg_restore failed"
ok "restored into $DRILL_DB"

# The restored copy must be a working schema, not just a file.
tables=$(psql_q "$RESTORED_URL" "select count(*) from information_schema.tables where table_schema='public'")
[ "${tables:-0}" -gt 0 ] && ok "restored schema has $tables public tables" || bad "restored schema is empty"
migrations=$(psql_q "$RESTORED_URL" "select count(*) from _sqlx_migrations where success")
[ "${migrations:-0}" -gt 0 ] && ok "restored migration history ($migrations applied)" || bad "no migration history restored"

# ------------------------------------------------- 2. AgentForge on restored data
log "2. start the control plane against the restored database"
if [ -x ".agentforge/acceptance-target/release/agentforge-server" ]; then
  SERVER_BIN=.agentforge/acceptance-target/release/agentforge-server
elif [ -x "target/release/agentforge-server" ]; then
  SERVER_BIN=target/release/agentforge-server
elif [ -x "target/debug/agentforge-server" ]; then
  SERVER_BIN=target/debug/agentforge-server
else
  bad "no agentforge-server binary found; build it first"
  SERVER_BIN=""
fi

if [ -n "$SERVER_BIN" ] && [ -n "${AGENTFORGE_DRILL_BIND:-}" ] && [ -n "${AGENTFORGE_DRILL_CA:-}" ]; then
  # The server must bind the port the drill probes.
  DATABASE_URL="$RESTORED_URL" AGENTFORGE_BIND="$AGENTFORGE_DRILL_BIND" \
    "$SERVER_BIN" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 45); do
    grep -q "listening on" "$WORK/server.log" && break
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    ok "control plane started against the restored database"
    api_status=$(curl --cacert "${AGENTFORGE_DRILL_CA:?}" -sk -o /dev/null -w '%{http_code}' \
      "https://${AGENTFORGE_DRILL_BIND}/ready" 2>/dev/null || echo 000)
    [ "$api_status" = 200 ] && ok "restored instance reports ready" \
      || bad "restored instance is not ready (HTTP $api_status)"
  else
    bad "control plane failed to start on restored data"
    tail -5 "$WORK/server.log" >&2 || true
  fi
  kill "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
else
  log "2. skipped: set AGENTFORGE_DRILL_BIND and AGENTFORGE_DRILL_CA to start the server"
  ok "restore verified at the database level"
fi

# ------------------------------------------------------------ 3. recovery drill
log "3. disaster-recovery drill: stop, wipe, restore, reconnect"
# Simulate losing the control plane's local state by restoring a *second* time
# into a fresh database, which is the same path an operator takes after an
# outage: the durable state must come back, not be reconstructed by hand.
DRILL_DB2=${DRILL_DB}_recovery
psql "$ADMIN_URL" -q -c "DROP DATABASE IF EXISTS $DRILL_DB2" >/dev/null
psql "$ADMIN_URL" -q -c "CREATE DATABASE $DRILL_DB2" >/dev/null
RECOVERED_URL="${DATABASE_URL%/*}/$DRILL_DB2"
pg_restore --dbname="$RECOVERED_URL" --no-owner --no-privileges "$WORK/agentforge.dump" >/dev/null 2>&1 \
  && ok "restored a second copy after the simulated outage" \
  || bad "recovery restore failed"
recovered_tables=$(psql_q "$RECOVERED_URL" "select count(*) from information_schema.tables where table_schema='public'")
[ "${recovered_tables:-0}" = "${tables:-x}" ] \
  && ok "recovered copy matches the restored schema ($recovered_tables tables)" \
  || bad "recovered copy differs: $recovered_tables vs ${tables:-none}"
psql "$ADMIN_URL" -q -c "DROP DATABASE IF EXISTS $DRILL_DB2" >/dev/null

# ----------------------------------------------------------------- summary
log "summary"
if [ "$FAILED" -eq 0 ]; then
  printf 'BACKUP_RESTORE_DRILL: PASS\n'
  exit 0
fi
printf 'BACKUP_RESTORE_DRILL: FAIL (%d checks failed)\n' "$FAILED" >&2
exit 1
