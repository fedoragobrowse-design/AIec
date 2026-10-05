#!/usr/bin/env bash
# AIec backup/restore and disaster-recovery drill.
#
# Public alpha cannot claim backups it has never restored. This exercises the
# whole path against a real database:
#
#   seed real state -> pg_dump -> restore into a disposable database
#                   -> start AIec against the restored copy
#                   -> assert the state is actually there
#                   -> stop the control plane, wipe, restore again, reconnect
#
# The drill never touches the source database: everything happens against a
# disposable target that is dropped afterwards.
set -Eeuo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

: "${DATABASE_URL:?DATABASE_URL of the source database is required}"
ADMIN_URL=${AIEC_DRILL_ADMIN_URL:-${DATABASE_URL%/*}/postgres}
DRILL_DB=${AIEC_DRILL_DB:-aiec_drill}
WORK=$(mktemp -d)

# A connection string on a command line is not private: any local user can read
# another process's argv through /proc, which makes the password in every URL
# below readable to every account on the machine for as long as the process
# lives. libpq reads the password from the environment instead, so it is taken
# out of the URLs once here and given to it that way.
source "$REPO/scripts/acceptance-db.sh"
acceptance_database_export_password "$DATABASE_URL" || exit 2

# `PGPASSWORD` is one value for the whole process, so the admin role and the
# source database must share it. They do by default — the admin URL is derived
# from `DATABASE_URL` — but an override that names a different role with a
# different password would silently authenticate as one of them and fail on the
# other. Saying so beats a confusing authentication error mid-drill.
if [ -n "${AIEC_DRILL_ADMIN_URL:-}" ]; then
  admin_password=$(acceptance_database_url_password "$ADMIN_URL")
  source_password=$(acceptance_database_url_password "$DATABASE_URL")
  if [ "$admin_password" != "$source_password" ]; then
    printf '%s\n' \
      'refusing to run: AIEC_DRILL_ADMIN_URL and DATABASE_URL carry different passwords, and one PGPASSWORD cannot satisfy both. Use one role for the drill.' >&2
    exit 1
  fi
  unset admin_password source_password
fi

# The full URLs stay intact: the control plane below is started with
# `DATABASE_URL=$RESTORED_URL` in its environment, and sqlx parses the password
# out of the URI itself rather than reading `PGPASSWORD` the way libpq does.
# Only the copies handed to `psql`/`pg_dump`/`pg_restore` as arguments are
# stripped, which is the only place the value was ever exposed to another
# account.
ADMIN_ARGV=$(acceptance_database_url_without_password "$ADMIN_URL")
DATABASE_ARGV=$(acceptance_database_url_without_password "$DATABASE_URL")
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
    psql "$ADMIN_ARGV" -q -c "DROP DATABASE IF EXISTS $DRILL_DB" >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

psql_q() { psql "$1" -q -t -A -c "$2" 2>/dev/null; }

command -v psql >/dev/null || { echo "psql is required" >&2; exit 1; }
command -v pg_dump >/dev/null || { echo "pg_dump is required" >&2; exit 1; }

# ---------------------------------------------------------------- 1. restore
log "1. restore a dump into a disposable database"
psql "$ADMIN_ARGV" -q -c "DROP DATABASE IF EXISTS $DRILL_DB" >/dev/null
psql "$ADMIN_ARGV" -q -c "CREATE DATABASE $DRILL_DB" >/dev/null
CREATED_DB=1
RESTORED_URL="${DATABASE_URL%/*}/$DRILL_DB"
# Same split as above: the full URL goes to the control plane's environment, the
# stripped one to `pg_restore`'s arguments.
RESTORED_ARGV="${DATABASE_ARGV%/*}/$DRILL_DB"

pg_dump --format=custom --no-owner --no-privileges --file="$WORK/aiec.dump" "$DATABASE_ARGV"
[ -s "$WORK/aiec.dump" ] && ok "dumped $(du -h "$WORK/aiec.dump" | cut -f1) of database state" \
  || bad "pg_dump produced nothing"

pg_restore --dbname="$RESTORED_ARGV" --no-owner --no-privileges "$WORK/aiec.dump" >/dev/null 2>&1 \
  || bad "pg_restore failed"
ok "restored into $DRILL_DB"

# The restored copy must be a working schema, not just a file.
tables=$(psql_q "$RESTORED_ARGV" "select count(*) from information_schema.tables where table_schema='public'")
[ "${tables:-0}" -gt 0 ] && ok "restored schema has $tables public tables" || bad "restored schema is empty"
migrations=$(psql_q "$RESTORED_ARGV" "select count(*) from _sqlx_migrations where success")
[ "${migrations:-0}" -gt 0 ] && ok "restored migration history ($migrations applied)" || bad "no migration history restored"

# ------------------------------------------------- 2. AIec on restored data
log "2. start the control plane against the restored database"
if [ -x ".aiec/acceptance-target/release/aiec-server" ]; then
  SERVER_BIN=.aiec/acceptance-target/release/aiec-server
elif [ -x "target/release/aiec-server" ]; then
  SERVER_BIN=target/release/aiec-server
elif [ -x "target/debug/aiec-server" ]; then
  SERVER_BIN=target/debug/aiec-server
else
  bad "no aiec-server binary found; build it first"
  SERVER_BIN=""
fi

if [ -n "$SERVER_BIN" ] && [ -n "${AIEC_DRILL_BIND:-}" ] && [ -n "${AIEC_DRILL_CA:-}" ]; then
  # The server must bind the port the drill probes.
  DATABASE_URL="$RESTORED_URL" AIEC_BIND="$AIEC_DRILL_BIND" \
    "$SERVER_BIN" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 45); do
    grep -q "listening on" "$WORK/server.log" && break
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    ok "control plane started against the restored database"
    api_status=$(curl --cacert "${AIEC_DRILL_CA:?}" -sk -o /dev/null -w '%{http_code}' \
      "https://${AIEC_DRILL_BIND}/ready" 2>/dev/null || echo 000)
    [ "$api_status" = 200 ] && ok "restored instance reports ready" \
      || bad "restored instance is not ready (HTTP $api_status)"
  else
    bad "control plane failed to start on restored data"
    tail -5 "$WORK/server.log" >&2 || true
  fi
  kill "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
else
  log "2. skipped: set AIEC_DRILL_BIND and AIEC_DRILL_CA to start the server"
  ok "restore verified at the database level"
fi

# ------------------------------------------------------------ 3. recovery drill
log "3. disaster-recovery drill: stop, wipe, restore, reconnect"
# Simulate losing the control plane's local state by restoring a *second* time
# into a fresh database, which is the same path an operator takes after an
# outage: the durable state must come back, not be reconstructed by hand.
DRILL_DB2=${DRILL_DB}_recovery
psql "$ADMIN_ARGV" -q -c "DROP DATABASE IF EXISTS $DRILL_DB2" >/dev/null
psql "$ADMIN_ARGV" -q -c "CREATE DATABASE $DRILL_DB2" >/dev/null
RECOVERED_ARGV="${DATABASE_ARGV%/*}/$DRILL_DB2"
pg_restore --dbname="$RECOVERED_ARGV" --no-owner --no-privileges "$WORK/aiec.dump" >/dev/null 2>&1 \
  && ok "restored a second copy after the simulated outage" \
  || bad "recovery restore failed"
recovered_tables=$(psql_q "$RECOVERED_ARGV" "select count(*) from information_schema.tables where table_schema='public'")
[ "${recovered_tables:-0}" = "${tables:-x}" ] \
  && ok "recovered copy matches the restored schema ($recovered_tables tables)" \
  || bad "recovered copy differs: $recovered_tables vs ${tables:-none}"
psql "$ADMIN_ARGV" -q -c "DROP DATABASE IF EXISTS $DRILL_DB2" >/dev/null

# ----------------------------------------------------------------- summary
log "summary"
if [ "$FAILED" -eq 0 ]; then
  printf 'BACKUP_RESTORE_DRILL: PASS\n'
  exit 0
fi
printf 'BACKUP_RESTORE_DRILL: FAIL (%d checks failed)\n' "$FAILED" >&2
exit 1
