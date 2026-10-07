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
# `acceptance_database_url_with_name` is the only way a database name is
# replaced: cutting the last path segment with `${URL%/*}` cuts inside the query
# when a query value carries a slash, and every rewritten URL then names the
# source database instead of the drill's own.
source "$REPO/scripts/acceptance-db.sh"
ADMIN_URL=${AIEC_DRILL_ADMIN_URL:-$(acceptance_database_url_with_name "$DATABASE_URL" postgres)}
DRILL_DB=${AIEC_DRILL_DB:-aiec_drill_${AIEC_ACCEPTANCE_RUN_ID//-/_}}
DRILL_DB2=${DRILL_DB}_recovery
SOURCE_DB=$(acceptance_database_url_name "$DATABASE_URL")
ADMIN_DB=$(acceptance_database_url_name "$ADMIN_URL")
for target in "$DRILL_DB" "$DRILL_DB2"; do
  acceptance_check_database_identifier "$target" || exit 2
  case "$target" in
    aiec|postgres|template0|template1|"$SOURCE_DB"|"$ADMIN_DB")
      printf 'refusing to run: a drill target names a source, admin, or protected database\n' >&2
      exit 2
      ;;
  esac
done
WORK=$(mktemp -d)

# A connection string on a command line is not private: any local user can read
# another process's argv through /proc, which makes the password in every URL
# below readable to every account on the machine for as long as the process
# lives. libpq reads the password from the environment instead, so it is taken
# out of the URLs once here and given to it that way.
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
CREATED_DB2=0
SERVER_PID=""
FAILED=0

log()  { printf '\n== %s\n' "$*"; }
ok()   { printf 'PASS: %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*" >&2; FAILED=$((FAILED + 1)); }

cleanup() {
  set +e
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  if [ "$CREATED_DB2" = 1 ]; then
    psql -X -v ON_ERROR_STOP=1 "$ADMIN_ARGV" -q -c "DROP DATABASE \"$DRILL_DB2\"" >/dev/null \
      || printf 'cleanup could not drop the owned recovery database\n' >&2
  fi
  if [ "$CREATED_DB" = 1 ]; then
    psql -X -v ON_ERROR_STOP=1 "$ADMIN_ARGV" -q -c "DROP DATABASE \"$DRILL_DB\"" >/dev/null \
      || printf 'cleanup could not drop the owned restored database\n' >&2
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

psql_q() { psql -X -v ON_ERROR_STOP=1 "$1" -q -t -A -c "$2"; }

command -v psql >/dev/null || { echo "psql is required" >&2; exit 1; }
command -v pg_dump >/dev/null || { echo "pg_dump is required" >&2; exit 1; }
command -v pg_restore >/dev/null || { echo "pg_restore is required" >&2; exit 1; }

# ---------------------------------------------------------------- 1. restore
log "1. restore a dump into a disposable database"
# CREATE is the ownership claim. A preexisting target is never dropped.
psql -X -v ON_ERROR_STOP=1 "$ADMIN_ARGV" -q -c "CREATE DATABASE \"$DRILL_DB\"" >/dev/null
CREATED_DB=1
RESTORED_URL=$(acceptance_database_url_with_name "$ADMIN_URL" "$DRILL_DB")
# Same split as above: the full URL goes to the control plane's environment, the
# stripped one to `pg_restore`'s arguments.
RESTORED_ARGV=$(acceptance_database_url_with_name "$ADMIN_ARGV" "$DRILL_DB")

pg_dump --format=custom --no-owner --no-privileges --file="$WORK/aiec.dump" "$DATABASE_ARGV"
[ -s "$WORK/aiec.dump" ] && ok "dumped $(du -h "$WORK/aiec.dump" | cut -f1) of database state" \
  || bad "pg_dump produced nothing"

if pg_restore --exit-on-error --dbname="$RESTORED_ARGV" --no-owner --no-privileges "$WORK/aiec.dump"; then
  ok "restored into $DRILL_DB"
else
  bad "pg_restore failed"
  exit 1
fi

# The restored copy must be a working schema, not just a file.
tables=$(psql_q "$RESTORED_ARGV" "select count(*) from information_schema.tables where table_schema='public'")
[ "${tables:-0}" -gt 0 ] && ok "restored schema has $tables public tables" || bad "restored schema is empty"
migrations=$(psql_q "$RESTORED_ARGV" "select count(*) from _sqlx_migrations where success")
[ "${migrations:-0}" -gt 0 ] && ok "restored migration history ($migrations applied)" || bad "no migration history restored"

# ------------------------------------------------- 2. AIec on restored data
log "2. start the control plane against the restored database"
SERVER_BIN=""
if [ -n "${AIEC_DRILL_BIND:-}" ] || [ -n "${AIEC_DRILL_CA:-}" ]; then
  if [ -z "${AIEC_DRILL_BIND:-}" ] || [ -z "${AIEC_DRILL_CA:-}" ]; then
    bad "set both AIEC_DRILL_BIND and AIEC_DRILL_CA to check the restored server"
    exit 1
  fi
  for candidate in .aiec/acceptance-target/release/aiec-server \
    "${CARGO_TARGET_DIR:-target}/release/aiec-server" \
    "${CARGO_TARGET_DIR:-target}/debug/aiec-server"; do
    if [ -x "$candidate" ]; then
      SERVER_BIN=$candidate
      break
    fi
  done
  if [ -z "$SERVER_BIN" ]; then
    bad "no aiec-server binary found; build it first"
    exit 1
  fi
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
    api_status=$(curl --cacert "${AIEC_DRILL_CA:?}" -sS -o /dev/null -w '%{http_code}' \
      "https://${AIEC_DRILL_BIND}/ready" || echo 000)
    [ "$api_status" = 200 ] && ok "restored instance reports ready" \
      || bad "restored instance is not ready (HTTP $api_status)"
  else
    bad "control plane failed to start on restored data"
  fi
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
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
psql -X -v ON_ERROR_STOP=1 "$ADMIN_ARGV" -q -c "CREATE DATABASE \"$DRILL_DB2\"" >/dev/null
CREATED_DB2=1
RECOVERED_ARGV=$(acceptance_database_url_with_name "$ADMIN_ARGV" "$DRILL_DB2")
pg_restore --exit-on-error --dbname="$RECOVERED_ARGV" --no-owner --no-privileges "$WORK/aiec.dump" \
  && ok "restored a second copy after the simulated outage" \
  || { bad "recovery restore failed"; exit 1; }
recovered_tables=$(psql_q "$RECOVERED_ARGV" "select count(*) from information_schema.tables where table_schema='public'")
[ "${recovered_tables:-0}" = "${tables:-x}" ] \
  && ok "recovered copy matches the restored schema ($recovered_tables tables)" \
  || bad "recovered copy differs: $recovered_tables vs ${tables:-none}"
psql -X -v ON_ERROR_STOP=1 "$ADMIN_ARGV" -q -c "DROP DATABASE \"$DRILL_DB2\"" >/dev/null
CREATED_DB2=0

# ----------------------------------------------------------------- summary
log "summary"
if [ "$FAILED" -eq 0 ]; then
  printf 'BACKUP_RESTORE_DRILL: PASS\n'
  exit 0
fi
printf 'BACKUP_RESTORE_DRILL: FAIL (%d checks failed)\n' "$FAILED" >&2
exit 1
