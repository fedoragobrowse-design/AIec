#!/usr/bin/env bash
# Isolated PostgreSQL for a live acceptance run. Sourced by the launchers; it
# defines two functions and nothing else.
#
# There are two ways to satisfy the requirement, and the isolation is the
# requirement in both:
#
#   * a private cluster this run builds and destroys, which needs initdb and
#     pg_ctl on the host; or
#   * a caller-supplied server named through AIEC_ACCEPTANCE_DATABASE_URL,
#     pointing at a database this run owns alone.
#
# There is deliberately no third option. A suite that ran against another run's
# rows, or against the deployment's own database, would produce evidence that
# belongs to something else, and the failure would be invisible in the report.

# Refuses a supplied URL that does not name a database of its own. The check is
# on the database name alone: a suite named aiec_guard_phase5 is disposable, and
# `aiec` is the deployment's.
acceptance_database_is_isolated() {
  local url=$1 name
  name=${url##*/}
  name=${name%%\?*}
  [[ $name == aiec_guard_* ]]
}

acceptance_prepare_database() {
  # $1 run root, $2 pg data directory, $3 socket directory, $4 pg bin directory
  local root=$1 pg=$2 sock=$3 pg_bin=$4
  ACCEPTANCE_DB_CLUSTER=1
  if [[ -n ${AIEC_ACCEPTANCE_DATABASE_URL:-} ]]; then
    if ! acceptance_database_is_isolated "$AIEC_ACCEPTANCE_DATABASE_URL"; then
      printf 'refusing an acceptance database this run does not own alone: %s\n' \
        "$AIEC_ACCEPTANCE_DATABASE_URL" >&2
      printf 'name it aiec_guard_<suite> or build a private cluster instead\n' >&2
      exit 2
    fi
    # The suite's other half runs in its own network namespace, where the host's
    # TCP ports do not exist. The database is reached through a Unix socket
    # instead: a socket is a filesystem object, and the filesystem is shared.
    local relay_url=${AIEC_ACCEPTANCE_DATABASE_URL#postgresql://}
    local relay_creds=${relay_url%%@*}
    relay_url=${relay_url##*@}
    local relay_hostport=${relay_url%%/*}
    local relay_db=${relay_url#*/}
    relay_db=${relay_db%%\?*}
    [[ $relay_db == "$relay_url" ]] && {
      printf 'an acceptance database URL must name a database: %s\n' \
        "$AIEC_ACCEPTANCE_DATABASE_URL" >&2
      exit 2
    }
    mkdir -p "$sock"
    # sqlx reaches a Unix-socket PostgreSQL by directory and appends
    # `.s.PGSQL.5432` itself, so the listener has to carry that exact name.
    python3 "$(dirname "${BASH_SOURCE[0]}")/acceptance-relay.py" \
      unix "$sock/.s.PGSQL.5432" tcp "$relay_hostport" &
    ACCEPTANCE_DB_RELAY=$!
    local waited=0
    while [[ ! -S $sock/.s.PGSQL.5432 ]]; do
      kill -0 "$ACCEPTANCE_DB_RELAY" 2>/dev/null || {
        printf 'the database relay exited before it was ready\n' >&2
        exit 2
      }
      sleep 0.1
      waited=$((waited + 1))
      [[ $waited -lt 100 ]] || {
        printf 'the database relay never bound its socket\n' >&2
        exit 2
      }
    done
    export DATABASE_URL="postgresql://${relay_creds}@localhost/$relay_db?host=$sock"
    printf 'acceptance database: %s via a unix socket at %s\n' "$relay_db" "$sock" >&2
    # Nothing of this run's is inside the server's data directory, so the trap
    # reaps the processes and leaves the server to its owner.
    ACCEPTANCE_DB_CLUSTER=0
    return
  fi
  mkdir -p "$pg" "$sock"
  chmod 700 "$root"
  [[ -x $pg_bin/initdb && -x $pg_bin/pg_ctl ]] || {
    printf 'no PostgreSQL server binaries at %s; set P?_PG_BIN or AIEC_ACCEPTANCE_DATABASE_URL\n' \
      "$pg_bin" >&2
    exit 2
  }
  # A fresh cluster per run: capacity, leases and quarantined sandboxes from an
  # earlier run would otherwise make this one start against a host that is
  # already full, which is a stale-fixture failure rather than a product one.
  "$pg_bin/pg_ctl" -D "$pg" -m immediate stop >/dev/null 2>&1 || true
  rm -rf -- "$sock" "$pg"
  mkdir -p "$sock"
  "$pg_bin/initdb" -D "$pg" -U aiec -A trust --no-sync >"$root/initdb.log" 2>&1
  "$pg_bin/pg_ctl" -D "$pg" -o "-k $sock -h ''" -l "$root/postgres.log" -w start >/dev/null
  # The bundled server has no client binaries, so the acceptance uses the
  # database `initdb` already created rather than one it cannot ask for.
  export DATABASE_URL="postgresql://aiec@localhost/postgres?host=$sock"
}

# Reaps anything this run started before stopping the database. The drivers
# launch a control plane and a worker, and `unshare --kill-child` only kills the
# direct child, so an interrupted run otherwise leaves servers bound to this
# run's directory and ports. Matching is on this run's own root, which is unique
# per run, so nothing belonging to another run can be caught by it.
acceptance_stop_database() {
  # $1 run root, $2 pg data directory, $3 pg bin directory
  local root=$1 pg=$2 pg_bin=$3
  pkill -9 -f -- "$root" >/dev/null 2>&1 || true
  # The relay runs in the outer namespace and would otherwise outlive the run,
  # still holding the socket a later run is about to bind.
  [[ -n ${ACCEPTANCE_DB_RELAY:-} ]] && kill "$ACCEPTANCE_DB_RELAY" 2>/dev/null
  if [[ ${ACCEPTANCE_DB_CLUSTER:-1} == 1 ]]; then
    "$pg_bin/pg_ctl" -D "$pg" -m immediate stop >/dev/null 2>&1 || true
  fi
  rmdir "$root/.lock" 2>/dev/null || true
}
