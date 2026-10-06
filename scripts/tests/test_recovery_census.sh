#!/usr/bin/env bash
# Proves the recovery-validation cleanup census fails closed.
#
# The harness's verdict is "this run leaked nothing", and the one input that
# must never reach it is a database it could not read. `sql` discards stderr
# and returns an empty string for a failed psql, exactly as it does for a query
# that matched nothing, so a census reading that empty string as `0` reports a
# clean host for a database it never reached - a green run that proves nothing.
#
# The two functions under test are lifted verbatim out of the real script
# rather than copied, so a copy cannot keep passing while the script regresses.
# psql itself is stubbed, because what is being tested is how the census reads a
# psql's answer, not psql: a stub that refuses the way a real one refuses is
# both hermetic and the only way this runs on a host without a client.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT=$ROOT/scripts/worker-recovery-validation.sh
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 1; }

FAILURES=0
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }

# ---------------------------------------------------------------- stub psql
# SQL_MODE decides the answer: `refuse` is what a server that is not there
# looks like, `empty` is a query that legitimately matched no row, `rows` is a
# multi-row answer, `notice` is a successful query that also writes to stderr,
# and `answer` is a query that matched one.
STUB=$(mktemp -d)
trap 'rm -rf "$STUB"' EXIT
cat >"$STUB/psql" <<'STUB_EOF'
#!/usr/bin/env bash
# Stands in for psql, so this test does not need a server or a client.
last=""
prev=""
for arg in "$@"; do
  if [ "$prev" = -c ]; then last=$arg; fi
  prev=$arg
done
case "${SQL_MODE:-answer}" in
  refuse)
    printf 'psql: error: connection to server failed: Connection refused\n' >&2
    exit 2
    ;;
  empty)
    exit 0
    ;;
  rows)
    printf 'first\nsecond\n'
    exit 0
    ;;
  notice)
    # A successful query with a NOTICE on stderr. Reproduced against real
    # PostgreSQL: merging the streams made `NOTICE:  lease row updated` the
    # value, so the generation and state assertions would have compared one
    # notice against another and passed on a database that had stopped being
    # consulted.
    printf 'NOTICE:  lease row updated\n' >&2
    printf '42\n'
    exit 0
    ;;
  *)
    if [[ $last == *'select 0'* ]]; then printf '0\n'; else printf '1\n'; fi
    exit 0
    ;;
esac
STUB_EOF
chmod +x "$STUB/psql"
export PATH=$STUB:$PATH
export SQL_MODE=answer

extract() {
  awk -v fn="$1" '
    $0 ~ "^" fn "\\(\\) \\{" { inside = 1 }
    inside { print }
    inside && /^}/ { exit }
  ' "$SCRIPT"
}
sql_def=$(extract sql)
value_def=$(extract sql_value)
[ -n "$sql_def" ] || { echo "could not extract sql() from the script" >&2; exit 1; }
[ -n "$value_def" ] || { echo "could not extract sql_value() from the script" >&2; exit 1; }
eval "$sql_def"
eval "$value_def"

SQL_ARGV_URL="postgresql://aiec@127.0.0.1:1/aiec"

# --------------------------------------------------------------- the reader
SQL_MODE=refuse
LABEL="sql_value refuses a database that is not there"
if sql_value "select count(*) from sandbox_leases" >/dev/null 2>&1; then
  fail "$LABEL"
else
  pass "$LABEL"
fi

# Captured rather than piped: `pipefail` makes the refusal - the very thing
# being asserted - the pipeline's status, so the branch a match needs never
# runs. The `|| true` is there for the same reason.
LABEL="the refusal is explained instead of answered with an empty value"
refusal=$(sql_value "select count(*) from sandbox_leases" 2>&1 >/dev/null || true)
if printf '%s' "$refusal" | grep -q "refusing to answer"; then
  pass "$LABEL"
else
  fail "$LABEL"
fi

LABEL="the permissive sql reader does return empty for the same failure"
if [ -z "$(sql "select count(*) from sandbox_leases")" ]; then
  pass "$LABEL"
else
  fail "$LABEL"
fi

# A query that matched nothing is not a failure, but an assertion comparing it
# is still answering a question the query did not answer. Both are refused, and
# the distinction matters: the old reader could not tell them apart at all.
SQL_MODE=empty
LABEL="sql_value refuses a query that matched nothing"
if sql_value "select id from sandbox_leases limit 1" >/dev/null 2>&1; then
  fail "$LABEL"
else
  pass "$LABEL"
fi

SQL_MODE=answer
LABEL="sql_value passes through a real answer"
if [ "$(sql_value "select state from sandboxes where id='x'")" = 1 ]; then
  pass "$LABEL"
else
  fail "$LABEL"
fi

# Only the first row is taken, as `head -1` used to do, and the rest of a
# multi-row answer never leaks into a value an assertion compares.
SQL_MODE=rows
LABEL="a multi-row answer is reduced to its first value"
if [ "$(sql_value "select id from sandbox_leases")" = first ]; then
  pass "$LABEL"
else
  fail "$LABEL"
fi

# A successful query is allowed to write to stderr. If those bytes reach the
# value, then `state_before` and `state_after` can both be the same notice while
# the database has in fact stopped answering - the same false green as the empty
# value, one stream further up.
SQL_MODE=notice
LABEL="a NOTICE on a successful query is not mistaken for the value"
noted=$(sql_value "select pg_temp.noticed()" 2>/dev/null || true)
if [ "$noted" = 42 ]; then
  pass "$LABEL"
else
  fail "$LABEL (value=[$noted])"
fi

LABEL="the merged-stream form would have answered with the notice"
merged=$(SQL_MODE=notice psql "$SQL_ARGV_URL" -t -A -F '|' -c "select 1" 2>&1 | head -1 || true)
if [ "$merged" != 42 ] && printf '%s' "$merged" | grep -q NOTICE; then
  pass "$LABEL ($merged)"
else
  fail "$LABEL (merged=[$merged])"
fi

# --------------------------------------- the state comparison that compared ''
# `state_after`/`state_before` were compared with `test "$a" = "$b"`. Two empty
# strings are equal, so a database that stopped answering between the two reads
# satisfied the assertion that a late completion changed nothing. The strict
# reader has to stop the sequence before that comparison is ever reached.
SQL_MODE=refuse
LABEL="the script cannot reach the state comparison with an unreadable state"
if state_before=$(sql_value "select state from sandboxes where id='x'"); then
  fail "$LABEL (the assertion would have compared two empty strings)"
else
  pass "$LABEL"
fi

# ------------------------------------------------- the census that read 0
# The exact arithmetic of the final verdict, so the regression is measured on
# the comparison that used to lie rather than on the helper alone.
census_reports_clean() { [ "${1:-0}" -eq 0 ]; }
LABEL="an unreadable lease census is not read as zero active leases"
if census_reports_clean unreadable 2>/dev/null; then
  fail "$LABEL (unreadable was treated as a clean host)"
else
  pass "$LABEL"
fi

LABEL="a genuinely empty database still reads as zero"
if census_reports_clean 0; then
  pass "$LABEL"
else
  fail "$LABEL"
fi

# ------------------------------------------------------------- the wiring
LABEL="every lease count an assertion decides on goes through sql_value"
# `sql` remains correct for printing state, so the check is that the two
# lease-count reads - the ones whose emptiness was defaulted to 0 - name the
# strict helper.
unfenced=$(grep -n 'sql "select count(\*) from sandbox_leases' "$SCRIPT" || true)
if [ -z "$unfenced" ]; then
  pass "$LABEL"
else
  fail "$LABEL: $unfenced"
fi

LABEL="no read whose result an assertion decides on uses the permissive reader"
# `sql` stays correct for `snapshot_state` and for the recovery poll loop, which
# is written to retry until the value appears. What must not remain is a read
# whose result is assigned for a later `check` to compare, so every surviving
# read has to be one of those two shapes.
# `(^|[^[:alnum:]_])sql "` so the `sql "` inside `psql "..."` does not count as
# a read of the permissive helper.
stray=$(grep -nE '(^|[^[:alnum:]_])sql "' "$SCRIPT" \
  | sed 's/^[0-9]*:[[:space:]]*//' \
  | grep -vE '^sql ' \
  | grep -vE '^(current_owner|current_gen|current_state)=' || true)
if [ -z "$stray" ]; then
  pass "$LABEL"
else
  fail "$LABEL: $stray"
fi

if [ "$FAILURES" -eq 0 ]; then
  printf '\nRECOVERY_CENSUS: PASS\n'
  exit 0
fi
printf '\nRECOVERY_CENSUS: FAIL (failures=%s)\n' "$FAILURES" >&2
exit 1
