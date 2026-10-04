#!/usr/bin/env bash
# Plumbing shared by the acceptance launchers. Sourced by them; it defines
# functions, mints one per-run identifier, and does nothing else.
#
# A run owns three things: this run's identifier, this run's scratch directory,
# and this run's database. Everything else on the host - a deployment, another
# run, the operator's own work - is out of scope and is never deleted, never
# counted as a leftover and never asserted to be gone.
#
# The database is either a private cluster this run builds and stops, or a
# caller-supplied server named through AIEC_ACCEPTANCE_DATABASE_URL pointing at
# a database this run owns alone. There is deliberately no third option: a suite
# that ran against another run's rows would produce evidence belonging to
# something else, and the failure would be invisible in the report.

# The per-run identifier, minted at source time so every process these
# launchers start inherits it: the control plane, the workers, the Firecracker
# processes the workers spawn, and the database relay. A process scan can then
# ask /proc/<pid>/environ for this exact value, which is evidence of descent
# from this run rather than a coincidence of command lines. The value is never
# printed.
if [ -z "${AIEC_ACCEPTANCE_RUN_ID:-}" ]; then
  AIEC_ACCEPTANCE_RUN_ID=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
  export AIEC_ACCEPTANCE_RUN_ID
fi

# Replaces the identifier with a fresh one. A launcher calls this before it
# starts anything, so two runs can never share a value - including a second run
# of the same launcher, and including a launcher invoked from a shell that
# sourced this file earlier for its own reasons.
acceptance_mark_run() {
  AIEC_ACCEPTANCE_RUN_ID=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
  export AIEC_ACCEPTANCE_RUN_ID
}

# Claims a scratch directory for this run, and refuses everything else.
#
# One rule: the path must not exist. An existing directory, file or symlink is
# somebody else's, and treating it as this run's scratch is what turns a re-run
# into evidence deletion. So the path is canonicalised and checked first, and
# only then created with a plain `mkdir`, which also refuses a path that turned
# up in the meantime. Nothing under the directory is removed on the way in: the
# directory was empty a moment ago, and the only way to delete a subtree of a
# caller-owned path is to accept one.
#
# Sets ACCEPTANCE_RUN_DIR to the canonical path.
#
# $1 requested path, $2 checkout root to protect.
acceptance_claim_run_dir() {
  local requested=$1 checkout=$2 resolved parent
  case $requested in
    ''|/|.|..)
      printf 'refusing to run: %s is not a scratch directory this run may own\n' "$requested" >&2
      return 2
      ;;
  esac
  if [ -e "$requested" ] || [ -L "$requested" ]; then
    printf 'refusing to run: %s already exists; remove it or choose a path this run may create\n' \
      "$requested" >&2
    return 2
  fi
  resolved=$(realpath -m -- "$requested") || {
    printf 'refusing to run: %s cannot be canonicalised\n' "$requested" >&2
    return 2
  }
  case $resolved in
    /*/*) ;;
    *)
      printf 'refusing to run: %s is too shallow to be a scratch directory\n' "$resolved" >&2
      return 2
      ;;
  esac
  case $resolved in
    /|/root|/home|/usr|/etc|/var|/tmp|/proc|/sys|/dev|/boot|"$checkout"|"$checkout"/scripts|"$checkout"/.git)
      printf 'refusing to run: %s is not a scratch directory this run may own\n' "$resolved" >&2
      return 2
      ;;
  esac
  case "$checkout/" in
    "$resolved"/*)
      printf 'refusing to run: %s contains the checkout at %s\n' "$resolved" "$checkout" >&2
      return 2
      ;;
  esac
  # The parent chain is created when it is missing. Every existing component has
  # been canonicalised above, so this only ever adds directories the caller
  # named on the way to a path nothing occupies.
  parent=${resolved%/*}
  mkdir -p -- "$parent" || {
    printf 'refusing to run: %s could not be created\n' "$resolved" >&2
    return 2
  }
  mkdir -- "$resolved" || {
    printf 'refusing to run: %s could not be created exclusively; another run owns it\n' \
      "$resolved" >&2
    return 2
  }
  chmod 700 -- "$resolved"
  ACCEPTANCE_RUN_DIR=$resolved
}

# Refuses to continue unless this process is already in a network namespace of
# its own.
#
# The Firecracker path creates TAP devices, nftables tables and masquerade rules.
# Run in the host namespace those land on the machine the deployment is serving
# from, so the refusal has to happen before a process starts and before any
# network is touched, not be a warning the operator can decline. There is no
# fallback path: the caller has to supply the namespace to have left behind and
# start the run somewhere else.
#
# $1 label for the message, $2 variable naming the host namespace.
acceptance_require_private_netns() {
  local host_ns=${!2:-} current
  current=$(readlink /proc/self/ns/net 2>/dev/null) || current=''
  if [ -z "$current" ]; then
    printf 'refusing to run %s: this process'"'"'s network namespace cannot be read\n' "$1" >&2
    return 2
  fi
  # Accepts the namespace as `readlink /proc/self/ns/net` printed it, or as the
  # path of a namespace file to read it from.
  case $host_ns in
    net:*) ;;
    '') ;;
    *) host_ns=$(readlink -- "$host_ns" 2>/dev/null) || host_ns='' ;;
  esac
  if [ -z "$host_ns" ]; then
    printf 'refusing to run %s: set %s to the network namespace this run must not share\n' \
      "$1" "$2" >&2
    printf 'capture it with `readlink /proc/self/ns/net` before entering a private one\n' >&2
    return 2
  fi
  if [ "$host_ns" = "$current" ]; then
    printf 'refusing to run %s in the host network namespace\n' "$1" >&2
    return 2
  fi
  ACCEPTANCE_NETNS=$current
}

# Brings loopback up in the namespace the run is already confined to. Every
# address these launchers bind is 127.0.0.1 and a fresh namespace has it down.
# This is namespace-local: no host interface, route or firewall rule changes.
acceptance_netns_loopback_up() {
  command -v ip >/dev/null 2>&1 || {
    printf 'ip is required to bring loopback up inside the run namespace\n' >&2
    return 2
  }
  ip link set lo up || return 2
}

# The database name a PostgreSQL URL names, and nothing else.
#
# Query first, then path: a socket directory is a query parameter containing
# slashes (`?host=/run/postgresql`), so stripping the path first would read the
# last component of the socket path as the database name.
#
# A URL that names no database at all is refused rather than parsed. Its last
# path component is then the authority — `user:password@host:port` — so
# `${url##*/}` would hand back credentials, and the caller that prints this name
# for a diagnostic would print a password. A component carrying `@` or `:` is
# therefore refused. `:` is legal unescaped in a URL path segment per RFC 3986
# (`pchar` includes it), so this is not a standards rule — it is the conservative
# reading. An authority without userinfo, `host:port`, carries no `@` and the
# `*:*` arm is what stops it, which is why that arm is here and not just `*@*`.
# A database name legitimately containing `:` would be refused; that is a
# deliberate trade against printing a password, and no caller in this tree uses
# one.
#
# Callers must not rely on an isolation check running first to make the
# credential case unreachable; this function's contract is "a database name and
# nothing else", so a credential is not a database name. Verified directly,
# including with `ACCEPTANCE_DB_NAME_PATTERN` set to `*`: the refusal happens
# before any pattern is consulted, so a wildcard pattern does not reopen it.
acceptance_database_url_name() {
  local url=$1
  url=${url%%\?*}
  local name=${url##*/}
  case $name in
    '' | /* | *@* | *:*) return 1 ;;
  esac
  printf '%s\n' "$name"
}

# True when the URL reaches PostgreSQL through a Unix socket: a `host` query
# parameter naming an absolute path rather than a `host:port` authority, written
# literally or percent-encoded as a URL requires. A socket is a filesystem
# object with no network namespace of its own, so such a URL is reachable
# unchanged from inside a run's private namespace and needs no relay.
acceptance_database_is_socket_url() {
  local url=$1 query pair key value
  [[ $url == *\?* ]] || return 1
  query=${url#*\?}
  local IFS='&'
  for pair in $query; do
    key=${pair%%=*}
    value=${pair#*=}
    case $key in
      host|Host|HOST) ;;
      *) continue ;;
    esac
    case $value in
      /*) return 0 ;;
      '%'2[Ff]*) return 0 ;;
      *) return 1 ;;
    esac
  done
  return 1
}

# Splits a URL that reaches a TCP server into its parts, for the relay.
# Sets ACCEPTANCE_DB_CREDS, ACCEPTANCE_DB_HOSTPORT and ACCEPTANCE_DB_NAME.
# Credentials and query survive untouched and are never printed.
#
# $1 URL.
acceptance_database_url_tcp_parts() {
  local url=$1 rest hostport creds= db
  case $url in
    postgres://*|postgresql://*) ;;
    *)
      printf 'the acceptance database URL is not a PostgreSQL URL\n' >&2
      return 2
      ;;
  esac
  rest=${url#*://}
  if [[ $rest == *\?* ]]; then rest=${rest%%\?*}; fi
  db=${rest#*/}
  if [ "$db" = "$rest" ] || [ -z "$db" ] || [[ $db == */* ]]; then
    printf 'the acceptance database URL must name a database\n' >&2
    return 2
  fi
  creds=
  hostport=${rest%%/*}
  if [[ $hostport == *@* ]]; then
    creds=${hostport%@*}
    hostport=${hostport#*@}
  fi
  if [ -z "$hostport" ] || [[ $hostport == */* ]]; then
    printf 'the acceptance database URL must name a host and a port\n' >&2
    return 2
  fi
  ACCEPTANCE_DB_CREDS=$creds
  ACCEPTANCE_DB_HOSTPORT=$hostport
  ACCEPTANCE_DB_NAME=$db
}

# Rewrites the database component of a PostgreSQL URL and preserves everything
# else verbatim: scheme, credentials, host, port and query. Only the name is
# replaced, which is what makes the function correct for both a TCP URL and one
# that names its socket directory in the query.
acceptance_database_url_with_name() {
  local url=$1 name=$2 scheme rest authority query=
  case $url in
    postgres://*) scheme=postgres:// rest=${url#postgres://} ;;
    postgresql://*) scheme=postgresql:// rest=${url#postgresql://} ;;
    *)
      printf 'the acceptance database URL is not a PostgreSQL URL\n' >&2
      return 2
      ;;
  esac
  if [[ $rest == *\?* ]]; then
    query="?${rest#*\?}"
    rest=${rest%%\?*}
  fi
  # The scheme comes off first: `%%/*` on the whole URL would cut at the first
  # slash, which in `postgresql://user@host/db` belongs to the `//`.
  if [[ ${rest#*/} == "$rest" ]]; then
    printf 'the acceptance database URL must name a database\n' >&2
    return 2
  fi
  authority=${rest%%/*}
  acceptance_check_database_identifier "$name" || return 2
  printf '%s%s/%s%s\n' "$scheme" "$authority" "$name" "$query"
}

# Refuses a database name that is not a plain unquoted SQL identifier of a size
# PostgreSQL accepts.
#
# A name reaches `CREATE DATABASE` and `DROP DATABASE` as interpolated text, so
# a name carrying a quote or a semicolon is DDL the caller did not intend to
# write, and a longer one is silently truncated by the server into a different
# database than the one that was created. Refusing is the only safe answer, and
# it is checked here so every caller inherits it.
acceptance_check_database_identifier() {
  if [[ $1 =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && [ "${#1}" -le 63 ]; then
    return 0
  fi
  printf 'refusing database name %s: it must be a plain identifier of at most 63 bytes\n' "$1" >&2
  return 2
}

# Succeeds when nothing is listening on a loopback TCP port.
#
# A launcher binds a fixed, documented port on a shared host. Finding one
# already bound means the address belongs to someone else, and binding it
# anyway is either an error the run reports as a product fault or a connection
# to somebody else's control plane, whose rows this run then reads and writes.
# "Somebody else is listening" and "this process cannot bind" both refuse,
# which is the right direction for both.
acceptance_port_free() {
  python3 - "$1" <<'PY'
import socket, sys

probe = socket.socket()
# TIME_WAIT from an earlier run is not an owner; a LISTEN socket still is.
probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    probe.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    probe.close()
PY
}

# Prints the pids of processes this run started: those whose command line
# contains $1, optionally restricted to those whose executable lives under $2,
# and - in every case - only those carrying this run's exact inherited
# identifier.
#
# The identifier is the proof. A command-line substring is not: it is text any
# process on the host can contain, including a deployment pointed at a similar
# path, and `pkill -f` cannot narrow a match afterwards. The subprocesses a
# run starts inherit the identifier, and so does everything they start, so the
# match is exact and a process that never descended from this run is never
# touched - which is also why a scan refuses outright when no identifier is
# present rather than falling back to the substring alone.
#
# The calling shell and its ancestors are never reported: the scan runs inside
# them, and a sweep that matched the shell whose trap invoked it would stop the
# run before it could clean anything else up.
#
# $1 command-line substring, $2 executable prefix (optional).
acceptance_run_owned_pids() {
  if [ -z "${AIEC_ACCEPTANCE_RUN_ID:-}" ]; then
    printf 'refusing to scan for this run'"'"'s processes without a run identifier\n' >&2
    return 2
  fi
  # The identifier travels in the environment, never on a command line, and is
  # never printed.
  python3 - "$1" "${2:-}" <<'PY'
import os, sys

pattern, root = sys.argv[1], sys.argv[2]
mark = f"AIEC_ACCEPTANCE_RUN_ID={os.environ['AIEC_ACCEPTANCE_RUN_ID']}".encode()


def parent(pid):
    with open(f"/proc/{pid}/stat") as handle:
        return int(handle.read().rsplit(") ", 1)[1].split()[1])


def carries_the_run_marker(pid):
    try:
        with open(f"/proc/{pid}/environ", "rb") as handle:
            return mark in handle.read().split(b"\0")
    except OSError:
        return False


skip, pid = set(), os.getpid()
while pid > 1 and pid not in skip:
    skip.add(pid)
    try:
        pid = parent(pid)
    except (OSError, IndexError, ValueError):
        break

for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    pid = int(entry)
    if pid in skip or not carries_the_run_marker(pid):
        continue
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            command = handle.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        continue
    if pattern and pattern not in command:
        continue
    if root:
        try:
            executable = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue
        if executable != root and not executable.startswith(root.rstrip("/") + "/"):
            continue
    print(pid)
PY
}

# Refuses a supplied URL that does not name a database of its own. The check is
# on the database name alone: a suite named aiec_guard_phase5 is disposable, and
# `aiec` is the deployment's. The pattern is a parameter so a suite with its own
# disposable prefix can name one without weakening the default.
acceptance_database_is_isolated() {
  # $1 URL, $2 disposable-name pattern (optional)
  local name pattern=${2:-aiec_guard_*}
  name=$(acceptance_database_url_name "$1") || return 1
  [[ -n $name && $name != /* ]] && [[ $name == $pattern ]]
}

# True when the docker CLI is reachable, directly or through `sg docker`, and
# records which in DOCKER_VIA_SG.
acceptance_have_docker() {
  if command -v docker >/dev/null 2>&1; then
    DOCKER_VIA_SG=0
    return 0
  fi
  # On the host the CLI is reachable only as a member of the docker group, and
  # that is only true if this invocation can join it.
  # `</dev/null` because a caller who is not a member of the docker group makes
  # sg ask for the group password; with no terminal the run would otherwise wait
  # on stdin here and at every later invocation instead of reporting the CLI
  # unavailable.
  if command -v sg >/dev/null 2>&1 \
    && sg docker -c 'command -v docker >/dev/null' </dev/null 2>/dev/null; then
    DOCKER_VIA_SG=1
    return 0
  fi
  DOCKER_VIA_SG=0
  return 1
}

# Runs the docker CLI with this run's arguments.
#
# `sg` executes its command through a shell and does not forward the arguments
# after it, so `sg docker ps -a -q` runs `ps` and reports nothing - an
# invocation that silently never reaches docker. The command line is therefore
# assembled here with shell quoting rather than handed over as argv.
acceptance_docker_cli() {
  if [ "${DOCKER_VIA_SG:-0}" != 1 ]; then
    docker "$@"
    return
  fi
  local line='docker' argument
  for argument in "$@"; do
    line="$line $(printf '%q' "$argument")"
  done
  sg docker -c "$line" </dev/null
}

acceptance_prepare_database() {
  # $1 run root, $2 pg data directory, $3 socket directory, $4 pg bin directory
  local root=$1 pg=$2 sock=$3 pg_bin=$4
  ACCEPTANCE_DB_CLUSTER=1
  if [[ -n ${AIEC_ACCEPTANCE_DATABASE_URL:-} ]]; then
    if ! acceptance_database_is_isolated "$AIEC_ACCEPTANCE_DATABASE_URL" "${ACCEPTANCE_DB_NAME_PATTERN:-}"; then
      printf 'refusing an acceptance database this run does not own alone\n' >&2
      printf 'name it aiec_guard_<suite> or build a private cluster instead\n' >&2
      exit 2
    fi
    # A URL that already names a Unix socket needs no relay: a socket is a
    # filesystem object, which the run's namespace shares, and parsing it as
    # `credentials@host:port/db` would read the socket directory as a host.
    if acceptance_database_is_socket_url "$AIEC_ACCEPTANCE_DATABASE_URL"; then
      export DATABASE_URL="$AIEC_ACCEPTANCE_DATABASE_URL"
      printf 'acceptance database: %s via the unix socket it already names\n' \
        "$(acceptance_database_url_name "$AIEC_ACCEPTANCE_DATABASE_URL")" >&2 || exit 2
      ACCEPTANCE_DB_CLUSTER=0
      return
    fi
    # The suite's other half runs in its own network namespace, where the
    # host's TCP ports do not exist. The database is reached through a Unix
    # socket instead, because the filesystem is shared.
    acceptance_database_url_tcp_parts "$AIEC_ACCEPTANCE_DATABASE_URL" || exit 2
    local creds=$ACCEPTANCE_DB_CREDS hostport=$ACCEPTANCE_DB_HOSTPORT db=$ACCEPTANCE_DB_NAME
    mkdir -p "$sock"
    # sqlx reaches a Unix-socket PostgreSQL by directory and appends
    # `.s.PGSQL.5432` itself, so the listener has to carry that exact name.
    python3 "$(dirname "${BASH_SOURCE[0]}")/acceptance-relay.py" \
      unix "$sock/.s.PGSQL.5432" tcp "$hostport" &
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
    if [ -n "$creds" ]; then
      export DATABASE_URL="postgresql://${creds}@localhost/$db?host=$sock"
    else
      export DATABASE_URL="postgresql://localhost/$db?host=$sock"
    fi
    printf 'acceptance database: %s via a unix socket at %s\n' "$db" "$sock" >&2
    # Nothing of this run's is inside the server's data directory, so the trap
    # reaps the processes and leaves the server to its owner.
    ACCEPTANCE_DB_CLUSTER=0
    return
  fi
  mkdir -p "$pg" "$sock"
  chmod 700 "$root"
  [[ -x $pg_bin/initdb && -x $pg_bin/pg_ctl ]] || {
    printf 'no PostgreSQL server binaries at %s; point the launcher'"'"'s pg bin variable at them, or set AIEC_ACCEPTANCE_DATABASE_URL\n' \
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

# Sets AIEC_IMAGE_MANIFEST and AIEC_IMAGE_MANIFEST_SECRET for a run that has not
# been given them, minted per run in this run's own scratch directory so nothing
# is written into the deployment's image directory and no run can inherit
# another's key. The digest is read from the artifact metadata the guest build
# wrote, never recomputed here.
#
# $1 run root, $2 image reference, $3 path to guest-capabilities.json.
acceptance_prepare_image_manifest() {
  local root=$1 reference=$2 capabilities=$3 directory
  [[ -f $capabilities ]] || {
    printf 'guest capability metadata %s does not exist\n' "$capabilities" >&2
    exit 2
  }
  if [[ -n ${AIEC_IMAGE_MANIFEST:-${AGENTFORGE_IMAGE_MANIFEST:-}} ]]; then
    export AIEC_IMAGE_MANIFEST=${AIEC_IMAGE_MANIFEST:-$AGENTFORGE_IMAGE_MANIFEST}
    export AIEC_IMAGE_MANIFEST_SECRET=${AIEC_IMAGE_MANIFEST_SECRET:-${AGENTFORGE_IMAGE_MANIFEST_SECRET:-}}
    [[ -f $AIEC_IMAGE_MANIFEST ]] || {
      printf 'image manifest %s does not exist\n' "$AIEC_IMAGE_MANIFEST" >&2
      exit 2
    }
    return
  fi
  directory=$root/image-manifest
  mkdir -p "$directory"
  chmod 700 "$directory"
  python3 - "$directory" "$reference" "$capabilities" <<'PY'
import hashlib, hmac, json, os, secrets, sys

directory, reference, capabilities = sys.argv[1], sys.argv[2], sys.argv[3]
with open(capabilities) as handle:
    digest = json.load(handle)["rootfs_sha256"]
manifest_path = os.path.join(directory, "manifest.json")
secret_path = os.path.join(directory, "secret")


def signature(secret):
    return hmac.new(
        secret.encode(), reference.encode() + b"\0" + digest.encode(), hashlib.sha256
    ).hexdigest()


def still_describes_these_bytes():
    """A retained manifest is reused only while it names this reference and
    digest under its own secret. Existence proves nothing: a run that pointed
    AIEC_ROOTFS at different scratch material leaves a manifest behind that
    describes those bytes, and reusing it makes the control plane hash this
    run's rootfs against an image it never signed - which fails closed with a
    digest mismatch that names neither the manifest nor the file."""
    try:
        with open(manifest_path) as handle:
            manifest = json.load(handle)
        with open(secret_path) as handle:
            secret = handle.read().strip()
    except (OSError, ValueError):
        return False
    return (
        manifest.get("reference") == reference
        and manifest.get("rootfs_sha256") == digest
        and hmac.compare_digest(manifest.get("signature", ""), signature(secret))
    )


def mint():
    secret = secrets.token_hex(32)
    manifest = {"reference": reference, "rootfs_sha256": digest, "signature": signature(secret)}
    fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(manifest, handle)
    # Owner-only from the first byte: this file is the deployment signing secret
    # for the lifetime of the run, not something to create readable and
    # tighten. Written after the manifest it signs, so an interrupted mint
    # leaves a pair the check above refuses and the next run replaces.
    fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(secret)


if not still_describes_these_bytes():
    mint()
PY
  export AIEC_IMAGE_MANIFEST=$directory/manifest.json
  export AIEC_IMAGE_MANIFEST_SECRET=$(cat "$directory/secret")
}

# Reaps anything this run started, then stops the database. The drivers launch a
# control plane and a worker, and `unshare --kill-child` only kills the direct
# child, so an interrupted run otherwise leaves servers bound to this run's
# directory and ports. The sweep goes through acceptance_run_owned_pids rather
# than `pkill -f`, which would signal every process on the host whose arguments
# mention the path and report afterwards no way to tell which was which.
acceptance_stop_database() {
  # $1 run root, $2 pg data directory, $3 pg bin directory
  local root=$1 pg=$2 pg_bin=$3 pid
  for pid in $(acceptance_run_owned_pids "$root" ""); do
    kill -9 "$pid" 2>/dev/null || true
  done
  # The relay runs in the outer namespace and would otherwise outlive the run,
  # still holding the socket a later run is about to bind.
  if [[ -n ${ACCEPTANCE_DB_RELAY:-} ]]; then
    kill "$ACCEPTANCE_DB_RELAY" 2>/dev/null
    wait "$ACCEPTANCE_DB_RELAY" 2>/dev/null
    ACCEPTANCE_DB_RELAY=
  fi
  if [[ ${ACCEPTANCE_DB_CLUSTER:-1} == 1 ]]; then
    "$pg_bin/pg_ctl" -D "$pg" -m immediate stop >/dev/null 2>&1 || true
  fi
  # Some launchers take a separate lock directory beside their scratch; releasing
  # it here keeps one trap responsible for both.
  rmdir "$root/.lock" 2>/dev/null || true
}
