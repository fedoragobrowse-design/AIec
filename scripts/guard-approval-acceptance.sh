#!/usr/bin/env bash
# Two-phase human approval acceptance (§44), against the deployed binaries, the
# real wire and a real PostgreSQL database.
#
# The approval surface is ownership-scoped rather than runtime-scoped: a queue
# entry is a row, a decision is a row, and a spend is a conditional update. None
# of it needs a microVM, a worker or a Guard gateway, so this suite deliberately
# runs the control plane alone. That keeps it fast enough to run on every change
# and keeps it honest about what it proves: the storage and API properties,
# not the runtime ones, which Phase 2 covers.
#
# Reuses the Phase 2 launcher's certificate and database layout so the two
# suites do not diverge in how they reach the server.
set -euo pipefail

# `APPROVAL_ROOT` is an operator override for a run that needs its directory to
# outlive it. The default must not be a fixed path: this one holds the run's TLS
# private keys and the API and worker credentials, and a name any local user can
# predict is a name any local user can read first — or own before we do, so the
# files below are written into a directory prepared to hand them over. `mktemp -d`
# creates the directory fresh with 0700 in one step, which is also why nothing
# here can be pre-created by someone else.
root=${APPROVAL_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/aiec-approval.XXXXXXXX")}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=${APPROVAL_REPO:-$(cd "$here/.." && pwd)}
bin=${P2_BIN:-$repo/target/release}

# Everything written below is a secret or a key. The permissions of the
# directory are only the first line; `openssl` and the servers also create files
# of their own, so the mode they are created with is pinned here as well.
umask 077
mkdir -p "$root/state" "$root/tls"
chmod 700 "$root" "$root/state" "$root/tls"

# The CA private key and the API key below are minted per run, so a root this
# script created has to go away with it. The old fixed path could only ever
# leave one behind and was overwritten each run; an unpredictable name with no
# removal leaves a fresh one every time, and the operator's override is the
# case that must survive.
approval_root_owned=0
if [ -z "${APPROVAL_ROOT:-}" ]; then
  approval_root_owned=1
  cleanup() {
    trap - EXIT INT TERM
    rm -rf -- "$root"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
fi
key=$(python3 -c 'import secrets;print(secrets.token_hex(24))')

cp_port=${P2_CP_PORT:-18544}
export P2_CP="https://127.0.0.1:$cp_port"
export P2_CP_BIND=127.0.0.1:$cp_port
worker_port=${P2_WORKER_PORT:-19544}
export P2_WORKER="https://127.0.0.1:$worker_port"
export P2_WORKER_BIND=127.0.0.1:$worker_port
export P2_TENANT=$(cat /proc/sys/kernel/random/uuid)
export P2_API_KEY="af_live_$key"
export P2_WORKER_TOKEN="af_live_$key"
# A certificate authority of its own, minted for this run. Borrowing an
# operator's long-lived key material to prove a test suite works would be a
# poor trade for files that cost nothing to regenerate.
export P2_CA=$root/tls/ca.crt
export P2_TLS_CERT=$root/tls/api.crt
export P2_TLS_KEY=$root/tls/api.key
if [ ! -s "$P2_CA" ]; then
  # `keyUsage=keyCertSign` is not decoration: OpenSSL 3 refuses a CA
  # certificate without it, and a Python client rejects the handshake outright
  # with CERTIFICATE_VERIFY_FAILED while curl quietly tolerates it. The suite
  # uses a Python client, so the run fails with no request in the server log -
  # which looks like the server never started.
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$root/tls/ca.key" -out "$P2_CA" \
    -subj "/CN=aiec-approval-acceptance-ca" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$P2_TLS_KEY" -out "$root/tls/api.csr" \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1
  printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' >"$root/tls/ext.cnf"
  openssl x509 -req -in "$root/tls/api.csr" -CA "$P2_CA" -CAkey "$root/tls/ca.key" \
    -CAcreateserial -days 2 -out "$P2_TLS_CERT" \
    -extfile "$root/tls/ext.cnf" >/dev/null 2>&1
  rm -f "$root/tls/api.csr"
fi
export P2_ROOT="$root"
export P2_BIN="$bin"
export APPROVAL_REPORT=${APPROVAL_REPORT:-$repo/benchmarks/guard-approval-acceptance.json}

# A database of its own, created before the run if it is not there. Two reasons,
# and the second is the important one: a shared database carries the stranded
# sandboxes of every other suite, and startup reclamation of those takes longer
# than any sane health deadline - so a suite pointed at one appears to fail for
# reasons that have nothing to do with it. Migrations also run against this at
# server start, which proves 0020 applies to a schema that has never seen it
# rather than to a table an earlier run created.
export DATABASE_URL=${APPROVAL_DATABASE_URL:-postgresql://aiec:aiec-dev-only@127.0.0.1:5432/aiec_approval}

set +e
python3 "$here/guard-approval-acceptance.py"
status=$?
set -e
exit "$status"
