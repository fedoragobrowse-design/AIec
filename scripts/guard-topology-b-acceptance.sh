#!/usr/bin/env bash
# Guard Topology B live acceptance (§50).
#
# Topology B is the shipped claim that "the agent runs outside": the trusted
# harness drives the sandbox through AIec's existing control channel and the
# guest is given no egress at all. This suite exists because that claim is a
# property of a *deployment* and not of a function: it is only observable when
# a real control plane, a real worker, a real microVM guest and a real kernel
# network boundary are all in play at once, and when the packet counters live
# in the host's own nftables table rather than in a test double.
#
# The runtime must be Firecracker. Guard is not implemented by the container
# runtime - `firecracker_capabilities` is what advertises `network_policy`, and
# the Guard attachment (TAP, gateway, nftables) exists only on the microVM
# path - so a Docker sandbox cannot carry a Guard policy at all. Placing a
# topology-B claim on Docker would be a claim about nothing.
#
# Everything runs inside one private user+network namespace, for the same reason
# the Phase 2 launcher does it: the nftables tables, the TAP and the routes are
# real and kernel-enforced, and they exist only for the duration of the run. The
# host's own ruleset is never read for a decision, never flushed and never
# modified - the whole stack cannot reach it.
#
# PostgreSQL runs outside the namespace and is reached over a Unix socket, which
# a network namespace cannot take away. The relay in this file is what makes
# that possible against a shared server rather than a private cluster.
set -euo pipefail

root=${TOPOB_ROOT:-${TMPDIR:-/tmp}/aiec-topology-b}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=${TOPOB_REPO:-$(cd "$here/.." && pwd)}
bin=${TOPOB_BIN:-$repo/target/release}

die() { printf '%s\n' "$*" >&2; exit 2; }

host_netns=$(readlink /proc/self/ns/net)
[[ $host_netns == net:* ]] || die 'cannot read the host network namespace'

if [[ ${1:-} != --inside ]]; then
  [[ -x "$bin/aiec-server" && -x "$bin/aiec" ]] || die "release binaries required in TOPOB_BIN ($bin)"
  for tool in unshare ip nft sysctl python3 openssl tcpdump sha256sum; do
    command -v "$tool" >/dev/null || die "$tool is required"
  done

  images=${TOPOB_IMAGES:-${AIEC_IMAGES:-/home/gobrowse/ga/images}}
  firecracker=${TOPOB_FIRECRACKER:-$repo/.agentforge/bin/firecracker-v1.17.0-x86_64}
  [[ -f "$images/aiec-rootfs.ext4" ]] || die "guest rootfs missing in TOPOB_IMAGES ($images)"
  [[ -f "$images/vmlinux" ]] || die "guest kernel missing in TOPOB_IMAGES ($images)"
  [[ -x "$firecracker" ]] || die "firecracker binary missing at $firecracker"
  [[ -w /dev/kvm ]] || die '/dev/kvm is not writable; microVM guests cannot boot'
  for tool in debugfs resize2fs e2fsck; do
    command -v "$tool" >/dev/null || die "$tool is required to materialize a guest disk"
  done

  export TOPOB_ROOT=$root TOPOB_BIN=$bin TOPOB_IMAGES=$images TOPOB_FIRECRACKER=$firecracker
  export TOPOB_DRIVER=${TOPOB_DRIVER:-$here/guard-topology-b-acceptance.py}
  export TOPOB_HOST_NETNS=$host_netns
  mkdir -p "$root"
  chmod 700 "$root"
  # A short path. A Unix socket path is limited to about a hundred bytes and the
  # database URL, every log and the whole VM tree are derived from this one.
  root=$(realpath -m "$root")
  TOPOB_ROOT=$root
  export TOPOB_ROOT

  # A database of its own, on the same server the other suites use. Two reasons,
  # and the second is the important one: a shared database carries the stranded
  # sandboxes of every other suite, and startup reclamation of those takes longer
  # than any sane health deadline - so a suite pointed at one appears to fail for
  # reasons that have nothing to do with it.
  export TOPOB_PG_ADMIN_URL=${TOPOB_PG_ADMIN_URL:-postgresql://aiec:aiec-dev-only@127.0.0.1:5432/postgres}
  export TOPOB_DATABASE_NAME=${TOPOB_DATABASE_NAME:-aiec_topob}
  python3 - "$TOPOB_PG_ADMIN_URL" "$TOPOB_DATABASE_NAME" <<'PY' || die 'could not prepare the acceptance database'
import sys
import psycopg
url, name = sys.argv[1], sys.argv[2]
with psycopg.connect(url, autocommit=True) as connection:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
        if cursor.fetchone() is None:
            cursor.execute(f'CREATE DATABASE "{name}"')
PY

  # One run at a time. Two runs would share this directory and this database, and
  # the first to exit would tear down the socket the second is still using.
  mkdir "$root/.lock" 2>/dev/null || die 'another topology B acceptance run holds the lock; wait for it'

  # The relays. Both this run's PostgreSQL and its object store live outside the
  # namespace, on a network this run's other half cannot route to, and both are
  # reached through a Unix socket instead. A socket is a filesystem object and
  # has no network namespace, which is the whole reason this works - and it is
  # why the suite needs no privileged database cluster of its own.
  cat >"$root/relay.py" <<'PY'
import os
import selectors
import socket
import sys


def open_listener(kind, address):
    if kind == "unix":
        path = address
        if os.path.exists(path):
            os.unlink(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
    else:
        host, port = address.split(":")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, int(port)))
    listener.listen(128)
    return listener


def open_upstream(kind, address):
    if kind == "unix":
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.connect(address)
    else:
        host, port = address.split(":")
        upstream = socket.create_connection((host, int(port)), 10)
    return upstream


listen_kind, listen_at, upstream_kind, upstream_at = sys.argv[1:5]
listener = open_listener(listen_kind, listen_at)
selector = selectors.DefaultSelector()
selector.register(listener, selectors.EVENT_READ, None)
while True:
    for key, _ in selector.select():
        if key.data is None:
            client, _ = listener.accept()
            try:
                upstream = open_upstream(upstream_kind, upstream_at)
            except OSError:
                client.close()
                continue
            client.setblocking(False)
            upstream.setblocking(False)
            selector.register(client, selectors.EVENT_READ, upstream)
            selector.register(upstream, selectors.EVENT_READ, client)
        else:
            peer = key.data
            try:
                chunk = key.fileobj.recv(65536)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                chunk = b""
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                selector.unregister(peer)
                peer.close()
                continue
            try:
                peer.sendall(chunk)
            except OSError:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                selector.unregister(peer)
                peer.close()
PY
  # sqlx reaches a Unix-socket PostgreSQL by directory, and appends
  # `.s.PGSQL.5432` itself. Passing the socket file directly produces
  # `Database(NotADirectory)` from the control plane's very first query.
  mkdir -p "$root/pgsock"
  python3 "$root/relay.py" unix "$root/pgsock/.s.PGSQL.5432" tcp 127.0.0.1:5432 &
  relay=$!
  for _ in $(seq 1 100); do
    [[ -S "$root/pgsock/.s.PGSQL.5432" ]] && break
    kill -0 "$relay" 2>/dev/null || die 'the database relay exited before it was ready'
    sleep 0.1
  done
  [[ -S "$root/pgsock/.s.PGSQL.5432" ]] || die 'the database relay never bound its socket'

  # A real S3-compatible endpoint. The control plane refuses to start without
  # object storage configured, and pointing it at a name that does not resolve
  # makes every accidental artifact write fail loudly - which is fine for a
  # suite that never writes one, and is not fine for the *claim* that this ran
  # against a deployment rather than a configuration sketch.
  export TOPOB_S3_PORT=${TOPOB_S3_PORT:-19844}
  cat >"$root/s3.py" <<'PY'
import hashlib
import json
import os
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STORE: dict[str, bytes] = {}
LOG: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _key(self) -> str:
        return urllib.parse.unquote(self.path.lstrip("/"))

    def _send(self, status: int, body: bytes = b"", content_type: str = "application/xml") -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_PUT(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length else b""
        if self.path.endswith("/"):
            self._send(200, b"", "application/xml")
            return
        STORE[self._key()] = body
        LOG.append({"method": "PUT", "key": self._key(), "bytes": len(body),
                    "etag": hashlib.md5(body).hexdigest()})  # noqa: S324 - S3 ETag spelling
        self.send_response(200)
        self.send_header("etag", '"%s"' % hashlib.md5(body).hexdigest())  # noqa: S324
        self.send_header("content-length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/__stats":
            self._send(200, json.dumps({"objects": len(STORE), "requests": LOG}).encode(),
                       "application/json")
            return
        if self.path.endswith("/"):
            self._send(200, b"", "application/xml")
            return
        key = self._key()
        if key not in STORE:
            self._send(404, b"<Error><Code>NoSuchKey</Code></Error>")
            return
        LOG.append({"method": "GET", "key": key, "bytes": len(STORE[key])})
        self._send(200, STORE[key], "application/octet-stream")

    def do_HEAD(self) -> None:
        key = self._key()
        if key.endswith("/"):
            self._send(200)
            return
        if key not in STORE:
            self._send(404)
            return
        self._send(200, STORE[key])

    def do_DELETE(self) -> None:
        STORE.pop(self._key(), None)
        self._send(204)


if __name__ == "__main__":
    path = sys.argv[1]
    if os.path.exists(path):
        os.unlink(path)
    ThreadingHTTPServer.address_family = socket.AF_UNIX
    server = ThreadingHTTPServer(path, Handler)
    server.serve_forever()
PY
  python3 "$root/s3.py" "$root/s3.sock" &
  s3=$!
  for _ in $(seq 1 100); do
    [[ -S "$root/s3.sock" ]] && break
    kill -0 "$s3" 2>/dev/null || die 'the object store exited before it was ready'
    sleep 0.1
  done
  [[ -S "$root/s3.sock" ]] || die 'the object store never bound its socket'

  # The lock is released here rather than by an earlier trap of its own: a
  # second `trap ... EXIT` replaces the first, so releasing it separately meant
  # an interrupted run left a lock with nothing behind it and every later run
  # refused. One trap, in reverse order of acquisition.
  stop_all() {
    kill -TERM "$s3" 2>/dev/null || true
    kill -TERM "$relay" 2>/dev/null || true
    wait "$s3" 2>/dev/null || true
    wait "$relay" 2>/dev/null || true
    pkill -9 -f -- "$root" >/dev/null 2>&1 || true
    rmdir "$root/.lock" >/dev/null 2>&1 || true
  }
  trap stop_all EXIT

  export TOPOB_REPORT=${TOPOB_REPORT:-$repo/benchmarks/guard-topology-b-acceptance.json}
  unshare --user --map-root-user --net --fork --kill-child=KILL bash "$0" --inside
  status=$?
  exit "$status"
fi

shift
[[ $(id -u) == 0 ]] || die 'acceptance must run root-mapped'
[[ $(readlink /proc/self/ns/net) != "${TOPOB_HOST_NETNS:?}" ]] || die 'refusing to run in the host network namespace'

root=$TOPOB_ROOT
bin=$TOPOB_BIN
images=$TOPOB_IMAGES
mkdir -p "$root/state-vms"

key=$(python3 -c 'import secrets;print(secrets.token_hex(24))')
image_secret=$(python3 -c 'import secrets;print(secrets.token_hex(32))')

# The guest secret is per run. The worker derives the sandbox's control identity
# from it and injects that identity into the guest's own disk, which is what makes
# the control channel the only way in: a caller without it holds no credential
# the guest would accept.
export TOPOB_GUEST_SECRET=$(python3 -c 'import secrets;print(secrets.token_hex(32))')
export TOPOB_STATE_DIR=$root/state-vms

# Ports are overridable so this suite cannot collide with the Phase 2 or approval
# suites on the same host.
cp_port=${TOPOB_CP_PORT:-18644}
worker_port=${TOPOB_WORKER_PORT:-19644}
model_port=${TOPOB_MODEL_PORT:-18999}
export TOPOB_CP="https://127.0.0.1:$cp_port"
export TOPOB_CP_BIND=127.0.0.1:$cp_port
export TOPOB_WORKER="https://127.0.0.1:$worker_port"
export TOPOB_WORKER_BIND=127.0.0.1:$worker_port
export TOPOB_MODEL_URL="http://127.0.0.1:$model_port/v1/chat/completions"
export TOPOB_TENANT=$(cat /proc/sys/kernel/random/uuid)
export TOPOB_API_KEY="af_live_$key"
export TOPOB_WORKER_TOKEN="af_live_key$key"
# A certificate authority of its own, minted for this run. Borrowing an
# operator's long-lived key material to prove a test suite works would be a
# poor trade for files that cost nothing to regenerate.
export TOPOB_CA=$root/tls/ca.crt
export TOPOB_TLS_CERT=$root/tls/api.crt
export TOPOB_TLS_KEY=$root/tls/api.key
mkdir -p "$root/tls"
if [ ! -s "$TOPOB_CA" ]; then
  # `keyUsage=keyCertSign` is not decoration: OpenSSL 3 refuses a CA certificate
  # without it, and a Python client rejects the handshake outright with
  # CERTIFICATE_VERIFY_FAILED while curl quietly tolerates it. The suite uses a
  # Python client, so the run fails with no request in the server log - which
  # looks like the server never started.
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$root/tls/ca.key" -out "$TOPOB_CA" \
    -subj "/CN=aiec-topology-b-acceptance-ca" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$TOPOB_TLS_KEY" -out "$root/tls/api.csr" \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1
  printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' >"$root/tls/ext.cnf"
  openssl x509 -req -in "$root/tls/api.csr" -CA "$TOPOB_CA" -CAkey "$root/tls/ca.key" \
    -CAcreateserial -days 2 -out "$TOPOB_TLS_CERT" \
    -extfile "$root/tls/ext.cnf" >/dev/null 2>&1
  rm -f "$root/tls/api.csr"
fi
export TOPOB_IMAGE=${TOPOB_IMAGE:-python:3.13}

# The signed guest image. The control plane refuses to boot with Firecracker
# configured and no manifest, and a manifest it cannot verify is a manifest it
# will not use - so the suite signs its own, with a key that exists only for
# this run, over the digest of the bytes actually on disk.
python3 - "$root" "$image_secret" "$images/aiec-rootfs.ext4" "$TOPOB_IMAGE" <<'PY' || die 'could not sign the guest image'
import hashlib
import hmac
import json
import os
import sys
import time

root, secret, rootfs, reference = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
stat = os.stat(rootfs)
stamp = f"{root}/{stat.st_size}-{int(stat.st_mtime)}.sha256"
if os.path.isfile(stamp):
    digest = open(stamp, encoding="utf-8").read().strip()
else:
    hasher = hashlib.sha256()
    with open(rootfs, "rb") as handle:
        for chunk in iter(lambda: handle.read(4 << 20), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    with open(stamp + ".tmp", "w", encoding="utf-8") as handle:
        handle.write(digest + "\n")
    os.replace(stamp + ".tmp", stamp)
# `aiec_core::image_manifest_signature`: HMAC-SHA256 over the reference, a NUL
# byte, and the digest. Reimplemented here so the manifest the suite signs is
# derived independently of the verifier that will check it.
signature = hmac.new(secret.encode(), reference.encode() + b"\0" + digest.encode(),
                     hashlib.sha256).hexdigest()
document = {"reference": reference, "rootfs_sha256": digest, "signature": signature}
with open(f"{root}/image-manifest.json", "w", encoding="utf-8") as handle:
    json.dump(document, handle)
with open(f"{root}/image-manifest.secret", "w", encoding="utf-8") as handle:
    handle.write(secret + "\n")
os.chmod(f"{root}/image-manifest.secret", 0o600)
print(f"[{time.strftime('%H:%M:%S')}] signed guest image {reference} rootfs_sha256={digest[:16]}...")
PY
export TOPOB_IMAGE_MANIFEST=$root/image-manifest.json
export TOPOB_IMAGE_MANIFEST_SECRET=$image_secret
export TOPOB_DATABASE_URL="postgresql://aiec:aiec-dev-only@localhost/$TOPOB_DATABASE_NAME?host=$root/pgsock"

# The object store answers on a Unix socket outside this namespace, so the
# control plane is given a loopback port that reaches it. Without this the
# control plane boots with an endpoint nothing is listening on, and the first
# artifact write - or the first health probe - fails as a connection refused
# that looks like a control plane fault.
python3 "$root/relay.py" tcp "127.0.0.1:$TOPOB_S3_PORT" unix "$root/s3.sock" &
s3_relay=$!
trap 'kill -TERM "$s3_relay" 2>/dev/null || true' EXIT

ip link set lo up
# Namespace-scoped forwarding. A fresh network namespace has this off, and a
# packet leaving the guest is dropped before it reaches any hook Guard counts -
# which reads as "the guest has no link" rather than as a policy decision.
sysctl -qw net.ipv4.ip_forward=1

set +e
python3 "$TOPOB_DRIVER" 2>&1 | tee "$root/driver.log"
status=${PIPESTATUS[0]}
set -e
exit "$status"