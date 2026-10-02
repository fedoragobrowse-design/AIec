#!/usr/bin/env bash
# Builds the in-guest agent harness (`aiec-agent`) as a static x86-64 musl
# executable and prints the path it wrote.
#
# The harness is a separate workspace on purpose (harness/Cargo.toml), so it is
# not produced by `cargo build --release` at the repository root. The Guard
# acceptance runs that binary INSIDE a Firecracker microVM, where there is no
# dynamic loader and no glibc: a dynamically linked harness would fail to exec
# and the failure would look like a transport fault rather than a missing
# loader. `ldd` is deliberately not the test - it prints "statically linked"
# for some static-PIE binaries and is absent entirely on hosts without it.
#
# The build runs in a container because musl-gcc is not a host requirement
# anyone should acquire to run the acceptance. Docker is already a dependency
# of scripts/build-firecracker-guest.sh, so this introduces nothing new.
#
# Env contract:
#   AIEC_HARNESS_BINARY   use this prebuilt binary instead of building
#   AIEC_HARNESS_OUT_DIR  output directory (default $XDG_CACHE_HOME/aiec/harness)
#
# Exit code 0 prints the absolute path of the binary on the last line.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${AIEC_HARNESS_OUT_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/aiec/harness}
TARGET=x86_64-unknown-linux-musl
step() { printf '==> %s\n' "$*" >&2; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || fail 'docker is required to build the static harness'
command -v file >/dev/null || fail 'file(1) is required to verify static linkage'

verify_static() {
  file "$1" | grep -qE 'ELF .*(static(-pie)? linked|statically linked)' \
    || fail "not a statically linked ELF: $1"
}

# The repository source is the only thing that decides what this binary is, so
# the cache key is the harness workspace's own state. A harness rebuilt after a
# source change is a different program and reusing the old one would make the
# acceptance prove something about code that no longer exists.
source_key=$(find "$ROOT/harness" -path '*/target' -prune -o \
  \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) -print0 \
  | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
BIN="$OUT/aiec-agent-$source_key"

if [ -n "${AIEC_HARNESS_BINARY:-}" ]; then
  [ -f "$AIEC_HARNESS_BINARY" ] || fail "AIEC_HARNESS_BINARY does not exist: $AIEC_HARNESS_BINARY"
  step "using the prebuilt harness from $AIEC_HARNESS_BINARY"
  verify_static "$AIEC_HARNESS_BINARY"
  realpath "$AIEC_HARNESS_BINARY"
  exit 0
fi

if [ -x "$BIN" ]; then
  verify_static "$BIN"
  step "reusing cached harness $BIN"
  printf '%s\n' "$BIN"
  exit 0
fi

mkdir -p "$OUT"
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/aiec-harness-build.XXXXXXXX")
trap 'rm -rf "$BUILD"' EXIT
step "building harness (musl, static) for $TARGET"
docker run --rm \
  -v "$ROOT":/src \
  -v "$BUILD":/out \
  -w /src/harness \
  rust:1.98-slim-bookworm \
  bash -c '
    set -euo pipefail
    apt-get update -qq
    apt-get install -y -qq musl-tools pkg-config >/dev/null
    rustup target add '"$TARGET"' >/dev/null
    # --locked: the acceptance proves the harness in Cargo.lock, not the newest
    # version the index happened to serve during a container build.
    cargo build --release --locked --target '"$TARGET"' --target-dir /out/target
    cp /out/target/'"$TARGET"'/release/aiec-agent /out/aiec-agent
    # Everything cargo wrote into /out is root-owned from the host'"'"'s point of
    # view, so the host cannot delete it afterwards. Removing it here, as the
    # user that created it, is the only way this leaves no debris.
    rm -rf /out/target
  ' >&2
[ -f "$BUILD/aiec-agent" ] || fail 'the container build produced no harness binary'
# `cp` out of a container runs as root and lands root-owned; the acceptance runs
# as an ordinary user and must be able to read and re-read this file.
cp "$BUILD/aiec-agent" "$BIN"
chmod 0755 "$BIN"
verify_static "$BIN"
# Stripped on purpose: the file is uploaded into a microVM over the guest
# transport on every acceptance run, and symbols are a third of its size.
strip "$BIN" 2>/dev/null || true
verify_static "$BIN"
step "harness $(sha256sum "$BIN" | awk '{print $1}') at $BIN"
printf '%s\n' "$BIN"
