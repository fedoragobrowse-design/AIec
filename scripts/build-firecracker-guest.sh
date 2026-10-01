#!/usr/bin/env bash
# Builds the AIec Firecracker guest root filesystem from a pinned Debian
# base image and records the verified artifact description in
# guest-capabilities.json. See docs/FIRECRACKER_GUEST.md.
#
# Env contract:
#   AIEC_GUEST_SECRET        required, at least 32 bytes, baked into the rootfs
#   AIEC_KERNEL              uncompressed kernel (default .aiec/images/vmlinux)
#   AIEC_GUEST_BASE_IMAGE    default debian:bookworm-slim
#   AIEC_GUEST_ROOTFS_SIZE   default 4G
# Positional arg 1 is the output directory (default .aiec/images).
# Exit code 2 means the rootfs was built but no kernel was found.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-"$ROOT/.aiec/images"}
SECRET=${AIEC_GUEST_SECRET:?set AIEC_GUEST_SECRET to at least 32 random bytes}
if [ "${#SECRET}" -lt 32 ]; then
  echo "AIEC_GUEST_SECRET must contain at least 32 bytes" >&2
  exit 1
fi
BASE_IMAGE=${AIEC_GUEST_BASE_IMAGE:-debian:bookworm-slim}
KERNEL=${AIEC_KERNEL:-$ROOT/.aiec/images/vmlinux}
ROOTFS_SIZE=${AIEC_GUEST_ROOTFS_SIZE:-4G}
for cmd in cargo mke2fs e2fsck resize2fs tar sha256sum awk date; do command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 1; }; done

step() { printf '==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- docker ----
# The build user is often not root and not a usable docker-group member, so
# every docker call goes through sg when the direct socket is not accessible.
DOCKER_MODE=direct
if ! docker info >/dev/null 2>&1; then
  if command -v sg >/dev/null 2>&1 && sg docker -c 'docker info' >/dev/null 2>&1; then
    DOCKER_MODE=group
  else
    fail "docker daemon unreachable: join the docker group, run as root, or set DOCKER_HOST"
  fi
fi
docker_cmd() {
  if [ "$DOCKER_MODE" = direct ]; then
    docker "$@"
  else
    sg docker -c "$(printf '%q ' docker "$@")"
  fi
}
step "docker access: $DOCKER_MODE"

TMP=$(mktemp -d)
CONTAINER=""
cleanup() {
  if [ -n "$CONTAINER" ]; then
    docker_cmd rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$OUT"

# ------------------------------------------------------- guest agent build --
GUEST_CARGO="$ROOT/guest/aiec-guest/Cargo.toml"
if grep -qE '^[[:space:]]*version\.workspace[[:space:]]*=[[:space:]]*true' "$GUEST_CARGO"; then
  GUEST_AGENT_VERSION=$(awk -F'"' '/^version = /{print $2; exit}' "$ROOT/Cargo.toml")
else
  GUEST_AGENT_VERSION=$(awk -F'"' '/^version = /{print $2; exit}' "$GUEST_CARGO")
fi
[ -n "$GUEST_AGENT_VERSION" ] || fail "could not read the aiec-guest version from $GUEST_CARGO"
GUEST_PROTOCOL_VERSION=$(awk '/^pub const PROTOCOL_VERSION:/{gsub(/;/,"",$NF); print $NF}' "$ROOT/crates/aiec-core/src/protocol.rs")
[[ "$GUEST_PROTOCOL_VERSION" =~ ^[0-9]+$ ]] || fail "could not read the guest wire protocol version"
step "building aiec-guest $GUEST_AGENT_VERSION (musl)"
cargo build --release -p aiec-guest --target x86_64-unknown-linux-musl
[ -x "$ROOT/target/x86_64-unknown-linux-musl/release/aiec-guest" ] || fail "guest agent binary was not produced"

# ------------------------------------------------------------ base image ----
if ! docker_cmd pull "$BASE_IMAGE" >/dev/null 2>&1; then
  docker_cmd image inspect "$BASE_IMAGE" >/dev/null 2>&1 || fail "cannot pull or resolve $BASE_IMAGE"
  echo "note: pull failed, using the local copy of $BASE_IMAGE"
fi
BASE_REPO_DIGEST=$(docker_cmd image inspect --format '{{index .RepoDigests 0}}' "$BASE_IMAGE" 2>/dev/null || true)
if [ -n "$BASE_REPO_DIGEST" ]; then
  BASE_DIGEST="${BASE_IMAGE%@*}@${BASE_REPO_DIGEST#*@}"
else
  BASE_DIGEST=$(docker_cmd image inspect --format '{{.Id}}' "$BASE_IMAGE")
fi
step "base image: $BASE_DIGEST"

# ------------------------------------------------- provision the container --
CONTAINER="aiec-guest-build-$$"
docker_cmd rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker_cmd run -d --name "$CONTAINER" "$BASE_IMAGE" sleep infinity >/dev/null
step "installing guest packages in $CONTAINER"
cat > "$TMP/provision.sh" <<'PROVISION'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=3 update
apt-get install -y --no-install-recommends \
  git ca-certificates curl python3 tar gzip coreutils util-linux hostname iproute2
apt-get clean
rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/* /usr/share/info/* /var/cache/apt/*
rm -rf /tmp/* /var/tmp/* /root/.cache
# /etc/resolv.conf is a docker-managed bind mount inside the container; it is
# left alone here (writing it would clobber the host file) and the real
# resolver configuration is written from the exported rootfs below.
umount /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf 2>/dev/null || true
PROVISION
docker_cmd exec -i "$CONTAINER" /bin/sh -s < "$TMP/provision.sh"

capture() { docker_cmd exec "$CONTAINER" /bin/sh -c "$1" | tr -d '\r'; }
GIT_VERSION=$(capture 'git --version')
CURL_VERSION=$(capture 'curl --version | head -n1')
PYTHON_VERSION=$(capture 'python3 --version')
TAR_VERSION=$(capture 'tar --version | head -n1')
for pair in "git:$GIT_VERSION" "curl:$CURL_VERSION" "python3:$PYTHON_VERSION" "tar:$TAR_VERSION"; do
  [ -n "${pair#*:}" ] || fail "could not read ${pair%%:*} version from the built image"
done

step "exporting the container filesystem"
mkdir -p "$TMP/rootfs"
docker_cmd export "$CONTAINER" | tar -x -C "$TMP/rootfs"
# Repository-owned guest files win over the base image. Debian bookworm is
# merged-usr, so /bin, /sbin and /lib are symlinks into /usr: a skeleton
# directory that collides with such a symlink must not replace it, and a
# skeleton file must be written through the symlink.
overlay_skeleton() {
  local entry rel target
  while IFS= read -r -d '' entry; do
    rel=${entry#"$ROOT/guest/rootfs"/}
    target="$TMP/rootfs/$rel"
    if [ -d "$entry" ] && [ ! -L "$entry" ]; then
      if [ -L "$target" ] && [ -d "$target" ]; then continue; fi
      mkdir -p "$target"
    else
      mkdir -p "$(dirname "$target")"
      cp -a "$entry" "$target"
    fi
  done < <(find "$ROOT/guest/rootfs" -mindepth 1 -print0)
}
overlay_skeleton
# docker export copies bind mounts as plain files and leaves host scratch behind.
rm -f "$TMP/rootfs/.dockerenv"
find "$TMP/rootfs/dev" -mindepth 1 ! -type d -delete 2>/dev/null || true
rm -f "$TMP/rootfs/etc/resolv.conf"
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$TMP/rootfs/etc/resolv.conf"
mkdir -p "$TMP/rootfs/usr/local/bin" "$TMP/rootfs/workspace" "$TMP/rootfs/proc" "$TMP/rootfs/sys" "$TMP/rootfs/dev" "$TMP/rootfs/run" "$TMP/rootfs/dev/pts"
install -m 0755 "$ROOT/target/x86_64-unknown-linux-musl/release/aiec-guest" "$TMP/rootfs/usr/local/bin/aiec-guest"
printf '%s' "$SECRET" > "$TMP/rootfs/etc/aiec-guest-secret"
chmod 0600 "$TMP/rootfs/etc/aiec-guest-secret"
ln -sf /sbin/init "$TMP/rootfs/init"

ROOTFS="$OUT/aiec-rootfs.ext4"
rm -f "$ROOTFS"
truncate -s "$ROOTFS_SIZE" "$ROOTFS"
step "building $ROOTFS ($(du -h "$ROOTFS" | cut -f1))"
mke2fs -q -t ext4 -F -d "$TMP/rootfs" "$ROOTFS"
e2fsck -fn "$ROOTFS"

# --------------------------------------------------------- capabilities -----
ROOTFS_SHA=$(sha256sum "$ROOTFS" | awk '{print $1}')
if [ -f "$KERNEL" ]; then
  KERNEL_SHA=$(sha256sum "$KERNEL" | awk '{print $1}')
  KERNEL_SHA_JSON="\"$KERNEL_SHA\""
else
  KERNEL_SHA="none"
  KERNEL_SHA_JSON="null"
fi
BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > "$OUT/guest-capabilities.json" <<EOF
{"schema":1,"artifact_version":"1.0.0","base":"$BASE_DIGEST","profile":"coding","capabilities":["sh","coreutils","git","ca-certificates","dns","https","tar","gzip","curl","python3"],"git_version":"$GIT_VERSION","guest_agent_version":"$GUEST_AGENT_VERSION","guest_protocol_version":$GUEST_PROTOCOL_VERSION,"rootfs_sha256":"$ROOTFS_SHA","kernel_sha256":$KERNEL_SHA_JSON,"built_at":"$BUILT_AT"}
EOF
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT/guest-capabilities.json" || fail "guest-capabilities.json is not valid JSON"
fi

if [ ! -f "$KERNEL" ]; then
  echo "guest image built at $ROOTFS"
  echo "kernel not built: set AIEC_KERNEL to an uncompressed Linux kernel or bzImage with virtio, vsock and ext4 support"
  exit 2
fi
sha256sum "$ROOTFS" "$KERNEL" > "$OUT/SHA256SUMS"
cat > "$OUT/manifest.json" <<EOF
{"schema":1,"rootfs":"$(basename "$ROOTFS")","kernel":"$(basename "$KERNEL")","control_port":1024,"guest_cid":3}
EOF

step "build summary"
printf '  base            %s\n' "$BASE_DIGEST"
printf '  git             %s\n' "$GIT_VERSION"
printf '  curl            %s\n' "$CURL_VERSION"
printf '  python3         %s\n' "$PYTHON_VERSION"
printf '  tar             %s\n' "$TAR_VERSION"
printf '  guest agent     %s (musl, static)\n' "$GUEST_AGENT_VERSION"
printf '  rootfs sha256   %s\n' "$ROOTFS_SHA"
printf '  kernel sha256   %s\n' "$KERNEL_SHA"
printf '  rootfs size     %s (%s)\n' "$(stat -c %s "$ROOTFS")" "$(du -h "$ROOTFS" | cut -f1)"
printf '  artifacts       %s\n' "$OUT"
echo "built $ROOTFS"
cat "$OUT/SHA256SUMS"
