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
#   AIEC_GUEST_GUI           default none (none|browser|desktop|playwright);
#                            browser adds chromium + chromedriver, desktop adds
#                            those plus Xvfb/xdotool/x11vnc/scrot, playwright
#                            adds the browser set plus python3-playwright using
#                            the system chromium (never a downloaded browser).
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
# The default `none` path must stay byte-identical to the old build: every
# GUI line below is gated on this variable, and when it is `none` the package
# list, profile, capabilities and filenames are exactly what they were.
GUI=${AIEC_GUEST_GUI:-none}
case "$GUI" in
  none|browser|desktop|playwright) ;;
  *) fail "AIEC_GUEST_GUI must be none, browser, desktop or playwright (got $GUI)" ;;
esac
# `cargo` is only needed when this script compiles the guest itself. The whole
# point of AIEC_GUEST_BINARY is a host that has no Rust toolchain at all, so
# demanding cargo before consulting the override makes the escape hatch
# unreachable on exactly the machine it exists for.
TOOLS="mke2fs e2fsck resize2fs tar sha256sum awk date"
[ -n "${AIEC_GUEST_BINARY:-}" ] || TOOLS="cargo $TOOLS"
for cmd in $TOOLS; do command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 1; }; done

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
GUEST_BIN="$ROOT/target/x86_64-unknown-linux-musl/release/aiec-guest"
if [ -n "${AIEC_GUEST_BINARY:-}" ]; then
  # A prebuilt guest agent is allowed, and its digest is recorded in the
  # manifest, because the image is a product of this script and the only
  # thing that may write the recorded digests is this script. This is the path
  # for a CI builder whose musl toolchain is not the host's.
  [ -f "$AIEC_GUEST_BINARY" ] || fail "AIEC_GUEST_BINARY does not exist: $AIEC_GUEST_BINARY"
  file "$AIEC_GUEST_BINARY" 2>/dev/null | grep -qE 'ELF .*(static(-pie)? linked|statically linked)' \
    || fail "AIEC_GUEST_BINARY is not a statically linked ELF: $AIEC_GUEST_BINARY"
  # A dynamically linked agent cannot exec inside the microVM, and that failure
  # looks like a transport fault rather than a missing loader, which is why
  # `ldd` is not the test: it prints "statically linked" for some static-PIE
  # binaries and is absent entirely on some hosts.
  # An agent that predates the per-sandbox control identity reads the shared
  # build-time secret instead of the one planted for it, and the machine then
  # fails to boot with an early EOF that looks like a transport fault. The
  # planted path is the marker for an agent that can read what the runtime
  # writes, and a stale agent is exactly what must never be baked into an image
  # whose digests are about to be recorded.
  # A pipe into `grep -q` is not usable here: `grep` exits at the first match,
  # `strings` dies of SIGPIPE, and under `pipefail` that non-zero status reads
  # as a failed check on a perfectly good binary. Reading the file directly
  # needs no binutils and cannot lose the match.
  grep -a -qF '/etc/aiec-guest-secret' "$AIEC_GUEST_BINARY" \
    || fail "AIEC_GUEST_BINARY does not read the planted control identity: $AIEC_GUEST_BINARY"
  step "using the prebuilt guest agent from $AIEC_GUEST_BINARY"
  mkdir -p "$(dirname "$GUEST_BIN")"
  install -m 0755 "$AIEC_GUEST_BINARY" "$GUEST_BIN"
else
  cargo build --release -p aiec-guest --target x86_64-unknown-linux-musl
fi
[ -x "$GUEST_BIN" ] || fail "guest agent binary was not produced"
GUEST_AGENT_SHA=$(sha256sum "$GUEST_BIN" | awk '{print $1}')

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
# GUI package sets are appended, never substituted: the base list below is the
# current image byte-for-byte, and each profile only adds its own names.
GUI_PACKAGES=""
case "$GUI" in
  browser|desktop|playwright) GUI_PACKAGES="chromium chromium-driver" ;;
esac
case "$GUI" in
  desktop) GUI_PACKAGES="$GUI_PACKAGES xvfb xdotool x11vnc scrot" ;;
  playwright) GUI_PACKAGES="$GUI_PACKAGES python3-playwright" ;;
esac
# The package list is spliced into the heredoc below by the outer shell, so
# the provision script itself stays quoted and inert: `$GUI_PACKAGES` expands
# here, nothing inside the container's script expands there.
GUI_LINE="git ca-certificates curl python3 tar gzip coreutils util-linux hostname iproute2 $GUI_PACKAGES"
cat > "$TMP/provision.sh" <<PROVISION
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=3 update
apt-get install -y --no-install-recommends $GUI_LINE
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
  # Without this the find below yields nothing, the loop body never runs, and
  # the build reports success while silently omitting everything the skeleton
  # contributes.
  [ -d "$ROOT/guest/rootfs" ] || fail "the guest rootfs skeleton is missing: $ROOT/guest/rootfs"
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
# `aiec-screenshot` arrives through the skeleton overlay above
# (guest/rootfs/usr/local/bin/aiec-screenshot): one helper for every GUI
# profile, so the script carries no second copy to drift. The none image
# deletes it - a text-only guest offers no screen path - and desktop stamps
# the marker the guest init starts Xvfb on.
if [ "$GUI" = none ]; then
  rm -f "$TMP/rootfs/usr/local/bin/aiec-screenshot"
elif [ "$GUI" = desktop ]; then
  # The guest init starts Xvfb when this marker exists; the base image has no
  # X server and must never try.
  touch "$TMP/rootfs/etc/aiec-xvfb"
fi

PROFILE=coding
CAPS='["sh","coreutils","git","ca-certificates","dns","https","tar","gzip","curl","python3"]'
ROOTFS_NAME=aiec-rootfs.ext4
CAPS_NAME=guest-capabilities.json
case "$GUI" in
  browser) PROFILE=coding-gui-browser; CAPS='["sh","coreutils","git","ca-certificates","dns","https","tar","gzip","curl","python3","chromium","chromedriver"]'; ROOTFS_NAME=rootfs-gui-browser.ext4; CAPS_NAME=guest-capabilities-gui-browser.json ;;
  desktop) PROFILE=coding-gui-desktop; CAPS='["sh","coreutils","git","ca-certificates","dns","https","tar","gzip","curl","python3","chromium","chromedriver","xvfb","xdotool","screenshot"]'; ROOTFS_NAME=rootfs-gui-desktop.ext4; CAPS_NAME=guest-capabilities-gui-desktop.json ;;
  playwright) PROFILE=coding-gui-playwright; CAPS='["sh","coreutils","git","ca-certificates","dns","https","tar","gzip","curl","python3","chromium","chromedriver","playwright"]'; ROOTFS_NAME=rootfs-gui-playwright.ext4; CAPS_NAME=guest-capabilities-gui-playwright.json ;;
esac

ROOTFS="$OUT/$ROOTFS_NAME"
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
cat > "$OUT/$CAPS_NAME" <<EOF
{"schema":1,"artifact_version":"1.0.0","base":"$BASE_DIGEST","profile":"$PROFILE","capabilities":$CAPS,"git_version":"$GIT_VERSION","guest_agent_version":"$GUEST_AGENT_VERSION","guest_agent_sha256":"$GUEST_AGENT_SHA","guest_protocol_version":$GUEST_PROTOCOL_VERSION,"rootfs_sha256":"$ROOTFS_SHA","kernel_sha256":$KERNEL_SHA_JSON,"built_at":"$BUILT_AT"}
EOF
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT/$CAPS_NAME" || fail "$CAPS_NAME is not valid JSON"
fi

# Variant outputs keep their own names: a GUI build must never overwrite the
# base image's manifest, checksums or capabilities in the same OUT directory.
MANIFEST_NAME=manifest.json
SUMS_NAME=SHA256SUMS
if [ "$GUI" != none ]; then
  MANIFEST_NAME="manifest-gui-$GUI.json"
  SUMS_NAME="SHA256SUMS-gui-$GUI"
fi

if [ ! -f "$KERNEL" ]; then
  echo "guest image built at $ROOTFS"
  echo "kernel not built: set AIEC_KERNEL to an uncompressed Linux kernel or bzImage with virtio, vsock and ext4 support"
  exit 2
fi
sha256sum "$ROOTFS" "$KERNEL" > "$OUT/$SUMS_NAME"
cat > "$OUT/$MANIFEST_NAME" <<EOF
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
cat "$OUT/$SUMS_NAME"
