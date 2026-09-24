#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-"$ROOT/.agentforge/images"}
SECRET=${AGENTFORGE_GUEST_SECRET:?set AGENTFORGE_GUEST_SECRET to at least 32 random bytes}
if [ "${#SECRET}" -lt 32 ]; then
  echo "AGENTFORGE_GUEST_SECRET must contain at least 32 bytes" >&2
  exit 1
fi
for cmd in cargo mke2fs e2fsck resize2fs; do command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 1; }; done
mkdir -p "$OUT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp -a "$ROOT/guest/rootfs/." "$TMP/rootfs/"
mkdir -p "$TMP/rootfs/usr/local/bin"
cargo build --release -p agentforge-guest --target x86_64-unknown-linux-musl
install -m 0755 "$ROOT/target/x86_64-unknown-linux-musl/release/agentforge-guest" "$TMP/rootfs/usr/local/bin/agentforge-guest"
install -m 0755 /usr/bin/busybox "$TMP/rootfs/bin/busybox"
for applet in sh mount mkdir hostname sleep cat echo ls printf kill sync; do
  ln -sf /bin/busybox "$TMP/rootfs/bin/$applet"
done
ln -sf /sbin/init "$TMP/rootfs/init"
printf '%s' "$SECRET" > "$TMP/rootfs/etc/agentforge-guest-secret"
chmod 0600 "$TMP/rootfs/etc/agentforge-guest-secret"
ROOTFS="$OUT/agentforge-rootfs.ext4"
rm -f "$ROOTFS"
truncate -s 4G "$ROOTFS"
mke2fs -q -t ext4 -F -d "$TMP/rootfs" "$ROOTFS"
e2fsck -fn "$ROOTFS"
KERNEL=${AGENTFORGE_KERNEL:-$ROOT/.agentforge/images/vmlinux}
if [ ! -f "$KERNEL" ]; then
  echo "guest image built at $ROOTFS"
  echo "kernel not built: set AGENTFORGE_KERNEL to an uncompressed Linux kernel or bzImage with virtio, vsock and ext4 support"
  exit 2
fi
sha256sum "$ROOTFS" "$KERNEL" > "$OUT/SHA256SUMS"
cat > "$OUT/manifest.json" <<EOF
{"schema":1,"rootfs":"$(basename "$ROOTFS")","kernel":"$(basename "$KERNEL")","control_port":1024,"guest_cid":3}
EOF
echo "built $ROOTFS"
cat "$OUT/SHA256SUMS"
