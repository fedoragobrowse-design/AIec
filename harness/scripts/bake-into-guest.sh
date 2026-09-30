#!/usr/bin/env bash
# Bakes the aiec-agent harness into a built Firecracker guest root filesystem
# and records what went in, so a host can tell whether a guest supports it
# before starting a run.
#
# The brief is explicit that guest CREATION must not run cargo build. A task
# that compiles in the guest pays for a toolchain, a registry and a build
# cache on every boot, in a machine that may live five minutes. So the binary
# is built here, once, at image time, and the guest gets a file.
#
# Usage:
#   bake-into-guest.sh <rootfs-dir> [capabilities.json]
#
# <rootfs-dir> is an unpacked root filesystem; /usr/local/bin/aiec-agent is
# created inside it. The capabilities file is updated in place with the
# version, the source commit and the sha256 of the binary that was baked in.
#
# Exit codes:
#   0  baked, manifest updated
#   1  something was wrong
#   2  the rootfs was updated but the manifest could not be rewritten
set -euo pipefail

HARNESS_ROOT=$(cd "$(dirname "$0")/.." && pwd)
REPO_ROOT=$(cd "$HARNESS_ROOT/.." && pwd)

ROOTFS=${1:?usage: bake-into-guest.sh <rootfs-dir> [capabilities.json]}
MANIFEST=${2:-}

step() { printf '==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ -d "$ROOTFS" ] || fail "not a directory: $ROOTFS"
command -v cargo >/dev/null || fail "cargo is not on PATH"
command -v sha256sum >/dev/null || fail "sha256sum is not on PATH"

# ------------------------------------------------------------------ build ----
# Built HERE, at image time. The guest never sees a compiler.
step "building the release binary"
( cd "$HARNESS_ROOT" && cargo build --release --locked )
BINARY="$HARNESS_ROOT/target/release/aiec-agent"
[ -x "$BINARY" ] || fail "the build produced no binary at $BINARY"

# `--version` prints "<name> <version>", so the version is the LAST field. The
# obvious `{print $1}` records the program name, which is not a version and
# looks like one sitting in a manifest.
VERSION=$("$BINARY" --version 2>/dev/null | awk '{print $NF}')
[ -n "$VERSION" ] || fail "could not read the version from the binary"
SHA=$(sha256sum "$BINARY" | awk '{print $1}')
PROTOCOL=$("$BINARY" capabilities | python3 -c 'import json,sys; print(json.load(sys.stdin)["protocol"])')

COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
DIRTY=""
if [ -n "$(git -C "$REPO_ROOT" status --porcelain harness/ 2>/dev/null)" ]; then
  # A build from a dirty tree is not attributable, and saying so is cheaper
  # than discovering later which code a guest was actually running.
  DIRTY=true
  COMMIT="$COMMIT-dirty"
fi

step "baking $VERSION into $ROOTFS"
mkdir -p "$ROOTFS/usr/local/bin"
install -m 0755 "$BINARY" "$ROOTFS/usr/local/bin/aiec-agent"

# Prove it is the right binary and that it runs against the guest's libc,
# rather than the build machine's. A harness that only starts on the host is
# not a harness.
step "verifying the baked binary runs against the guest"
if command -v chroot >/dev/null && [ "$(id -u)" = "0" ]; then
  chroot "$ROOTFS" /usr/local/bin/aiec-agent capabilities >/dev/null \
    || fail "the baked binary does not run inside the rootfs"
else
  step "skipping the chroot check (needs root, or chroot is unavailable)"
fi

# ---------------------------------------------------------------- manifest ----
[ -n "$MANIFEST" ] || { step "no manifest given; nothing to record"; exit 0; }
[ -f "$MANIFEST" ] || fail "manifest not found: $MANIFEST"

step "recording the harness in $MANIFEST"
BAKE_TMP=$(mktemp)
python3 - "$MANIFEST" "$BAKE_TMP" "$VERSION" "$COMMIT" "$SHA" "$PROTOCOL" "$DIRTY" <<'PY' || exit 2
import json, sys

manifest, out, version, commit, sha, protocol, dirty = sys.argv[1:8]
with open(manifest) as handle:
    doc = json.load(handle)

capabilities = list(doc.get("capabilities", []))
# A host decides on capability names, so the harness announces itself the same
# way everything else in the guest does.
for name in ("aiec-agent", "coding-agent"):
    if name not in capabilities:
        capabilities.append(name)

doc["capabilities"] = capabilities
doc["aiec_agent"] = {
    "version": version,
    "commit": commit,
    "sha256": sha,
    "protocol": int(protocol),
    "path": "/usr/local/bin/aiec-agent",
}
if dirty:
    doc["aiec_agent"]["built_from_dirty_tree"] = True

with open(out, "w") as handle:
    json.dump(doc, handle, indent=1, sort_keys=True)
    handle.write("\n")
PY
mv "$BAKE_TMP" "$MANIFEST"
step "recorded: aiec-agent $VERSION (${COMMIT:0:12}) protocol $PROTOCOL"
