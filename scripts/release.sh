#!/usr/bin/env bash
# Produce a tagged AgentForge public-alpha release.
#
# Builds the server, worker and CLI, records the guest artifact metadata, runs
# the static gates, and writes release notes. It refuses to publish anything that
# does not build clean, and it never includes a secret in the artifacts.
set -Eeuo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

VERSION=${1:-${AGENTFORGE_RELEASE_TAG:-}}
if [ -z "$VERSION" ]; then
  echo "usage: release.sh <tag>   (for example v0.2.0-alpha.1)" >&2
  exit 2
fi
case "$VERSION" in
  v*) ;;
  *) echo "tag must start with v, e.g. v0.2.0-alpha.1" >&2; exit 2 ;;
esac

DIST="dist/$VERSION"
mkdir -p "$DIST"
log() { printf '\n== %s\n' "$*"; }

log "static gates"
cargo fmt --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check

log "build release binaries"
cargo build --release -p agentforge-api --bin agentforge-server -p agentforge-cli --bin agentforge
install -m 0755 target/release/agentforge-server "$DIST/agentforge-server"
install -m 0755 target/release/agentforge "$DIST/agentforge"
# The worker is the same binary as the CLI, invoked with the worker subcommand;
# a named copy makes the artifact self-describing.
install -m 0755 target/release/agentforge "$DIST/agentforge-worker"

log "guest artifact metadata"
if [ -f .agentforge/images/guest-capabilities.json ]; then
  cp .agentforge/images/guest-capabilities.json "$DIST/guest-capabilities.json"
  sha256sum .agentforge/images/agentforge-rootfs.ext4 > "$DIST/guest-rootfs.sha256" 2>/dev/null || true
  log "guest: $(python3 -c 'import json;d=json.load(open(".agentforge/images/guest-capabilities.json"));print(d.get("base"),d.get("git_version"))' 2>/dev/null || echo unknown)"
else
  echo "no guest artifact metadata present; the Firecracker guest image has not been built" >&2
fi

log "release notes"
cat > "$DIST/RELEASE_NOTES.md" <<EOF
# AgentForge $VERSION

Public alpha. Invite-only, limited capacity, no SLA.

## What is new

- Invitation-gated accounts: a stranger can sign up and receive an API key.
- Tenant self-service for API keys, with scope escalation refused.
- Cloud console for keys, sandboxes, usage and service health.
- Hosted Firecracker execution behind the existing runtime abstraction, with
  AgentForge keeping ownership of every public sandbox identifier.
- Public workloads are restricted to microVM isolation.
- Append-only security audit log, worker drain, and a global execution budget.
- Per-tenant rate limiting with Retry-After.

## Known limitations

- Invite-only signup, single region, no SLA.
- Hosted capacity is provided by a third party; AgentForge's own native Firecracker
  runtime is complete and is what self-hosted deployments run, but the hosted
  fleet is not AgentForge-operated hardware.
- Multi-host (separate control and worker machines) is not yet validated.
- Snapshots preserve the workspace filesystem, not running VM memory.
- Public API stability is not guaranteed before 1.0.

## Security

Report vulnerabilities to security@gobrowse.dev. See SECURITY.md.
EOF

log "checksums"
( cd "$DIST" && sha256sum ./* > SHA256SUMS )
ls -l "$DIST"
log "release staged in $DIST"
echo "Push the tag and the dist artifacts to publish; nothing is published by this script."
