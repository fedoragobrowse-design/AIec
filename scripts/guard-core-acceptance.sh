#!/usr/bin/env bash
# Builds nothing. Every address/listener/firewall change is in a disposable netns.
set -euo pipefail
if [[ ${1:-} != --inside ]]; then
  executable=${1:-target/release/examples/guard_core_acceptance}
  [[ -x "$executable" ]] || { printf '%s\n' 'prebuilt guard_core_acceptance executable required' >&2; exit 2; }
  executable=$(realpath "$executable")
  for tool in unshare ip nft sysctl setsid; do command -v "$tool" >/dev/null; done
  : "${AIEC_FIRECRACKER_BIN:?load the existing Firecracker environment first}"
  : "${AIEC_KERNEL:?}" "${AIEC_ROOTFS:?}" "${AIEC_GUEST_SECRET:?}"
  exec unshare --user --map-root-user --net --fork --kill-child=KILL "$0" --inside "$executable"
fi
shift
[[ $(id -u) == 0 && $(readlink /proc/self/ns/net) != $(readlink /proc/1/ns/net) ]] || {
  printf '%s\n' 'refusing acceptance outside isolated root-mapped net namespace' >&2; exit 2;
}
state=$(mktemp -d "${TMPDIR:-/tmp}/aiec-guard-acceptance.XXXXXXXX")
chmod 700 "$state"
child=
cleanup() {
  trap - EXIT INT TERM
  if [[ -n $child ]]; then
    kill -TERM -- "-$child" 2>/dev/null || true
    for _ in {1..10}; do
      kill -0 -- "-$child" 2>/dev/null || break
      sleep 1
    done
    kill -KILL -- "-$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  rm -rf -- "$state"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ip link set lo up
# Public-looking addresses below are LOCAL sentinels, not Internet destinations.
for address in 198.18.0.10 198.18.0.20 198.18.0.21 93.184.216.34 10.123.0.10 169.254.1.10 169.254.169.254; do
  ip address add "$address/32" dev lo
done
ip -6 address add fd00:feed::10/128 dev lo
# This sysctl is network-namespace scoped; never changes the host firewall/routes.
sysctl -qw net.ipv4.ip_forward=1
export AIEC_GUARD_ACCEPTANCE_STATE="$state"
unset AIEC_TAP AIEC_JAILER AIEC_GUARD_CREDENTIALS_FILE AIEC_GUARD_BOUNDARY_FILE AIEC_ALLOW_LEGACY_NETWORK
setsid "$1" &
child=$!
set +e
wait "$child"
status=$?
set -e
exit "$status"
