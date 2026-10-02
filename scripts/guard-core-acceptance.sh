#!/usr/bin/env bash
# Builds nothing. Every address/listener/firewall change is in a disposable netns.
#
# The launcher creates the namespace and nothing else. Loopback, the local
# sentinel addresses and the namespace-scoped forward setting belong to the
# driver, because the driver is what verifies isolation first - configuring a
# network before knowing which network it is would defeat the point of the check.
set -euo pipefail

if [[ ${1:-} != --inside ]]; then
  executable=${1:-target/release/examples/guard_core_acceptance}
  [[ -x "$executable" ]] || { printf '%s\n' 'prebuilt guard_core_acceptance executable required' >&2; exit 2; }
  executable=$(realpath "$executable")
  for tool in unshare ip nft sysctl setsid; do command -v "$tool" >/dev/null; done
  : "${AIEC_FIRECRACKER_BIN:?load the existing Firecracker environment first}"
  : "${AIEC_KERNEL:?}" "${AIEC_ROOTFS:?}" "${AIEC_GUEST_SECRET:?}"
  # Absolute, because the re-exec happens inside a namespace where a relative
  # $0 no longer resolves to anything.
  self=$(realpath "$0")
  # The host's network namespace inode, recorded BEFORE unshare. Inside the new
  # namespace PID 1 belongs to the host namespace but reading another process's
  # namespace link is denied, so `/proc/1/ns/net` comes back empty rather than
  # as an inode and cannot be compared from within. Handing the host's inode in
  # instead makes the driver's comparison a real, positive test: it knows what
  # it must NOT be.
  host_netns=$(readlink /proc/self/ns/net)
  [[ $host_netns == net:* ]] || {
    printf '%s\n' 'cannot read the host network namespace' >&2
    exit 2
  }
  export AIEC_GUARD_ACCEPTANCE_HOST_NETNS="$host_netns"
  exec unshare --user --map-root-user --net --fork --kill-child=KILL \
    bash "$self" --inside "$executable"
fi
shift

# Inside the disposable namespace. The driver repeats this comparison and is
# the gate: this one is a convenience that fails fast with a clear message.
[[ $(id -u) == 0 ]] || { printf '%s\n' 'acceptance must run root-mapped' >&2; exit 2; }
[[ $(readlink /proc/self/ns/net) != "${AIEC_GUARD_ACCEPTANCE_HOST_NETNS:?}" ]] || {
  printf '%s\n' 'refusing to run in the host network namespace' >&2
  exit 2
}

state=$(mktemp -d "${TMPDIR:-/tmp}/aiec-guard-acceptance.XXXXXXXX")
chmod 700 "$state"
child=
cleanup() {
  trap - EXIT INT TERM
  if [[ -n $child ]]; then
    kill -TERM -- "-$child" 2>/dev/null || true
    for _ in {1..10}; do
      kill -0 -- "-$child" 2>/dev/null && break
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

export AIEC_GUARD_ACCEPTANCE_STATE="$state"
unset AIEC_TAP AIEC_JAILER AIEC_GUARD_CREDENTIALS_FILE AIEC_GUARD_BOUNDARY_FILE
# The incident reproduction needs one deliberately unguarded sandbox as its
# control leg, which is exactly what the main run must never contain. It is
# opt-in and unset by default, so the ordinary acceptance still cannot create
# an unguarded guest even if the operator exported the variable beforehand.
if [[ ${AIEC_REPRO_LEGACY_CONTROL:-0} == 1 ]]; then
  export AIEC_ALLOW_LEGACY_NETWORK=1
else
  unset AIEC_ALLOW_LEGACY_NETWORK AIEC_REPRO_LEGACY_CONTROL
fi
setsid "$1" &
child=$!
set +e
wait "$child"
status=$?
set -e
exit "$status"
