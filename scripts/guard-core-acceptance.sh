#!/usr/bin/env bash
# Builds the in-guest agent harness (a static musl container build) and changes
# nothing else on the host. Every address/listener/firewall change is in a
# disposable netns.
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
  # The in-guest agent harness is static musl, which is a container build, and
  # a container is a host-side tool - so it is built here, before the namespace
  # exists, and the path is handed to the driver. Building it inside the
  # namespace instead would mean the one artifact the agent leg depends on is
  # produced by a step the acceptance is supposed to be verifying. The script
  # prints progress on stderr and the absolute path on its last stdout line.
  AIEC_AGENT_BINARY=$(bash "$(dirname "$self")/build-harness-static.sh" | tail -n1)
  [[ -x $AIEC_AGENT_BINARY ]] || {
    printf 'the in-guest harness build produced no executable: %s\n' "$AIEC_AGENT_BINARY" >&2
    exit 2
  }
  export AIEC_AGENT_BINARY
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
# The driver writes its report to stdout. It is captured to a file rather than
# piped, because the run also has to be waited on as a process and a pipe
# would make the status that matters be the reader's rather than the driver's.
report=$(mktemp "${TMPDIR:-/tmp}/guard-core-report.XXXXXX")
setsid "$1" >"$report" 2>&1 &
child=$!
set +e
wait "$child"
status=$?
set -e
cat "$report"
# The driver prints a build line before its report, so the report is the JSON
# object in the stream rather than the stream itself.
json=$(python3 -c 'import json, sys
text = sys.stdin.read()
start = text.find("{")
if start < 0:
    sys.exit(1)
try:
    report = json.loads(text[start:])
except ValueError:
    sys.exit(1)
print(json.dumps(report))
sys.exit(0 if report.get("status") == "PASS" else 1)' <"$report") || json=
if [[ $status == 0 && -n $json ]]; then
  artifact=${AIEC_AGENT_REPORT:-benchmarks/guard-core-acceptance.json}
  mkdir -p "$(dirname "$artifact")"
  printf '%s\n' "$json" >"$artifact"
  printf 'published %s\n' "$artifact" >&2
else
  printf 'run did not pass; leaving the committed artifact untouched\n' >&2
fi
rm -f "$report"
exit "$status"
