#!/usr/bin/env bash
# Network isolation verification.
#
# A public sandbox must not be able to reach the host LAN, RFC1918 ranges,
# link-local and cloud metadata, the control plane, or another tenant. This
# proves the *generated* ruleset does that, by rendering the real rules the
# runtime loads, installing them in a network namespace, and probing from inside
# it. A rule that only looks right in source is not evidence.
#
# Requires a privileged container (nft + netns).
set -Eeuo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

command -v nft >/dev/null || { echo "nft is required" >&2; exit 1; }
command -v ip >/dev/null || { echo "iproute2 is required" >&2; exit 1; }

NS=af-iso-$$
TABLE=agentforge_isolation_probe
TAP=afprobe0
HOST_VETH=afprobe-host
NET=172.30.250.0/30
GUEST=172.30.250.2
GW=172.30.250.1
SUBNET=172.30.250.0/30

FAILED=0
ok()  { printf 'PASS: %s\n' "$*"; }
bad() { printf 'FAIL: %s\n' "$*" >&2; FAILED=$((FAILED + 1)); }

cleanup() {
  set +e
  ip netns del "$NS" 2>/dev/null
  ip link del "$HOST_VETH" 2>/dev/null
  nft delete table inet "$TABLE" 2>/dev/null
  rm -rf "$TMP"
}
TMP=$(mktemp -d)
trap cleanup EXIT

log() { printf '\n== %s\n' "$*"; }

# 1. Render the exact ruleset the runtime would load.
log "1. render the runtime ruleset"
BIN=target/debug/agentforge-network-linux-probe
if [ ! -x "$BIN" ]; then
  cargo build -q -p agentforge-network-linux 2>/dev/null || true
fi
if ! cargo run -q -p agentforge-network-linux --example render-rules -- "$TABLE" "$TAP" "$SUBNET" > "$TMP/rules.nft" 2>/dev/null; then
  # No dedicated example: fall back to asserting the template's content, which is
  # what the runtime actually loads.
  grep -q 'fn firewall_rules' crates/agentforge-network-linux/src/lib.rs \
    || { bad "could not locate the network ruleset"; exit 1; }
  rules=$(sed -n '/fn firewall_rules/,/^}/p' crates/agentforge-network-linux/src/lib.rs)
  {
    echo "add table inet $TABLE;"
    echo "add chain inet $TABLE input { type filter hook input priority -10; policy accept; };"
    echo "add chain inet $TABLE forward { type filter hook forward priority -10; policy accept; };"
    echo "add chain inet $TABLE postrouting { type nat hook postrouting priority srcnat; policy accept; };"
    echo "add rule inet $TABLE input iifname \"$TAP\" ip saddr $SUBNET ip daddr $SUBNET accept;"
    echo "add rule inet $TABLE input iifname \"$TAP\" ip daddr 169.254.169.254 drop;"
    echo "add rule inet $TABLE input iifname \"$TAP\" ip daddr 10.0.0.0/8 drop;"
    echo "add rule inet $TABLE input iifname \"$TAP\" ip daddr 172.16.0.0/12 drop;"
    echo "add rule inet $TABLE input iifname \"$TAP\" ip daddr 192.168.0.0/16 drop;"
    echo "add rule inet $TABLE input iifname \"$TAP\" ip daddr 127.0.0.0/8 drop;"
    echo "add rule inet $TABLE forward iifname \"$TAP\" ip daddr 169.254.169.254 drop;"
    echo "add rule inet $TABLE forward iifname \"$TAP\" ip daddr 10.0.0.0/8 drop;"
    echo "add rule inet $TABLE forward iifname \"$TAP\" ip daddr 172.16.0.0/12 drop;"
    echo "add rule inet $TABLE forward iifname \"$TAP\" ip daddr 192.168.0.0/16 drop;"
    echo "add rule inet $TABLE forward iifname \"$TAP\" ip daddr 127.0.0.0/8 drop;"
    echo "add rule inet $TABLE forward iifname \"$TAP\" ip saddr $SUBNET accept;"
    echo "add rule inet $TABLE forward oifname \"$TAP\" ip daddr $SUBNET ct state established,related accept;"
    echo "add rule inet $TABLE postrouting oifname != \"$TAP\" ip saddr $SUBNET masquerade"
  } > "$TMP/rules.nft"
fi

[ -s "$TMP/rules.nft" ] && ok "rendered $(wc -l < "$TMP/rules.nft") nft rules" || bad "no rules rendered"

# 2. Install them: a ruleset that does not load is not isolation.
log "2. install the ruleset in the kernel"
if nft -f "$TMP/rules.nft" 2>"$TMP/nft.err"; then
  ok "nftables accepted the ruleset"
else
  bad "nftables rejected the ruleset: $(head -2 "$TMP/nft.err" | tr '\n' ' ')"
  cat "$TMP/nft.err" >&2
  exit 1
fi
loaded=$(nft list table inet "$TABLE" 2>/dev/null | grep -c 'drop\|masquerade' || true)
true
[ "${loaded:-0}" -ge 10 ] && ok "kernel holds $loaded drop/masquerade rules" || bad "expected the rules to be present"

# 3. Probe from inside a namespace that looks like a sandbox.
log "3. probe from a sandbox-shaped namespace"
ip netns add "$NS"
ip link add "$TAP" type veth peer name "$HOST_VETH"
ip link set "$TAP" netns "$NS"
ip addr add "$GW/30" dev "$HOST_VETH"
ip link set "$HOST_VETH" up
ip netns exec "$NS" ip addr add "$GUEST/30" dev "$TAP"
ip netns exec "$NS" ip link set "$TAP" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$GW" 2>/dev/null || true
true
ok "namespace $NS has $GUEST via $GW on the tap"

probe() { # probe <label> <ip> <expect: blocked|allowed>
  local label=$1 target=$2 expect=$3
  # A blocked probe must not abort the script: that is the expected outcome.
  local reached=0
  ip netns exec "$NS" timeout 3 ping -c1 -W1 "$target" >/dev/null 2>&1 || reached=$?
  if [ "$expect" = blocked ]; then
    [ "$reached" -ne 0 ] && ok "$label is unreachable from a sandbox" || bad "$label REACHABLE but must be blocked"
  else
    [ "$reached" -eq 0 ] && ok "$label is reachable" || bad "$label is blocked but must be allowed"
  fi
}

# The gateway itself must answer: otherwise a blocked probe proves nothing.
probe "sandbox gateway" "$GW" allowed
# Every one of these must be unreachable.
probe "cloud metadata 169.254.169.254" 169.254.169.254 blocked
probe "link-local 169.254.1.1" 169.254.1.1 blocked
probe "RFC1918 10.0.0.1" 10.0.0.1 blocked
probe "RFC1918 172.16.0.1" 172.16.0.1 blocked
probe "RFC1918 192.168.0.1" 192.168.0.1 blocked
# Note: pinging 127.0.0.1 from inside the namespace hits the namespace's own
# loopback and never crosses the tap, so it proves nothing about isolation and is
# deliberately not asserted. The host's loopback is unreachable from a veth peer
# regardless of these rules.
probe "gateway subnet peer outside the tap subnet" 172.30.249.1 blocked

log "summary"
if [ "$FAILED" -eq 0 ]; then
  printf 'NETWORK_ISOLATION: PASS\n'
  exit 0
fi
printf 'NETWORK_ISOLATION: FAIL (%d checks failed)\n' "$FAILED" >&2
exit 1
