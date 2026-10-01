//! Policy compiler and operator-boundary verifier.
//!
//! One validated [`GuardPolicy`] is compiled once into a [`CompiledPolicy`]
//! that every enforcement surface consults: the gateway, the DNS resolver, the
//! credential broker and the nftables rule model. Nothing here emits shell
//! commands or hands out nftables syntax.
//!
//! ## What the verifier models
//!
//! The verifier evaluates the *finite rule model* exhaustively: every egress
//! rule, model endpoint and credential binding is checked against the operator
//! boundary, and every blocked range is probed with concrete representative
//! addresses. That is complete for the compiled rule set as modelled here.
//! It is **not** a formal proof about the host network, about live DNS answers
//! or about the guest kernel, and no SMT solver is claimed. Failures are
//! reported as concrete counterexamples naming the host, port, rule and range.
//!
//! ## Boundary precedence
//!
//! 1. `protected_cidrs` and `blocked_hosts` always deny. They hold the runtime
//!    gateway, guest, peer-sandbox and management addresses and can never be
//!    overridden by a test mapping.
//! 2. Operator `blocked_cidrs` always deny.
//! 3. Guard's default non-public ranges deny private, loopback, link-local,
//!    metadata, multicast, CGNAT, documentation and otherwise reserved space for
//!    both IPv4 and IPv6.
//! 4. An exact operator `test_destinations` entry (`host:port` -> addresses)
//!    may authorize a local mock address past step 3 only. It never creates an
//!    egress permission on its own: the policy must still permit the host and
//!    port.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::policy::{
    GuardPolicy, Limits, MAX_HOST_BYTES, ModelEndpoint, PolicyTemplate, eq_ignore_case,
    zone_matches,
};
use crate::{GuardError, Result};

/// Maximum number of CIDRs accepted in any boundary list.
pub const MAX_BOUNDARY_CIDRS: usize = 256;
/// Maximum number of blocked host names accepted in a boundary.
pub const MAX_BLOCKED_HOSTS: usize = 256;
/// Maximum number of operator test destinations.
pub const MAX_TEST_DESTINATIONS: usize = 64;
/// Maximum number of addresses per operator test destination.
pub const MAX_TEST_ADDRESSES: usize = 16;

fn boundary_error(message: impl Into<String>) -> GuardError {
    GuardError::Policy(message.into())
}

/// Maps a numeric DNS record type to the schema-accepted name. Types outside
/// this set, including `ANY`, `NS`, `TXT` and `NULL`, are never answered.
fn dns_record_type_name(record_type: u16) -> Option<&'static str> {
    match record_type {
        1 => Some("A"),
        28 => Some("AAAA"),
        _ => None,
    }
}

/// Builds a concrete counterexample naming host, port, rule and cause.
fn counterexample(
    kind: &str,
    host: &str,
    port: Option<u16>,
    protocol: &str,
    rule: &str,
    cause: &str,
) -> GuardError {
    let port = match port {
        Some(port) => port.to_string(),
        None => "any".to_string(),
    };
    GuardError::Policy(format!(
        "{kind}: host={host} port={port} protocol={protocol} matched rule={rule}: {cause}"
    ))
}

/// Guard's default non-public ranges. They always deny unless an exact operator
/// test destination authorizes the address for that host.
///
/// Parsed once and shared: destination checks run on the gateway's per-request
/// path and must not allocate.
fn default_blocked_cidrs() -> &'static [IpNet] {
    static RANGES: std::sync::LazyLock<Vec<IpNet>> = std::sync::LazyLock::new(|| {
        [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "::/128",
            "::1/128",
            "64:ff9b::/96",
            "100::/64",
            "2001::/32",
            "2001:db8::/32",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
        ]
        .into_iter()
        .map(|cidr| {
            cidr.parse::<IpNet>()
                .expect("default Guard boundary CIDR must parse")
        })
        .collect()
    });
    &RANGES
}

/// Default reasons for the ranges above, used in counterexamples.
fn default_block_reason(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) => match v4.octets() {
            [0, _, _, _] => "this network",
            [10, _, _, _] | [172, 16..=31, _, _] | [192, 168, _, _] => "RFC1918 private range",
            [100, 64..=127, _, _] => "CGNAT shared address space",
            [127, _, _, _] => "loopback range",
            [169, 254, _, _] => {
                "link-local range, includes the cloud metadata endpoint 169.254.169.254"
            }
            [192, 0, 0, _] => "IETF protocol assignment range",
            [192, 0, 2, _] => "documentation range",
            [192, 88, 99, _] => "6to4 relay anycast range",
            [198, 18..=19, _, _] => "benchmarking range",
            [198, 51, 100, _] | [203, 0, 113, _] => "documentation range",
            [224..=239, _, _, _] => "multicast range",
            [240..=255, _, _, _] => "reserved range",
            _ => "non-public address space",
        },
        IpAddr::V6(v6) => {
            if *v6 == Ipv6Addr::UNSPECIFIED {
                "unspecified address"
            } else if v6.is_loopback() {
                "loopback address"
            } else if (u32::from(v6.segments()[0]) & 0xfe00) == 0xfc00 {
                "unique local address"
            } else if (u32::from(v6.segments()[0]) & 0xffc0) == 0xfe80 {
                "link-local address, includes IPv6 metadata"
            } else if (u32::from(v6.segments()[0]) & 0xff00) == 0xff00 {
                "multicast address"
            } else if *v6 == Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0) {
                "documentation address"
            } else if (u32::from(v6.segments()[0]) & 0xff00) == 0xfe00 {
                "reserved address"
            } else {
                "non-public address space"
            }
        }
    }
}

/// Unwraps IPv4-mapped and IPv4-compatible IPv6 addresses so a v4 range cannot
/// be bypassed through an `::ffff:` spelling.
fn normalize_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => match v6.to_ipv4() {
                Some(v4) if v4.octets() != [0, 0, 0, 0] => IpAddr::V4(v4),
                _ => IpAddr::V6(v6),
            },
        },
        other => other,
    }
}

/// Whether an address is loopback, link-local, private or otherwise not a public
/// unicast destination.
fn is_non_public(ip: &IpAddr) -> bool {
    match normalize_addr(*ip) {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_private()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 2)
                // 198.18.0.0/15: the mask must be 0x12, because 18 and 19 are
                // 0x12 and 0x13. Written as 0x18 it matched nothing, which made
                // the benchmarking range look like public space and rejected
                // the one range a local mock is allowed to use.
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 0x12)
                || (v4.octets()[0] == 198 && v4.octets()[1] == 51 && v4.octets()[2] == 100)
                || (v4.octets()[0] == 203 && v4.octets()[1] == 0 && v4.octets()[2] == 113)
                || (v4.octets()[0] >= 240)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some()
        }
    }
}

/// Representative addresses inside a range, used to probe blocked space.
fn representative_addresses(net: &IpNet) -> Vec<IpAddr> {
    match *net {
        IpNet::V4(v4) => {
            let prefix = v4.prefix_len();
            let base = v4.network().octets();
            let last = v4.broadcast().octets();
            let mut out = vec![IpAddr::V4(Ipv4Addr::from(base))];
            if prefix < 32 {
                let mut next = base;
                next[3] = next[3].wrapping_add(1);
                out.push(IpAddr::V4(Ipv4Addr::from(next)));
            }
            if prefix <= 1 {
                out.push(IpAddr::V4(Ipv4Addr::from(last)));
            }
            out
        }
        IpNet::V6(v6) => {
            let prefix = v6.prefix_len();
            let base = v6.network().segments();
            let last = v6.broadcast().segments();
            let mut out = vec![IpAddr::V6(Ipv6Addr::from(base))];
            if prefix < 128 {
                let mut next = base;
                next[7] = next[7].wrapping_add(1);
                out.push(IpAddr::V6(Ipv6Addr::from(next)));
            }
            if prefix <= 1 {
                out.push(IpAddr::V6(Ipv6Addr::from(last)));
            }
            out
        }
    }
}

/// Operator-supplied boundary the compiled policy must respect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorBoundary {
    /// Extra ranges the operator blocks, on top of Guard's defaults.
    pub blocked_cidrs: Vec<IpNet>,
    /// Ranges that can never be authorized by a policy or a test mapping: the
    /// Guard gateway, guest, peer-sandbox and management addresses. Runtime
    /// adds its own `/32`s here.
    pub protected_cidrs: Vec<IpNet>,
    /// Host names that are never reachable, such as control-plane names.
    pub blocked_hosts: Vec<String>,
    /// Exact operator test mappings `host:port` -> local mock addresses.
    pub test_destinations: BTreeMap<String, Vec<IpAddr>>,
}

/// The `host:port` key format used by [`OperatorBoundary::test_destinations`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestDestination {
    host: String,
    port: u16,
}

impl TestDestination {
    /// Parses and validates a `host:port` test destination key.
    pub fn parse(key: &str) -> Result<Self> {
        let (host, port) = key.rsplit_once(':').ok_or_else(|| {
            boundary_error(format!(
                "test destination key {key} must be host:port with a canonical host"
            ))
        })?;
        crate::policy::validate_dns_name(host, "test destination host", 2)?;
        if host.len() > MAX_HOST_BYTES {
            return Err(boundary_error("test destination host is too long"));
        }
        let port: u16 = port.parse().map_err(|_| {
            boundary_error(format!("test destination key {key} has an invalid port"))
        })?;
        if port == 0 {
            return Err(boundary_error(format!(
                "test destination key {key} must not use port 0"
            )));
        }
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    /// Builds and validates the key for a host and port.
    pub fn new(host: &str, port: u16) -> Result<Self> {
        Self::parse(&format!("{host}:{port}"))
    }

    /// The canonical host of this mapping.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port of this mapping.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for TestDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl OperatorBoundary {
    /// A production boundary.
    ///
    /// `blocked_cidrs` holds operator *additions* only: Guard's default
    /// non-public ranges always apply and are never stored here, so an exact
    /// operator test mapping can still authorize a local mock address.
    pub fn production() -> Self {
        Self::default()
    }

    /// Validates boundary structure: bounded lists, canonical host names,
    /// non-public test addresses and no contradicting entries.
    pub fn validate(&self) -> Result<()> {
        for (label, list) in [
            ("blocked_cidrs", &self.blocked_cidrs),
            ("protected_cidrs", &self.protected_cidrs),
        ] {
            if list.len() > MAX_BOUNDARY_CIDRS {
                return Err(boundary_error(format!(
                    "{label} has {} entries, maximum is {MAX_BOUNDARY_CIDRS}",
                    list.len()
                )));
            }
            for (index, cidr) in list.iter().enumerate() {
                if list[..index].contains(cidr) {
                    return Err(boundary_error(format!(
                        "{label} contains duplicate entry {cidr}"
                    )));
                }
            }
        }
        if self.blocked_hosts.len() > MAX_BLOCKED_HOSTS {
            return Err(boundary_error(format!(
                "blocked_hosts has {} entries, maximum is {MAX_BLOCKED_HOSTS}",
                self.blocked_hosts.len()
            )));
        }
        for (index, host) in self.blocked_hosts.iter().enumerate() {
            crate::policy::validate_dns_name(host, "blocked_hosts entry", 1)?;
            if self.blocked_hosts[..index].contains(host) {
                return Err(boundary_error(format!(
                    "blocked_hosts contains duplicate entry {host}"
                )));
            }
        }
        if self.test_destinations.len() > MAX_TEST_DESTINATIONS {
            return Err(boundary_error(format!(
                "test_destinations has {} entries, maximum is {MAX_TEST_DESTINATIONS}",
                self.test_destinations.len()
            )));
        }
        for (key, addresses) in &self.test_destinations {
            let parsed = TestDestination::parse(key)?;
            if addresses.len() > MAX_TEST_ADDRESSES {
                return Err(boundary_error(format!(
                    "test destination {parsed} has {} addresses, maximum is {MAX_TEST_ADDRESSES}",
                    addresses.len()
                )));
            }
            if addresses.is_empty() {
                return Err(boundary_error(format!(
                    "test destination {parsed} must list at least one address"
                )));
            }
            if self.blocked_hosts.iter().any(|host| host == parsed.host()) {
                return Err(boundary_error(format!(
                    "test destination {parsed} names blocked host {}; blocked hosts can never be \
                     authorized",
                    parsed.host()
                )));
            }
            for (index, address) in addresses.iter().enumerate() {
                if !is_non_public(address) {
                    return Err(boundary_error(format!(
                        "test destination {parsed} lists public address {address}; operator test \
                         mappings authorize local mock addresses only"
                    )));
                }
                if addresses[..index].contains(address) {
                    return Err(boundary_error(format!(
                        "test destination {parsed} lists address {address} twice"
                    )));
                }
                for (label, ranges) in [
                    ("protected", &self.protected_cidrs),
                    ("blocked", &self.blocked_cidrs),
                ] {
                    if let Some(net) = ranges.iter().find(|net| net.contains(address)) {
                        return Err(boundary_error(format!(
                            "test destination {parsed} lists {address}, which is inside operator \
                             {label} range {net} and can never be authorized"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether a host name is never reachable. Case-folded and allocation-free.
    pub fn blocks_host(&self, host: &str) -> bool {
        self.blocked_hosts
            .iter()
            .any(|blocked| eq_ignore_case(blocked, host))
    }

    /// Whether an address falls inside an operator-added blocked range. These
    /// always deny and are never overridable by a test mapping.
    pub fn operator_blocked(&self, ip: &IpAddr) -> Option<IpNet> {
        let ip = normalize_addr(*ip);
        self.blocked_cidrs
            .iter()
            .copied()
            .find(|net| net.contains(&ip))
    }

    /// Whether an address falls inside one of Guard's default non-public
    /// ranges. Only an exact operator test mapping may authorize these.
    pub fn default_blocked(&self, ip: &IpAddr) -> Option<(IpNet, &'static str)> {
        let ip = normalize_addr(*ip);
        default_blocked_cidrs()
            .iter()
            .find(|net| net.contains(&ip))
            .map(|net| (*net, default_block_reason(&ip)))
    }

    /// Every network this boundary denies, for consumers that must classify or
    /// materialize the same ranges.
    ///
    /// Enforcement backends iterate this instead of keeping a second,
    /// hand-maintained list of private, loopback, metadata or reserved ranges,
    /// so the rule model and the boundary cannot drift apart. The order is
    /// stable: Guard defaults, then operator additions, then protected ranges.
    pub fn denied_networks(&self) -> impl Iterator<Item = &'_ IpNet> {
        default_blocked_cidrs()
            .iter()
            .chain(self.blocked_cidrs.iter())
            .chain(self.protected_cidrs.iter())
    }

    /// Whether an address falls inside a range that can never be authorized.
    fn protected_range(&self, ip: &IpAddr) -> Option<IpNet> {
        let ip = normalize_addr(*ip);
        self.protected_cidrs
            .iter()
            .copied()
            .find(|net| net.contains(&ip))
    }

    /// Addresses an operator mapped for exactly this host and port.
    ///
    /// Allocation-free: the `host:port` key is rendered into a stack buffer, so
    /// this is safe to call on the gateway's per-request path.
    pub fn test_addresses(&self, host: &str, port: u16) -> &[IpAddr] {
        let key = EndpointKey::new(host, port);
        self.test_destinations
            .iter()
            .find(|(candidate, _)| candidate.as_bytes().eq_ignore_ascii_case(key.as_bytes()))
            .map_or(&[], |(_, addresses)| addresses.as_slice())
    }

    /// Whether an address is an operator test address for this host on any port.
    ///
    /// Allocation-free: keys are validated at load time as `host:port`, so the
    /// host is matched by prefix plus the colon separator.
    pub fn is_test_address(&self, host: &str, ip: &IpAddr) -> bool {
        let ip = normalize_addr(*ip);
        let host = crate::policy::strip_trailing_dot(host);
        self.test_destinations.iter().any(|(key, addresses)| {
            let bytes = key.as_bytes();
            bytes.len() > host.len()
                && bytes[host.len()] == b':'
                && bytes[..host.len()].eq_ignore_ascii_case(host.as_bytes())
                && addresses.contains(&ip)
        })
    }
}

/// A `host:port` key rendered into a stack buffer, so hot-path lookups against
/// the test-destination map never allocate.
struct EndpointKey {
    buf: [u8; MAX_HOST_BYTES + 6],
    len: usize,
}

impl EndpointKey {
    fn new(host: &str, port: u16) -> Self {
        let mut buf = [0_u8; MAX_HOST_BYTES + 6];
        let host = crate::policy::strip_trailing_dot(host).as_bytes();
        let host = &host[..host.len().min(MAX_HOST_BYTES)];
        buf[..host.len()].copy_from_slice(host);
        buf[host.len()] = b':';
        let mut index = host.len() + 1;
        let mut remaining = port;
        let mut digits = [0_u8; 5];
        let mut cursor = digits.len();
        loop {
            cursor -= 1;
            digits[cursor] = b'0' + u8::try_from(remaining % 10).unwrap_or(0);
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        buf[index..index + (digits.len() - cursor)].copy_from_slice(&digits[cursor..]);
        index += digits.len() - cursor;
        Self { buf, len: index }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryFile {
    #[serde(default)]
    blocked_cidrs: Vec<IpNet>,
    #[serde(default)]
    protected_cidrs: Vec<IpNet>,
    #[serde(default)]
    blocked_hosts: Vec<String>,
    #[serde(default)]
    test_destinations: BTreeMap<String, Vec<IpAddr>>,
}

impl From<&OperatorBoundary> for BoundaryFile {
    fn from(boundary: &OperatorBoundary) -> Self {
        Self {
            blocked_cidrs: boundary.blocked_cidrs.clone(),
            protected_cidrs: boundary.protected_cidrs.clone(),
            blocked_hosts: boundary.blocked_hosts.clone(),
            test_destinations: boundary.test_destinations.clone(),
        }
    }
}

impl Serialize for OperatorBoundary {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        BoundaryFile::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OperatorBoundary {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let file = BoundaryFile::deserialize(deserializer)?;
        let boundary = Self {
            blocked_cidrs: file.blocked_cidrs,
            protected_cidrs: file.protected_cidrs,
            blocked_hosts: file.blocked_hosts,
            test_destinations: file.test_destinations,
        };
        boundary
            .validate()
            .map_err(|err| D::Error::custom(err.to_string()))?;
        Ok(boundary)
    }
}

/// A validated policy plus its canonical hash and the boundary it was checked
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    policy: GuardPolicy,
    policy_hash: String,
    boundary: OperatorBoundary,
}

impl CompiledPolicy {
    /// The normalized policy, stored in canonical form.
    pub fn policy(&self) -> &GuardPolicy {
        &self.policy
    }

    /// Hex SHA-256 of the canonical policy.
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    /// The boundary this policy was verified against.
    pub fn boundary(&self) -> &OperatorBoundary {
        &self.boundary
    }

    /// The first-class model endpoint, if any.
    pub fn model_endpoint(&self) -> Option<&ModelEndpoint> {
        self.policy.model.as_ref()
    }

    /// The credential binding for a placeholder name.
    pub fn credential(&self, name: &str) -> Option<&crate::policy::CredentialBinding> {
        self.policy
            .credentials
            .iter()
            .find(|binding| binding.name == name)
    }

    /// Rate, byte and concurrency ceilings.
    pub fn limits(&self) -> &Limits {
        &self.policy.limits
    }

    /// DNS enforcement scope.
    pub fn dns(&self) -> &crate::policy::DnsPolicy {
        &self.policy.network.dns
    }

    /// Whether an egress rule permits exactly this destination.
    pub fn allows_host(&self, host: &str, port: u16) -> bool {
        self.endpoint(host, port).is_some()
    }

    /// Whether a DNS query is permitted.
    ///
    /// `record_type` is the numeric DNS record type of the question (`1` for A,
    /// `28` for AAAA). A query is answered only when the name is inside the
    /// configured zone scope and the record type is schema-accepted, so unknown
    /// zones are refused rather than recursively forwarded and `ANY`, `NS`,
    /// `TXT` and `NULL` stay denied. Port authorization is a separate check:
    /// the gateway resolves the answer and then applies
    /// [`CompiledPolicy::allows_host`] and [`CompiledPolicy::endpoint`].
    pub fn allows_dns(&self, name: &str, record_type: u16) -> bool {
        let Some(record) = dns_record_type_name(record_type) else {
            return false;
        };
        if !self.policy.network.dns.allows_name(name) {
            return false;
        }
        self.policy
            .network
            .dns
            .allowed_record_types
            .iter()
            .any(|allowed| allowed == record)
    }

    /// The egress rule for a destination, if any.
    ///
    /// Allocation-free: policy hosts are canonical lowercase, so the query is
    /// compared with ASCII case folding instead of being normalized.
    pub fn endpoint(&self, host: &str, port: u16) -> Option<&crate::policy::EgressRule> {
        self.policy
            .network
            .egress
            .iter()
            .find(|rule| rule.port == port && eq_ignore_case(&rule.host, host))
    }

    /// Whether a resolved destination address is usable for a permitted host.
    ///
    /// This is the gateway-side check performed on the address it actually
    /// resolved and pinned, so a public name that resolves into private,
    /// metadata, loopback or otherwise reserved space is still denied.
    pub fn check_destination(&self, host: &str, ip: IpAddr) -> Result<()> {
        crate::policy::validate_query_host(host, "destination host", 2)?;
        let ip = normalize_addr(ip);
        if let Some(net) = self.boundary.protected_range(&ip) {
            return Err(counterexample(
                "DENIED BOUNDARY VIOLATION",
                host,
                None,
                "any",
                "operator boundary protected range",
                &format!("{ip} is a protected address inside {net}, which can never be authorized"),
            ));
        }
        if self.boundary.blocks_host(host) {
            return Err(counterexample(
                "DENIED BOUNDARY VIOLATION",
                host,
                None,
                "any",
                "operator boundary blocked_hosts",
                "host name is blocked by the operator boundary",
            ));
        }
        if let Some(net) = self.boundary.operator_blocked(&ip) {
            return Err(counterexample(
                "DENIED BOUNDARY VIOLATION",
                host,
                None,
                "any",
                "operator boundary blocked range",
                &format!("{ip} is inside operator blocked range {net}"),
            ));
        }
        if let Some((net, reason)) = self.boundary.default_blocked(&ip)
            && !self.boundary.is_test_address(host, &ip)
        {
            return Err(counterexample(
                "DENIED BOUNDARY VIOLATION",
                host,
                None,
                "any",
                "Guard default blocked range",
                &format!("{ip} is inside {net} ({reason})"),
            ));
        }
        Ok(())
    }

    /// Whether a plain-HTTP upstream is authorized.
    ///
    /// Both conditions must hold: the policy must permit that host and port, and
    /// the operator must have mapped exactly this `host:port` to this address.
    /// An operator mapping alone never creates an egress permission, and a
    /// mapping can never override a protected or blocked destination.
    pub fn allows_plain_http_upstream(&self, host: &str, port: u16, ip: IpAddr) -> bool {
        let ip = normalize_addr(ip);
        if !self.allows_host(host, port) && !self.is_model_endpoint(host, port) {
            return false;
        }
        if self.boundary.blocks_host(host) || self.boundary.protected_range(&ip).is_some() {
            return false;
        }
        if self.boundary.operator_blocked(&ip).is_some() {
            return false;
        }
        self.boundary.test_addresses(host, port).contains(&ip)
    }

    fn is_model_endpoint(&self, host: &str, port: u16) -> bool {
        self.policy
            .model
            .as_ref()
            .is_some_and(|model| eq_ignore_case(&model.host, host) && model.port == port)
    }

    /// Re-runs every finite boundary check over the compiled rule model.
    ///
    /// `Ok(())` is the verifier's PASS. A failure is a concrete counterexample
    /// naming the host, port, rule and blocked range.
    pub fn verify(&self) -> Result<()> {
        self.verify_rule_boundaries()?;
        self.verify_model_upstreams()?;
        Ok(())
    }

    fn verify_rule_boundaries(&self) -> Result<()> {
        let policy = &self.policy;
        for (index, rule) in policy.network.egress.iter().enumerate() {
            let label = format!("network.egress[{index}] {}", rule.host);
            self.verify_host_name(&rule.host, rule.port, rule.protocol.as_str(), &label)?;
        }
        if let Some(model) = &policy.model {
            let label = format!("model endpoint {}:{}", model.host, model.port);
            self.verify_host_name(
                &model.host,
                model.port,
                crate::policy::EGRESS_PROTOCOL_TCP,
                &label,
            )?;
        }
        for binding in &policy.credentials {
            let label = format!("credentials[{}]", binding.name);
            self.verify_host_name(
                &binding.host,
                binding.port,
                crate::policy::EGRESS_PROTOCOL_TCP,
                &label,
            )?;
        }
        for zone in &policy.network.dns.allowed_zones {
            if policy
                .network
                .egress
                .iter()
                .any(|rule| zone_matches(zone, &rule.host))
            {
                continue;
            }
            return Err(counterexample(
                "DENIED BOUNDARY VIOLATION",
                zone,
                None,
                "udp",
                "network.dns.allowed_zones",
                "DNS zone has no egress destination behind it",
            ));
        }
        Ok(())
    }

    fn verify_host_name(&self, host: &str, port: u16, protocol: &str, rule: &str) -> Result<()> {
        if self.boundary.blocks_host(host) {
            return Err(counterexample(
                "DENIED BOUNDARY VIOLATION",
                host,
                Some(port),
                protocol,
                rule,
                "host name is listed in the operator boundary blocked_hosts",
            ));
        }

        let mut probes: Vec<IpNet> = self.boundary.blocked_cidrs.clone();
        probes.extend(default_blocked_cidrs());
        for net in probes {
            for address in representative_addresses(&net) {
                // An address the operator explicitly mapped for this host is the
                // sanctioned local-mock exception, not a boundary violation.
                if self.boundary.is_test_address(host, &address) {
                    continue;
                }
                if self.check_destination(host, address).is_ok() {
                    return Err(counterexample(
                        "DENIED BOUNDARY VIOLATION",
                        host,
                        Some(port),
                        protocol,
                        rule,
                        &format!(
                            "{address} is inside blocked range {net} but the rule resolves to it"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn verify_model_upstreams(&self) -> Result<()> {
        let Some(model) = &self.policy.model else {
            return Ok(());
        };
        if model.scheme == crate::policy::MODEL_SCHEME_HTTP {
            let addresses = self.boundary.test_addresses(&model.host, model.port);
            if addresses.is_empty() {
                return Err(counterexample(
                    "DENIED BOUNDARY VIOLATION",
                    &model.host,
                    Some(model.port),
                    "tcp",
                    "model scheme",
                    "plain HTTP upstream requires an explicit operator test destination for this \
                     host and port",
                ));
            }
            for address in addresses {
                if !self.allows_plain_http_upstream(&model.host, model.port, *address) {
                    return Err(counterexample(
                        "DENIED BOUNDARY VIOLATION",
                        &model.host,
                        Some(model.port),
                        "tcp",
                        "operator test destination",
                        &format!(
                            "test address {address} cannot be authorized for this model \
                                  endpoint"
                        ),
                    ));
                }
            }
        } else if !self
            .boundary
            .test_addresses(&model.host, model.port)
            .is_empty()
        {
            // An operator mock mapping on a real HTTPS model endpoint is legal
            // (tests point it at a local TLS mock), but the address must still be
            // non-public and permitted, which allows_plain_http_upstream checks.
            for address in self.boundary.test_addresses(&model.host, model.port) {
                if !self.allows_host(&model.host, model.port) {
                    return Err(counterexample(
                        "DENIED BOUNDARY VIOLATION",
                        &model.host,
                        Some(model.port),
                        "tcp",
                        "operator test destination",
                        &format!("test address {address} has no policy egress rule"),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Compiles a validated policy against an operator boundary.
///
/// Compilation validates the policy, normalizes and hashes it, and then checks
/// every finite host, port and rule relationship against the boundary. A policy
/// that cannot be shown safe is refused; there is no degraded compilation.
pub fn compile(policy: &GuardPolicy, boundary: &OperatorBoundary) -> Result<CompiledPolicy> {
    policy.validate()?;
    boundary.validate()?;
    let normalized = policy.normalized();
    let policy_hash = normalized.hash()?;
    let compiled = CompiledPolicy {
        policy: normalized,
        policy_hash,
        boundary: boundary.clone(),
    };
    compiled.verify()?;
    Ok(compiled)
}

/// Convenience for the common no-network case.
pub fn compile_no_network(boundary: &OperatorBoundary) -> Result<CompiledPolicy> {
    compile(
        &GuardPolicy::template(PolicyTemplate::NoNetwork, None, Vec::new())?,
        boundary,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        CredentialBinding, DnsPolicy, EgressRule, GuardConfig, GuardPolicy, Limits, NetworkPolicy,
    };

    fn model_endpoint() -> ModelEndpoint {
        ModelEndpoint {
            host: "api.example-model.com".to_string(),
            port: 443,
            scheme: crate::policy::MODEL_SCHEME_HTTPS.to_string(),
            allowed_methods: vec!["POST".to_string()],
            allowed_paths: vec!["/v1/".to_string()],
            credential: "model-main".to_string(),
        }
    }

    fn model_only_policy() -> GuardPolicy {
        GuardPolicy::template(
            PolicyTemplate::ModelOnly,
            Some(model_endpoint()),
            Vec::new(),
        )
        .expect("model-only template")
    }

    fn production_boundary() -> OperatorBoundary {
        OperatorBoundary::production()
    }

    fn read_only_policy() -> GuardPolicy {
        let rule = EgressRule {
            host: "api.docs.example.com".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            allowed_methods: vec!["GET".to_string()],
            allowed_paths: vec!["/v1/docs/".to_string()],
        };
        GuardPolicy::template(PolicyTemplate::ReadOnlyApi, None, vec![rule])
            .expect("read-only template")
    }

    #[test]
    fn compile_hashes_normalized_policy_deterministically() {
        let policy = model_only_policy();
        let boundary = production_boundary();
        let first = compile(&policy, &boundary).expect("compile");
        let second = compile(&policy.normalized(), &boundary).expect("compile normalized");
        assert_eq!(first.policy_hash(), second.policy_hash());
        assert_eq!(first.policy_hash().len(), 64);
        assert!(first.policy_hash().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_is_independent_of_semantic_ordering() {
        // Same semantic content, different listing order in every set-like list.
        let zone_a = DnsPolicy {
            allowed_zones: vec!["b.example.com".to_string(), "a.example.com".to_string()],
            allowed_record_types: vec!["AAAA".to_string(), "A".to_string()],
        };
        let zone_b = DnsPolicy {
            allowed_zones: vec!["a.example.com".to_string(), "b.example.com".to_string()],
            allowed_record_types: vec!["A".to_string(), "AAAA".to_string()],
        };
        let rule_a = EgressRule {
            host: "b.example.com".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            allowed_methods: vec!["POST".to_string(), "GET".to_string()],
            allowed_paths: vec!["/v2/".to_string(), "/v1/".to_string()],
        };
        let rule_b = EgressRule {
            host: "a.example.com".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_paths: vec!["/v1/".to_string(), "/v2/".to_string()],
        };
        let build = |zones: DnsPolicy, rules: Vec<EgressRule>, bindings: Vec<CredentialBinding>| {
            GuardPolicy {
                version: 1,
                network: NetworkPolicy {
                    dns: zones,
                    egress: rules,
                },
                model: None,
                credentials: bindings,
                limits: Limits::default(),
            }
        };
        let binding_a = CredentialBinding {
            name: "model-main".to_string(),
            host: "a.example.com".to_string(),
            port: 443,
            header: "authorization".to_string(),
        };
        let binding_b = CredentialBinding {
            name: "model-main".to_string(),
            ..binding_a.clone()
        };
        let one = build(
            zone_a,
            vec![rule_a.clone(), rule_b.clone()],
            vec![binding_a],
        );
        let other = build(zone_b, vec![rule_b, rule_a], vec![binding_b]);
        // Both are valid policies, so the comparison is between two legal
        // spellings of the same rule set rather than a valid and invalid one.
        one.validate().expect("first policy is valid");
        other.validate().expect("second policy is valid");
        let one_hash = one.hash().expect("hash");
        let other_hash = other.hash().expect("hash");
        assert_eq!(one_hash, other_hash);
    }

    #[test]
    fn blocks_private_link_local_and_loopback_destinations() {
        let compiled = compile(&model_only_policy(), &production_boundary()).expect("compile");
        for ip in [
            "10.1.2.3",
            "127.0.0.1",
            "169.254.169.254",
            "192.168.5.5",
            "172.20.0.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            let err = compiled
                .check_destination("api.example-model.com", ip.parse().expect("ip"))
                .expect_err("private destination must be denied");
            let text = err.to_string();
            assert!(text.contains("DENIED BOUNDARY VIOLATION"), "{ip}: {text}");
            assert!(text.contains("api.example-model.com"), "{ip}: {text}");
        }
    }

    #[test]
    fn allows_public_destination_and_ipv4_mapped_forms_are_normalized() {
        let compiled = compile(&model_only_policy(), &production_boundary()).expect("compile");
        compiled
            .check_destination(
                "api.example-model.com",
                "93.184.216.34".parse().expect("ip"),
            )
            .expect("public destination");
        let err = compiled
            .check_destination(
                "api.example-model.com",
                "::ffff:127.0.0.1".parse().expect("ip"),
            )
            .expect_err("mapped loopback must be denied");
        assert!(err.to_string().contains("127.0.0.1"));
    }

    #[test]
    fn protected_range_denies_even_with_test_mapping() {
        let mut boundary = production_boundary();
        boundary.protected_cidrs = vec!["127.0.0.1/32".parse().expect("cidr")];
        boundary.test_destinations.insert(
            "mock.model.test:80".to_string(),
            vec!["127.0.0.1".parse().expect("ip")],
        );
        let policy = GuardPolicy::template(
            PolicyTemplate::ModelOnly,
            Some(ModelEndpoint {
                host: "mock.model.test".to_string(),
                port: 80,
                scheme: crate::policy::MODEL_SCHEME_HTTP.to_string(),
                allowed_methods: vec!["POST".to_string()],
                allowed_paths: vec!["/v1/".to_string()],
                credential: "model-main".to_string(),
            }),
            Vec::new(),
        )
        .expect("policy");
        let err = compile(&policy, &boundary).expect_err("protected range must deny");
        assert!(err.to_string().contains("protected"));
    }

    #[test]
    fn operator_test_mapping_authorizes_local_mock_http_only() {
        let mut boundary = production_boundary();
        boundary.test_destinations.insert(
            "mock.model.test:80".to_string(),
            vec!["127.0.0.1".parse().expect("ip")],
        );
        let model = ModelEndpoint {
            host: "mock.model.test".to_string(),
            port: 80,
            scheme: crate::policy::MODEL_SCHEME_HTTP.to_string(),
            allowed_methods: vec!["POST".to_string()],
            allowed_paths: vec!["/v1/".to_string()],
            credential: "model-main".to_string(),
        };
        let policy = GuardPolicy::template(PolicyTemplate::ModelOnly, Some(model), Vec::new())
            .expect("policy");
        let compiled = compile(&policy, &boundary).expect("mock http permitted by test mapping");
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");
        compiled
            .check_destination("mock.model.test", ip)
            .expect("mock address authorized");
        assert!(compiled.allows_plain_http_upstream("mock.model.test", 80, ip));
        assert!(!compiled.allows_plain_http_upstream("mock.model.test", 8080, ip));
        assert!(!compiled.allows_plain_http_upstream("other.model.test", 80, ip));
    }

    #[test]
    fn plain_http_model_requires_explicit_test_mapping() {
        let mut model = model_endpoint();
        model.scheme = crate::policy::MODEL_SCHEME_HTTP.to_string();
        let policy = GuardPolicy::template(PolicyTemplate::ModelOnly, Some(model), Vec::new())
            .expect("policy");
        let err = compile(&policy, &production_boundary())
            .expect_err("plain http without test mapping must fail");
        assert!(err.to_string().contains("test destination"));
    }

    #[test]
    fn blocked_host_in_policy_is_a_counterexample() {
        let mut boundary = production_boundary();
        boundary.blocked_hosts = vec!["api.example-model.com".to_string()];
        let err = compile(&model_only_policy(), &boundary).expect_err("blocked host");
        let text = err.to_string();
        assert!(text.contains("DENIED BOUNDARY VIOLATION"), "{text}");
        assert!(text.contains("api.example-model.com"), "{text}");
        assert!(text.contains("network.egress[0]"), "{text}");
    }

    #[test]
    fn dns_scope_is_name_and_record_type_scoped() {
        let compiled = compile(&read_only_policy(), &production_boundary()).expect("compile");
        assert!(compiled.allows_dns("api.docs.example.com", 1));
        assert!(compiled.allows_dns("api.docs.example.com", 28));
        assert!(!compiled.allows_dns("evil.example.com", 1));
        assert!(!compiled.allows_dns("api.docs.example.com.evil.test", 1));
        // NS, TXT, NULL and ANY are never answered.
        for record_type in [2_u16, 16, 10, 255] {
            assert!(!compiled.allows_dns("api.docs.example.com", record_type));
        }
        // Port authorization is a separate, explicit check.
        assert!(compiled.allows_host("api.docs.example.com", 443));
        assert!(!compiled.allows_host("api.docs.example.com", 80));
        assert!(compiled.endpoint("api.docs.example.com", 443).is_some());
        assert!(compiled.endpoint("api.docs.example.com", 8443).is_none());
    }

    #[test]
    fn suffix_zone_is_explicit_only() {
        let policy = GuardPolicy::template(
            PolicyTemplate::ReadOnlyApi,
            None,
            vec![EgressRule {
                host: "api.example.com".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
                allowed_methods: vec!["GET".to_string()],
                allowed_paths: Vec::new(),
            }],
        )
        .expect("policy");
        let compiled = compile(&policy, &production_boundary()).expect("compile");
        assert!(compiled.allows_dns("api.example.com", 1));
        assert!(!compiled.allows_dns("secret.example.com", 1));
        assert!(!compiled.allows_dns("example.com", 1));
    }

    #[test]
    fn boundary_validation_rejects_bad_operators_input() {
        let mut boundary = production_boundary();
        boundary.blocked_hosts = vec!["bad host".to_string()];
        assert!(boundary.validate().is_err());

        let mut boundary = production_boundary();
        boundary.test_destinations.insert(
            "mock.model.test".to_string(),
            vec!["127.0.0.1".parse().expect("ip")],
        );
        assert!(boundary.validate().is_err(), "key must be host:port");

        let mut boundary = production_boundary();
        boundary.test_destinations.insert(
            "mock.model.test:80".to_string(),
            vec!["93.184.216.34".parse().expect("ip")],
        );
        assert!(
            boundary.validate().is_err(),
            "test mappings must be non-public"
        );

        let mut boundary = production_boundary();
        boundary.blocked_hosts = vec!["mock.model.test".to_string()];
        boundary.test_destinations.insert(
            "mock.model.test:80".to_string(),
            vec!["127.0.0.1".parse().expect("ip")],
        );
        assert!(
            boundary.validate().is_err(),
            "blocked host cannot be a test destination"
        );
    }

    #[test]
    fn boundary_serde_round_trips_and_rejects_unknown_fields() {
        let boundary = production_boundary();
        let text = serde_yaml_ng::to_string(&boundary).expect("serialize");
        let parsed: OperatorBoundary = serde_yaml_ng::from_str(&text).expect("deserialize");
        assert_eq!(parsed, boundary);
        let unknown = "blocked_cidrs: []\nunexpected: 1\n";
        assert!(serde_yaml_ng::from_str::<OperatorBoundary>(unknown).is_err());
    }

    #[test]
    fn compile_no_network_permits_nothing() {
        let compiled = compile_no_network(&production_boundary()).expect("compile");
        assert!(!compiled.allows_host("api.example-model.com", 443));
        assert!(!compiled.allows_dns("api.example-model.com", 1));
        assert!(compiled.model_endpoint().is_none());
        compiled.verify().expect("verify");
    }

    #[test]
    fn guard_config_selection_never_defaults_to_internet() {
        let config = GuardConfig::default();
        let policy = config.effective_policy().expect("effective");
        assert!(policy.network.egress.is_empty());
        assert!(policy.network.dns.allowed_zones.is_empty());
        assert!(policy.model.is_none());
    }

    #[test]
    fn shipped_boundaries_parse_and_enforce_as_documented() {
        let production: OperatorBoundary = serde_yaml_ng::from_str(include_str!(
            "../../../policies/guard/boundary.production.yaml"
        ))
        .expect("production boundary");
        assert!(production.test_destinations.is_empty());
        assert!(
            production
                .protected_cidrs
                .contains(&"169.254.169.254/32".parse().expect("cidr"))
        );
        let compiled = compile(&model_only_policy(), &production).expect("compile");
        for ip in ["169.254.169.254", "10.244.7.9", "192.0.0.5"] {
            let err = compiled
                .check_destination("api.example-model.com", ip.parse().expect("ip"))
                .expect_err("protected or blocked");
            assert!(
                err.to_string().contains("DENIED BOUNDARY VIOLATION"),
                "{ip}"
            );
        }

        let local: OperatorBoundary = serde_yaml_ng::from_str(include_str!(
            "../../../policies/guard/boundary.local-test.yaml"
        ))
        .expect("local boundary");
        let mock_policy = GuardPolicy::from_yaml(include_str!(
            "../../../policies/guard/model-only.local-mock.yaml"
        ))
        .expect("local mock policy");
        let mock = compile(&mock_policy, &local).expect("local mock compiles");
        // The shipped local boundary maps to the benchmarking range, not to
        // loopback: loopback is where a worker's own services live, and a
        // boundary able to authorize it could reach something real.
        assert!(mock.allows_plain_http_upstream(
            "mock.model.test",
            8080,
            "198.18.0.10".parse().unwrap()
        ));
        // The right address on the wrong port is still refused.
        assert!(!mock.allows_plain_http_upstream(
            "mock.web.test",
            8080,
            "198.18.0.11".parse().unwrap()
        ));
        // And the same mapping does not exist in production, where it is absent.
        assert!(!compiled.allows_plain_http_upstream(
            "mock.model.test",
            8080,
            "198.18.0.10".parse().unwrap()
        ));
        // Loopback is refused outright even in the local-test boundary.
        assert!(!mock.allows_plain_http_upstream(
            "mock.model.test",
            8080,
            "127.0.0.1".parse().unwrap()
        ));
    }

    /// The benchmark range is the one non-public range a local mock may use, and
    /// it was classified as public space for a while because the mask was
    /// written `0x18` rather than `0x12` - 18 and 19 are 0x12 and 0x13. Nothing
    /// else pins that, so the boundaries of the range are asserted here.
    #[test]
    fn the_benchmarking_range_is_the_only_one_a_mock_may_use() {
        for address in ["198.18.0.10", "198.19.255.254"] {
            assert!(
                is_non_public(&address.parse().expect("ip")),
                "{address} is inside 198.18.0.0/15 and must be usable by a local mock"
            );
        }
        // One address past the range, and one before it, are public space.
        for address in ["198.20.0.1", "198.17.255.254"] {
            assert!(
                !is_non_public(&address.parse().expect("ip")),
                "{address} is outside 198.18.0.0/15 and must stay public"
            );
        }
    }

    /// A mapping authorizes one exact host and address, not a range and not a
    /// neighbour. The mask fix above made this true; nothing asserted it.
    #[test]
    fn a_test_mapping_authorizes_exactly_its_own_address() {
        let local: OperatorBoundary = serde_yaml_ng::from_str(include_str!(
            "../../../policies/guard/boundary.local-test.yaml"
        ))
        .expect("local boundary");
        let mock_policy = GuardPolicy::from_yaml(include_str!(
            "../../../policies/guard/model-only.local-mock.yaml"
        ))
        .expect("local mock policy");
        let mock = compile(&mock_policy, &local).expect("local mock compiles");
        assert!(mock.allows_plain_http_upstream(
            "mock.model.test",
            8080,
            "198.18.0.10".parse().unwrap()
        ));
        // A neighbouring address in the same range is not covered.
        assert!(!mock.allows_plain_http_upstream(
            "mock.model.test",
            8080,
            "198.18.0.99".parse().unwrap()
        ));
        // Nor is loopback, which is where a worker's own services live.
        assert!(!mock.allows_plain_http_upstream(
            "mock.model.test",
            8080,
            "127.0.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn operator_protected_range_beats_test_mapping_in_shipped_boundary() {
        let mut local: OperatorBoundary = serde_yaml_ng::from_str(include_str!(
            "../../../policies/guard/boundary.local-test.yaml"
        ))
        .expect("local boundary");
        // The protected range has to be one the boundary actually maps, or the
        // test proves nothing: protecting an address no mapping mentions cannot
        // conflict with anything.
        local.protected_cidrs = vec!["198.18.0.10/32".parse().expect("cidr")];
        assert!(
            local.validate().is_err(),
            "a test mapping inside a protected range is refused"
        );
        local.protected_cidrs.clear();
        local.validate().expect("valid boundary");
    }

    #[test]
    fn verify_reports_a_counterexample_when_the_boundary_blocks_policy_hosts() {
        let mut boundary = production_boundary();
        boundary.blocked_hosts = vec!["api.example-model.com".to_string()];
        let text = compile(&model_only_policy(), &boundary)
            .expect_err("blocked model host")
            .to_string();
        assert!(text.contains("DENIED BOUNDARY VIOLATION"), "{text}");
        assert!(text.contains("api.example-model.com"), "{text}");
        assert!(text.contains("port=443"), "{text}");

        let mut boundary = production_boundary();
        boundary.blocked_hosts = vec!["api.docs.example.com".to_string()];
        let text = compile(&read_only_policy(), &boundary)
            .expect_err("blocked allowlist host")
            .to_string();
        assert!(text.contains("api.docs.example.com"), "{text}");
        assert!(text.contains("network.egress[0]"), "{text}");
    }

    #[test]
    fn query_forms_fold_case_and_trailing_root_dot() {
        let compiled = compile(&model_only_policy(), &production_boundary()).expect("compile");
        let public: IpAddr = "93.184.216.34".parse().expect("ip");
        for query in [
            "api.example-model.com",
            "API.Example-Model.COM",
            "api.example-model.com.",
            "API.EXAMPLE-MODEL.com.",
        ] {
            compiled
                .check_destination(query, public)
                .unwrap_or_else(|err| panic!("{query} must be usable: {err}"));
            assert!(compiled.allows_host(query, 443), "{query}");
            assert!(compiled.endpoint(query, 443).is_some(), "{query}");
        }

        // A blocked host must not be reachable through a differently cased or
        // trailing-dot query either.
        let strict = OperatorBoundary {
            blocked_hosts: vec!["api.example-model.com".to_string()],
            ..production_boundary()
        };
        let err = compile(&model_only_policy(), &strict).expect_err("blocked host");
        assert!(err.to_string().contains("DENIED BOUNDARY VIOLATION"));
    }

    #[test]
    fn test_destination_keys_are_parsed_strictly() {
        assert!(TestDestination::parse("mock.model.test:8080").is_ok());
        assert!(TestDestination::parse("mock.model.test").is_err());
        assert!(TestDestination::parse("mock.model.test:0").is_err());
        assert!(TestDestination::parse("mock.model.test:not-a-port").is_err());
        assert!(TestDestination::parse("*.model.test:80").is_err());
        assert!(TestDestination::parse("MOCK.model.test:80").is_err());
        let parsed = TestDestination::new("mock.model.test", 8080).expect("test destination");
        assert_eq!(parsed.host(), "mock.model.test");
        assert_eq!(parsed.port(), 8080);
        assert_eq!(parsed.to_string(), "mock.model.test:8080");
    }

    #[test]
    fn mapped_and_compatible_ipv6_forms_cannot_bypass_the_boundary() {
        let compiled = compile(&model_only_policy(), &production_boundary()).expect("compile");
        for ip in ["::ffff:10.0.0.5", "::ffff:169.254.169.254", "0.0.0.0", "::"] {
            assert!(
                compiled
                    .check_destination("api.example-model.com", ip.parse().expect("ip"))
                    .is_err(),
                "{ip} must be denied"
            );
        }
    }

    #[test]
    fn denied_networks_covers_defaults_operator_additions_and_protected() {
        let boundary = OperatorBoundary {
            blocked_cidrs: vec!["10.244.0.0/16".parse().expect("cidr")],
            protected_cidrs: vec!["169.254.169.254/32".parse().expect("cidr")],
            ..production_boundary()
        };
        boundary.validate().expect("valid boundary");
        let nets: Vec<IpNet> = boundary.denied_networks().copied().collect();
        assert_eq!(nets.len(), default_blocked_cidrs().len() + 2);
        for required in [
            "10.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "192.168.0.0/16",
            "fc00::/7",
            "fe80::/10",
            "10.244.0.0/16",
            "169.254.169.254/32",
        ] {
            let net: IpNet = required.parse().expect("cidr");
            assert!(nets.contains(&net), "{required} must be in denied_networks");
        }
        // Every advertised network really is denied for a policy host.
        let compiled = compile(&model_only_policy(), &boundary).expect("compile");
        for net in nets {
            for address in representative_addresses(&net) {
                assert!(
                    compiled
                        .check_destination("api.example-model.com", address)
                        .is_err(),
                    "{address} in {net} must be denied"
                );
            }
        }
    }

    #[test]
    fn test_destination_inside_operator_blocked_range_is_refused() {
        let mut boundary = production_boundary();
        boundary.blocked_cidrs = vec!["127.0.0.0/8".parse().expect("cidr")];
        boundary.test_destinations.insert(
            "mock.model.test:8080".to_string(),
            vec!["127.0.0.1".parse().expect("ip")],
        );
        let err = boundary
            .validate()
            .expect_err("contradictory boundary")
            .to_string();
        assert!(err.contains("blocked range"), "{err}");
    }
}
