//! Deterministic nftables rule text for exactly one Guard attachment.
//!
//! This module is deliberately standard-library only and depends on nothing
//! else in the crate: the text it produces is what `NftablesBackend` feeds to
//! `nft -f`, so the same text can be rendered, inspected and checked with
//! `nft -c` without pulling in the rest of Guard.
//!
//! Two invariants drive the whole design:
//!
//! * Guard only ever owns the two tables it creates for one attachment. The
//!   host's other tables, chains and policies are never referenced, so applying
//!   or removing a guest cannot change traffic that does not belong to it.
//! * Guest supplied values (interface name, identifiers) are validated against a
//!   closed character set before they are rendered, so they cannot terminate an
//!   nft expression and inject a second rule.

use std::net::Ipv4Addr;

/// nftables family holding the guest's IPv4 enforcement.
pub(crate) const FAMILY_V4: &str = "ip";
/// nftables family holding the guest's IPv6 enforcement.
pub(crate) const FAMILY_V6: &str = "ip6";
/// Every table Guard creates starts with this prefix and is followed by the
/// complete 32 character hexadecimal sandbox UUID.
pub(crate) const TABLE_PREFIX: &str = "aiec_guard_";
/// Linux stores interface names in a 16 byte field including the terminator.
pub(crate) const MAX_INTERFACE_LEN: usize = 15;
/// The per-IPv4-address counter for attempts to reach an operator blocked range.
pub(crate) const COUNTER_BLOCKED_RANGE: &str = "cnt_blocked_range";
/// The counter for guest traffic denied for any other reason.
pub(crate) const COUNTER_OTHER_DENIED: &str = "cnt_other_denied";
/// The counter for every IPv6 packet seen on the guest interface.
pub(crate) const COUNTER_IPV6: &str = "cnt_ipv6";
/// Chain priority for Guard's own base chains.
///
/// A guest packet is judged by Guard before any other base chain, and before
/// the ordinary filter hook, so no host rule can accept a guest packet first
/// and no connection-tracking rule can grandfather a flow that was opened
/// before a cut. A cut therefore takes effect for traffic that is already
/// established: the drop is unconditional and does not consult connection
/// state, so a stale or spoofed established entry cannot restore a path.
pub(crate) const CHAIN_PRIORITY: i32 = -10;
/// Destination-side forwarding drops run after every source-side Guard chain.
/// Equal priorities let a peer's table count another guest's blocked attempt,
/// hiding the attempt from the originating guest's watchdog.
const DESTINATION_PRIORITY: i32 = CHAIN_PRIORITY + 1;
/// The counter for permitted DNS traffic from the assigned guest source.
pub(crate) const COUNTER_DNS_PERMITTED: &str = "cnt_dns_permitted";
/// The counter for permitted model broker traffic from the assigned guest source.
pub(crate) const COUNTER_BROKER_PERMITTED: &str = "cnt_broker_permitted";
/// Upper bound on operator supplied blocked ranges rendered into one table. A
/// boundary larger than this is a configuration error, not a rule set.
pub(crate) const MAX_BLOCKED_RANGES: usize = 1024;
/// Upper bound on the generated text handed to `nft`.
pub(crate) const MAX_RULESET_BYTES: usize = 256 * 1024;

/// Transport protocol of a packet considered for a permit decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    Other,
}

/// The verdict a packet receives and the named counter that records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub permitted: bool,
    pub counter: &'static str,
}

/// An IPv4 range rendered into the ruleset and matched by the decision model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockedRange {
    pub(crate) text: String,
    network: u32,
    mask: u32,
}

impl BlockedRange {
    /// Parses a rendered range.
    ///
    /// Both `a.b.c.d/len` and a bare `a.b.c.d` are accepted, the latter as a
    /// single address, so a caller holding a plain address cannot smuggle text
    /// into the ruleset by leaving off a prefix.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, prefix),
            None => (text, "32"),
        };
        let mut network = 0u32;
        let mut octets = 0usize;
        for part in address.split('.') {
            if octets == 4 {
                return Err(format!("blocked range {text:?} has more than four octets"));
            }
            let value: u8 = part
                .parse()
                .map_err(|_| format!("blocked range {text:?} has a non numeric octet"))?;
            if part.len() > 3 {
                return Err(format!("blocked range {text:?} has an oversized octet"));
            }
            network = (network << 8) | u32::from(value);
            octets += 1;
        }
        if octets != 4 {
            return Err(format!("blocked range {text:?} is not a dotted quad"));
        }
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("blocked range {text:?} has a non numeric prefix"))?;
        if prefix > 32 {
            return Err(format!("blocked range {text:?} has a prefix above 32"));
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        // Canonical text: a bare address and its /32 spelling are the same
        // range, so they must render as the same rule rather than as two rules
        // that disagree about equality.
        let canonical = Ipv4Addr::from(network & mask);
        Ok(Self {
            text: format!("{canonical}/{prefix}"),
            network: network & mask,
            mask,
        })
    }

    pub(crate) fn contains(&self, address: Ipv4Addr) -> bool {
        let value = u32::from(address);
        value & self.mask == self.network
    }
}

/// Inputs of one enforcement ruleset, already reduced to what nft can render.
pub(crate) struct RuleParams {
    /// Complete 32 character hexadecimal sandbox UUID.
    pub(crate) sandbox: String,
    pub(crate) interface: String,
    pub(crate) guest_ip: Ipv4Addr,
    pub(crate) gateway_ip: Ipv4Addr,
    pub(crate) dns_port: u16,
    pub(crate) broker_port: u16,
    /// Whether the compiled policy permits the gateway's DNS listener.
    pub(crate) permits_dns: bool,
    /// Whether the compiled policy permits the gateway's model broker.
    pub(crate) permits_broker: bool,
    /// Whether this generation drops everything immediately.
    pub(crate) cut: bool,
    pub(crate) blocked_ipv4: Vec<String>,
}

/// The single source of truth for what one attachment is allowed to do, and for
/// the nftables text that enforces exactly that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuleModel {
    pub(crate) table: String,
    pub(crate) interface: String,
    pub(crate) guest_ip: Ipv4Addr,
    pub(crate) gateway_ip: Ipv4Addr,
    pub(crate) dns_port: u16,
    pub(crate) broker_port: u16,
    pub(crate) permits_dns: bool,
    pub(crate) permits_broker: bool,
    pub(crate) cut: bool,
    pub(crate) blocked_ipv4: Vec<BlockedRange>,
}

/// Builds the Guard owned table name for a sandbox.
///
/// The name carries the complete UUID rather than a prefix, so two sandboxes
/// created in the same millisecond, or a sandbox whose identifier shares a
/// prefix with another's, can never be given the same table.
pub(crate) fn table_name(sandbox: &str) -> String {
    format!("{TABLE_PREFIX}{sandbox}")
}

impl RuleModel {
    pub(crate) fn new(params: RuleParams) -> Result<Self, String> {
        if params.sandbox.len() != 32 || !params.sandbox.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("sandbox identifier is not a complete hexadecimal UUID".to_string());
        }
        validate_interface(&params.interface)?;
        if params.guest_ip == params.gateway_ip {
            return Err("guest and gateway addresses are identical".to_string());
        }
        if params.guest_ip.is_unspecified() || params.gateway_ip.is_unspecified() {
            return Err("guest and gateway addresses must not be unspecified".to_string());
        }
        if params.dns_port == 0 || params.broker_port == 0 {
            return Err("gateway ports must not be zero".to_string());
        }
        if params.dns_port == params.broker_port {
            return Err("the DNS and broker listeners must not share a port".to_string());
        }
        if params.blocked_ipv4.len() > MAX_BLOCKED_RANGES {
            return Err(format!(
                "operator boundary holds {} IPv4 ranges, the limit is {MAX_BLOCKED_RANGES}",
                params.blocked_ipv4.len()
            ));
        }
        let blocked_ipv4 = params
            .blocked_ipv4
            .iter()
            .map(|text| BlockedRange::parse(text))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            table: table_name(&params.sandbox),
            interface: params.interface,
            guest_ip: params.guest_ip,
            gateway_ip: params.gateway_ip,
            dns_port: params.dns_port,
            broker_port: params.broker_port,
            permits_dns: params.permits_dns,
            permits_broker: params.permits_broker,
            cut: params.cut,
            blocked_ipv4,
        })
    }

    /// The verdict and named counter for one guest packet, in the same order
    /// the generated rules apply them.
    pub(crate) fn verdict(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        transport: Transport,
        port: u16,
    ) -> Verdict {
        if self.permits(source, destination, transport, port) {
            let counter = if port == self.broker_port {
                COUNTER_BROKER_PERMITTED
            } else {
                COUNTER_DNS_PERMITTED
            };
            return Verdict {
                permitted: true,
                counter,
            };
        }
        let blocked = self
            .blocked_ipv4
            .iter()
            .any(|range| range.contains(destination));
        Verdict {
            permitted: false,
            counter: if blocked {
                COUNTER_BLOCKED_RANGE
            } else {
                COUNTER_OTHER_DENIED
            },
        }
    }

    /// Whether the ruleset permits this packet to reach the host. Forwarded
    /// traffic is never permitted, and neither is any traffic once cut.
    pub(crate) fn permits(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        transport: Transport,
        port: u16,
    ) -> bool {
        if self.cut {
            return false;
        }
        if source != self.guest_ip || destination != self.gateway_ip {
            return false;
        }
        match transport {
            Transport::Tcp => {
                (self.permits_dns && port == self.dns_port)
                    || (self.permits_broker && port == self.broker_port)
            }
            Transport::Udp => self.permits_dns && port == self.dns_port,
            Transport::Other => false,
        }
    }

    /// IPv6 is never permitted: one unconditional drop covers every route,
    /// including link-local neighbours and established flows.
    pub(crate) fn permits_ipv6(&self) -> bool {
        false
    }

    /// Renders the complete `nft -f` batch for this attachment.
    ///
    /// The batch only creates; it assumes no table of this name exists. Use
    /// [`RuleModel::render_replace`] to install over an existing generation.
    pub(crate) fn render(&self) -> Result<String, String> {
        let mut lines: Vec<String> = Vec::with_capacity(32 + self.blocked_ipv4.len() * 2);
        self.render_ipv4(&mut lines);
        self.render_ipv6(&mut lines);
        finish(lines)
    }

    /// Renders the batch that makes this model the attachment's only
    /// generation, whether or not a previous generation is installed.
    ///
    /// `add table` on an existing table and `flush table` on a table with rules
    /// are both accepted by nft, and `flush table` keeps the table, its chains
    /// and its named counters while removing every rule. The batch is therefore
    /// idempotent as a whole: applying it twice leaves the same rules and the
    /// same counters, and applying it over a cut or a previous policy fully
    /// replaces them within one transaction. Keeping the counters is what lets a
    /// watchdog read one cumulative count per attachment across generations.
    pub(crate) fn render_replace(&self) -> Result<String, String> {
        let mut lines: Vec<String> = Vec::with_capacity(34 + self.blocked_ipv4.len() * 2);
        lines.push(format!("add table {FAMILY_V4} {}", self.table));
        lines.push(format!("flush table {FAMILY_V4} {}", self.table));
        lines.push(format!("add table {FAMILY_V6} {}", self.table));
        lines.push(format!("flush table {FAMILY_V6} {}", self.table));
        self.render_ipv4(&mut lines);
        self.render_ipv6(&mut lines);
        finish(lines)
    }

    fn render_ipv4(&self, lines: &mut Vec<String>) {
        let table = &self.table;
        let iface = &self.interface;
        lines.push(format!(
            "# AIec Guard: sandbox {} on {iface}, IPv4",
            self.table
        ));
        lines.push(format!("add table {FAMILY_V4} {table}"));
        for counter in [
            COUNTER_BLOCKED_RANGE,
            COUNTER_OTHER_DENIED,
            COUNTER_DNS_PERMITTED,
            COUNTER_BROKER_PERMITTED,
        ] {
            lines.push(format!("add counter {FAMILY_V4} {table} {counter}"));
        }
        lines.push(format!(
            "add chain {FAMILY_V4} {table} input {{ type filter hook input priority {CHAIN_PRIORITY}; policy accept; }}"
        ));
        lines.push(format!(
            "add chain {FAMILY_V4} {table} forward {{ type filter hook forward priority {CHAIN_PRIORITY}; policy accept; }}"
        ));
        lines.push(format!(
            "add chain {FAMILY_V4} {table} forward_to_guest {{ type filter hook forward priority {DESTINATION_PRIORITY}; policy accept; }}"
        ));

        // Permitted flows first: the gateway address is a host address and is
        // frequently inside an operator blocked range, and the gateway is the
        // one destination the guest is meant to reach. Every permit names the
        // assigned source, the gateway destination, the protocol and the port,
        // so a guest cannot borrow the permit from another sandbox, a sibling
        // port, a raw socket or a different destination.
        if self.permits_dns && !self.cut {
            lines.push(format!(
                "add rule {FAMILY_V4} {table} input iifname \"{iface}\" ip saddr {guest} ip daddr {gateway} tcp dport {port} counter name \"{COUNTER_DNS_PERMITTED}\" accept",
                guest = self.guest_ip,
                gateway = self.gateway_ip,
                port = self.dns_port
            ));
            lines.push(format!(
                "add rule {FAMILY_V4} {table} input iifname \"{iface}\" ip saddr {guest} ip daddr {gateway} udp dport {port} counter name \"{COUNTER_DNS_PERMITTED}\" accept",
                guest = self.guest_ip,
                gateway = self.gateway_ip,
                port = self.dns_port
            ));
        }
        if self.permits_broker && !self.cut {
            lines.push(format!(
                "add rule {FAMILY_V4} {table} input iifname \"{iface}\" ip saddr {guest} ip daddr {gateway} tcp dport {port} counter name \"{COUNTER_BROKER_PERMITTED}\" accept",
                guest = self.guest_ip,
                gateway = self.gateway_ip,
                port = self.broker_port
            ));
        }

        // Blocked ranges are counted and dropped whatever source claims to send
        // them, so a spoofed source cannot hide an attempt from the operator.
        for range in &self.blocked_ipv4 {
            lines.push(format!(
                "add rule {FAMILY_V4} {table} input iifname \"{iface}\" ip daddr {cidr} counter name \"{COUNTER_BLOCKED_RANGE}\" drop",
                cidr = range.text
            ));
            lines.push(format!(
                "add rule {FAMILY_V4} {table} forward iifname \"{iface}\" ip daddr {cidr} counter name \"{COUNTER_BLOCKED_RANGE}\" drop",
                cidr = range.text
            ));
        }

        // Anti source spoofing: only the address the operator assigned to this
        // attachment is ever accepted, whatever the packet claims.
        lines.push(format!(
            "add rule {FAMILY_V4} {table} input iifname \"{iface}\" ip saddr != {guest} counter name \"{COUNTER_OTHER_DENIED}\" drop",
            guest = self.guest_ip
        ));
        // Everything else the guest sends to the host, established flows
        // included, is denied. No rule accepts on connection state, so an
        // established flow to a destination that is not permitted stays denied.
        lines.push(format!(
            "add rule {FAMILY_V4} {table} input iifname \"{iface}\" ip saddr {guest} counter name \"{COUNTER_OTHER_DENIED}\" drop",
            guest = self.guest_ip
        ));
        // The guest has exactly one path out, which terminates in the gateway on
        // the host. It may not be used as a router in either direction.
        lines.push(format!(
            "add rule {FAMILY_V4} {table} forward iifname \"{iface}\" counter name \"{COUNTER_OTHER_DENIED}\" drop"
        ));
        lines.push(format!(
            "add rule {FAMILY_V4} {table} forward_to_guest oifname \"{iface}\" counter name \"{COUNTER_OTHER_DENIED}\" drop"
        ));
    }

    fn render_ipv6(&self, lines: &mut Vec<String>) {
        let table = &self.table;
        let iface = &self.interface;
        lines.push(format!(
            "# AIec Guard: sandbox {} on {iface}, IPv6",
            self.table
        ));
        lines.push(format!("add table {FAMILY_V6} {table}"));
        lines.push(format!("add counter {FAMILY_V6} {table} {COUNTER_IPV6}"));
        lines.push(format!(
            "add chain {FAMILY_V6} {table} input {{ type filter hook input priority {CHAIN_PRIORITY}; policy accept; }}"
        ));
        lines.push(format!(
            "add chain {FAMILY_V6} {table} forward {{ type filter hook forward priority {CHAIN_PRIORITY}; policy accept; }}"
        ));
        lines.push(format!(
            "add chain {FAMILY_V6} {table} forward_to_guest {{ type filter hook forward priority {DESTINATION_PRIORITY}; policy accept; }}"
        ));
        lines.push(format!(
            "add rule {FAMILY_V6} {table} input iifname \"{iface}\" counter name \"{COUNTER_IPV6}\" drop"
        ));
        lines.push(format!(
            "add rule {FAMILY_V6} {table} forward iifname \"{iface}\" counter name \"{COUNTER_IPV6}\" drop"
        ));
        lines.push(format!(
            "add rule {FAMILY_V6} {table} forward_to_guest oifname \"{iface}\" counter name \"{COUNTER_IPV6}\" drop"
        ));
    }
}

/// Joins rendered lines and refuses to hand nft an oversized batch.
fn finish(lines: Vec<String>) -> Result<String, String> {
    let mut script = lines.join("\n");
    script.push('\n');
    if script.len() > MAX_RULESET_BYTES {
        return Err(format!(
            "the generated ruleset is {} bytes, the limit is {MAX_RULESET_BYTES}",
            script.len()
        ));
    }
    Ok(script)
}

/// Interface names arrive from the host network backend, which is itself
/// influenced by sandbox state. Only the characters Linux permits in an
/// interface name are accepted, so no guest identifier can close a quoted nft
/// expression and append a rule of its own.
fn validate_interface(interface: &str) -> Result<(), String> {
    let mut characters = interface.chars();
    let Some(first) = characters.next() else {
        return Err("the guest interface name is empty".to_string());
    };
    if interface.len() > MAX_INTERFACE_LEN {
        return Err(format!(
            "the guest interface name is {} bytes, the limit is {MAX_INTERFACE_LEN}",
            interface.len()
        ));
    }
    if !first.is_ascii_alphanumeric()
        || !characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(
            "the guest interface name holds characters that are not valid in an nft expression"
                .to_string(),
        );
    }
    Ok(())
}
