//! Linux TAP and nftables network backend.

use aiec_core::{
    CoreError, Sandbox, SandboxId,
    network::{NetworkAttachment, NetworkBackend, NetworkCapabilities, NetworkPolicy},
};
use async_trait::async_trait;
use std::{collections::HashSet, process::Stdio};
use tokio::{io::AsyncWriteExt, process::Command};

use std::net::Ipv4Addr;

mod guard;
pub use guard::GuardNetworkManager;

/// Address space the per-sandbox point-to-point subnets are carved from.
const TAP_BASE: &str = "172.30";
/// Prefix length of a per-sandbox link.
const TAP_PREFIX: u8 = 30;
/// How many independent links the address space holds.
///
/// 16 third octets of 64 aligned /30s each. The count matters less than the
/// alignment: a /30 whose network address is not a multiple of four is not a
/// network, and `ip` and nftables both mask it down to the nearest one that is.
const TAP_SLOTS: u32 = 1024;
/// Addresses of the point-to-point link between the host TAP and the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TapAddressPlan {
    /// Network address in CIDR form, such as `172.30.8.0/30`.
    network: String,
    /// Host-side TAP address, such as `172.30.8.1`.
    host: String,
    /// Address configured inside the guest, such as `172.30.8.2`.
    guest: String,
}

/// The /30 belonging to one slot of the pool.
///
/// The /30 is aligned to four addresses, so the declared network is the network
/// the kernel and nftables actually use, and the host always owns `.1` of it
/// while the guest owns `.2`. No slot can be a network or broadcast address, or
/// contain an address outside its own subnet.
fn tap_address_plan_slot(slot: u32) -> TapAddressPlan {
    // Wraps rather than running off the end, so an index one past the pool
    // describes the same link as index zero. The pool is what the host has
    // addresses for, so anything beyond it is the same slot.
    let slot = slot % TAP_SLOTS;
    let third = 8 + (slot / 64) as u8;
    let fourth = (slot % 64) * 4;
    TapAddressPlan {
        network: format!("{TAP_BASE}.{third}.{fourth}/{TAP_PREFIX}"),
        host: format!("{TAP_BASE}.{third}.{}", fourth + 1),
        guest: format!("{TAP_BASE}.{third}.{}", fourth + 2),
    }
}

/// Picks a plan for this sandbox, skipping any slot already in use.
///
/// Deriving the /30 purely from the identifier is what makes a plan stable and
/// also what made it collide: two identifiers sharing a slot mod `TAP_SLOTS`
/// were handed one /30, so both guests configured the same address and the
/// kernel held two identical connected routes whose selection depends on
/// insertion order. Random identifiers make that a birthday collision rather
/// than a rare event — about 87% across 64 concurrent sandboxes — so it was a
/// property of the allocator being stateless, not of the pool being too small.
///
/// The probe starts at the sandbox's own slot and walks the whole pool, so an
/// exhausted pool is refused rather than served a duplicate. `occupied` is
/// given the plan under consideration and answers whether it is already live;
/// the caller supplies it from the host's own address inventory.
fn choose_tap_plan(
    id: SandboxId,
    occupied: impl Fn(TapAddressPlan) -> bool,
) -> Result<TapAddressPlan, CoreError> {
    let start = (id.as_u128() % u128::from(TAP_SLOTS)) as u32;
    (0..TAP_SLOTS)
        .map(|offset| tap_address_plan_slot((start + offset) % TAP_SLOTS))
        .find(|plan| !occupied(plan.clone()))
        .ok_or_else(|| {
            CoreError::LimitExceeded(format!(
                "TAP address capacity: all {TAP_SLOTS} /30s in {TAP_BASE}.0.0/16 are in use"
            ))
        })
}

/// Creates isolated TAP attachments and applies per-sandbox nftables policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxNetworkManager;

/// Serializes the read-occupancy-then-assign window inside this process.
///
/// Probing the host inventory and running `ip addr add` are separate steps, so
/// two placements that overlap exactly there — which is the common case when a
/// batch is admitted at once — can both find a slot free and both take it. The
/// kernel does not reject the second: a second interface may carry an address
/// that is already in use, so the duplicate becomes two live sandboxes on one
/// subnet with no error anywhere. Holding this across the probe and the
/// assignment closes that window for concurrent placements in one worker.
///
/// It does not close it across processes, and a deployment with two workers on
/// one host still relies on the inventory probe rather than on an atomic
/// reservation. That is recorded rather than claimed fixed.
static TAP_RESERVATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

impl LinuxNetworkManager {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NetworkBackend for LinuxNetworkManager {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            restricted_allowlists: false,
            dns_controls: false,
            bandwidth_limits: false,
        }
    }

    async fn prepare(
        &self,
        sandbox: &Sandbox,
        policy: &NetworkPolicy,
    ) -> Result<NetworkAttachment, CoreError> {
        if !policy.is_enabled() {
            return Ok(NetworkAttachment::default());
        }
        if !policy.allowed_hosts().is_empty() {
            return Err(CoreError::Unsupported(
                "restricted host allowlists require a DNS/IP policy plugin; refusing ambiguous nftables enforcement".into(),
            ));
        }

        // Occupancy comes from the host's own address inventory rather than from
        // a record this process keeps, because the inventory is what the kernel
        // will actually reject: a duplicate address fails at `ip addr add`, and
        // a link whose guest half matches another sandbox's is never reported
        // as an error at all — it silently becomes two sandboxes on one subnet.
        // Held until the address is actually on the link, so the probe below and
        // the `ip addr add` after it cannot interleave with another placement.
        let _reservation = TAP_RESERVATION.lock().await;
        let assigned = assigned_ipv4().await?;
        let plan = choose_tap_plan(sandbox.id, |candidate| {
            [candidate.host, candidate.guest].iter().any(|address| {
                address
                    .parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|ip| assigned.contains(&ip))
            })
        })?;
        let suffix = &sandbox.id.to_string()[..12];
        let tap = format!("af{suffix}");
        let table = format!("aiec_{suffix}");
        let device = NetworkAttachment {
            resource: tap.clone(),
            addresses: vec![plan.host.clone()],
            guest_addresses: vec![plan.guest.clone()],
        };

        let commands: Vec<Vec<String>> = vec![
            vec![
                "tuntap".into(),
                "add".into(),
                "dev".into(),
                tap.clone(),
                "mode".into(),
                "tap".into(),
            ],
            vec![
                "addr".into(),
                "add".into(),
                format!("{}/{}", plan.host, TAP_PREFIX),
                "dev".into(),
                tap.clone(),
            ],
            vec![
                "link".into(),
                "set".into(),
                "dev".into(),
                tap.clone(),
                "up".into(),
            ],
        ];
        for args in commands {
            if let Err(error) = run_ip(&args).await {
                let _ = self.release(sandbox, &device).await;
                return Err(error);
            }
        }
        // The address is assigned and the link is up, so the reservation is
        // spent and the next placement may probe again.
        drop(_reservation);

        if let Err(error) = enable_ip_forwarding().await {
            let _ = self.release(sandbox, &device).await;
            return Err(error);
        }

        let mut child = match Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                let _ = self.release(sandbox, &device).await;
                return Err(error.into());
            }
        };
        if let Some(stdin) = child.stdin.as_mut()
            && let Err(error) = stdin
                .write_all(firewall_rules(&table, &tap, &plan.network).as_bytes())
                .await
        {
            drop(child.stdin.take());
            let _ = child.wait().await;
            let _ = self.release(sandbox, &device).await;
            return Err(error.into());
        }
        drop(child.stdin.take());
        let output = match child.wait_with_output().await {
            Ok(output) => output,
            Err(error) => {
                let _ = self.release(sandbox, &device).await;
                return Err(error.into());
            }
        };
        if !output.status.success() {
            let _ = self.release(sandbox, &device).await;
            return Err(CoreError::Io(std::io::Error::other(format!(
                "nft isolation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))));
        }
        Ok(device)
    }

    async fn release(
        &self,
        sandbox: &Sandbox,
        attachment: &NetworkAttachment,
    ) -> Result<(), CoreError> {
        if attachment.resource.is_empty() {
            return Ok(());
        }
        let suffix = &sandbox.id.to_string()[..12];
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &format!("aiec_{suffix}")])
            .status()
            .await;
        let _ = Command::new("ip")
            .args(["link", "del", &attachment.resource])
            .status()
            .await;
        Ok(())
    }
}

/// Every IPv4 address currently assigned on this host.
///
/// Read from the kernel rather than from a record either backend keeps, because
/// the kernel is what decides whether an address is available and what a
/// collision with another link actually does.
async fn assigned_ipv4() -> Result<HashSet<Ipv4Addr>, CoreError> {
    let output = Command::new("ip")
        .args(["-j", "-4", "addr", "show"])
        .output()
        .await
        .map_err(|error| {
            CoreError::Unavailable(format!("address inventory unavailable: {error}"))
        })?;
    if !output.status.success() {
        return Err(CoreError::Unavailable(
            "address inventory unavailable: ip -j -4 addr show failed".into(),
        ));
    }
    parse_assigned_ipv4(&output.stdout)
}

/// Pulls every assigned address out of `ip -j -4 addr show` output.
///
/// Interfaces without an IPv4 address carry no `addr_info`, and an address can
/// be IPv6-only or malformed, so anything unparseable is skipped rather than
/// failing the whole read — an inventory that is missing one address must not
/// stop a sandbox from being placed, or it would be a denial of service rather
/// than a safety check.
fn parse_assigned_ipv4(stdout: &[u8]) -> Result<HashSet<Ipv4Addr>, CoreError> {
    let values: Vec<serde_json::Value> = serde_json::from_slice(stdout)
        .map_err(|_| CoreError::Unavailable("invalid ip address inventory".into()))?;
    let mut assigned = HashSet::new();
    for interface in values {
        let Some(addresses) = interface["addr_info"].as_array() else {
            continue;
        };
        for address in addresses {
            if let Some(ip) = address["local"]
                .as_str()
                .and_then(|value| value.parse().ok())
            {
                assigned.insert(ip);
            }
        }
    }
    Ok(assigned)
}

async fn run_ip(args: &[String]) -> Result<(), CoreError> {
    run_tool("ip", args, "TAP setup failed").await
}

/// Enables host IPv4 routing so traffic from the guest can leave the host.
async fn enable_ip_forwarding() -> Result<(), CoreError> {
    run_tool(
        "sysctl",
        &["-w".into(), "net.ipv4.ip_forward=1".into()],
        "enabling net.ipv4.ip_forward failed",
    )
    .await
}

async fn run_tool(program: &str, args: &[String], failure: &str) -> Result<(), CoreError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|error| {
            CoreError::Io(std::io::Error::other(format!(
                "{program} could not be executed: {error}"
            )))
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(CoreError::Io(std::io::Error::other(format!(
            "{failure}: {}",
            String::from_utf8_lossy(&output.stderr)
        ))))
    }
}

/// Builds the per-sandbox nftables ruleset.
///
/// The guest subnet is private space, so it is accepted explicitly before the
/// wide private-range drops that protect host services, and masqueraded on the
/// way out so the guest never needs an address the internet can route back to.
fn firewall_rules(table: &str, tap: &str, subnet: &str) -> String {
    format!(
        "add table inet {table}; \
add chain inet {table} input {{ type filter hook input priority -10; policy accept; }}; \
add chain inet {table} forward {{ type filter hook forward priority -10; policy accept; }}; \
add chain inet {table} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}; \
add rule inet {table} input iifname \"{tap}\" ip saddr {subnet} ip daddr {subnet} accept; \
add rule inet {table} input iifname \"{tap}\" ip daddr 169.254.169.254 drop; \
add rule inet {table} input iifname \"{tap}\" ip daddr 10.0.0.0/8 drop; \
add rule inet {table} input iifname \"{tap}\" ip daddr 172.16.0.0/12 drop; \
add rule inet {table} input iifname \"{tap}\" ip daddr 192.168.0.0/16 drop; \
add rule inet {table} input iifname \"{tap}\" ip daddr 127.0.0.0/8 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 169.254.169.254 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 10.0.0.0/8 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 172.16.0.0/12 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 192.168.0.0/16 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 127.0.0.0/8 drop; \
add rule inet {table} forward iifname \"{tap}\" ip saddr {subnet} accept; \
add rule inet {table} forward oifname \"{tap}\" ip daddr {subnet} ct state established,related accept; \
add rule inet {table} postrouting oifname != \"{tap}\" ip saddr {subnet} masquerade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> Sandbox {
        Sandbox {
            id: uuid::Uuid::now_v7(),
            tenant_id: uuid::Uuid::now_v7(),
            node_id: None,
            image_id: "test".into(),
            state: aiec_core::SandboxState::Creating,
            runtime: aiec_core::RuntimeKind::Firecracker,
            cpu: 1,
            memory_mb: 128,
            disk_mb: 512,
            timeout_seconds: 60,
            network: NetworkPolicy::Internet,
            environment: Default::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            runtime_path: None,
        }
    }

    #[test]
    fn firewall_is_scoped_to_tap() {
        let rules = firewall_rules("aiec_0123456789ab", "af0123456789ab", "172.30.8.0/30");
        assert!(rules.contains("hook input"));
        assert!(rules.contains("hook forward"));
        assert!(!rules.contains("hook output"));
        for destination in [
            "169.254.169.254",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
        ] {
            assert!(rules.contains(destination));
        }
    }

    #[test]
    fn subnet_allocation_is_always_a_valid_point_to_point_link() {
        fn assert_valid(plan: &TapAddressPlan) {
            let (address, prefix) = plan.network.rsplit_once('/').expect("cidr suffix");
            assert_eq!(prefix, TAP_PREFIX.to_string());
            let mut octets: Vec<u8> = address
                .split('.')
                .map(|part| part.parse().expect("numeric octet"))
                .collect();
            assert_eq!(octets.len(), 4, "a dotted quad");
            assert_eq!(octets[0], 172, "{address} is outside the reserved range");
            assert!(
                (8..=23).contains(&octets[2]),
                "{address} is outside the reserved range"
            );
            // Aligned: the last octet of a /30 network address is a multiple of
            // four, and `.1` and `.2` of that block are the two usable hosts.
            let block = octets.pop().expect("fourth octet");
            assert_eq!(block % 4, 0, "{address} is not aligned to a /30");
            let stem = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
            assert_eq!(address, format!("{stem}.{block}").as_str());
            assert_eq!(plan.host, format!("{stem}.{}", block + 1).as_str());
            assert_eq!(plan.guest, format!("{stem}.{}", block + 2).as_str());
        }

        // Every slot in the address space maps to a distinct subnet, and each
        // sandbox ends up with a usable host and guest address on its own /30.
        let mut seen = std::collections::HashSet::new();
        for index in 0..u128::from(TAP_SLOTS) {
            let plan = tap_address_plan_slot(index as u32);
            assert_valid(&plan);
            assert!(seen.insert(plan.network.clone()));
        }
        assert_eq!(seen.len(), TAP_SLOTS as usize, "the pool is fully used");
        // Two identifiers that differ only in the low bits have to land on
        // different links, because that is exactly the case an unaligned plan
        // collapses.
        for index in 1..u128::from(TAP_SLOTS) {
            let a = tap_address_plan_slot((index - 1) as u32);
            let b = tap_address_plan_slot(index as u32);
            assert_ne!(a.network, b.network);
            assert_ne!(a.host, b.host);
        }
        // And the pool wraps rather than running off the end of the address
        // space, so a sandbox beyond the last slot still gets a real link.
        assert_valid(&tap_address_plan_slot(TAP_SLOTS));
        for _ in 0..256 {
            assert_valid(&tap_address_plan_slot(
                (uuid::Uuid::now_v7().as_u128() % u128::from(TAP_SLOTS)) as u32,
            ));
        }
    }

    /// The declared network has to BE a network address, and it has to be the
    /// one the host and guest actually end up on.
    ///
    /// The old plan took the third octet from the identifier and wrote it into
    /// `/30` unaligned, so `172.30.9.0/30` was handed to `ip` and to nftables.
    /// Both mask it to `172.30.8.0/30`, which meant a sandbox with third octet 9
    /// and one with third octet 8 were given the same subnet and the same host
    /// address on two different links, while the rules named a network that
    /// does not exist. The old distinctness check compared the unnormalised
    /// strings, so it passed on values that collide.
    #[test]
    fn every_subnet_is_aligned_and_two_sandboxes_never_share_one() {
        /// The address `network` masks to at its prefix length.
        fn masked(network: &str) -> String {
            let (address, prefix) = network.split_once('/').expect("cidr suffix");
            let prefix: u32 = prefix.parse().expect("prefix length");
            let octets: Vec<u32> = address
                .split('.')
                .map(|part| part.parse().expect("numeric octet"))
                .collect();
            let bits = 32 - prefix;
            let value = octets.iter().fold(0u32, |acc, octet| (acc << 8) | octet);
            let masked = if bits >= 32 {
                value
            } else {
                value & (!0u32 << bits)
            };
            format!(
                "{}.{}.{}.{}/{prefix}",
                (masked >> 24) & 0xff,
                (masked >> 16) & 0xff,
                (masked >> 8) & 0xff,
                masked & 0xff
            )
        }

        let mut seen = std::collections::HashSet::new();
        for index in 0..u128::from(TAP_SLOTS) {
            let plan = tap_address_plan_slot(index as u32);
            assert_eq!(
                masked(&plan.network),
                plan.network,
                "{} is not a /{TAP_PREFIX} network address",
                plan.network
            );
            // The host and the guest sit either side of the link, inside the
            // subnet they are told about, and neither is the network or the
            // broadcast address.
            let block = plan.network.split_once('/').expect("cidr suffix").0;
            let prefix = format!("{}.", block.rsplit_once('.').expect("dotted quad").0);
            for address in [&plan.host, &plan.guest] {
                assert!(
                    address.starts_with(&prefix),
                    "{address} is not inside {}",
                    plan.network
                );
            }
            assert!(
                seen.insert(plan.network.clone()),
                "two ids share {}",
                plan.network
            );
        }
        // The pool wraps, so two identifiers more than a pool apart can share a
        // subnet. That is only safe while they are not live at the same time,
        // which is what the pool size buys: 1024 links against a cluster that
        // runs a few dozen sandboxes at once.
        assert_eq!(
            tap_address_plan_slot(0).network,
            tap_address_plan_slot(TAP_SLOTS).network,
            "the pool wraps rather than running out of addresses"
        );
    }

    #[test]
    fn identical_sandbox_id_maps_to_identical_subnet() {
        let id = uuid::Uuid::now_v7();
        assert_eq!(
            choose_tap_plan(id, |_| false).expect("a free slot"),
            choose_tap_plan(id, |_| false).expect("a free slot"),
            "the same identifier must resolve to the same link"
        );
    }

    /// Two *concurrently live* sandboxes must not be handed one /30.
    ///
    /// `tap_address_plan` is a pure modulo over 1024 slots, so it collides on
    /// the birthday bound, not on the wrap: with 64 concurrent sandboxes the
    /// chance that some pair shares a subnet is about 87%. A collision is not
    /// merely untidy — both guests get the same address, so one can source
    /// another's guest IP onto its own link, and the kernel holds two identical
    /// connected routes whose selection depends on insertion order, so return
    /// traffic for one link can leave the other.
    ///
    /// The existing distinctness tests only walked consecutive slot indices,
    /// which never collide, so the pool looked collision-free. This is stated
    /// against the allocator rather than the pure function, because the pure
    /// function is deterministic and therefore cannot both collide and not
    /// collide: what an operator depends on is that a *live* slot is skipped.
    #[test]
    fn a_chosen_slot_is_never_one_that_is_already_occupied() {
        let id = uuid::Uuid::from_u128(700);
        let occupied = tap_address_plan_slot((id.as_u128() % u128::from(TAP_SLOTS)) as u32);
        let chosen =
            choose_tap_plan(id, |candidate| candidate == occupied).expect("a free slot exists");
        assert_ne!(
            chosen, occupied,
            "a sandbox was handed a subnet that is already live"
        );
    }

    /// The probe has to walk the whole pool, not give up at the first hit.
    #[test]
    fn choosing_a_slot_walks_past_occupied_slots_to_find_a_free_one() {
        let id = uuid::Uuid::from_u128(5);
        let free = tap_address_plan_slot(TAP_SLOTS - 1);
        let chosen = choose_tap_plan(id, |candidate| candidate != free)
            .expect("the pool has one free slot left");
        assert_eq!(
            chosen, free,
            "the probe stopped before the only free slot instead of looking for it"
        );
    }

    /// Exhaustion is a refusal, never a collision.
    #[test]
    fn a_full_pool_refuses_rather_than_handing_out_a_duplicate_subnet() {
        let result = choose_tap_plan(uuid::Uuid::from_u128(1), |_| true);
        assert!(
            matches!(result, Err(CoreError::LimitExceeded(_))),
            "a full pool returned {result:?} instead of refusing"
        );
    }

    /// The occupancy check reads the kernel, so it has to survive the shapes
    /// `ip -j` actually emits. An interface with no IPv4 address has no
    /// `addr_info` at all, a host address can be secondary, and a link-local
    /// is still a link-local. Skipping rather than failing matters: an
    /// inventory the reader cannot fully understand must not stop a sandbox
    /// being placed, or it becomes a denial of service in place of a safety
    /// check.
    #[test]
    fn the_address_inventory_reads_every_assigned_address_and_survives_odd_shapes() {
        let inventory = br#"[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1"}]},
            {"ifname":"eth0","flags":["BROADCAST"],"addr_info":[
                {"family":"inet","local":"10.0.0.5"},
                {"family":"inet","local":"10.0.0.5","secondary":true}]},
            {"ifname":"af0123456789ab","addr_info":[{"family":"inet","local":"172.30.8.2"}]},
            {"ifname":"tun0"},
            {"ifname":"weird","addr_info":[{"family":"inet","local":"not-an-ip"}]}]"#;
        let assigned = parse_assigned_ipv4(inventory).expect("readable inventory");
        for expected in ["127.0.0.1", "10.0.0.5", "172.30.8.2"] {
            assert!(
                assigned.contains(&expected.parse().expect("ip")),
                "{expected} is assigned but was not read: {assigned:?}"
            );
        }
        assert_eq!(
            assigned.len(),
            3,
            "a repeated address is one address, and unreadable ones are skipped: {assigned:?}"
        );
    }

    /// A garbage inventory must be an error, not an empty set. An empty set
    /// would make every slot look free and reintroduce the collision.
    #[test]
    fn an_unreadable_address_inventory_is_refused_rather_than_read_as_empty() {
        let result = parse_assigned_ipv4(b"not json at all");
        assert!(
            matches!(&result, Err(CoreError::Unavailable(message)) if message == "invalid ip address inventory"),
            "an unreadable inventory produced {result:?}"
        );
    }

    /// The end-to-end property an operator depends on: a plan whose addresses
    /// are already on the host is never handed out, even when the identifier's
    /// own slot is exactly that one. This is the collision that was live.
    #[test]
    fn a_live_link_is_never_handed_to_a_second_sandbox() {
        let first = uuid::Uuid::from_u128(700);
        let second = uuid::Uuid::from_u128(700 + 1);
        let mut assigned: HashSet<std::net::Ipv4Addr> = HashSet::new();
        let mut place = |id: uuid::Uuid| {
            let plan = choose_tap_plan(id, |candidate| {
                [candidate.host, candidate.guest]
                    .iter()
                    .any(|address| assigned.contains(&address.parse().expect("ip")))
            })
            .expect("a free slot");
            for address in [&plan.host, &plan.guest] {
                assigned.insert(address.parse().expect("ip"));
            }
            plan
        };
        let a = place(first);
        let b = place(second);
        assert_ne!(
            a.network, b.network,
            "two live sandboxes were placed on one /30"
        );
    }

    #[test]
    fn firewall_masquerades_guest_traffic_and_keeps_guest_subnet_reachable() {
        let rules = firewall_rules("aiec_0123456789ab", "af0123456789ab", "172.30.8.0/30");
        assert!(rules.contains("type nat hook postrouting priority srcnat"));
        assert!(rules.contains("oifname != \"af0123456789ab\" ip saddr 172.30.8.0/30 masquerade"));
        assert!(rules.contains("forward iifname \"af0123456789ab\" ip saddr 172.30.8.0/30 accept"));
        assert!(rules.contains("forward oifname \"af0123456789ab\" ip daddr 172.30.8.0/30 ct state established,related accept"));
        // The guest gateway lives inside 172.16.0.0/12, so its allow rule must be
        // evaluated before the private-range drops or the guest loses its default route.
        let gateway = rules
            .find("input iifname \"af0123456789ab\" ip saddr 172.30.8.0/30 ip daddr 172.30.8.0/30 accept")
            .expect("guest subnet input allow rule");
        let private_drop = rules
            .find("input iifname \"af0123456789ab\" ip daddr 172.16.0.0/12 drop")
            .expect("private range drop rule");
        assert!(gateway < private_drop);
        let metadata_drop = rules
            .find("forward iifname \"af0123456789ab\" ip daddr 169.254.169.254 drop")
            .expect("metadata drop rule");
        let outbound = rules
            .find("forward iifname \"af0123456789ab\" ip saddr 172.30.8.0/30 accept")
            .expect("outbound accept rule");
        assert!(metadata_drop < outbound);
    }

    #[tokio::test]
    async fn disabled_policy_never_touches_host_networking() {
        let attachment = LinuxNetworkManager::new()
            .prepare(&sandbox(), &NetworkPolicy::Disabled)
            .await
            .expect("disabled policy needs no host resources");
        assert!(attachment.resource.is_empty());
        assert!(attachment.addresses().is_empty());
        assert!(attachment.guest_addresses().is_empty());
    }

    #[tokio::test]
    async fn restricted_allowlist_fails_closed_without_plugin() {
        let result = LinuxNetworkManager::new()
            .prepare(
                &sandbox(),
                &NetworkPolicy::Restricted {
                    allowed_hosts: vec!["pypi.org".into()],
                },
            )
            .await;
        assert!(matches!(result, Err(CoreError::Unsupported(_))));
    }
}
