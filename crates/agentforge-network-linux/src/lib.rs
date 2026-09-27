//! Linux TAP and nftables network backend.

use agentforge_core::{
    CoreError, Sandbox, SandboxId,
    network::{NetworkAttachment, NetworkBackend, NetworkCapabilities, NetworkPolicy},
};
use async_trait::async_trait;
use std::process::Stdio;
use tokio::{io::AsyncWriteExt, process::Command};

/// Address space the per-sandbox point-to-point subnets are carved from.
const TAP_BASE: &str = "172.30";
/// Prefix length of a per-sandbox link.
const TAP_PREFIX: u8 = 30;

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

/// Derives a stable point-to-point subnet from a sandbox identifier.
///
/// The /30 is selected on the third octet only, so the host always owns `.1` and
/// the guest always owns `.2`; no sandbox can be handed a network or broadcast
/// address, or an address outside the sandbox's own subnet.
fn tap_address_plan(id: SandboxId) -> TapAddressPlan {
    let third = ((id.as_u128() % 200) as u8) + 8;
    TapAddressPlan {
        network: format!("{TAP_BASE}.{third}.0/{TAP_PREFIX}"),
        host: format!("{TAP_BASE}.{third}.1"),
        guest: format!("{TAP_BASE}.{third}.2"),
    }
}

/// Creates isolated TAP attachments and applies per-sandbox nftables policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxNetworkManager;

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

        let plan = tap_address_plan(sandbox.id);
        let suffix = &sandbox.id.to_string()[..12];
        let tap = format!("af{suffix}");
        let table = format!("agentforge_{suffix}");
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
            .args(["delete", "table", "inet", &format!("agentforge_{suffix}")])
            .status()
            .await;
        let _ = Command::new("ip")
            .args(["link", "del", &attachment.resource])
            .status()
            .await;
        Ok(())
    }
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
            state: agentforge_core::SandboxState::Creating,
            runtime: agentforge_core::RuntimeKind::Firecracker,
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
        let rules = firewall_rules("agentforge_0123456789ab", "af0123456789ab", "172.30.8.0/30");
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
            let (network, prefix) = plan.network.rsplit_once('/').expect("cidr suffix");
            let host = plan.host.clone();
            let guest = plan.guest.clone();
            let third: u8 = host
                .split('.')
                .nth(2)
                .expect("third octet")
                .parse()
                .expect("numeric third octet");
            assert!(
                (8..=207).contains(&third),
                "third octet {third} out of range"
            );
            let expected = format!("{TAP_BASE}.{third}");
            assert_eq!(network, format!("{expected}.0").as_str());
            assert_eq!(prefix, TAP_PREFIX.to_string());
            assert_eq!(host, format!("{expected}.1").as_str());
            assert_eq!(guest, format!("{expected}.2").as_str());
        }

        // Every reachable third octet maps to a distinct subnet, and each sandbox
        // ends up with a usable host and guest address on its own /30.
        let mut seen = std::collections::HashSet::new();
        for index in 0..200u128 {
            let plan = tap_address_plan(uuid::Uuid::from_u128(index));
            assert_valid(&plan);
            assert!(seen.insert(plan.network.clone()));
        }
        for _ in 0..256 {
            assert_valid(&tap_address_plan(uuid::Uuid::now_v7()));
        }
    }

    #[test]
    fn identical_sandbox_id_maps_to_identical_subnet() {
        let id = uuid::Uuid::now_v7();
        assert_eq!(tap_address_plan(id), tap_address_plan(id));
    }

    #[test]
    fn firewall_masquerades_guest_traffic_and_keeps_guest_subnet_reachable() {
        let rules = firewall_rules("agentforge_0123456789ab", "af0123456789ab", "172.30.8.0/30");
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
