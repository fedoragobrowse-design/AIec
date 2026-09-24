//! Linux TAP and nftables network backend.

use agentforge_core::{
    CoreError, Sandbox,
    network::{NetworkAttachment, NetworkBackend, NetworkCapabilities, NetworkPolicy},
};
use async_trait::async_trait;
use std::process::Stdio;
use tokio::{io::AsyncWriteExt, process::Command};

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
            return Err(CoreError::InvalidRequest(
                "restricted host allowlists are not supported by the Linux TAP backend".into(),
            ));
        }

        let suffix = &sandbox.id.to_string()[..12];
        let tap = format!("af{suffix}");
        let table = format!("agentforge_{suffix}");
        let address = format!("172.30.0.{}", ((sandbox.id.as_u128() & 0x3f) + 2) as u8);
        let device = NetworkAttachment {
            resource: tap.clone(),
            addresses: vec![address.clone()],
        };

        let commands: Vec<Vec<String>> = vec![
            vec!["tuntap".into(), "add".into(), "dev".into(), tap.clone(), "mode".into(), "tap".into()],
            vec!["addr".into(), "add".into(), format!("{address}/30"), "dev".into(), tap.clone()],
            vec!["link".into(), "set".into(), "dev".into(), tap.clone(), "up".into()],
        ];
        for args in commands {
            if let Err(error) = run_ip(&args).await {
                let _ = self.release(sandbox, &device).await;
                return Err(error);
            }
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
            && let Err(error) = stdin.write_all(firewall_rules(&table, &tap).as_bytes()).await
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
    let output = Command::new("ip").args(args).output().await?;
    if output.status.success() {
        Ok(())
    } else {
        Err(CoreError::Io(std::io::Error::other(format!(
            "TAP setup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))))
    }
}

fn firewall_rules(table: &str, tap: &str) -> String {
    format!(
        "add table inet {table}; \
add chain inet {table} input {{ type filter hook input priority -10; policy accept; }}; \
add chain inet {table} forward {{ type filter hook forward priority -10; policy accept; }}; \
add rule inet {table} input iifname \"{tap}\" ip daddr 169.254.169.254 drop; \
add rule inet {table} input iifname \"{tap}\" ip daddr 10.0.0.0/8 drop; \
add rule inet {table} input iifname \"{tap}\" ip daddr 172.16.0.0/12 drop; \
add rule inet {table} input iifname \"{tap}\" ip daddr 192.168.0.0/16 drop; \
add rule inet {table} input iifname \"{tap}\" ip daddr 127.0.0.0/8 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 169.254.169.254 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 10.0.0.0/8 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 172.16.0.0/12 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 192.168.0.0/16 drop; \
add rule inet {table} forward iifname \"{tap}\" ip daddr 127.0.0.0/8 drop"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_is_scoped_to_tap() {
        let rules = firewall_rules("agentforge_0123456789ab", "af0123456789ab");
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
}
