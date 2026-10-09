//! `aiec upgrade`: comparing this machine against the deployment.
//!
//! Notify-only by design: it prints what is behind and exits 0, it never
//! rewrites the running binary. A self-modifying CLI is an update channel with
//! no signature check, and this product's trust story is signed manifests, not
//! curl-piped overwrites. The deployment publishes its versions at
//! `GET /v1/versions`; the worker logs the same warning at startup so a fleet
//! that never runs the CLI still says it is behind.

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum UpgradeCommand {
    /// Compares this CLI (and the harness protocol it speaks) against the
    /// deployment at `--url` and reports when either side is behind.
    Check,
}

pub async fn upgrade_command(url: &str, command: UpgradeCommand) -> Result<()> {
    match command {
        UpgradeCommand::Check => check(url).await,
    }
}
/// Orders dotted-numeric versions (`1.10.0` > `1.9.0`), falling back to plain
/// string order for anything non-numeric. `minimum_cli` is a floor, not a
/// pin: a CLI newer than the floor clears it, so equality would warn a caller
/// that is already fine.
fn version_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    let numeric = |side: &str| {
        side.split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Vec<_>>()
    };
    let (left_parts, right_parts) = (numeric(left), numeric(right));
    if left_parts.iter().all(|part| part.is_some()) && right_parts.iter().all(|part| part.is_some())
    {
        let (left_parts, right_parts): (Vec<u64>, Vec<u64>) = (
            left_parts.into_iter().flatten().collect(),
            right_parts.into_iter().flatten().collect(),
        );
        left_parts.cmp(&right_parts)
    } else {
        left.cmp(right)
    }
}
async fn check(url: &str) -> Result<()> {
    // No credential on purpose: the versions endpoint is public so a caller
    // can ask what the deployment is before it can authenticate as anyone.
    // The empty bearer reaches no auth layer; `/v1/versions` sits outside it.
    let client = aiec_client::AIecClient::new(url, "")
        .map_err(|error| anyhow::anyhow!("building client for {url}: {error}"))?;
    let versions = client
        .versions()
        .await
        .map_err(|error| anyhow::anyhow!("reading versions from {url}/v1/versions: {error}"))?;
    let get = |key: &str| {
        versions
            .get(key)
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
    };
    let api = get("api");
    let harness_protocol = versions
        .get("harness_protocol")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let recommended_harness = get("recommended_harness");
    let recommended_guest = get("recommended_guest_artifact");
    let minimum_cli = get("minimum_cli");

    let cli = env!("CARGO_PKG_VERSION");
    let ours = aiec_core::protocol::PROTOCOL_VERSION;
    println!("cli {cli} (harness protocol {ours})");
    println!("api {api} (harness {recommended_harness}, guest artifact {recommended_guest})");

    // Both directions, both exit 0: the point is the sentence, not the code.
    // A newer CLI against an older deployment warns the other way round, so an
    // operator who upgraded the laptop first still learns the fleet is behind.
    let mut current = true;
    if minimum_cli != "unknown" && version_cmp(cli, minimum_cli) == std::cmp::Ordering::Less {
        println!("behind: deployment wants CLI at least {minimum_cli}, this is {cli}");
        current = false;
    }
    if recommended_harness != "unknown"
        && version_cmp(cli, recommended_harness) == std::cmp::Ordering::Less
    {
        println!("behind: deployment recommends harness {recommended_harness}, this CLI is {cli}");
        current = false;
    }
    if harness_protocol != 0 && u64::from(ours) != harness_protocol {
        println!(
            "behind: deployment speaks harness protocol {harness_protocol}, this CLI speaks {ours}"
        );
        current = false;
    }
    if current {
        println!("current");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::version_cmp;
    use std::cmp::Ordering;

    /// The floor is a floor: newer clears it, older warns, equal is current.
    /// Plain string order would call `1.10.0` older than `1.9.0`.
    #[test]
    fn version_floor_orders_numerically() {
        assert_eq!(version_cmp("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(version_cmp("0.1.0", "99.0-minimum"), Ordering::Less);
        assert_eq!(version_cmp("0.1.0", "0.1.0"), Ordering::Equal);
    }
}
