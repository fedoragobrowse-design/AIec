//! Guarded attachment lifecycle. No ordinary forwarding or masquerade is used.

use crate::{LinuxNetworkManager, TAP_PREFIX, TAP_SLOTS};
use aiec_core::{
    CoreError, Sandbox,
    network::{NetworkAttachment, NetworkBackend, NetworkCapabilities, NetworkPolicy},
};
use aiec_guard::{
    compiler::{OperatorBoundary, compile},
    enforcement::{EnforcementBackend, GuardAttachment, NftablesBackend},
    events::{Category, Decision, EventInput, EventSink, FileEventSink},
    gateway::{CredentialStore, GatewayConfig, GuardGateway},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::Mutex,
};
use uuid::Uuid;

const BROKER_PORT: u16 = 8443;
const DNS_PORT: u16 = 53;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

struct RunningGuard {
    attachment: GuardAttachment,
    gateway: GuardGateway,
}

/// Worker-side owner of out-of-guest gateways and their network attachments.
/// Settings are operator environment, never taken from guest/request headers.
#[derive(Clone)]
pub struct GuardNetworkManager {
    state_dir: PathBuf,
    credential_file: Option<PathBuf>,
    boundary_file: Option<PathBuf>,
    allow_legacy: bool,
    local_test_mode: bool,
    /// Whether this host can actually install the rules Guard promises.
    ///
    /// Probed once, because a capability the scheduler places governed work on
    /// has to mean something. `NetworkCapabilities` describes the backend type;
    /// only the host can say whether `nft` exists and whether the process may
    /// use it.
    can_enforce: bool,
    enforcement: Arc<NftablesBackend>,
    running: Arc<Mutex<BTreeMap<Uuid, RunningGuard>>>,
}

/// Whether this host can install and read nftables rules.
///
/// A read is enough to know the binary exists and the caller has the privilege,
/// and it changes nothing: listing the ruleset does not modify the firewall. The
/// answer is the reason a worker should or should not advertise network policy
/// enforcement, so it is taken once at startup rather than discovered by a
/// sandbox that believed it was governed.
fn probe_enforcement() -> bool {
    std::process::Command::new("nft")
        .args(["list", "ruleset"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

impl GuardNetworkManager {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            credential_file: std::env::var_os("AIEC_GUARD_CREDENTIALS_FILE").map(PathBuf::from),
            boundary_file: std::env::var_os("AIEC_GUARD_BOUNDARY_FILE").map(PathBuf::from),
            allow_legacy: std::env::var("AIEC_ALLOW_LEGACY_NETWORK").as_deref() == Ok("1"),
            local_test_mode: std::env::var("AIEC_GUARD_TEST_MODE").as_deref() == Ok("1"),
            can_enforce: probe_enforcement(),
            enforcement: Arc::new(NftablesBackend::new()),
            running: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Explicit operator settings for isolated acceptance or embedded deployment.
    pub fn with_operator_files(
        mut self,
        boundary: Option<PathBuf>,
        credentials: Option<PathBuf>,
    ) -> Self {
        self.boundary_file = boundary;
        self.credential_file = credentials;
        self
    }

    /// Local mock destinations require a separate network namespace.
    pub fn with_local_test_mode(mut self) -> Self {
        self.local_test_mode = true;
        self
    }

    fn directory(&self, id: Uuid) -> PathBuf {
        self.state_dir.join(id.to_string())
    }

    async fn boundary(&self) -> Result<OperatorBoundary, CoreError> {
        match &self.boundary_file {
            None => Ok(OperatorBoundary::default()),
            Some(path) => {
                let bytes = bounded_read(path, MAX_CONFIG_BYTES).await?;
                serde_json::from_slice(&bytes).map_err(|_| {
                    CoreError::InvalidRequest("invalid operator Guard boundary file".into())
                })
            }
        }
    }

    async fn create_guard(&self, sandbox: &Sandbox) -> Result<RunningGuard, CoreError> {
        let config = sandbox
            .environment
            .guard
            .as_ref()
            .ok_or_else(|| CoreError::InvalidRequest("Guard selection missing".into()))?;
        let policy = config
            .effective_policy()
            .map_err(|e| CoreError::Unavailable(format!("guard policy selection: {e}")))?;
        self.enforcement
            .health()
            .await
            .map_err(|e| CoreError::Unavailable(format!("guard enforcement probe: {e}")))?;
        let occupied = assigned_ipv4().await?;
        let start = (sandbox.id.as_u128() % u128::from(TAP_SLOTS)) as u32;
        let slot = (0..TAP_SLOTS)
            .map(|offset| (start + offset) % TAP_SLOTS)
            .find(|slot| {
                let (host, guest) = addresses(*slot);
                !occupied.contains(&host) && !occupied.contains(&guest)
            })
            .ok_or_else(|| CoreError::LimitExceeded("Guard TAP address capacity".into()))?;
        let (gateway_ip, guest_ip) = addresses(slot);
        let suffix = hex::encode(Sha256::digest(sandbox.id.as_bytes()));
        let interface = format!("ag{}", &suffix[..13]);
        let attachment = GuardAttachment {
            sandbox_id: sandbox.id,
            tenant_id: sandbox.tenant_id,
            interface,
            guest_ip,
            gateway_ip,
            dns_port: DNS_PORT,
            broker_port: BROKER_PORT,
        };
        let mut boundary = self
            .boundary()
            .await
            .map_err(|e| CoreError::Unavailable(format!("guard operator boundary: {e}")))?;
        let mock_addresses: HashSet<_> = boundary
            .test_destinations
            .values()
            .flat_map(|addresses| addresses.iter().copied())
            .collect();
        aiec_guard::deployment::validate_operator_test_mode(&boundary, self.local_test_mode)
            .map_err(guard_error)?;
        protect_attached_addresses(
            &mut boundary,
            occupied.iter().copied(),
            &mock_addresses,
            [gateway_ip, guest_ip],
        );
        let compiled = compile(&policy, &boundary).map_err(guard_error)?;
        if sandbox
            .environment
            .guard_policy_hash
            .as_ref()
            .is_some_and(|hash| hash != compiled.policy_hash())
        {
            return Err(CoreError::InvalidRequest(
                "stored Guard policy hash mismatch".into(),
            ));
        }
        let dir = self.directory(sandbox.id);
        // Each of these names itself. "Guard I/O: Permission denied" tells an
        // operator nothing about which of the four filesystem steps refused,
        // and this is the path a worker walks the first time it places a
        // sandbox under Guard.
        private_directory(&dir).await.map_err(|e| {
            CoreError::Io(std::io::Error::new(
                io_kind_of(&e),
                format!("guard state directory: {e}"),
            ))
        })?;
        let credentials = match &self.credential_file {
            Some(path) => CredentialStore::from_file(path)
                .map_err(|e| CoreError::Unavailable(format!("guard credential store: {e}")))?,
            None => CredentialStore::empty(),
        };
        // The journal is opened before anything else is installed, and it is
        // the first thing that writes outside memory. Naming it here rather
        // than letting `guard_error` flatten it is the difference between an
        // operator reading "event journal" and reading a bare errno.
        let events = Arc::new(
            FileEventSink::open(dir.join("events.jsonl"))
                .map_err(|e| CoreError::Unavailable(format!("guard event journal: {e}")))?,
        );
        // Link remains DOWN until both filter and listeners are installed.
        ip(&["tuntap", "add", "dev", &attachment.interface, "mode", "tap"]).await?;
        let result = async {
            ip(&[
                "addr",
                "add",
                &format!("{gateway_ip}/{TAP_PREFIX}"),
                "dev",
                &attachment.interface,
            ])
            .await?;
            self.enforcement
                .apply_policy(&compiled, &attachment)
                .await
                .map_err(|e| CoreError::Unavailable(format!("guard nftables apply: {e}")))?;
            let gateway = GuardGateway::start(GatewayConfig {
                sandbox_id: sandbox.id,
                tenant_id: sandbox.tenant_id,
                compiled: compiled.clone(),
                bind_ip: gateway_ip,
                guest_ip,
                broker_port: BROKER_PORT,
                dns_port: DNS_PORT,
                credentials: Arc::new(credentials),
                events: events.clone(),
            })
            .await
            .map_err(|e| CoreError::Unavailable(format!("guard gateway start: {e}")))?;
            private_json(
                &dir.join("attachment.json"),
                &serde_json::json!({ "attachment": attachment, "node_id": sandbox.node_id }),
            )
            .await
            .map_err(|e| CoreError::Io(std::io::Error::new(io_kind_of(&e), format!("guard attachment record: {e}"))))?;
            private_json(
                &dir.join("effective-policy.json"),
                &serde_json::json!({"policy":compiled.policy(),"policy_hash":compiled.policy_hash()}),
            )
            .await
            .map_err(|e| CoreError::Io(std::io::Error::new(io_kind_of(&e), format!("guard policy record: {e}"))))?;
            events
                .append(EventInput {
                    sandbox_id: sandbox.id,
                    tenant_id: sandbox.tenant_id,
                    policy_hash: compiled.policy_hash().to_owned(),
                    category: Category::Lifecycle,
                    decision: Decision::Allow,
                    reason: "guard-installed-before-guest-boot".into(),
                    ..Default::default()
                })
                .await
                .map_err(|e| CoreError::Unavailable(format!("guard journal append: {e}")))?;
            ip(&["link", "set", "dev", &attachment.interface, "up"]).await?;
            Ok::<_, CoreError>(RunningGuard {
                attachment: attachment.clone(),
                gateway,
            })
        }
        .await;
        if result.is_err() {
            // A failed setup never becomes an unfiltered attachment.
            let _ = self.enforcement.cut_network(&attachment).await;
            if ip(&["link", "del", "dev", &attachment.interface])
                .await
                .is_ok()
            {
                let _ = self.enforcement.remove_policy(&attachment).await;
            }
        }
        result
    }
}

#[async_trait]
impl NetworkBackend for GuardNetworkManager {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            // Reported from the probe, not from the backend type. A worker that
            // claims this is a promise the scheduler places governed work on, so
            // a host without `nft` or the privilege to use it must say so here
            // rather than at the first boot that trusted the claim.
            restricted_allowlists: self.can_enforce,
            dns_controls: self.can_enforce,
            bandwidth_limits: false,
        }
    }

    async fn prepare(
        &self,
        sandbox: &Sandbox,
        policy: &NetworkPolicy,
    ) -> Result<NetworkAttachment, CoreError> {
        if sandbox.environment.guard.is_none() {
            if policy.is_enabled() && !self.allow_legacy {
                return Err(CoreError::Unsupported("unguarded network requires operator AIEC_ALLOW_LEGACY_NETWORK=1; select a Guard policy instead".into()));
            }
            return LinuxNetworkManager::new().prepare(sandbox, policy).await;
        }
        let mut running = self.running.lock().await;
        if running.contains_key(&sandbox.id) {
            return Err(CoreError::InvalidRequest(
                "Guard attachment already running".into(),
            ));
        }
        let guard = self.create_guard(sandbox).await?;
        let result = NetworkAttachment {
            resource: guard.attachment.interface.clone(),
            addresses: vec![guard.attachment.gateway_ip.to_string()],
            guest_addresses: vec![guard.attachment.guest_ip.to_string()],
        };
        running.insert(sandbox.id, guard);
        Ok(result)
    }

    async fn release(
        &self,
        sandbox: &Sandbox,
        attachment: &NetworkAttachment,
    ) -> Result<(), CoreError> {
        if !attachment.resource.starts_with("ag") {
            return LinuxNetworkManager::new()
                .release(sandbox, attachment)
                .await;
        }
        let mut running = self.running.lock().await;
        let stored = bounded_read(
            &self.directory(sandbox.id).join("attachment.json"),
            MAX_CONFIG_BYTES,
        )
        .await?;
        let stored: serde_json::Value = serde_json::from_slice(&stored)
            .map_err(|_| CoreError::InvalidRequest("invalid Guard attachment record".into()))?;
        let guard: GuardAttachment = serde_json::from_value(stored["attachment"].clone())
            .map_err(|_| CoreError::InvalidRequest("invalid Guard attachment record".into()))?;
        let node: Option<Uuid> = serde_json::from_value(stored["node_id"].clone())
            .map_err(|_| CoreError::InvalidRequest("invalid Guard owner record".into()))?;
        if guard.sandbox_id != sandbox.id
            || guard.tenant_id != sandbox.tenant_id
            || guard.interface != attachment.resource
            || node != sandbox.node_id
        {
            return Err(CoreError::InvalidRequest(
                "Guard attachment ownership mismatch".into(),
            ));
        }
        if stored["released"].as_bool() == Some(true) {
            return Ok(());
        }
        self.enforcement
            .cut_network(&guard)
            .await
            .map_err(guard_error)?;
        // Do not delete filtering while a guest still has a live interface.
        ip(&["link", "set", "dev", &guard.interface, "down"]).await?;
        if let Some(guard) = running.remove(&sandbox.id) {
            guard.gateway.cut().map_err(guard_error)?;
            guard.gateway.shutdown().await.map_err(guard_error)?;
        }
        ip(&["link", "del", "dev", &guard.interface]).await?;
        self.enforcement
            .remove_policy(&guard)
            .await
            .map_err(guard_error)?;
        private_json(
            &self.directory(sandbox.id).join("attachment.json"),
            &serde_json::json!({"attachment":guard,"node_id":node,"released":true}),
        )
        .await?;
        Ok(())
    }
}

fn ipnet_from_v4(address: Ipv4Addr) -> ipnet::IpNet {
    ipnet::IpNet::from(std::net::IpAddr::V4(address))
}

/// Protects every address this attachment depends on, without naming a range
/// twice.
///
/// A test exception can never authorize a guarded peer or the gateway, so each
/// occupied host address and each end of this attachment's own link is added.
/// Occupied addresses include the local mocks the boundary already protects, and
/// Guard refuses a boundary that names the same destination or zone twice - so
/// without the deduplication the *second* sandbox on a host can never attach,
/// because the first one's mocks are already protected by the operator file.
fn protect_attached_addresses(
    boundary: &mut OperatorBoundary,
    occupied: impl IntoIterator<Item = Ipv4Addr>,
    mock_addresses: &HashSet<std::net::IpAddr>,
    link: [Ipv4Addr; 2],
) {
    for address in occupied
        .into_iter()
        .filter(|address| !mock_addresses.contains(&std::net::IpAddr::V4(*address)))
        .chain(link)
    {
        let range = ipnet_from_v4(address);
        if !boundary.protected_cidrs.contains(&range) {
            boundary.protected_cidrs.push(range);
        }
    }
}

fn addresses(slot: u32) -> (Ipv4Addr, Ipv4Addr) {
    let third = 8 + (slot / 64) as u8;
    let fourth = ((slot % 64) * 4) as u8;
    (
        Ipv4Addr::new(172, 30, third, fourth + 1),
        Ipv4Addr::new(172, 30, third, fourth + 2),
    )
}

fn guard_error(error: aiec_guard::GuardError) -> CoreError {
    CoreError::Unavailable(error.to_string())
}

async fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>, CoreError> {
    let mut file = tokio::fs::File::open(path).await?;
    if file.metadata().await?.len() > limit {
        return Err(CoreError::LimitExceeded("Guard configuration file".into()));
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > limit {
        return Err(CoreError::LimitExceeded("Guard configuration file".into()));
    }
    Ok(bytes)
}

async fn private_directory(path: &Path) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::create_dir_all(path).await?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    Ok(())
}

async fn private_json(path: &Path, value: &serde_json::Value) -> Result<(), CoreError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| CoreError::InvalidRequest("invalid Guard state".into()))?;
    let temporary = path.with_extension(format!("{}.tmp", Uuid::now_v7()));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&temporary).await?;
    file.write_all(&bytes).await?;
    file.sync_all().await?;
    tokio::fs::rename(&temporary, path).await?;
    Ok(())
}

/// The I/O kind behind a core error, so a labelled one keeps the kind a caller
/// might be matching on.
fn io_kind_of(error: &CoreError) -> std::io::ErrorKind {
    match error {
        CoreError::Io(inner) => inner.kind(),
        _ => std::io::ErrorKind::Other,
    }
}

async fn assigned_ipv4() -> Result<HashSet<Ipv4Addr>, CoreError> {
    let bytes = tool("ip", &["-j", "-4", "addr", "show"]).await?;
    let values: Vec<serde_json::Value> = serde_json::from_slice(&bytes)
        .map_err(|_| CoreError::Unavailable("invalid ip address inventory".into()))?;
    let mut assigned = HashSet::new();
    for interface in values {
        if let Some(addresses) = interface["addr_info"].as_array() {
            for address in addresses {
                if let Some(ip) = address["local"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
                {
                    assigned.insert(ip);
                }
            }
        }
    }
    Ok(assigned)
}

async fn ip(args: &[&str]) -> Result<(), CoreError> {
    tool("ip", args).await.map(|_| ())
}

async fn tool(program: &str, args: &[&str]) -> Result<Vec<u8>, CoreError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            CoreError::Io(std::io::Error::new(
                e.kind(),
                format!("could not run `{program} {}`: {e}", args.join(" ")),
            ))
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CoreError::Unavailable("network command stdout missing".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CoreError::Unavailable("network command stderr missing".into()))?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut output = Vec::new();
        let mut diagnostic = Vec::new();
        let mut lines = tokio::io::AsyncReadExt::take(stdout, 1024 * 1024 + 1);
        let mut errors = tokio::io::AsyncReadExt::take(stderr, 4097);
        let (status, out, err) = tokio::join!(
            child.wait(),
            lines.read_to_end(&mut output),
            errors.read_to_end(&mut diagnostic)
        );
        out?;
        err?;
        if output.len() > 1024 * 1024 || diagnostic.len() > 4096 {
            return Err(CoreError::LimitExceeded("network command output".into()));
        }
        if !status?.success() {
            return Err(CoreError::Unavailable(format!(
                "{program} failed: {}",
                String::from_utf8_lossy(&diagnostic)
            )));
        }
        Ok(output)
    })
    .await
    .map_err(|_| CoreError::Unavailable(format!("{program} timed out")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boundary_protecting(address: &str) -> OperatorBoundary {
        let mut boundary = OperatorBoundary::default();
        boundary
            .protected_cidrs
            .push(address.parse().expect("cidr"));
        boundary
    }

    /// The second sandbox on a host used to be unable to attach at all: the
    /// occupied-address set includes the local mocks, and the boundary already
    /// protected them, so the range was pushed twice and Guard - correctly -
    /// refused a document naming the same destination twice.
    #[test]
    fn an_address_the_boundary_already_protects_is_not_added_twice() {
        let mut boundary = boundary_protecting("198.18.0.21/32");
        let mocks: HashSet<std::net::IpAddr> = ["198.18.0.21", "198.18.0.10"]
            .iter()
            .map(|a| a.parse().expect("ip"))
            .collect();
        protect_attached_addresses(
            &mut boundary,
            [Ipv4Addr::new(198, 18, 0, 21), Ipv4Addr::new(198, 18, 0, 10)],
            &mocks,
            [Ipv4Addr::new(172, 30, 8, 1), Ipv4Addr::new(172, 30, 8, 2)],
        );
        let protected: Vec<String> = boundary
            .protected_cidrs
            .iter()
            .map(|range| range.to_string())
            .collect();
        // The mock is skipped because it is a test destination, the pre-existing
        // range appears once, and the attachment's own link is added.
        assert_eq!(
            protected,
            vec!["198.18.0.21/32", "172.30.8.1/32", "172.30.8.2/32"],
            "a protected range must not be named twice: {protected:?}",
        );
    }

    /// A non-mock occupied address is protected, and a repeated attachment does
    /// not grow the list.
    #[test]
    fn a_guarded_peer_is_protected_once_however_often_it_appears() {
        let mocks = HashSet::new();
        let mut boundary = OperatorBoundary::default();
        for _ in 0..2 {
            protect_attached_addresses(
                &mut boundary,
                [Ipv4Addr::new(10, 0, 0, 5)],
                &mocks,
                [Ipv4Addr::new(172, 30, 9, 1), Ipv4Addr::new(172, 30, 9, 2)],
            );
        }
        assert_eq!(
            boundary.protected_cidrs.len(),
            3,
            "{:?}",
            boundary.protected_cidrs,
        );
    }
}
