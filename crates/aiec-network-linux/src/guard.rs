//! Guarded attachment lifecycle. No ordinary forwarding or masquerade is used.

use crate::{LinuxNetworkManager, TAP_PREFIX, TAP_SLOTS};
use aiec_core::{
    CoreError, Sandbox,
    network::{NetworkAttachment, NetworkBackend, NetworkCapabilities, NetworkPolicy},
};
use aiec_guard::{
    canaries::{CanaryEnforcer, CanaryMonitor},
    compiler::{OperatorBoundary, compile},
    control::{
        BudgetAuthority, GuardControlCommand, GuardControlResponse, GuardFence, GuardIdentity,
        GuardRuntimeObservation, QuarantineRequest,
    },
    enforcement::{CounterSource, EnforcementBackend, GuardAttachment, NftablesBackend},
    events::{Category, Decision, EventInput, EventSink, FileEventSink, GuardEvent},
    gateway::{CredentialStore, GatewayConfig, GatewayControl, GatewayNetworkCut, GuardGateway},
    proposals::{AtomicPolicy, ProposalStore, ProposalStoreConfig},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
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
    node_id: Option<Uuid>,
    /// The policy cell the gateway enforces, advanced by an approved proposal.
    /// Nothing else may hold a copy: a stale copy would compare a live
    /// telemetry call against a hash the guest no longer runs under, or
    /// reinstall the previous ruleset on a restore.
    policy: Arc<AtomicPolicy>,
    gateway: Mutex<Option<GuardGateway>>,
    control: GatewayControl,
    fence: std::sync::RwLock<GuardFence>,
    events: Arc<FileEventSink>,
    kernel: Mutex<()>,
    released: AtomicBool,
    kernel_cut: AtomicBool,
    /// The operator boundary this attachment was compiled against, kept for
    /// verifying a candidate policy before it is installed.
    boundary: Option<OperatorBoundary>,
    /// Built on first use, so an attachment nobody proposes against never pays
    /// for a store.
    proposals: Mutex<Option<Arc<ProposalStore>>>,
}

/// Enforces a canary tripwire with the actions this attachment already owns.
///
/// The port has exactly two methods. There is no method that could widen a
/// policy, restore a cut, or release a quarantine, so a canary firing can only
/// ever be more restrictive than what was already in force.
struct AttachmentCanaryEnforcer {
    guard: Weak<RunningGuard>,
    cut: std::sync::Arc<dyn aiec_guard::enforcement::EnforcementBackend>,
}

#[async_trait]
impl CanaryEnforcer for AttachmentCanaryEnforcer {
    async fn cut(&self) -> Result<(), aiec_guard::GuardError> {
        let Some(guard) = self.guard.upgrade() else {
            return Ok(());
        };
        if let Some(gateway) = guard.gateway.lock().await.as_ref() {
            // A canary firing is a containment decision, not a transient cut:
            // the next heartbeat must not re-admit the machine that just
            // touched a tripwire.
            gateway.hold_cut("canary fired")?;
        }
        let _ = self.cut.cut_network(&guard.attachment).await;
        guard
            .kernel_cut
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    async fn quarantine(&self, request: QuarantineRequest) -> Result<(), aiec_guard::GuardError> {
        // The quarantine itself is a control-plane decision - it marks durable
        // state and dispatches a pause and a capture - so a worker-side canary
        // cuts and reports, and the control plane's reaper path decides the
        // rest. Reporting an unapplied quarantine as done would be a lie.
        let _ = request;
        Err(aiec_guard::GuardError::Unavailable(
            "canary quarantine is applied by the control plane".into(),
        ))
    }
}

#[derive(Clone, Copy)]
struct LeaseContext {
    tenant_id: Uuid,
    node_id: Option<Uuid>,
    fence: GuardFence,
}

struct AttachmentCut {
    guard: Weak<RunningGuard>,
    enforcement: Arc<NftablesBackend>,
}

#[async_trait]
impl GatewayNetworkCut for AttachmentCut {
    async fn cut_network(&self) -> aiec_guard::Result<()> {
        let Some(guard) = self.guard.upgrade() else {
            return Ok(());
        };
        let _kernel = guard.kernel.lock().await;
        if guard.released.load(Ordering::Acquire)
            || !guard.control.network_cut()
            || guard.kernel_cut.load(Ordering::Acquire)
        {
            return Ok(());
        }
        if let Err(error) = self.enforcement.cut_network(&guard.attachment).await {
            // If nft is unavailable, the attachment itself must still stop passing packets.
            ip(&["link", "set", "dev", &guard.attachment.interface, "down"])
                .await
                .map_err(|fallback| {
                    aiec_guard::GuardError::Unavailable(format!(
                        "{error}; attachment cut: {fallback}"
                    ))
                })?;
        }
        guard.kernel_cut.store(true, Ordering::Release);
        Ok(())
    }
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
    running: Arc<Mutex<BTreeMap<Uuid, Arc<RunningGuard>>>>,
    preparing: Arc<Mutex<()>>,
    budget_authority: Arc<RwLock<Option<Arc<dyn BudgetAuthority>>>>,
    fences: Arc<RwLock<BTreeMap<Uuid, LeaseContext>>>,
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
            preparing: Arc::new(Mutex::new(())),
            budget_authority: Arc::new(RwLock::new(None)),
            fences: Arc::new(RwLock::new(BTreeMap::new())),
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

    /// Installs the durable control-plane authority, shared by all runtime clones.
    /// Reconfiguration cannot replace an authority underneath running workloads.
    pub fn configure_budget_authority(
        &self,
        authority: Arc<dyn BudgetAuthority>,
    ) -> Result<(), CoreError> {
        let mut configured = self.budget_authority.write().map_err(|_| {
            CoreError::Unavailable("Guard budget authority configuration poisoned".into())
        })?;
        if configured.is_some() {
            return Err(CoreError::InvalidRequest(
                "Guard budget authority already configured".into(),
            ));
        }
        *configured = Some(authority);
        Ok(())
    }

    /// Parent dispatch authenticates current ownership before issuing this fence.
    pub async fn guard_set_fence(
        &self,
        sandbox: &Sandbox,
        fence: GuardFence,
    ) -> Result<(), CoreError> {
        if fence.generation < 0 {
            return Err(CoreError::InvalidRequest(
                "invalid Guard ownership generation".into(),
            ));
        }
        let running = self.running.lock().await.get(&sandbox.id).cloned();
        if let Some(guard) = running.as_ref()
            && (guard.fence.read().map(|bound| bound.lease_id).ok() != Some(fence.lease_id)
                || guard.attachment.tenant_id != sandbox.tenant_id
                || guard.node_id != sandbox.node_id)
        {
            return Err(CoreError::InvalidRequest(
                "cannot change lease of a live Guard attachment".into(),
            ));
        }
        // A lease renewal advances the authorized generation for the same lease,
        // so reservations commit against the generation the worker owns now.
        if let Some(guard) = running {
            {
                let mut bound = guard.fence.write().map_err(|_| {
                    CoreError::Unavailable("Guard ownership fence is poisoned".into())
                })?;
                if bound.lease_id == fence.lease_id && fence.generation < bound.generation {
                    return Ok(());
                }
                *bound = fence;
            }
            if let Some(gateway) = guard.gateway.lock().await.as_ref() {
                let _ = gateway.set_fence(fence);
            }
        }
        let mut fences = self
            .fences
            .write()
            .map_err(|_| CoreError::Unavailable("Guard lease context poisoned".into()))?;
        if let Some(previous) = fences.get(&sandbox.id) {
            if previous.tenant_id != sandbox.tenant_id || previous.node_id != sandbox.node_id {
                return Err(CoreError::InvalidRequest(
                    "Guard lease ownership mismatch".into(),
                ));
            }
            if previous.fence.lease_id == fence.lease_id
                && previous.fence.generation > fence.generation
            {
                return Ok(());
            }
        }
        fences.insert(
            sandbox.id,
            LeaseContext {
                tenant_id: sandbox.tenant_id,
                node_id: sandbox.node_id,
                fence,
            },
        );
        Ok(())
    }

    async fn bound_guard(
        &self,
        sandbox: &Sandbox,
        policy_hash: &str,
        fence: GuardFence,
    ) -> Result<Arc<RunningGuard>, CoreError> {
        let guard = self
            .running
            .lock()
            .await
            .get(&sandbox.id)
            .cloned()
            .ok_or_else(|| CoreError::Unavailable("Guard attachment is not running".into()))?;
        let (context_tenant, context_node, context_fence) = {
            let contexts = self
                .fences
                .read()
                .map_err(|_| CoreError::Unavailable("Guard lease context poisoned".into()))?;
            let context = contexts
                .get(&sandbox.id)
                .ok_or_else(|| CoreError::Unavailable("Guard lease context missing".into()))?;
            (context.tenant_id, context.node_id, context.fence)
        };
        if context_tenant != sandbox.tenant_id
            || context_node != sandbox.node_id
            || context_fence.lease_id != fence.lease_id
            || guard.fence.read().map(|bound| bound.lease_id).ok() != Some(fence.lease_id)
            || fence.generation < 0
            || fence.generation < context_fence.generation
        {
            return Err(CoreError::InvalidRequest(
                "Guard action ownership fence mismatch".into(),
            ));
        }
        // A renewal advances the generation of the same lease, so a worker whose
        // ownership was re-checked moments ago legitimately presents a newer one
        // than the context recorded at startup. Refusing that would leave a
        // healthy attachment unusable for the life of the lease; what must not be
        // accepted is a *different* lease, and that is refused above.
        if fence.generation > context_fence.generation {
            {
                let mut bound = guard.fence.write().map_err(|_| {
                    CoreError::Unavailable("Guard ownership fence is poisoned".into())
                })?;
                if bound.lease_id != fence.lease_id || fence.generation < bound.generation {
                    return Err(CoreError::InvalidRequest(
                        "Guard action ownership fence mismatch".into(),
                    ));
                }
                *bound = fence;
            }
            if let Some(gateway) = guard.gateway.lock().await.as_ref() {
                let _ = gateway.set_fence(fence);
            }
            let mut contexts = self
                .fences
                .write()
                .map_err(|_| CoreError::Unavailable("Guard lease context poisoned".into()))?;
            if let Some(entry) = contexts.get_mut(&sandbox.id)
                && entry.fence.lease_id == fence.lease_id
            {
                entry.fence = fence;
            }
        }
        if guard.attachment.sandbox_id != sandbox.id
            || guard.attachment.tenant_id != sandbox.tenant_id
            || guard.node_id != sandbox.node_id
            || guard.control.policy_hash() != policy_hash
            || guard.released.load(Ordering::Acquire)
        {
            return Err(CoreError::InvalidRequest(
                "Guard attachment identity mismatch".into(),
            ));
        }
        Ok(guard)
    }

    /// Reports liveness for every live attachment this manager owns.
    ///
    /// This is the manager's own heartbeat, not the gateway's: the first one
    /// also installs the attachment's packet rules, and a gateway that merely
    /// stops refusing would leave the kernel denying everything.
    pub async fn heartbeat_every_attachment(&self) {
        let entries: Vec<(Uuid, Arc<RunningGuard>)> = {
            let running = self.running.lock().await;
            running
                .iter()
                .map(|(id, guard)| (*id, guard.clone()))
                .collect()
        };
        let contexts = match self.fences.read() {
            Ok(contexts) => contexts.clone(),
            Err(_) => return,
        };
        for (sandbox_id, guard) in entries {
            let Some(context) = contexts.get(&sandbox_id) else {
                continue;
            };
            let sandbox = Sandbox {
                id: sandbox_id,
                tenant_id: context.tenant_id,
                node_id: context.node_id,
                image_id: String::new(),
                state: aiec_core::SandboxState::Running,
                runtime: aiec_core::RuntimeKind::Firecracker,
                cpu: 0,
                memory_mb: 0,
                disk_mb: 0,
                timeout_seconds: 0,
                network: Default::default(),
                environment: Default::default(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                runtime_path: None,
            };
            let policy_hash = guard.control.policy_hash();
            let fence = context.fence;
            if let Err(error) = self.guard_heartbeat(&sandbox, &policy_hash, fence).await {
                eprintln!("guard heartbeat refused for {sandbox_id}: {error}");
            }
        }
    }

    /// Whether every live attachment has been activated by a heartbeat.
    pub async fn attachments_active(&self) -> bool {
        let guards: Vec<Arc<RunningGuard>> = self.running.lock().await.values().cloned().collect();
        let total = guards.len();
        if total == 0 {
            return true;
        }
        let mut active = 0usize;
        for guard in &guards {
            if let Some(gateway) = guard.gateway.lock().await.as_ref()
                && !gateway.network_cut()
                && !guard.kernel_cut.load(Ordering::Acquire)
            {
                active += 1;
            }
        }
        active == total
    }

    /// How many attachments this manager currently owns.
    pub async fn attachment_count(&self) -> usize {
        self.running.lock().await.len()
    }

    /// The proposal store for a live attachment, built on the same policy cell
    /// the gateway enforces.
    ///
    /// The store lives here rather than in the control plane on purpose: the
    /// live policy and the kernel rules are this process's, so an approved
    /// proposal can only take effect where it is enforced. The control plane
    /// records the human decision and dispatches; this applies it.
    pub async fn proposal_store(
        &self,
        sandbox: &Sandbox,
        policy_hash: &str,
        fence: GuardFence,
    ) -> Result<Arc<ProposalStore>, CoreError> {
        let guard = self.bound_guard(sandbox, policy_hash, fence).await?;
        if let Some(store) = guard.proposals.lock().await.as_ref() {
            return Ok(store.clone());
        }
        // The policy cell is taken from the gateway and the store is built
        // without holding the gateway lock, so an apply can never be blocked by
        // a decision that is waiting on this store.
        let policy = {
            let gateway = guard.gateway.lock().await;
            gateway
                .as_ref()
                .ok_or_else(|| CoreError::Unavailable("Guard gateway stopped".into()))?
                .control()
                .policy()
        };
        let boundary = guard
            .boundary
            .clone()
            .ok_or_else(|| CoreError::Unavailable("operator boundary is not loaded".into()))?;
        let store = Arc::new(
            ProposalStore::new(ProposalStoreConfig {
                sandbox_id: sandbox.id,
                tenant_id: sandbox.tenant_id,
                boundary,
                policy,
                enforcement: self.enforcement.clone(),
                attachment: guard.attachment.clone(),
                events: guard.events.clone(),
            })
            .map_err(guard_error)?,
        );
        *guard.proposals.lock().await = Some(store.clone());
        Ok(store)
    }

    pub async fn guard_heartbeat(
        &self,
        sandbox: &Sandbox,
        policy_hash: &str,
        fence: GuardFence,
    ) -> Result<(), CoreError> {
        let guard = self.bound_guard(sandbox, policy_hash, fence).await?;
        let gateway = guard.gateway.lock().await;
        let gateway = gateway
            .as_ref()
            .ok_or_else(|| CoreError::Unavailable("Guard gateway stopped".into()))?;
        let _kernel = guard.kernel.lock().await;
        if guard.released.load(Ordering::Acquire) {
            return Err(CoreError::Unavailable("Guard attachment released".into()));
        }
        let first = gateway
            .heartbeat(&GuardIdentity {
                sandbox_id: sandbox.id,
                tenant_id: sandbox.tenant_id,
                policy_hash: policy_hash.to_owned(),
            })
            .map_err(guard_error)?;
        if first {
            if let Err(error) = self
                .enforcement
                .restore_network(guard.policy.load().compiled(), &guard.attachment)
                .await
            {
                let _ = gateway.cut();
                let _ = self.enforcement.cut_network(&guard.attachment).await;
                return Err(guard_error(error));
            }
            guard.kernel_cut.store(false, Ordering::Release);
            if gateway.network_cut() {
                self.enforcement
                    .cut_network(&guard.attachment)
                    .await
                    .map_err(guard_error)?;
                return Err(CoreError::Unavailable("Guard activation expired".into()));
            }
        }
        Ok(())
    }

    pub async fn guard_cut(
        &self,
        sandbox: &Sandbox,
        policy_hash: &str,
        fence: GuardFence,
    ) -> Result<(), CoreError> {
        let guard = self.bound_guard(sandbox, policy_hash, fence).await?;
        // Cut the gateway before any kernel I/O. Audit failure never skips nft.
        let gateway_result = guard.control.cut().map_err(guard_error);
        let kernel_result = AttachmentCut {
            guard: Arc::downgrade(&guard),
            enforcement: self.enforcement.clone(),
        }
        .cut_network()
        .await
        .map_err(guard_error);
        kernel_result?;
        gateway_result
    }

    /// Caller must authenticate and fence an explicit operator release.
    pub async fn guard_restore(
        &self,
        sandbox: &Sandbox,
        policy_hash: &str,
        fence: GuardFence,
    ) -> Result<(), CoreError> {
        let guard = self.bound_guard(sandbox, policy_hash, fence).await?;
        let gateway = guard.gateway.lock().await;
        let gateway = gateway
            .as_ref()
            .ok_or_else(|| CoreError::Unavailable("Guard gateway stopped".into()))?;
        // No kernel mutex while waiting for the durable release event:
        // the watchdog must be able to cut nft even if that journal hangs.
        // This is the authorized path, reserved for a caller that has already
        // proved the operator decision; an ordinary release cannot reopen a
        // cut the dead-man switch latched.
        gateway.authorized_release().await.map_err(guard_error)?;
        let _kernel = guard.kernel.lock().await;
        if guard.released.load(Ordering::Acquire) || gateway.network_cut() {
            return Err(CoreError::Unavailable(
                "Guard release fenced by attachment cut".into(),
            ));
        }
        if let Err(error) = self
            .enforcement
            .restore_network(guard.policy.load().compiled(), &guard.attachment)
            .await
        {
            let _ = gateway.cut();
            let _ = self.enforcement.cut_network(&guard.attachment).await;
            return Err(guard_error(error));
        }
        guard.kernel_cut.store(false, Ordering::Release);
        ip(&["link", "set", "dev", &guard.attachment.interface, "up"]).await?;
        if gateway.network_cut() {
            self.enforcement
                .cut_network(&guard.attachment)
                .await
                .map_err(guard_error)?;
            return Err(CoreError::Unavailable("Guard release expired".into()));
        }
        Ok(())
    }

    pub async fn guard_observation(
        &self,
        sandbox: &Sandbox,
        policy_hash: &str,
        fence: GuardFence,
        after: u64,
    ) -> Result<GuardRuntimeObservation, CoreError> {
        let guard = self.bound_guard(sandbox, policy_hash, fence).await?;
        let counters = self
            .enforcement
            .counters(&guard.attachment)
            .await
            .map_err(guard_error)?;
        let sink = guard.events.clone();
        let (page, head) = tokio::task::spawn_blocking(move || sink.verified_snapshot(after))
            .await
            .map_err(|_| CoreError::Unavailable("Guard journal verification task failed".into()))?
            .map_err(guard_error)?;
        if page.events.iter().any(|event| {
            event.sandbox_id != sandbox.id
                || event.tenant_id != sandbox.tenant_id
                || event.policy_hash != policy_hash
        }) {
            return Err(CoreError::Unavailable(
                "Guard journal identity mismatch".into(),
            ));
        }
        Ok(GuardRuntimeObservation {
            identity: GuardIdentity {
                sandbox_id: sandbox.id,
                tenant_id: sandbox.tenant_id,
                policy_hash: policy_hash.to_owned(),
            },
            counters,
            events: page.events,
            observed_at: chrono::Utc::now(),
            event_start_sequence: page.offset as u64 + 1,
            event_previous_hash: page
                .first_previous_hash
                .unwrap_or_else(|| head.head_hash.clone()),
            event_sequence: head.count,
            event_head: head.head_hash,
            network_cut: guard.control.network_cut(),
        })
    }

    pub async fn guard_append_event(
        &self,
        sandbox: &Sandbox,
        policy_hash: &str,
        fence: GuardFence,
        event: EventInput,
    ) -> Result<GuardEvent, CoreError> {
        let guard = self.bound_guard(sandbox, policy_hash, fence).await?;
        if event.sandbox_id != sandbox.id
            || event.tenant_id != sandbox.tenant_id
            || event.policy_hash != policy_hash
        {
            return Err(CoreError::InvalidRequest(
                "Guard event identity mismatch".into(),
            ));
        }
        // Reuse the gateway's file owner; never acquire a second writer lock.
        guard.events.append(event).await.map_err(guard_error)
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

    async fn create_guard(&self, sandbox: &Sandbox) -> Result<Arc<RunningGuard>, CoreError> {
        let authority = self
            .budget_authority
            .read()
            .map_err(|_| {
                CoreError::Unavailable("Guard budget authority configuration poisoned".into())
            })?
            .clone()
            .ok_or_else(|| {
                CoreError::Unavailable(
                    "guarded workloads require an external durable budget authority".into(),
                )
            })?;
        let context = self
            .fences
            .read()
            .map_err(|_| CoreError::Unavailable("Guard lease context poisoned".into()))?
            .get(&sandbox.id)
            .copied()
            .ok_or_else(|| {
                CoreError::Unavailable(
                    "Guard requires an authorized ownership fence before attachment".into(),
                )
            })?;
        if context.tenant_id != sandbox.tenant_id || context.node_id != sandbox.node_id {
            return Err(CoreError::InvalidRequest(
                "Guard lease ownership mismatch".into(),
            ));
        }
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
                .cut_network(&attachment)
                .await
                .map_err(|e| CoreError::Unavailable(format!("guard nftables apply: {e}")))?;
            // The layer 7 policy rides with the sandbox, not with the network
            // policy: it changes what Guard may see, and the operator's
            // acknowledgement for interception is checked again here.
            let l7 = sandbox
                .environment
                .guard
                .as_ref()
                .and_then(|guard| guard.l7.clone());
            let gateway = GuardGateway::start_with_l7(GatewayConfig {
                compiled: compiled.clone(),
                sandbox_id: sandbox.id,
                tenant_id: sandbox.tenant_id,
                fence: context.fence,
                bind_ip: gateway_ip,
                guest_ip,
                broker_port: BROKER_PORT,
                dns_port: DNS_PORT,
                credentials: Arc::new(credentials),
                events: events.clone(),
                budget_authority: authority,
                watchdog_timeout: Duration::from_millis(config.watchdog_timeout_ms),
            }, l7)
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
            let control = gateway.control();
            let guard = Arc::new(RunningGuard {
                attachment: attachment.clone(),
                node_id: sandbox.node_id,
                policy: gateway.control().policy(),
                fence: std::sync::RwLock::new(context.fence),
                control,
                gateway: Mutex::new(Some(gateway)),
                events: events.clone(),
                kernel: Mutex::new(()),
                released: AtomicBool::new(false),
                kernel_cut: AtomicBool::new(true),
                boundary: Some(boundary),
                proposals: Mutex::new(None),
            });
            {
                let gateway = guard.gateway.lock().await;
                let gateway = gateway.as_ref().expect("new gateway");
                gateway.set_network_cut_handler(Arc::new(AttachmentCut {
                    guard: Arc::downgrade(&guard),
                    enforcement: self.enforcement.clone(),
                }));
                // Canaries are optional and are only constructed when the
                // sandbox configures one. Only the two observations the host
                // actually sees are wired: a resolved name and a presented
                // credential. A file the guest reads is not visible outside the
                // guest, so it is not wired to an authoritative action here.
                if let Some(guard_config) = &sandbox.environment.guard {
                    let monitor = CanaryMonitor::new(
                        &guard_config.canaries,
                        GuardIdentity {
                            sandbox_id: sandbox.id,
                            tenant_id: sandbox.tenant_id,
                            policy_hash: compiled.policy_hash().to_owned(),
                        },
                        context.fence,
                        events.clone(),
                        Arc::new(AttachmentCanaryEnforcer {
                            guard: Arc::downgrade(&guard),
                            cut: self.enforcement.clone(),
                        }),
                    )
                    .map_err(guard_error)?;
                    if let Some(monitor) = monitor {
                        gateway.control().set_canaries(monitor);
                    }
                }
            }
            Ok::<_, CoreError>(guard)
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

    fn configure_guard_budget_authority(
        &self,
        authority: Arc<dyn BudgetAuthority>,
    ) -> Result<(), CoreError> {
        self.configure_budget_authority(authority)
    }

    async fn guard_set_fence(&self, sandbox: &Sandbox, fence: GuardFence) -> Result<(), CoreError> {
        GuardNetworkManager::guard_set_fence(self, sandbox, fence).await
    }

    async fn guard_control(
        &self,
        sandbox: &Sandbox,
        fence: GuardFence,
        command: GuardControlCommand,
    ) -> Result<GuardControlResponse, CoreError> {
        match command {
            GuardControlCommand::SetFence { fence } => {
                self.guard_set_fence(sandbox, fence).await?;
                Ok(GuardControlResponse::Unit)
            }
            GuardControlCommand::ApplyProposal {
                proposal,
                approved_by,
            } => {
                if proposal.sandbox_id != sandbox.id || proposal.tenant_id != sandbox.tenant_id {
                    return Err(CoreError::InvalidRequest(
                        "proposal belongs to another sandbox or tenant".into(),
                    ));
                }
                let base = proposal.base_policy_hash.clone();
                let store = self.proposal_store(sandbox, &base, fence).await?;
                match store.apply_attested(proposal.clone(), &approved_by).await {
                    Ok(outcome) => Ok(GuardControlResponse::PolicyApplied {
                        proposal_id: outcome.proposal_id,
                        previous_policy_hash: outcome.previous_policy_hash,
                        policy_hash: outcome.policy_hash,
                        already_applied: false,
                    }),
                    // The apply already happened; the control plane is retrying
                    // after a lost response and needs the same answer, not a
                    // second ruleset install and a second audit record.
                    Err(aiec_guard::GuardError::AlreadyApplied(detail)) => {
                        let hash = detail
                            .rsplit_once(':')
                            .map(|(_, hash)| hash.to_owned())
                            .ok_or_else(|| {
                                CoreError::Unavailable(
                                    "replayed apply carried no policy hash".into(),
                                )
                            })?;
                        Ok(GuardControlResponse::PolicyApplied {
                            proposal_id: proposal.id,
                            previous_policy_hash: base,
                            policy_hash: hash,
                            already_applied: true,
                        })
                    }
                    Err(error) => Err(guard_error(error)),
                }
            }
            // A release is the same fenced restore an operator already uses:
            // it clears the latch through the gateway's authorized path and
            // reinstalls the rules, and only then does the control plane call
            // the sandbox released.
            GuardControlCommand::Release { policy_hash } => {
                self.guard_restore(sandbox, &policy_hash, fence).await?;
                Ok(GuardControlResponse::Released {
                    policy_hash: policy_hash.to_owned(),
                })
            }
            GuardControlCommand::Heartbeat { policy_hash } => {
                self.guard_heartbeat(sandbox, &policy_hash, fence).await?;
                Ok(GuardControlResponse::Unit)
            }
            GuardControlCommand::Cut { policy_hash } => {
                self.guard_cut(sandbox, &policy_hash, fence).await?;
                Ok(GuardControlResponse::Unit)
            }
            GuardControlCommand::Observe { policy_hash, after } => {
                Ok(GuardControlResponse::Observation(
                    self.guard_observation(sandbox, &policy_hash, fence, after)
                        .await?,
                ))
            }
            GuardControlCommand::AppendEvent { policy_hash, event } => {
                Ok(GuardControlResponse::Event(
                    self.guard_append_event(sandbox, &policy_hash, fence, event)
                        .await?,
                ))
            }
            GuardControlCommand::CapturePaused { .. } => Err(CoreError::Unsupported(
                "paused Guard capture belongs to the runtime".into(),
            )),
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
        let _preparing = self.preparing.lock().await;
        if self.running.lock().await.contains_key(&sandbox.id) {
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
        self.running.lock().await.insert(sandbox.id, guard);
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
        let running = self.running.lock().await.remove(&sandbox.id);
        if let Some(running) = running {
            running.released.store(true, Ordering::Release);
            let _ = running.control.cut();
            let gateway = running.gateway.lock().await.take();
            if let Some(gateway) = gateway {
                let _ = gateway.cut();
                gateway.shutdown().await.map_err(guard_error)?;
            }
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
        self.fences
            .write()
            .map_err(|_| CoreError::Unavailable("Guard lease context poisoned".into()))?
            .remove(&sandbox.id);
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
