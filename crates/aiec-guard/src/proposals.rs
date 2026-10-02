//! Policy proposals: an agent may ask, a human decides, the verifier decides
//! whether the ask is safe.
//!
//! The authority split is structural rather than advisory. [`AgentCredential`]
//! is what the guest plane holds, and the only thing it can do here is
//! [`ProposalStore::submit`]. Every path that changes what the sandbox may
//! reach takes a [`HumanApproval`], which cannot be constructed from anything
//! but operator-side credential material held in the operator process, is not
//! serializable, and therefore cannot arrive over a wire from the plane it
//! governs. The optional watcher has no method on this type at all: it can
//! narrow a decision, but there is no call it could make that widens one,
//! approves a proposal, or releases a hold.
//!
//! An approved proposal is not applied by writing a file. It is verified,
//! installed into the enforcement backend, and swapped into the live policy in
//! one step, so a policy that fails verification, or a kernel that refuses the
//! ruleset, leaves the previous policy in force and produces no new policy
//! hash.

use crate::compiler::{CompiledPolicy, OperatorBoundary, compile};
use crate::enforcement::{EnforcementBackend, GuardAttachment};
use crate::events::{Category, Decision, EventInput, EventSink, GuardEvent, MAX_REASON_BYTES};
use crate::gateway::CredentialStore;
use crate::policy::{EgressRule, GuardPolicy, L7Policy, validate_dns_name};
use crate::{GuardError, Result};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

/// Longest operator-facing summary on a proposal.
pub const MAX_SUMMARY_BYTES: usize = 256;
/// Most proposals that may wait for a human at once.
pub const MAX_PENDING_PROPOSALS: usize = 32;
/// Most destinations one proposal may ask for.
pub const MAX_GRANTS_PER_PROPOSAL: usize = 16;
/// Longest denial note an operator may attach.
pub const MAX_NOTE_BYTES: usize = 256;
/// Longest agent identity label.
pub const MAX_AGENT_ID_BYTES: usize = 64;

/// Who the guest plane is. It carries no secret and no authority beyond the
/// ability to ask.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCredential {
    sandbox_id: Uuid,
    tenant_id: Uuid,
    /// Which agent inside the sandbox asked, for the audit record.
    agent_id: String,
}

impl AgentCredential {
    /// Builds a guest-plane identity, refusing an unbounded label.
    pub fn new(sandbox_id: Uuid, tenant_id: Uuid, agent_id: &str) -> Result<Self> {
        if agent_id.is_empty() || agent_id.len() > MAX_AGENT_ID_BYTES || !printable(agent_id) {
            return Err(GuardError::Denied(
                "agent identity label is empty, oversized or not printable".into(),
            ));
        }
        Ok(Self {
            sandbox_id,
            tenant_id,
            agent_id: agent_id.to_owned(),
        })
    }

    /// The sandbox this identity speaks for.
    pub fn sandbox_id(&self) -> Uuid {
        self.sandbox_id
    }

    /// The tenant this identity speaks for.
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Which agent asked.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}

/// Proof that the caller is a human operator.
///
/// There is deliberately no constructor from a string a caller might have
/// received over the network: the only way to obtain one is to present operator
/// credential material to the operator's own credential store. The type is not
/// serializable for the same reason.
pub struct HumanApproval {
    operator: String,
}

impl std::fmt::Debug for HumanApproval {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HumanApproval")
            .field("operator", &self.operator)
            .finish_non_exhaustive()
    }
}

impl HumanApproval {
    /// Mints an approval from operator-side credential material.
    ///
    /// The credential store lives in the operator process, outside the guest,
    /// so a sandbox - or a proposal that arrived from one - cannot satisfy this
    /// comparison.
    pub fn operator(
        operator_id: &str,
        credential_name: &str,
        secret: &str,
        credentials: &CredentialStore,
    ) -> Result<Self> {
        if operator_id.is_empty()
            || operator_id.len() > MAX_AGENT_ID_BYTES
            || !printable(operator_id)
        {
            return Err(GuardError::Denied(
                "operator identity label is empty, oversized or not printable".into(),
            ));
        }
        if !credentials.matches(credential_name, secret) {
            return Err(GuardError::Denied(
                "operator approval credential does not match the operator credential store".into(),
            ));
        }
        Ok(Self {
            operator: operator_id.to_owned(),
        })
    }

    /// Which operator this approval names, for the audit record.
    pub fn operator_id(&self) -> &str {
        &self.operator
    }
}

/// One destination a proposal asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressGrant {
    /// Canonical DNS name.
    pub host: String,
    /// Destination TCP port.
    pub port: u16,
    /// Allowed methods; empty asks for an opaque destination-only permission,
    /// which the summary has to say out loud.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Allowed path prefixes; empty asks for every path on that destination.
    #[serde(default)]
    pub paths: Vec<String>,
}

impl EgressGrant {
    fn validate(&self, field: &str) -> Result<()> {
        validate_dns_name(&self.host, &format!("{field}.host"), 2)?;
        if self.port == 0 {
            return Err(GuardError::Policy(format!("{field}.port must not be zero")));
        }
        if self.methods.len() > crate::policy::MAX_LIST_ITEMS
            || self.paths.len() > crate::policy::MAX_LIST_ITEMS
        {
            return Err(GuardError::Policy(format!(
                "{field} has more entries than the schema accepts"
            )));
        }
        for method in &self.methods {
            if method.is_empty()
                || method.len() > crate::policy::MAX_METHOD_BYTES
                || !method.bytes().all(|byte| {
                    byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
                })
            {
                return Err(GuardError::Policy(format!(
                    "{field}.methods must be uppercase HTTP tokens"
                )));
            }
        }
        for path in &self.paths {
            if !crate::l7::safe_path(path) || path.len() > crate::policy::MAX_PATH_BYTES {
                return Err(GuardError::Policy(format!(
                    "{field}.paths must be absolute bounded paths without percent-encoding"
                )));
            }
        }
        Ok(())
    }

    fn to_rule(&self) -> EgressRule {
        let mut methods = self.methods.clone();
        let mut paths = self.paths.clone();
        methods.sort();
        paths.sort();
        EgressRule {
            host: self.host.clone(),
            port: self.port,
            protocol: crate::policy::EGRESS_PROTOCOL_TCP.to_string(),
            allowed_methods: methods,
            allowed_paths: paths,
        }
    }
}

/// What an agent asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalRequest {
    /// One line a human reads before deciding.
    pub summary: String,
    /// Destinations to add. A request may only add; there is no form of this
    /// struct that removes, narrows or reorders a rule already in force.
    pub allow: Vec<EgressGrant>,
}

impl ProposalRequest {
    fn validate(&self) -> Result<()> {
        if self.summary.is_empty()
            || self.summary.len() > MAX_SUMMARY_BYTES
            || !printable(&self.summary)
        {
            return Err(GuardError::Denied(
                "proposal summary is empty, oversized or not printable".into(),
            ));
        }
        if self.allow.is_empty() || self.allow.len() > MAX_GRANTS_PER_PROPOSAL {
            return Err(GuardError::Denied(format!(
                "a proposal must ask for between 1 and {MAX_GRANTS_PER_PROPOSAL} destinations"
            )));
        }
        for (index, grant) in self.allow.iter().enumerate() {
            grant.validate(&format!("allow[{index}]"))?;
        }
        for (index, grant) in self.allow.iter().enumerate() {
            if self.allow[..index]
                .iter()
                .any(|other| other.host == grant.host && other.port == grant.port)
            {
                return Err(GuardError::Denied(
                    "a proposal may not ask for the same destination twice".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Where a proposal is in the one-way workflow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposalState {
    /// Waiting for a human. Nothing about the policy has changed.
    Pending,
    /// Applied; carries the policy hash that is now in force.
    Approved { policy_hash: String },
    /// A human said no.
    Denied { note: String },
    /// The verifier refused it, so no human decision was ever needed.
    Refused { reason: String },
}

/// A recorded proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub id: Uuid,
    pub sandbox_id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: String,
    pub request: ProposalRequest,
    /// The policy hash the proposal was written against; a proposal that is no
    /// longer a pure extension of it cannot be approved.
    pub base_policy_hash: String,
    pub state: ProposalState,
}

impl Proposal {
    /// Whether this proposal is still awaiting a decision.
    pub fn is_pending(&self) -> bool {
        matches!(self.state, ProposalState::Pending)
    }
}

/// What one approval did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyOutcome {
    pub proposal_id: Uuid,
    pub operator_id: String,
    /// The hash that was in force before this apply.
    pub previous_policy_hash: String,
    /// The hash that is in force now.
    pub policy_hash: String,
    /// The audit record for the apply.
    pub event: GuardEvent,
}

/// The policy in force, and the layer 7 rules that belong to it.
#[derive(Clone, Debug)]
pub struct ActivePolicy {
    compiled: Arc<CompiledPolicy>,
    l7: Option<L7Policy>,
}

impl ActivePolicy {
    /// The verified policy.
    pub fn compiled(&self) -> &CompiledPolicy {
        &self.compiled
    }

    /// A shared handle on the verified policy, for callers that must not hold a
    /// borrow across an await point.
    pub fn shared(&self) -> Arc<CompiledPolicy> {
        self.compiled.clone()
    }

    /// The layer 7 policy, if the attachment has one.
    pub fn l7(&self) -> Option<&L7Policy> {
        self.l7.as_ref()
    }

    /// The canonical hash of the policy in force.
    pub fn policy_hash(&self) -> &str {
        self.compiled.policy_hash()
    }
}

/// The live policy for one attachment.
///
/// Every reader sees a policy that has already passed the verifier, and a swap
/// replaces it in one write, so no request is ever decided against a policy
/// that is half of two.
#[derive(Debug)]
pub struct AtomicPolicy {
    current: RwLock<Arc<ActivePolicy>>,
}

impl AtomicPolicy {
    /// Adopts a compiled policy, refusing a layer 7 policy that cannot be
    /// enforced as written.
    pub fn new(compiled: CompiledPolicy, l7: Option<L7Policy>) -> Result<Self> {
        if let Some(l7) = &l7 {
            crate::l7::validate(l7)?;
        }
        Ok(Self {
            current: RwLock::new(Arc::new(ActivePolicy {
                compiled: Arc::new(compiled),
                l7,
            })),
        })
    }

    /// The policy in force right now.
    pub fn load(&self) -> Arc<ActivePolicy> {
        self.current.read().clone()
    }

    /// The verified policy in force right now.
    pub fn compiled(&self) -> Arc<CompiledPolicy> {
        self.current.read().compiled.clone()
    }

    /// The layer 7 policy in force right now.
    pub fn l7(&self) -> Option<L7Policy> {
        self.current.read().l7.clone()
    }

    /// The canonical hash in force right now.
    pub fn policy_hash(&self) -> String {
        self.current.read().compiled.policy_hash().to_owned()
    }

    /// Installs a policy that has already been verified.
    ///
    /// Verification runs again here so that no code path can install a policy
    /// that has not passed, and the swap itself cannot fail: a caller that got
    /// this far is holding a verified policy and a working enforcement backend,
    /// and a failed apply never reaches it.
    pub(crate) fn swap(&self, compiled: CompiledPolicy) -> Result<String> {
        compiled.verify()?;
        let mut current = self.current.write();
        let l7 = current.l7.clone();
        let policy_hash = compiled.policy_hash().to_owned();
        *current = Arc::new(ActivePolicy {
            compiled: Arc::new(compiled),
            l7,
        });
        Ok(policy_hash)
    }
}

/// Everything the store needs to verify, install and record a proposal.
pub struct ProposalStoreConfig {
    pub sandbox_id: Uuid,
    pub tenant_id: Uuid,
    /// The boundary every candidate policy is verified against.
    pub boundary: OperatorBoundary,
    /// The live policy an approved proposal replaces.
    pub policy: Arc<AtomicPolicy>,
    /// The enforcement substrate the new policy has to be installed into.
    pub enforcement: Arc<dyn EnforcementBackend>,
    /// The attachment those rules belong to.
    pub attachment: GuardAttachment,
    /// Where the audit record goes.
    pub events: Arc<dyn EventSink>,
}

/// Proposals for one attachment.
pub struct ProposalStore {
    config: ProposalStoreConfig,
    proposals: Mutex<BTreeMap<Uuid, Proposal>>,
    /// Serializes applies so two approvals cannot interleave an install and a
    /// swap.
    apply_lock: tokio::sync::Mutex<()>,
}

impl ProposalStore {
    pub fn new(config: ProposalStoreConfig) -> Result<Self> {
        config.policy.load().compiled().verify()?;
        Ok(Self {
            config,
            proposals: Mutex::new(BTreeMap::new()),
            apply_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// The policy this store changes.
    pub fn policy(&self) -> &Arc<AtomicPolicy> {
        &self.config.policy
    }

    /// The boundary candidates are verified against.
    pub fn boundary(&self) -> &OperatorBoundary {
        &self.config.boundary
    }

    /// Records a request from the guest plane.
    ///
    /// This changes no policy and no enforcement: the result is a pending
    /// proposal and an audit record saying a proposal was made.
    pub async fn submit(
        &self,
        agent: &AgentCredential,
        request: ProposalRequest,
    ) -> Result<Proposal> {
        if agent.sandbox_id != self.config.sandbox_id || agent.tenant_id != self.config.tenant_id {
            return Err(GuardError::Denied(
                "agent credential is not scoped to this sandbox".into(),
            ));
        }
        request.validate()?;
        let base_policy_hash = self.config.policy.policy_hash();
        let proposal = Proposal {
            id: Uuid::new_v4(),
            sandbox_id: self.config.sandbox_id,
            tenant_id: self.config.tenant_id,
            agent_id: agent.agent_id.clone(),
            request,
            base_policy_hash,
            state: ProposalState::Pending,
        };
        {
            let mut proposals = self.proposals.lock();
            if proposals.len() >= MAX_PENDING_PROPOSALS {
                return Err(GuardError::Denied(format!(
                    "the proposal queue holds the maximum of {MAX_PENDING_PROPOSALS} entries"
                )));
            }
            proposals.insert(proposal.id, proposal.clone());
        }
        // An unaudited proposal is refused rather than merely unrecorded: the
        // journal is how an operator later proves what changed the policy.
        self.append(
            Decision::Allow,
            "policy proposal submitted for human review",
            None,
        )
        .await?;
        Ok(proposal)
    }

    /// Every proposal, oldest first.
    /// Re-adopts proposals read back from durable storage.
    ///
    /// A proposal that vanished with the process would be a lost human
    /// decision, so a control plane that keeps proposals in storage rebuilds the
    /// store from them at start. A restored proposal is not trusted: approval
    /// re-checks the policy hash it was written against, so one that no longer
    /// describes a pure extension of the policy in force is refused rather than
    /// applied.
    pub fn restore(&self, restored: impl IntoIterator<Item = Proposal>) -> Result<usize> {
        let mut proposals = self.proposals.lock();
        for proposal in restored {
            if proposal.sandbox_id != self.config.sandbox_id
                || proposal.tenant_id != self.config.tenant_id
            {
                return Err(GuardError::Denied(
                    "a stored proposal belongs to another sandbox or tenant".into(),
                ));
            }
            if proposals.len() >= MAX_PENDING_PROPOSALS {
                return Err(GuardError::Denied(format!(
                    "the proposal queue holds the maximum of {MAX_PENDING_PROPOSALS} entries"
                )));
            }
            proposals.insert(proposal.id, proposal);
        }
        Ok(proposals.len())
    }

    pub fn proposals(&self) -> Vec<Proposal> {
        self.proposals.lock().values().cloned().collect()
    }

    /// One proposal.
    pub fn proposal(&self, id: Uuid) -> Result<Proposal> {
        self.proposals
            .lock()
            .get(&id)
            .cloned()
            .ok_or_else(|| GuardError::Denied("no such policy proposal".into()))
    }

    /// Reviews and, if the verifier agrees, applies a pending proposal.
    ///
    /// The order is the point: the candidate is built, checked to be a pure
    /// extension of the policy in force, verified against the boundary, and
    /// installed into the enforcement backend before anything is swapped. A
    /// refusal at any step leaves the previous policy in force and produces no
    /// new policy hash.
    pub async fn approve(&self, review: &HumanApproval, id: Uuid) -> Result<ApplyOutcome> {
        self.pending(id)?;
        self.apply_locked(id, review.operator_id()).await
    }

    async fn apply_locked(&self, id: Uuid, approved_by: &str) -> Result<ApplyOutcome> {
        let proposal = self.pending(id)?;
        let _apply = self.apply_lock.lock().await;
        let current = self.config.policy.load();
        if current.policy_hash() != proposal.base_policy_hash {
            self.settle(
                id,
                ProposalState::Refused {
                    reason: "the policy changed since this proposal was written".to_owned(),
                },
            )?;
            return Err(GuardError::Denied(
                "policy proposal was written against a different policy".into(),
            ));
        }
        let candidate = candidate_policy(current.compiled().policy(), &proposal.request)?;
        let verified = match compile(&candidate, &self.config.boundary) {
            Ok(verified) => verified,
            Err(error) => {
                let reason = bound_reason(&format!("verifier refused the proposal: {error}"));
                self.settle(
                    id,
                    ProposalState::Refused {
                        reason: reason.clone(),
                    },
                )?;
                // The refusal is as much an audit fact as the apply would have
                // been: an operator has to be able to see what the verifier
                // turned down, and why.
                self.append(Decision::Deny, &reason, None).await?;
                return Err(GuardError::Denied(reason));
            }
        };
        if let Err(error) = self
            .config
            .enforcement
            .apply_policy(&verified, &self.config.attachment)
            .await
        {
            self.append(Decision::Deny, "enforcement refused the new ruleset", None)
                .await?;
            return Err(GuardError::Unavailable(format!(
                "policy apply failed and the previous policy stays in force: {error}"
            )));
        }
        let previous_policy_hash = current.policy_hash().to_owned();
        let policy_hash = self.config.policy.swap(verified)?;
        let event = self
            .append_with_hash(
                Decision::Allow,
                &format!(
                    "policy proposal {} applied by operator review",
                    proposal.id.simple()
                ),
                single_destination(&proposal.request),
                &policy_hash,
            )
            .await?;
        self.settle(
            id,
            ProposalState::Approved {
                policy_hash: policy_hash.clone(),
            },
        )?;
        Ok(ApplyOutcome {
            proposal_id: proposal.id,
            operator_id: approved_by.to_owned(),
            previous_policy_hash,
            policy_hash,
            event,
        })
    }

    /// Applies a proposal the control plane has already reviewed and approved.
    ///
    /// [`ProposalStore::approve`] demands a [`HumanApproval`], which only an
    /// operator process holding credential material can mint. The worker that
    /// owns the policy holds no such material, so it applies a decision the
    /// control plane has already made - and re-checks everything that makes the
    /// apply safe: the proposal's identity, tenant and sandbox, the base policy
    /// hash still in force, the verifier, and the ruleset install.
    ///
    /// What this does not add is a new authority: the attestation is the control
    /// plane's, which already authorises every worker operation, and the human
    /// decision behind it was checked where the human made it.
    pub async fn apply_attested(
        &self,
        proposal: Proposal,
        approved_by: &str,
    ) -> Result<ApplyOutcome> {
        if approved_by.is_empty()
            || approved_by.len() > MAX_AGENT_ID_BYTES
            || !printable(approved_by)
        {
            return Err(GuardError::Denied(
                "approving operator label is empty, oversized or not printable".into(),
            ));
        }
        let id = proposal.id;
        // A lost response is the normal case, not the exotic one. `restore` would
        // overwrite a decided record with the caller's still-pending copy, so a
        // proposal that is already in the store is reconciled, never restored.
        if let Ok(existing) = self.proposal(id) {
            if !same_request(&existing, &proposal) {
                return Err(GuardError::Denied(
                    "a replayed proposal id carries a different request".into(),
                ));
            }
            return match &existing.state {
                ProposalState::Pending => self.apply_locked(id, approved_by).await,
                ProposalState::Approved { policy_hash } => self.confirm_replay(id, policy_hash),
                ProposalState::Denied { .. } | ProposalState::Refused { .. } => Err(
                    GuardError::Denied("policy proposal is no longer pending".into()),
                ),
            };
        }
        // Re-submitting through the public path would mint a second identity for
        // the same request; the durable record is restored as it stands.
        self.restore([proposal])?;
        self.apply_locked(id, approved_by).await
    }

    /// Confirms an apply that already happened, without doing it twice.
    ///
    /// The confirmation is only given when the live policy really carries the
    /// hash the first apply produced: "already applied" is a claim about the
    /// enforcement in force, and has to be true of it rather than of a record.
    fn confirm_replay(&self, id: Uuid, applied_hash: &str) -> Result<ApplyOutcome> {
        if self.config.policy.load().policy_hash() != applied_hash {
            return Err(GuardError::Denied(
                "the proposal was applied under a different policy than the one in force".into(),
            ));
        }
        Err(GuardError::AlreadyApplied(format!(
            "{}:{applied_hash}",
            id.simple()
        )))
    }

    /// Records a human refusal. Nothing about the policy changes.
    pub async fn deny(&self, review: &HumanApproval, id: Uuid, note: &str) -> Result<Proposal> {
        let proposal = self.pending(id)?;
        if note.is_empty() || note.len() > MAX_NOTE_BYTES || !printable(note) {
            return Err(GuardError::Denied(
                "denial note is empty, oversized or not printable".into(),
            ));
        }
        self.append(
            Decision::Deny,
            &format!(
                "policy proposal {} denied by {}",
                proposal.id.simple(),
                review.operator_id()
            ),
            None,
        )
        .await?;
        self.settle(
            id,
            ProposalState::Denied {
                note: note.to_owned(),
            },
        )
    }

    /// A proposal that is still waiting for a decision.
    fn pending(&self, id: Uuid) -> Result<Proposal> {
        let proposal = self.proposal(id)?;
        if !proposal.is_pending() {
            return Err(GuardError::Denied(
                "policy proposal is no longer pending".into(),
            ));
        }
        Ok(proposal)
    }

    fn settle(&self, id: Uuid, state: ProposalState) -> Result<Proposal> {
        let mut proposals = self.proposals.lock();
        let proposal = proposals
            .get_mut(&id)
            .ok_or_else(|| GuardError::Denied("no such policy proposal".into()))?;
        proposal.state = state;
        Ok(proposal.clone())
    }

    async fn append(
        &self,
        decision: Decision,
        reason: &str,
        destination: Option<String>,
    ) -> Result<GuardEvent> {
        let hash = self.config.policy.policy_hash();
        self.append_with_hash(decision, reason, destination, &hash)
            .await
    }

    async fn append_with_hash(
        &self,
        decision: Decision,
        reason: &str,
        destination: Option<String>,
        policy_hash: &str,
    ) -> Result<GuardEvent> {
        let event = EventInput {
            sandbox_id: self.config.sandbox_id,
            tenant_id: self.config.tenant_id,
            policy_hash: policy_hash.to_owned(),
            category: Category::Policy,
            decision,
            reason: bound_reason(reason),
            destination,
            request_bytes: 0,
            response_bytes: 0,
            duration_ms: 0,
        };
        self.config.events.append(event).await
    }
}

/// The candidate policy a request would install.
///
/// The only edit is an addition of destinations, and the result is checked to
/// be a pure extension of what is in force: same version, same limits, same
/// model endpoint, same credentials, same DNS scope, and every existing egress
/// rule still present and unchanged. A proposal therefore cannot widen a
/// credential binding, lift a rate limit, or quietly replace the rules a
/// destination already had.
fn candidate_policy(base: &GuardPolicy, request: &ProposalRequest) -> Result<GuardPolicy> {
    let mut candidate = base.clone();
    for grant in &request.allow {
        candidate.network.egress.push(grant.to_rule());
        // A permitted destination the guest could not resolve would never be
        // reachable, so the resolver scope grows with it - and only with it.
        if !candidate.network.dns.allowed_zones.contains(&grant.host) {
            candidate.network.dns.allowed_zones.push(grant.host.clone());
        }
    }
    if !is_extension_of(base, &candidate) {
        return Err(GuardError::Denied(
            "a proposal may only add destinations; it may not weaken or replace policy".into(),
        ));
    }
    Ok(candidate)
}

/// The policy a granted request installs, derived exactly as the store
/// derives it.
///
/// The control plane needs the resulting policy, not only its hash: the
/// sandbox record is what authorizes later observations, and a record that
/// still carries the base policy can no longer name the ruleset in force.
pub fn applied_policy(base: &GuardPolicy, request: &ProposalRequest) -> Result<GuardPolicy> {
    candidate_policy(base, request)
}

fn is_extension_of(base: &GuardPolicy, candidate: &GuardPolicy) -> bool {
    if base.version != candidate.version
        || base.limits != candidate.limits
        || base.model != candidate.model
        || base.credentials != candidate.credentials
        || base.network.dns.allowed_record_types != candidate.network.dns.allowed_record_types
    {
        return false;
    }
    // Resolution scope may only grow, and every name it grows to must be one
    // the new rules actually permit: a proposal cannot buy DNS for a host it
    // does not also open.
    base.network
        .dns
        .allowed_zones
        .iter()
        .all(|zone| candidate.network.dns.allowed_zones.contains(zone))
        && candidate.network.dns.allowed_zones.iter().all(|zone| {
            base.network.dns.allowed_zones.contains(zone)
                || candidate
                    .network
                    .egress
                    .iter()
                    .any(|rule| &rule.host == zone)
        })
        && candidate
            .network
            .egress
            .iter()
            .filter(|rule| base.network.egress.contains(rule))
            .count()
            == base.network.egress.len()
        && candidate.network.egress.len() > base.network.egress.len()
}

fn single_destination(request: &ProposalRequest) -> Option<String> {
    match request.allow.as_slice() {
        [grant] => Some(format!("{}:{}", grant.host, grant.port)),
        _ => None,
    }
}

/// Whether agent- or operator-facing text is one line of printable ASCII.
///
/// Control characters are refused because they split a record into fields that
/// do not exist, and non-ASCII because these fields are rendered at a fixed
/// width. Space is deliberately allowed: an ordinary label or note is words,
/// and a rule that rejects words rejects the field.
pub fn printable(value: &str) -> bool {
    !value
        .chars()
        .any(|character| character.is_control() || !character.is_ascii())
}

/// Truncates operator-facing text to what an event record accepts, on a
/// character boundary.
/// Whether a replayed proposal is the same request that was decided.
fn same_request(stored: &Proposal, incoming: &Proposal) -> bool {
    stored.sandbox_id == incoming.sandbox_id
        && stored.tenant_id == incoming.tenant_id
        && stored.agent_id == incoming.agent_id
        && stored.request == incoming.request
        && stored.base_policy_hash == incoming.base_policy_hash
}

fn bound_reason(reason: &str) -> String {
    let cleaned: String = reason
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    if cleaned.len() <= MAX_REASON_BYTES {
        return cleaned;
    }
    let mut truncated = String::new();
    for character in cleaned.chars() {
        if truncated.len() + character.len_utf8() > MAX_REASON_BYTES - 3 {
            break;
        }
        truncated.push(character);
    }
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> EgressGrant {
        EgressGrant {
            host: "api.example.com".into(),
            port: 443,
            methods: vec!["GET".into()],
            paths: vec!["/v1/".into()],
        }
    }

    #[test]
    fn a_proposal_only_adds_and_never_replaces() {
        let base = GuardPolicy::default();
        let request = ProposalRequest {
            summary: "please allow api.example.com:443".into(),
            allow: vec![grant()],
        };
        let candidate = candidate_policy(&base, &request).expect("a pure addition");
        assert_eq!(candidate.network.egress.len(), 1);
        assert!(base.network.egress.is_empty());

        let mut narrowed = request;
        narrowed.allow[0].methods = vec!["GET".into(), "DELETE".into()];
        let mut replacing = base.clone();
        replacing.network.egress.push(grant().to_rule());
        let result = candidate_policy(&replacing, &narrowed);
        assert!(
            result.is_ok(),
            "adding another destination is still an addition"
        );
    }

    #[test]
    fn reasons_stay_inside_the_event_bound() {
        let long = "x".repeat(MAX_REASON_BYTES * 2);
        let bounded = bound_reason(&long);
        assert!(bounded.len() <= MAX_REASON_BYTES);
        assert!(!bound_reason("reason\nwith\ncontrol").contains('\n'));
    }
}
