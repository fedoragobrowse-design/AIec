//! Behavioural tests for the proposal workflow: an agent may ask, only a human
//! may decide, and the verifier decides whether the ask is safe.

use aiec_guard::{
    GuardError, Result,
    compiler::{CompiledPolicy, OperatorBoundary, compile},
    enforcement::{EnforcementBackend, GuardAttachment, TestBackend},
    events::{EventSink, FileEventSink, GuardEvent, read_events, verify_chain},
    gateway::CredentialStore,
    policy::{EgressRule, GuardPolicy, ModelEndpoint, PolicyTemplate},
    proposals::{
        AgentCredential, AtomicPolicy, EgressGrant, HumanApproval, ProposalRequest, ProposalState,
        ProposalStore, ProposalStoreConfig, applied_policy,
    },
};
use parking_lot::Mutex;
use std::{net::Ipv4Addr, path::PathBuf, sync::Arc};
use uuid::Uuid;

const OPERATOR_CREDENTIAL: &str = "operator-approval";
const OPERATOR_SECRET: &str = "operator-only-synthetic-secret";
const GRANTED_HOST: &str = "api.example.com";

/// The real test enforcement model, with every install recorded, so a test can
/// see that an approved proposal was actually programmed rather than only
/// stored in memory.
struct RecordingBackend {
    inner: Arc<TestBackend>,
    installed: Mutex<Vec<String>>,
}

impl RecordingBackend {
    fn new(inner: Arc<TestBackend>) -> Self {
        Self {
            inner,
            installed: Mutex::new(Vec::new()),
        }
    }

    fn installed(&self) -> Vec<String> {
        self.installed.lock().clone()
    }
}

#[async_trait::async_trait]
impl EnforcementBackend for RecordingBackend {
    async fn apply_policy(
        &self,
        policy: &CompiledPolicy,
        attachment: &GuardAttachment,
    ) -> Result<()> {
        self.inner.apply_policy(policy, attachment).await?;
        self.installed.lock().push(policy.policy_hash().to_owned());
        Ok(())
    }
    async fn remove_policy(&self, attachment: &GuardAttachment) -> Result<()> {
        self.inner.remove_policy(attachment).await
    }
    async fn cut_network(&self, attachment: &GuardAttachment) -> Result<()> {
        self.inner.cut_network(attachment).await
    }
    async fn restore_network(
        &self,
        policy: &CompiledPolicy,
        attachment: &GuardAttachment,
    ) -> Result<()> {
        self.inner.restore_network(policy, attachment).await
    }
    async fn health(&self) -> Result<()> {
        self.inner.health().await
    }
}

/// An enforcement substrate that refuses every install, standing in for a
/// kernel that will not take the ruleset.
struct RefusingBackend;

#[async_trait::async_trait]
impl EnforcementBackend for RefusingBackend {
    async fn apply_policy(&self, _: &CompiledPolicy, _: &GuardAttachment) -> Result<()> {
        Err(GuardError::Unavailable("nft refused the ruleset".into()))
    }
    async fn remove_policy(&self, _: &GuardAttachment) -> Result<()> {
        Ok(())
    }
    async fn cut_network(&self, _: &GuardAttachment) -> Result<()> {
        Ok(())
    }
    async fn restore_network(&self, _: &CompiledPolicy, _: &GuardAttachment) -> Result<()> {
        Ok(())
    }
    async fn health(&self) -> Result<()> {
        Ok(())
    }
}

struct Harness {
    store: ProposalStore,
    policy: Arc<AtomicPolicy>,
    enforcement: Arc<RecordingBackend>,
    journal: PathBuf,
    credentials: CredentialStore,
    agent: AgentCredential,
    keep: bool,
}

fn attachment() -> GuardAttachment {
    GuardAttachment {
        sandbox_id: Uuid::nil(),
        tenant_id: Uuid::nil(),
        interface: "veth-guard".into(),
        guest_ip: Ipv4Addr::new(10, 0, 2, 2),
        gateway_ip: Ipv4Addr::new(10, 0, 2, 1),
        dns_port: 53,
        broker_port: 8080,
    }
}

fn base_policy() -> GuardPolicy {
    GuardPolicy::template(
        PolicyTemplate::ModelPlusAllowlist,
        Some(ModelEndpoint {
            host: "model.example.com".into(),
            port: 443,
            scheme: "https".into(),
            ..Default::default()
        }),
        vec![EgressRule {
            host: "registry.example.com".into(),
            port: 443,
            protocol: "tcp".into(),
            allowed_methods: vec!["GET".into()],
            allowed_paths: vec!["/v1/".into()],
        }],
    )
    .expect("base policy")
}

fn request(host: &str, port: u16) -> ProposalRequest {
    ProposalRequest {
        summary: format!("please allow {host}:{port}"),
        allow: vec![EgressGrant {
            host: host.to_owned(),
            port,
            methods: vec!["POST".into()],
            paths: vec!["/v2/".into()],
        }],
    }
}

impl Harness {
    /// `backend` is what an approved proposal has to be installed into; `None`
    /// installs into the test backend, which is a real model of the kernel's
    /// rules rather than a stub.
    async fn new(blocked_host: Option<&str>, backend: Option<Arc<dyn EnforcementBackend>>) -> Self {
        let sandbox_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let mut boundary = OperatorBoundary::default();
        if let Some(host) = blocked_host {
            boundary.blocked_hosts.push(host.to_owned());
        }
        let compiled = compile(&base_policy(), &boundary).expect("base policy compiles");
        let policy = Arc::new(AtomicPolicy::new(compiled, None).expect("policy cell"));
        let attachment = attachment();
        let enforcement = Arc::new(RecordingBackend::new(Arc::new(TestBackend::default())));
        enforcement
            .apply_policy(&policy.compiled(), &attachment)
            .await
            .expect("base ruleset installed");
        let directory =
            std::env::temp_dir().join(format!("aiec-guard-proposals-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("journal directory");
        let journal = directory.join("events.jsonl");
        let sink: Arc<dyn EventSink> = Arc::new(FileEventSink::open(&journal).expect("journal"));
        let store = ProposalStore::new(ProposalStoreConfig {
            sandbox_id,
            tenant_id,
            boundary,
            policy: Arc::clone(&policy),
            enforcement: match backend {
                Some(backend) => backend,
                None => Arc::clone(&enforcement) as Arc<dyn EnforcementBackend>,
            },
            attachment: attachment.clone(),
            events: sink,
        })
        .expect("proposal store");
        let mut credentials = CredentialStore::empty();
        credentials
            .insert(OPERATOR_CREDENTIAL.into(), OPERATOR_SECRET.into())
            .expect("operator credential");
        let agent = AgentCredential::new(sandbox_id, tenant_id, "planner-1").expect("agent");
        Self {
            store,
            policy,
            enforcement,
            journal,
            credentials,
            agent,
            keep: false,
        }
    }

    fn operator(&self) -> HumanApproval {
        HumanApproval::operator(
            "ops-oncall",
            OPERATOR_CREDENTIAL,
            OPERATOR_SECRET,
            &self.credentials,
        )
        .expect("operator approval")
    }

    fn hash(&self) -> String {
        self.policy.policy_hash()
    }

    fn events(&self) -> Vec<GuardEvent> {
        read_events(&self.journal).expect("journal")
    }

    /// Every policy hash the enforcement substrate was asked to install.
    fn installed(&self) -> Vec<String> {
        self.enforcement.installed()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if !self.keep
            && let Some(directory) = self.journal.parent()
        {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

#[tokio::test]
async fn a_pending_proposal_changes_no_policy_no_enforcement_and_no_hash() {
    let h = Harness::new(None, None).await;
    let before_hash = h.hash();
    let before_installed = h.installed();
    let proposal = h
        .store
        .submit(&h.agent, request(GRANTED_HOST, 443))
        .await
        .expect("an agent may submit");

    assert!(matches!(proposal.state, ProposalState::Pending));
    assert_eq!(
        h.hash(),
        before_hash,
        "a pending proposal changed the policy"
    );
    assert_eq!(h.installed(), before_installed);
    assert!(!h.policy.compiled().allows_host(GRANTED_HOST, 443));
    assert_eq!(
        h.store.proposals().len(),
        1,
        "the proposal is recorded and still waiting"
    );
    // The submission itself is auditable.
    assert!(
        h.events()
            .iter()
            .any(|event| event.reason.contains("submitted for human review"))
    );
}

#[tokio::test]
async fn a_human_approval_applies_a_safe_change_with_a_new_hash_and_an_audit_record() {
    let h = Harness::new(None, None).await;
    let before_hash = h.hash();
    let proposal = h
        .store
        .submit(&h.agent, request(GRANTED_HOST, 443))
        .await
        .expect("submission");

    let outcome = h
        .store
        .approve(&h.operator(), proposal.id)
        .await
        .expect("a safe proposal applies");

    assert_eq!(outcome.previous_policy_hash, before_hash);
    assert_ne!(
        outcome.policy_hash, before_hash,
        "a new policy hash is in force"
    );
    assert_eq!(h.hash(), outcome.policy_hash);
    assert!(h.policy.compiled().allows_host(GRANTED_HOST, 443));
    let applied = h.policy.compiled();
    let rule = applied
        .policy()
        .network
        .egress
        .iter()
        .find(|rule| rule.host == GRANTED_HOST)
        .expect("the granted destination");
    assert_eq!(rule.allowed_methods, vec!["POST".to_owned()]);
    assert_eq!(rule.allowed_paths, vec!["/v2/".to_owned()]);
    assert!(
        h.policy
            .compiled()
            .policy()
            .network
            .dns
            .allowed_zones
            .contains(&GRANTED_HOST.to_owned()),
        "a permitted destination the guest cannot resolve would never be reachable"
    );

    // The kernel was reprogrammed, not just the in-process copy.
    // The enforcement substrate was reprogrammed, not only the in-process copy.
    assert_eq!(
        h.installed(),
        vec![before_hash.clone(), outcome.policy_hash.clone()],
        "the kernel was handed exactly the new policy"
    );

    let events = h.events();
    verify_chain(&events).expect("the audit trail is intact");
    let applied = events
        .iter()
        .find(|event| event.reason.contains("applied by operator review"))
        .expect("the apply is audited");
    assert_eq!(applied.policy_hash, outcome.policy_hash);
    assert_eq!(applied.category, aiec_guard::events::Category::Policy);
    assert_eq!(applied.destination.as_deref(), Some("api.example.com:443"));
    assert_eq!(
        h.store.proposal(proposal.id).expect("recorded").state,
        ProposalState::Approved {
            policy_hash: outcome.policy_hash.clone()
        }
    );

    // The decision is one-way: a second approval finds nothing pending.
    assert!(h.store.approve(&h.operator(), proposal.id).await.is_err());
}

#[tokio::test]
async fn an_unsafe_proposal_is_refused_by_the_verifier_and_the_old_policy_stays_in_force() {
    let h = Harness::new(Some("blocked.example.com"), None).await;
    let before_hash = h.hash();
    let before_installed = h.installed();
    let proposal = h
        .store
        .submit(&h.agent, request("blocked.example.com", 443))
        .await
        .expect("submission");

    let error = h
        .store
        .approve(&h.operator(), proposal.id)
        .await
        .expect_err("the verifier refuses a boundary violation");
    assert!(error.to_string().contains("blocked_hosts"), "{error}");

    assert_eq!(h.hash(), before_hash, "a refused proposal changes nothing");
    assert_eq!(h.installed(), before_installed);
    assert!(!h.policy.compiled().allows_host("blocked.example.com", 443));
    assert!(matches!(
        h.store.proposal(proposal.id).expect("recorded").state,
        ProposalState::Refused { .. }
    ));
    assert!(
        h.events()
            .iter()
            .any(|event| event.decision == aiec_guard::events::Decision::Deny
                && event.reason.contains("verifier refused the proposal")),
        "the refusal is audited"
    );
}

#[tokio::test]
async fn an_agent_credential_cannot_mint_an_approval_or_weaken_a_rule_in_force() {
    let h = Harness::new(None, None).await;
    let before_hash = h.hash();

    // Nothing in the guest plane can produce an operator approval: the minting
    // path needs credential material that lives only in the operator process.
    assert!(
        HumanApproval::operator("planner-1", OPERATOR_CREDENTIAL, "guessed", &h.credentials)
            .is_err()
    );
    assert!(
        HumanApproval::operator("ops-oncall", "model-main", OPERATOR_SECRET, &h.credentials)
            .is_err(),
        "another credential's secret does not mint an approval"
    );
    assert!(
        HumanApproval::operator(
            "ops-oncall",
            OPERATOR_CREDENTIAL,
            OPERATOR_SECRET,
            &CredentialStore::empty()
        )
        .is_err(),
        "an empty operator store mints nothing"
    );

    // A credential scoped to another sandbox cannot even propose here.
    let foreign = AgentCredential::new(Uuid::new_v4(), Uuid::new_v4(), "planner-1").expect("agent");
    assert!(
        h.store
            .submit(&foreign, request(GRANTED_HOST, 443))
            .await
            .is_err()
    );

    // A proposal may not replace a destination that is already governed: an
    // agent cannot answer "widen this rule" by naming the same host and port.
    let widening = h
        .store
        .submit(&h.agent, request("registry.example.com", 443))
        .await
        .expect("submission");
    assert!(
        h.store.approve(&h.operator(), widening.id).await.is_err(),
        "a proposal over a governed destination cannot replace its rule"
    );
    assert_eq!(h.hash(), before_hash);
    let still = h
        .policy
        .compiled()
        .policy()
        .network
        .egress
        .iter()
        .find(|rule| rule.host == "registry.example.com")
        .expect("the original rule")
        .clone();
    assert_eq!(still.allowed_methods, vec!["GET".to_owned()]);
    assert_eq!(still.allowed_paths, vec!["/v1/".to_owned()]);
}

#[tokio::test]
async fn a_failed_apply_leaves_the_previous_policy_in_force() {
    let h = Harness::new(None, Some(Arc::new(RefusingBackend))).await;
    let before_hash = h.hash();
    let proposal = h
        .store
        .submit(&h.agent, request(GRANTED_HOST, 443))
        .await
        .expect("submission");

    let error = h
        .store
        .approve(&h.operator(), proposal.id)
        .await
        .expect_err("a refused ruleset is not an approval");
    assert!(
        error.to_string().contains("previous policy stays in force"),
        "{error}"
    );
    assert_eq!(h.hash(), before_hash);
    assert!(!h.policy.compiled().allows_host(GRANTED_HOST, 443));
    // It stays pending, because nothing about it was decided.
    assert!(matches!(
        h.store.proposal(proposal.id).expect("recorded").state,
        ProposalState::Pending
    ));
}

#[tokio::test]
async fn a_proposal_survives_a_control_plane_restart_and_stays_bound_to_its_policy() {
    let h = Harness::new(None, None).await;
    let submitted = h
        .store
        .submit(&h.agent, request(GRANTED_HOST, 443))
        .await
        .expect("submission");

    // The record a control plane persists and reads back is the same record.
    let stored = serde_json::to_vec(&submitted).expect("proposal serializes");
    let read_back: aiec_guard::proposals::Proposal =
        serde_json::from_slice(&stored).expect("proposal deserializes");
    assert_eq!(read_back, submitted);

    // Rebuilding the store from that record keeps it reviewable, and it still
    // applies because it was written against the policy now in force.
    h.store.restore(vec![read_back.clone()]).expect("restored");
    let outcome = h
        .store
        .approve(&h.operator(), submitted.id)
        .await
        .expect("a restored proposal applies");
    assert_ne!(outcome.policy_hash, outcome.previous_policy_hash);
    assert!(h.policy.compiled().allows_host(GRANTED_HOST, 443));

    // A record from another sandbox is refused rather than adopted.
    let other = Harness::new(None, None).await;
    assert!(
        other.store.restore(vec![submitted.clone()]).is_err(),
        "one sandbox's proposal cannot enter another's store"
    );
}

#[tokio::test]
async fn a_human_denial_is_recorded_and_leaves_the_policy_alone() {
    let h = Harness::new(None, None).await;
    let before_hash = h.hash();
    let proposal = h
        .store
        .submit(&h.agent, request(GRANTED_HOST, 443))
        .await
        .expect("submission");

    let denied = h
        .store
        .deny(&h.operator(), proposal.id, "not this quarter")
        .await
        .expect("a human may deny");

    assert_eq!(
        denied.state,
        ProposalState::Denied {
            note: "not this quarter".into()
        }
    );
    assert_eq!(h.hash(), before_hash);
    assert!(!h.policy.compiled().allows_host(GRANTED_HOST, 443));
    assert!(h.store.approve(&h.operator(), proposal.id).await.is_err());
    assert!(
        h.events()
            .iter()
            .any(|event| event.reason.contains("denied by ops-oncall"))
    );
}

#[tokio::test]
async fn the_policy_the_control_plane_names_is_the_one_the_store_installs() {
    // The control plane re-derives the applied policy so it can record it on
    // the sandbox, and may only do so while its derivation is the store's: a
    // divergence would leave the record naming a policy the guest is not
    // enforced by, and every later observation would refuse.
    let h = Harness::new(None, None).await;
    let submitted = request(GRANTED_HOST, 443);
    let base = h.policy.compiled().policy().clone();
    let proposal = h
        .store
        .submit(&h.agent, submitted.clone())
        .await
        .expect("submission");
    let outcome = h
        .store
        .approve(&h.operator(), proposal.id)
        .await
        .expect("a safe proposal applies");
    let derived = applied_policy(&base, &submitted).expect("the derived policy");
    assert_eq!(
        derived.hash().expect("canonical hash"),
        outcome.policy_hash,
        "the derived policy is the one in force"
    );
    assert_eq!(
        derived.normalized(),
        h.policy.compiled().policy().clone().normalized(),
        "the control plane can name the installed ruleset"
    );
}
