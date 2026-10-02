//! Pre-tool approval for high-risk operations.
//!
//! The harness asks the control plane whether it may perform a tool call, and
//! the harness cannot answer for itself. When the approval service cannot be
//! reached, a configured high-risk operation is denied: an approval system that
//! is unavailable is not an approval.

use std::{collections::BTreeSet, sync::Arc};

use aiec_client::{AIecClient, ClientError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct ApprovalPolicy {
    /// Tools that require an approval before they run.
    pub high_risk: BTreeSet<String>,
    /// Whether an unreachable approval service denies or allows. Denying is the
    /// only safe reading of "the harness cannot self-approve".
    pub fail_closed: bool,
    pub endpoint: String,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            high_risk: [
                "sandbox.destroy",
                "sandbox.write_file",
                "sandbox.delete_file",
                "secret.set",
                "secret.delete",
                "quarantine.release",
                "policy.apply",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            fail_closed: true,
            endpoint: String::new(),
        }
    }
}

impl ApprovalPolicy {
    /// Whether this tool needs an answer before it runs.
    pub fn requires_approval(&self, tool: &str) -> bool {
        self.high_risk.contains(tool)
    }

    /// A policy that asks about nothing, for a deployment that has not opted in.
    pub fn disabled() -> Self {
        Self {
            high_risk: BTreeSet::new(),
            ..Default::default()
        }
    }
}

/// What the control plane answered.
#[derive(Clone, Debug, Deserialize)]
pub struct ApprovalDecision {
    #[serde(rename = "approved")]
    pub approved: bool,
    /// Why, in the operator's words. Recorded, never parsed.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ApprovalRequest<'a> {
    sandbox_id: Uuid,
    tool: &'a str,
    /// Digest of the call's own arguments. Required by the control plane: an
    /// approval is for one call, so there has to be something to bind it to.
    digest: &'a str,
    detail: Option<&'a str>,
}

/// Asks the control plane, and never answers for itself.
#[async_trait]
pub trait Approver: Send + Sync {
    /// Whether this tool needs an approval.
    fn requires_approval(&self, tool: &str) -> bool;

    /// Asks about one specific call. `None` means the service could not be
    /// reached; the caller decides, and under a fail-closed policy that
    /// decision is a denial.
    async fn approve(
        &self,
        sandbox_id: Uuid,
        tool: &str,
        request_digest: &str,
        detail: Option<&str>,
    ) -> Option<ApprovalDecision>;
}

/// The real approver: an HTTP call to the control plane's approval route.
pub struct ControlPlaneApprover {
    client: AIecClient,
    policy: ApprovalPolicy,
}

impl ControlPlaneApprover {
    pub fn new(client: AIecClient, policy: ApprovalPolicy) -> Self {
        Self { client, policy }
    }
}

#[async_trait]
impl Approver for ControlPlaneApprover {
    fn requires_approval(&self, tool: &str) -> bool {
        self.policy.requires_approval(tool)
    }

    async fn approve(
        &self,
        sandbox_id: Uuid,
        tool: &str,
        request_digest: &str,
        detail: Option<&str>,
    ) -> Option<ApprovalDecision> {
        let response = self
            .client
            .guard_approval(
                sandbox_id,
                &serde_json::to_value(ApprovalRequest {
                    sandbox_id,
                    tool,
                    digest: request_digest,
                    detail,
                })
                .ok()?,
            )
            .await
            .ok()?;
        serde_json::from_value(response).ok()
    }
}

/// The gate every high-risk tool call passes through.
#[derive(Clone)]
pub struct ApprovalGate {
    approver: Arc<dyn Approver>,
    fail_closed: bool,
}

impl ApprovalGate {
    pub fn new(approver: Arc<dyn Approver>, fail_closed: bool) -> Self {
        Self {
            approver,
            fail_closed,
        }
    }

    pub fn requires_approval(&self, tool: &str) -> bool {
        self.approver.requires_approval(tool)
    }

    /// Decides whether a high-risk call may proceed.
    ///
    /// The three refusals are distinct on purpose: the operator said no, the
    /// service was unreachable, and this call was never high risk in the first
    /// place. A harness that cannot tell them apart will retry the wrong ones.
    pub async fn check(
        &self,
        sandbox_id: Uuid,
        tool: &str,
        request_digest: &str,
        detail: Option<&str>,
    ) -> Result<Allowance, ApprovalRefusal> {
        if !self.approver.requires_approval(tool) {
            return Ok(Allowance::NotRequired);
        }
        match self
            .approver
            .approve(sandbox_id, tool, request_digest, detail)
            .await
        {
            Some(decision) if decision.approved => Ok(Allowance::Approved {
                reason: decision.reason,
            }),
            Some(decision) => Err(ApprovalRefusal::Denied {
                reason: decision
                    .reason
                    .unwrap_or_else(|| "refused by operator".into()),
            }),
            None if self.fail_closed => Err(ApprovalRefusal::Unavailable),
            None => Ok(Allowance::Approved { reason: None }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Allowance {
    NotRequired,
    Approved { reason: Option<String> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalRefusal {
    Denied { reason: String },
    Unavailable,
}

impl std::fmt::Display for ApprovalRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { reason } => write!(f, "high-risk operation refused: {reason}"),
            Self::Unavailable => write!(
                f,
                "high-risk operation refused: the approval service could not be reached"
            ),
        }
    }
}

/// The reason a client error means "not approved" rather than "broken".
pub fn approval_from_error(error: &ClientError) -> Option<ApprovalRefusal> {
    if let ClientError::Api {
        status, message, ..
    } = error
        && status == &reqwest::StatusCode::FORBIDDEN
    {
        return Some(ApprovalRefusal::Denied {
            reason: message.chars().take(200).collect(),
        });
    }
    None
}
