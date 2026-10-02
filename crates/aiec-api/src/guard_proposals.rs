//! Policy proposals: an agent may ask, only a human may decide.
//!
//! The decision is recorded durably here; the apply happens on the worker that
//! owns the live policy and the kernel rules. That split is the point: the
//! control plane cannot be the authority for a policy it does not enforce, and
//! a worker must not be handed an approval it cannot verify for itself, so it
//! re-checks the base policy, the boundary and the ruleset before swapping.

use std::collections::BTreeSet;

use aiec_core::{
    ApprovalDecisionRequest, ApprovalState, GuardProposal, GuardToolApproval, Sandbox, Scope,
};
use aiec_guard::{
    control::{GuardControlCommand, GuardControlResponse, GuardFence},
    proposals::{ProposalRequest, ProposalState, printable},
};
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ApiFailure, ApiResult, AppState, Principal};

/// The body an agent submits. It cannot name a sandbox other than the one in
/// the path, and it cannot state a policy hash or a decision.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitProposalBody {
    pub request: ProposalRequest,
}

/// A human's decision.
///
/// The body carries no identity: who approved is the authenticated principal,
/// and an operator-supplied label is recorded beside it as a label, never as the
/// identity the audit record attributes the change to.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewProposalBody {
    /// Optional human-facing label for the reviewer, e.g. "oncall".
    #[serde(default)]
    pub operator_label: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// The identity a decision is attributed to.
fn reviewer(principal: &Principal, label: Option<&str>) -> Result<String, ApiFailure> {
    let mut identity = format!("key:{}", principal.key_id);
    if let Some(label) = label {
        if label.is_empty() || label.len() > 64 || !printable(label) {
            return Err(ApiFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "reviewer label is empty, oversized or not printable",
            ));
        }
        identity.push('/');
        identity.push_str(label);
    }
    Ok(identity)
}

/// A scope grants review authority, not permission to review one's own ask.
/// The requester identity is stamped at submission from the authenticated key.
fn require_independent_reviewer(
    principal: &Principal,
    proposal: &GuardProposal,
) -> Result<(), ApiFailure> {
    if proposal.agent_id == format!("key:{}", principal.key_id) {
        return Err(ApiFailure::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "a policy proposal requires a different authenticated reviewer",
        ));
    }
    Ok(())
}

async fn sandbox_of(state: &AppState, principal: &Principal, id: Uuid) -> ApiResult<Sandbox> {
    let sandbox = state
        .repository()
        .get_sandbox(principal.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if sandbox.environment.guard.is_none() {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "sandbox is not guarded",
        ));
    }
    Ok(Json(sandbox))
}

async fn current_fence(
    state: &AppState,
    tenant: Uuid,
    id: Uuid,
) -> std::result::Result<GuardFence, ApiFailure> {
    let dispatch = state
        .scheduler()
        .dispatch_target(tenant, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(GuardFence {
        lease_id: dispatch.lease_id,
        generation: dispatch.generation,
    })
}

pub(crate) async fn submit_proposal(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<SubmitProposalBody>,
) -> ApiResult<GuardProposal> {
    principal
        .authorize(Scope::GuardPropose)
        .map_err(ApiFailure::from)?;
    let sandbox = sandbox_of(&state, &principal, id).await?;
    // An agent proposes against the policy the sandbox runs now. Recording a
    // stale base would only produce a refusal at the worker later.
    let base = sandbox
        .environment
        .guard_policy_hash
        .clone()
        .ok_or_else(|| {
            ApiFailure::new(
                StatusCode::CONFLICT,
                "conflict",
                "sandbox has no recorded guard policy hash",
            )
        })?;
    let proposal = GuardProposal {
        id: new_id(),
        sandbox_id: id,
        tenant_id: principal.tenant_id,
        // The agent identifies itself to the operator; the guest's claim about
        // who it is is recorded, not trusted to be true.
        agent_id: format!("key:{}", principal.key_id),
        request: body.request,
        base_policy_hash: base,
        state: ProposalState::Pending,
        decided_by: None,
        decided_at: None,
        created_at: Utc::now(),
    };
    let stored = state
        .repository()
        .put_guard_proposal(proposal)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(stored))
}

pub(crate) async fn list_proposals(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Vec<GuardProposal>> {
    principal
        .authorize(Scope::GuardRead)
        .map_err(ApiFailure::from)?;
    let _ = sandbox_of(&state, &principal, id).await?;
    let proposals = state
        .repository()
        .list_guard_proposals(principal.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(proposals))
}

pub(crate) async fn get_proposal(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, proposal)): Path<(Uuid, Uuid)>,
) -> ApiResult<GuardProposal> {
    principal
        .authorize(Scope::GuardRead)
        .map_err(ApiFailure::from)?;
    Ok(Json(
        state
            .repository()
            .get_guard_proposal(principal.tenant_id, id, proposal)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

/// Human approval. The decision is recorded here and then dispatched to the
/// worker that owns the policy; a refusal there leaves the decision pending
/// rather than marking it approved, because the apply is what approves.
pub(crate) async fn approve_proposal(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, proposal)): Path<(Uuid, Uuid)>,
    Json(body): Json<ReviewProposalBody>,
) -> ApiResult<GuardProposal> {
    principal
        .authorize(Scope::GuardApprove)
        .map_err(ApiFailure::from)?;
    let sandbox = sandbox_of(&state, &principal, id).await?;
    let mut stored = state
        .repository()
        .get_guard_proposal(principal.tenant_id, id, proposal)
        .await
        .map_err(ApiFailure::from)?;
    require_independent_reviewer(&principal, &stored)?;
    if !matches!(stored.state, ProposalState::Pending) {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "policy proposal is no longer pending",
        ));
    }
    let fence = current_fence(&state, principal.tenant_id, id).await?;
    let runtime = state.runtime_for(&sandbox).map_err(ApiFailure::from)?;
    let policy_hash = stored.base_policy_hash.clone();
    let operator = reviewer(&principal, body.operator_label.as_deref())?;
    let applied = runtime
        .guard_control(
            &sandbox,
            fence,
            GuardControlCommand::ApplyProposal {
                proposal: stored.as_guard(),
                approved_by: operator.clone(),
            },
        )
        .await
        .map_err(ApiFailure::from)?;
    let GuardControlResponse::PolicyApplied {
        policy_hash: new_hash,
        previous_policy_hash,
        ..
    } = applied
    else {
        return Err(ApiFailure::new(
            StatusCode::BAD_GATEWAY,
            "runtime_unavailable",
            "worker returned no policy apply result",
        ));
    };
    if previous_policy_hash != policy_hash {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "the policy changed while the proposal was being approved",
        ));
    }
    stored.state = ProposalState::Approved {
        policy_hash: new_hash.clone(),
    };
    stored.decided_by = Some(operator);
    stored.decided_at = Some(Utc::now());
    let stored = state
        .repository()
        .put_guard_proposal(stored)
        .await
        .map_err(ApiFailure::from)?;
    // The applied ruleset becomes the sandbox's recorded configuration, not
    // just a hash beside the superseded policy: every later observation,
    // heartbeat and release is authorized against the policy this record
    // carries, so a record still holding the base policy would refuse reads of
    // a correctly enforced sandbox. The policy is derived from the same base
    // and request the store derived it from, and is accepted only when it
    // hashes to what the worker actually installed.
    let mut applied = sandbox.environment.guard.clone().ok_or_else(|| {
        ApiFailure::new(StatusCode::CONFLICT, "conflict", "sandbox is not guarded")
    })?;
    let base = applied.effective_policy().map_err(|error| {
        ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            format!("recorded guard policy is unusable: {error}"),
        )
    })?;
    let policy = aiec_guard::proposals::applied_policy(&base, &stored.request).map_err(|_| {
        ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "proposal is not a valid extension of the recorded policy",
        )
    })?;
    let derived = policy.hash().map_err(|error| {
        ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            format!("applied policy is unusable: {error}"),
        )
    })?;
    if derived != new_hash {
        return Err(ApiFailure::new(
            StatusCode::BAD_GATEWAY,
            "runtime_unavailable",
            "worker applied a policy the control plane cannot name",
        ));
    }
    applied.policy = Some(policy);
    applied.policy_template = aiec_guard::policy::PolicyTemplate::NoNetwork;
    applied.model_endpoint = None;
    applied.allowlist.clear();
    if let Err(error) = state
        .repository()
        .update_guard_policy(principal.tenant_id, id, &applied, &new_hash)
        .await
    {
        tracing::warn!(%id, %error, "guard policy applied but its recorded configuration could not be updated");
    } else if let Ok(rebound) = state
        .repository()
        .get_sandbox(principal.tenant_id, id)
        .await
    {
        // The durable budget is bound to the policy it was opened under, so
        // the approved policy has to be named there too: usage already spent
        // carries over, and the ceilings do not move.
        if let Err(error) =
            crate::guard::initialize_guard_budget(state.repository().as_ref(), &rebound).await
        {
            tracing::warn!(%id, %error, "guard budget could not follow the approved policy");
        }
    }
    Ok(Json(stored))
}

pub(crate) async fn deny_proposal(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, proposal)): Path<(Uuid, Uuid)>,
    Json(body): Json<ReviewProposalBody>,
) -> ApiResult<GuardProposal> {
    principal
        .authorize(Scope::GuardApprove)
        .map_err(ApiFailure::from)?;
    let mut stored = state
        .repository()
        .get_guard_proposal(principal.tenant_id, id, proposal)
        .await
        .map_err(ApiFailure::from)?;
    require_independent_reviewer(&principal, &stored)?;
    if !matches!(stored.state, ProposalState::Pending) {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "policy proposal is no longer pending",
        ));
    }
    let operator = reviewer(&principal, body.operator_label.as_deref())?;
    let note = body.note.unwrap_or_else(|| "denied by operator".into());
    if note.len() > 512 {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "denial note is longer than 512 bytes",
        ));
    }
    stored.state = ProposalState::Denied { note };
    stored.decided_by = Some(operator);
    stored.decided_at = Some(Utc::now());
    Ok(Json(
        state
            .repository()
            .put_guard_proposal(stored)
            .await
            .map_err(ApiFailure::from)?,
    ))
}

/// The harness asks whether one high-risk tool call may run.
///
/// The answer is this control plane's, and it is the same answer for every
/// caller: the request states a sandbox, a tool and a digest of the call's own
/// arguments, and the answer comes from a recorded human decision about exactly
/// that call. No request body can carry its own verdict.
///
/// `digest` is what stops an approval from being a capability. An operator who
/// permitted `write_file("/etc/rc", <these bytes>)` did not permit different
/// bytes at the same path, and a request that omits the digest cannot spend a
/// grant because none matches.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBody {
    pub sandbox_id: Uuid,
    pub tool: String,
    /// Digest of the tool and its canonical arguments, lowercase hex.
    #[serde(default)]
    pub digest: Option<String>,
    /// Optional detail for the operator's decision, never parsed.
    #[serde(default)]
    pub detail: Option<String>,
}

/// The calls that are safe without asking, because they only read.
///
/// This is an allowlist rather than a denylist on purpose. A tool nobody has
/// classified - one added to the MCP surface tomorrow, or one whose name is
/// misspelled by the caller - is refused until somebody decides it is safe,
/// which is the only direction that fails the way the rest of Guard fails.
fn known_safe_tools() -> BTreeSet<String> {
    [
        "sandbox.get",
        "sandbox.list_owned",
        "sandbox.read_file",
        "sandbox.list_files",
        "secret.list",
        "snapshot.list",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// How long an unanswered request stays open before it stops being a request.
const APPROVAL_TTL_SECONDS: i64 = 300;

async fn approve_tool(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<ApprovalBody>,
) -> ApiResult<ApprovalAnswer> {
    principal
        .authorize(Scope::SandboxesWrite)
        .map_err(ApiFailure::from)?;
    if body.sandbox_id != id {
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "approval names a different sandbox than the request path",
        ));
    }
    if body.tool.is_empty() || body.tool.len() > 64 || !body.tool.is_ascii() {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "tool name is empty, oversized or not a plain name",
        ));
    }
    let Some(digest) = body.digest.as_deref() else {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "digest is required: an approval is for one call, not for a tool",
        ));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "digest must be 64 lowercase hex characters",
        ));
    }
    if let Some(detail) = body.detail.as_deref()
        && (detail.len() > 256 || detail.chars().any(|c| c.is_control()))
    {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "detail is longer than 256 bytes or carries control characters",
        ));
    }
    // Ownership first: a caller may not ask about a sandbox it does not hold.
    let _ = state
        .repository()
        .get_sandbox(principal.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if known_safe_tools().contains(&body.tool) {
        return Ok(Json(ApprovalAnswer {
            approved: true,
            reason: None,
            required: false,
        }));
    }

    // Spend any grant a human already made. The spend is atomic and bound to
    // this key, so a grant is good for exactly one call by exactly the key that
    // asked for it.
    let spent = state
        .repository()
        .consume_guard_tool_approval(
            principal.tenant_id,
            id,
            &body.tool,
            digest,
            principal.key_id,
            Utc::now(),
        )
        .await
        .map_err(ApiFailure::from)?;
    if spent.is_some() {
        return Ok(Json(ApprovalAnswer {
            approved: true,
            reason: None,
            required: true,
        }));
    }

    // Nothing has decided this call. Record the request so an operator can, and
    // answer with a refusal that names itself - never a silent yes, and never
    // an approval the harness supplied.
    state
        .repository()
        .get_or_put_guard_tool_approval(GuardToolApproval {
            id: new_id(),
            sandbox_id: id,
            tenant_id: principal.tenant_id,
            tool: body.tool.clone(),
            request_digest: digest.to_string(),
            detail: body.detail.clone(),
            // From the principal, never from the body: a caller must not be
            // able to nominate somebody to decide on its behalf.
            requested_by_key_id: principal.key_id,
            requested_by_label: reviewer(&principal, None)?,
            state: ApprovalState::Pending,
            decided_by_key_id: None,
            decided_by_label: None,
            decided_at: None,
            expires_at: Utc::now() + chrono::Duration::seconds(APPROVAL_TTL_SECONDS),
            consumed_at: None,
            created_at: Utc::now(),
        })
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(ApprovalAnswer {
        approved: false,
        reason: Some(format!(
            "{} has no operator approval for this exact call",
            body.tool
        )),
        required: true,
    }))
}

/// An operator's decision on one pending request.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBody {
    /// The request being decided, as recorded by the asker.
    pub request_id: Uuid,
    pub decision: ApprovalState,
}

/// Records an operator's decision about one specific high-risk call.
///
/// This is the positive half of §44, and the reason it needs
/// `Scope::GuardApprove` while the check above needs only `SandboxesWrite`:
/// the identity that asks must not be the identity that decides. Scope alone
/// would not be enough, since one key may hold both scopes, so the decision is
/// additionally refused when the decider is the requester - by key id, in the
/// store, and by a trigger beneath it.
async fn decide_tool_approval(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<DecisionBody>,
) -> ApiResult<GuardToolApproval> {
    principal
        .authorize(Scope::GuardApprove)
        .map_err(ApiFailure::from)?;
    if body.decision == ApprovalState::Pending {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "decision must be granted or denied",
        ));
    }
    let _ = state
        .repository()
        .get_sandbox(principal.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let decided = state
        .repository()
        .decide_guard_tool_approval(ApprovalDecisionRequest {
            tenant: principal.tenant_id,
            sandbox: id,
            request_id: body.request_id,
            decision: body.decision,
            decided_by_key_id: principal.key_id,
            decided_by_label: &reviewer(&principal, None)?,
            at: Utc::now(),
        })
        .await
        .map_err(ApiFailure::from)?;
    // Unknown, already decided and self-approval are one answer on purpose:
    // telling them apart would tell a caller probing for its own authority
    // exactly which of them happened.
    decided
        .ok_or_else(|| {
            ApiFailure::new(
                StatusCode::CONFLICT,
                "conflict",
                "approval request is not pending, or was not this requester's to decide",
            )
        })
        .map(Json)
}

/// Lists the approval requests for one sandbox, so an operator can find the
/// `request_id` a decision needs.
///
/// Without this the ask/grant flow is unusable through the API: the harness
/// knows it asked, but nothing in the API's surface carried the request's id
/// back to the person meant to decide, so the only way to find one was to read
/// the table directly. It requires `GuardApprove` rather than
/// `SandboxesWrite` because it is the operator's queue, not the caller's.
async fn list_tool_approvals(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Vec<GuardToolApproval>> {
    principal
        .authorize(Scope::GuardApprove)
        .map_err(ApiFailure::from)?;

    let _ = state
        .repository()
        .get_sandbox(principal.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    let approvals = state
        .repository()
        .list_guard_tool_approvals(principal.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    Ok(Json(approvals))
}

#[derive(Clone, Debug, Serialize)]
pub struct ApprovalAnswer {
    pub approved: bool,
    pub reason: Option<String>,
    /// Whether this call needed a decision at all. False means it was allowed
    /// because it is a known-safe read; true means nothing has decided it.
    pub required: bool,
}

/// The routes, merged into the tenant's protected surface.
pub(crate) fn routes() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/sandboxes/{id}/guard/approval", post(approve_tool))
        .route(
            "/sandboxes/{id}/guard/tool-approvals",
            post(decide_tool_approval).get(list_tool_approvals),
        )
        .route(
            "/sandboxes/{id}/guard/proposals",
            post(submit_proposal).get(list_proposals),
        )
        .route(
            "/sandboxes/{id}/guard/proposals/{proposal}",
            get(get_proposal),
        )
        .route(
            "/sandboxes/{id}/guard/proposals/{proposal}/approve",
            post(approve_proposal),
        )
        .route(
            "/sandboxes/{id}/guard/proposals/{proposal}/deny",
            post(deny_proposal),
        )
}

fn new_id() -> Uuid {
    aiec_core::new_id()
}
