//! Policy proposals: an agent may ask, only a human may decide.
//!
//! The decision is recorded durably here; the apply happens on the worker that
//! owns the live policy and the kernel rules. That split is the point: the
//! control plane cannot be the authority for a policy it does not enforce, and
//! a worker must not be handed an approval it cannot verify for itself, so it
//! re-checks the base policy, the boundary and the ruleset before swapping.

use aiec_core::{GuardProposal, Sandbox, Scope};
use aiec_guard::{
    control::{GuardControlCommand, GuardControlResponse, GuardFence},
    proposals::{ProposalRequest, ProposalState},
};
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use chrono::Utc;
use serde::Deserialize;
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
        if label.is_empty() || label.len() > 64 || !label.chars().all(|c| c.is_ascii_graphic()) {
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
    // The sandbox's recorded identity is the hash it runs under from now on.
    if let Err(error) = state
        .repository()
        .update_guard_policy_hash(principal.tenant_id, id, &new_hash)
        .await
    {
        tracing::warn!(%id, %error, "guard policy applied but its recorded hash could not be updated");
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

/// The routes, merged into the tenant's protected surface.
pub(crate) fn routes() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
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
