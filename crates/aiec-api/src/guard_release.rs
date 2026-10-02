//! Releasing a quarantined sandbox.
//!
//! This is the one path that reopens a machine, so it is deliberately narrow:
//! a distinct scope from the one that can cause a quarantine, an identity taken
//! from the authenticated principal rather than the request, and a fenced
//! dispatch to the worker that owns the policy before any durable state says
//! the sandbox is released. A sandbox whose network is still deny-all is not
//! released, however willing the control plane is to say otherwise.

use aiec_core::{SandboxState, Scope};
use aiec_guard::{control::GuardControlCommand, proposals::printable};
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ApiFailure, AppState, Principal};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBody {
    /// Optional human-facing label for the reviewer, recorded beside the
    /// identity the audit record attributes the release to.
    #[serde(default)]
    pub operator_label: Option<String>,
    /// Why the machine is being released.
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReleaseOutcome {
    pub sandbox_id: Uuid,
    pub released_by: String,
    pub policy_hash: String,
    pub note: Option<String>,
}

pub async fn release_sandbox(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<ReleaseBody>,
) -> Result<axum::Json<ReleaseOutcome>, ApiFailure> {
    principal
        .authorize(Scope::GuardRelease)
        .map_err(ApiFailure::from)?;
    let sandbox = state
        .repository()
        .get_sandbox(principal.tenant_id, id)
        .await
        .map_err(ApiFailure::from)?;
    if sandbox.state != SandboxState::Quarantined {
        // Releasing something that is not held would be a no-op that looks like
        // an action, and a machine that is merely paused is an operator's
        // resume, not a Guard release.
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "sandbox is not quarantined",
        ));
    }
    if let Some(label) = body.operator_label.as_deref()
        && (label.is_empty() || label.len() > 64 || !printable(label))
    {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "reviewer label is empty, oversized or not printable",
        ));
    }
    if let Some(note) = body.note.as_deref()
        && (note.is_empty() || note.len() > 512 || !printable(note))
    {
        return Err(ApiFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "release note is empty, oversized or not printable",
        ));
    }
    let mut released_by = format!("key:{}", principal.key_id);
    if let Some(label) = body.operator_label.as_deref() {
        released_by.push('/');
        released_by.push_str(label);
    }
    let policy_hash = sandbox
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
    let fence = {
        let dispatch = state
            .scheduler()
            .dispatch_target(principal.tenant_id, id)
            .await
            .map_err(ApiFailure::from)?;
        aiec_guard::control::GuardFence {
            lease_id: dispatch.lease_id,
            generation: dispatch.generation,
        }
    };
    let runtime = state.runtime_for(&sandbox).map_err(ApiFailure::from)?;
    // The worker reopens the network first. Only once it says so does durable
    // state follow, so the two can never disagree in the direction that would
    // report a released machine that is still deny-all.
    runtime
        .guard_control(
            &sandbox,
            fence,
            GuardControlCommand::Release {
                policy_hash: policy_hash.clone(),
            },
        )
        .await
        .map_err(ApiFailure::from)?;
    if let Err(error) = state
        .repository()
        .release_guard_quarantine(principal.tenant_id, id, &released_by)
        .await
    {
        tracing::warn!(
            %id,
            %error,
            "guard network released but the durable quarantine mark could not be cleared"
        );
        return Err(ApiFailure::new(
            StatusCode::CONFLICT,
            "conflict",
            "network was released but durable state still records a quarantine",
        ));
    }
    Ok(axum::Json(ReleaseOutcome {
        sandbox_id: id,
        released_by,
        policy_hash,
        note: body.note,
    }))
}
