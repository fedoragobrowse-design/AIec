//! Platform policy evaluation independent of policy implementation.

use crate::{CreateSandboxRequest, RestoreSnapshotRequest, Sandbox};

/// Result of evaluating one platform policy rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Whether the operation may proceed.
    pub allowed: bool,
    /// Stable reason suitable for logs and API errors.
    pub reason: Option<String>,
}

impl PolicyDecision {
    /// Allows an operation.
    pub fn allow() -> Self {
        Self { allowed: true, reason: None }
    }

    /// Denies an operation for a specific reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self { allowed: false, reason: Some(reason.into()) }
    }
}

/// Operation being evaluated by [`PlatformPolicy`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PolicyOperation<'a> {
    /// Validate a sandbox creation request.
    CreateSandbox(&'a CreateSandboxRequest),
    /// Validate a snapshot restore request.
    RestoreSnapshot(&'a RestoreSnapshotRequest),
    /// Validate an already materialized sandbox.
    Sandbox(&'a Sandbox),
}

/// Evaluates admission and resource policy without binding to an implementation.
pub trait PlatformPolicy: Send + Sync {
    /// Evaluates one operation.
    fn evaluate(&self, operation: PolicyOperation<'_>) -> PolicyDecision;
}

#[cfg(test)]
mod tests {
    use super::PolicyDecision;

    #[test]
    fn allow_has_no_denial_reason() {
        assert_eq!(PolicyDecision::allow(), PolicyDecision { allowed: true, reason: None });
    }

    #[test]
    fn deny_preserves_reason() {
        assert_eq!(PolicyDecision::deny("network denied"), PolicyDecision {
            allowed: false,
            reason: Some("network denied".into()),
        });
    }
}
