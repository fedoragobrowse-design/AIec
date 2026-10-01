//! Out-of-guest policy, network enforcement and credential governance for AIec.
//! This crate deliberately has no dependency on the sandbox control plane.

pub mod budget_client;
pub mod compiler;
pub mod control;
pub mod deployment;
pub mod dns;
pub mod enforcement;
pub mod events;
pub mod gateway;
pub mod policy;
pub mod watchdog;

pub type Result<T, E = GuardError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    #[error("invalid Guard policy: {0}")]
    Policy(String),
    #[error("Guard denied: {0}")]
    Denied(String),
    #[error("Guard evidence integrity: {0}")]
    Integrity(String),
    #[error("Guard unavailable: {0}")]
    Unavailable(String),
    #[error("Guard I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Guard JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Guard YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
}
