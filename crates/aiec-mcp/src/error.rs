//! Structured MCP error model.
//!
//! Every failure a tool can produce is one of a fixed set of codes, so a calling
//! agent can branch on the cause instead of parsing prose. Nothing here ever
//! carries a credential: tokens, API keys and guest secrets are redacted at the
//! boundary rather than at the call site, so a new tool cannot leak one by
//! forgetting.

use serde::Serialize;

/// A machine-readable failure code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    SandboxNotFound,
    SandboxNotRunning,
    LocalCapacityUnavailable,
    CommandTimeout,
    OutputLimitExceeded,
    FileTooLarge,
    UnsupportedOperation,
    AiecApiUnavailable,
    LocalRuntimeUnavailable,
    AuthFailed,
    InvalidArgument,
}

impl ErrorCode {
    /// The stable wire representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SandboxNotFound => "SANDBOX_NOT_FOUND",
            Self::SandboxNotRunning => "SANDBOX_NOT_RUNNING",
            Self::LocalCapacityUnavailable => "LOCAL_CAPACITY_UNAVAILABLE",
            Self::CommandTimeout => "COMMAND_TIMEOUT",
            Self::OutputLimitExceeded => "OUTPUT_LIMIT_EXCEEDED",
            Self::FileTooLarge => "FILE_TOO_LARGE",
            Self::UnsupportedOperation => "UNSUPPORTED_OPERATION",
            Self::AiecApiUnavailable => "AIEC_API_UNAVAILABLE",
            Self::LocalRuntimeUnavailable => "LOCAL_RUNTIME_UNAVAILABLE",
            Self::AuthFailed => "AUTH_FAILED",
            Self::InvalidArgument => "INVALID_ARGUMENT",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A tool failure, carrying its code and enough context to act on.
#[derive(Debug, Clone, Serialize)]
pub struct McpError {
    pub code: ErrorCode,
    pub message: String,
    /// Request-scoped identifiers, safe to log and to correlate with AIec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Extra machine-readable context, such as requested versus available
    /// capacity when a local worker cannot take a sandbox.
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
}

impl McpError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            sandbox_id: None,
            request_id: None,
            details: serde_json::Value::Null,
        }
    }

    pub fn with_sandbox(mut self, id: impl std::fmt::Display) -> Self {
        self.sandbox_id = Some(id.to_string());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for McpError {}

/// Anything a tool can fail with, mapped onto the structured model.
#[derive(Debug, thiserror::Error)]
pub enum ToolFailure {
    #[error(transparent)]
    Mcp(#[from] McpError),
    #[error("the local AIec control plane is unreachable: {0}")]
    ApiUnavailable(String),
    #[error("the local AIec control plane rejected the request: {message}")]
    Api { code: String, message: String },
}

impl ToolFailure {
    /// Converts any failure into the structured MCP error.
    pub fn into_error(self) -> McpError {
        match self {
            Self::Mcp(error) => error,
            Self::ApiUnavailable(detail) => McpError::new(
                ErrorCode::AiecApiUnavailable,
                format!("the local AIec control plane is unreachable: {detail}"),
            ),
            Self::Api { code, message } => {
                // The control plane's own vocabulary is preserved where it is
                // already one of ours, so a caller sees one consistent set.
                // These are the codes the control plane actually emits; a
                // capacity refusal in particular arrives as
                // `scheduler_unavailable`, not `conflict`.
                let mapped = match code.as_str() {
                    "not_found" => ErrorCode::SandboxNotFound,
                    "scheduler_unavailable" | "quota_exceeded" => {
                        ErrorCode::LocalCapacityUnavailable
                    }
                    "runtime_unavailable" => ErrorCode::LocalRuntimeUnavailable,
                    "invalid_request" => ErrorCode::InvalidArgument,
                    "unauthorized" | "forbidden" => ErrorCode::AuthFailed,
                    "unsupported" => ErrorCode::UnsupportedOperation,
                    "rate_limited" => ErrorCode::LocalCapacityUnavailable,
                    "timeout" => ErrorCode::CommandTimeout,
                    // The control plane reports an output-limit refusal and a
                    // guest timeout as a generic `backend` error, so the message
                    // is what distinguishes them. Without this, a clipped
                    // megabyte of stdout would be reported as an outage.
                    _ => classify_backend(&message),
                };
                McpError::new(mapped, message)
            }
        }
    }
}

/// Distinguishes the backend failures the control plane reports generically.
fn classify_backend(message: &str) -> ErrorCode {
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("output limit") || lowered.contains("output too large") {
        ErrorCode::OutputLimitExceeded
    } else if lowered.contains("timed out") || lowered.contains("timeout") {
        ErrorCode::CommandTimeout
    } else if lowered.contains("no space left") || lowered.contains("disk full") {
        ErrorCode::FileTooLarge
    } else {
        ErrorCode::AiecApiUnavailable
    }
}

pub type ToolResult<T> = Result<T, McpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_serialise_to_their_wire_names() {
        assert_eq!(
            serde_json::to_string(&ErrorCode::LocalCapacityUnavailable).unwrap(),
            "\"LOCAL_CAPACITY_UNAVAILABLE\""
        );
        assert_eq!(ErrorCode::AuthFailed.to_string(), "AUTH_FAILED");
    }

    #[test]
    fn control_plane_codes_map_onto_mcp_codes() {
        let failure = ToolFailure::Api {
            code: "not_found".into(),
            message: "no such sandbox".into(),
        };
        assert_eq!(failure.into_error().code, ErrorCode::SandboxNotFound);

        // The live control plane reports a full local worker as
        // `scheduler_unavailable`; that must not surface as an API outage.
        for code in ["scheduler_unavailable", "quota_exceeded"] {
            let failure = ToolFailure::Api {
                code: code.into(),
                message: "no schedulable worker has capacity".into(),
            };
            assert_eq!(
                failure.into_error().code,
                ErrorCode::LocalCapacityUnavailable,
                "{code} must map to a capacity failure"
            );
        }

        let failure = ToolFailure::Api {
            code: "runtime_unavailable".into(),
            message: "firecracker is not available".into(),
        };
        assert_eq!(
            failure.into_error().code,
            ErrorCode::LocalRuntimeUnavailable
        );
    }

    #[test]
    fn generic_backend_errors_keep_their_meaning() {
        // The control plane's own message, which it reports with code `backend`.
        let failure = ToolFailure::Api {
            code: "backend".into(),
            message: "archive: Docker output limit exceeded".into(),
        };
        assert_eq!(
            failure.into_error().code,
            ErrorCode::OutputLimitExceeded,
            "a clipped output limit must not be reported as an outage"
        );

        let failure = ToolFailure::Api {
            code: "backend".into(),
            message: "command timed out in guest".into(),
        };
        assert_eq!(failure.into_error().code, ErrorCode::CommandTimeout);

        let failure = ToolFailure::Api {
            code: "backend".into(),
            message: "worker transport: error sending request".into(),
        };
        assert_eq!(failure.into_error().code, ErrorCode::AiecApiUnavailable);
    }

    #[test]
    fn an_unreachable_control_plane_is_not_reported_as_a_bad_request() {
        let failure = ToolFailure::ApiUnavailable("connection refused".into());
        assert_eq!(failure.into_error().code, ErrorCode::AiecApiUnavailable);
    }
}
