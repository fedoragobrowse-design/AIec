//! Server configuration.
//!
//! Every setting is local-only by default: the bind address is loopback, the
//! control plane must be local, and the sandbox TTL is short because these are
//! disposable development machines.

use std::net::SocketAddr;

use crate::error::McpError;
use crate::guard::LocalEndpoint;

/// Resolved configuration for one MCP server process.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub endpoint: LocalEndpoint,
    pub api_key: String,
    pub token: std::sync::Arc<zeroize::Zeroizing<String>>,
    pub max_parallel: usize,
    pub default_ttl_seconds: u64,
    pub max_output_bytes: usize,
    pub cleanup_on_shutdown: bool,
}

impl Config {
    /// Builds configuration from the environment.
    ///
    /// `AIEC_LOCAL_API_KEY` names the control-plane key, distinct from
    /// `AIEC_MCP_TOKEN`, which authenticates MCP clients to this server.
    pub fn from_env() -> Result<Self, McpError> {
        let bind_raw = env_or("AIEC_MCP_BIND", "127.0.0.1:8765");
        let bind: SocketAddr = bind_raw.parse().map_err(|_| {
            McpError::invalid(format!("AIEC_MCP_BIND is not a socket address: {bind_raw}"))
        })?;

        // Anything that is not loopback is a deliberate choice, so it is
        // refused unless the operator asked for it by name.
        let allow_non_loopback_bind = env_flag("AIEC_MCP_ALLOW_REMOTE_BIND");
        if !bind.ip().is_loopback() && !allow_non_loopback_bind {
            return Err(McpError::invalid(format!(
                "refusing to bind {bind}: this is a local development interface. \
                 Set AIEC_MCP_ALLOW_REMOTE_BIND=1 if you really mean it."
            )));
        }

        let api_url = env_or("AIEC_LOCAL_API_URL", "https://127.0.0.1:18443");
        let allow_private_network = env_flag("AIEC_MCP_ALLOW_PRIVATE_NETWORK");
        let endpoint = LocalEndpoint::parse(&api_url, allow_private_network)?;

        let api_key = std::env::var("AIEC_LOCAL_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                McpError::invalid(
                    "AIEC_LOCAL_API_KEY is required: the local control plane needs a key \
                     even though this server is local",
                )
            })?;

        let token = crate::auth::resolve_token()?;

        Ok(Self {
            bind,
            endpoint,
            api_key,
            token: std::sync::Arc::new(token),
            max_parallel: env_usize("AIEC_MCP_MAX_PARALLEL", 2).clamp(1, 16),
            default_ttl_seconds: env_u64("AIEC_MCP_DEFAULT_TTL", 1800).clamp(60, 86_400),
            max_output_bytes: env_usize("AIEC_MCP_MAX_OUTPUT_BYTES", 1_048_576)
                .clamp(1024, 16_777_216),
            cleanup_on_shutdown: env_flag_or("AIEC_MCP_CLEANUP_ON_SHUTDOWN", true),
        })
    }
}

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

fn env_flag(name: &str) -> bool {
    env_flag_or(name, false)
}

fn env_flag_or(name: &str, fallback: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            value == "1" || value == "true" || value == "yes" || value == "on"
        }
        Err(_) => fallback,
    }
}

fn env_usize(name: &str, fallback: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(fallback)
}

fn env_u64(name: &str, fallback: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addresses_are_validated() {
        assert!("127.0.0.1:8765".parse::<SocketAddr>().is_ok());
        assert!("not-an-address".parse::<SocketAddr>().is_err());
    }
}
