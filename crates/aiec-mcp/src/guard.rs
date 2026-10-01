//! The local-only guarantee, enforced in code.
//!
//! This server exists to drive sandboxes on a private AIec control plane. If it
//! can be pointed at AIec Cloud or at a hosted provider, the isolation the user
//! is relying on silently stops existing, so the check lives here rather than in
//! documentation: every outbound AIec address is validated before a client is
//! constructed, and a runtime that is not a local one is refused.
//!
//! "Local" means, in order of decreasing confidence:
//!
//! * a loopback address (`127.0.0.0/8`, `::1`) — always allowed;
//! * a private or link-local address (RFC1918, `fe80::/10`) — allowed only when
//!   the operator has explicitly opted in, because a private LAN address is
//!   still a network hop and may not be this developer's own machine;
//! * anything else — refused. That includes `api.aiec.gobrowse.dev` and every
//!   DNS name that could resolve to a hosted provider.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{ErrorCode, McpError};

/// A validated AIec control-plane endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEndpoint {
    /// The URL as the client will use it.
    pub url: String,
    host: String,
    is_loopback: bool,
}

/// Outcome of a local-only check, kept for logging and for the health endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locality {
    Loopback,
    PrivateOptIn,
}

impl LocalEndpoint {
    /// Validates that `url` addresses a local control plane.
    ///
    /// `allow_private_network` is the operator's explicit opt-in for a control
    /// plane on their own LAN, which is how a single-host home or lab setup
    /// runs. It is off by default so that a mistyped or hostile configuration
    /// cannot reach the internet.
    pub fn parse(url: &str, allow_private_network: bool) -> Result<Self, McpError> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Err(McpError::invalid("the AIec base URL is empty"));
        }

        let rest = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .ok_or_else(|| {
                McpError::invalid(format!(
                    "the AIec base URL must be http:// or https://, got `{trimmed}`"
                ))
            })?;
        let scheme = &trimmed[..trimmed.len() - rest.len()];

        // Authority ends at the first '/', '?' or '#'; what follows is path,
        // query and fragment, kept as written.
        let (authority, tail) = match rest.find(['/', '?', '#']) {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        };
        // Strip any userinfo and IPv6 brackets, then keep host and port.
        let authority = match authority.rsplit_once('@') {
            Some((_, host)) => host,
            None => authority,
        };
        let (host, _port) = split_host_port(authority);

        if host.is_empty() {
            return Err(McpError::invalid(format!(
                "the AIec base URL has no host: `{trimmed}`"
            )));
        }

        let locality = classify_host(&host, allow_private_network)?;
        Ok(Self {
            // Rebuilt from the userinfo-free authority rather than kept as
            // `trimmed`: this string is logged at startup, returned by
            // aiec_health and served on the unauthenticated /health route, so a
            // credential embedded in the URL must not survive parsing.
            url: format!("{scheme}{authority}{tail}")
                .trim_end_matches('/')
                .to_owned(),
            host,
            is_loopback: locality == Locality::Loopback,
        })
    }

    /// Whether the control plane is on this machine.
    pub fn is_loopback(&self) -> bool {
        self.is_loopback
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// Rejects runtimes that would send the workload somewhere other than a
    /// local sandbox.
    ///
    /// `hosted` and the external provider runtimes are refused outright: the
    /// user asked for local compute, and a silent fallback to a provider is the
    /// one outcome that must never happen.
    pub fn require_local_runtime(runtime: &str) -> Result<(), McpError> {
        match runtime {
            "firecracker" | "bwrap-dev" | "docker" => Ok(()),
            "hosted" | "e2b" => Err(McpError::new(
                ErrorCode::LocalRuntimeUnavailable,
                format!(
                    "runtime `{runtime}` executes outside this machine; this server only \
                     drives local AIec sandboxes"
                ),
            )
            .with_details(serde_json::json!({
                "requested_runtime": runtime,
                "allowed_runtimes": ["firecracker", "bwrap-dev", "docker"],
            }))),
            other => Err(McpError::invalid(format!("unknown runtime `{other}`"))),
        }
    }
}

/// Splits `host:port`, handling bracketed IPv6 literals.
fn split_host_port(authority: &str) -> (String, Option<String>) {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        let port = tail.strip_prefix(':').map(str::to_owned);
        return (host.to_owned(), port);
    }
    match authority.rsplit_once(':') {
        // A bare IPv6 literal has several colons and no port.
        Some((host, port)) if !host.contains(':') && !port.is_empty() => {
            (host.to_owned(), Some(port.to_owned()))
        }
        _ => (authority.to_owned(), None),
    }
}

fn classify_host(host: &str, allow_private_network: bool) -> Result<Locality, McpError> {
    // An IP literal is decidable immediately.
    if let Ok(address) = host.parse::<IpAddr>() {
        return classify_address(address, allow_private_network, host);
    }

    // `localhost` and its subdomains are loopback by definition.
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Ok(Locality::Loopback);
    }

    // Any other DNS name is refused: it could resolve to a hosted provider, and
    // resolving it here would be a network call on the startup path.
    Err(remote_endpoint_error(host))
}

fn classify_address(
    address: IpAddr,
    allow_private_network: bool,
    host: &str,
) -> Result<Locality, McpError> {
    match address {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return Ok(Locality::Loopback);
            }
            if is_private_v4(v4) || v4.is_link_local() {
                if allow_private_network {
                    return Ok(Locality::PrivateOptIn);
                }
                return Err(private_network_error(host));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Ok(Locality::Loopback);
            }
            // Unique-local fc00::/7 and link-local fe80::/10.
            let unique_local = (v6.segments()[0] & 0xfe00) == 0xfc00;
            let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            if unique_local || link_local {
                if allow_private_network {
                    return Ok(Locality::PrivateOptIn);
                }
                return Err(private_network_error(host));
            }
            // IPv4-mapped loopback, e.g. ::ffff:127.0.0.1.
            if let Some(v4) = v6.to_ipv4_mapped()
                && v4.is_loopback()
            {
                return Ok(Locality::Loopback);
            }
        }
    }
    Err(remote_endpoint_error(host))
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    matches!(a, 10) || (a == 172 && (16..32).contains(&b)) || (a == 192 && b == 168)
}

fn remote_endpoint_error(host: &str) -> McpError {
    McpError::new(
        ErrorCode::InvalidArgument,
        format!(
            "`{host}` is not a local address; this server refuses to talk to AIec Cloud \
             or any external sandbox provider"
        ),
    )
    .with_details(serde_json::json!({
        "host": host,
        "hint": "use 127.0.0.1, ::1, or set AIEC_MCP_ALLOW_PRIVATE_NETWORK=1 for a \
                 control plane on your own private network",
    }))
}

fn private_network_error(host: &str) -> McpError {
    McpError::new(
        ErrorCode::InvalidArgument,
        format!(
            "`{host}` is on a private network but this server only trusts loopback by \
             default; set AIEC_MCP_ALLOW_PRIVATE_NETWORK=1 if that is your own machine"
        ),
    )
    .with_details(serde_json::json!({
        "host": host,
        "opt_in": "AIEC_MCP_ALLOW_PRIVATE_NETWORK=1",
    }))
}

/// Recognises a cloud endpoint by name so the error can name the actual problem.
pub fn describe_host(host: &str) -> &'static str {
    if host.ends_with("aiec.gobrowse.dev") {
        "AIec Cloud"
    } else if host.contains("e2b") {
        "an external sandbox provider"
    } else {
        "an external service"
    }
}

/// Reserved for the IPv6 loopback constant used above.
#[allow(dead_code)]
const LOOPBACK_V6: Ipv6Addr = Ipv6Addr::LOCALHOST;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_endpoints_are_accepted() {
        for url in [
            "http://127.0.0.1:18443",
            "https://127.0.0.1:18443/",
            "http://localhost:8080",
            "http://[::1]:18443",
            "http://127.0.0.2:1",
        ] {
            let endpoint = LocalEndpoint::parse(url, false).expect(url);
            assert!(endpoint.is_loopback(), "{url} should be loopback");
        }
    }

    #[test]
    fn the_cloud_endpoint_is_refused() {
        let error = LocalEndpoint::parse("https://api.aiec.gobrowse.dev", false).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(
            error.message.contains("AIec Cloud"),
            "the error should name the cloud: {}",
            error.message
        );
    }

    #[test]
    fn public_dns_names_are_refused_without_a_network_call() {
        for url in [
            "https://api.aiec.gobrowse.dev",
            "https://example.com",
            "https://8.8.8.8",
            "http://1.1.1.1:80",
        ] {
            assert!(
                LocalEndpoint::parse(url, true).is_err(),
                "{url} must be refused"
            );
        }
    }

    #[test]
    fn private_networks_need_an_explicit_opt_in() {
        let refused = LocalEndpoint::parse("https://192.168.1.250:18443", false).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidArgument);
        assert!(refused.message.contains("AIEC_MCP_ALLOW_PRIVATE_NETWORK"));

        let allowed = LocalEndpoint::parse("https://192.168.1.250:18443", true).unwrap();
        assert!(!allowed.is_loopback());
        assert_eq!(allowed.host(), "192.168.1.250");
    }

    #[test]
    fn every_rfc1918_range_is_recognised() {
        for host in ["10.0.0.5", "172.16.4.4", "172.31.255.1", "192.168.0.1"] {
            assert!(
                LocalEndpoint::parse(&format!("http://{host}:1"), false).is_err(),
                "{host} should need the opt-in"
            );
            assert!(
                LocalEndpoint::parse(&format!("http://{host}:1"), true).is_ok(),
                "{host} should be allowed with the opt-in"
            );
        }
        // 172.15 and 172.32 are outside RFC1918 and must stay refused even with
        // the opt-in, so the range is not implemented as a loose prefix test.
        for host in ["172.15.0.1", "172.32.0.1"] {
            assert!(LocalEndpoint::parse(&format!("http://{host}:1"), true).is_err());
        }
    }

    #[test]
    fn malformed_urls_are_rejected() {
        for url in ["", "ftp://127.0.0.1", "127.0.0.1:18443", "http://"] {
            assert!(
                LocalEndpoint::parse(url, true).is_err(),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn userinfo_cannot_disguise_a_remote_host() {
        let error =
            LocalEndpoint::parse("https://127.0.0.1@api.aiec.gobrowse.dev", false).unwrap_err();
        assert!(error.message.contains("aiec.gobrowse.dev"));
    }

    /// The userinfo is dropped to make the host decision, so it must not be
    /// kept for anything else either: `url` is printed at startup, returned by
    /// the health tool and served on the unauthenticated /health route.
    #[test]
    fn userinfo_is_stripped_from_the_stored_url() {
        let endpoint = LocalEndpoint::parse("https://af_live_secret@127.0.0.1:18443/", false)
            .expect("a loopback host is local whoever the userinfo claims");
        assert_eq!(endpoint.url, "https://127.0.0.1:18443");
        assert!(
            !endpoint.url.contains("af_live_secret"),
            "the stored URL still carries the credential: {}",
            endpoint.url
        );
        assert!(endpoint.is_loopback());
        assert_eq!(endpoint.host(), "127.0.0.1");
    }

    /// Only the userinfo is removed; the path and query are the operator's and
    /// the locality decision is unaffected either way.
    #[test]
    fn stripping_userinfo_keeps_the_path_and_the_locality() {
        let endpoint =
            LocalEndpoint::parse("http://user:pw@127.0.0.1:18443/v1/?debug=1", false).unwrap();
        assert_eq!(endpoint.url, "http://127.0.0.1:18443/v1/?debug=1");
        assert!(endpoint.is_loopback());
    }

    #[test]
    fn host_runtimes_are_refused() {
        for runtime in ["hosted", "e2b"] {
            let error = LocalEndpoint::require_local_runtime(runtime).unwrap_err();
            assert_eq!(error.code, ErrorCode::LocalRuntimeUnavailable);
        }
        for runtime in ["firecracker", "bwrap-dev", "docker"] {
            assert!(LocalEndpoint::require_local_runtime(runtime).is_ok());
        }
    }
}
