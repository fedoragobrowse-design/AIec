//! Operator-only local-mock exemptions; never selected by a guest policy.

use crate::{GuardError, Result, compiler::OperatorBoundary};
use std::net::IpAddr;

/// Production has no test destinations. Local mocks require explicit opt-in,
/// a separate network namespace and benchmark-only addresses. The compiler
/// still checks exact host/port mappings and non-overridable protected ranges.
pub fn validate_operator_test_mode(boundary: &OperatorBoundary, enabled: bool) -> Result<()> {
    if boundary.test_destinations.is_empty() {
        return Ok(());
    }
    if !enabled
        || std::fs::read_link("/proc/self/ns/net")? == std::fs::read_link("/proc/1/ns/net")?
        || boundary
            .test_destinations
            .values()
            .flatten()
            .any(|address| match address {
                IpAddr::V4(address) => {
                    let octets = address.octets();
                    octets[0] != 198 || !matches!(octets[1], 18 | 19)
                }
                IpAddr::V6(_) => true,
            })
    {
        return Err(GuardError::Policy(
            "mock destinations require explicit local-test mode, an isolated network namespace, and 198.18.0.0/15 addresses".into(),
        ));
    }
    Ok(())
}
