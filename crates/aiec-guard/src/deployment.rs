//! Operator-only local-mock exemptions; never selected by a guest policy.

use crate::{GuardError, Result, compiler::OperatorBoundary};
use std::net::IpAddr;
use std::sync::OnceLock;

/// The host's network namespace inode, recorded before the launcher unshared.
///
/// `OnceLock` rather than `LazyLock` because the value is runtime input set once
/// by [`set_host_network_namespace`], not a constant initializer.
static HOST_NETWORK_NAMESPACE: OnceLock<String> = OnceLock::new();

/// Records the host's network namespace inode.
///
/// A fresh user+network namespace cannot read PID 1's namespace link at all -
/// it belongs to a process outside it - so comparing against it answers nothing
/// and fails with a permission error on exactly the configuration this is meant
/// to permit. The launcher knows the host's inode because it read it before
/// unsharing, and passes it in; that is the comparison.
///
/// Called once, from the acceptance driver's initialization.
pub fn set_host_network_namespace(inode: String) {
    let _ = HOST_NETWORK_NAMESPACE.set(inode);
}

/// Whether `own` names a network namespace other than `host`.
///
/// Separated from the process-global so both directions are testable: the
/// global can only be written once per process, so a test that set it would
/// make every later test order-dependent. Unverifiable is treated as **not**
/// isolated - a local-mock exception must never be granted because the check
/// could not be performed.
fn differs_from_host(own: Option<&std::path::Path>, host: Option<&str>) -> bool {
    // A recorded-but-empty inode is not a recording: `/proc/self/ns/net` never
    // reads as empty, so comparing against "" would answer "different" for a
    // process that is in fact on the host's namespace and hand the exception to
    // exactly the case it exists to refuse. Blank is treated as absent.
    let Some(host) = host.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    let Some(own) = own else {
        return false;
    };
    std::fs::read_link(own)
        .map(|value| value.to_string_lossy().trim() != host)
        .unwrap_or(false)
}

/// Whether this process is demonstrably in a network namespace of its own.
///
/// True only when the operator recorded the host's namespace inode and it
/// differs from ours. Unverifiable is treated as **not** isolated: a local-mock
/// exception must never be granted because the check could not be performed.
fn in_disposable_namespace() -> bool {
    differs_from_host(
        Some(std::path::Path::new("/proc/self/ns/net")),
        HOST_NETWORK_NAMESPACE.get().map(String::as_str),
    )
}

/// Production has no test destinations. Local mocks require explicit opt-in,
/// a separate network namespace and benchmark-only addresses. The compiler
/// still checks exact host/port mappings and non-overridable protected ranges.
pub fn validate_operator_test_mode(boundary: &OperatorBoundary, enabled: bool) -> Result<()> {
    if boundary.test_destinations.is_empty() {
        return Ok(());
    }
    if !enabled
        || !in_disposable_namespace()
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
            "mock destinations require explicit local-test mode, a network namespace of this \
             process's own (the launcher records the host's namespace inode before unsharing), \
             and 198.18.0.0/15 addresses"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::OperatorBoundary;

    fn boundary_with_mock() -> OperatorBoundary {
        let mut boundary = OperatorBoundary::default();
        boundary.test_destinations.insert(
            "mock.model.test:8080".to_string(),
            vec!["198.18.0.10".parse().expect("ip")],
        );
        boundary
    }

    /// The validator once compared `/proc/self/ns/net` against
    /// `/proc/1/ns/net`, which is unreadable from inside a fresh user and
    /// network namespace - so it refused on exactly the configuration it
    /// exists to permit. It now compares against the host inode the launcher
    /// recorded before unsharing. Unverifiable is still a refusal: an operator
    /// who recorded nothing has not demonstrated isolation.
    #[test]
    fn an_unrecorded_host_namespace_is_treated_as_not_isolated() {
        assert!(!differs_from_host(
            Some(std::path::Path::new("/proc/self/ns/net")),
            None,
        ));
    }

    /// An operator who set the variable and left it empty has recorded
    /// nothing, and nothing must not be read as "a different namespace" -
    /// that would grant the exception to a process sitting on the host's
    /// network, which is the one configuration the exception must never reach.
    #[test]
    fn a_blank_recorded_host_namespace_is_treated_as_not_isolated() {
        assert!(!differs_from_host(
            Some(std::path::Path::new("/proc/self/ns/net")),
            Some(""),
        ));
        assert!(!differs_from_host(
            Some(std::path::Path::new("/proc/self/ns/net")),
            Some("   "),
        ));
    }

    #[test]
    fn a_matching_namespace_inode_is_not_isolated() {
        let own = std::fs::read_link("/proc/self/ns/net").expect("this namespace");
        assert!(!differs_from_host(
            Some(std::path::Path::new("/proc/self/ns/net")),
            Some(&own.to_string_lossy()),
        ));
    }

    #[test]
    fn a_differing_namespace_inode_is_isolated() {
        let own = std::fs::read_link("/proc/self/ns/net").expect("this namespace");
        let other = if own.to_string_lossy().contains("1") {
            "net:[4026531999]"
        } else {
            "net:[1]"
        };
        assert!(differs_from_host(
            Some(std::path::Path::new("/proc/self/ns/net")),
            Some(other),
        ));
    }

    /// The end-to-end shape: with nothing recorded, a boundary carrying mock
    /// destinations is refused however test mode is set.
    #[test]
    fn a_mock_boundary_needs_a_recorded_and_different_namespace() {
        let boundary = boundary_with_mock();
        assert!(validate_operator_test_mode(&boundary, true).is_err());
        // And without mock destinations the check does not apply at all.
        assert!(validate_operator_test_mode(&OperatorBoundary::default(), false).is_ok());
    }

    /// A test address outside the benchmarking range is never acceptable, in any
    /// namespace: it is the rule that keeps a mock mapping from being pointed at
    /// something real.
    #[test]
    fn a_mock_address_outside_the_benchmark_range_is_refused() {
        let mut boundary = boundary_with_mock();
        boundary.test_destinations.insert(
            "mock.model.test:8080".to_string(),
            vec!["127.0.0.1".parse().expect("ip")],
        );
        assert!(validate_operator_test_mode(&boundary, true).is_err());
    }
}
