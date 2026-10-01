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

/// Whether this process is demonstrably in a network namespace of its own.
///
/// True only when the operator recorded the host's namespace inode and it
/// differs from ours. Unverifiable is treated as **not** isolated: a local-mock
/// exception must never be granted because the check could not be performed.
fn in_disposable_namespace() -> bool {
    let Some(host) = HOST_NETWORK_NAMESPACE.get() else {
        return false;
    };
    // `readlink`, not reading the file: `/proc/self/ns/net` is a symlink whose
    // target is the `net:[inode]` string, not a file with contents.
    std::fs::read_link("/proc/self/ns/net")
        .map(|own| own.to_string_lossy().trim() != host.trim())
        .unwrap_or(false)
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
