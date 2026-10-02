//! Reduced isolation is a declared downgrade, never a silent one.
//!
//! Guard's guarantees assume a microVM. A deployment that cannot provide one can
//! still run guarded workloads on a weaker boundary, but only by asking for it
//! explicitly and by saying so everywhere the runtime is reported: an operator
//! reading a sandbox, a worker reporting its capabilities, or an API client
//! looking at a created sandbox all see that the isolation they are relying on
//! is not the isolation the product is built around.

use crate::{RuntimeKind, runtime::RuntimeIsolation};

/// What a deployment is allowed to give up, and what it is told.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReducedIsolation {
    /// Set only by an operator who has explicitly accepted a weaker boundary.
    pub allowed: bool,
}

/// The isolation a runtime kind provides, and whether it is the real thing.
pub fn isolation_for(runtime: RuntimeKind) -> RuntimeIsolation {
    match runtime {
        RuntimeKind::Firecracker => RuntimeIsolation::MicroVm,
        RuntimeKind::Docker => RuntimeIsolation::Container,
        RuntimeKind::BwrapDev | RuntimeKind::Hosted => RuntimeIsolation::Process,
    }
}

/// Whether this runtime gives untrusted code a boundary worth defending.
pub fn is_full_isolation(runtime: RuntimeKind) -> bool {
    isolation_for(runtime) == RuntimeIsolation::MicroVm
}

/// A line an operator or a log can carry, naming what was given up.
pub fn notice(runtime: RuntimeKind) -> Option<String> {
    if is_full_isolation(runtime) {
        return None;
    }
    Some(format!(
        "reduced isolation: {} provides {} rather than a microVM; Guard's enforcement \
         assumes an attacker-controlled guest behind a kernel boundary it does not own",
        runtime.as_str(),
        isolation_for(runtime).as_str()
    ))
}

/// Whether a guarded workload may run here at all.
///
/// Default is no. A deployment that wants a guarded sandbox on a weaker runtime
/// says so once, in configuration, and the API keeps reporting the downgrade.
pub fn guarded_allowed(runtime: RuntimeKind, reduced: ReducedIsolation) -> Result<(), String> {
    if is_full_isolation(runtime) || reduced.allowed {
        return Ok(());
    }
    Err(format!(
        "guarded workloads need a microVM; {} provides {}. Set AIEC_ALLOW_REDUCED_ISOLATION=1 \
         to accept the downgrade explicitly.",
        runtime.as_str(),
        isolation_for(runtime).as_str()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_microvm_is_full_isolation() {
        assert!(is_full_isolation(RuntimeKind::Firecracker));
        for weaker in [
            RuntimeKind::Docker,
            RuntimeKind::BwrapDev,
            RuntimeKind::Hosted,
        ] {
            assert!(!is_full_isolation(weaker), "{:?}", weaker);
        }
    }

    #[test]
    fn a_microvm_needs_no_notice_and_a_weaker_runtime_names_itself() {
        assert!(notice(RuntimeKind::Firecracker).is_none());
        let said = notice(RuntimeKind::Docker).expect("a downgrade is reported");
        assert!(said.contains("docker"), "{said}");
        assert!(said.contains("container"), "{said}");
        assert!(said.contains("reduced isolation"), "{said}");
    }

    #[test]
    fn a_guarded_workload_is_refused_on_a_weaker_runtime_until_an_operator_says_otherwise() {
        let strict = ReducedIsolation::default();
        assert!(guarded_allowed(RuntimeKind::Firecracker, strict).is_ok());
        let refused = guarded_allowed(RuntimeKind::Docker, strict).expect_err("not without a yes");
        assert!(
            refused.contains("AIEC_ALLOW_REDUCED_ISOLATION"),
            "{refused}"
        );
        let accepted = ReducedIsolation { allowed: true };
        assert!(
            guarded_allowed(RuntimeKind::Docker, accepted).is_ok(),
            "an explicit opt-in is honoured"
        );
    }
}
