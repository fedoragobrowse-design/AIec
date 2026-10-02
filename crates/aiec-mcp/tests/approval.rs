//! The approval hook's own tests: a high-risk call is refused when the service
//! cannot answer, and a low-risk call is not silently escalated.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use aiec_client::ClientError;
use aiec_mcp::approval::{
    Allowance, ApprovalDecision, ApprovalGate, ApprovalPolicy, ApprovalRefusal, Approver,
    approval_from_error,
};
use async_trait::async_trait;

struct Scripted {
    answer: Option<ApprovalDecision>,
    calls: AtomicUsize,
}

#[async_trait]
impl Approver for Scripted {
    fn requires_approval(&self, tool: &str) -> bool {
        tool.starts_with("destructive.")
    }

    async fn approve(
        &self,
        _sandbox: uuid::Uuid,
        _tool: &str,
        _detail: Option<&str>,
    ) -> Option<ApprovalDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answer.clone()
    }
}

fn scripted(answer: Option<ApprovalDecision>) -> Arc<Scripted> {
    Arc::new(Scripted {
        answer,
        calls: AtomicUsize::new(0),
    })
}

fn gate(answer: Option<ApprovalDecision>, fail_closed: bool) -> (ApprovalGate, Arc<Scripted>) {
    let approver = scripted(answer);
    (ApprovalGate::new(approver.clone(), fail_closed), approver)
}

#[tokio::test]
async fn a_read_needs_no_answer_and_is_never_asked() {
    let (gate, approver) = gate(
        Some(ApprovalDecision {
            approved: false,
            reason: None,
        }),
        true,
    );
    let outcome = gate
        .check(uuid::Uuid::nil(), "read.get", None)
        .await
        .expect("a read is not high risk");
    assert_eq!(outcome, Allowance::NotRequired);
    assert_eq!(approver.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_high_risk_call_with_an_unreachable_service_is_refused() {
    let (gate, approver) = gate(None, true);
    let refusal = gate
        .check(uuid::Uuid::nil(), "destructive.destroy", None)
        .await
        .expect_err("an unreachable approval service is not an approval");
    assert_eq!(refusal, ApprovalRefusal::Unavailable);
    assert!(refusal.to_string().contains("could not be reached"));
    assert_eq!(approver.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_operator_refusal_and_an_unreachable_service_are_different_refusals() {
    let (denied, _) = gate(
        Some(ApprovalDecision {
            approved: false,
            reason: Some("not this quarter".into()),
        }),
        true,
    );
    let refusal = denied
        .check(uuid::Uuid::nil(), "destructive.destroy", None)
        .await
        .expect_err("the operator said no");
    assert_eq!(
        refusal,
        ApprovalRefusal::Denied {
            reason: "not this quarter".into()
        }
    );
}

#[tokio::test]
async fn an_approved_high_risk_call_carries_the_reason_it_was_allowed() {
    let (gate, _) = gate(
        Some(ApprovalDecision {
            approved: true,
            reason: Some("incident 42".into()),
        }),
        true,
    );
    let allowance = gate
        .check(uuid::Uuid::nil(), "destructive.destroy", None)
        .await
        .expect("approved");
    assert_eq!(
        allowance,
        Allowance::Approved {
            reason: Some("incident 42".into())
        }
    );
}

/// A deployment that has classified nothing as high risk.
struct Permissive;

#[async_trait]
impl Approver for Permissive {
    fn requires_approval(&self, _tool: &str) -> bool {
        false
    }

    async fn approve(
        &self,
        _sandbox: uuid::Uuid,
        _tool: &str,
        _detail: Option<&str>,
    ) -> Option<ApprovalDecision> {
        None
    }
}

#[tokio::test]
async fn a_gate_asks_exactly_what_its_approver_says_it_asks_about() {
    let gate = ApprovalGate::new(Arc::new(Permissive), true);
    assert!(!gate.requires_approval("destructive.destroy"));
    assert!(!gate.requires_approval("anything.at.all"));
    // And the default policy does ask, which is why the two disagree.
    assert!(ApprovalPolicy::default().requires_approval("sandbox.destroy"));
}

#[tokio::test]
async fn a_forbidden_api_error_is_a_denial_and_other_failures_are_not() {
    let forbidden = ClientError::Api {
        status: reqwest::StatusCode::FORBIDDEN,
        code: "forbidden".into(),
        message: "high-risk operation refused".into(),
        request_id: uuid::Uuid::nil(),
    };
    assert!(matches!(
        approval_from_error(&forbidden),
        Some(ApprovalRefusal::Denied { .. })
    ));
    let broken = ClientError::Decode("not json".into());
    assert!(approval_from_error(&broken).is_none());
}

#[test]
fn the_default_policy_lists_the_operations_an_operator_would_not_want_done_to_them() {
    let policy = ApprovalPolicy::default();
    assert!(
        policy.fail_closed,
        "an unavailable service denies by default"
    );
    for tool in [
        "sandbox.destroy",
        "sandbox.write_file",
        "secret.set",
        "quarantine.release",
    ] {
        assert!(policy.requires_approval(tool), "{tool} must be asked about");
    }
    assert!(!policy.requires_approval("sandbox.list_owned"));
}
