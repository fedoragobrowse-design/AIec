//! `aiec guard` - the operator surface for a guarded sandbox.
//!
//! Read-only views first, then the two actions that change authority: a
//! quarantine and a human policy decision. The credential a command needs is
//! the credential the control plane checks; nothing here decides anything the
//! control plane and the worker do not re-check.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde_json::{Value, json};

#[derive(Subcommand)]
pub enum GuardCommand {
    /// Compile and verify a policy without applying it.
    Verify {
        #[arg(long)]
        policy: std::path::PathBuf,
        #[arg(long)]
        boundary: Option<std::path::PathBuf>,
    },
    /// The sandbox's Guard state: policy hash, budgets and attachment.
    Show { sandbox_id: uuid::Uuid },
    /// Verified journal entries for the sandbox.
    Events {
        sandbox_id: uuid::Uuid,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Quarantine a sandbox now, as an operator.
    Quarantine {
        sandbox_id: uuid::Uuid,
        /// Why, in the operator's words. Recorded in the incident.
        #[arg(long, default_value = "operator-initiated quarantine")]
        reason: String,
    },
    /// Release a quarantined sandbox.
    Release {
        sandbox_id: uuid::Uuid,
        /// Who is releasing it, recorded in the incident.
        #[arg(long, default_value = "operator")]
        operator: String,
    },
    /// Pending and decided policy proposals.
    Proposals { sandbox_id: uuid::Uuid },
    /// Decide one proposal.
    Proposal {
        #[command(subcommand)]
        command: ProposalCommand,
    },
    /// The quarantine incident for a sandbox.
    Incident { sandbox_id: uuid::Uuid },
    /// Convert an OpenShell policy document into a Guard policy.
    ImportOpenshell {
        #[arg(long)]
        input: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
        #[arg(long)]
        l7_out: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum ProposalCommand {
    /// Approve a pending proposal. The control plane runs the verifier first.
    Approve {
        sandbox_id: uuid::Uuid,
        proposal_id: uuid::Uuid,
        #[arg(long)]
        operator: String,
    },
    /// Deny a pending proposal. Nothing about the policy changes.
    Deny {
        sandbox_id: uuid::Uuid,
        proposal_id: uuid::Uuid,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        note: Option<String>,
    },
}

/// One HTTP call, with the CLI's usual error surface.
async fn call(
    client: &reqwest::Client,
    url: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let verb = method.as_str().to_owned();
    let described = format!("{verb} {path}");
    let mut request = client
        .request(method, format!("{url}{path}"))
        .header("accept", "application/json");
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.with_context(|| described.clone())?;
    let status = response.status();
    let raw = response.text().await.unwrap_or_default();
    let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    if !status.is_success() {
        let message = parsed
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or(raw.as_str());
        anyhow::bail!("{status}: {message}");
    }
    Ok(parsed)
}

pub async fn guard_command(url: &str, key: Option<String>, command: GuardCommand) -> Result<()> {
    match command {
        GuardCommand::Verify { policy, boundary } => {
            let document = std::fs::read_to_string(&policy)
                .with_context(|| format!("read {}", policy.display()))?;
            let compiled = match &boundary {
                Some(path) => {
                    let text = std::fs::read_to_string(path)
                        .with_context(|| format!("read {}", path.display()))?;
                    let boundary: aiec_guard::compiler::OperatorBoundary =
                        aiec_guard::policy::parse_boundary(&text)?;
                    aiec_guard::compiler::compile(
                        &aiec_guard::policy::GuardConfig::from_yaml(&document)?
                            .effective_policy()?,
                        &boundary,
                    )?
                }
                None => {
                    let config = aiec_guard::policy::GuardConfig::from_yaml(&document)?;
                    aiec_guard::compiler::compile(
                        &config.effective_policy()?,
                        &aiec_guard::compiler::OperatorBoundary::production(),
                    )?
                }
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "verified": true,
                    "policy_hash": compiled.policy_hash(),
                    "network_default": "deny",
                }))?
            );
        }
        GuardCommand::ImportOpenshell { input, out, l7_out } => {
            let document = std::fs::read_to_string(&input)
                .with_context(|| format!("read {}", input.display()))?;
            match aiec_guard::openshell::import_openshell(&document) {
                Ok(imported) => {
                    std::fs::write(&out, aiec_guard::openshell::to_yaml(&imported.policy)?)
                        .with_context(|| format!("write {}", out.display()))?;
                    if let Some(path) = l7_out {
                        let l7 = imported.l7.ok_or_else(|| {
                            anyhow::anyhow!("the imported document carried no layer 7 policy")
                        })?;
                        std::fs::write(&path, aiec_guard::policy::l7_to_yaml(&l7)?)
                            .with_context(|| format!("write {}", path.display()))?;
                    }
                    println!("{}", serde_json::to_string_pretty(&imported.report)?);
                }
                Err(failure) => {
                    // No policy file is written when the import is refused: a
                    // partial conversion is not a smaller policy, it is a
                    // different one.
                    eprintln!("{}", serde_json::to_string_pretty(&failure.report)?);
                    std::process::exit(2);
                }
            }
        }
        GuardCommand::Show { sandbox_id } => {
            let client = authenticated(url, key).await?;
            let sandbox = call(
                &client,
                url,
                reqwest::Method::GET,
                &format!("/v1/sandboxes/{sandbox_id}"),
                None,
            )
            .await?;
            let environment = sandbox.get("environment").cloned().unwrap_or(Value::Null);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "sandbox_id": sandbox_id,
                    "state": sandbox.get("state"),
                    "guard_policy_hash": environment.get("guard_policy_hash"),
                    "topology": environment.get("guard").and_then(|g| g.get("topology")),
                }))?
            );
        }
        GuardCommand::Events { sandbox_id, limit } => {
            let client = authenticated(url, key).await?;
            let events = call(
                &client,
                url,
                reqwest::Method::GET,
                &format!("/v1/sandboxes/{sandbox_id}/events?limit={limit}"),
                None,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        GuardCommand::Incident { sandbox_id } => {
            let client = authenticated(url, key).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &call(
                        &client,
                        url,
                        reqwest::Method::GET,
                        &format!("/v1/sandboxes/{sandbox_id}/guard/incident"),
                        None,
                    )
                    .await?
                )?
            );
        }
        GuardCommand::Quarantine { sandbox_id, reason } => {
            let client = authenticated(url, key).await?;
            // The observation the watchdog would have sent is fetched from the
            // authoritative telemetry, so an operator quarantine is fenced the
            // same way an automatic one is.
            let fence = call(
                &client,
                url,
                reqwest::Method::GET,
                &format!("/v1/sandboxes/{sandbox_id}/guard/telemetry?after=0"),
                None,
            )
            .await?
            .get("fence")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("telemetry carried no ownership fence"))?;
            let policy_hash = call(
                &client,
                url,
                reqwest::Method::GET,
                &format!("/v1/sandboxes/{sandbox_id}/guard/telemetry?after=0"),
                None,
            )
            .await?
            .get("identity")
            .and_then(|i| i.get("policy_hash"))
            .and_then(|h| h.as_str())
            .unwrap_or_default()
            .to_owned();
            let incident = call(
                &client,
                url,
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{sandbox_id}/guard/quarantine"),
                Some(json!({
                    "fence": fence,
                    "policy_hash": policy_hash,
                    "rules": [{"rule": "operator.quarantine", "evidence_references": [reason]}],
                })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&incident)?);
        }
        GuardCommand::Release {
            sandbox_id,
            operator,
        } => {
            let client = authenticated(url, key).await?;
            let released = call(
                &client,
                url,
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{sandbox_id}/guard/release"),
                Some(json!({ "operator": operator })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&released)?);
        }
        GuardCommand::Proposals { sandbox_id } => {
            let client = authenticated(url, key).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &call(
                        &client,
                        url,
                        reqwest::Method::GET,
                        &format!("/v1/sandboxes/{sandbox_id}/guard/proposals"),
                        None,
                    )
                    .await?
                )?
            );
        }
        GuardCommand::Proposal { command } => {
            let client = authenticated(url, key).await?;
            let (sandbox_id, proposal_id, method, body) = match command {
                ProposalCommand::Approve {
                    sandbox_id,
                    proposal_id,
                    operator,
                } => (
                    sandbox_id,
                    proposal_id,
                    "approve",
                    json!({"operator_label": operator}),
                ),
                ProposalCommand::Deny {
                    sandbox_id,
                    proposal_id,
                    operator,
                    note,
                } => (
                    sandbox_id,
                    proposal_id,
                    "deny",
                    json!({"operator_label": operator, "note": note}),
                ),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &call(
                        &client,
                        url,
                        reqwest::Method::POST,
                        &format!(
                            "/v1/sandboxes/{sandbox_id}/guard/proposals/{proposal_id}/{method}"
                        ),
                        Some(body),
                    )
                    .await?
                )?
            );
        }
    }
    Ok(())
}

/// A plain HTTP client carrying the tenant key. The SDK client does not speak
/// the Guard routes, and the routes themselves are the authority on what a key
/// may do.
async fn authenticated(_url: &str, key: Option<String>) -> Result<reqwest::Client> {
    let key = key
        .or_else(|| std::env::var("AIEC_API_KEY").ok())
        .context("set --api-key, --api-key-file or AIEC_API_KEY")?;
    Ok(reqwest::Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))?,
            );
            headers
        })
        .build()?)
}
