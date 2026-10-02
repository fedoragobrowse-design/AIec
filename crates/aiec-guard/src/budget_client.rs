//! Durable budget reservations through the existing worker/control-plane boundary.
use std::{net::IpAddr, path::Path, time::Duration};

use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    GuardError, Result,
    control::{BudgetAuthority, BudgetDebit, GuardFence, GuardIdentity, QuarantineRequest},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetReserveRequest<I = GuardIdentity> {
    pub identity: I,

    pub fence: GuardFence,
    pub debit: BudgetDebit,
}

/// The worker's authenticated critical-canary restriction request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerQuarantineRequest {
    pub identity: GuardIdentity,
    pub request: QuarantineRequest,
}

/// No retry or process-local fallback: an uncertain reservation refuses traffic.
#[derive(Clone)]
pub struct HttpBudgetAuthority {
    client: reqwest::Client,
    quarantine_endpoint: reqwest::Url,
    endpoint: reqwest::Url,
}

impl HttpBudgetAuthority {
    pub fn new(
        api_url: &str,
        token: Zeroizing<String>,
        node_id: Uuid,
        ca_cert: Option<&Path>,
        local_loopback_http: bool,
    ) -> Result<Self> {
        let mut endpoint = reqwest::Url::parse(api_url)
            .map_err(|_| GuardError::Policy("invalid control-plane URL".into()))?;
        let loopback = endpoint
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !(endpoint.scheme() == "https"
                || (endpoint.scheme() == "http" && local_loopback_http && loopback))
        {
            return Err(GuardError::Policy(
                "budget authority requires verified HTTPS or explicit numeric-loopback HTTP".into(),
            ));
        }
        if token.is_empty() || token.len() > 4096 {
            return Err(GuardError::Policy("invalid worker credential".into()));
        }
        let mut headers = HeaderMap::new();
        let mut bearer = Zeroizing::new(String::with_capacity(7 + token.len()));
        bearer.push_str("Bearer ");
        bearer.push_str(&token);
        let mut authorization = HeaderValue::from_str(&bearer)
            .map_err(|_| GuardError::Policy("invalid worker credential".into()))?;
        authorization.set_sensitive(true);
        headers.insert(AUTHORIZATION, authorization);
        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5));
        if let Some(path) = ca_cert {
            let metadata = std::fs::metadata(path)?;
            if !metadata.is_file() || metadata.len() > 1024 * 1024 {
                return Err(GuardError::Policy("invalid control-plane CA file".into()));
            }
            let certificate = reqwest::Certificate::from_pem(&std::fs::read(path)?)
                .map_err(|_| GuardError::Policy("invalid control-plane CA certificate".into()))?;
            builder = builder.add_root_certificate(certificate);
        }
        endpoint.set_path(&format!("/v1/workers/{node_id}/guard/reserve"));
        let mut quarantine_endpoint = endpoint.clone();
        quarantine_endpoint.set_path(&format!("/v1/workers/{node_id}/guard/quarantine"));
        let client = builder
            .build()
            .map_err(|_| GuardError::Unavailable("budget authority client unavailable".into()))?;
        Ok(Self {
            client,
            endpoint,
            quarantine_endpoint,
        })
    }
}

#[async_trait]
impl BudgetAuthority for HttpBudgetAuthority {
    async fn reserve(
        &self,
        identity: &GuardIdentity,
        fence: GuardFence,
        debit: BudgetDebit,
    ) -> Result<()> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&BudgetReserveRequest {
                identity,
                fence,
                debit,
            })
            .send()
            .await
            .map_err(|_| {
                GuardError::Unavailable("durable budget reservation unavailable".into())
            })?;
        match response.status() {
            reqwest::StatusCode::NO_CONTENT => Ok(()),
            reqwest::StatusCode::FORBIDDEN
            | reqwest::StatusCode::CONFLICT
            | reqwest::StatusCode::TOO_MANY_REQUESTS
            | reqwest::StatusCode::GONE => Err(GuardError::Denied(
                "durable budget reservation refused".into(),
            )),
            _ => Err(GuardError::Unavailable(
                "durable budget reservation failed".into(),
            )),
        }
    }

    /// Reports a critical canary to the control plane, which owns the durable
    /// quarantine. An uncertain report is an error rather than a release: the
    /// attachment has already cut, so the guest stays contained either way.
    async fn quarantine(&self, identity: &GuardIdentity, request: QuarantineRequest) -> Result<()> {
        if request.policy_hash != identity.policy_hash {
            return Err(GuardError::Denied(
                "quarantine names a different policy than the identity".into(),
            ));
        }
        let response = self
            .client
            .post(self.quarantine_endpoint.clone())
            .json(&WorkerQuarantineRequest {
                identity: identity.clone(),
                request,
            })
            .send()
            .await
            .map_err(|_| {
                GuardError::Unavailable("guard quarantine authority unavailable".into())
            })?;
        match response.status() {
            // An already-latched quarantine also answers 204, so a conflict is
            // a real binding failure rather than a duplicate report.
            reqwest::StatusCode::NO_CONTENT => Ok(()),
            reqwest::StatusCode::FORBIDDEN
            | reqwest::StatusCode::BAD_REQUEST
            | reqwest::StatusCode::CONFLICT => Err(GuardError::Denied(
                "guard quarantine refused by the control plane".into(),
            )),
            _ => Err(GuardError::Unavailable("guard quarantine failed".into())),
        }
    }
}
