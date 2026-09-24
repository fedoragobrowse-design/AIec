use agentforge_core::*;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, de::DeserializeOwned};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("API error {status}: {message} (request {request_id})")]
    Api {
        status: StatusCode,
        code: String,
        message: String,
        request_id: Uuid,
    },
    #[error("invalid response: {0}")]
    Decode(String),
}
#[derive(Debug, Deserialize)]
struct ErrorDocument {
    error: ApiErrorBody,
}

#[derive(Clone)]
pub struct AgentForgeClient {
    http: Client,
    base_url: String,
    api_key: String,
}
impl AgentForgeClient {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let http = Client::builder().timeout(Duration::from_secs(60)).build()?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            api_key: api_key.into(),
        })
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(&self.api_key)
    }
    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, ClientError> {
        let response = request.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            let document: ErrorDocument = serde_json::from_slice(&bytes)
                .map_err(|_| ClientError::Decode("malformed API error".into()))?;
            return Err(ClientError::Api {
                status,
                code: document.error.code,
                message: document.error.message,
                request_id: document.error.request_id,
            });
        }
        serde_json::from_slice(&bytes).map_err(|error| ClientError::Decode(error.to_string()))
    }
    pub async fn health(&self) -> Result<serde_json::Value, ClientError> {
        self.send(self.request(reqwest::Method::GET, "/health"))
            .await
    }
    pub async fn ready(&self) -> Result<serde_json::Value, ClientError> {
        self.send(self.request(reqwest::Method::GET, "/ready"))
            .await
    }
    pub async fn create_sandbox(
        &self,
        request: &CreateSandboxRequest,
    ) -> Result<Sandbox, ClientError> {
        self.send(
            self.request(reqwest::Method::POST, "/v1/sandboxes")
                .json(request),
        )
        .await
    }
    pub async fn list_sandboxes(&self) -> Result<Vec<Sandbox>, ClientError> {
        self.send(self.request(reqwest::Method::GET, "/v1/sandboxes"))
            .await
    }
    pub async fn get_sandbox(&self, id: Uuid) -> Result<Sandbox, ClientError> {
        self.send(self.request(reqwest::Method::GET, &format!("/v1/sandboxes/{id}")))
            .await
    }
    pub async fn delete_sandbox(&self, id: Uuid) -> Result<(), ClientError> {
        self.send_empty(self.request(reqwest::Method::DELETE, &format!("/v1/sandboxes/{id}")))
            .await
    }
    pub async fn start(&self, id: Uuid) -> Result<Sandbox, ClientError> {
        self.send(self.request(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/start")))
            .await
    }
    pub async fn stop(&self, id: Uuid) -> Result<Sandbox, ClientError> {
        self.send(self.request(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/stop")))
            .await
    }
    pub async fn resume(&self, id: Uuid) -> Result<Sandbox, ClientError> {
        self.send(self.request(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/resume")))
            .await
    }
    pub async fn exec(&self, id: Uuid, request: &ExecRequest) -> Result<ExecResult, ClientError> {
        self.send(
            self.request(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/exec"))
                .json(request),
        )
        .await
    }
    pub async fn put_file(&self, id: Uuid, request: &PutFileRequest) -> Result<(), ClientError> {
        self.send_empty(
            self.request(reqwest::Method::PUT, &format!("/v1/sandboxes/{id}/files"))
                .json(request),
        )
        .await
    }
    pub async fn get_file(&self, id: Uuid, path: &str) -> Result<FileContent, ClientError> {
        let url = format!("/v1/sandboxes/{id}/files/content?path={}", urlencode(path));
        self.send(self.request(reqwest::Method::GET, &url)).await
    }
    pub async fn list_files(&self, id: Uuid, path: &str) -> Result<Vec<FileEntry>, ClientError> {
        let url = format!("/v1/sandboxes/{id}/files?path={}", urlencode(path));
        self.send(self.request(reqwest::Method::GET, &url)).await
    }
    pub async fn delete_file(&self, id: Uuid, path: &str) -> Result<(), ClientError> {
        self.send_empty(self.request(
            reqwest::Method::DELETE,
            &format!("/v1/sandboxes/{id}/files?path={}", urlencode(path)),
        ))
        .await
    }
    pub async fn make_directory(&self, id: Uuid, path: &str) -> Result<(), ClientError> {
        self.send_empty(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{id}/files/mkdir"),
            )
            .json(&MakeDirectoryRequest { path: path.into() }),
        )
        .await
    }
    pub async fn create_snapshot(&self, id: Uuid) -> Result<Snapshot, ClientError> {
        self.send(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{id}/snapshots"),
            )
            .json(&serde_json::json!({})),
        )
        .await
    }
    pub async fn list_snapshots(&self, id: Uuid) -> Result<Vec<Snapshot>, ClientError> {
        self.send(self.request(
            reqwest::Method::GET,
            &format!("/v1/sandboxes/{id}/snapshots"),
        ))
        .await
    }
    pub async fn restore_snapshot(
        &self,
        id: Uuid,
        request: &RestoreSnapshotRequest,
    ) -> Result<Sandbox, ClientError> {
        self.send(
            self.request(
                reqwest::Method::POST,
                &format!("/v1/snapshots/{id}/restore"),
            )
            .json(request),
        )
        .await
    }
    pub async fn delete_snapshot(&self, id: Uuid) -> Result<(), ClientError> {
        self.send_empty(self.request(reqwest::Method::DELETE, &format!("/v1/snapshots/{id}")))
            .await
    }
    pub async fn usage(&self) -> Result<Vec<UsageSummary>, ClientError> {
        self.send(self.request(reqwest::Method::GET, "/v1/usage"))
            .await
    }
    async fn send_empty(&self, request: reqwest::RequestBuilder) -> Result<(), ClientError> {
        let response = request.send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let bytes = response.bytes().await?;
        let document: ErrorDocument = serde_json::from_slice(&bytes)
            .map_err(|_| ClientError::Decode("malformed API error".into()))?;
        Err(ClientError::Api {
            status,
            code: document.error.code,
            message: document.error.message,
            request_id: document.error.request_id,
        })
    }
}
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
