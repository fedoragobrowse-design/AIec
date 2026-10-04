//! Hosted sandbox runtime backed by the E2B managed Firecracker service.
//!
//! Public alpha runs untrusted workloads on this runtime when a deployment owns
//! no KVM host. The isolation boundary is the provider's, so the runtime speaks
//! two protocols: the E2B control plane over HTTPS for lifecycle operations, and
//! `envd`, the in-guest agent, for command execution and workspace files.
//!
//! # Identity
//!
//! AIec owns the public sandbox identity. The provider's sandbox id is
//! never surfaced to a client: the control plane writes it into
//! [`Sandbox::runtime_path`] with the state transition that follows
//! [`SandboxRuntime::create`], and every later operation resolves the provider
//! resource from that value. See [`RuntimePathProvider`] for the seam.
//!
//! # Capabilities E2B does not have
//!
//! E2B cannot produce an AIec virtual machine or memory snapshot, cannot
//! enforce a per-sandbox network allowlist, and cannot restart a sandbox that
//! was killed or expired. Those operations fail with a precise reason instead of
//! a faked result.

use crate::SandboxRuntime;
use aiec_core::runtime::{
    FileChunk, FileChunkRequest, RuntimeCapabilities, RuntimeHealth, RuntimeIsolation,
};
use aiec_core::snapshots::MAX_WORKSPACE_ARCHIVE_BYTES;
use aiec_core::{
    CoreError, DeleteFileRequest, ExecRequest, ExecResult, FileContent, FileEntry,
    MAX_EXEC_SECONDS, MAX_FILE, MAX_STDERR, MAX_STDOUT, MakeDirectoryRequest, NetworkPolicy,
    PutFileRequest, Sandbox,
};
use async_trait::async_trait;
use base64::Engine;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Prefix of the runtime-private provider handle stored in
/// [`Sandbox::runtime_path`].
const RUNTIME_PATH_PREFIX: &str = "e2b://";

/// E2B's production control plane.
const DEFAULT_API_BASE_URL: &str = "https://api.e2b.app";

/// Domain the provider serves guest agents from.
const DEFAULT_ENVD_DOMAIN: &str = "e2b.app";

/// Port `envd` listens on inside a provider sandbox.
const DEFAULT_ENVD_PORT: u16 = 49983;

/// Default template used when a sandbox does not name an E2B template.
const DEFAULT_TEMPLATE: &str = "base";

/// Provider ceiling for a single sandbox lifetime. The current Hobby plan caps
/// a sandbox at one hour, so a longer request can never be honoured and is
/// clamped here instead of being silently cut by the provider.
const MAX_PROVIDER_TIMEOUT_SECONDS: u64 = 3_600;

const DEFAULT_SANDBOX_TIMEOUT_SECONDS: u64 = 900;
const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
const WORKSPACE_ROOT: &str = "/workspace";

/// Connect protocol endpoints exposed by `envd`.
///
/// `envd` serves its gRPC services over the Connect protocol on plain HTTPS.
/// Unary calls answer with one JSON document; server streams answer with
/// length-prefixed envelopes.
const CONNECT_PROTOCOL_VERSION: &str = "1";
/// ConnectRPC's JSON media type. The plain `application/json` type is rejected
/// by envd with 415 Unsupported Media Type.
const CONNECT_CONTENT_TYPE: &str = "application/connect+json";

const ENVD_START: &str = "/process.Process/Start";
const ENVD_LIST_DIR: &str = "/filesystem.Filesystem/ListDir";
const ENVD_MAKE_DIR: &str = "/filesystem.Filesystem/MakeDir";
const ENVD_REMOVE: &str = "/filesystem.Filesystem/Remove";
const ENVELOPE_HEADER: usize = 5;
const ENVELOPE_COMPRESSED: u8 = 0b0000_0001;
const ENVELOPE_END: u8 = 0b0000_0010;

/// Provider error codes that mean "the provider has no room right now".
///
/// They are saturation conditions rather than a caller mistake, so they map to
/// [`CoreError::Unavailable`] and surface as a retryable HTTP 503. Mapping them
/// to [`CoreError::QuotaExceeded`] would report HTTP 429 `quota_exceeded`, which
/// clients read as "this tenant is over its own quota" and answer by refusing
/// further work instead of retrying.
const CAPACITY_ERROR_CODES: [&str; 3] = [
    "sandbox_capacity_unavailable",
    "sandbox_no_compatible_node",
    "sandbox_placement_timeout",
];

/// Control-plane seam for a runtime that allocates a third-party resource.
///
/// [`SandboxRuntime::create`] allocates the provider sandbox but cannot return
/// its identifier, so the runtime exposes the handle here and the control plane
/// persists it in [`Sandbox::runtime_path`] with the state transition that
/// follows `create`. Without that write the provider resource would be
/// unreachable after a control-plane restart.
pub trait RuntimePathProvider: Send + Sync {
    /// Returns the handle to persist, or `None` when this sandbox has no
    /// provider resource.
    fn runtime_path(&self, sandbox: &Sandbox) -> Option<String>;
}

/// Connection settings for the E2B provider.
pub struct E2bConfig {
    /// Control-plane base URL without a trailing slash.
    pub api_base_url: String,
    /// Provider API key. Never logged and never included in an error message.
    pub api_key: String,
    /// Template used when a sandbox does not name an E2B template itself.
    pub default_template: String,
    /// Sandbox lifetime requested at creation and by every connect.
    pub timeout_seconds: u64,
    /// Deadline for a single control-plane or guest-agent call.
    pub request_timeout: Duration,
    /// Port `envd` listens on inside a provider sandbox.
    pub envd_port: u16,
    /// Domain the provider serves guest agents from.
    pub envd_domain: String,
    /// Fixed guest-agent base URL, used by private gateways and by tests.
    pub envd_base_url: Option<String>,
    /// Whether the configured template ships the coding toolchain AIec's
    /// public workloads expect.
    ///
    /// AIec cannot inspect a provider template, so this is an operator
    /// assertion rather than something the runtime can verify: it defaults to
    /// false and only becomes true when AIEC_E2B_CODING_GUEST says so,
    /// because a policy admitting public workloads on this claim must never
    /// inherit it by accident.
    pub coding_guest: bool,
}

impl fmt::Debug for E2bConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("E2bConfig")
            .field("api_base_url", &self.api_base_url)
            .field("api_key", &"[redacted]")
            .field("default_template", &self.default_template)
            .field("timeout_seconds", &self.timeout_seconds)
            .field("request_timeout", &self.request_timeout)
            .field("envd_port", &self.envd_port)
            .field("envd_domain", &self.envd_domain)
            .field("envd_base_url", &self.envd_base_url)
            .field("coding_guest", &self.coding_guest)
            .finish()
    }
}

impl E2bConfig {
    /// Reads the hosted runtime configuration from the environment.
    ///
    /// Returns `Ok(None)` when no API key is configured, so a self-hosted
    /// deployment keeps running exactly as before.
    pub fn from_env_if_configured() -> Result<Option<Self>, CoreError> {
        match std::env::var("AIEC_E2B_API_KEY") {
            Ok(key) if !key.trim().is_empty() => Ok(Some(Self::from_env_with_key(key)?)),
            _ => Ok(None),
        }
    }

    /// Reads the hosted runtime configuration, failing when no key is set.
    pub fn from_env() -> Result<Self, CoreError> {
        let key = std::env::var("AIEC_E2B_API_KEY")
            .map_err(|_| CoreError::InvalidRequest("AIEC_E2B_API_KEY is required".into()))?;
        Self::from_env_with_key(key)
    }

    fn from_env_with_key(api_key: String) -> Result<Self, CoreError> {
        if api_key.trim().is_empty() {
            return Err(CoreError::InvalidRequest(
                "AIEC_E2B_API_KEY is empty".into(),
            ));
        }
        let api_base_url = env_or("AIEC_E2B_API_URL", DEFAULT_API_BASE_URL);
        if !(api_base_url.starts_with("https://") || api_base_url.starts_with("http://")) {
            return Err(CoreError::InvalidRequest(
                "AIEC_E2B_API_URL must be an http or https URL".into(),
            ));
        }
        let envd_port = env_number("AIEC_E2B_ENVD_PORT", u64::from(DEFAULT_ENVD_PORT));
        Ok(Self {
            api_base_url,
            api_key,
            default_template: env_or("AIEC_E2B_TEMPLATE", DEFAULT_TEMPLATE),
            timeout_seconds: env_number(
                "AIEC_E2B_TIMEOUT_SECONDS",
                DEFAULT_SANDBOX_TIMEOUT_SECONDS,
            )
            .clamp(1, MAX_PROVIDER_TIMEOUT_SECONDS),
            request_timeout: Duration::from_secs(
                env_number(
                    "AIEC_E2B_REQUEST_TIMEOUT_SECONDS",
                    DEFAULT_REQUEST_TIMEOUT_SECONDS,
                )
                .clamp(1, 600),
            ),
            envd_port: u16::try_from(envd_port).map_err(|_| {
                CoreError::InvalidRequest("AIEC_E2B_ENVD_PORT is not a port".into())
            })?,
            envd_domain: env_or("AIEC_E2B_ENVD_DOMAIN", DEFAULT_ENVD_DOMAIN),
            envd_base_url: std::env::var("AIEC_E2B_ENVD_BASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            // Fail closed: AIec cannot inspect a provider template, so
            // the coding-toolchain claim is the operator's to make explicitly
            // once the template they point at has been verified.
            coding_guest: env_flag("AIEC_E2B_CODING_GUEST", false),
        })
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{path}", self.api_base_url.trim_end_matches('/'))
    }

    /// Base URL of the guest agent for one provider sandbox.
    fn envd_url(&self, provider_sandbox_id: &str, path: &str) -> String {
        match &self.envd_base_url {
            Some(base) => format!("{}/{provider_sandbox_id}{path}", base.trim_end_matches('/')),
            None => format!(
                "https://{}-{}.{}{path}",
                self.envd_port, provider_sandbox_id, self.envd_domain
            ),
        }
    }
}

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

fn env_number(name: &str, fallback: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(fallback)
}

fn env_flag(name: &str, fallback: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => fallback,
    }
}

/// Provider sandbox together with the token its guest agent requires.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProviderSandbox {
    id: String,
    access_token: String,
}

/// Control-plane view of a provider sandbox.
///
/// The provider returns far more fields than the runtime needs; unknown fields
/// are ignored so a provider addition cannot break decoding.
#[derive(Debug, serde::Deserialize)]
struct ProviderSandboxInfo {
    #[serde(rename = "sandboxID")]
    sandbox_id: String,
    #[serde(rename = "envdAccessToken", default)]
    envd_access_token: Option<String>,
}

/// A hosted sandbox runtime backed by E2B.
pub struct E2bRuntime {
    client: reqwest::Client,
    config: Arc<E2bConfig>,
    /// Provider handles allocated by this process, keyed by AIec sandbox
    /// id. The persisted [`Sandbox::runtime_path`] stays authoritative; this
    /// only saves a control-plane round trip between operations.
    bindings: Mutex<HashMap<Uuid, ProviderSandbox>>,
}

/// One guest command invocation, bundled so a caller cannot pass a partial set.
struct GuestExec {
    working_directory: Option<String>,
    environment: BTreeMap<String, String>,
    stdin: Option<String>,
    timeout_seconds: u64,
    stdout_limit: Option<usize>,
}

impl fmt::Debug for E2bRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("E2bRuntime")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl E2bRuntime {
    /// Builds a runtime for the configured provider account.
    pub fn new(config: E2bConfig) -> Result<Self, CoreError> {
        let client = reqwest::Client::builder()
            .connect_timeout(config.request_timeout)
            .build()
            .map_err(|error| {
                CoreError::Unavailable(format!("E2B HTTP client could not be created: {error}"))
            })?;
        Ok(Self {
            client,
            config: Arc::new(config),
            bindings: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the provider handle AIec should persist for a sandbox.
    ///
    /// The persisted value wins, because it is the only handle that survives a
    /// control-plane restart.
    pub fn provider_sandbox_id(&self, sandbox: &Sandbox) -> Option<String> {
        if let Some(id) = sandbox.runtime_path.as_deref().and_then(parse_runtime_path) {
            return Some(id.to_owned());
        }
        self.bindings
            .try_lock()
            .ok()
            .and_then(|bindings| bindings.get(&sandbox.id).map(|binding| binding.id.clone()))
    }

    /// Template this runtime falls back to when a sandbox carries an AIec
    /// content address instead of a provider template id.
    pub fn provider_template(&self) -> &str {
        &self.config.default_template
    }

    async fn remember(&self, sandbox_id: Uuid, binding: ProviderSandbox) {
        self.bindings.lock().await.insert(sandbox_id, binding);
    }

    async fn cached(&self, sandbox_id: Uuid) -> Option<ProviderSandbox> {
        self.bindings.lock().await.get(&sandbox_id).cloned()
    }

    /// Resolves the live provider sandbox backing an AIec sandbox.
    async fn binding(&self, sandbox: &Sandbox) -> Result<ProviderSandbox, CoreError> {
        let persisted = sandbox.runtime_path.as_deref().and_then(parse_runtime_path);
        if let Some(cached) = self.cached(sandbox.id).await
            && persisted.is_none_or(|id| id == cached.id)
        {
            return Ok(cached);
        }
        let Some(id) = persisted else {
            return Err(CoreError::NotFound(format!(
                "hosted sandbox {} has no E2B provider binding",
                sandbox.id
            )));
        };
        let binding = self.refresh(id).await?;
        self.remember(sandbox.id, binding.clone()).await;
        Ok(binding)
    }

    /// Returns the provider sandbox for an AIec sandbox that already owns
    /// one, if that sandbox still exists at the provider.
    ///
    /// A handle whose sandbox is gone is reported as absent so `create` can
    /// allocate a replacement instead of failing every retry.
    async fn existing_binding(
        &self,
        sandbox: &Sandbox,
    ) -> Result<Option<ProviderSandbox>, CoreError> {
        let Some(id) = sandbox.runtime_path.as_deref().and_then(parse_runtime_path) else {
            return Ok(None);
        };
        if let Some(cached) = self.cached(sandbox.id).await
            && cached.id == id
        {
            return Ok(Some(cached));
        }
        match self.refresh(id).await {
            Ok(binding) => Ok(Some(binding)),
            Err(CoreError::NotFound(_)) => {
                tracing::warn!(
                    sandbox_id = %sandbox.id,
                    provider_sandbox_id = %id,
                    "persisted E2B sandbox no longer exists; a replacement will be created"
                );
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Reads a provider sandbox and refreshes the guest agent token.
    async fn refresh(&self, provider_sandbox_id: &str) -> Result<ProviderSandbox, CoreError> {
        let info = self.fetch(provider_sandbox_id).await?;
        Ok(ProviderSandbox {
            id: provider_sandbox_id.to_owned(),
            access_token: info.envd_access_token.unwrap_or_default(),
        })
    }

    async fn control(
        &self,
        request: reqwest::RequestBuilder,
        operation: &str,
    ) -> Result<reqwest::Response, CoreError> {
        let response = request
            .header("X-API-Key", &self.config.api_key)
            .timeout(self.config.request_timeout)
            .send()
            .await
            .map_err(|error| transport_error(error, operation, self.config.request_timeout))?;
        if response.status().is_success() {
            return Ok(response);
        }
        Err(provider_error(response, operation).await)
    }

    async fn fetch(&self, provider_sandbox_id: &str) -> Result<ProviderSandboxInfo, CoreError> {
        let response = self
            .control(
                self.client.get(self.config.api_url(&format!(
                    "/sandboxes/{}",
                    encode_path_segment(provider_sandbox_id)
                ))),
                "get sandbox",
            )
            .await?;
        decode_info(response, provider_sandbox_id).await
    }

    /// Resumes a paused sandbox, or refreshes a running one.
    ///
    /// E2B has one operation for both: connect returns the sandbox and extends
    /// its lifetime, resuming it first when it is paused.
    async fn connect(&self, binding: &ProviderSandbox) -> Result<(), CoreError> {
        let response = self
            .control(
                self.client
                    .post(self.config.api_url(&format!(
                        "/v2/sandboxes/{}/connect",
                        encode_path_segment(&binding.id)
                    )))
                    .json(&json!({
                        "timeout": self.config.timeout_seconds,
                        "memory": true,
                    })),
                "connect sandbox",
            )
            .await?;
        let info = decode_info(response, &binding.id).await?;
        // A resumed sandbox comes back with a fresh guest agent token.
        if let Some(token) = info.envd_access_token.filter(|token| !token.is_empty()) {
            let mut bindings = self.bindings.lock().await;
            for entry in bindings.values_mut().filter(|entry| entry.id == binding.id) {
                entry.access_token = token.clone();
            }
        }
        Ok(())
    }

    fn envd_request(
        &self,
        binding: &ProviderSandbox,
        method: reqwest::Method,
        path: &str,
    ) -> reqwest::RequestBuilder {
        let request = self
            .client
            .request(method, self.config.envd_url(&binding.id, path));
        if binding.access_token.is_empty() {
            request
        } else {
            request.header("X-Access-Token", &binding.access_token)
        }
        .header("E2b-Sandbox-Id", &binding.id)
        .header("E2b-Sandbox-Port", self.config.envd_port.to_string())
    }

    /// Calls a unary `envd` method and decodes its JSON response.
    async fn envd_unary<T: serde::de::DeserializeOwned>(
        &self,
        binding: &ProviderSandbox,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<T, CoreError> {
        let response = self
            .envd_request(binding, reqwest::Method::POST, path)
            .header("Content-Type", "application/json")
            .header("Connect-Protocol-Version", CONNECT_PROTOCOL_VERSION)
            .timeout(self.config.request_timeout)
            .json(&body)
            .send()
            .await
            .map_err(|error| guest_transport(error, method))?;
        if !response.status().is_success() {
            return Err(guest_status(
                response.status().as_u16(),
                method,
                provider_detail(response).await,
            ));
        }
        response.json::<T>().await.map_err(|error| {
            CoreError::Backend(format!(
                "envd {method} returned an unreadable response: {error}"
            ))
        })
    }

    async fn make_directory_raw(
        &self,
        binding: &ProviderSandbox,
        path: &str,
    ) -> Result<(), CoreError> {
        // Every filesystem method echoes the entry it touched; an empty object
        // decodes for all of them.
        let _: Value = self
            .envd_unary(
                binding,
                "make directory",
                ENVD_MAKE_DIR,
                json!({ "path": path }),
            )
            .await?;
        Ok(())
    }

    async fn upload(
        &self,
        binding: &ProviderSandbox,
        path: &str,
        content: &[u8],
    ) -> Result<(), CoreError> {
        let response = self
            .envd_request(binding, reqwest::Method::POST, "/files")
            .query(&[("path", path)])
            .header("Content-Type", "application/octet-stream")
            .timeout(self.config.request_timeout)
            .body(content.to_vec())
            .send()
            .await
            .map_err(|error| guest_transport(error, "file write"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(guest_status(
                response.status().as_u16(),
                "file write",
                provider_detail(response).await,
            ))
        }
    }

    async fn run_command(
        &self,
        binding: &ProviderSandbox,
        command: &[String],
        working_directory: Option<String>,
        environment: BTreeMap<String, String>,
        stdin: Option<String>,
        timeout_seconds: u64,
    ) -> Result<ExecResult, CoreError> {
        self.run_exec(
            binding,
            command,
            GuestExec {
                working_directory,
                environment,
                stdin,
                timeout_seconds,
                stdout_limit: None,
            },
        )
        .await
    }

    async fn run_exec(
        &self,
        binding: &ProviderSandbox,
        command: &[String],
        options: GuestExec,
    ) -> Result<ExecResult, CoreError> {
        let GuestExec {
            working_directory,
            environment,
            stdin,
            timeout_seconds,
            stdout_limit,
        } = options;
        let Some((program, arguments)) = command.split_first() else {
            return Err(CoreError::InvalidRequest("empty command".into()));
        };
        let seconds = timeout_seconds.clamp(1, MAX_EXEC_SECONDS);
        let process = json!({
            "cmd": program,
            "args": arguments,
            "envs": environment,
            "cwd": working_directory.unwrap_or_else(|| WORKSPACE_ROOT.to_owned()),
        });
        let mut body = envelope(&encode_json(&json!({ "process": process }))?)?;
        if let Some(input) = stdin {
            if input.len() > MAX_FILE {
                return Err(CoreError::LimitExceeded("stdin".into()));
            }
            let frame = encode_json(&json!({
                "data": { "stdin": base64::engine::general_purpose::STANDARD.encode(input.as_bytes()) }
            }))?;
            body.extend_from_slice(&envelope(&frame)?);
        }
        // Client half-close: without it the guest keeps the process stdin open
        // and the command would never observe EOF.
        body.extend_from_slice(&end_stream_frame());

        let started = Instant::now();
        let mut response = self
            .envd_request(binding, reqwest::Method::POST, ENVD_START)
            .header("Content-Type", CONNECT_CONTENT_TYPE)
            .header("Connect-Protocol-Version", CONNECT_PROTOCOL_VERSION)
            .body(body)
            .send()
            .await
            .map_err(|error| guest_transport(error, "exec"))?;
        if !response.status().is_success() {
            return Err(guest_status(
                response.status().as_u16(),
                "exec",
                provider_detail(response).await,
            ));
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
        let mut decoder = StreamDecoder {
            stdout_limit,
            ..StreamDecoder::default()
        };
        let mut timed_out = false;
        while !decoder.finished {
            match tokio::time::timeout_at(deadline, response.chunk()).await {
                Err(_elapsed) => {
                    timed_out = true;
                    break;
                }
                Ok(Ok(Some(chunk))) => decoder.push(&chunk)?,
                Ok(Ok(None)) => break,
                Ok(Err(error)) => {
                    return Err(guest_transport(error, "exec stream"));
                }
            }
        }
        if let Some(message) = &decoder.error {
            return Err(CoreError::Backend(format!("envd exec failed: {message}")));
        }
        let stderr = String::from_utf8_lossy(&decoder.stderr).into_owned();
        Ok(ExecResult {
            exit_code: if timed_out {
                124
            } else {
                decoder.exit_code.unwrap_or(0)
            },
            stdout: String::from_utf8_lossy(&decoder.stdout).into_owned(),
            stderr: if timed_out {
                format!("{stderr}\ncommand timed out")
            } else {
                stderr
            },
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            timed_out,
        })
    }
}

impl RuntimePathProvider for E2bRuntime {
    fn runtime_path(&self, sandbox: &Sandbox) -> Option<String> {
        self.provider_sandbox_id(sandbox)
            .map(|id| format_runtime_path(&id))
    }
}

#[async_trait]
impl SandboxRuntime for E2bRuntime {
    async fn create(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        // A retried create must never allocate a second provider sandbox: one
        // AIec sandbox id owns exactly one E2B sandbox.
        if let Some(existing) = self.existing_binding(sandbox).await? {
            self.remember(sandbox.id, existing).await;
            return Ok(());
        }
        let allow_internet_access = match sandbox.network {
            NetworkPolicy::Internet => true,
            NetworkPolicy::Disabled => false,
            NetworkPolicy::Restricted { .. } => {
                return Err(CoreError::Unsupported(
                    "E2B hosted sandboxes cannot enforce a per-sandbox host allowlist".into(),
                ));
            }
        };
        let template = template_for(&sandbox.image_id, &self.config.default_template);
        let timeout_seconds = sandbox
            .timeout_seconds
            .min(self.config.timeout_seconds)
            .clamp(1, MAX_PROVIDER_TIMEOUT_SECONDS);
        let response = self
            .control(
                self.client
                    .post(self.config.api_url("/v2/sandboxes"))
                    .json(&json!({
                        "templateID": template,
                        "timeout": timeout_seconds,
                        "allow_internet_access": allow_internet_access,
                        "metadata": { "aiec_sandbox_id": sandbox.id.to_string() },
                    })),
                "create sandbox",
            )
            .await?;
        let info = decode_info(response, "created sandbox").await?;
        let binding = ProviderSandbox {
            id: info.sandbox_id,
            access_token: info.envd_access_token.unwrap_or_default(),
        };
        tracing::info!(
            sandbox_id = %sandbox.id,
            provider_sandbox_id = %binding.id,
            %template,
            "hosted sandbox created"
        );
        self.remember(sandbox.id, binding.clone()).await;
        // The template must expose the workspace root every AIec file and
        // exec operation addresses; `envd` creates it when it is absent.
        self.make_directory_raw(&binding, WORKSPACE_ROOT).await?;
        Ok(())
    }

    async fn start(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        // E2B sandboxes run from creation, so start is the provider's connect
        // call: it resumes a paused sandbox and extends a running one's life.
        let binding = self.binding(sandbox).await?;
        self.connect(&binding).await
    }

    async fn stop(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        // E2B has no terminal stop. Pausing is the only reversible suspension
        // that keeps the workspace, which is exactly the stop-then-start
        // contract; releasing the sandbox for good is `destroy`.
        self.pause(sandbox).await
    }

    async fn pause(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        let binding = self.binding(sandbox).await?;
        self.control(
            self.client
                .post(self.config.api_url(&format!(
                    "/sandboxes/{}/pause",
                    encode_path_segment(&binding.id)
                )))
                .json(&json!({ "memory": true })),
            "pause sandbox",
        )
        .await
        .map(|_| ())
    }

    async fn resume(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        let binding = self.binding(sandbox).await?;
        self.connect(&binding).await
    }

    async fn exec(&self, sandbox: &Sandbox, request: ExecRequest) -> Result<ExecResult, CoreError> {
        aiec_core::validate_exec(&request)?;
        let binding = self.binding(sandbox).await?;
        let working_directory = request
            .working_directory
            .as_deref()
            .map(workspace_path)
            .transpose()?
            .map(|path| path.to_string_lossy().into_owned());
        self.run_command(
            &binding,
            &request.command,
            working_directory,
            request.environment,
            request.stdin,
            request.timeout_seconds,
        )
        .await
    }

    async fn put_file(&self, sandbox: &Sandbox, request: PutFileRequest) -> Result<(), CoreError> {
        let path = workspace_path(&request.path)?;
        let content = base64::engine::general_purpose::STANDARD
            .decode(request.content_base64.as_bytes())
            .map_err(|_| CoreError::InvalidRequest("file content is not valid base64".into()))?;
        if content.len() > MAX_FILE {
            return Err(CoreError::LimitExceeded("file content".into()));
        }
        let binding = self.binding(sandbox).await?;
        self.upload(&binding, &path.to_string_lossy(), &content)
            .await
    }

    async fn get_file_chunk(
        &self,
        sandbox: &Sandbox,
        request: FileChunkRequest,
    ) -> Result<FileChunk, CoreError> {
        request.validate()?;
        let mut request = request;
        request.path = workspace_path(&request.path)?
            .to_string_lossy()
            .into_owned();
        let binding = self.binding(sandbox).await?;
        // envd /files follows symlinks: a separate stat + HTTP range cannot
        // protect against link swaps. Read the range through one guest-held
        // descriptor and emit a bounded byte array on its existing RPC stream.
        const READ: &str = r#"import os,sys,stat,json
r=json.loads(sys.argv[1])
def opened():
 fd=os.open('/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  parts=r['path'].removeprefix('/workspace/').split('/')
  for i,part in enumerate(parts):
   n=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_DIRECTORY if i<len(parts)-1 else 0),dir_fd=fd)
   os.close(fd)
   fd=n
  return fd
 except:
  os.close(fd)
  raise
def version(s):
 return f'{s.st_dev}:{s.st_ino}:{s.st_size}:{s.st_mtime_ns}:{s.st_ctime_ns}'
fd=None
try:
 if not 1<=r['length']<=65536: raise ValueError('invalid chunk length')
 fd=opened()
 s=os.fstat(fd)
 if not stat.S_ISREG(s.st_mode): raise ValueError('not a regular file')
 if s.st_size>16777216:
  print(json.dumps({'code':'limit_exceeded','error':'file too large'}))
 else:
  v=version(s)
  if r['offset']>s.st_size or r['offset']<0 or (r['expected_version'] is not None and r['expected_version']!=v):
   raise ValueError('file changed or invalid offset')
  n=min(r['length'],s.st_size-r['offset'])
  data=os.pread(fd,n,r['offset'])
  after=opened()
  try:
   if len(data)!=n or version(os.fstat(fd))!=v or version(os.fstat(after))!=v:
    raise ValueError('file changed while reading')
  finally:
   os.close(after)
  print(json.dumps({'content':list(data),'size_bytes':s.st_size,'version':v,'eof':r['offset']+n==s.st_size},separators=(',',':')))
except Exception as e:
 print(json.dumps({'code':'not_found' if isinstance(e,FileNotFoundError) else 'conflict','error':str(e)[:1024]}))
finally:
 if fd is not None: os.close(fd)
"#;
        let result = self
            .run_exec(
                &binding,
                &[
                    "python3".into(),
                    "-c".into(),
                    READ.into(),
                    serde_json::to_string(&request)
                        .map_err(|error| CoreError::Backend(error.to_string()))?,
                ],
                GuestExec {
                    working_directory: None,
                    environment: BTreeMap::new(),
                    stdin: None,
                    timeout_seconds: 30,
                    stdout_limit: Some(request.length * 4 + 4096),
                },
            )
            .await?;
        if result.exit_code != 0 {
            return Err(CoreError::Backend(format!(
                "guest range read failed: {}",
                result.stderr.trim()
            )));
        }
        #[derive(serde::Deserialize)]
        struct GuestChunk {
            #[serde(
                default,
                deserialize_with = "aiec_core::runtime::deserialize_file_chunk_bytes"
            )]
            content: Vec<u8>,
            #[serde(default)]
            size_bytes: u64,
            #[serde(default)]
            version: String,
            #[serde(default)]
            eof: bool,
            error: Option<String>,
            code: Option<String>,
        }
        let reply: GuestChunk = serde_json::from_str(&result.stdout).map_err(|error| {
            CoreError::Backend(format!("invalid guest range response: {error}"))
        })?;
        if let Some(error) = reply.error {
            return Err(match reply.code.as_deref() {
                Some("limit_exceeded") => CoreError::LimitExceeded(error),
                Some("not_found") => CoreError::NotFound(error),
                _ => CoreError::Conflict(error),
            });
        }
        let chunk = FileChunk {
            bytes: reply.content.into(),
            size_bytes: reply.size_bytes,
            version: reply.version,
            eof: reply.eof,
        };
        request.validate_chunk(&chunk)?;
        Ok(chunk)
    }
    async fn get_file(&self, sandbox: &Sandbox, path: &str) -> Result<FileContent, CoreError> {
        let path = workspace_path(path)?;
        let binding = self.binding(sandbox).await?;
        let response = self
            .envd_request(&binding, reqwest::Method::GET, "/files")
            .query(&[("path", path.to_string_lossy().as_ref())])
            .timeout(self.config.request_timeout)
            .send()
            .await
            .map_err(|error| guest_transport(error, "file read"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CoreError::NotFound(format!(
                "no such file: {}",
                path.to_string_lossy()
            )));
        }
        if !response.status().is_success() {
            return Err(guest_status(
                response.status().as_u16(),
                "file read",
                provider_detail(response).await,
            ));
        }
        let content = read_bounded(response, MAX_FILE, "file read").await?;
        Ok(FileContent {
            path: path.to_string_lossy().into_owned(),
            content_base64: base64::engine::general_purpose::STANDARD.encode(&content),
        })
    }

    async fn list_files(&self, sandbox: &Sandbox, path: &str) -> Result<Vec<FileEntry>, CoreError> {
        let path = workspace_path(path)?;
        let binding = self.binding(sandbox).await?;
        let listing: Value = self
            .envd_unary(
                &binding,
                "list directory",
                ENVD_LIST_DIR,
                json!({ "path": path, "depth": 1 }),
            )
            .await?;
        file_entries(&listing, &path)
    }

    async fn delete_file(
        &self,
        sandbox: &Sandbox,
        request: DeleteFileRequest,
    ) -> Result<(), CoreError> {
        let path = workspace_path(&request.path)?;
        let binding = self.binding(sandbox).await?;
        let _: Value = self
            .envd_unary(
                &binding,
                "remove path",
                ENVD_REMOVE,
                json!({ "path": path }),
            )
            .await?;
        Ok(())
    }

    async fn make_directory(
        &self,
        sandbox: &Sandbox,
        request: MakeDirectoryRequest,
    ) -> Result<(), CoreError> {
        let path = workspace_path(&request.path)?;
        let binding = self.binding(sandbox).await?;
        self.make_directory_raw(&binding, &path.to_string_lossy())
            .await
    }

    async fn import_workspace_archive(
        &self,
        sandbox: &Sandbox,
        archive: &[u8],
    ) -> Result<(), CoreError> {
        if archive.len() > MAX_WORKSPACE_ARCHIVE_BYTES {
            return Err(CoreError::LimitExceeded(
                "workspace snapshot exceeds 64 MiB".into(),
            ));
        }
        let binding = self.binding(sandbox).await?;
        // The archive is staged outside the workspace, so a failed extraction
        // cannot leave the live workspace half replaced.
        let staging = format!("/tmp/aiec-stage-{}", Uuid::now_v7());
        let staged_archive = format!("{staging}/workspace.tar");
        let extracted = format!("{staging}/workspace");
        // `restore_archive` owns the staging directory: only it knows whether a
        // failure left the staged copy as the sole surviving workspace, so a
        // blanket cleanup here would delete the recovery copy its own error
        // message tells the caller where to find.
        self.restore_archive(&binding, &staging, &staged_archive, &extracted, archive)
            .await
    }

    async fn destroy(&self, sandbox: &Sandbox) -> Result<(), CoreError> {
        self.bindings.lock().await.remove(&sandbox.id);
        let Some(id) = sandbox.runtime_path.as_deref().and_then(parse_runtime_path) else {
            // Nothing was ever allocated for this sandbox.
            return Ok(());
        };
        match self
            .control(
                self.client.delete(
                    self.config
                        .api_url(&format!("/sandboxes/{}", encode_path_segment(id))),
                ),
                "kill sandbox",
            )
            .await
        {
            Ok(_) => Ok(()),
            // Killing an already dead sandbox is the desired end state.
            Err(CoreError::NotFound(_)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn health(&self) -> RuntimeHealth {
        match self
            .control(
                self.client
                    .get(self.config.api_url("/v2/sandboxes"))
                    .query(&[("state", "running"), ("limit", "1")]),
                "list sandboxes",
            )
            .await
        {
            Ok(response) => match response.json::<Vec<ProviderSandboxInfo>>().await {
                Ok(_) => RuntimeHealth::healthy(),
                Err(error) => RuntimeHealth::unhealthy(format!(
                    "E2B returned an unreadable sandbox list: {error}"
                )),
            },
            Err(error) => RuntimeHealth::unhealthy(error.to_string()),
        }
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            isolation: RuntimeIsolation::MicroVm,
            exec: true,
            files: true,
            streaming: false,
            pty: false,
            docker_image: false,
            guest_agent: true,
            full_kernel_isolation: true,
            portable_workspace: false,
            // E2B snapshots its own microVM internally, but it cannot produce an
            // AIec virtual machine or memory snapshot.
            vm_snapshot: false,
            memory_resume: false,
            network_policy: false,
            gpu: false,
            pause: true,
            pause_reclaims_resources: true,
            workspace_snapshot: false,
            // A hosted provider materializes its own machine; there is no local
            // immutable base image whose writable size we would have to reserve.
            minimum_disk_mb: 0,
            vsock: false,
            coding_guest: self.config.coding_guest,
        }
    }
}

impl E2bRuntime {
    /// Discards a staging directory that no longer holds the only copy of a
    /// workspace.
    ///
    /// A cleanup failure is never allowed to mask the outcome of the restore it
    /// is cleaning up after.
    async fn discard_staging(&self, binding: &ProviderSandbox, staging: &str) {
        if let Err(error) = self
            .run_command(
                binding,
                &["rm".to_owned(), "-rf".to_owned(), staging.to_owned()],
                None,
                BTreeMap::new(),
                None,
                120,
            )
            .await
        {
            tracing::warn!(%error, "E2B workspace staging cleanup failed");
        }
    }

    /// Replaces the live workspace with a portable archive captured elsewhere.
    ///
    /// The bytes are staged outside the workspace and only swapped in once the
    /// extraction is known to be complete, so a failure leaves either the old
    /// workspace or an explicit report that it is gone. Every failure but the
    /// final install cleans the staging directory up, because up to that point
    /// the live workspace is still the copy worth keeping; the install failure
    /// deliberately leaves it, since that is where the error tells the caller
    /// the only surviving copy of their workspace is.
    async fn restore_archive(
        &self,
        binding: &ProviderSandbox,
        staging: &str,
        staged_archive: &str,
        extracted: &str,
        archive: &[u8],
    ) -> Result<(), CoreError> {
        self.make_directory_raw(binding, staging).await?;
        self.upload(binding, staged_archive, archive).await?;
        let unpack = self
            .run_command(
                binding,
                &[
                    "tar".to_owned(),
                    "-xf".to_owned(),
                    staged_archive.to_owned(),
                    "-C".to_owned(),
                    staging.to_owned(),
                ],
                None,
                BTreeMap::new(),
                None,
                300,
            )
            .await?;
        if unpack.exit_code != 0 {
            self.discard_staging(binding, staging).await;
            return Err(CoreError::Backend(format!(
                "workspace archive could not be extracted: {}",
                unpack.stderr.trim()
            )));
        }
        let probe = self
            .run_command(
                binding,
                &["test".to_owned(), "-d".to_owned(), extracted.to_owned()],
                None,
                BTreeMap::new(),
                None,
                60,
            )
            .await?;
        if probe.exit_code != 0 {
            self.discard_staging(binding, staging).await;
            return Err(CoreError::Backend(
                "workspace archive did not contain a workspace directory".into(),
            ));
        }
        let clear = self
            .run_command(
                binding,
                &["rm".to_owned(), "-rf".to_owned(), WORKSPACE_ROOT.to_owned()],
                None,
                BTreeMap::new(),
                None,
                300,
            )
            .await?;
        if clear.exit_code != 0 {
            self.discard_staging(binding, staging).await;
            return Err(CoreError::Backend(format!(
                "existing workspace could not be replaced: {}",
                clear.stderr.trim()
            )));
        }
        let install = self
            .run_command(
                binding,
                &[
                    "mv".to_owned(),
                    extracted.to_owned(),
                    WORKSPACE_ROOT.to_owned(),
                ],
                None,
                BTreeMap::new(),
                None,
                300,
            )
            .await?;
        if install.exit_code == 0 {
            self.discard_staging(binding, staging).await;
            return Ok(());
        }
        // The live workspace is gone and this staged copy is the only one
        // left, so it is deliberately kept: cleaning up here would discard the
        // workspace the message below points the caller at.
        Err(CoreError::Backend(format!(
            "workspace restore failed: {}; the previous workspace was removed and the staged copy is at {extracted}",
            install.stderr.trim()
        )))
    }
}

/// Wraps one JSON message in a Connect envelope.
fn envelope(body: &[u8]) -> Result<Vec<u8>, CoreError> {
    framed(0, body)
}

/// Marks the client half of a bidirectional stream as finished. The empty
/// object is the protocol's end-of-stream message body.
fn end_stream_frame() -> Vec<u8> {
    vec![ENVELOPE_END, 0, 0, 0, 2, b'{', b'}']
}

fn framed(flags: u8, body: &[u8]) -> Result<Vec<u8>, CoreError> {
    let length = u32::try_from(body.len())
        .map_err(|_| CoreError::LimitExceeded("envd frame is too large".into()))?;
    let mut frame = Vec::with_capacity(body.len() + ENVELOPE_HEADER);
    frame.push(flags);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

fn encode_json(value: &Value) -> Result<Vec<u8>, CoreError> {
    serde_json::to_vec(value)
        .map_err(|error| CoreError::Backend(format!("envd request could not be encoded: {error}")))
}

/// Accumulates an `envd` server stream within AIec's output bounds.
#[derive(Default)]
struct StreamDecoder {
    buffer: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    error: Option<String>,
    finished: bool,
    stdout_limit: Option<usize>,
}

impl StreamDecoder {
    fn push(&mut self, chunk: &[u8]) -> Result<(), CoreError> {
        let frame_limit = self
            .stdout_limit
            .map_or(MAX_STDERR, |limit| limit.div_ceil(3) * 4 + 4096);
        if self.stdout_limit.is_some()
            && chunk.len() > (frame_limit + ENVELOPE_HEADER).saturating_sub(self.buffer.len())
        {
            return Err(CoreError::LimitExceeded("E2B range response frame".into()));
        }
        self.buffer.extend_from_slice(chunk);
        loop {
            if self.finished {
                self.buffer.clear();
                return Ok(());
            }
            if self.buffer.len() < ENVELOPE_HEADER {
                return Ok(());
            }
            let flags = self.buffer[0];
            let length = usize::try_from(u32::from_be_bytes([
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
                self.buffer[4],
            ]))
            .unwrap_or(usize::MAX);
            if length > frame_limit {
                return Err(CoreError::LimitExceeded(format!(
                    "E2B exec frame of {length} bytes exceeds the AIec bound"
                )));
            }
            if self.buffer.len() < ENVELOPE_HEADER + length {
                return Ok(());
            }
            let payload = self.buffer[ENVELOPE_HEADER..ENVELOPE_HEADER + length].to_vec();
            self.buffer.drain(..ENVELOPE_HEADER + length);
            if flags & ENVELOPE_END != 0 {
                self.finished = true;
                continue;
            }
            if flags & ENVELOPE_COMPRESSED != 0 {
                return Err(CoreError::Backend(
                    "E2B returned a compressed exec stream".into(),
                ));
            }
            let message: Value = serde_json::from_slice(&payload).map_err(|error| {
                CoreError::Backend(format!("envd exec stream was unreadable: {error}"))
            })?;
            self.apply(&message)?;
        }
    }

    fn apply(&mut self, message: &Value) -> Result<(), CoreError> {
        if let Some(error) = message.get("error") {
            self.error = Some(rpc_error_message(error));
            self.finished = true;
            return Ok(());
        }
        let Some(event) = message.get("event") else {
            return Ok(());
        };
        if let Some(data) = event.get("data") {
            if let Some(chunk) = data.get("stdout").and_then(Value::as_str) {
                let limit = self.stdout_limit.unwrap_or(MAX_STDOUT);
                if chunk.len() > limit.div_ceil(3) * 4 {
                    return Err(CoreError::LimitExceeded("E2B range output".into()));
                }
                append_bounded(&mut self.stdout, &decode_chunk(chunk)?, limit)?;
            }
            if let Some(chunk) = data.get("stderr").and_then(Value::as_str) {
                let limit = self.stdout_limit.map_or(MAX_STDERR, |_| 4096);
                if self.stdout_limit.is_some() && chunk.len() > limit.div_ceil(3) * 4 {
                    return Err(CoreError::LimitExceeded("E2B range error output".into()));
                }
                append_bounded(&mut self.stderr, &decode_chunk(chunk)?, limit)?;
            }
        }
        if let Some(end) = event.get("end") {
            self.exit_code = end
                .get("exitCode")
                .and_then(Value::as_i64)
                .and_then(|code| i32::try_from(code).ok());
            if let Some(message) = end
                .get("error")
                .and_then(Value::as_str)
                .filter(|message| !message.is_empty())
            {
                self.error = Some(message.to_owned());
            }
            self.finished = true;
        }
        Ok(())
    }
}

fn decode_chunk(chunk: &str) -> Result<Vec<u8>, CoreError> {
    base64::engine::general_purpose::STANDARD
        .decode(chunk.as_bytes())
        .map_err(|_| CoreError::Backend("envd exec stream chunk was not base64".into()))
}

fn append_bounded(target: &mut Vec<u8>, chunk: &[u8], bound: usize) -> Result<(), CoreError> {
    if target.len().saturating_add(chunk.len()) > bound {
        return Err(CoreError::LimitExceeded(format!(
            "E2B exec output exceeds the AIec bound of {bound} bytes"
        )));
    }
    target.extend_from_slice(chunk);
    Ok(())
}

fn rpc_error_message(error: &Value) -> String {
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("no message");
    format!("{code}: {message}")
}

/// Applies the same workspace guard every other runtime uses.
fn workspace_path(raw: &str) -> Result<PathBuf, CoreError> {
    aiec_core::safe_path(raw)
}

/// AIec content addresses are not provider templates; anything else is
/// taken as an E2B template id or alias.
fn template_for(image_id: &str, default_template: &str) -> String {
    if image_id.starts_with("afimg1_") || image_id.is_empty() {
        default_template.to_owned()
    } else {
        image_id.to_owned()
    }
}

fn format_runtime_path(provider_sandbox_id: &str) -> String {
    format!("{RUNTIME_PATH_PREFIX}{provider_sandbox_id}")
}

fn parse_runtime_path(value: &str) -> Option<&str> {
    let id = value.strip_prefix(RUNTIME_PATH_PREFIX)?;
    if id.is_empty() || id.chars().any(char::is_whitespace) {
        None
    } else {
        Some(id)
    }
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

async fn decode_info(
    response: reqwest::Response,
    subject: &str,
) -> Result<ProviderSandboxInfo, CoreError> {
    let info = response
        .json::<ProviderSandboxInfo>()
        .await
        .map_err(|error| {
            CoreError::Backend(format!("E2B {subject} response was unreadable: {error}"))
        })?;
    if info.sandbox_id.is_empty() || info.sandbox_id.chars().any(char::is_whitespace) {
        return Err(CoreError::Backend(format!(
            "E2B {subject} response carried an invalid sandbox id"
        )));
    }
    Ok(info)
}

async fn read_bounded(
    mut response: reqwest::Response,
    bound: usize,
    what: &str,
) -> Result<Vec<u8>, CoreError> {
    if response
        .content_length()
        .is_some_and(|length| length > bound as u64)
    {
        return Err(CoreError::LimitExceeded(format!(
            "{what} exceeds {bound} bytes"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| guest_transport(error, what))?
    {
        if body.len().saturating_add(chunk.len()) > bound {
            return Err(CoreError::LimitExceeded(format!(
                "{what} exceeds {bound} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn provider_detail(response: reqwest::Response) -> String {
    response
        .text()
        .await
        .map(|body| body.chars().take(256).collect::<String>())
        .unwrap_or_else(|_| "no response body".to_owned())
}

fn transport_error(error: reqwest::Error, operation: &str, timeout: Duration) -> CoreError {
    if error.is_timeout() {
        CoreError::Unavailable(format!(
            "E2B {operation} timed out after {}s",
            timeout.as_secs()
        ))
    } else {
        CoreError::Unavailable(format!(
            "E2B {operation} could not reach the provider: {error}"
        ))
    }
}

fn guest_transport(error: reqwest::Error, operation: &str) -> CoreError {
    if error.is_timeout() || error.is_connect() {
        CoreError::Unavailable(format!(
            "envd {operation} could not reach the sandbox: {error}"
        ))
    } else {
        CoreError::Backend(format!("envd {operation} failed: {error}"))
    }
}

fn guest_status(status: u16, operation: &str, detail: String) -> CoreError {
    let summary = format!("envd {operation} failed with HTTP {status}: {detail}");
    match status {
        400 => CoreError::InvalidRequest(summary),
        401 | 403 => CoreError::Forbidden(summary),
        404 => CoreError::NotFound(summary),
        408 | 504 => CoreError::Unavailable(summary),
        _ => CoreError::Backend(summary),
    }
}

async fn provider_error(response: reqwest::Response, operation: &str) -> CoreError {
    let status = response.status().as_u16();
    let body = provider_detail(response).await;
    let parsed: Option<Value> = serde_json::from_str(&body).ok();
    let error_code = parsed
        .as_ref()
        .and_then(|value| value.get("error_code"))
        .and_then(Value::as_str);
    let message = parsed
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .unwrap_or(&body);
    map_provider_failure(status, error_code, message, operation)
}

/// Maps one E2B control-plane failure onto an AIec error.
fn map_provider_failure(
    status: u16,
    error_code: Option<&str>,
    message: &str,
    operation: &str,
) -> CoreError {
    if let Some(code) = error_code
        && CAPACITY_ERROR_CODES.contains(&code)
    {
        return CoreError::Unavailable(format!(
            "E2B has no capacity to serve this {operation} ({code}): {message}"
        ));
    }
    let summary = format!("E2B {operation} failed with HTTP {status}: {message}");
    match status {
        400 => CoreError::InvalidRequest(summary),
        401 | 403 => CoreError::Forbidden(summary),
        404 => CoreError::NotFound(summary),
        409 => CoreError::Conflict(summary),
        // Saturation and rate limiting are retryable rather than a tenant quota
        // breach, so they stay `Unavailable` and surface as HTTP 503.
        429 => CoreError::Unavailable(summary),
        503 | 504 => CoreError::Unavailable(summary),
        _ => CoreError::Backend(summary),
    }
}

fn file_entries(listing: &Value, root: &Path) -> Result<Vec<FileEntry>, CoreError> {
    let entries = listing
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| CoreError::Backend("envd listing carried no entries".into()))?;
    if entries.len() > crate::MAX_LIST_ENTRIES {
        return Err(CoreError::LimitExceeded(
            "workspace listing has too many members".into(),
        ));
    }
    let mut files = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && *name != "." && *name != "..")
            .ok_or_else(|| CoreError::Backend("envd listing carried an unnamed entry".into()))?;
        let kind = match entry.get("type").and_then(Value::as_str) {
            Some("FILE_TYPE_DIRECTORY") | Some("dir") | Some("directory") => "directory",
            Some("FILE_TYPE_SYMLINK") | Some("symlink") => "symlink",
            Some("FILE_TYPE_FILE") | Some("file") => "file",
            _ => "other",
        };
        files.push(FileEntry {
            name: name.to_owned(),
            path: root.join(name).to_string_lossy().into_owned(),
            kind: kind.into(),
            // protojson renders 64-bit integers as strings.
            size: entry.get("size").and_then(flexible_u64).unwrap_or(0),
        });
    }
    Ok(files)
}

fn flexible_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|raw| raw.parse::<u64>().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn test_config(api_base_url: String, envd_base_url: Option<String>) -> E2bConfig {
        E2bConfig {
            api_base_url,
            api_key: "e2b_test_key".into(),
            default_template: DEFAULT_TEMPLATE.to_owned(),
            timeout_seconds: 900,
            request_timeout: Duration::from_secs(5),
            envd_port: DEFAULT_ENVD_PORT,
            envd_domain: DEFAULT_ENVD_DOMAIN.to_owned(),
            envd_base_url,
            coding_guest: true,
        }
    }

    #[test]
    fn runtime_path_round_trips_only_our_own_handles() {
        assert_eq!(format_runtime_path("sbx_1"), "e2b://sbx_1");
        assert_eq!(parse_runtime_path("e2b://sbx_1"), Some("sbx_1"));
        assert_eq!(parse_runtime_path("e2b://"), None);
        assert_eq!(parse_runtime_path("e2b://sbx 1"), None);
        assert_eq!(parse_runtime_path("/var/lib/aiec"), None);
    }

    #[test]
    fn envd_url_follows_the_provider_convention() {
        let direct = test_config("https://api.e2b.app".into(), None);
        assert_eq!(
            direct.envd_url("sbx_1", "/files"),
            "https://49983-sbx_1.e2b.app/files"
        );
        let gateway = test_config("https://api.e2b.app".into(), Some("http://gw/".into()));
        assert_eq!(gateway.envd_url("sbx_1", "/files"), "http://gw/sbx_1/files");
    }

    #[test]
    fn config_never_renders_its_api_key() {
        let config = test_config("https://api.e2b.app".into(), None);
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("e2b_test_key"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }

    #[test]
    fn aiec_image_ids_fall_back_to_the_configured_template() {
        assert_eq!(template_for("afimg1_deadbeef", "base"), "base");
        assert_eq!(template_for("my-e2b-template", "base"), "my-e2b-template");
    }

    #[test]
    fn control_plane_failures_map_to_aiec_errors() {
        // The provider reports saturation with a machine-readable code even when
        // the status is a plain 429, so both routes must stay retryable.
        assert!(matches!(
            map_provider_failure(
                503,
                Some("sandbox_capacity_unavailable"),
                "no room",
                "create sandbox"
            ),
            CoreError::Unavailable(_)
        ));
        assert!(matches!(
            map_provider_failure(
                429,
                Some("sandbox_placement_timeout"),
                "slow",
                "create sandbox"
            ),
            CoreError::Unavailable(_)
        ));
        assert!(matches!(
            map_provider_failure(429, None, "too many requests", "create sandbox"),
            CoreError::Unavailable(_)
        ));
        assert!(matches!(
            map_provider_failure(401, None, "invalid api key", "create sandbox"),
            CoreError::Forbidden(_)
        ));
        assert!(matches!(
            map_provider_failure(404, None, "not found", "get sandbox"),
            CoreError::NotFound(_)
        ));
        assert!(matches!(
            map_provider_failure(400, None, "bad template", "create sandbox"),
            CoreError::InvalidRequest(_)
        ));
        assert!(matches!(
            map_provider_failure(409, None, "already paused", "pause sandbox"),
            CoreError::Conflict(_)
        ));
        assert!(matches!(
            map_provider_failure(500, Some("internal_server_error"), "boom", "create sandbox"),
            CoreError::Backend(_)
        ));
    }

    #[test]
    fn guest_failures_map_to_aiec_errors() {
        assert!(matches!(
            guest_status(401, "exec", "unauthenticated".into()),
            CoreError::Forbidden(_)
        ));
        assert!(matches!(
            guest_status(404, "file read", "missing".into()),
            CoreError::NotFound(_)
        ));
        assert!(matches!(
            guest_status(408, "exec", "deadline".into()),
            CoreError::Unavailable(_)
        ));
        assert!(matches!(
            guest_status(500, "exec", "crashed".into()),
            CoreError::Backend(_)
        ));
    }

    #[test]
    fn stream_decoder_collects_output_and_exit_code() {
        let mut decoder = StreamDecoder::default();
        let stdout = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let stderr = base64::engine::general_purpose::STANDARD.encode(b"warned");
        let mut body = Vec::new();
        for message in [
            json!({ "event": { "data": { "stdout": stdout } } }),
            json!({ "event": { "data": { "stderr": stderr } } }),
            json!({ "event": { "end": { "exitCode": 3 } } }),
        ] {
            body.extend_from_slice(&envelope(&encode_json(&message).unwrap()).unwrap());
        }
        // One byte at a time proves partial frames are buffered, not dropped.
        for byte in &body {
            decoder.push(&[*byte]).unwrap();
        }
        assert!(decoder.finished);
        assert_eq!(decoder.stdout, b"hello");
        assert_eq!(decoder.stderr, b"warned");
        assert_eq!(decoder.exit_code, Some(3));
    }

    #[test]
    fn stream_decoder_rejects_output_beyond_the_aiec_bound() {
        let chunk = base64::engine::general_purpose::STANDARD.encode(vec![b'x'; 64]);
        let frame =
            envelope(&encode_json(&json!({ "event": { "data": { "stdout": chunk } } })).unwrap())
                .unwrap();
        let mut decoder = StreamDecoder::default();
        for _ in 0..(MAX_STDOUT / 64) {
            assert!(decoder.push(&frame).is_ok());
        }
        assert!(decoder.push(&frame).is_err());
    }

    #[test]
    fn range_decoder_bounds_cumulative_output_and_declared_frames() {
        let frame = envelope(&encode_json(&json!({
            "event": { "data": { "stdout": base64::engine::general_purpose::STANDARD.encode(b"123456") } }
        })).unwrap()).unwrap();
        let mut decoder = StreamDecoder {
            stdout_limit: Some(10),
            ..StreamDecoder::default()
        };
        decoder.push(&frame).unwrap();
        assert!(matches!(
            decoder.push(&frame),
            Err(CoreError::LimitExceeded(_))
        ));
        let mut decoder = StreamDecoder {
            stdout_limit: Some(10),
            ..StreamDecoder::default()
        };
        let mut header = [0; ENVELOPE_HEADER];
        header[1..].copy_from_slice(&100_000u32.to_be_bytes());
        assert!(matches!(
            decoder.push(&header),
            Err(CoreError::LimitExceeded(_))
        ));
    }

    #[test]
    fn file_entries_map_provider_enum_names() {
        let listing = json!({
            "entries": [
                { "name": "a.txt", "path": "/workspace/a.txt", "type": "FILE_TYPE_FILE", "size": "12" },
                { "name": "sub", "path": "/workspace/sub", "type": "FILE_TYPE_DIRECTORY", "size": 0 }
            ]
        });
        let entries = file_entries(&listing, Path::new("/workspace")).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, "file");
        assert_eq!(entries[0].size, 12);
        assert_eq!(entries[0].path, "/workspace/a.txt");
        assert_eq!(entries[1].kind, "directory");
    }
}
