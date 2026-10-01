//! Tenant run secrets: names in the workload, values only at exec time.
//!
//! A `WorkloadSpec` carries `secrets: Vec<String>` — the *names* a workload
//! wants, never their values — because the workload document is durable. It
//! lands in the `runs` row, in the attempt document, in the event log and in
//! every results document a caller can read. A value written there is a value
//! in a backup, a replica and an audit trail. So the control plane resolves the
//! names into values as late as possible: immediately before a command is
//! executed inside the machine, and never writes them anywhere.
//!
//! # Where the values come from
//!
//! An operator-configured directory named by `AIEC_RUN_SECRETS_DIR`, holding one
//! file per tenant:
//!
//! ```text
//! $AIEC_RUN_SECRETS_DIR/
//! └── 0f6c1d2e-6f3a-7c1b-9a55-2f0f1d3b4c5a.json
//! ```
//!
//! ```json
//! {
//!   "tenant_id": "0f6c1d2e-6f3a-7c1b-9a55-2f0f1d3b4c5a",
//!   "secrets": { "GITHUB_TOKEN": "ghp_..." }
//! }
//! ```
//!
//! The directory and every file in it must belong to the user running the API
//! and must not be readable by group or other (`0700` for the directory, `0600`
//! for the file). `tenant_id` inside the file must match the tenant asking for
//! it, so a file copied into the wrong tenant's slot fails loudly instead of
//! handing one tenant another's credentials.
//!
//! There is no network call, no vault client and no shared guest path. A secret
//! reaches the guest the way every other environment variable does, through the
//! existing `ExecRequest`.
//!
//! # Refusing rather than inventing
//!
//! A requested name that is not configured is an error, raised before any
//! sandbox is started — never a placeholder value, and never an empty string
//! that the workload would treat as success. A workload with no requested
//! secrets needs no configuration at all and never touches the filesystem.
//!
//! # Wiring
//!
//! The resolver is built once at startup (`AppState::with_run_secrets`) and
//! used from three places, all in `runs.rs`:
//!
//! - `validate`, before a run is admitted, resolves the references once so a
//!   name the tenant does not hold, or one the workload also spells out as a
//!   literal, is refused before a machine is placed. That resolution is
//!   dropped immediately.
//! - `run_command` resolves once per command and hands the *same* resolved set
//!   to the exec and to the redactor that scrubs its output and its transport
//!   error. One read, one set: a redactor built from a second read would scrub
//!   against whatever the file says now rather than the value that actually
//!   ran, and the value that ran is the one in the output.
//!
//! - the collection phase resolves once more, for the redactor that scrubs
//!   `git status` and `git diff`. A task can write a credential into a tracked
//!   file, so the diff carries it even though the git commands themselves run
//!   with an empty environment.
//!
//! `redactor_for` and `merge_environment` are one-call conveniences over
//! `resolve` for callers that need only the merge or only the redactor. The run
//! path deliberately uses neither: it takes both from a single resolution.
//!
//! Scrubbing is uncapped (`redact_text_uncapped`, `redact_output_uncapped`) on
//! purpose. [`MAX_REDACTED_BYTES`] is the cap for a caller with no other
//! bound; a run has one — its phase preview budget — and that budget keeps the
//! head *and* the tail, where the reason a command failed usually is. Capping
//! first would discard the tail before the budget ever saw it.
//!
//! Redaction is literal: it removes the value wherever it appears verbatim. A
//! workload that re-encodes a secret before printing it (base64, a URL query
//! parameter) puts something in the captured output that is not the secret and
//! is not removed. No scrubber can do better without reading the guest's
//! memory, so this is stated rather than claimed away.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aiec_core::{CoreError, TenantId};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

/// Environment variable naming the tenant secret directory.
pub const SECRETS_DIR_ENV: &str = "AIEC_RUN_SECRETS_DIR";

/// Largest tenant secret file that will be read.
///
/// A secret map is a handful of short values. Reading an unbounded file is how
/// a control plane gets used as an amplifier, so the ceiling is checked before
/// the read and the read itself stops one byte past it.
pub const MAX_SECRET_FILE_BYTES: usize = 64 * 1024;

/// Largest number of names one tenant file may declare.
pub const MAX_SECRETS_PER_TENANT: usize = 32;

/// Largest number of distinct names one run may request.
pub const MAX_SECRETS_PER_REQUEST: usize = 32;

/// Largest size of a single value.
pub const MAX_SECRET_VALUE_BYTES: usize = 16 * 1024;

/// Largest total payload handed to one exec, so a run cannot ask for a megabyte
/// of credentials and blow out its own command line.
pub const MAX_RESOLVED_BYTES: usize = 64 * 1024;

/// Bytes kept per redacted command stream.
pub const MAX_REDACTED_BYTES: usize = 8 * 1024;

/// What a redacted span is replaced with.
const PLACEHOLDER: &str = "[redacted]";
/// Appended when redacted output had to be cut short.
const TRUNCATION_MARKER: &str = "\n[truncated]";

/// One tenant's file on disk. Deliberately has no `Debug`: a derived one would
/// print every value in the map.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantSecretFile {
    tenant_id: TenantId,
    secrets: BTreeMap<String, String>,
}

/// Resolves requested secret names for a tenant against an operator-owned
/// directory.
///
/// Constructed once at startup with [`RunSecretResolver::from_env`] or
/// [`RunSecretResolver::new`] and then shared. It holds no per-request state
/// and no cache, because a cache of secret values is a second copy of the
/// secret store with weaker controls.
#[derive(Clone, Debug)]
pub struct RunSecretResolver {
    root: Option<PathBuf>,
}

impl RunSecretResolver {
    /// A resolver with no store behind it. Only workloads that request no
    /// secrets work; any request is [`CoreError::Unavailable`].
    pub fn disabled() -> Self {
        Self { root: None }
    }

    /// Reads `AIEC_RUN_SECRETS_DIR` once. Unset or empty means "no store",
    /// which is the default self-hoster position: runs work, secret-requesting
    /// runs are refused before they start.
    ///
    /// A configured-but-unusable directory is an error at startup rather than
    /// at the first run, because a store that cannot be trusted should never
    /// have been accepted.
    pub fn from_env() -> Result<Self, CoreError> {
        match std::env::var(SECRETS_DIR_ENV) {
            Ok(path) if !path.trim().is_empty() => Self::new(path.trim()),
            _ => Ok(Self::disabled()),
        }
    }

    /// Validates the directory and keeps its canonical path.
    ///
    /// Canonicalising once at startup means a later symlink swap on the root
    /// cannot redirect resolution, and it means the per-run check is a single
    /// `metadata` call rather than a filesystem walk.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CoreError> {
        let root = root.as_ref();
        let metadata = std::fs::symlink_metadata(root)
            .map_err(|error| CoreError::Backend(format!("stat {}: {error}", root.display())))?;
        if metadata.file_type().is_symlink() {
            return Err(CoreError::Backend(format!(
                "{} is a symlink; the run secret directory must be a real directory",
                root.display()
            )));
        }
        if !metadata.is_dir() {
            return Err(CoreError::Backend(format!(
                "{} is not a directory",
                root.display()
            )));
        }
        ensure_private(&metadata, root)?;
        let canonical = std::fs::canonicalize(root)?;
        Ok(Self {
            root: Some(canonical),
        })
    }

    /// Whether a store is configured at all.
    pub fn is_configured(&self) -> bool {
        self.root.is_some()
    }

    /// The directory in use, for startup logging. Contains no secret.
    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    /// Resolves `refs` for `tenant`.
    ///
    /// Errors before any sandbox is placed: a name that is not a legal
    /// environment variable, a tenant with no store behind it, a requested
    /// secret that tenant does not hold, or a file whose permissions make it
    /// untrustworthy.
    pub async fn resolve(
        &self,
        tenant: TenantId,
        refs: &[String],
    ) -> Result<ResolvedSecrets, CoreError> {
        let names = requested_names(refs)?;
        if names.is_empty() {
            return Ok(ResolvedSecrets::default());
        }
        let Some(root) = self.root.as_deref() else {
            return Err(CoreError::Unavailable(format!(
                "a secret was requested but no run secret store is configured; set {SECRETS_DIR_ENV}"
            )));
        };
        let path = tenant_path(root, tenant)?;
        let file = read_tenant_file(&path, tenant).await?;

        let mut values: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
        let mut total = 0usize;
        for name in names {
            let Some(value) = file.secrets.get(&name) else {
                // Named, not valued: a caller has to learn which reference is
                // wrong, and a name is not itself a secret.
                return Err(CoreError::NotFound(format!(
                    "no secret named `{name}` is configured for this tenant"
                )));
            };
            check_value(&name, value)?;
            total += value.len();
            if total > MAX_RESOLVED_BYTES {
                return Err(CoreError::LimitExceeded(format!(
                    "the requested secrets exceed the {MAX_RESOLVED_BYTES} byte per-exec ceiling"
                )));
            }
            values.insert(name, Zeroizing::new(value.clone()));
        }
        Ok(ResolvedSecrets { values })
    }

    /// Resolves and folds the result into the environment already assembled for
    /// a command.
    ///
    /// `base_environment` is whatever the caller had before the run secrets:
    /// per-sandbox secrets, the workload's own `environment`, anything else. A
    /// name present in both is refused rather than silently resolved, because
    /// a literal in the run document is exactly what must not be stored, and a
    /// sandbox secret losing to a run secret is a race nobody can debug.
    pub async fn merge_environment(
        &self,
        tenant: TenantId,
        refs: &[String],
        base_environment: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, CoreError> {
        let resolved = self.resolve(tenant, refs).await?;
        resolved.merge(base_environment)
    }

    /// A redactor over the values these references resolve to.
    ///
    /// For a caller that needs a redactor without the resolved set. It resolves
    /// a second time, so a caller that is about to execute a command should
    /// take the redactor from the same [`ResolvedSecrets`] it resolved for that
    /// exec instead - otherwise the values being replaced are whatever the file
    /// says now, not the ones that ran.
    pub async fn redactor_for(
        &self,
        tenant: TenantId,
        refs: &[String],
    ) -> Result<SecretRedactor, CoreError> {
        Ok(self.resolve(tenant, refs).await?.redactor())
    }
}

/// The values resolved for one exec, wiped from memory when dropped.
///
/// Its `Debug` output is names only: a log line that prints this object must
/// show what a workload asked for, never what it was given.
#[derive(Default)]
pub struct ResolvedSecrets {
    values: BTreeMap<String, Zeroizing<String>>,
}

impl ResolvedSecrets {
    /// The resolved names, for workload metadata and event detail.
    pub fn names(&self) -> Vec<&str> {
        self.values.keys().map(String::as_str).collect()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The environment to hand to `ExecRequest`.
    pub fn environment(&self) -> BTreeMap<String, String> {
        self.values
            .iter()
            .map(|(name, value)| (name.clone(), value.to_string()))
            .collect()
    }

    /// Merges into the environment already assembled for a command.
    ///
    /// Refuses to overwrite: a name present in both is ambiguous, and picking
    /// a winner would either hide a credential that is about to be written to
    /// the run document or hide a sandbox secret that a workload shadowed.
    pub fn merge(
        &self,
        base_environment: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, CoreError> {
        for name in self.values.keys() {
            if base_environment.contains_key(name) {
                return Err(CoreError::InvalidRequest(format!(
                    "the command environment already defines `{name}`, which is also a requested secret; remove the literal value and request the secret by name"
                )));
            }
        }
        let mut merged = self.environment();
        merged.extend(base_environment.clone());
        Ok(merged)
    }

    /// A redactor over exactly these values.
    pub fn redactor(&self) -> SecretRedactor {
        SecretRedactor::new(
            self.values
                .values()
                .map(|value| value.to_string())
                .collect(),
        )
    }
}

impl fmt::Debug for ResolvedSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSecrets")
            .field("names", &self.names())
            .finish_non_exhaustive()
    }
}

/// Removes resolved secret values from text that is about to be stored,
/// returned or logged.
///
/// Command output is evidence and has to be kept, so it cannot simply be
/// discarded when it contains a credential. It can be scrubbed: the values are
/// known, so every occurrence of one is replaced in place, and the result is
/// bounded so a secret echoed in a loop cannot turn a captured stream into
/// stored megabytes.
#[derive(Clone, Default)]
pub struct SecretRedactor {
    values: Vec<Zeroizing<String>>,
}

impl SecretRedactor {
    /// Builds a redactor over an explicit set of values.
    pub fn new(values: Vec<String>) -> Self {
        let mut values: Vec<Zeroizing<String>> = values.into_iter().map(Zeroizing::new).collect();
        // Longest first, so a value that contains another is replaced whole
        // rather than leaving a fragment behind.
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self { values }
    }

    /// Whether there is anything to scrub.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Scrubs `input` with no size limit of its own.
    ///
    /// [`Self::redact_text`] caps because most callers have no other bound. A
    /// run does: its phase budget clips head-and-tail afterwards and records
    /// that it clipped. Capping here instead would throw away the tail, which
    /// is where a failing build, a test summary or a traceback puts the reason
    /// the caller came for - and would do so on a stream the phase budget was
    /// going to keep anyway.
    pub fn redact_text_uncapped(&self, input: &str) -> String {
        let mut scrubbed = input.to_owned();
        for value in &self.values {
            if value.is_empty() || !scrubbed.contains(value.as_str()) {
                continue;
            }
            scrubbed = scrubbed.replace(value.as_str(), PLACEHOLDER);
        }
        scrubbed
    }

    /// Scrubs `input`, returning at most [`MAX_REDACTED_BYTES`] plus the
    /// truncation marker.
    pub fn redact_text(&self, input: &str) -> String {
        truncate(&self.redact_text_uncapped(input), MAX_REDACTED_BYTES)
    }

    /// Scrubs a command's captured streams with no size limit, for a caller that
    /// bounds them itself. Both streams are scrubbed independently.
    pub fn redact_output_uncapped(&self, stdout: &str, stderr: &str) -> (String, String) {
        (
            self.redact_text_uncapped(stdout),
            self.redact_text_uncapped(stderr),
        )
    }

    /// Scrubs a command's captured streams. Both are bounded independently.
    pub fn redact_output(&self, stdout: &str, stderr: &str) -> (String, String) {
        (self.redact_text(stdout), self.redact_text(stderr))
    }

    /// Scrubs a [`CoreError`], keeping its variant.
    ///
    /// The variant is what a caller branches on and what a retry set is built
    /// from, so redaction cannot replace it with a string; only the message is
    /// rewritten.
    pub fn redact_error(&self, error: &CoreError) -> CoreError {
        match error {
            CoreError::InvalidRequest(message) => {
                CoreError::InvalidRequest(self.redact_text(message))
            }
            CoreError::NotFound(message) => CoreError::NotFound(self.redact_text(message)),
            CoreError::Conflict(message) => CoreError::Conflict(self.redact_text(message)),
            CoreError::Forbidden(message) => CoreError::Forbidden(self.redact_text(message)),
            CoreError::LimitExceeded(message) => {
                CoreError::LimitExceeded(self.redact_text(message))
            }
            CoreError::QuotaExceeded(message) => {
                CoreError::QuotaExceeded(self.redact_text(message))
            }
            CoreError::Unavailable(message) => CoreError::Unavailable(self.redact_text(message)),
            CoreError::Transient(message) => CoreError::Transient(self.redact_text(message)),
            CoreError::Unsupported(message) => CoreError::Unsupported(self.redact_text(message)),
            CoreError::Backend(message) => CoreError::Backend(self.redact_text(message)),
            CoreError::Io(io) => {
                CoreError::Io(std::io::Error::other(self.redact_text(&io.to_string())))
            }
        }
    }
}

impl fmt::Debug for SecretRedactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRedactor")
            .field("values", &self.values.len())
            .finish()
    }
}

/// Validates and de-duplicates requested names.
///
/// Done before anything is read, so a malformed reference fails the same way
/// whether or not a store is configured, and a caller gets one error naming one
/// problem instead of one per field.
fn requested_names(refs: &[String]) -> Result<Vec<String>, CoreError> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for name in refs {
        if !is_valid_env_name(name) {
            return Err(CoreError::InvalidRequest(format!(
                "`{name}` is not a usable secret name: uppercase ASCII letters, digits and underscores only, up to 64 characters"
            )));
        }
        names.insert(name.as_str());
    }
    if names.len() > MAX_SECRETS_PER_REQUEST {
        return Err(CoreError::LimitExceeded(format!(
            "a run may request at most {MAX_SECRETS_PER_REQUEST} secrets"
        )));
    }
    Ok(names.into_iter().map(str::to_owned).collect())
}

/// Whether `name` can be an environment variable inside the guest.
///
/// The same rule the sandbox secret API enforces, so a name accepted at
/// `PUT /v1/sandboxes/{id}/secrets/{name}` is accepted here.
pub fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// The tenant's file, built from the tenant UUID alone.
///
/// A UUID has no separator a path can split on, so this cannot escape the root
/// even before canonicalisation. The check is kept because a future change to
/// the file layout is exactly how that would start escaping.
fn tenant_path(root: &Path, tenant: TenantId) -> Result<PathBuf, CoreError> {
    let path = root.join(format!("{tenant}.json"));
    if path.parent() != Some(root) || !path.starts_with(root) {
        return Err(CoreError::Forbidden(
            "refusing to read a tenant secret file outside the secret directory".into(),
        ));
    }
    Ok(path)
}

async fn read_tenant_file(path: &Path, tenant: TenantId) -> Result<TenantSecretFile, CoreError> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CoreError::NotFound(format!(
                "no run secret file is configured for this tenant ({})",
                path.display()
            ))
        } else {
            CoreError::Io(error)
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(CoreError::Backend(format!(
            "{} is a symlink; a run secret file must be a real file",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(CoreError::Backend(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    ensure_private(&metadata, path)?;
    if metadata.len() > MAX_SECRET_FILE_BYTES as u64 {
        return Err(CoreError::LimitExceeded(format!(
            "{} is larger than the {MAX_SECRET_FILE_BYTES} byte ceiling",
            path.display()
        )));
    }

    // Opened with O_NOFOLLOW so the path checked above and the descriptor read
    // below are the same file even if the name is swapped in between.
    let file = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .await?;
    let opened = file.metadata().await?;
    ensure_private(&opened, path)?;

    // Reads one byte past the ceiling so a file that grew after the stat is
    // caught by the length check rather than read whole.
    let mut bytes = Vec::with_capacity(MAX_SECRET_FILE_BYTES.min(opened.len() as usize));
    let mut limited = file.take(MAX_SECRET_FILE_BYTES as u64 + 1);
    limited.read_to_end(&mut bytes).await?;
    if bytes.len() > MAX_SECRET_FILE_BYTES {
        return Err(CoreError::LimitExceeded(format!(
            "{} grew past the {MAX_SECRET_FILE_BYTES} byte ceiling while it was read",
            path.display()
        )));
    }

    // A parse failure is reported by position only. The message names the
    // offending field — a name here, never a value — but a position says the
    // same thing without depending on that.
    let file: TenantSecretFile = serde_json::from_slice(&bytes).map_err(|error| {
        CoreError::Backend(format!(
            "{} is not a valid run secret file (line {}, column {})",
            path.display(),
            error.line(),
            error.column()
        ))
    })?;
    if file.tenant_id != tenant {
        return Err(CoreError::Forbidden(format!(
            "{} belongs to a different tenant than the one that asked for it",
            path.display()
        )));
    }
    if file.secrets.len() > MAX_SECRETS_PER_TENANT {
        return Err(CoreError::LimitExceeded(format!(
            "{} declares more than {MAX_SECRETS_PER_TENANT} secrets",
            path.display()
        )));
    }
    Ok(file)
}

/// Owner-only, and owned by the user the API runs as.
///
/// A group- or world-readable secret file is refused rather than used: the file
/// is the entire tenant boundary here, so a mode that lets another local user
/// read it has already lost it.
fn ensure_private(metadata: &std::fs::Metadata, path: &Path) -> Result<(), CoreError> {
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(CoreError::Backend(format!(
            "{} is mode {:o}; a run secret must not be accessible to other users",
            path.display(),
            mode
        )));
    }
    let owner = metadata.uid();
    // SAFETY: `geteuid` reads process credentials and has no preconditions.
    let process = unsafe { libc::geteuid() };
    if owner != process {
        return Err(CoreError::Backend(format!(
            "{} is owned by uid {owner} but the API runs as uid {process}",
            path.display()
        )));
    }
    Ok(())
}

fn check_value(name: &str, value: &str) -> Result<(), CoreError> {
    if value.is_empty() {
        return Err(CoreError::Backend(format!(
            "secret `{name}` is configured empty; remove it or give it a value"
        )));
    }
    if value.len() > MAX_SECRET_VALUE_BYTES {
        return Err(CoreError::LimitExceeded(format!(
            "secret `{name}` is larger than the {MAX_SECRET_VALUE_BYTES} byte ceiling"
        )));
    }
    if value.as_bytes().contains(&0) {
        return Err(CoreError::Backend(format!(
            "secret `{name}` contains a NUL byte and cannot be an environment variable"
        )));
    }
    Ok(())
}

fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + TRUNCATION_MARKER.len());
    out.push_str(&text[..end]);
    out.push_str(TRUNCATION_MARKER);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A tenant secret directory that removes itself, and a canary that must
    /// never appear in a log line, a debug render or a stored document.
    struct Fixture {
        root: PathBuf,
        canary: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aiec-run-secrets-{label}-{}-{unique}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("create the secret directory");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            Self {
                root,
                canary: format!("canary-{label}-{unique}0f1e2d3c"),
            }
        }

        /// Writes a tenant file and returns its path.
        fn write(&self, tenant: TenantId, secrets: &[(String, String)]) -> PathBuf {
            let map: serde_json::Map<String, serde_json::Value> = secrets
                .iter()
                .map(|(name, value)| (name.clone(), serde_json::Value::String(value.clone())))
                .collect();
            let body = serde_json::json!({ "tenant_id": tenant, "secrets": map });
            self.write_raw(tenant, &serde_json::to_vec(&body).expect("encode"))
        }

        /// Writes arbitrary bytes as a tenant file and locks its mode down.
        fn write_raw(&self, tenant: TenantId, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(format!("{tenant}.json"));
            std::fs::write(&path, bytes).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
            path
        }
    }

    fn tenant(seed: u128) -> TenantId {
        uuid::Uuid::from_u128(seed)
    }

    #[tokio::test]
    async fn resolves_requested_names_for_the_owning_tenant() {
        let fixture = Fixture::new("resolve");
        let owner = tenant(0x1111_2222_3333_4444_5555_6666_7777_8888);
        fixture.write(
            owner,
            &[
                ("GITHUB_TOKEN".to_owned(), fixture.canary.clone()),
                ("CI_MODE".to_owned(), "1".to_owned()),
            ],
        );
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let resolved = resolver
            .resolve(owner, &["GITHUB_TOKEN".to_owned(), "CI_MODE".to_owned()])
            .await
            .expect("resolve");

        assert_eq!(
            resolved.environment().get("GITHUB_TOKEN"),
            Some(&fixture.canary)
        );
        // Only the names travel; the value does not.
        assert_eq!(resolved.names(), vec!["CI_MODE", "GITHUB_TOKEN"]);
        assert_eq!(resolved.len(), 2);
        let rendered = format!("{resolved:?}");
        assert!(!rendered.contains(&fixture.canary), "{rendered}");
        assert!(rendered.contains("GITHUB_TOKEN"), "{rendered}");
    }

    #[tokio::test]
    async fn one_tenant_never_reads_another_tenants_file() {
        let fixture = Fixture::new("isolation");
        let owner = tenant(0xaaaa_bbbb_cccc_dddd_eeee_ffff_0000_1111);
        let stranger = tenant(0x1111_2222_3333_4444_5555_6666_7777_8889);
        fixture.write(
            owner,
            &[("GITHUB_TOKEN".to_owned(), fixture.canary.clone())],
        );
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let error = resolver
            .resolve(stranger, &["GITHUB_TOKEN".to_owned()])
            .await
            .expect_err("another tenant's secret must not resolve");
        assert!(matches!(error, CoreError::NotFound(_)), "{error}");
        assert!(!error.to_string().contains(&fixture.canary));
    }

    #[tokio::test]
    async fn a_file_naming_a_different_tenant_is_refused() {
        let fixture = Fixture::new("identity");
        let asked = tenant(0x9999_8888_7777_6666_5555_4444_3333_2222);
        let body = serde_json::to_vec(&serde_json::json!({
            "tenant_id": tenant(1),
            "secrets": {"GITHUB_TOKEN": fixture.canary},
        }))
        .expect("encode");
        fixture.write_raw(asked, &body);
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let error = resolver
            .resolve(asked, &["GITHUB_TOKEN".to_owned()])
            .await
            .expect_err("a mismatched file must not resolve");
        assert!(matches!(error, CoreError::Forbidden(_)), "{error}");
        assert!(!error.to_string().contains(&fixture.canary));
    }

    #[tokio::test]
    async fn a_missing_ref_fails_before_anything_is_executed() {
        let fixture = Fixture::new("missing");
        let owner = tenant(0x4444_3333_2222_1111_0000_ffff_eeee_dddd);
        fixture.write(owner, &[("CI_MODE".to_owned(), "1".to_owned())]);
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let error = resolver
            .resolve(owner, &["NPM_TOKEN".to_owned()])
            .await
            .expect_err("an unconfigured ref must fail");
        assert!(matches!(error, CoreError::NotFound(_)), "{error}");
        // The name is reported so the caller can fix the request; that is all.
        assert!(error.to_string().contains("NPM_TOKEN"), "{error}");
    }

    #[tokio::test]
    async fn refs_must_be_usable_environment_names() {
        let fixture = Fixture::new("names");
        let owner = tenant(0x7777_6666_5555_4444_3333_2222_1111_0000);
        fixture.write(
            owner,
            &[("GITHUB_TOKEN".to_owned(), fixture.canary.clone())],
        );
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let too_long = "A".repeat(65);
        for bad in [
            "github-token",
            "GITHUB TOKEN",
            "GITHUB.TOKEN",
            "GITHUB/TOKEN",
            "",
            too_long.as_str(),
        ] {
            let error = resolver
                .resolve(owner, &[bad.to_owned()])
                .await
                .expect_err("a malformed name must be refused");
            assert!(matches!(error, CoreError::InvalidRequest(_)), "{bad:?}");
        }
        assert!(is_valid_env_name("GITHUB_TOKEN"));
        assert!(is_valid_env_name("CI_2"));
        assert!(!is_valid_env_name(&too_long));
    }

    #[tokio::test]
    async fn no_refs_works_without_any_configuration() {
        let resolver = RunSecretResolver::disabled();
        assert!(!resolver.is_configured());
        assert!(resolver.root().is_none());
        let resolved = resolver
            .resolve(tenant(0x1234_5678_9abc_def0_1234_5678_9abc_def0), &[])
            .await
            .expect("an empty request needs no store");
        assert!(resolved.is_empty());
        assert!(resolved.environment().is_empty());
    }

    #[tokio::test]
    async fn a_request_without_a_store_is_unavailable_not_a_fake_value() {
        let resolver = RunSecretResolver::disabled();
        let error = resolver
            .resolve(
                tenant(0x1234_5678_9abc_def0_1234_5678_9abc_def1),
                &["GITHUB_TOKEN".to_owned()],
            )
            .await
            .expect_err("no store means no secrets");
        assert!(matches!(error, CoreError::Unavailable(_)), "{error}");
        assert!(error.to_string().contains(SECRETS_DIR_ENV), "{error}");
    }

    #[tokio::test]
    async fn a_world_readable_file_is_refused() {
        let fixture = Fixture::new("mode");
        let owner = tenant(0xdead_beef_0000_1111_2222_3333_4444_5555);
        let path = fixture.write(
            owner,
            &[("GITHUB_TOKEN".to_owned(), fixture.canary.clone())],
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let error = resolver
            .resolve(owner, &["GITHUB_TOKEN".to_owned()])
            .await
            .expect_err("a world-readable secret must be refused");
        assert!(matches!(error, CoreError::Backend(_)), "{error}");
        assert!(!error.to_string().contains(&fixture.canary));
    }

    #[test]
    fn a_world_readable_directory_is_refused_at_startup() {
        let fixture = Fixture::new("dirmode");
        std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        assert!(matches!(
            RunSecretResolver::new(&fixture.root),
            Err(CoreError::Backend(_))
        ));
    }

    #[tokio::test]
    async fn a_symlinked_file_is_refused() {
        let fixture = Fixture::new("symlink");
        let owner = tenant(0x0bad_f00d_0000_1111_2222_3333_4444_5555);
        let real = fixture.root.join("elsewhere.json");
        std::fs::write(&real, b"{}").expect("write");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::os::unix::fs::symlink(&real, fixture.root.join(format!("{owner}.json")))
            .expect("symlink");
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let error = resolver
            .resolve(owner, &["GITHUB_TOKEN".to_owned()])
            .await
            .expect_err("a symlinked secret must be refused");
        assert!(matches!(error, CoreError::Backend(_)), "{error}");
    }

    #[test]
    fn a_symlinked_root_is_refused() {
        let fixture = Fixture::new("rootsymlink");
        let link = fixture.root.with_extension("link");
        std::os::unix::fs::symlink(&fixture.root, &link).expect("symlink");
        assert!(matches!(
            RunSecretResolver::new(&link),
            Err(CoreError::Backend(_))
        ));
    }

    #[tokio::test]
    async fn an_oversized_map_is_refused() {
        let fixture = Fixture::new("map");
        let owner = tenant(0x5151_5151_6262_7373_8484_9595_a6a6_a7a7);
        let secrets: Vec<(String, String)> = (0..=MAX_SECRETS_PER_TENANT)
            .map(|index| (format!("SECRET_{index}"), "v".to_owned()))
            .collect();
        fixture.write(owner, &secrets);
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        // One name is requested, so this can only fail on the file's own map
        // ceiling rather than on the request ceiling.
        let error = resolver
            .resolve(owner, &["SECRET_0".to_owned()])
            .await
            .expect_err("an oversized map must be refused");
        assert!(matches!(error, CoreError::LimitExceeded(_)), "{error}");
    }

    #[tokio::test]
    async fn an_oversized_file_is_refused() {
        let fixture = Fixture::new("file");
        let owner = tenant(0x5151_5151_6262_7373_8484_9595_a6a6_a7a8);
        fixture.write_raw(owner, &vec![b'x'; MAX_SECRET_FILE_BYTES + 1]);
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let error = resolver
            .resolve(owner, &["SECRET_0".to_owned()])
            .await
            .expect_err("an oversized file must be refused");
        assert!(matches!(error, CoreError::LimitExceeded(_)), "{error}");
    }

    #[tokio::test]
    async fn too_many_requested_names_are_refused() {
        let resolver = RunSecretResolver::disabled();
        let requested: Vec<String> = (0..=MAX_SECRETS_PER_REQUEST)
            .map(|index| format!("SECRET_{index}"))
            .collect();
        let error = resolver
            .resolve(tenant(2), &requested)
            .await
            .expect_err("too many refs must be refused");
        assert!(matches!(error, CoreError::LimitExceeded(_)), "{error}");
    }

    #[tokio::test]
    async fn an_empty_or_nul_value_is_refused_rather_than_passed_on() {
        let fixture = Fixture::new("values");
        let owner = tenant(0x1a2b_3c4d_5e6f_7081_9293_a4b5_c6d7);
        fixture.write(
            owner,
            &[
                ("EMPTY_SECRET".to_owned(), String::new()),
                ("NUL_SECRET".to_owned(), "a\u{0}b".to_owned()),
            ],
        );
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let error = resolver
            .resolve(owner, &["EMPTY_SECRET".to_owned()])
            .await
            .expect_err("an empty value must be refused");
        assert!(matches!(error, CoreError::Backend(_)), "{error}");
        let error = resolver
            .resolve(owner, &["NUL_SECRET".to_owned()])
            .await
            .expect_err("a NUL in a value must be refused");
        assert!(matches!(error, CoreError::Backend(_)), "{error}");
    }

    #[tokio::test]
    async fn a_duplicate_ref_is_one_secret_not_two() {
        let fixture = Fixture::new("duplicate");
        let owner = tenant(0xfeed_face_dead_beef_0123_4567_89ab_cdef);
        fixture.write(
            owner,
            &[("GITHUB_TOKEN".to_owned(), fixture.canary.clone())],
        );
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let resolved = resolver
            .resolve(
                owner,
                &["GITHUB_TOKEN".to_owned(), "GITHUB_TOKEN".to_owned()],
            )
            .await
            .expect("resolve");
        assert_eq!(resolved.len(), 1);
    }

    #[tokio::test]
    async fn a_literal_in_the_workload_environment_cannot_shadow_a_secret() {
        let fixture = Fixture::new("shadow");
        let owner = tenant(0x3333_4444_5555_6666_7777_8888_9999_aaaa);
        fixture.write(
            owner,
            &[("GITHUB_TOKEN".to_owned(), fixture.canary.clone())],
        );
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let environment = BTreeMap::from([
            ("CI_MODE".to_owned(), "1".to_owned()),
            ("GITHUB_TOKEN".to_owned(), "literal-not-a-secret".to_owned()),
        ]);
        let error = resolver
            .merge_environment(owner, &["GITHUB_TOKEN".to_owned()], &environment)
            .await
            .expect_err("an ambiguous name must not be resolved silently");
        assert!(matches!(error, CoreError::InvalidRequest(_)), "{error}");

        // The clean case still merges, with the secret alongside the setting.
        let environment = BTreeMap::from([("CI_MODE".to_owned(), "1".to_owned())]);
        let merged = resolver
            .merge_environment(owner, &["GITHUB_TOKEN".to_owned()], &environment)
            .await
            .expect("merge");
        assert_eq!(merged.len(), 2);
        assert_eq!(merged.get("CI_MODE"), Some(&"1".to_owned()));
        assert_eq!(merged.get("GITHUB_TOKEN"), Some(&fixture.canary));
    }

    #[tokio::test]
    async fn redaction_scrubs_captured_output_and_keeps_it_bounded() {
        let fixture = Fixture::new("output");
        let owner = tenant(0xabcd_ef01_2345_6789_abcd_ef01_2345_6789);
        fixture.write(
            owner,
            &[("GITHUB_TOKEN".to_owned(), fixture.canary.clone())],
        );
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");
        let redactor = resolver
            .redactor_for(owner, &["GITHUB_TOKEN".to_owned()])
            .await
            .expect("redactor");

        let stdout = format!("cloning with {}\ndone", fixture.canary);
        let (stdout, stderr) = redactor.redact_output(&stdout, "warning: no credentials");
        assert!(!stdout.contains(&fixture.canary), "{stdout}");
        assert!(stdout.contains(PLACEHOLDER), "{stdout}");
        assert!(stdout.contains("cloning with"), "{stdout}");
        assert_eq!(stderr, "warning: no credentials");

        let flood = fixture.canary.repeat(MAX_REDACTED_BYTES);
        let scrubbed = redactor.redact_text(&flood);
        assert!(!scrubbed.contains(&fixture.canary));
        assert!(scrubbed.ends_with(TRUNCATION_MARKER));
        assert!(scrubbed.len() <= MAX_REDACTED_BYTES + TRUNCATION_MARKER.len());
    }

    /// The run path scrubs uncapped and lets its phase budget clip head-and-tail
    /// afterwards. If the scrubber capped first, the reason a command failed -
    /// a test summary, a traceback, a compiler diagnostic at the end of a long
    /// log - would be the first thing thrown away, and the run would store a
    /// preview with the cause missing.
    #[tokio::test]
    async fn uncapped_scrubbing_keeps_the_end_a_long_log_puts_the_reason_in() {
        let fixture = Fixture::new("uncapped");
        let owner = tenant(0x1234_5678_9abc_def0_1234_5678_9abc_def0);
        fixture.write(
            owner,
            &[("GITHUB_TOKEN".to_owned(), fixture.canary.clone())],
        );
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");
        let redactor = resolver
            .resolve(owner, &["GITHUB_TOKEN".to_owned()])
            .await
            .expect("resolve")
            .redactor();

        let noise = "compiling module\n".repeat(20_000);
        let stdout = format!(
            "{noise}auth failed for {}\n{note}",
            fixture.canary,
            note = "error: token rejected".repeat(50)
        );
        let capped = redactor.redact_text(&stdout);
        assert!(
            capped.ends_with(TRUNCATION_MARKER),
            "the capped form is expected to lose the end"
        );

        let (scrubbed, stderr) = redactor.redact_output_uncapped(&stdout, "fatal");
        assert!(!scrubbed.contains(&fixture.canary), "{scrubbed}");
        assert!(scrubbed.contains(PLACEHOLDER), "{scrubbed}");
        assert!(
            scrubbed.contains("auth failed for"),
            "the credential's own line must survive the scrub"
        );
        assert!(
            scrubbed.ends_with("token rejected"),
            "the end of the log must survive so a phase budget can keep it"
        );
        assert_eq!(stderr, "fatal");
    }

    #[tokio::test]
    async fn redaction_keeps_the_error_variant() {
        let fixture = Fixture::new("error");
        let owner = tenant(0x0f0f_1e1e_2d2d_3c3c_4b4b_5a5a_6969_7878);
        fixture.write(
            owner,
            &[("GITHUB_TOKEN".to_owned(), fixture.canary.clone())],
        );
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");
        let resolved = resolver
            .resolve(owner, &["GITHUB_TOKEN".to_owned()])
            .await
            .expect("resolve");
        let redactor = resolved.redactor();

        let leaky = CoreError::Unavailable(format!("upstream rejected token {}", fixture.canary));
        let scrubbed = redactor.redact_error(&leaky);
        assert!(matches!(scrubbed, CoreError::Unavailable(_)), "{scrubbed}");
        assert!(
            !scrubbed.to_string().contains(&fixture.canary),
            "{scrubbed}"
        );
        assert!(scrubbed.to_string().contains(PLACEHOLDER), "{scrubbed}");

        let not_found = redactor.redact_error(&CoreError::NotFound("gone".into()));
        assert!(matches!(not_found, CoreError::NotFound(_)), "{not_found}");
        let io = redactor.redact_error(&CoreError::Io(std::io::Error::other(format!(
            "write failed: {}",
            fixture.canary
        ))));
        assert!(matches!(io, CoreError::Io(_)), "{io}");
        assert!(!io.to_string().contains(&fixture.canary), "{io}");
        assert!(!format!("{redactor:?}").contains(&fixture.canary));
    }

    #[tokio::test]
    async fn malformed_json_is_reported_without_quoting_the_file() {
        let fixture = Fixture::new("malformed");
        let owner = tenant(0x9a9a_9a9a_8b8b_8b8b_7c7c_7c7c_6d6d_6d6d);
        let truncated = format!(
            "{{\"tenant_id\": \"{owner}\", \"secrets\": {{\"T\": \"{}\"",
            fixture.canary
        );
        fixture.write_raw(owner, truncated.as_bytes());
        let resolver = RunSecretResolver::new(&fixture.root).expect("resolver");

        let error = resolver
            .resolve(owner, &["T".to_owned()])
            .await
            .expect_err("a truncated file must be refused");
        assert!(matches!(error, CoreError::Backend(_)), "{error}");
        assert!(!error.to_string().contains(&fixture.canary), "{error}");
    }

    #[test]
    fn truncation_keeps_char_boundaries() {
        let text = "a".repeat(MAX_REDACTED_BYTES + 1) + "é";
        let cut = truncate(&text, 8);
        assert_eq!(cut, "aaaaaaaa\n[truncated]");
    }
}
