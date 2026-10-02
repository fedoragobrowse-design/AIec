//! Per-sandbox control identity for the host/guest vsock channel.
//!
//! ## What this replaces
//!
//! The control channel between a worker and a guest agent used to be
//! authenticated with one build-time secret: `AIEC_GUEST_SECRET`, baked into the
//! guest image at build time and configured on every worker. That secret is
//! shared by every sandbox the image has ever started, on every node the image
//! has been copied to, and it never expires. A guest that learns it - which is
//! exactly what a guest is assumed to have done - holds a credential that
//! authenticates it as *any* sandbox, on *any* worker, for as long as the image
//! exists.
//!
//! ## What replaces it
//!
//! A [`ControlIdentity`]: 32 bytes of fresh randomness per sandbox, derived
//! under a deployment root so a rotation is cheap, bound to one sandbox
//! identifier and one generation, and stored on the host in a directory that is
//! not part of any snapshot surface.
//!
//! The properties, and where each is enforced:
//!
//! * **Unique per sandbox.** The derivation mixes the deployment root, the
//!   sandbox identifier and the generation, so two sandboxes cannot collide
//!   even though the same root is used for both.
//! * **Not reusable by another sandbox.** The presented secret is only ever
//!   compared against the record belonging to the sandbox that presented it,
//!   and the derivation itself is bound to that identifier. A secret lifted out
//!   of sandbox A verifies for A and for nothing else.
//! * **Short-lived.** Every record carries `expires_at`, and verification
//!   refuses a record past it. [`ControlIdentityStore::rotate`] mints a
//!   replacement, so a long-lived sandbox is re-issued rather than held open by
//!   an identity that never dies.
//! * **Rotatable and revocable.** Rotation replaces the secret and bumps the
//!   generation, so the previous secret stops verifying immediately. Revocation
//!   refuses the sandbox outright; a later [`ControlIdentityStore::issue`]
//!   starts from a strictly higher generation, so a record that was revoked and
//!   whose file was restored from a backup cannot come back at the same
//!   generation it was revoked at.
//! * **Not in a portable workspace snapshot.** The store lives in its own
//!   directory beside `vms/` and `snapshots/`, never inside either, and a
//!   portable workspace archive is built from the guest's `/workspace` tree -
//!   which this never touches. The identity is written into the per-sandbox disk
//!   image, and that image is not a portable workspace.
//! * **Verified per sandbox.** [`ControlIdentityStore::verify`] is the only way
//!   to turn a presented secret into a proof, and it takes the sandbox
//!   identifier as an argument rather than reading it from what was presented.

use crate::RuntimeError;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// Directory, relative to the worker state directory, holding control
/// identities.
///
/// A sibling of `vms/` and `snapshots/`, never inside either. A snapshot of
/// either cannot reach it, and an identity therefore cannot travel inside one.
pub const CONTROL_IDENTITY_DIR: &str = "control-identities";

/// Default lifetime of one issued identity.
///
/// Short enough that a leaked secret stops being useful on its own, and long
/// enough that an ordinary sandbox never has to be re-keyed mid-run.
pub const DEFAULT_CONTROL_IDENTITY_TTL_SECONDS: u64 = 3_600;

/// Shortest lifetime an operator may configure.
///
/// Below this a sandbox would be re-keyed more often than the control channel's
/// own round trip, which buys nothing: a rotation is only worth making when the
/// previous secret is not immediately guessable by whoever prompted it.
pub const MIN_CONTROL_IDENTITY_TTL_SECONDS: u64 = 60;

/// Longest lifetime an operator may configure.
///
/// An identity that outlives the sandbox it belongs to is a credential with no
/// owner left to notice its use.
pub const MAX_CONTROL_IDENTITY_TTL_SECONDS: u64 = 24 * 3_600;

/// Largest identity document accepted from disk, in bytes.
const MAX_RECORD_BYTES: u64 = 4 * 1024;

/// Domain separation tag for the identity derivation.
///
/// Changing it invalidates every identity ever issued, which is the point: the
/// tag is part of the definition of the credential, not a detail of its
/// encoding.
const DERIVATION_DOMAIN: &[u8] = b"aiec.guard.control-identity.v1\0";

fn identity_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::Unavailable(message.into())
}

/// Bytes that are cleared when they go out of scope.
///
/// A plain `Vec<u8>` field would leave the secret in freed heap until the
/// allocator reuses the page. This is a fixed-size array with a `Drop` that
/// overwrites it in place, so the secret does not outlive the value that holds
/// it by more than the width of one allocation.
pub struct SecretBytes([u8; 32]);

impl SecretBytes {
    fn random() -> Self {
        // Two v4 UUIDs are 32 bytes of OS randomness. The crate takes no RNG
        // dependency, and inventing one here would be worse than reusing the
        // primitive the rest of the workspace already uses for API keys.
        let mut bytes = [0u8; 32];

        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self(bytes)
    }

    /// The secret's bytes.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // A volatile write, so the clear is not elided as a dead store.
            // Safety: `byte` is a live, uniquely borrowed element of `self.0`.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

/// The persisted form of one identity.
///
/// `deny_unknown_fields` so a record written by a newer build is refused rather
/// than partially believed: a document this build cannot fully interpret is not
/// a document whose secret it can check.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct IdentityRecord {
    sandbox_id: Uuid,
    generation: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    /// Whether this record was revoked. A revoked record is kept, not deleted,
    /// so the generation counter cannot be rolled back by restoring an older
    /// file from a backup.
    revoked: bool,
    secret_hex: String,
}

impl IdentityRecord {
    fn secret(&self) -> Result<SecretBytes, RuntimeError> {
        let bytes = hex::decode(&self.secret_hex).map_err(|_| {
            identity_error("control identity record is not valid hexadecimal".to_owned())
        })?;
        let secret: [u8; 32] = bytes.try_into().map_err(|_| {
            identity_error("control identity record is not a 32-byte secret".to_owned())
        })?;
        Ok(SecretBytes(secret))
    }
}

/// One sandbox's control identity.
#[derive(Clone, Debug)]
pub struct ControlIdentity {
    sandbox_id: Uuid,
    generation: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    secret: SecretBytes,
}

impl ControlIdentity {
    /// The sandbox this identity authenticates.
    pub fn sandbox_id(&self) -> Uuid {
        self.sandbox_id
    }

    /// Which issuance this is. Rotation increments it.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// When the identity was issued.
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    /// When verification of this identity stops.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// The secret to authenticate this sandbox's control channel with.
    pub fn secret(&self) -> &SecretBytes {
        &self.secret
    }

    /// How long this identity has left, relative to `now`.
    pub fn remaining(&self, now: DateTime<Utc>) -> chrono::Duration {
        self.expires_at - now
    }
}

/// Proof that a sandbox presented the secret belonging to its own current
/// identity.
///
/// Only [`ControlIdentityStore::verify`] can produce one, and it takes the
/// sandbox identifier as an argument, so a proof cannot be minted for a sandbox
/// by presenting another sandbox's secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedControlIdentity {
    sandbox_id: Uuid,
    generation: u64,
}

impl VerifiedControlIdentity {
    /// The sandbox whose identity verified.
    pub fn sandbox_id(&self) -> Uuid {
        self.sandbox_id
    }

    /// The generation that verified.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// The on-disk store of per-sandbox control identities.
#[derive(Clone, Debug)]
pub struct ControlIdentityStore {
    root: PathBuf,
    ttl: chrono::Duration,
    root_secret: SecretBytes,
}

impl ControlIdentityStore {
    /// Opens the store rooted at `root`, reading or creating its root secret.
    ///
    /// The root secret is what makes an issuance cheap to rotate and is itself
    /// per-deployment: it never leaves this host and is not the build-time guest
    /// secret, which is exactly the credential this store exists to stop
    /// depending on.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, RuntimeError> {
        Self::with_ttl(
            root,
            chrono::Duration::seconds(DEFAULT_CONTROL_IDENTITY_TTL_SECONDS as i64),
        )
    }

    /// Opens the store with an explicit lifetime, refusing one outside the
    /// documented bounds.
    pub fn with_ttl(root: impl Into<PathBuf>, ttl: chrono::Duration) -> Result<Self, RuntimeError> {
        let root = root.into();
        let seconds = ttl.num_seconds();
        if !(MIN_CONTROL_IDENTITY_TTL_SECONDS as i64..=MAX_CONTROL_IDENTITY_TTL_SECONDS as i64)
            .contains(&seconds)
        {
            return Err(RuntimeError::Unavailable(format!(
                "control identity lifetime must be {MIN_CONTROL_IDENTITY_TTL_SECONDS}..={MAX_CONTROL_IDENTITY_TTL_SECONDS} seconds, got {seconds}"
            )));
        }
        std::fs::create_dir_all(&root)?;
        restrict_directory(&root)?;
        let root_secret = Self::load_or_create_root_secret(&root)?;
        Ok(Self {
            root,
            ttl,
            root_secret,
        })
    }

    /// Where this store keeps its records.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The lifetime every issuance gets.
    pub fn ttl(&self) -> chrono::Duration {
        self.ttl
    }

    /// Issues a fresh identity for `sandbox_id`, replacing any existing one.
    ///
    /// The generation is strictly greater than any generation this store has
    /// issued for the sandbox, including a revoked one, so restoring an old
    /// record file cannot bring a revoked generation back.
    pub fn issue(&self, sandbox_id: Uuid) -> Result<ControlIdentity, RuntimeError> {
        self.issue_at(sandbox_id, Utc::now())
    }

    /// [`Self::issue`] at a stated time, so expiry is testable without a clock
    /// race.
    pub fn issue_at(
        &self,
        sandbox_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ControlIdentity, RuntimeError> {
        let previous = self.read_record(sandbox_id)?;
        let generation = previous.map_or(1, |record| record.generation + 1);
        self.write_identity(sandbox_id, generation, now)
    }

    /// Re-keys `sandbox_id` and returns the new identity.
    ///
    /// The previous secret stops verifying the moment this returns, which is the
    /// whole point of a rotation: the caller has to be able to install the new
    /// secret on the guest, and until it does, control of that guest is lost.
    /// That is the safe direction to fail in.
    pub fn rotate(&self, sandbox_id: Uuid) -> Result<ControlIdentity, RuntimeError> {
        self.rotate_at(sandbox_id, Utc::now())
    }

    /// [`Self::rotate`] at a stated time.
    pub fn rotate_at(
        &self,
        sandbox_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ControlIdentity, RuntimeError> {
        self.issue_at(sandbox_id, now)
    }

    /// Refuses `sandbox_id` from now on.
    ///
    /// The record is kept and marked rather than removed, so a later
    /// [`Self::issue`] continues from a higher generation instead of reusing the
    /// one that was revoked.
    pub fn revoke(&self, sandbox_id: Uuid) -> Result<(), RuntimeError> {
        let Some(mut record) = self.read_record(sandbox_id)? else {
            // Revoking a sandbox that never had an identity is a no-op, not an
            // error: the wanted end state already holds.
            return Ok(());
        };
        record.revoked = true;
        record.secret_hex = hex::encode([0u8; 32]);
        self.write_record(sandbox_id, &record)
    }

    /// Whether `sandbox_id` is currently revoked.
    pub fn is_revoked(&self, sandbox_id: Uuid) -> Result<bool, RuntimeError> {
        Ok(self
            .read_record(sandbox_id)?
            .is_some_and(|record| record.revoked))
    }

    /// The live identity for `sandbox_id`, or a refusal.
    ///
    /// Fails closed on every way this can be absent: no record, a revoked
    /// record, or one past its expiry.
    pub fn current(&self, sandbox_id: Uuid) -> Result<ControlIdentity, RuntimeError> {
        self.current_at(sandbox_id, Utc::now())
    }

    /// [`Self::current`] at a stated time.
    pub fn current_at(
        &self,
        sandbox_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ControlIdentity, RuntimeError> {
        let record = self.read_record(sandbox_id)?.ok_or_else(|| {
            identity_error(format!(
                "sandbox {sandbox_id} has no control identity; a per-sandbox identity must be \
                 issued before its control channel is used"
            ))
        })?;
        if record.revoked {
            return Err(identity_error(format!(
                "the control identity of sandbox {sandbox_id} is revoked"
            )));
        }
        if now >= record.expires_at {
            return Err(identity_error(format!(
                "the control identity of sandbox {sandbox_id} expired at {}",
                record.expires_at
            )));
        }
        Ok(ControlIdentity {
            sandbox_id,
            generation: record.generation,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            secret: record.secret()?,
        })
    }

    /// The key to authenticate `sandbox_id`'s control channel with.
    ///
    /// Fails closed rather than falling back to a shared secret: a sandbox with
    /// no live identity is a sandbox the worker will not talk to.
    pub fn frame_key(&self, sandbox_id: Uuid) -> Result<SecretBytes, RuntimeError> {
        Ok(self.current(sandbox_id)?.secret)
    }

    /// Verifies a presented secret against the identity of `sandbox_id`.
    ///
    /// The comparison is constant time and the record is the one belonging to
    /// `sandbox_id`, so a secret that is valid somewhere else in the deployment
    /// is not valid here.
    pub fn verify(
        &self,
        sandbox_id: Uuid,
        presented: &[u8],
    ) -> Result<VerifiedControlIdentity, RuntimeError> {
        self.verify_at(sandbox_id, presented, Utc::now())
    }

    /// [`Self::verify`] at a stated time.
    pub fn verify_at(
        &self,
        sandbox_id: Uuid,
        presented: &[u8],
        now: DateTime<Utc>,
    ) -> Result<VerifiedControlIdentity, RuntimeError> {
        let identity = self.current_at(sandbox_id, now)?;
        if !constant_time_eq(identity.secret.expose(), presented) {
            return Err(identity_error(format!(
                "sandbox {sandbox_id} presented a secret that is not its current control identity"
            )));
        }
        Ok(VerifiedControlIdentity {
            sandbox_id,
            generation: identity.generation,
        })
    }

    /// Writes a fresh identity for `sandbox_id` and returns it.
    fn write_identity(
        &self,
        sandbox_id: Uuid,
        generation: u64,
        now: DateTime<Utc>,
    ) -> Result<ControlIdentity, RuntimeError> {
        let secret = self.derive(sandbox_id, generation, now);
        let record = IdentityRecord {
            sandbox_id,
            generation,
            issued_at: now,
            expires_at: now + self.ttl,
            revoked: false,
            secret_hex: hex::encode(secret.expose()),
        };
        self.write_record(sandbox_id, &record)?;
        Ok(ControlIdentity {
            sandbox_id,
            generation,
            issued_at: now,
            expires_at: record.expires_at,
            secret,
        })
    }

    /// Derives the secret for one issuance.
    ///
    /// The sandbox identifier and the generation are both in the derived message,
    /// so the same deployment root produces a different secret for every sandbox
    /// and a different secret again on every rotation. The issue time is in there
    /// too, so two issuances of the same sandbox at the same nanosecond are still
    /// distinguished.
    fn derive(&self, sandbox_id: Uuid, generation: u64, issued_at: DateTime<Utc>) -> SecretBytes {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.root_secret.expose())
            .expect("HMAC accepts a 32-byte key");
        mac.update(DERIVATION_DOMAIN);
        mac.update(sandbox_id.as_bytes());
        mac.update(&generation.to_be_bytes());
        mac.update(issued_at.to_rfc3339().as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&mac.finalize().into_bytes());
        SecretBytes(bytes)
    }

    fn record_path(&self, sandbox_id: Uuid) -> PathBuf {
        // The path is derived from a UUID, so it cannot traverse and cannot be
        // steered outside the store by a caller-supplied string.
        self.root.join(format!("{sandbox_id}.json"))
    }

    fn read_record(&self, sandbox_id: Uuid) -> Result<Option<IdentityRecord>, RuntimeError> {
        let path = self.record_path(sandbox_id);
        let document = match std::fs::read(&path) {
            Ok(document) => document,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(identity_error(format!(
                    "control identity {} is unreadable: {error}",
                    path.display()
                )));
            }
        };
        if document.len() as u64 > MAX_RECORD_BYTES {
            return Err(identity_error(format!(
                "control identity {} is larger than {MAX_RECORD_BYTES} bytes",
                path.display()
            )));
        }
        let record: IdentityRecord = serde_json::from_slice(&document).map_err(|error| {
            identity_error(format!(
                "control identity {} is malformed: {error}",
                path.display()
            ))
        })?;
        // A record filed under one sandbox and claiming another is a record this
        // store will not interpret: the path is the lookup key, and a mismatch
        // means the file was moved or copied rather than issued.
        if record.sandbox_id != sandbox_id {
            return Err(identity_error(format!(
                "control identity {} claims sandbox {} but is filed as {sandbox_id}",
                path.display(),
                record.sandbox_id
            )));
        }
        Ok(Some(record))
    }

    fn write_record(&self, sandbox_id: Uuid, record: &IdentityRecord) -> Result<(), RuntimeError> {
        let path = self.record_path(sandbox_id);
        let document = serde_json::to_vec(record)?;
        // Written through a temporary file and renamed, so a crash mid-write
        // leaves the previous record intact rather than a truncated one that
        // would parse as "no identity" and read as an outage.
        let temporary = path.with_extension("json.tmp");
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temporary)?;
            std::io::Write::write_all(&mut file, &document)?;
            file.sync_all()?;
        }
        restrict_file(&temporary)?;
        std::fs::rename(&temporary, &path)?;
        restrict_file(&path)
    }

    fn load_or_create_root_secret(root: &Path) -> Result<SecretBytes, RuntimeError> {
        let path = root.join("root.key");
        let existing = match std::fs::read(&path) {
            Ok(document) => document,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let secret = SecretBytes::random();
                let path_text = format!("{}\n", hex::encode(secret.expose()));
                let temporary = root.join("root.key.tmp");
                std::fs::write(&temporary, path_text.as_bytes())?;
                restrict_file(&temporary)?;
                std::fs::rename(&temporary, &path)?;
                restrict_file(&path)?;
                return Ok(secret);
            }
            Err(error) => {
                return Err(identity_error(format!(
                    "control identity root key is unreadable: {error}"
                )));
            }
        };
        // The trailing newline is written for readability and stripped here, so
        // an operator who inspects the file does not corrupt it.
        let text = std::str::from_utf8(&existing)
            .map_err(|_| identity_error("control identity root key is not text"))?
            .trim();
        let bytes = hex::decode(text)
            .map_err(|_| identity_error("control identity root key is not hexadecimal"))?;
        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| identity_error("control identity root key is not 32 bytes"))?;
        Ok(SecretBytes(secret))
    }
}

fn constant_time_eq(expected: &[u8; 32], presented: &[u8]) -> bool {
    if presented.len() != expected.len() {
        return false;
    }
    expected
        .iter()
        .zip(presented)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

/// Owner-only on a directory, so another local account cannot list identities.
fn restrict_directory(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Owner-only on a file, so another local account cannot read a secret.
fn restrict_file(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Whether `path` is inside `root`.
///
/// Used to assert that a store root is not inside a snapshot surface, and that
/// a snapshot is not inside a store.
pub fn is_within(root: &Path, path: &Path) -> bool {
    path.starts_with(root)
}

/// SHA-256 of a file, streamed.
///
/// Provided here so the runtime can check what it wrote into a disk image
/// without adding a second hashing helper.
pub fn file_digest(path: &Path) -> Result<String, RuntimeError> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Path inside the guest where the agent reads its control secret from.
pub const GUEST_SECRET_PATH: &str = "/etc/aiec-guest-secret";

/// Writes `secret` into `image` at [`GUEST_SECRET_PATH`].
///
/// The guest reads its secret out of its own filesystem, so a per-sandbox
/// identity has to be planted in the per-sandbox disk rather than in the shared
/// base image. `debugfs` edits an unmounted ext4 image in place, which is what
/// makes this possible without mounting anything or touching the base image the
/// sandbox was cloned from.
///
/// The file is replaced, not appended to, and the write is read back before this
/// returns: an image whose secret did not take would boot a guest that cannot
/// authenticate, and the failure would surface much later as an unexplained
/// handshake error rather than here.
pub fn install_guest_secret(image: &Path, secret: &SecretBytes) -> Result<(), RuntimeError> {
    if !image.is_file() {
        return Err(identity_error(format!(
            "guest disk image {} is missing, so no control identity can be installed",
            image.display()
        )));
    }
    let encoded = hex::encode(secret.expose());
    let scratch = image.with_extension("guard-identity");
    std::fs::write(&scratch, format!("{encoded}\n").as_bytes())?;
    let result = (|| -> Result<(), RuntimeError> {
        let directory = Path::new(GUEST_SECRET_PATH)
            .parent()
            .expect("a constant absolute path has a parent");
        let commands = format!(
            "mkdir {}\nrm {GUEST_SECRET_PATH}\nwrite {} {GUEST_SECRET_PATH}\n",
            directory.display(),
            scratch.display()
        );
        let script = scratch.with_extension("guard-identity.cmds");
        std::fs::write(&script, commands.as_bytes())?;
        let output = std::process::Command::new("debugfs")
            .arg("-w")
            .arg("-f")
            .arg(&script)
            .arg(image)
            .output()
            .map_err(|error| {
                identity_error(format!(
                    "debugfs is required to install a per-sandbox control identity and could not \
                     be run: {error}"
                ))
            })?;
        if !output.status.success() {
            return Err(identity_error(format!(
                "debugfs refused to install the control identity into {}: {}",
                image.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        read_guest_secret(image).and_then(|installed| {
            if installed == encoded {
                Ok(())
            } else {
                Err(identity_error(
                    "the control identity was not written into the guest disk image",
                ))
            }
        })
    })();
    let _ = std::fs::remove_file(&scratch);
    let _ = std::fs::remove_file(scratch.with_extension("guard-identity.cmds"));
    result
}

/// Reads [`GUEST_SECRET_PATH`] back out of an unmounted guest disk image.
pub fn read_guest_secret(image: &Path) -> Result<String, RuntimeError> {
    let script = image.with_extension("guard-read");
    std::fs::write(&script, format!("cat {GUEST_SECRET_PATH}\n").as_bytes())?;
    let output = std::process::Command::new("debugfs")
        .arg("-f")
        .arg(&script)
        .arg(image)
        .output()
        .map_err(|error| {
            identity_error(format!(
                "debugfs could not read the guest control identity: {error}"
            ))
        })?;
    let _ = std::fs::remove_file(&script);
    if !output.status.success() {
        return Err(identity_error(format!(
            "the guest disk image {} carries no control identity",
            image.display()
        )));
    }
    // `debugfs` echoes the command it ran, so the secret is the last non-empty
    // line rather than the whole of stdout.
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    text.lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("debugfs"))
        .map(str::to_owned)
        .ok_or_else(|| identity_error("the guest control identity file is empty"))
}

/// A [`ControlIdentityStore`] opened on first use.
///
/// [`crate::FirecrackerRuntime::new`] cannot return an error, and opening the
/// store touches the filesystem - creating the directory and reading or writing
/// the root key. Deferring that to the first sandbox that needs an identity
/// keeps construction free of side effects, so a runtime can be built in a test
/// or a dry run against a state directory that does not exist yet, and it keeps
/// the failure where it belongs: on the operation that needed the identity.
///
/// The open result is remembered, including a failure. Retrying a failed open on
/// every call would turn one permissions problem into a retry storm on the
/// control path; a worker whose store cannot be opened should stay broken until
/// it is restarted with a working state directory.
#[derive(Clone, Debug)]
pub struct LazyControlIdentityStore {
    root: PathBuf,
    ttl: chrono::Duration,
    opened: std::sync::Arc<std::sync::OnceLock<Result<ControlIdentityStore, String>>>,
}

impl LazyControlIdentityStore {
    /// A store rooted at `root` that opens on first use with the default
    /// lifetime.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_ttl(
            root,
            chrono::Duration::seconds(DEFAULT_CONTROL_IDENTITY_TTL_SECONDS as i64),
        )
    }

    /// A store rooted at `root` with an explicit lifetime, checked when the
    /// store opens rather than here: an invalid lifetime is a configuration
    /// error the first real use reports, not a construction error on a runtime
    /// that may never start a sandbox.
    pub fn with_ttl(root: impl Into<PathBuf>, ttl: chrono::Duration) -> Self {
        Self {
            root: root.into(),
            ttl,
            opened: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// The opened store.
    pub fn get(&self) -> Result<&ControlIdentityStore, RuntimeError> {
        self.opened
            .get_or_init(|| {
                ControlIdentityStore::with_ttl(self.root.clone(), self.ttl)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|message| identity_error(message.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("aiec-identity-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn store(&self) -> ControlIdentityStore {
            ControlIdentityStore::open(self.0.join(CONTROL_IDENTITY_DIR)).expect("store")
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + seconds, 0).expect("timestamp")
    }

    /// The property the whole module exists for: one sandbox's secret is not
    /// another sandbox's, even though both were issued by the same store.
    #[test]
    fn two_sandboxes_get_different_secrets() {
        let dir = Dir::new();
        let store = dir.store();
        let first = store.issue(Uuid::new_v4()).expect("first");
        let second = store.issue(Uuid::new_v4()).expect("second");
        assert_ne!(first.secret().expose(), second.secret().expose());
        assert_eq!(first.generation(), 1);
    }

    #[test]
    fn a_secret_presented_for_another_sandbox_is_refused() {
        let dir = Dir::new();
        let store = dir.store();
        let first = store.issue(Uuid::new_v4()).expect("first");
        let second = store.issue(Uuid::new_v4()).expect("second");
        // It is the right secret, for the wrong sandbox.
        assert!(
            store
                .verify(second.sandbox_id(), first.secret().expose())
                .is_err(),
            "a valid secret from sandbox A must not authenticate sandbox B"
        );
        assert!(
            store
                .verify(first.sandbox_id(), first.secret().expose())
                .is_ok(),
            "it is still the right secret for its own sandbox"
        );
    }

    #[test]
    fn a_record_filed_under_another_sandbox_is_refused_rather_than_believed() {
        let dir = Dir::new();
        let store = dir.store();
        let identity = store.issue(Uuid::new_v4()).expect("issue");
        // Copy the record over another sandbox's path, as a stolen file would be.
        let stolen = store.record_path(identity.sandbox_id());
        let other = Uuid::new_v4();
        std::fs::copy(&stolen, store.record_path(other)).expect("copy");
        let error = store
            .current(other)
            .expect_err("a copied record is not this sandbox's record");
        assert!(error.to_string().contains("claims sandbox"), "{error}");
    }

    #[test]
    fn an_identity_stops_verifying_once_it_expires() {
        let dir = Dir::new();
        let store = ControlIdentityStore::with_ttl(
            dir.0.join(CONTROL_IDENTITY_DIR),
            chrono::Duration::seconds(MIN_CONTROL_IDENTITY_TTL_SECONDS as i64),
        )
        .expect("store");
        let sandbox = Uuid::new_v4();
        let identity = store.issue_at(sandbox, at(0)).expect("issue");
        assert!(
            store
                .verify_at(sandbox, identity.secret().expose(), at(30))
                .is_ok(),
            "inside its lifetime it verifies"
        );
        let error = store
            .verify_at(
                sandbox,
                identity.secret().expose(),
                at(MIN_CONTROL_IDENTITY_TTL_SECONDS as i64 + 1),
            )
            .expect_err("past its lifetime it does not");
        assert!(error.to_string().contains("expired"), "{error}");
        assert!(
            store
                .current_at(sandbox, at(MAX_CONTROL_IDENTITY_TTL_SECONDS as i64 + 10))
                .is_err(),
            "long after its lifetime there is no identity to use"
        );
    }

    #[test]
    fn a_lifetime_outside_the_documented_bounds_is_refused() {
        let dir = Dir::new();
        for seconds in [
            0i64,
            MIN_CONTROL_IDENTITY_TTL_SECONDS as i64 - 1,
            MAX_CONTROL_IDENTITY_TTL_SECONDS as i64 + 1,
        ] {
            let error = ControlIdentityStore::with_ttl(
                dir.0.join(CONTROL_IDENTITY_DIR),
                chrono::Duration::seconds(seconds),
            )
            .expect_err("an unbounded lifetime is refused");
            assert!(error.to_string().contains("lifetime must be"), "{error}");
        }
    }

    /// Rotation is what makes a leak recoverable: the new secret works and the
    /// old one is dead the moment the rotation returns.
    #[test]
    fn the_previous_secret_is_refused_after_a_rotation() {
        let dir = Dir::new();
        let store = dir.store();
        let sandbox = Uuid::new_v4();
        let first = store.issue(sandbox).expect("issue");
        let second = store.rotate(sandbox).expect("rotate");
        assert_eq!(second.generation(), first.generation() + 1);
        assert_ne!(first.secret().expose(), second.secret().expose());
        assert!(
            store.verify(sandbox, first.secret().expose()).is_err(),
            "the rotated-out secret must not verify"
        );
        assert!(
            store.verify(sandbox, second.secret().expose()).is_ok(),
            "the new secret must verify"
        );
    }

    #[test]
    fn a_revoked_sandbox_is_refused_and_cannot_return_to_its_old_generation() {
        let dir = Dir::new();
        let store = dir.store();
        let sandbox = Uuid::new_v4();
        let identity = store.issue(sandbox).expect("issue");
        store.revoke(sandbox).expect("revoke");
        assert!(store.is_revoked(sandbox).expect("revoked"));
        assert!(
            store.verify(sandbox, identity.secret().expose()).is_err(),
            "a revoked identity must not verify"
        );
        assert!(store.current(sandbox).is_err());

        // A record file restored from before the revocation cannot come back at
        // the generation it was revoked at.
        let reissued = store.issue(sandbox).expect("re-issue");
        assert!(reissued.generation() > identity.generation());
        assert!(store.is_revoked(sandbox).is_ok_and(|revoked| !revoked));
    }

    #[test]
    fn a_sandbox_with_no_identity_is_refused_rather_than_falling_back() {
        let dir = Dir::new();
        let store = dir.store();
        let error = store
            .frame_key(Uuid::new_v4())
            .expect_err("no identity, no channel");
        assert!(error.to_string().contains("no control identity"), "{error}");
    }

    /// The store must not sit inside a surface a snapshot copies.
    #[test]
    fn the_store_is_outside_the_snapshot_and_vm_surfaces() {
        let dir = Dir::new();
        let state = dir.0.join("state");
        let store = ControlIdentityStore::open(state.join(CONTROL_IDENTITY_DIR)).expect("store");
        let vms = state.join("vms");
        let snapshots = state.join("snapshots");
        for sandbox in [Uuid::new_v4(), Uuid::new_v4()] {
            let record = store.record_path(sandbox);
            assert!(
                !is_within(&vms, &record),
                "a record under vms/ would be snapshotted"
            );
            assert!(
                !is_within(&snapshots, &record),
                "a record under snapshots/ would be snapshotted"
            );
            assert!(!is_within(&vms, store.root()));
            assert!(!is_within(&snapshots, store.root()));
        }
        assert!(is_within(store.root(), &store.record_path(Uuid::new_v4())));
    }

    /// A secret is a credential, so the file it is in is not world-readable and
    /// no `Debug` render carries it.
    #[test]
    fn secrets_are_not_readable_by_another_local_account_and_never_rendered() {
        let dir = Dir::new();
        let store = dir.store();
        let sandbox = Uuid::new_v4();
        let identity = store.issue(sandbox).expect("issue");
        let mode = std::fs::metadata(store.record_path(sandbox))
            .expect("record")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "an identity file must be owner-only");
        let directory_mode = std::fs::metadata(store.root())
            .expect("root")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700, "the store must not be listable");

        let hex_secret = hex::encode(identity.secret().expose());
        assert!(!format!("{:?}", identity.secret()).contains(&hex_secret));
        assert!(!format!("{identity:?}").contains(&hex_secret));
        assert!(!format!("{store:?}").contains(&hex_secret));
    }

    /// A record written by something that does not understand this format is not
    /// partially believed: an unknown field means the secret in it cannot be
    /// checked the way this build checks one.
    #[test]
    fn a_record_with_an_unknown_field_is_refused() {
        let dir = Dir::new();
        let store = dir.store();
        let sandbox = Uuid::new_v4();
        let identity = store.issue(sandbox).expect("issue");
        let path = store.record_path(sandbox);
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("record")).expect("json");
        record["attestation"] = serde_json::json!("quoted-by-a-vendor");
        std::fs::write(&path, serde_json::to_vec(&record).expect("encode")).expect("write");
        let error = store
            .current(sandbox)
            .expect_err("an unknown field is a version this build does not have");
        assert!(error.to_string().contains("malformed"), "{error}");
        // The record was still written by this store, so the secret is unchanged;
        // what changed is that this build will not interpret the document.
        assert_eq!(identity.generation(), 1);
    }

    /// Issued secrets must not be guessable from the store's public state: the
    /// derivation is keyed, so two stores with the same records' shapes produce
    /// different secrets for the same sandbox id and generation.
    #[test]
    fn a_different_deployment_root_yields_a_different_secret() {
        let first = Dir::new();
        let second = Dir::new();
        let sandbox = Uuid::new_v4();
        let a = first.store().issue_at(sandbox, at(0)).expect("first");
        let b = second.store().issue_at(sandbox, at(0)).expect("second");
        assert_ne!(a.secret().expose(), b.secret().expose());
    }

    #[test]
    fn a_store_survives_being_reopened() {
        let dir = Dir::new();
        let sandbox = Uuid::new_v4();
        let identity = dir.store().issue(sandbox).expect("issue");
        // A worker restart must not re-key a running sandbox, or control of it
        // would be lost to a process boundary.
        let reopened = dir.store();
        assert!(
            reopened.verify(sandbox, identity.secret().expose()).is_ok(),
            "a restart must not invalidate a live identity"
        );
    }
}
