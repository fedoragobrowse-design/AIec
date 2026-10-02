//! Signed guest image admission: a signed manifest, a verified kernel digest
//! and a verified rootfs digest, or no boot.
//!
//! ## What this is
//!
//! AIec already hashes a guest image. Hashing answers "is this the image I
//! expected?", which is only worth anything if the expected value came from
//! somewhere an attacker does not control. This module supplies that somewhere:
//! an operator-held signing key. A guarded workload that sets
//! [`ImageTrustGate::REQUIRED`] will not start an image whose manifest is
//! missing, unsigned, signed by an unknown key, signed by a key the operator has
//! removed, expired, issued implausibly far in the future, or whose recorded
//! kernel and rootfs digests do not match the bytes on disk.
//!
//! Verification returns a [`VerifiedImage`], whose fields are private and which
//! has no public constructor. A boot path that takes a `VerifiedImage` cannot be
//! handed one by anything but [`ImageTrustGate::admit`], so "the operator said
//! this image is trusted" is a value that had to be earned rather than a boolean
//! somebody set.
//!
//! ## Signature scheme
//!
//! HMAC-SHA256 over a canonical, domain-separated, length-prefixed encoding of
//! the manifest, with the key selected by the manifest's `key_id`. The encoding
//! is byte-exact and version-tagged: changing it invalidates every signature
//! ever issued, which is the point of including a version. Keys are held by id
//! rather than by position so an operator can add a new key, have it sign new
//! manifests, and then remove the old one without a coordinated cutover - and so
//! a manifest signed by a key that is no longer present is refused rather than
//! quietly checked against the wrong secret.
//!
//! ## No TPM, no attestation
//!
//! Nothing here measures a running guest, binds a measurement to hardware, or
//! detects a running kernel that has been subverted. There is no TPM, no
//! measured boot, no TPM quote and no remote attestation, and this module makes
//! no claim about any of them. What it does establish is a property of *bytes at
//! rest on this host*: that the kernel and rootfs about to be booted are the
//! ones an operator signed. A guest that is compromised after boot keeps its
//! privileges; only the out-of-guest enforcement described in the Guard spec
//! limits what a compromised guest can reach.
//!
//! Attestation is future work and would be additive, not a replacement: a
//! measured-boot quote would extend this from "the bytes on this host match a
//! signed manifest" to "the bytes this host booted are the ones the hardware
//! measured". The admission surface below does not have to change for that,
//! because it already demands a proof object rather than a boolean.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;

use crate::CoreError;

/// Manifest wire version this module understands.
pub const MANIFEST_VERSION: u16 = 1;

/// Largest manifest document accepted from disk, in bytes.
///
/// A manifest is a few hundred bytes of operator metadata. The bound stops a
/// substituted multi-megabyte file from being read into memory on the boot path.
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024;

/// File name of the signed manifest, read from the guest artifact directory.
pub const TRUSTED_IMAGE_FILE: &str = "image-trust.json";

/// Shortest signing key accepted.
///
/// HMAC-SHA256 has a 64-byte block, so a shorter key is still a well-defined
/// function; the floor here is a floor on entropy, not on the primitive. A key
/// shorter than this is a configuration mistake worth refusing at load.
pub const MIN_SIGNING_KEY_BYTES: usize = 32;

/// Upper bound on the clock skew tolerated between the signer and this host.
///
/// A manifest whose `issued_at` is further ahead than this is refused: a
/// signature that claims to have been made in the future is either a clock that
/// disagrees badly enough to matter or a replay attempt, and neither should
/// boot a guest.
pub const MAX_FUTURE_SKEW_SECONDS: i64 = 300;

/// Buffer the streamed digest of an image is read through.
const DIGEST_CHUNK: usize = 1024 * 1024;

/// Domain separation tag for the manifest signature.
///
/// Changing this invalidates every signature ever issued, which is deliberate:
/// the tag is part of the hash definition, not a detail of the encoding.
const CANONICAL_DOMAIN: &[u8] = b"aiec.guard.image-manifest.v1\0";

fn trust_error(message: impl Into<String>) -> CoreError {
    CoreError::Forbidden(message.into())
}

/// A signed statement about one guest image.
///
/// Deserialization refuses unknown fields, so a document written for a future
/// version of this format is rejected rather than partially understood.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedImageManifest {
    /// Wire version; only [`MANIFEST_VERSION`] is understood.
    pub version: u16,
    /// Operator key that signed this manifest, selected from the trust store.
    pub key_id: String,
    /// Image reference this manifest is about.
    pub reference: String,
    /// Lowercase hex SHA-256 of the kernel image.
    pub kernel_sha256: String,
    /// Lowercase hex SHA-256 of the root filesystem image.
    pub rootfs_sha256: String,
    /// When the signer issued the manifest, UTC.
    pub issued_at: DateTime<Utc>,
    /// When the manifest stops being acceptable, UTC. `None` never expires.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Hex HMAC-SHA256 over the canonical encoding of every field above.
    pub signature: String,
}

impl TrustedImageManifest {
    /// Builds and signs a manifest for one image.
    ///
    /// This is the operator-side and test-side constructor: the runtime never
    /// signs anything, it only admits.
    pub fn sign(
        key_id: &str,
        secret: &[u8],
        reference: &str,
        kernel_sha256: &str,
        rootfs_sha256: &str,
        issued_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, CoreError> {
        if secret.len() < MIN_SIGNING_KEY_BYTES {
            return Err(CoreError::InvalidRequest(format!(
                "image signing key must contain at least {MIN_SIGNING_KEY_BYTES} bytes"
            )));
        }
        let manifest = Self {
            version: MANIFEST_VERSION,
            key_id: key_id.to_owned(),
            reference: reference.to_owned(),
            kernel_sha256: kernel_sha256.to_owned(),
            rootfs_sha256: rootfs_sha256.to_owned(),
            issued_at,
            expires_at,
            signature: String::new(),
        };
        let signature = hex::encode(hmac_sha256(secret, &manifest.canonical_bytes()));
        Ok(Self {
            signature,
            ..manifest
        })
    }

    /// The exact bytes the signature covers.
    ///
    /// Every field is length-prefixed and the whole thing is domain-tagged, so
    /// no two distinct manifests can produce the same encoding, and a signature
    /// cannot be moved from one field to another.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(CANONICAL_DOMAIN);
        push_u16(&mut out, self.version);
        push_str(&mut out, &self.key_id);
        push_str(&mut out, &self.reference);
        push_str(&mut out, &self.kernel_sha256);
        push_str(&mut out, &self.rootfs_sha256);
        push_str(&mut out, &self.issued_at.to_rfc3339());
        match &self.expires_at {
            Some(expiry) => {
                out.push(1);
                push_str(&mut out, &expiry.to_rfc3339());
            }
            None => out.push(0),
        }
        out
    }

    /// Parses a manifest document, refusing unknown fields and bad shapes.
    pub fn parse(document: &[u8]) -> Result<Self, CoreError> {
        if document.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(CoreError::InvalidRequest(format!(
                "signed image manifest is larger than {MAX_MANIFEST_BYTES} bytes"
            )));
        }
        let manifest: Self = serde_json::from_slice(document)
            .map_err(|error| CoreError::InvalidRequest(error.to_string()))?;
        if manifest.version != MANIFEST_VERSION {
            return Err(CoreError::InvalidRequest(format!(
                "signed image manifest declares version {}, this build understands {MANIFEST_VERSION}",
                manifest.version
            )));
        }
        if manifest.key_id.is_empty() || manifest.key_id.len() > 64 {
            return Err(CoreError::InvalidRequest(
                "signed image manifest key_id must be 1..=64 bytes".into(),
            ));
        }
        if !is_sha256_hex(&manifest.kernel_sha256) {
            return Err(CoreError::InvalidRequest(
                "signed image manifest kernel digest is not a sha-256".into(),
            ));
        }
        if !is_sha256_hex(&manifest.rootfs_sha256) {
            return Err(CoreError::InvalidRequest(
                "signed image manifest rootfs digest is not a sha-256".into(),
            ));
        }
        Ok(manifest)
    }

    /// Reads a signed manifest from `path`, failing closed on every problem.
    pub fn load(path: &std::path::Path) -> Result<Self, CoreError> {
        let file = std::fs::File::open(path).map_err(|error| {
            CoreError::Unavailable(format!(
                "signed image manifest {} is unreadable: {error}",
                path.display()
            ))
        })?;
        let document = read_bounded(file, MAX_MANIFEST_BYTES).map_err(|error| {
            CoreError::Unavailable(format!(
                "signed image manifest {} is unreadable: {error}",
                path.display()
            ))
        })?;
        Self::parse(&document).map_err(|error| match error {
            CoreError::InvalidRequest(message) => CoreError::Unavailable(format!(
                "signed image manifest {} is malformed: {message}",
                path.display()
            )),
            other => other,
        })
    }
}

/// A manifest that passed every check.
///
/// The fields are private and there is no public constructor, so the only way to
/// obtain one is [`ImageTrustGate::admit`] returning `Ok`. A boot path that
/// demands this type cannot be satisfied by a caller that merely believes the
/// image is fine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedImage {
    reference: String,
    key_id: String,
    kernel_sha256: String,
    rootfs_sha256: String,
}

impl VerifiedImage {
    /// The image reference the operator signed.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// The operator key whose signature was accepted.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The kernel digest that was verified against the bytes on disk.
    pub fn kernel_sha256(&self) -> &str {
        &self.kernel_sha256
    }

    /// The rootfs digest that was verified against the bytes on disk.
    pub fn rootfs_sha256(&self) -> &str {
        &self.rootfs_sha256
    }
}

/// One operator-held signing key.
///
/// `Debug` is implemented by hand because the derived one would print the
/// secret into any log line, error context or test failure that formats it.
#[derive(Clone, PartialEq, Eq)]
struct SigningKey {
    secret: Vec<u8>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SigningKey(<redacted>)")
    }
}

/// Whether guarded workloads must boot a signed image.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ImageTrustRequirement {
    /// Hash verification only: today's behaviour, for deployments that have not
    /// opted in. Nothing here is claimed beyond the digests already checked.
    #[default]
    Optional,
    /// A guarded workload must present a manifest this gate admits.
    REQUIRED,
}

impl ImageTrustRequirement {
    /// Parses the operator's spelling of the requirement.
    pub fn parse(raw: &str) -> Result<Self, CoreError> {
        match raw {
            "" | "0" | "false" | "optional" => Ok(Self::Optional),
            "1" | "true" | "required" => Ok(Self::REQUIRED),
            other => Err(CoreError::InvalidRequest(format!(
                "image trust requirement must be one of required, optional; got {other:?}"
            ))),
        }
    }

    /// Whether a boot is refused without an admitted manifest.
    pub fn is_required(self) -> bool {
        matches!(self, Self::REQUIRED)
    }
}

/// The operator's signing keys and the requirement they are held to.
#[derive(Clone, Default)]
pub struct ImageTrustGate {
    requirement: ImageTrustRequirement,
    keys: BTreeMap<String, SigningKey>,
}

impl std::fmt::Debug for ImageTrustGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImageTrustGate")
            .field("requirement", &self.requirement)
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ImageTrustGate {
    /// A gate that admits nothing and requires nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// A gate with a requirement and no keys.
    ///
    /// A required gate with no keys admits no image at all, which is the correct
    /// state for a deployment that has not loaded its keys yet: it fails closed
    /// instead of quietly behaving as though signing were optional.
    pub fn new(requirement: ImageTrustRequirement) -> Self {
        Self {
            requirement,
            keys: BTreeMap::new(),
        }
    }

    /// The requirement this gate holds boot to.
    pub fn requirement(&self) -> ImageTrustRequirement {
        self.requirement
    }

    /// Whether an unsigned image is refused.
    pub fn is_required(&self) -> bool {
        self.requirement.is_required()
    }

    /// Adds or replaces one operator signing key.
    ///
    /// Replacing an existing `key_id` is a rotation step: manifests already
    /// signed by it keep verifying, because verification selects the key by id
    /// and not by insertion order.
    pub fn insert_key(&mut self, key_id: &str, secret: &[u8]) -> Result<(), CoreError> {
        if key_id.is_empty() || key_id.len() > 64 {
            return Err(CoreError::InvalidRequest(
                "image signing key id must be 1..=64 bytes".into(),
            ));
        }
        if secret.len() < MIN_SIGNING_KEY_BYTES {
            return Err(CoreError::InvalidRequest(format!(
                "image signing key must contain at least {MIN_SIGNING_KEY_BYTES} bytes"
            )));
        }
        self.keys.insert(
            key_id.to_owned(),
            SigningKey {
                secret: secret.to_vec(),
            },
        );
        Ok(())
    }

    /// Removes one signing key.
    ///
    /// After this returns `true`, a manifest naming that key is refused, which
    /// is how an operator revokes a signing key without reissuing the image.
    pub fn remove_key(&mut self, key_id: &str) -> bool {
        self.keys.remove(key_id).is_some()
    }

    /// The key identifiers this gate will accept a signature from.
    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }

    /// Admits one image, or refuses it with a reason.
    ///
    /// `kernel_sha256` and `rootfs_sha256` are the digests actually observed of
    /// the bytes about to be booted, not values copied out of the manifest: a
    /// manifest that agrees with itself but not with the disk is exactly the case
    /// this has to catch.
    ///
    /// The checks, in order, are: the manifest is present, its version is one
    /// this build understands, its `key_id` names a key this gate still holds, its
    /// signature verifies under that key in constant time, it is not issued
    /// implausibly far in the future, it is not past `expires_at`, and both
    /// recorded digests match the observed ones.
    pub fn admit(
        &self,
        manifest: Option<&TrustedImageManifest>,
        kernel_sha256: &str,
        rootfs_sha256: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedImage, CoreError> {
        let Some(manifest) = manifest else {
            return Err(trust_error(
                "guest image is unsigned: a signed manifest is required to boot it",
            ));
        };
        if manifest.version != MANIFEST_VERSION {
            return Err(trust_error(format!(
                "guest image manifest version {} is not supported",
                manifest.version
            )));
        }
        let Some(key) = self.keys.get(&manifest.key_id) else {
            return Err(trust_error(format!(
                "guest image manifest is signed by unknown key {:?}",
                manifest.key_id
            )));
        };
        let expected = hex::encode(hmac_sha256(&key.secret, &manifest.canonical_bytes()));
        if !constant_time_eq(expected.as_bytes(), manifest.signature.as_bytes()) {
            return Err(trust_error(
                "guest image manifest signature does not verify under its key",
            ));
        }
        let ahead = (manifest.issued_at - now).num_seconds();
        if ahead > MAX_FUTURE_SKEW_SECONDS {
            return Err(trust_error(format!(
                "guest image manifest claims to be issued {ahead}s in the future"
            )));
        }
        if let Some(expiry) = manifest.expires_at
            && now >= expiry
        {
            return Err(trust_error("guest image manifest has expired"));
        }
        if !digests_match(&manifest.kernel_sha256, kernel_sha256) {
            return Err(trust_error(format!(
                "guest kernel image does not match its signed digest: manifest {}, image {}",
                manifest.kernel_sha256, kernel_sha256
            )));
        }
        if !digests_match(&manifest.rootfs_sha256, rootfs_sha256) {
            return Err(trust_error(format!(
                "guest rootfs image does not match its signed digest: manifest {}, image {}",
                manifest.rootfs_sha256, rootfs_sha256
            )));
        }
        Ok(VerifiedImage {
            reference: manifest.reference.clone(),
            key_id: manifest.key_id.clone(),
            kernel_sha256: manifest.kernel_sha256.clone(),
            rootfs_sha256: manifest.rootfs_sha256.clone(),
        })
    }
}

/// SHA-256 of everything `reader` yields, streamed.
///
/// The images are multi-gigabyte and the boot path may not depend on holding one
/// in memory, so the digest is computed chunk by chunk over a fixed buffer.
pub fn sha256_reader<R: Read>(reader: &mut R) -> Result<String, CoreError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; DIGEST_CHUNK];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Reads at most `limit` bytes, refusing anything longer.
fn read_bounded<R: Read>(mut reader: R, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let mut out = Vec::new();
    let mut buffer = vec![0u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(out);
        }
        if out.len() as u64 + read as u64 > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "document is larger than its bound",
            ));
        }
        out.extend_from_slice(&buffer[..read]);
    }
}

fn hmac_sha256(secret: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn digests_match(recorded: &str, observed: &str) -> bool {
    is_sha256_hex(observed) && constant_time_eq(recorded.as_bytes(), observed.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const KEY: &[u8] = b"operator-image-signing-key-32-bytes!!";
    const OTHER_KEY: &[u8] = b"a-different-operator-key-32-bytes!!";
    const KERNEL: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const ROOTFS: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
    }

    fn digest_of(bytes: &[u8]) -> String {
        sha256_reader(&mut Cursor::new(bytes.to_vec())).expect("digest")
    }

    fn trusted_gate() -> ImageTrustGate {
        let mut gate = ImageTrustGate::new(ImageTrustRequirement::REQUIRED);
        gate.insert_key("primary", KEY).expect("key");
        gate
    }

    fn manifest() -> TrustedImageManifest {
        TrustedImageManifest::sign(
            "primary",
            KEY,
            "debian-12-coding",
            KERNEL,
            ROOTFS,
            now(),
            Some(now() + chrono::Duration::hours(1)),
        )
        .expect("sign")
    }

    #[test]
    fn a_signed_image_is_admitted_with_the_digests_that_were_checked() {
        let image = trusted_gate()
            .admit(Some(&manifest()), KERNEL, ROOTFS, now())
            .expect("signed image");
        assert_eq!(image.reference(), "debian-12-coding");
        assert_eq!(image.key_id(), "primary");
        assert_eq!(image.kernel_sha256(), KERNEL);
        assert_eq!(image.rootfs_sha256(), ROOTFS);
    }

    #[test]
    fn an_unsigned_image_is_refused_even_when_the_bytes_are_the_right_ones() {
        let error = trusted_gate()
            .admit(None, KERNEL, ROOTFS, now())
            .expect_err("no manifest is no admission");
        assert!(matches!(error, CoreError::Forbidden(_)), "{error}");
        assert!(error.to_string().contains("unsigned"), "{error}");
    }

    /// The property that makes signing worth anything: the recorded digest is
    /// compared with the digest of the bytes, not with itself.
    #[test]
    fn a_manifest_that_agrees_with_itself_but_not_with_the_disk_is_refused() {
        let bytes_digest = digest_of(b"the kernel that is actually on disk");
        let error = trusted_gate()
            .admit(Some(&manifest()), &bytes_digest, ROOTFS, now())
            .expect_err("a manifest is not a promise about the disk");
        assert!(
            error.to_string().contains("kernel image does not match"),
            "{error}"
        );

        let other = digest_of(b"a different rootfs entirely");
        let error = trusted_gate()
            .admit(Some(&manifest()), KERNEL, &other, now())
            .expect_err("rootfs must be checked too");
        assert!(
            error.to_string().contains("rootfs image does not match"),
            "{error}"
        );
    }

    #[test]
    fn a_manifest_signed_by_a_key_the_operator_removed_is_refused() {
        let signed_elsewhere = TrustedImageManifest::sign(
            "primary",
            OTHER_KEY,
            "debian-12-coding",
            KERNEL,
            ROOTFS,
            now(),
            None,
        )
        .expect("sign");
        let mut gate = trusted_gate();
        assert!(gate.remove_key("primary"));
        let error = gate
            .admit(Some(&signed_elsewhere), KERNEL, ROOTFS, now())
            .expect_err("a removed key signs nothing");
        assert!(error.to_string().contains("unknown key"), "{error}");

        // A manifest naming no key at all is refused the same way.
        let error = gate
            .admit(Some(&manifest()), KERNEL, ROOTFS, now())
            .expect_err("the removed key is gone for good");
        assert!(error.to_string().contains("unknown key"), "{error}");
    }

    #[test]
    fn a_manifest_signed_by_a_different_key_under_a_known_id_is_refused() {
        // The failure a signature scheme exists to catch: the key id is right,
        // the key behind it is not.
        let forged = TrustedImageManifest::sign(
            "primary",
            OTHER_KEY,
            "debian-12-coding",
            KERNEL,
            ROOTFS,
            now(),
            None,
        )
        .expect("sign");
        let error = trusted_gate()
            .admit(Some(&forged), KERNEL, ROOTFS, now())
            .expect_err("signature must verify under the named key");
        assert!(error.to_string().contains("does not verify"), "{error}");
    }

    /// Rotation: a second key admits its own manifests and the old one still
    /// admits its own, until the operator removes it.
    #[test]
    fn a_rotated_key_verifies_until_it_is_removed() {
        let mut gate = trusted_gate();
        gate.insert_key("next", OTHER_KEY).expect("key");
        let from_next = TrustedImageManifest::sign(
            "next",
            OTHER_KEY,
            "debian-13-coding",
            KERNEL,
            ROOTFS,
            now(),
            None,
        )
        .expect("sign");
        assert_eq!(
            gate.admit(Some(&from_next), KERNEL, ROOTFS, now())
                .expect("new key")
                .key_id(),
            "next"
        );
        assert!(gate.remove_key("primary"));
        let error = gate
            .admit(Some(&manifest()), KERNEL, ROOTFS, now())
            .expect_err("the old key is revoked");
        assert!(error.to_string().contains("unknown key"), "{error}");
    }

    #[test]
    fn an_expired_manifest_is_refused_and_a_live_one_is_not() {
        let expired = TrustedImageManifest::sign(
            "primary",
            KEY,
            "debian-12-coding",
            KERNEL,
            ROOTFS,
            now() - chrono::Duration::hours(2),
            Some(now() - chrono::Duration::hours(1)),
        )
        .expect("sign");
        let error = trusted_gate()
            .admit(Some(&expired), KERNEL, ROOTFS, now())
            .expect_err("expired is expired");
        assert!(error.to_string().contains("expired"), "{error}");
        assert!(
            trusted_gate()
                .admit(Some(&manifest()), KERNEL, ROOTFS, now())
                .is_ok()
        );
    }

    #[test]
    fn a_manifest_issued_far_in_the_future_is_refused() {
        let ahead = TrustedImageManifest::sign(
            "primary",
            KEY,
            "debian-12-coding",
            KERNEL,
            ROOTFS,
            now() + chrono::Duration::hours(1),
            None,
        )
        .expect("sign");
        let error = trusted_gate()
            .admit(Some(&ahead), KERNEL, ROOTFS, now())
            .expect_err("a signature from the future is not trusted");
        assert!(error.to_string().contains("in the future"), "{error}");
    }

    /// Any change to a signed field invalidates the signature, including a
    /// change that leaves the document the same length.
    #[test]
    fn every_signed_field_is_covered_by_the_signature() {
        let base = manifest();
        let mut edited = base.clone();
        edited.reference = "evil-12-coding".into();
        let error = trusted_gate()
            .admit(Some(&edited), KERNEL, ROOTFS, now())
            .expect_err("reference is signed");
        assert!(error.to_string().contains("does not verify"), "{error}");

        let mut edited = base.clone();
        edited.expires_at = Some(now() + chrono::Duration::days(3650));
        assert!(
            trusted_gate()
                .admit(Some(&edited), KERNEL, ROOTFS, now())
                .is_err(),
            "expiry is signed too"
        );

        let mut edited = base;
        edited.key_id = "next".into();
        assert!(
            trusted_gate()
                .admit(Some(&edited), KERNEL, ROOTFS, now())
                .is_err(),
            "the key id is signed, so it cannot be swapped to borrow another key"
        );
    }

    #[test]
    fn a_required_gate_holding_no_keys_admits_nothing() {
        let gate = ImageTrustGate::new(ImageTrustRequirement::REQUIRED);
        let error = gate
            .admit(Some(&manifest()), KERNEL, ROOTFS, now())
            .expect_err("no keys means nothing verifies");
        assert!(error.to_string().contains("unknown key"), "{error}");
    }

    #[test]
    fn a_short_signing_key_is_refused_rather_than_accepted_weakly() {
        let mut gate = ImageTrustGate::empty();
        let error = gate
            .insert_key("primary", b"too short")
            .expect_err("a short key is refused");
        assert!(error.to_string().contains("at least"), "{error}");
        assert!(gate.key_ids().is_empty());
    }

    #[test]
    fn a_debug_render_never_contains_a_signing_key() {
        let gate = trusted_gate();
        let rendered = format!("{gate:?}");
        assert!(rendered.contains("primary"), "{rendered}");
        assert!(
            !rendered.contains("operator-image-signing-key"),
            "{rendered}"
        );
    }

    /// An unknown field in the document is a document this build does not
    /// understand, and must not be partially believed.
    #[test]
    fn a_manifest_with_an_unknown_field_is_refused() {
        let document = serde_json::to_vec(&serde_json::json!({
            "version": MANIFEST_VERSION,
            "key_id": "primary",
            "reference": "debian-12-coding",
            "kernel_sha256": KERNEL,
            "rootfs_sha256": ROOTFS,
            "issued_at": now().to_rfc3339(),
            "signature": "00",
            "attestation": "quoted-by-a-vendor"
        }))
        .expect("encode");
        let error = TrustedImageManifest::parse(&document)
            .expect_err("an unknown field is a version this build does not have");
        assert!(matches!(error, CoreError::InvalidRequest(_)), "{error}");
    }

    #[test]
    fn a_manifest_declaring_another_version_is_refused() {
        let document = serde_json::to_vec(&serde_json::json!({
            "version": MANIFEST_VERSION + 1,
            "key_id": "primary",
            "reference": "debian-12-coding",
            "kernel_sha256": KERNEL,
            "rootfs_sha256": ROOTFS,
            "issued_at": now().to_rfc3339(),
            "signature": "00"
        }))
        .expect("encode");
        let error = TrustedImageManifest::parse(&document).expect_err("future version");
        assert!(error.to_string().contains("version"), "{error}");
    }

    #[test]
    fn the_requirement_parses_only_its_documented_spellings() {
        assert_eq!(
            ImageTrustRequirement::parse("required").expect("parse"),
            ImageTrustRequirement::REQUIRED
        );
        assert_eq!(
            ImageTrustRequirement::parse("").expect("parse"),
            ImageTrustRequirement::Optional
        );
        assert!(ImageTrustRequirement::parse("maybe").is_err());
        assert!(ImageTrustRequirement::REQUIRED.is_required());
        assert!(!ImageTrustRequirement::Optional.is_required());
    }

    /// The streamed digest has to agree with a one-shot digest, and has to read
    /// more than a single chunk to be worth anything on a multi-gigabyte image.
    #[test]
    fn the_streamed_digest_covers_every_chunk() {
        let image = vec![0x5au8; DIGEST_CHUNK * 2 + 12345];
        let expected = hex::encode(Sha256::digest(&image));
        assert_eq!(digest_of(&image), expected);
    }
}
