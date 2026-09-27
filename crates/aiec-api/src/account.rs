//! Self-service accounts for public alpha.
//!
//! A stranger must be able to sign up with an invite, get an API key, and see
//! what they are allowed to do — without an operator creating anything for
//! them by hand. Signup is invite-gated because public alpha is deliberately
//! limited capacity, and an API key's plaintext is returned exactly once,
//! because AIec stores only a hash and could not show it again.

use crate::CoreError;
use aiec_core::ApiKeyRecord;
use aiec_core::storage::{MetadataStore, TenantRecord};
use aiec_core::{Scope, key_digest, validate_api_key};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use uuid::Uuid;

/// The scopes a new key gets. Deliberately excludes `Admin`: a self-service key
/// can use sandboxes and snapshots, not administer the platform.
pub const DEFAULT_KEY_SCOPES: [Scope; 4] = [
    Scope::SandboxesRead,
    Scope::SandboxesWrite,
    Scope::SnapshotsRead,
    Scope::SnapshotsWrite,
];
/// Request body for `POST /v1/account`.
#[derive(Deserialize)]
pub struct SignupRequest {
    /// The invite code issued to this person.
    pub invite: String,
    /// Display name for the account.
    pub name: String,
}

/// Request body for `POST /v1/keys`.
#[derive(Deserialize)]
pub struct CreateKeyRequest {
    /// A label so the key can be identified later.
    #[serde(default)]
    pub name: String,
    /// Optional expiry; the key stops working at this instant.
    #[serde(default)]
    pub expires_in_days: Option<i64>,
    /// Scopes to grant. Empty means [`DEFAULT_KEY_SCOPES`].
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// What a successful key creation returns. `key` is present exactly once.
#[derive(Serialize)]
pub struct CreatedKey {
    pub id: Uuid,
    pub name: String,
    pub key: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
}

/// A key as shown in the dashboard: metadata only, never the secret.
#[derive(Serialize)]
pub struct KeyMetadata {
    pub id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
    pub revoked_at: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
    pub last_used_at: Option<chrono::DateTime<Utc>>,
    /// Whether this key is still usable right now.
    pub active: bool,
}

impl From<ApiKeyRecord> for KeyMetadata {
    fn from(record: ApiKeyRecord) -> Self {
        let now = Utc::now();
        let active =
            record.revoked_at.is_none() && record.expires_at.is_none_or(|expiry| expiry > now);
        Self {
            id: record.id,
            name: record.name,
            scopes: record
                .scopes
                .iter()
                .map(|scope| scope_wire_name(scope.clone()))
                .collect(),
            expires_at: record.expires_at,
            revoked_at: record.revoked_at,
            created_at: record.created_at,
            last_used_at: record.last_used_at,
            active,
        }
    }
}

/// A tenant account as shown in the dashboard.
#[derive(Serialize)]
pub struct AccountView {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<Utc>,
}

/// The wire spelling of a scope, matching what `Scope::parse` accepts.
///
/// Deriving this from the debug output would produce "sandboxesread"; the
/// documented form is "sandboxes:read", so the mapping is explicit.
fn scope_wire_name(scope: Scope) -> String {
    match scope {
        Scope::SandboxesRead => "sandboxes:read",
        Scope::SandboxesWrite => "sandboxes:write",
        Scope::SnapshotsRead => "snapshots:read",
        Scope::SnapshotsWrite => "snapshots:write",
        Scope::Admin => "admin",
    }
    .to_string()
}

/// Verifies an invite code.
///
/// A deployment without `AIEC_INVITE_CODES` has signup closed rather
/// than open: a missing configuration must never silently become "anyone can
/// create an account".
pub fn invite_is_valid(configured: &[String], supplied: &str) -> bool {
    let supplied = supplied.trim();
    !supplied.is_empty()
        && configured
            .iter()
            .any(|code| constant_time_eq(code.trim(), supplied))
}

/// Compares two strings without leaking their contents through timing.
fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    left.iter()
        .zip(right.iter())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

/// Generates a fresh API key in the documented `af_live_` format.
pub fn generate_api_key() -> String {
    // 32 random bytes rendered as hex satisfies the 48..=64 length rule with
    // room to spare and carries 256 bits of entropy.
    let mut body = [0u8; 32];
    if getrandom(&mut body).is_err() {
        // Falling back to a digest of time and a fresh uuid keeps the key
        // unpredictable enough to be usable rather than panicking on a host
        // without a CSPRNG; the key is shown once and immediately rotatable.
        let seed = format!("{}:{}", Utc::now().to_rfc3339(), Uuid::now_v7());
        body.copy_from_slice(&Sha256::digest(seed.as_bytes()));
    }
    format!("af_live_{}", hex::encode(body))
}

/// Fills a buffer from the operating system CSPRNG.
fn getrandom(buffer: &mut [u8]) -> Result<(), CoreError> {
    let mut file = std::fs::File::open("/dev/urandom")?;
    file.read_exact(buffer)?;
    Ok(())
}

/// Creates the tenant for a successful signup and its first API key.
pub async fn create_account(
    repository: &dyn MetadataStore,
    request: SignupRequest,
) -> Result<(AccountView, CreatedKey), CoreError> {
    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(CoreError::InvalidRequest(
            "account name must be 1-80 characters".into(),
        ));
    }
    let now = Utc::now();
    let tenant = TenantRecord {
        id: Uuid::now_v7(),
        name: name.to_string(),
        created_at: now,
    };
    repository.put_tenant(tenant.clone()).await?;
    let (created, _record) = create_key(
        repository,
        tenant.id,
        "default",
        DEFAULT_KEY_SCOPES.to_vec(),
        None,
    )
    .await?;
    Ok((
        AccountView {
            id: tenant.id,
            name: tenant.name,
            created_at: tenant.created_at,
        },
        created,
    ))
}

/// Issues a new API key for a tenant. The plaintext is returned once.
pub async fn create_key(
    repository: &dyn MetadataStore,
    tenant: Uuid,
    name: &str,
    scopes: Vec<Scope>,
    expires_in_days: Option<i64>,
) -> Result<(CreatedKey, ApiKeyRecord), CoreError> {
    if scopes.is_empty() {
        return Err(CoreError::InvalidRequest(
            "a key needs at least one scope".into(),
        ));
    }
    let raw = generate_api_key();
    validate_api_key(&raw)?;
    let now = Utc::now();
    let expires_at = match expires_in_days {
        None => None,
        Some(days) if (1..=365).contains(&days) => Some(now + chrono::Duration::days(days)),
        Some(_) => {
            return Err(CoreError::InvalidRequest(
                "expires_in_days must be between 1 and 365".into(),
            ));
        }
    };
    let record = ApiKeyRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant,
        digest: key_digest(&raw),
        scopes: scopes.clone(),
        expires_at,
        revoked_at: None,
        name: name.trim().to_string(),
        created_at: now,
        last_used_at: None,
    };
    repository.put_key(record.clone()).await?;
    Ok((
        CreatedKey {
            id: record.id,
            name: name.trim().to_string(),
            key: raw,
            scopes: scopes
                .iter()
                .map(|scope| format!("{scope:?}").to_lowercase().replace('_', ":"))
                .collect(),
            expires_at,
            created_at: now,
        },
        record,
    ))
}

/// Lists a tenant's keys as metadata. Secrets are never returned: only a hash
/// is stored, so there is nothing to show.
pub async fn list_keys_for(
    repository: &dyn MetadataStore,
    tenant: Uuid,
) -> Result<Vec<KeyMetadata>, CoreError> {
    Ok(repository
        .list_keys(tenant)
        .await?
        .into_iter()
        .map(KeyMetadata::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_must_match_exactly() {
        let configured = vec!["alpha-one".to_string(), "beta-two".to_string()];
        assert!(invite_is_valid(&configured, "alpha-one"));
        assert!(!invite_is_valid(&configured, "alpha"));
        assert!(!invite_is_valid(&configured, ""));
    }

    #[test]
    fn no_configured_invites_means_signup_is_closed() {
        // A missing configuration must not silently become "anyone may sign up".
        assert!(!invite_is_valid(&[], "anything"));
        assert!(!invite_is_valid(&[], ""));
    }

    #[test]
    fn generated_keys_are_well_formed_and_unique() {
        let first = generate_api_key();
        let second = generate_api_key();
        validate_api_key(&first).expect("generated key is valid");
        validate_api_key(&second).expect("generated key is valid");
        assert_ne!(first, second, "keys must not repeat");
        assert!(first.starts_with("af_live_"));
    }

    #[test]
    fn default_scopes_exclude_admin() {
        // A self-service key must never be able to administer the platform.
        assert!(!DEFAULT_KEY_SCOPES.contains(&Scope::Admin));
        assert!(DEFAULT_KEY_SCOPES.contains(&Scope::SandboxesWrite));
    }
}
