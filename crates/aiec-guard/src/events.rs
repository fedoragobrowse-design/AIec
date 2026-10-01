//! Structured, tamper-evident Guard telemetry.
//!
//! Guard emits its authoritative journal outside the guest. Records are JSON
//! objects with bounded metadata only: there is no field for a prompt, a
//! request/response body, an authorization header or a credential, and
//! `deny_unknown_fields` refuses records that carry one. Every record carries
//! the previous record's hash, so mutation, reordering and interior deletion are
//! detectable by [`verify_chain`].
//!
//! Integrity model and its limits:
//!
//! * Chaining proves a journal is an unaltered prefix-and-order sequence of the
//!   records the writer committed.
//! * Chaining alone cannot prove that *no* trailing records were removed. An
//!   operator therefore anchors [`JournalHead`] somewhere the guest cannot
//!   reach: the remote sink's acknowledged head, or an offline copy. A local
//!   journal that only ever had its tail cut still replays as a valid chain,
//!   which is documented behaviour and not a guarantee.
//!
//! Nothing in this module claims OCSF conformance: the shape is
//! OCSF-inspired, not an OCSF implementation.

mod file;
mod remote;

pub use file::{EventPage, FileEventSink, read_events, read_events_page, verify_file};
pub use remote::{
    HttpEventSink, HttpEventSinkConfig, RemoteAck, RemoteEventSink, RemoteQueue, RemoteQueueConfig,
    RemoteStatsSnapshot,
};
use std::path::PathBuf;

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{GuardError, Result};

/// Maximum bytes accepted for one serialized journal record.
pub const MAX_LINE_BYTES: usize = 4096;
/// Maximum bytes accepted for a whole-journal replay.
pub const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum records returned by one [`read_events_page`] call.
pub const MAX_PAGE_EVENTS: usize = 4096;
/// Maximum records accepted by a whole-journal replay.
pub const MAX_EVENTS: usize = 1_000_000;
/// Maximum bytes of [`EventInput::reason`].
pub const MAX_REASON_BYTES: usize = 256;
/// Maximum bytes of [`EventInput::destination`].
pub const MAX_DESTINATION_BYTES: usize = 512;
/// Maximum bytes of [`EventInput::policy_hash`].
pub const MAX_POLICY_HASH_BYTES: usize = 128;

/// `previous_hash` of the first record in a journal.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Domain separation tag; changing it invalidates every existing journal.
const CANONICAL_DOMAIN: &[u8] = b"aiec.guard.event.v1\0";

/// Field tags of the canonical encoding. They are part of the hash definition.
const TAG_TIMESTAMP: u8 = 1;
const TAG_EVENT_ID: u8 = 2;
const TAG_SANDBOX_ID: u8 = 3;
const TAG_TENANT_ID: u8 = 4;
const TAG_POLICY_HASH: u8 = 5;
const TAG_CATEGORY: u8 = 6;
const TAG_DECISION: u8 = 7;
const TAG_REASON: u8 = 8;
const TAG_DESTINATION: u8 = 9;
const TAG_REQUEST_BYTES: u8 = 10;
const TAG_RESPONSE_BYTES: u8 = 11;
const TAG_DURATION_MS: u8 = 12;
const TAG_PREVIOUS_HASH: u8 = 13;

/// What a Guard record is about.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// DNS resolution decisions taken by the gateway resolver.
    Dns,
    /// Network attachment and destination decisions.
    Network,
    /// Model broker requests and refusals.
    Model,
    /// Credential binding use and refusal. Metadata only, never the secret.
    Credential,
    /// Policy compilation, selection and application.
    #[default]
    Policy,
    /// Sandbox lifecycle transitions.
    Lifecycle,
    /// Quarantine actions.
    Quarantine,
}

impl Category {
    /// Stable lowercase wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Network => "network",
            Self::Model => "model",
            Self::Credential => "credential",
            Self::Policy => "policy",
            Self::Lifecycle => "lifecycle",
            Self::Quarantine => "quarantine",
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What Guard did, or refused to do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// The guarded action proceeded.
    Allow,
    /// The guarded action was refused.
    #[default]
    Deny,
    /// The action proceeded with an operator-relevant caveat.
    Warn,
    /// Network egress was cut for the attachment.
    Cut,
    /// The sandbox was paused pending operator review.
    Pause,
    /// The sandbox was quarantined.
    Quarantine,
}

impl Decision {
    /// Stable lowercase wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Warn => "warn",
            Self::Cut => "cut",
            Self::Pause => "pause",
            Self::Quarantine => "quarantine",
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bounded, credential-free metadata for one Guard decision.
///
/// There is deliberately no field for a prompt, a model request or response
/// body, an authorization header or a credential value, and unknown fields are
/// rejected on deserialization. Callers must build this from policy decisions
/// and static reasons, never from unvalidated guest or upstream text.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventInput {
    /// Sandbox the decision applies to.
    #[serde(default)]
    pub sandbox_id: Uuid,
    /// Tenant the sandbox belongs to.
    #[serde(default)]
    pub tenant_id: Uuid,
    /// Hash of the policy in force when the decision was taken.
    #[serde(default)]
    pub policy_hash: String,
    /// Decision category.
    #[serde(default)]
    pub category: Category,
    /// Decision outcome.
    #[serde(default)]
    pub decision: Decision,
    /// Short operator-facing explanation, at most [`MAX_REASON_BYTES`].
    #[serde(default)]
    pub reason: String,
    /// Destination the decision applied to, when there is one.
    #[serde(default)]
    pub destination: Option<String>,
    /// Bytes sent upstream for this decision.
    #[serde(default)]
    pub request_bytes: u64,
    /// Bytes received upstream for this decision.
    #[serde(default)]
    pub response_bytes: u64,
    /// Wall-clock duration of the guarded action.
    #[serde(default)]
    pub duration_ms: u64,
}

impl EventInput {
    /// Rejects metadata that is too large, non-ASCII or carries control
    /// characters, which is how a record would otherwise smuggle a newline
    /// into the journal or a secret into operator tooling.
    pub fn validate(&self) -> Result<()> {
        bounded_metadata(
            "policy_hash",
            &self.policy_hash,
            MAX_POLICY_HASH_BYTES,
            true,
        )?;
        bounded_metadata("reason", &self.reason, MAX_REASON_BYTES, true)?;
        if let Some(destination) = &self.destination {
            bounded_metadata("destination", destination, MAX_DESTINATION_BYTES, false)?;
            if destination.chars().any(char::is_whitespace) {
                return Err(GuardError::Denied(
                    "event metadata field `destination` must not contain whitespace".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Rejects oversized, non-ASCII or control-character metadata.
fn bounded_metadata(field: &str, value: &str, max_bytes: usize, allow_empty: bool) -> Result<()> {
    if value.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(GuardError::Denied(format!(
                "event metadata field `{field}` must not be empty"
            )))
        };
    }
    if value.len() > max_bytes {
        return Err(GuardError::Denied(format!(
            "event metadata field `{field}` exceeds {max_bytes} bytes"
        )));
    }
    // Printable ASCII only: no control characters, no DEL, no non-ASCII.
    let printable = value.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
    if !printable {
        return Err(GuardError::Denied(format!(
            "event metadata field `{field}` must be printable ASCII without control characters"
        )));
    }
    Ok(())
}

/// One chained journal record.
///
/// The [`EventInput`] fields are inlined so that a record is a single flat JSON
/// object, and `current_hash` is recomputed from every other field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardEvent {
    /// When the decision was taken, UTC.
    pub timestamp: DateTime<Utc>,
    /// Unique record identifier.
    pub event_id: Uuid,
    /// Sandbox the decision applies to.
    pub sandbox_id: Uuid,
    /// Tenant the sandbox belongs to.
    pub tenant_id: Uuid,
    /// Hash of the policy in force when the decision was taken.
    pub policy_hash: String,
    /// Decision category.
    pub category: Category,
    /// Decision outcome.
    pub decision: Decision,
    /// Short operator-facing explanation.
    pub reason: String,
    /// Destination the decision applied to, when there is one.
    pub destination: Option<String>,
    /// Bytes sent upstream for this decision.
    pub request_bytes: u64,
    /// Bytes received upstream for this decision.
    pub response_bytes: u64,
    /// Wall-clock duration of the guarded action.
    pub duration_ms: u64,
    /// Hash of the preceding record, [`GENESIS_HASH`] for the first one.
    pub previous_hash: String,
    /// Hash of this record's canonical encoding, excluding this field.
    pub current_hash: String,
}

impl GuardEvent {
    /// Builds a record and computes its hash.
    pub fn new(
        timestamp: DateTime<Utc>,
        event_id: Uuid,
        input: EventInput,
        previous_hash: String,
    ) -> Result<Self> {
        input.validate()?;
        if !is_sha256_hex(&previous_hash) {
            return Err(GuardError::Integrity(
                "previous_hash is not a sha-256 hex digest".to_string(),
            ));
        }
        let mut event = Self {
            timestamp,
            event_id,
            sandbox_id: input.sandbox_id,
            tenant_id: input.tenant_id,
            policy_hash: input.policy_hash,
            category: input.category,
            decision: input.decision,
            reason: input.reason,
            destination: input.destination,
            request_bytes: input.request_bytes,
            response_bytes: input.response_bytes,
            duration_ms: input.duration_ms,
            previous_hash,
            current_hash: String::new(),
        };
        event.current_hash = event.compute_hash();
        Ok(event)
    }

    /// The bounded metadata of this record.
    pub fn input(&self) -> EventInput {
        EventInput {
            sandbox_id: self.sandbox_id,
            tenant_id: self.tenant_id,
            policy_hash: self.policy_hash.clone(),
            category: self.category,
            decision: self.decision,
            reason: self.reason.clone(),
            destination: self.destination.clone(),
            request_bytes: self.request_bytes,
            response_bytes: self.response_bytes,
            duration_ms: self.duration_ms,
        }
    }

    /// Deterministic canonical encoding used for hashing.
    ///
    /// The encoding is an explicit tagged, length-prefixed byte stream rather
    /// than a serialization of a map, so it does not depend on field ordering or
    /// on the enabled `serde_json` features. `current_hash` is excluded because
    /// it is the hash of this encoding; `previous_hash` is included because the
    /// chain is what makes a record meaningful.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(CANONICAL_DOMAIN);
        push_str_field(
            &mut out,
            TAG_TIMESTAMP,
            &self.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true),
        );
        push_str_field(&mut out, TAG_EVENT_ID, &self.event_id.to_string());
        push_str_field(&mut out, TAG_SANDBOX_ID, &self.sandbox_id.to_string());
        push_str_field(&mut out, TAG_TENANT_ID, &self.tenant_id.to_string());
        push_str_field(&mut out, TAG_POLICY_HASH, &self.policy_hash);
        push_str_field(&mut out, TAG_CATEGORY, self.category.as_str());
        push_str_field(&mut out, TAG_DECISION, self.decision.as_str());
        push_str_field(&mut out, TAG_REASON, &self.reason);
        push_option_field(&mut out, TAG_DESTINATION, self.destination.as_deref());
        push_u64_field(&mut out, TAG_REQUEST_BYTES, self.request_bytes);
        push_u64_field(&mut out, TAG_RESPONSE_BYTES, self.response_bytes);
        push_u64_field(&mut out, TAG_DURATION_MS, self.duration_ms);
        push_str_field(&mut out, TAG_PREVIOUS_HASH, &self.previous_hash);
        out
    }

    /// Hash of [`Self::canonical_bytes`], lowercase hex sha-256.
    pub fn compute_hash(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }

    /// Recomputes this record's own hash, which detects content tampering
    /// without needing any other record.
    pub fn verify_self_hash(&self) -> Result<()> {
        let expected = self.compute_hash();
        if self.current_hash != expected {
            return Err(GuardError::Integrity(format!(
                "record {} does not hash to its current_hash",
                self.event_id
            )));
        }
        Ok(())
    }

    /// Rejects a record whose metadata or hashes are out of bounds.
    pub fn verify_bounds(&self) -> Result<()> {
        self.input().validate()?;
        if !is_sha256_hex(&self.previous_hash) || !is_sha256_hex(&self.current_hash) {
            return Err(GuardError::Integrity(format!(
                "record {} has a malformed chain hash",
                self.event_id
            )));
        }
        Ok(())
    }
}

/// Append-only telemetry sink. Shared by the gateway, the model broker and the
/// DNS resolver, and safe to call concurrently from any number of tasks.
#[async_trait]
pub trait EventSink: Send + Sync {
    /// Records one decision and returns the committed record.
    ///
    /// Returning `Ok` means the record is durable in this sink. Returning an
    /// error must never be interpreted as "recorded"; the caller decides
    /// whether an unrecorded decision is a hard failure.
    async fn append(&self, input: EventInput) -> Result<GuardEvent>;
}

/// Head of a journal, for anchoring and for cross-sink agreement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalHead {
    /// Number of records committed to this journal.
    pub count: u64,
    /// `current_hash` of the last committed record, [`GENESIS_HASH`] if empty.
    pub head_hash: String,
}

/// What [`FileEventSink::rotate`] sealed, and where it put it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    /// Path the sealed segment was moved to.
    pub archive: PathBuf,
    /// Records in the sealed segment, all of them chain-verified.
    pub records: usize,
    /// Head hash of the sealed segment, to match against the one before it.
    pub previous_head: Option<String>,
}

/// Verifies that `events` is one unaltered chain starting at the genesis hash.
pub fn verify_chain(events: &[GuardEvent]) -> Result<()> {
    if events.len() > MAX_EVENTS {
        return Err(GuardError::Integrity(format!(
            "journal holds {} records, replay bound is {MAX_EVENTS}",
            events.len()
        )));
    }
    let mut expected = GENESIS_HASH.to_string();
    for (index, event) in events.iter().enumerate() {
        if event.previous_hash != expected {
            return Err(GuardError::Integrity(format!(
                "record {} chains to {} but the previous record hashes to {expected}",
                index + 1,
                event.previous_hash
            )));
        }
        event.verify_self_hash()?;
        expected = event.current_hash.clone();
    }
    Ok(())
}

/// Whether `value` is a lowercase hex sha-256 digest.
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_str_field(out: &mut Vec<u8>, tag: u8, value: &str) {
    out.push(tag);
    push_bytes(out, value.as_bytes());
}

fn push_u64_field(out: &mut Vec<u8>, tag: u8, value: u64) {
    out.push(tag);
    push_bytes(out, value.to_string().as_bytes());
}

fn push_option_field(out: &mut Vec<u8>, tag: u8, value: Option<&str>) {
    out.push(tag);
    out.push(u8::from(value.is_some()));
    if let Some(value) = value {
        push_bytes(out, value.as_bytes());
    }
}
