//! Network policy and backend-neutral attachment lifecycle.

use crate::Sandbox;
use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub use crate::SandboxId;

/// Desired outbound network access for a sandbox.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NetworkPolicy {
    #[default]
    /// No network interface or route is attached.
    Disabled,
    /// General outbound internet access is permitted.
    Internet,
    /// Access is restricted to the listed DNS names.
    Restricted {
        /// Exact host names the sandbox may contact.
        allowed_hosts: Vec<String>,
    },
}


impl NetworkPolicy {
    /// Whether a network attachment is required.
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Returns the allowlist for a restricted policy.
    pub fn allowed_hosts(&self) -> &[String] {
        match self {
            Self::Restricted { allowed_hosts } => allowed_hosts,
            _ => &[],
        }
    }
}

impl Serialize for NetworkPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("enabled", &self.is_enabled())?;
        if let Self::Restricted { allowed_hosts } = self {
            map.serialize_entry("allowed_hosts", allowed_hosts)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for NetworkPolicy {

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Compatibility {
            #[serde(default)]
            enabled: bool,
            #[serde(default)]
            allowed_hosts: Vec<String>,
        }
        let value = Compatibility::deserialize(deserializer)?;
        if !value.enabled {
            Ok(Self::Disabled)
        } else if value.allowed_hosts.is_empty() {
            Ok(Self::Internet)
        } else {
            Ok(Self::Restricted { allowed_hosts: value.allowed_hosts })
        }
    }
}
impl NetworkAttachment {
    /// Creates an attachment description from backend resource data.
    pub fn new(resource: impl Into<String>, addresses: Vec<String>) -> Self {
        Self { resource: resource.into(), addresses }
    }

    /// Returns the backend resource name.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Returns addresses assigned to the attachment.
    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }
}

impl fmt::Display for NetworkPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("disabled"),
            Self::Internet => formatter.write_str("internet"),
            Self::Restricted { allowed_hosts } => write!(formatter, "restricted:{allowed_hosts:?}"),
        }
    }
}

/// Capabilities of a network implementation.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NetworkCapabilities {
    /// Host allowlists can be enforced.
    pub restricted_allowlists: bool,
    /// DNS controls can be enforced independently of routing.
    pub dns_controls: bool,
    /// Bandwidth limits can be applied.
    pub bandwidth_limits: bool,
}

/// Opaque backend attachment returned after network preparation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAttachment {
    /// Backend resource name, such as a TAP device.
    pub resource: String,
    /// Addresses assigned to the sandbox interface.
    pub addresses: Vec<String>,
}

/// Creates and releases network resources for sandboxes.
#[async_trait]
pub trait NetworkBackend: Send + Sync {
    /// Reports immutable network backend capabilities.
    fn capabilities(&self) -> NetworkCapabilities;
    /// Creates and configures an attachment satisfying `policy`.
    async fn prepare(
        &self,
        sandbox: &Sandbox,
        policy: &NetworkPolicy,
    ) -> Result<NetworkAttachment, crate::CoreError>;
    /// Releases an attachment previously returned by [`prepare`](Self::prepare).
    async fn release(
        &self,
        sandbox: &Sandbox,
        attachment: &NetworkAttachment,
    ) -> Result<(), crate::CoreError>;
}
