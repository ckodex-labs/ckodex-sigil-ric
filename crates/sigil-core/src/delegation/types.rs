use crate::signing::{hex_digest, ReceiptSignature};
use crate::types::RepresentationReceipt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::collections::{BTreeMap, BTreeSet};

/// Upper bound on the authority any downstream consumer or delegated agent may exercise.
/// Ordered strictly from lowest authority to highest authority:
/// Escalate < Observe < Draft < Act.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCeiling {
    /// Human escalation gate required; autonomous execution prohibited.
    Escalate = 0,
    /// Read-only observation.
    Observe = 1,
    /// Draft proposals or pending changes without applying mutations.
    Draft = 2,
    /// Full autonomous execution.
    Act = 3,
}

impl AuthorityCeiling {
    /// Returns true if this ceiling permits the requested child ceiling.
    pub fn permits(self, child: AuthorityCeiling) -> bool {
        child <= self
    }
}

impl std::fmt::Display for AuthorityCeiling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityCeiling::Escalate => write!(f, "escalate"),
            AuthorityCeiling::Observe => write!(f, "observe"),
            AuthorityCeiling::Draft => write!(f, "draft"),
            AuthorityCeiling::Act => write!(f, "act"),
        }
    }
}

impl std::str::FromStr for AuthorityCeiling {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "escalate" => Ok(AuthorityCeiling::Escalate),
            "observe" => Ok(AuthorityCeiling::Observe),
            "draft" => Ok(AuthorityCeiling::Draft),
            "act" => Ok(AuthorityCeiling::Act),
            other => Err(format!(
                "unknown authority ceiling `{other}`, expected escalate, observe, draft, or act"
            )),
        }
    }
}

/// Typed capability granted to an agent within an execution boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "target", rename_all = "snake_case")]
pub enum Capability {
    /// Read-only access to a path, file, or resource.
    Read { path: String },
    /// Write access to a path, file, or resource.
    Write { path: String },
    /// Command execution capability.
    Execute { command: String },
    /// Network egress access to host or domain.
    Network { host: String },
    /// Tool invocation capability such as an MCP tool.
    Tool { name: String },
    /// Domain-specific custom action.
    Custom { action: String },
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Capability::Read { path } => write!(f, "read:{path}"),
            Capability::Write { path } => write!(f, "write:{path}"),
            Capability::Execute { command } => write!(f, "execute:{command}"),
            Capability::Network { host } => write!(f, "network:{host}"),
            Capability::Tool { name } => write!(f, "tool:{name}"),
            Capability::Custom { action } => write!(f, "custom:{action}"),
        }
    }
}

impl std::str::FromStr for Capability {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.starts_with('{') {
            return serde_json::from_str(trimmed).map_err(|e| e.to_string());
        }
        if let Some((kind, target)) = trimmed.split_once(':') {
            match kind.to_ascii_lowercase().as_str() {
                "read" => Ok(Capability::Read {
                    path: target.to_string(),
                }),
                "write" => Ok(Capability::Write {
                    path: target.to_string(),
                }),
                "execute" | "exec" => Ok(Capability::Execute {
                    command: target.to_string(),
                }),
                "network" | "net" => Ok(Capability::Network {
                    host: target.to_string(),
                }),
                "tool" => Ok(Capability::Tool {
                    name: target.to_string(),
                }),
                "custom" => Ok(Capability::Custom {
                    action: target.to_string(),
                }),
                other => Err(format!(
                    "unknown capability kind `{other}`, expected read, write, execute, network, tool, or custom"
                )),
            }
        } else {
            Err(format!(
                "invalid capability `{trimmed}`, expected format `kind:target` such as `read:src/*`"
            ))
        }
    }
}

impl Capability {
    /// Returns true if this capability is covered by or attenuated from the parent capability.
    pub fn is_covered_by(&self, parent: &Capability) -> bool {
        if self == parent {
            return true;
        }

        match (self, parent) {
            (Capability::Read { path: child_p }, Capability::Read { path: parent_p }) => {
                matches_path(child_p, parent_p)
            }
            (Capability::Write { path: child_p }, Capability::Write { path: parent_p }) => {
                matches_path(child_p, parent_p)
            }
            (
                Capability::Execute { command: child_c },
                Capability::Execute { command: parent_c },
            ) => matches_execute(child_c, parent_c),
            (Capability::Network { host: child_h }, Capability::Network { host: parent_h }) => {
                matches_network(child_h, parent_h)
            }
            (Capability::Tool { name: child_n }, Capability::Tool { name: parent_n }) => {
                matches_generic(child_n, parent_n)
            }
            (Capability::Custom { action: child_a }, Capability::Custom { action: parent_a }) => {
                matches_generic(child_a, parent_a)
            }
            _ => false,
        }
    }
}

fn matches_path(child: &str, pattern: &str) -> bool {
    if child.contains('\0') {
        return false;
    }
    let child_path = std::path::Path::new(child);
    for component in child_path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return false;
        }
    }
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if prefix.ends_with('/') {
            return child.starts_with(prefix);
        }
        child.starts_with(prefix)
    } else {
        child == pattern
    }
}

fn matches_execute(child: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if child.contains(';')
        || child.contains('&')
        || child.contains('|')
        || child.contains('`')
        || child.contains("$(")
    {
        return false;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        child.starts_with(prefix)
    } else {
        child == pattern
    }
}

fn matches_network(child: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return child.ends_with(&format!(".{suffix}")) || child == suffix;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return child.starts_with(prefix);
    }
    child == pattern
}

fn matches_generic(child: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return child.starts_with(prefix);
    }
    child == pattern
}

fn escape_field(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Checks that all child capabilities are covered by at least one parent capability.
pub fn is_attenuated(
    child_caps: &BTreeSet<Capability>,
    parent_caps: &BTreeSet<Capability>,
) -> Result<(), Capability> {
    for child in child_caps {
        let covered = parent_caps.iter().any(|parent| child.is_covered_by(parent));
        if !covered {
            return Err(child.clone());
        }
    }
    Ok(())
}

/// Cryptographically bound delegation lease issued from a principal to an agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLease {
    /// Unique lease identifier.
    pub lease_id: String,
    /// Parent lease ID in the delegation tree, or None for root intent.
    pub parent_lease_id: Option<String>,
    /// Identity of the delegating principal.
    pub principal: String,
    /// Identity of the delegated agent.
    pub delegatee: String,
    /// Current recursion depth where 0 represents root and 1 represents first child.
    pub depth: u32,
    /// Hard recursion depth limit.
    pub max_depth: u32,
    /// Attenuated set of permitted capabilities.
    pub capabilities: BTreeSet<Capability>,
    /// Maximum authority ceiling.
    pub authority_ceiling: AuthorityCeiling,
    /// SHA-384 canonical digest of the admitted task representation receipt.
    pub representation_digest: String,
    /// Issue timestamp in Unix epoch seconds.
    pub issued_at: u64,
    /// Expiration timestamp in Unix epoch seconds.
    pub expires_at: u64,
    /// Monotonic revocation epoch.
    pub revocation_epoch: u64,
    /// ECDSA P-384 signature over canonical lease message by delegator.
    pub signature: Option<ReceiptSignature>,
}

impl CapabilityLease {
    /// Generates the versioned, deterministic signing message for this lease.
    pub fn canonical_message(&self) -> String {
        let mut caps_list: Vec<String> = self
            .capabilities
            .iter()
            .map(|c| serde_json::to_string(c).unwrap_or_default())
            .collect();
        caps_list.sort();
        let caps_joined = caps_list.join(";");

        format!(
            "sigil-lease-v1|id={}|parent={}|principal={}|delegatee={}|depth={}|max_depth={}|ceiling={:?}|rep={}|issued={}|expires={}|epoch={}|caps={}",
            escape_field(&self.lease_id),
            escape_field(self.parent_lease_id.as_deref().unwrap_or("none")),
            escape_field(&self.principal),
            escape_field(&self.delegatee),
            self.depth,
            self.max_depth,
            self.authority_ceiling,
            escape_field(&self.representation_digest),
            self.issued_at,
            self.expires_at,
            self.revocation_epoch,
            escape_field(&caps_joined)
        )
    }
}

/// Parameters for initializing a root capability lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootLeaseParams {
    pub principal: String,
    pub delegatee: String,
    pub capabilities: BTreeSet<Capability>,
    pub authority_ceiling: AuthorityCeiling,
    pub representation_digest: String,
    pub max_depth: u32,
    pub validity_seconds: u64,
    pub issued_at: u64,
    pub revocation_epoch: u64,
}

impl RootLeaseParams {
    pub fn new(
        principal: impl Into<String>,
        delegatee: impl Into<String>,
        representation_digest: impl Into<String>,
    ) -> Self {
        Self {
            principal: principal.into(),
            delegatee: delegatee.into(),
            capabilities: BTreeSet::new(),
            authority_ceiling: AuthorityCeiling::Act,
            representation_digest: representation_digest.into(),
            max_depth: 3,
            validity_seconds: 3600,
            issued_at: 0,
            revocation_epoch: 1,
        }
    }
}

/// Request to create a delegated child lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationRequest {
    pub delegatee: String,
    pub capabilities: BTreeSet<Capability>,
    pub authority_ceiling: AuthorityCeiling,
    pub representation_digest: String,
    pub validity_seconds: u64,
}

/// Typed wire envelope carrying representation receipt, delegation lease, and task payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEnvelope {
    pub envelope_id: String,
    pub lease: CapabilityLease,
    pub receipt: RepresentationReceipt,
    pub payload: String,
    pub signature: Option<ReceiptSignature>,
}

impl AgentEnvelope {
    /// Generates the deterministic canonical message for signing an agent envelope.
    pub fn canonical_message(&self) -> String {
        let mut hasher = Sha384::new();
        hasher.update(self.payload.as_bytes());
        let payload_digest = hex_digest(&hasher.finalize());
        format!(
            "sigil-envelope-v1|id={}|lease={}|receipt={}|payload_digest={}|payload_len={}",
            escape_field(&self.envelope_id),
            escape_field(&self.lease.lease_id),
            escape_field(&self.receipt.canonical_digest),
            payload_digest,
            self.payload.len()
        )
    }
}

/// In-memory revocation registry tracking revoked lease IDs and revocation epoch.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RevocationRegistry {
    pub current_epoch: u64,
    pub revoked_lease_ids: BTreeSet<String>,
    #[serde(default)]
    pub parent_map: BTreeMap<String, String>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, lease_id: impl Into<String>) {
        self.revoked_lease_ids.insert(lease_id.into());
    }

    pub fn record_lineage(
        &mut self,
        lease_id: impl Into<String>,
        parent_lease_id: impl Into<String>,
    ) {
        self.parent_map
            .insert(lease_id.into(), parent_lease_id.into());
    }

    pub fn advance_epoch(&mut self) {
        self.current_epoch = self.current_epoch.saturating_add(1);
    }

    pub fn is_revoked(&self, lease: &CapabilityLease) -> bool {
        if lease.revocation_epoch < self.current_epoch {
            return true;
        }
        if self.revoked_lease_ids.contains(&lease.lease_id) {
            return true;
        }
        if let Some(parent) = &lease.parent_lease_id {
            if self.revoked_lease_ids.contains(parent) {
                return true;
            }
            let mut curr = parent.as_str();
            while let Some(ancestor) = self.parent_map.get(curr) {
                if self.revoked_lease_ids.contains(ancestor) {
                    return true;
                }
                curr = ancestor.as_str();
            }
        }
        false
    }
}

/// Errors occurring during lease creation, attenuation, or verification.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    #[error("capability escalation: child requested {requested:?}, not permitted by parent lease")]
    CapabilityEscalation { requested: Capability },

    #[error(
        "authority ceiling escalation: child ceiling {child:?} exceeds parent ceiling {parent:?}"
    )]
    AuthorityCeilingEscalation {
        child: AuthorityCeiling,
        parent: AuthorityCeiling,
    },

    #[error("max delegation depth {max_depth} reached (current: {depth})")]
    MaxDepthExceeded { depth: u32, max_depth: u32 },

    #[error("representation digest mismatch: lease specifies {expected}, receipt has {actual}")]
    RepresentationMismatch { expected: String, actual: String },

    #[error("expired lease: now {now} > expires_at {expires_at}")]
    LeaseExpired { now: u64, expires_at: u64 },

    #[error("premature lease: now {now} < issued_at {issued_at}")]
    LeasePremature { now: u64, issued_at: u64 },

    #[error("lease has been revoked: {lease_id}")]
    LeaseRevoked { lease_id: String },

    #[error("revocation epoch expired: lease epoch {lease_epoch} < current {current_epoch}")]
    RevocationEpochExpired {
        lease_epoch: u64,
        current_epoch: u64,
    },

    #[error(
        "broken delegation chain: parent lease id {expected:?} does not match actual {actual}"
    )]
    BrokenChain {
        expected: Option<String>,
        actual: String,
    },

    #[error("signature error: {0}")]
    Signature(String),

    #[error("missing signature on lease: {0}")]
    MissingSignature(String),
}
