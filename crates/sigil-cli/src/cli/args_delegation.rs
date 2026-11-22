//! Arguments of the lease and envelope commands.

use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct LeaseCreateCommand {
    /// Path to parent lease JSON file if delegating from an existing lease.
    #[arg(long)]
    pub parent: Option<PathBuf>,
    /// Delegating principal identity required for root lease, such as agent://orchestrator.
    #[arg(long)]
    pub principal: Option<String>,
    /// Delegated agent identity, such as agent://worker-1.
    #[arg(long)]
    pub delegatee: String,
    /// Capabilities to grant, repeatable, such as read:src/* or tool:search.
    #[arg(long = "capability", short = 'c')]
    pub capabilities: Vec<sigil_core::Capability>,
    /// Authority ceiling: escalate, observe, draft, or act.
    #[arg(long, default_value = "act")]
    pub ceiling: sigil_core::AuthorityCeiling,
    /// SHA-384 hex digest of the admitted task representation receipt.
    #[arg(long, conflicts_with = "receipt")]
    pub representation_digest: Option<String>,
    /// Path to admitted RepresentationReceipt JSON file to bind.
    #[arg(long, conflicts_with = "representation_digest")]
    pub receipt: Option<PathBuf>,
    /// Maximum recursion depth allowed for downstream delegations.
    #[arg(long, default_value_t = 3)]
    pub max_depth: u32,
    /// Validity window in seconds.
    #[arg(long, default_value_t = 3600)]
    pub validity: u64,
    /// Output file path for the generated lease JSON, defaults to stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct LeaseVerifyCommand {
    /// Path to capability lease JSON file.
    #[arg(long, conflicts_with = "chain")]
    pub lease: Option<PathBuf>,
    /// Path to delegation chain JSON file containing an array of capability leases.
    #[arg(long, conflicts_with = "lease")]
    pub chain: Option<PathBuf>,
    /// Verification public key as hex uncompressed SEC1 point or PEM file path.
    #[arg(long)]
    pub key: Option<String>,
    /// Unix timestamp to evaluate lease validity against, defaults to current time.
    #[arg(long)]
    pub now: Option<u64>,
    /// Path to revocation registry JSON file.
    #[arg(long)]
    pub revocation_registry: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct EnvelopeCreateCommand {
    /// Path to CapabilityLease JSON file.
    #[arg(long)]
    pub lease: PathBuf,
    /// Path to RepresentationReceipt JSON file.
    #[arg(long)]
    pub receipt: PathBuf,
    /// Task payload text.
    #[arg(long)]
    pub payload: Option<String>,
    /// Path to file containing task payload.
    #[arg(long, conflicts_with = "payload")]
    pub payload_file: Option<PathBuf>,
    /// Output file path for the generated envelope JSON, defaults to stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct EnvelopeVerifyCommand {
    /// Path to AgentEnvelope JSON file.
    #[arg(long)]
    pub envelope: PathBuf,
    /// Verification public key as hex uncompressed SEC1 point or PEM file path.
    #[arg(long)]
    pub key: Option<String>,
    /// Unix timestamp to evaluate lease validity against, defaults to current time.
    #[arg(long)]
    pub now: Option<u64>,
    /// Path to revocation registry JSON file.
    #[arg(long)]
    pub revocation_registry: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct LeaseRevokeCommand {
    /// Path to revocation registry JSON file.
    #[arg(long)]
    pub registry: PathBuf,
    /// Lease identifier to revoke.
    #[arg(long)]
    pub lease_id: String,
    /// Parent lease identifier if tracking lineage revocation.
    #[arg(long)]
    pub parent_id: Option<String>,
    /// Advance epoch number after revocation.
    #[arg(long, default_value_t = false)]
    pub advance_epoch: bool,
    /// Output file path for updated registry, defaults to modifying in place.
    #[arg(long)]
    pub out: Option<PathBuf>,
}
