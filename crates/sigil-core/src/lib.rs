pub mod attestation;
pub mod delegation;
pub mod emit;
pub mod engine;
pub mod error;
pub mod evidence;
mod framework_map;
pub mod intake;
pub mod lfdd;
pub mod merge;
pub mod parallel;
pub mod perplexity;
pub mod policy;
pub mod scan;
pub mod signing;
pub mod sink;
pub mod taint;
pub mod terminal;
pub mod tokenizer_ffi;
pub mod types;
pub mod vocab;

pub use attestation::{attest_receipt, verify_attestation, DsseEnvelope};
pub use delegation::{
    create_root_lease, delegate, is_attenuated, validate_chain, validate_envelope, validate_lease,
    AgentEnvelope, AuthorityCeiling, Capability, CapabilityLease, DelegationError,
    DelegationRequest, RevocationRegistry, RootLeaseParams,
};
pub use engine::Sigil;
pub use error::{Result, SigilError};
pub use parallel::TokenizerActor;
pub use policy::Policy;
pub use signing::{EcdsaP384Signer, ReceiptSignature, ReceiptSigner, SignatureVerifyError};
pub use sink::{EvidenceSink, JsonlEvidenceSink};
pub use types::{
    BoundaryContext, ByteRange, ByteSegment, DlpAction, DlpFinding, DlpKind, EntropyProfile,
    EvidenceBundle, EvidenceFormat, FlagReason, Grapheme, InputAssessment, Provenance,
    RepresentationReceipt, ScanFinding, Severity, SigilOutput, TaintedGrapheme, TextSegment,
    TokenAnnotation, TrustLevel, Verdict,
};
pub use vocab::{SpecialTokenMode, Vocab};
