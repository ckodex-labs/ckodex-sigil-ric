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
pub mod receipt;
pub mod retrieval;
pub mod scan;
pub mod signing;
pub mod sink;
pub mod taint;
pub mod terminal;
pub mod tokenizer_ffi;
pub mod types;
pub mod vocab;

pub use attestation::{DsseEnvelope, attest_receipt, attest_representation, verify_attestation};
pub use delegation::{
    AgentEnvelope, AuthorityCeiling, Capability, CapabilityLease, DelegationError,
    DelegationRequest, RevocationRegistry, RootLeaseParams, create_root_lease, delegate,
    is_attenuated, validate_chain, validate_envelope, validate_lease,
};
pub use engine::Sigil;
pub use error::{Result, SigilError};
pub use parallel::TokenizerActor;
pub use policy::Policy;
pub use receipt::{ConsumedParity, ConsumedView, RECEIPT_VERSION, ReceiptVerifyError};
pub use signing::{EcdsaP384Signer, ReceiptSignature, ReceiptSigner, SignatureVerifyError};
pub use sink::{EvidenceSink, JsonlEvidenceSink};
pub use types::{
    BoundaryContext, ByteRange, ByteSegment, DlpAction, DlpFinding, DlpKind, EntropyProfile,
    EvidenceBundle, EvidenceFormat, FlagReason, Grapheme, InputAssessment, Provenance,
    RepresentationReceipt, ScanFinding, Severity, SigilOutput, TaintedGrapheme, TextSegment,
    TokenAnnotation, TrustLevel, Verdict,
};
pub use vocab::{SpecialTokenMode, Vocab};
