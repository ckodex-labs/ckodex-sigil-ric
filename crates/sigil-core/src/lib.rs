pub mod attestation;
pub mod emit;
pub mod engine;
pub mod error;
pub mod evidence;
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
pub mod tokenizer_ffi;
pub mod types;
pub mod vocab;

pub use attestation::{attest_receipt, verify_attestation, DsseEnvelope};
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
