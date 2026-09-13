use crate::{
    emit::emit_output,
    error::Result,
    intake::{intake_bytes_segment, intake_text_segment},
    merge::security_aware_merge,
    policy::Policy,
    scan::run_scan,
    signing::{receipt_message, ReceiptSignature, ReceiptSigner},
    sink::EvidenceSink,
    taint::apply_provenance,
    types::{
        ByteSegment, EvidenceBundle, Provenance, RepresentationReceipt, SigilOutput, TextSegment,
    },
    vocab::Vocab,
};
use sha2::{Digest, Sha384};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Sigil {
    vocab: Vocab,
    policy: Policy,
    receipt_signer: Option<Arc<dyn ReceiptSigner>>,
    evidence_sink: Option<Arc<Mutex<dyn EvidenceSink<EvidenceBundle> + Send>>>,
}

impl std::fmt::Debug for Sigil {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sigil")
            .field("vocab", &self.vocab)
            .field("policy", &self.policy)
            .field("receipt_signer", &self.receipt_signer.is_some())
            .field("evidence_sink", &self.evidence_sink.is_some())
            .finish()
    }
}

impl Sigil {
    pub fn new(vocab: Vocab, policy: Policy) -> Result<Self> {
        Ok(Self {
            vocab,
            policy,
            receipt_signer: None,
            evidence_sink: None,
        })
    }

    /// Attach a receipt signer. When present, every emitted receipt carries
    /// a signature over its content (docs/RIC-CONTRACT.md DEV-3). Key
    /// material lives in the signer, never in `Policy`.
    pub fn with_receipt_signer(mut self, signer: Arc<dyn ReceiptSigner>) -> Self {
        self.receipt_signer = Some(signer);
        self
    }

    /// Attach an evidence sink. When present, every emitted
    /// `EvidenceBundle` is written through it before the output is
    /// returned — a sink error fails the call rather than emitting a
    /// bundle whose `persisted` flag would be false (LIVE-003).
    pub fn with_evidence_sink(
        mut self,
        sink: Arc<Mutex<dyn EvidenceSink<EvidenceBundle> + Send>>,
    ) -> Self {
        self.evidence_sink = Some(sink);
        self
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn vocab(&self) -> &Vocab {
        &self.vocab
    }

    pub fn process_text_segments(&self, segments: &[TextSegment<'_>]) -> Result<SigilOutput> {
        let mut base_offset = 0usize;
        let mut raw_hasher = Sha384::new();
        let mut graphemes = Vec::new();

        for segment in segments {
            raw_hasher.update(segment.text.as_bytes());
            let intake = intake_text_segment(segment.text, base_offset, &self.policy)?;
            graphemes.extend(apply_provenance(intake, segment.provenance));
            base_offset += segment.text.len();
        }

        self.process_graphemes(graphemes, raw_hasher)
    }

    pub fn process_bytes_segments(&self, segments: &[ByteSegment<'_>]) -> Result<SigilOutput> {
        let mut base_offset = 0usize;
        let mut raw_hasher = Sha384::new();
        let mut graphemes = Vec::new();

        for segment in segments {
            raw_hasher.update(segment.bytes);
            let intake = intake_bytes_segment(segment.bytes, base_offset, &self.policy)?;
            graphemes.extend(apply_provenance(intake, segment.provenance));
            base_offset += segment.bytes.len();
        }

        self.process_graphemes(graphemes, raw_hasher)
    }

    pub fn scan_text(&self, text: &str) -> Result<SigilOutput> {
        self.process_text_segments(&[TextSegment {
            text,
            provenance: Provenance::User,
        }])
    }

    fn process_graphemes(
        &self,
        mut graphemes: Vec<crate::types::TaintedGrapheme>,
        raw_hasher: Sha384,
    ) -> Result<SigilOutput> {
        let mut report = run_scan(&self.policy, &mut graphemes);
        let (merged, merge_findings) = security_aware_merge(
            &self.vocab,
            &graphemes,
            self.policy.merge.suppress_cross_boundary,
        );

        // Merge-boundary records participate in the same evidence stream as
        // scan findings so tokenization-level boundary events are auditable.
        report.absorb(merge_findings);

        let mut canonical_hasher = Sha384::new();
        for grapheme in &graphemes {
            canonical_hasher.update(grapheme.grapheme.text.as_bytes());
        }
        let mut receipt = RepresentationReceipt {
            raw_digest: hex_digest(&raw_hasher.finalize()),
            canonical_digest: hex_digest(&canonical_hasher.finalize()),
            digest_algorithm: "sha384".to_string(),
            normalization: self.policy.intake.normalization.to_string(),
            vocab: self.vocab.name.clone(),
            token_count: merged.len(),
            signature: None,
        };
        if let Some(signer) = &self.receipt_signer {
            let message = receipt_message(
                &receipt.raw_digest,
                &receipt.canonical_digest,
                &receipt.digest_algorithm,
                &receipt.normalization,
                &receipt.vocab,
                receipt.token_count,
            );
            receipt.signature = Some(ReceiptSignature {
                algorithm: signer.algorithm(),
                key_id: signer.key_id(),
                signature: hex_digest(&signer.sign(&message)),
            });
        }

        let mut output = emit_output(&self.policy, merged, report, receipt);
        if let (Some(bundle), Some(sink)) = (&mut output.evidence, &self.evidence_sink) {
            bundle.persisted = true;
            sink.lock()
                .map_err(|_| {
                    crate::error::SigilError::Io(std::io::Error::other("evidence sink poisoned"))
                })?
                .record(bundle)?;
        }
        Ok(output)
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
