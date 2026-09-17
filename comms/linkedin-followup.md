# LinkedIn follow-up — SIGIL is public

**A few weeks ago I asked: can we prove the AI saw what we approved?**

Today the answer is a public repository.

**SIGIL — Source Integrity & Governed Interpretation Layer** is now open source under ckodex-labs: a Rust workspace that sits in front of the model and enforces one contract — **no authority-bearing consumer may receive a representation that was not itself admitted.**

What shipped since the original post:

**The kernel is real, not a slide.** Intake, canonicalization, representation binding between raw and model-consumed bytes, provenance through every transform, and a verdict gate owned by the kernel — not by whichever adapter ran last.

**Every verdict carries evidence.** Admissions emit receipts — what entered, how it changed, what was allowed through — signed with ECDSA P-384, with Sigstore keyless signing support. A third party can verify a receipt with one CLI command and a pinned key. No producer code required.

**It speaks the vocabulary security teams already use.** Every detector finding maps to MITRE ATLAS and ATT&CK technique IDs — verified against the atlas-data v5.6.0 dataset, not a stale crosswalk — and every detector also maps to the ATLAS mitigation it realizes. `scan` output tells you what the adversary attempted (AML.T0051, AML.T0068, AML.T0010…) and what answered it (AML.M0015, AML.M0020…). We audited our own mapping online and published the corrections in the commit history.

**The threat model is honest.** `docs/THREAT-MODEL.md` lists 15 abuse paths — including the ones we don't fully close. Residual risk is documented, not hidden: pinned extractors prove identity, not safety; unsigned receipts carry no cryptographic integrity; the downstream consumer must honour the verdict.

**Multimodal is covered.** Images (OCR + render-divergence for text a human can't see), audio (ASR), video, documents (per-page PDF render comparison), code carriers, terminal escape sequences — each channel derives text with lineage, and the fusion layer treats the merge boundary itself as an attack surface. Individually benign inputs that compose into instructions get flagged at composition, not after.

**One command to try it:**

```
cat suspicious.txt | sigil-cli scan --fail-on deny
```

Everything runs locally. The tokenizer is the instrument; the boundary is the product.

If your agents consume documents, retrieved context, tool output, or other models' output — the question is no longer whether the content was scanned. It is whether the scanned representation is the one the model consumed.

Repository: github.com/ckodex-labs/ckodex-sigil-ric
Threat model, ATLAS/ATT&CK mapping, and conformance vectors are in the tree.

#AISecurity #LLMSecurity #AgenticAI #MultimodalAI #CyberSecurity #ZeroTrust #MITRE
