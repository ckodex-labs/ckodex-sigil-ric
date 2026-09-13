# LinkedIn post — AI Representation Integrity

**What if the AI did not actually "see" what your security controls approved?**

This question has been bothering me as AI systems move beyond chat and begin consuming documents, images, audio, video, retrieved knowledge, tool outputs, and other agent-generated content.

We tend to think about AI security at the content level:

A user uploads a document.
A scanner checks it.
A human sees it.
The AI processes it.

But there is a subtle problem.

The representation the **human sees**, the representation the **security scanner analyzes**, and the representation the **model actually consumes** may be different.

An image can contain text extracted by **OCR (Optical Character Recognition)**.
Audio can become text through **ASR (Automatic Speech Recognition)**.
A document may carry visible text, hidden text, metadata, annotations, embedded objects, or retrieved context.

And a multimodal model can fuse several individually harmless inputs into a semantic instruction that did not exist in any single artifact.

That changes the security question.

Instead of asking only:

**"Is this content malicious?"**

we also need to ask:

**"Did a trust boundary disappear while preparing this content for the model?"**

There are two boundaries I find particularly interesting.

**1. Unsafe merge boundaries.**
Modern language models break text into tokens using **BPE (Byte-Pair Encoding)**. During that process, tokenization can combine material from different trust zones — for example, trusted system context and untrusted user content can end up inside the same model-consumable representation. The tokenizer is doing exactly what it was designed to do. From a security perspective, we may have lost provenance.

**2. Unsafe multimodal fusion boundaries.**
The same phenomenon appears one level higher. Trusted user instruction + untrusted image + OCR-derived text + document metadata + retrieved context → one fused model context. Individually, each input may look harmless. The security event can happen **when they are combined**.

This suggests an architectural principle that deserves far more attention:

> **Classification must happen before transformation, and provenance must survive all the way to model perception.**

I have been building a small security kernel called **SIGIL — Source Integrity & Governed Interpretation Layer** — around this idea, governed by a contract we call **RIC — Representation Integrity Contract**: admit what will be interpreted, execute what was admitted, and prove the two are the same.

SIGIL is not intended to replace tokenizers, OCR, ASR, **DLP (Data Loss Prevention)**, or policy engines. It sits around them and preserves:

- where each piece of information came from
- its trust level and sensitivity
- how it was transformed
- whether tokenization erased a boundary
- whether multimodal fusion elevated or erased one
- which exact representation was admitted to the model

The goal is not another binary SAFE/UNSAFE verdict. It is a verifiable statement:

**This is what entered. This is how it changed. This is what the model was allowed to perceive. This is the authority we allowed as a result.**

For agentic AI, that last part matters enormously. When representation integrity becomes uncertain, the system should reduce authority — act → draft → observe → escalate — rather than hoping a prompt-injection classifier catches everything.

The most interesting research direction here is not "better prompt-injection detection." It is:

## Trust-Preserving Multimodal Fusion

Can we preserve source, trust, authority, and provenance boundaries while heterogeneous information is transformed and fused into model context — and prove afterward that the representation our controls approved is the representation the model actually consumed?

I am running a bounded **POC (Proof of Concept)** with three reproducible cases: hidden Unicode instructions, image/OCR-based instructions, and cross-modal composition where benign inputs become dangerous only when fused. If the hypothesis is wrong, the experiment should tell us quickly. If it is right, the same primitive could protect **RAG (Retrieval-Augmented Generation)**, document AI, multimodal copilots, and tool-using agents.

**Status update (2026-09):** this is no longer only a proposal. The kernel exists — SIGIL v0.3, a Rust workspace with 85 passing tests and executable conformance vectors (CV-RIC-001..008). Every admission now carries a receipt binding what entered, how it changed, and what the model was allowed to perceive — signed with **ECDSA P-384** and verifiable by a third party with a single CLI command and a pinned key, no producer code required. The contract itself is published as **RIC v0.1**, with per-boundary conformance definitions for model inputs today and tool, retrieval, and agent-to-agent boundaries specified next.

The question I keep coming back to is simple:

> **Can we prove the AI saw what we approved?**

#AISecurity #AgenticAI #MultimodalAI #CyberSecurity #LLMSecurity #ZeroTrust #ResponsibleAI
