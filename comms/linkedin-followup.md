# LinkedIn follow-up: SIGIL is public

A few weeks ago I asked whether we can prove an AI model actually saw what security controls approved.

Today the code is public.

SIGIL is open source under ckodex-labs. It is a Rust workspace that runs ahead of model inference. Its job is simple. No system may run on text that was not explicitly checked and admitted.

Here is what works in the repository today.

The code runs end to end. Intake, text normalization, raw-to-token byte mapping, transform history, and verdict checks all live in the core engine. The boundary gate belongs to the engine, not to whichever parsing script finished last.

Every verdict produces evidence. When the engine admits text, it generates an admission receipt recording the original bytes, each normalization step, and the exact admitted slice. The receipt is signed with ECDSA P-384, with support for Sigstore keyless signing. Anyone with the public key can verify the receipt from the command line without installing our build tools.

Findings map to standard security taxonomies. Every detector finding ties directly to MITRE ATLAS and ATT&CK IDs, checked against the atlas-data v5.6.0 release. The scan output lists adversary techniques like AML.T0051 or AML.T0068 alongside the corresponding mitigations. We checked our mappings against live upstream tables and committed the test cases.

The threat model documents blind spots. In docs/THREAT-MODEL.md we track 15 abuse paths, including where protection stops. Pinned binaries confirm identity rather than safety. Unsigned receipts lack tamper resistance. Downstream consumers still have to enforce the verdict exit code.

Multiple input types are supported. The engine handles OCR from images, speech recognition from audio, video stream demuxing, PDF render comparisons for invisible text, source code comments, and terminal escape sequences. Each pipeline step preserves origin data, and the fusion layer flags when clean inputs combine into malicious prompts.

Run it on any file:

```
cat suspicious.txt | sigil-cli scan --fail-on deny
```

Everything runs locally on your machine. The tokenizer is just the tool, but the boundary is the point.

If your systems consume PDFs, search results, tool output, or prompts from other models, scanning the original file is no longer enough. You need proof that the admitted text matches what the model executed.

Repository: github.com/ckodex-labs/ckodex-sigil-ric

#AISecurity #LLMSecurity #AgenticAI #MultimodalAI #CyberSecurity #ZeroTrust #MITRE
