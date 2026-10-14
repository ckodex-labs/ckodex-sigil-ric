# LinkedIn post on representation integrity

What if an AI never actually saw what your security checks approved?

This question started nagging at me once models stopped being simple text boxes. Today they pull in PDF reports, raw images, audio clips, database rows, tool outputs, and text from other agents.

Most AI security still operates at the file or string level. A user uploads a file, a scanner inspects it, a human glances at a preview, and the model runs.

That flow hides an uncomfortable gap. The text a human sees, the payload a scanner checks, and the raw byte sequence a model digests are often three distinct things.

Take an image. An OCR pipeline extracts text from pixels. An audio clip becomes text through speech recognition. A PDF might hide invisible layers, white-on-white text, or malformed metadata. A multimodal model then stitches these pieces into one prompt, turning harmless fragments into an actionable instruction that never existed in any single file.

The core question changes. Asking whether an upload looks malicious is not enough. You also have to ask whether the boundaries separating trusted instructions from untrusted data survived the trip into the model.

Two points fail often.

First, text tokenizers drop boundaries. Most models run byte-pair encoding. When a tokenizer merges byte pairs across a prompt boundary, trusted system text and untrusted user inputs fuse into shared tokens. The tokenizer is just doing its job. The security system, however, lost track of who wrote what.

Second, multimodal fusion drops boundaries. A trusted system prompt, an untrusted user query, OCR text from a screenshot, and extracted document metadata get combined into a single context window. Individually, each input looks clean. The command only takes shape once the model reads them together.

The rule ought to be straightforward. Classify text before transforming it, and carry that provenance directly into the model.

I built a small engine called SIGIL around this idea, guided by a rule called the Representation Integrity Contract. The contract says you only execute what you admitted, and you prove both are identical.

SIGIL does not replace tokenizers, OCR engines, or policy tools. It wraps them. It tracks where each fragment came from, records every cleanup step, flags when tokenization crosses a boundary, and notes when combined inputs create new commands.

The output is not a thumbs-up or thumbs-down flag. It is an audit record. Here is what came in, here is how the pipeline altered it, here is what the model received, and here is the authority granted to the run.

That matters for autonomous agents. If the system cannot prove what the model read, it should pull back privileges. Drop from autonomous execution to drafting a change, or stop and ask a human. Relying on a prompt-injection filter to catch everything is wishful thinking.

The real engineering problem is not writing better prompt filters. It is keeping trust boundaries intact while data gets parsed, resized, and merged.

I tested this with three practical cases, including hidden Unicode tag characters, text hidden inside images, and benign multi-part inputs that only become dangerous when merged. The current build has 384 tests passing across nine crates. Every admission writes an admission receipt that links the input to the exact bytes sent to the model. The engine signs that receipt with ECDSA P-384, meaning anyone with the public key can verify the admission using one CLI call without needing our build setup. The contract itself is documented as RIC v0.1, covering model inputs now with tool and agent boundaries next.

The bottom line is simple. Can you prove your AI saw what you approved?

#AISecurity #AgenticAI #MultimodalAI #CyberSecurity #LLMSecurity #ZeroTrust
