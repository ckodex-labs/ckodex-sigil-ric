# Formal Verification Artifacts

This directory mirrors the machine-checkable contract surface described in
`SIGIL-SPEC.md`:

- `SigilPipeline.tla`
- `SigilSafety.tla`
- `SigilMcpSafety.tla`
- `TaintAlgebra.tla`
- `SigilLiveness.tla`
- `SigilValanceComp.tla`
- `ProbeSafety.tla`
- `MC/*.cfg`

The modules are intentionally concise so they can be extended alongside the
Rust implementation and the conformance tests.

Executable conformance vectors live in
`crates/sigil-core/tests/conformance_vectors.rs` (CV-RIC-001..008) and pin the
Representation Integrity Contract behaviors: Unicode Tags detection, strip
semantics, merge-boundary findings, receipt determinism, raw-input byte-range
traceability, and restrictive trust composition.
