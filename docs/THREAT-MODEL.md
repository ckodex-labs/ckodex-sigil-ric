# SIGIL Threat Model

SIGIL defends the input boundary and its attached tool surfaces against:

- prompt injection
- Unicode control abuse
- DLP and secret exfiltration
- token smuggling
- cross-tool contamination
- cross-modal injection
- behavioral drift around the model boundary

It does not replace model integrity checks (`SHIELD`) or execution-boundary
governance (`Valance`).

## Evidence-backed regressions

The attack surfaces above are covered by checked-in regression tests:

- Core prompt injection, Unicode abuse, and secret exfiltration:
  `crates/sigil-core/tests/attack_proofs.rs`
- MCP schema drift and cross-tool contamination:
  `crates/sigil-mcp/tests/attack_proofs.rs`
- Cross-modal injection and hidden payloads:
  `crates/sigil-multimodal/tests/attack_proofs.rs`
- Behavioral drift and escalation to SHIELD:
  `crates/sigil-probe/tests/attack_proofs.rs`

The layer contracts and ownership boundaries are documented in
[`docs/CONTRACTS.md`](./CONTRACTS.md) and are treated as the authoritative
interface boundary for the workspace.
