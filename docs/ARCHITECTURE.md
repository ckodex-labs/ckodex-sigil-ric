# SIGIL Architecture

SIGIL is organized as a layered security boundary:

1. `sigil-core` for intake, provenance, scan, merge, and emit
2. `sigil-mcp` for tool-response inspection and per-server trust
3. `sigil-probe` for behavioral monitoring and SHIELD escalation
4. `sigil-multimodal` for cross-modal taint propagation
5. `sigil-s` for semantic companion-model scoring

See [SIGIL-SPEC.md](../SIGIL-SPEC.md) for the full formal description.
