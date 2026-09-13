# MCP Security Gate

The MCP gate treats every server response as untrusted until:

- it is validated against declared schema
- it is scanned through `sigil-core`
- it is assigned a per-server trust profile
- the response budget is enforced
- evidence is emitted for auditability

The implementation lives in `crates/sigil-mcp`.
