# ADR-002: Kernel I/O behind adapters, and a separate sigil-tokenizer crate

- **Status:** Proposed. Implementation targets 0.5.0, after the owner approves this ADR (RIC-MM-001 O-7, decided 2026-11-23: ADR now, code in 0.5).
- **Scope:** `sigil-core` public API, `sigil-cli`, `sigil-mcp`, `sigil-server`, `sigil-ffi`.
- **Supersedes:** nothing. Implements RIC-MM-001 plan items R-F and R-G (M4).

## Context

`docs/CONTRACTS.md` lists IO among what `sigil-core` must not own, but three
kernel paths touch the filesystem (RIC-MM-001 finding F9):

| Path | What it does | Why it matters |
|---|---|---|
| `crates/sigil-core/src/sink.rs` `JsonlEvidenceSink::open` | opens and appends to a file | the proof space writes evidence through a kernel type, so the kernel picks file modes and locking |
| `crates/sigil-core/src/signing.rs` `parse_verifying_key` (used by `verify_receipt_signature`) | reads its argument as a path if a file by that name exists, else parses it as a key | one string means two things: a key argument that happens to name a readable file changes which key a receipt is verified against |
| `crates/sigil-core/src/policy/validate.rs` | reads custom DLP pattern files named in the policy | policy validation depends on the host filesystem, so the same policy can validate differently on two hosts |

`sigil-core` also holds `tokenizer_ffi`, the `unsafe` boundary to the Zig
tokenizer, and its `build.rs` runs `zig build-lib`. The workspace denies
`unsafe_code` and allows it only in that module, so the kernel crate cannot
`forbid` unsafe code, and every consumer of the kernel builds Zig.

## Decision

1. **Kernel takes bytes and writers, adapters take paths.**
   - `JsonlEvidenceSink::new(impl Write)` stays in the kernel; `open(path)`
     moves to an adapter (`sigil-cli` helpers and `sigil-mcp` sink, the two
     callers today).
   - Verification-key parsing in the kernel accepts key text only (SPKI PEM
     or SEC1 hex), as signing-key loading already does
     (`EcdsaP384Signer::from_pkcs8_pem`). Reading a key file moves to the CLI
     and server, which take a path explicitly; the path-or-key heuristic is
     removed, not moved.
   - Policy validation takes pattern file contents. The policy loader adapter
     reads the files and passes their bytes with their names; a configured
     file that is missing or malformed stays a hard error (D4).
2. **`sigil-tokenizer`**: a new crate holding `tokenizer_ffi`, the Zig build
   and the vocab byte tables. `sigil-core` depends on it and declares
   `#![forbid(unsafe_code)]`. `sigil-ffi` keeps re-exporting the C ABI.
3. **A gate keeps it so**: `scripts/check_contracts.py` fails if
   `crates/sigil-core/src` (outside test modules) names `std::fs`,
   `std::process`, `std::net` or `unsafe`.

## Compatibility

Public API changes, so this is 0.5.0: `JsonlEvidenceSink::open` and the
path-accepting key constructor leave `sigil-core`. Serialized forms
(receipts, evidence, leases, envelopes) and signing messages do not change.
CLI flags keep their names and meaning.

## Verification

- Capture-and-compare: every CLI subcommand's output before and after, as
  for the RIC-MM-001 refactors (only random IDs and timestamps normalised).
- Existing conformance vectors CV-RIC-001 to CV-RIC-040 and the tiktoken
  parity tests pass unchanged.
- New vectors: a verification-key argument that names a file is never read by the kernel;
  pattern validation gives the same result for the same bytes regardless of
  the working directory; the contract gate fails on an injected `std::fs` use.

## Alternatives considered

- **Keep the I/O and record a derogation.** Rejected: the path-or-PEM key
  heuristic is a confusion risk, not only a layering issue.
- **Feature-gate the I/O inside `sigil-core`.** Rejected: a default-on
  feature keeps the kernel's dependency on the host, and a default-off one
  breaks every current caller anyway.

## Consequences

The kernel becomes testable without a filesystem, and the key source is
explicit. Two adapters gain a few lines each. Consumers that only need the
kernel stop building Zig only if they do not tokenize; tokenizing still needs
`sigil-tokenizer`.
