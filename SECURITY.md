# Security policy

## Reporting a vulnerability

SIGIL is itself a security boundary — flaws in it matter more than most.
Please report suspected vulnerabilities privately through
[GitHub Security Advisories](../../security/advisories/new) rather than
a public issue.

Include: the affected crate and version or commit, the input or call
sequence that reproduces it, and what boundary you believe it crosses
(e.g. an admitted representation reaching a consumer, a verifier
accepting a forged receipt, a scan path bypass).

Reports are handled on a best-effort basis — no response-time SLA is
claimed. You will receive an acknowledgement and, where a fix lands,
credit in the release note unless you ask otherwise.

## Scope

In scope: the `crates/sigil-*` workspace crates, the CLI, and the C FFI
boundary. Out of scope: the pinned external extractors (ffmpeg,
tesseract, pdftoppm) — report those upstream.

## Supported versions

Only the latest `develop` state is supported until a first tagged
release exists.
