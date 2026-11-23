# Security policy

SIGIL is a security control, so a flaw in it can let unsafe input reach a
model with more authority than it should have. Reports are welcome and
handled privately.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | yes |
| 0.3.x and earlier | no; upgrade to 0.4 |

## Reporting a vulnerability

Report it privately through GitHub: the repository's **Security** tab,
**Report a vulnerability**
(<https://github.com/ckodex-labs/ckodex-sigil-ric/security/advisories/new>).
Please do not open a public issue, pull request or discussion for a
suspected vulnerability.

Include what you can of:

- the SIGIL version or commit, and the command or API call;
- the input (or a minimal reproducer) and the decision SIGIL made;
- the decision you expected, and why, citing the RIC rule if you know it
  (`docs/RIC-SPEC.md`);
- whether a receipt, lease or attestation verified when it should not have.

## What to expect

- An acknowledgement within 3 working days.
- An assessment, with a severity and a planned fix version, within 10
  working days.
- A fix released with a GitHub security advisory, crediting you unless you
  ask otherwise. We coordinate the disclosure date with you; the default is
  when a fixed release is available.

## Scope

In scope: anything that makes SIGIL admit input it should deny, grant a
higher authority ceiling than the rules allow, accept a forged or altered
receipt, lease, envelope or attestation, or leak input content into logs or
errors. Detection gaps for a known attack class (`docs/QA-SCORECARD.md`) are
in scope; a new attack class is welcome as a report.

Out of scope: findings that need control of the host SIGIL runs on, and
third-party models or files SIGIL only references (for example the Qwen2-VL
files in `docs/reference-models/`); report those upstream.

## Verifying what you run

Releases are signed with Sigstore from the release workflow and carry SLSA
provenance and an SBOM; see `docs/RELEASE-VERIFICATION.md`.
