# Verifying a SIGIL release

Every release from v0.4.0 on is built by `.github/workflows/release.yml` from
the tagged commit, inside the Dagger pipeline (`ci/src/stages.rs`, stages
`release` and `sbom`), and signed keylessly: the Sigstore certificates are
issued to that workflow's GitHub OIDC identity, so there is no long-lived
signing key. Each release carries:

| File | What it is |
|---|---|
| `sigil-<version>-<arch>-unknown-linux-gnu.tar.gz` | `sigil-cli`, `libsigil.a` and `libsigil.so`, the C header, licences, README and changelog, for x86_64 and aarch64 Linux (glibc 2.35 or later, built in `rust:1.88-bookworm`) |
| `SHA384SUMS`, `SHA256SUMS` | checksums of the archives (and, for SHA-256, the SBOM) |
| `sigil-<version>.cdx.json` | CycloneDX SBOM of the source tree (syft) |
| `*.sigstore.json` | a Sigstore bundle per file: signature, certificate and transparency-log proof |

GitHub also stores SLSA build provenance and an SBOM attestation for each
archive (`gh attestation`).

## 1. Checksums

    sha384sum --check SHA384SUMS        # macOS: shasum -a 384 -c SHA384SUMS

## 2. Signature (cosign 2.x or 3.x)

    v=v0.4.0
    f=sigil-${v#v}-x86_64-unknown-linux-gnu.tar.gz
    cosign verify-blob "$f" --bundle "$f.sigstore.json" \
      --certificate-identity "https://github.com/ckodex-labs/ckodex-sigil-ric/.github/workflows/release.yml@refs/tags/$v" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com

The identity pins both the workflow file and the tag: a signature made by
any other workflow, branch or repository does not verify. Check
`SHA384SUMS.sigstore.json` the same way to trust the checksum file.

## 3. Build provenance and SBOM attestation (GitHub CLI)

    gh attestation verify "$f" --repo ckodex-labs/ckodex-sigil-ric
    gh attestation verify "$f" --repo ckodex-labs/ckodex-sigil-ric \
      --predicate-type https://cyclonedx.org/bom

The provenance names the workflow run, the commit and the runner that built
the archive.

## 4. Rebuild it yourself

The archive is byte-stable for a commit on a given architecture: entries
sorted, owner 0, mtimes set to the commit time, gzip without a timestamp.

    git checkout "$v"
    dagger run cargo run --release --manifest-path ci/Cargo.toml -- release
    sha384sum dist/*.tar.gz

A rebuild of the same commit gave the same archive digest twice in a row on
the maintainer's machine (2026-11-23). Whether a rebuild on a different host
matches depends on the Rust toolchain image resolving to the same build, which
this release does not pin by digest.

## What is not in a release

SIGIL's Qwen2-VL interpreter needs Qwen2-VL-2B's tokenizer and processor
files. They are not redistributed; fetch them from their original repository
(`docs/reference-models/QWEN2-VL-2B.md`). No macOS or Windows binaries are
published yet; build from source with `cargo build --release -p sigil-cli`.
