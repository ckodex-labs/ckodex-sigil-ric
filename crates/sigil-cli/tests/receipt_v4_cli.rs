//! RIC-MM-001 WP5 at the CLI surface: `verify-receipt` picks the signing
//! message by receipt version, so receipts the binary signed before v4 still
//! verify, and a v4 media receipt fails once its consumed block is changed.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/receipts")
        .join(name)
}

fn sigil() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sigil-cli"))
}

fn verify(receipt: &Path) -> serde_json::Value {
    verify_with(receipt, "signer.pub.hex")
}

fn verify_with(receipt: &Path, key: &str) -> serde_json::Value {
    let out = sigil()
        .args(["--format", "json", "verify-receipt", "--receipt"])
        .arg(receipt)
        .arg("--key")
        .arg(fixture(key))
        .output()
        .expect("spawn sigil-cli");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    json["result"].clone()
}

/// The public key that signed a fixture (tests/fixtures/receipts/README.md).
fn signer_of(fixture_name: &str) -> &'static str {
    if fixture_name.starts_with("v2_") {
        "v2_signer.pub.hex"
    } else {
        "signer.pub.hex"
    }
}

#[test]
fn cv_ric_034_receipts_signed_before_and_after_v4_verify() {
    for name in [
        "v2_tokenize.json",
        "v4_tokenize.json",
        "v4_perceive_qwen.json",
    ] {
        let outcome = verify_with(&fixture(name), signer_of(name));
        assert_eq!(outcome["valid"], true, "{name}: {outcome}");
    }
}

#[test]
fn cv_ric_035_a_changed_consumed_digest_fails_at_the_cli() {
    let mut receipt: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/receipts/v4_perceive_qwen.json"
    ))
    .expect("fixture");
    // The 80² nearest view's digest in place of the 644² bicubic one.
    receipt["consumed"]["digest"] = serde_json::Value::String("06801a38".repeat(12));
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tampered.json");
    std::fs::write(&path, receipt.to_string()).expect("write");
    let outcome = verify(&path);
    assert_eq!(outcome["valid"], false);
    assert!(
        outcome["error"]
            .as_str()
            .expect("error")
            .contains("does not match"),
        "{outcome}"
    );
}

#[test]
fn a_media_receipt_attests_under_the_v4_predicate_and_verifies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("attest.key.pem");
    let public = dir.path().join("attest.pub.pem");
    let keygen = sigil()
        .args(["--format", "json", "keygen", "--out-private"])
        .arg(&key)
        .arg("--out-public")
        .arg(&public)
        .output()
        .expect("keygen");
    assert!(keygen.status.success());
    let attest = sigil()
        .args(["--format", "json", "attest", "--receipt"])
        .arg(fixture("v4_perceive_qwen.json"))
        .arg("--signing-key")
        .arg(&key)
        .output()
        .expect("attest");
    assert!(
        attest.status.success(),
        "{}",
        String::from_utf8_lossy(&attest.stderr)
    );
    let envelope = dir.path().join("envelope.json");
    std::fs::write(&envelope, &attest.stdout).expect("write envelope");
    let verify = sigil()
        .args(["--format", "json", "verify-attestation", "--attestation"])
        .arg(&envelope)
        .arg("--key")
        .arg(&public)
        .output()
        .expect("verify-attestation");
    let outcome: serde_json::Value = serde_json::from_slice(&verify.stdout).expect("json");
    assert_eq!(outcome["result"]["valid"], true, "{outcome}");
}
