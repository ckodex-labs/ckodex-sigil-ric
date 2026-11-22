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
    let out = sigil()
        .args(["--format", "json", "verify-receipt", "--receipt"])
        .arg(receipt)
        .arg("--key")
        .arg(fixture("signer.pub.hex"))
        .output()
        .expect("spawn sigil-cli");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    json["result"].clone()
}

#[test]
fn cv_ric_034_receipts_signed_before_and_after_v4_verify() {
    for name in [
        "v2_tokenize.json",
        "v4_tokenize.json",
        "v4_perceive_qwen.json",
    ] {
        let outcome = verify(&fixture(name));
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
fn attesting_a_media_receipt_is_refused_until_the_predicate_carries_consumed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("attest.key.pem");
    let status = sigil()
        .args(["keygen", "--out-private"])
        .arg(&key)
        .arg("--out-public")
        .arg(dir.path().join("attest.pub.pem"))
        .status()
        .expect("keygen");
    assert!(status.success());
    let attest = |receipt: &str| {
        sigil()
            .args(["--format", "json", "attest", "--receipt"])
            .arg(fixture(receipt))
            .arg("--signing-key")
            .arg(&key)
            .output()
            .expect("attest")
    };
    let media = attest("v4_perceive_qwen.json");
    assert!(!media.status.success());
    assert!(String::from_utf8_lossy(&media.stderr).contains("consumed block"));
    assert!(
        attest("v4_tokenize.json").status.success(),
        "text receipts still attest"
    );
}
