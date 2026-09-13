use crate::cli::commands::*;
use crate::cli::helpers::*;
use crate::cli::types::*;
use sigil_core::policy::Policy;
use sigil_core::Vocab;

mod verify_receipt_tests {
    use super::*;
    use sigil_core::{EcdsaP384Signer, Policy, Sigil};
    use std::sync::Arc;

    fn signed_output_json() -> (String, String) {
        let signer =
            Arc::new(EcdsaP384Signer::from_private_key_bytes(&[42u8; 48]).expect("valid scalar"));
        let key = signer.verification_key_hex();
        let engine = Sigil::new(Vocab::tiktoken("cl100k_base"), Policy::default())
            .expect("engine")
            .with_receipt_signer(signer);
        let output = engine.scan_text("verify me").expect("scan");
        let json = serde_json::to_string(&output).expect("serialize");
        (json, key)
    }

    #[test]
    fn verify_receipt_accepts_full_sigil_output_envelope() {
        let (json, key) = signed_output_json();
        let path = std::env::temp_dir().join("sigil-verify-receipt-full.json");
        std::fs::write(&path, json).expect("write");
        let outcome = verify_receipt_command(&VerifyReceiptCommand {
            receipt: path.clone(),
            key,
        })
        .expect("verify");
        std::fs::remove_file(path).ok();
        assert!(outcome.valid, "outcome: {outcome:?}");
        assert_eq!(outcome.algorithm.as_deref(), Some("ecdsa-p384-sha384"));
    }

    #[test]
    fn verify_receipt_rejects_tampered_token_count() {
        let (json, key) = signed_output_json();
        let mut value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        value["receipt"]["token_count"] = serde_json::json!(999);
        let path = std::env::temp_dir().join("sigil-verify-receipt-tampered.json");
        std::fs::write(&path, serde_json::to_string(&value).expect("serialize")).expect("write");
        let outcome = verify_receipt_command(&VerifyReceiptCommand {
            receipt: path.clone(),
            key,
        })
        .expect("verify");
        std::fs::remove_file(path).ok();
        assert!(!outcome.valid);
        assert!(outcome.error.is_some());
    }

    #[test]
    fn verify_receipt_reports_unsigned() {
        let engine = Sigil::new(Vocab::tiktoken("cl100k_base"), Policy::default()).expect("engine");
        let output = engine.scan_text("unsigned probe").expect("scan");
        let path = std::env::temp_dir().join("sigil-verify-receipt-unsigned.json");
        std::fs::write(&path, serde_json::to_string(&output).expect("serialize")).expect("write");
        let outcome = verify_receipt_command(&VerifyReceiptCommand {
            receipt: path.clone(),
            key: "00".repeat(97),
        })
        .expect("verify");
        std::fs::remove_file(path).ok();
        assert!(!outcome.valid);
        assert_eq!(outcome.error.as_deref(), Some("receipt is unsigned"));
    }
}

#[cfg(test)]
mod keygen_signing_tests {
    use super::*;

    #[test]
    fn keygen_sign_verify_loop_through_cli_paths() {
        let dir = std::env::temp_dir().join("sigil-keygen-loop-test");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let private = dir.join("private.pem");
        let public = dir.join("public.pem");

        // 1. keygen
        let outcome = keygen_command(&KeygenCommand {
            out_private: private.clone(),
            out_public: public.clone(),
        })
        .expect("keygen");
        assert!(private.exists());
        assert!(public.exists());
        assert_eq!(outcome.verification_key_hex.len(), 97 * 2);

        // 2. sign through the loaded-key path
        let signer = load_signing_key(Some(&private))
            .expect("load")
            .expect("signer present");
        let engine = build_sigil(
            Vocab::tiktoken("cl100k_base"),
            Policy::default(),
            Some(&signer),
            None,
        )
        .expect("engine");
        let output = engine.scan_text("key loop probe").expect("scan");
        assert!(output.receipt.signature.is_some());

        // 3. verify through the verify-receipt command path
        let receipt_path = dir.join("signed.json");
        std::fs::write(
            &receipt_path,
            serde_json::to_string(&serde_json::json!({ "result": output })).expect("serialize"),
        )
        .expect("write");
        let verification = verify_receipt_command(&VerifyReceiptCommand {
            receipt: receipt_path.clone(),
            key: outcome.verification_key_hex,
        })
        .expect("verify");
        assert!(verification.valid, "verification: {verification:?}");

        // 4. wrong key fails
        let wrong = verify_receipt_command(&VerifyReceiptCommand {
            receipt: receipt_path,
            key: "04".to_string() + &"ab".repeat(96),
        })
        .expect("verify");
        assert!(!wrong.valid);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keygen_rejects_unwritable_private_path() {
        let outcome = keygen_command(&KeygenCommand {
            out_private: std::path::PathBuf::from("/nonexistent-dir-xyz/key.pem"),
            out_public: std::path::PathBuf::from("/nonexistent-dir-xyz/pub.pem"),
        });
        assert!(outcome.is_err());
    }
}
