//! RIC-MM-001 WP6: the exact Qwen2-VL request ID stream from pinned assets.
//!
//! CV-RIC-036: placeholder counts, image streams and whole-request ID
//! streams equal what Hugging Face's own code produced
//! (scripts/reference/qwen2vl_ids.py: tokenizers 0.22.2, transformers
//! 5.12.1) and, for the specimen, the transformers 4.57.6 run recorded in
//! specimens.json.
//! CV-RIC-037: the template and processor digests are part of the
//! interpreter: a changed file does not load, and the identity covers every
//! pinned digest.

use std::path::{Path, PathBuf};

use serde_json::Value;
use sigil_multimodal::{ArtifactRef, PerceptionAdapter, PerceptionError};
use sigil_perception::ImageAdapter;
use sigil_perception::preprocess::builtin;
use sigil_perception::vlm::{
    AssetPin, InterpreterError, Part, QWEN2_VL_2B, Qwen2VlInterpreter, identity_digest, ids_sha384,
};

/// The Qwen2-VL-2B files the interpreter tests run against. SIGIL does not
/// redistribute them: `scripts/reference/fetch_qwen2vl_assets.sh` fetches them
/// from their Hugging Face repository at the pinned revision into
/// `.ref-models/qwen2-vl-2b` (or set `SIGIL_QWEN2VL_ASSETS`). Missing files fail
/// the test; they are never skipped.
fn assets() -> PathBuf {
    let dir = std::env::var_os("SIGIL_QWEN2VL_ASSETS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.ref-models/qwen2-vl-2b"),
        PathBuf::from,
    );
    assert!(
        dir.join("tokenizer.json").is_file(),
        "Qwen2-VL assets missing at {}: run scripts/reference/fetch_qwen2vl_assets.sh",
        dir.display()
    );
    dir
}

fn interpreter() -> Qwen2VlInterpreter {
    Qwen2VlInterpreter::load(&assets(), &QWEN2_VL_2B).expect("pinned assets load")
}

fn reference() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/multimodal/qwen2vl_ids.json"
    ))
    .expect("reference")
}

fn ids(value: &Value) -> Vec<u32> {
    value
        .as_array()
        .expect("ids")
        .iter()
        .map(|id| u32::try_from(id.as_u64().expect("id")).expect("u32"))
        .collect()
}

fn grid(value: &Value) -> [u64; 3] {
    let g: Vec<u64> = value
        .as_array()
        .expect("grid")
        .iter()
        .map(|v| v.as_u64().expect("u64"))
        .collect();
    [g[0], g[1], g[2]]
}

#[test]
fn cv_ric_036_text_ids_equal_hugging_face_tokenizers() {
    let interpreter = interpreter();
    for case in reference()["texts"].as_array().expect("texts") {
        let text = case["text"].as_str().expect("text");
        assert_eq!(
            interpreter.tokenizer().encode(text).expect("encode"),
            ids(&case["ids"]),
            "{text:?}"
        );
    }
}

#[test]
fn cv_ric_036_whole_files_encode_as_hugging_face_does() {
    let interpreter = interpreter();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for doc in reference()["documents"].as_array().expect("documents") {
        let path = doc["path"].as_str().expect("path");
        // The model card is one of the fetched files, not part of the repository.
        let file = path
            .strip_prefix(".ref-models/qwen2-vl-2b/")
            .map_or_else(|| root.join(path), |name| assets().join(name));
        let raw = std::fs::read(file).expect("read document");
        assert_eq!(
            sha384_hex(&raw),
            doc["sha384"].as_str().expect("sha"),
            "{path} changed since the reference ran: rerun scripts/reference/qwen2vl_ids.py"
        );
        let text = std::str::from_utf8(&raw).expect("utf-8");
        let encoded = interpreter.tokenizer().encode(text).expect("encode");
        assert_eq!(
            encoded.len() as u64,
            doc["count"].as_u64().expect("count"),
            "{path}"
        );
        assert_eq!(
            ids_sha384(&encoded),
            doc["ids_sha384_u32le"].as_str().expect("sha"),
            "{path}"
        );
    }
}

fn sha384_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha384};
    Sha384::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn cv_ric_036_request_streams_equal_the_processor() {
    let interpreter = interpreter();
    let reference = reference();
    let grid_thw = grid(&reference["grid_thw"]);
    for request in reference["requests"].as_array().expect("requests") {
        let parts: Vec<Part<'_>> = request["parts"]
            .as_array()
            .expect("parts")
            .iter()
            .map(|part| match part["type"].as_str() {
                Some("image") => Part::Image { grid_thw },
                _ => Part::Text(part["text"].as_str().expect("text")),
            })
            .collect();
        let stream = interpreter.encode_request(&parts).expect("encode request");
        assert_eq!(stream.ids, ids(&request["ids"]), "{}", request["rendered"]);
        assert_eq!(
            stream.placeholders.len() as u64,
            request["images"].as_u64().expect("n")
        );
    }
}

#[test]
fn cv_ric_036_the_specimen_view_expands_to_the_processor_count_and_stream() {
    let interpreter = interpreter();
    let specimens: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/multimodal/specimens.json"
    ))
    .expect("specimens");
    let recorded = &specimens["image"]["qwen2vl"];
    // The 644² view SIGIL produces under the Qwen2-VL profile.
    let grid_thw = interpreter.grid_for_view(644, 644);
    assert_eq!(grid_thw, grid(&recorded["grid_thw"]));
    assert_eq!(interpreter.placeholders(grid_thw), Ok(529));
    assert_eq!(recorded["placeholders"], 529);
    let digest = interpreter
        .placeholder_stream_digest(grid_thw)
        .expect("digest");
    assert_eq!(
        digest,
        recorded["placeholder_stream_sha384"].as_str().expect("sha")
    );
    assert_eq!(
        digest,
        reference()["placeholder_stream_sha384_u32le"]
            .as_str()
            .expect("sha")
    );
}

#[test]
fn cv_ric_036_the_profile_matches_the_pinned_processor_config() {
    let interpreter = interpreter();
    let qwen = builtin("qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow").expect("profile");
    assert!(interpreter.matches_profile(&qwen));
    let nearest = builtin("thumbnail/nearest-80").expect("profile");
    assert!(!interpreter.matches_profile(&nearest));
}

#[test]
fn a_grid_that_is_not_whole_merges_is_refused() {
    assert_eq!(
        interpreter().placeholders([1, 45, 45]),
        Err(InterpreterError::Grid([1, 45, 45]))
    );
    assert_eq!(
        interpreter().placeholders([1, 0, 46]),
        Err(InterpreterError::Grid([1, 0, 46]))
    );
}

#[test]
fn user_text_cannot_forge_a_placeholder() {
    let interpreter = interpreter();
    // Hugging Face's default turns the literal into the real image-pad ID.
    assert_eq!(
        interpreter
            .tokenizer()
            .encode("<|image_pad|> hi")
            .expect("encode"),
        ids(&reference()["special_in_user_text"])
    );
    assert_eq!(
        interpreter.encode_request(&[Part::Text("<|image_pad|> hi")]),
        Err(InterpreterError::SpecialTokenInText(
            "<|image_pad|>".to_string()
        ))
    );
    // Split across two parts, the literal still forms once they concatenate.
    assert_eq!(
        interpreter.encode_request(&[Part::Text("<|vision"), Part::Text("_start|>")]),
        Err(InterpreterError::SpecialTokenInText(
            "<|vision_start|>".to_string()
        ))
    );
}

fn copy_assets(changed: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, _) in QWEN2_VL_2B.files {
        let mut bytes = std::fs::read(assets().join(name)).expect("read");
        if *name == changed {
            bytes.extend_from_slice(b" ");
        }
        std::fs::write(dir.path().join(name), bytes).expect("write");
    }
    dir
}

#[test]
fn cv_ric_037_a_changed_template_or_processor_config_does_not_load() {
    for file in [
        "chat_template.json",
        "preprocessor_config.json",
        "tokenizer.json",
        "config.json",
    ] {
        let dir = copy_assets(file);
        match Qwen2VlInterpreter::load(dir.path(), &QWEN2_VL_2B) {
            Err(InterpreterError::DigestMismatch { file: f, .. }) => assert_eq!(f, file),
            other => panic!("{file}: expected a digest mismatch, got {other:?}"),
        }
    }
    let unchanged = copy_assets("");
    assert!(Qwen2VlInterpreter::load(unchanged.path(), &QWEN2_VL_2B).is_ok());
}

#[test]
fn cv_ric_037_the_identity_covers_every_pinned_digest() {
    let interpreter = interpreter();
    assert_eq!(interpreter.identity(), identity_digest(&QWEN2_VL_2B));
    for index in 0..QWEN2_VL_2B.files.len() {
        let mut files = QWEN2_VL_2B.files.to_vec();
        files[index].1 = "00";
        let other = AssetPin {
            files: Box::leak(files.into_boxed_slice()),
            ..QWEN2_VL_2B
        };
        assert_ne!(
            identity_digest(&other),
            interpreter.identity(),
            "{}",
            files_name(index)
        );
    }
    let other_revision = AssetPin {
        revision: "0000",
        ..QWEN2_VL_2B
    };
    assert_ne!(identity_digest(&other_revision), interpreter.identity());
}

fn files_name(index: usize) -> &'static str {
    QWEN2_VL_2B.files[index].0
}

fn perceive_specimen(profile: &str) -> Result<sigil_multimodal::PerceptionReport, PerceptionError> {
    let bytes = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/multimodal/attack_source.png"),
    )
    .expect("specimen");
    ImageAdapter {
        ocr: None,
        profile: Some(builtin(profile).expect("profile")),
        interpreter: Some(std::sync::Arc::new(interpreter())),
    }
    .perceive(&ArtifactRef {
        source_id: "attack_source.png".to_string(),
        media_type: Some("image/png".to_string()),
        bytes: &bytes,
    })
}

#[test]
fn cv_ric_036_the_model_view_binds_the_placeholder_stream_and_interpreter() {
    let report = perceive_specimen("qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow")
        .expect("perceive");
    let consumed = report.consumed.expect("consumed");
    assert_eq!(consumed.placeholders, Some(529));
    assert_eq!(
        consumed.placeholder_stream_digest.as_deref(),
        reference()["placeholder_stream_sha384_u32le"].as_str()
    );
    assert_eq!(
        consumed.interpreter.as_deref(),
        Some(identity_digest(&QWEN2_VL_2B).as_str())
    );
}

#[test]
fn an_interpreter_that_does_not_patch_like_the_profile_fails_closed() {
    let result = perceive_specimen("thumbnail/nearest-80");
    assert!(
        matches!(&result, Err(PerceptionError::ExtractorFailed(why)) if why.contains("does not match profile")),
        "{result:?}"
    );
}
