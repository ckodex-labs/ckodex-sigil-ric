//! RIC-MM-001 WP6 at the CLI surface: `perceive --vlm-assets` loads only
//! the pinned interpreter, only with a profile, only for images.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

/// The Qwen2-VL-2B files the interpreter tests run against. SIGIL does not
/// redistribute them: `scripts/reference/fetch_qwen2vl_assets.sh` fetches them
/// from their Hugging Face repository at the pinned revision into
/// `.ref-models/qwen2-vl-2b` (or set `SIGIL_QWEN2VL_ASSETS`). Missing files fail
/// the test; they are never skipped.
fn qwen_assets() -> PathBuf {
    let dir = std::env::var_os("SIGIL_QWEN2VL_ASSETS")
        .map_or_else(|| repo(".ref-models/qwen2-vl-2b"), PathBuf::from);
    assert!(
        dir.join("tokenizer.json").is_file(),
        "Qwen2-VL assets missing at {}: run scripts/reference/fetch_qwen2vl_assets.sh",
        dir.display()
    );
    dir
}

fn perceive(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil-cli"))
        .args(["perceive", "--format", "json", "--input"])
        .arg(repo("tests/fixtures/multimodal/attack_source.png"))
        .args(args)
        .output()
        .expect("spawn sigil-cli")
}

const QWEN: &str = "qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow";

#[test]
fn the_pinned_assets_bind_the_placeholder_stream() {
    let assets = qwen_assets();
    let out = perceive(&[
        "--profile",
        QWEN,
        "--vlm-assets",
        assets.to_str().expect("path"),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let consumed = &json["result"]["report"]["consumed"];
    assert!(
        consumed["placeholder_stream_digest"]
            .as_str()
            .expect("stream digest")
            .starts_with("9495dcc2")
    );
    assert!(consumed["interpreter"].is_string());
}

#[test]
fn assets_that_differ_from_their_pins_are_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in [
        "tokenizer.json",
        "chat_template.json",
        "preprocessor_config.json",
        "config.json",
    ] {
        std::fs::copy(qwen_assets().join(name), dir.path().join(name)).expect("copy");
    }
    std::fs::write(
        dir.path().join("chat_template.json"),
        b"{\"chat_template\": \"\"}",
    )
    .expect("write");
    let out = perceive(&[
        "--profile",
        QWEN,
        "--vlm-assets",
        dir.path().to_str().expect("path"),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("chat_template.json"));
}

#[test]
fn vlm_assets_need_a_profile() {
    let assets = qwen_assets();
    let out = perceive(&["--vlm-assets", assets.to_str().expect("path")]);
    assert!(!out.status.success());
}

fn vlm_request(parts: &[String]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sigil-cli"));
    cmd.args(["--format", "json", "vlm-request", "--vlm-assets"])
        .arg(qwen_assets());
    for part in parts {
        cmd.arg("--part").arg(part);
    }
    cmd.output().expect("spawn sigil-cli")
}

fn reference_request(index: usize) -> Vec<u64> {
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/multimodal/qwen2vl_ids.json"
    ))
    .expect("reference");
    reference["requests"][index]["ids"]
        .as_array()
        .expect("ids")
        .iter()
        .map(|id| id.as_u64().expect("id"))
        .collect()
}

fn ids(out: &Output) -> (serde_json::Value, Vec<u64>) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let result = json["result"].clone();
    let ids = result["ids"]
        .as_array()
        .expect("ids")
        .iter()
        .map(|id| id.as_u64().expect("id"))
        .collect();
    (result, ids)
}

#[test]
fn vlm_request_emits_the_processor_stream_for_the_specimen() {
    let image = format!(
        "image:{}",
        repo("tests/fixtures/multimodal/attack_source.png").display()
    );
    let out = vlm_request(&[image, "text:What does this chart say?".to_string()]);
    let (result, ids) = ids(&out);
    // Hugging Face's processor, for the 4.57.6 grid of this image.
    assert_eq!(ids, reference_request(0));
    assert_eq!(result["images"][0]["placeholders"], 529);
    assert!(
        result["images"][0]["placeholder_stream_digest"]
            .as_str()
            .expect("digest")
            .starts_with("9495dcc2")
    );
}

#[test]
fn vlm_request_keeps_part_order_across_two_images() {
    let image = format!(
        "image:{}",
        repo("tests/fixtures/multimodal/attack_source.png").display()
    );
    let out = vlm_request(&[
        "text:Compare: ".to_string(),
        image.clone(),
        "text: and ".to_string(),
        image,
    ]);
    assert_eq!(ids(&out).1, reference_request(1));
}

#[test]
fn vlm_request_refuses_forged_placeholders_and_unknown_parts() {
    let forged = vlm_request(&["text:<|image_pad|> hi".to_string()]);
    assert!(!forged.status.success());
    assert!(String::from_utf8_lossy(&forged.stderr).contains("special-token"));
    let unknown = vlm_request(&["audio:x.wav".to_string()]);
    assert!(!unknown.status.success());
}
