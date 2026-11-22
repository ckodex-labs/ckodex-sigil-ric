//! RIC-MM-001 WP6 at the CLI surface: `perceive --vlm-assets` loads only
//! the pinned interpreter, only with a profile, only for images.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
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
    let assets = repo("assets/qwen2-vl-2b");
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
        std::fs::copy(repo("assets/qwen2-vl-2b").join(name), dir.path().join(name)).expect("copy");
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
    let assets = repo("assets/qwen2-vl-2b");
    let out = perceive(&["--vlm-assets", assets.to_str().expect("path")]);
    assert!(!out.status.success());
}
