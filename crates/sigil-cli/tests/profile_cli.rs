//! RIC-MM-001 WP4 at the CLI surface: `perceive --profile` binds the model's
//! view in the report, and a profile that cannot apply is a config error.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn specimen(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/multimodal")
        .join(name)
}

fn perceive(input: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil-cli"))
        .args(["perceive", "--format", "json", "--input"])
        .arg(specimen(input))
        .args(args)
        .output()
        .expect("spawn sigil-cli")
}

#[test]
fn the_profile_binds_the_consumed_view_but_an_unread_view_resolves_nothing() {
    let out = perceive(
        "attack_source.png",
        &[
            "--profile",
            "qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow",
            "--analyze",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let consumed = &json["result"]["report"]["consumed"];
    assert_eq!(consumed["parity"], "reference-matched");
    assert_eq!(consumed["placeholders"], 529);
    assert!(
        consumed["digest"]
            .as_str()
            .expect("digest")
            .starts_with("94c72b7a")
    );
    // No --ocr-binary: nothing read the view, so the cap stays (the
    // reference-matched, OCR-read case is CV-RIC-029 in sigil-perception).
    assert!(consumed["extractor"].is_null());
    assert_eq!(json["result"]["analysis"]["authority_ceiling"], "observe");
}

#[test]
fn without_a_profile_the_image_ceiling_is_observe() {
    let out = perceive("attack_source.png", &["--analyze"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(json["result"]["report"]["consumed"].is_null());
    assert_eq!(json["result"]["analysis"]["authority_ceiling"], "observe");
}

#[test]
fn an_unknown_profile_is_rejected_with_the_built_in_names() {
    let out = perceive("attack_source.png", &["--profile", "made-up/profile"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown --profile"), "{stderr}");
    assert!(stderr.contains("thumbnail/nearest-80"), "{stderr}");
}

#[test]
fn a_profile_of_the_wrong_modality_is_rejected() {
    let out = perceive("attack_source.png", &["--profile", "audio/16k-decimate"]);
    assert!(!out.status.success(), "an audio profile has no image view");
}

#[test]
fn a_resampler_needs_an_ffmpeg_resampled_profile() {
    let wav = specimen("attack_96k.wav");
    let out = Command::new(env!("CARGO_BIN_EXE_sigil-cli"))
        .args([
            "perceive",
            "--format",
            "json",
            "--modality",
            "audio",
            "--input",
        ])
        .arg(&wav)
        .args([
            "--profile",
            "audio/16k-decimate",
            "--resampler-binary",
            "/bin/echo",
        ])
        .output()
        .expect("spawn sigil-cli");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ffmpeg-resampled"));
}

#[test]
fn a_stated_delivery_is_recorded_in_the_consumed_block() {
    let out = perceive(
        "attack_source.png",
        &[
            "--profile",
            "qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow",
            "--delivery",
            "sigil-supplied",
            "--analyze",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(
        json["result"]["report"]["consumed"]["delivery"],
        "sigil-supplied"
    );
    // Evidence only: the unread view still caps the ceiling (decision O-5).
    assert_eq!(json["result"]["analysis"]["authority_ceiling"], "observe");
}

#[test]
fn delivery_needs_a_profile_and_a_known_label() {
    let bare = perceive("attack_source.png", &["--delivery", "sigil-supplied"]);
    assert!(
        !bare.status.success(),
        "no profile, no consumed block to state it in"
    );
    let unknown = perceive(
        "attack_source.png",
        &[
            "--profile",
            "thumbnail/nearest-80",
            "--delivery",
            "trust-me",
        ],
    );
    assert!(!unknown.status.success());
}
