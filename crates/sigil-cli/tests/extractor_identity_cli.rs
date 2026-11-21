//! RIC-MM-001 WP1 end to end: `sigil-cli perceive` on the audio specimen
//! binds the ASR arguments and declared model files into the transcript
//! channel's extractor identity (CV-RIC-022, CV-RIC-023 at the CLI surface).
//!
//! The ASR is a /bin/sh stand-in that drains stdin and names its resample
//! mode; it exercises the same pin and spawn path as
//! `scripts/reference/whisper-stdin` without needing the Whisper models.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn specimen() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/multimodal/attack_96k.wav")
}

fn perceive(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil-cli"))
        .arg("perceive")
        .args(["--modality", "audio", "--format", "json", "--input"])
        .arg(specimen())
        .args(args)
        .output()
        .expect("spawn sigil-cli")
}

struct Fixture {
    dir: tempfile::TempDir,
    asr: String,
}

impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let asr = dir.path().join("asr");
        std::fs::write(&asr, "#!/bin/sh\ncat >/dev/null\necho \"heard via $1\"\n").expect("asr");
        std::fs::set_permissions(&asr, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        Self {
            asr: asr.to_string_lossy().into_owned(),
            dir,
        }
    }

    fn model(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, bytes).expect("model");
        path.to_string_lossy().into_owned()
    }

    fn identity(&self, mode: &str, model: &str) -> serde_json::Value {
        let out = perceive(&[
            "--transcript-binary",
            &self.asr,
            "--transcript-args",
            mode,
            "--transcript-model",
            model,
        ]);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
        json["result"]["report"]["channels"]
            .as_array()
            .expect("channels")
            .iter()
            .find(|channel| channel["channel_kind"] == "transcript")
            .expect("transcript channel")["extractor"]
            .clone()
    }
}

#[test]
fn ffmpeg_and_naive_runs_have_different_identities() {
    let fx = Fixture::new();
    let encoder = fx.model("tiny.en-encoder.onnx", b"encoder weights");
    let ffmpeg = fx.identity("ffmpeg", &encoder);
    let naive = fx.identity("naive", &encoder);
    assert_eq!(
        ffmpeg["config_digest"], naive["config_digest"],
        "same adapter binary"
    );
    assert_ne!(ffmpeg["identity_digest"], naive["identity_digest"]);
    assert_eq!(ffmpeg["identity_version"], 2);
}

#[test]
fn swapping_the_encoder_file_changes_the_identity() {
    let fx = Fixture::new();
    let a = fx.model("encoder-a.onnx", b"encoder weights A");
    let b = fx.model("encoder-b.onnx", b"encoder weights B");
    assert_ne!(
        fx.identity("ffmpeg", &a)["identity_digest"],
        fx.identity("ffmpeg", &b)["identity_digest"]
    );
}

#[test]
fn identical_runs_have_identical_identities() {
    let fx = Fixture::new();
    let encoder = fx.model("encoder.onnx", b"encoder weights");
    assert_eq!(
        fx.identity("naive", &encoder),
        fx.identity("naive", &encoder)
    );
}

#[test]
fn a_missing_declared_model_is_a_config_error() {
    let fx = Fixture::new();
    let missing = fx.dir.path().join("absent.onnx");
    let out = perceive(&[
        "--transcript-binary",
        &fx.asr,
        "--transcript-model",
        &missing.to_string_lossy(),
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("absent.onnx"), "stderr: {stderr}");
}

#[test]
fn a_model_without_its_tool_is_rejected() {
    let fx = Fixture::new();
    let encoder = fx.model("encoder.onnx", b"weights");
    let out = perceive(&["--transcript-model", &encoder]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("--transcript-model needs --transcript-binary")
    );
}
