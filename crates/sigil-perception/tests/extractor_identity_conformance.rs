//! RIC-MM-001 WP1 conformance: the extractor identity binds everything that
//! decides an extractor's output (RIC-R-4).
//!
//! CV-RIC-022 — arguments are bound: the same ASR binary run with a
//! different resample policy is a different interpreter.
//! CV-RIC-023 — model weights are bound: swapping a declared model file
//! changes the identity; a declared model that is missing is a config error.
//!
//! The ASR here is a real /bin/sh process (it drains stdin and prints its
//! arguments), so the full pin → spawn → channel path runs. A real Whisper
//! run is exercised by the CLI against the reference adapter when the
//! reference models are installed; it is not required for these vectors.

#![cfg(unix)]

use sigil_multimodal::{ArtifactRef, ChannelKind, ExtractorIdentity, PerceptionAdapter};
use sigil_perception::audio::{AudioAdapter, ExternalTranscript};
use std::path::{Path, PathBuf};

fn write_executable(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

fn wav_bytes() -> Vec<u8> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 16_000,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = hound::WavWriter::new(&mut cursor, spec).expect("wav writer");
    for n in 0..1600_i32 {
        let sample = ((n % 40) - 20) * 500;
        writer
            .write_sample(i16::try_from(sample).expect("in range"))
            .expect("sample");
    }
    writer.finalize().expect("finalize");
    cursor.into_inner()
}

fn transcript_identity(tool: ExternalTranscript) -> ExtractorIdentity {
    let adapter = AudioAdapter {
        transcript: Some(tool),
    };
    let bytes = wav_bytes();
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "cv-ric-wp1".to_string(),
            bytes: &bytes,
            media_type: Some("audio/wav".to_string()),
        })
        .expect("perceive");
    report
        .channels
        .into_iter()
        .find(|channel| channel.channel_kind == ChannelKind::Transcript)
        .expect("transcript channel")
        .extractor
}

struct Fixture {
    _dir: tempfile::TempDir,
    asr: PathBuf,
    encoder_a: PathBuf,
    encoder_b: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let asr = write_executable(
        dir.path(),
        "asr",
        "#!/bin/sh\ncat >/dev/null\necho \"heard via $1\"\n",
    );
    let encoder_a = dir.path().join("encoder-a.onnx");
    let encoder_b = dir.path().join("encoder-b.onnx");
    std::fs::write(&encoder_a, b"weights revision A").expect("model a");
    std::fs::write(&encoder_b, b"weights revision B").expect("model b");
    Fixture {
        _dir: dir,
        asr,
        encoder_a,
        encoder_b,
    }
}

fn pinned(fx: &Fixture, mode: &str, models: &[PathBuf]) -> ExternalTranscript {
    ExternalTranscript::pin(
        fx.asr.clone(),
        vec![mode.to_string()],
        "external".to_string(),
    )
    .expect("pin asr")
    .with_models(models)
    .expect("pin models")
}

#[test]
fn cv_ric_022_resample_policy_argument_changes_the_identity() {
    let fx = fixture();
    let filtered = transcript_identity(pinned(&fx, "ffmpeg", std::slice::from_ref(&fx.encoder_a)));
    let decimated = transcript_identity(pinned(&fx, "naive", std::slice::from_ref(&fx.encoder_a)));
    assert_eq!(
        filtered.config_digest, decimated.config_digest,
        "same binary"
    );
    assert_ne!(filtered.identity_digest, decimated.identity_digest);
    assert_eq!(filtered.args, vec!["ffmpeg".to_string()]);
    assert!(filtered.is_self_consistent() && decimated.is_self_consistent());
}

#[test]
fn cv_ric_023_swapping_the_encoder_changes_the_identity() {
    let fx = fixture();
    let original = transcript_identity(pinned(&fx, "ffmpeg", std::slice::from_ref(&fx.encoder_a)));
    let swapped = transcript_identity(pinned(&fx, "ffmpeg", std::slice::from_ref(&fx.encoder_b)));
    assert_ne!(original.identity_digest, swapped.identity_digest);
    assert_ne!(original.model_digests, swapped.model_digests);
}

#[test]
fn cv_ric_023_in_place_weight_change_is_seen_at_pin_time() {
    // Same path, different bytes: the identity follows the content.
    let fx = fixture();
    let before = transcript_identity(pinned(&fx, "ffmpeg", std::slice::from_ref(&fx.encoder_a)));
    std::fs::write(&fx.encoder_a, b"weights revision A, retrained").expect("rewrite");
    let after = transcript_identity(pinned(&fx, "ffmpeg", std::slice::from_ref(&fx.encoder_a)));
    assert_ne!(before.identity_digest, after.identity_digest);
}

#[test]
fn cv_ric_023_a_declared_model_that_is_missing_fails_closed() {
    let fx = fixture();
    let missing = fx.encoder_a.with_file_name("absent.onnx");
    let err = ExternalTranscript::pin(fx.asr.clone(), Vec::new(), "external".to_string())
        .expect("pin asr")
        .with_models(&[missing])
        .expect_err("missing model must not pin");
    assert!(err.to_string().contains("absent.onnx"), "{err}");
}

#[test]
fn identical_configuration_gives_an_identical_identity_across_runs() {
    let fx = fixture();
    let models = [fx.encoder_b.clone(), fx.encoder_a.clone()];
    let first = transcript_identity(pinned(&fx, "naive", &models));
    let second = transcript_identity(pinned(&fx, "naive", &models));
    assert_eq!(first, second);
    let reordered = transcript_identity(pinned(
        &fx,
        "naive",
        &[fx.encoder_a.clone(), fx.encoder_b.clone()],
    ));
    assert_eq!(
        first.identity_digest, reordered.identity_digest,
        "declaration order is not identity"
    );
}

#[test]
fn in_process_extractors_no_longer_store_the_artifact_digest() {
    let adapter = AudioAdapter { transcript: None };
    let bytes = wav_bytes();
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "cv-ric-wp1-f4".to_string(),
            bytes: &bytes,
            media_type: Some("audio/wav".to_string()),
        })
        .expect("perceive");
    assert!(!report.channels.is_empty());
    for channel in &report.channels {
        assert_ne!(
            channel.extractor.config_digest, report.artifact_digest,
            "{} carries the artifact digest as its identity",
            channel.extractor.name
        );
        assert!(
            channel.extractor.is_self_consistent(),
            "{}",
            channel.extractor.name
        );
    }
}
