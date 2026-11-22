//! The ffmpeg-resampled audio view (`whisper/16k-filtered`): SIGIL runs a
//! pinned ffmpeg with the reference command and binds what it produced.
//!
//! The reference is ffmpeg itself, run here with the exact command
//! `scripts/reference/whisper-stdin` uses. These tests need ffmpeg
//! installed and fail without it.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha384};
use sigil_core::Vocab;
use sigil_core::policy::Policy;
use sigil_multimodal::perception::channels_to_modal_inputs;
use sigil_multimodal::{
    ArtifactRef, AuthorityCeiling, ConsumedParity, Modality, MultimodalEngine, PerceptionAdapter,
    PerceptionError,
};
use sigil_perception::ExternalPipe;
use sigil_perception::audio::AudioAdapter;
use sigil_perception::model_view::resampler_args;
use sigil_perception::preprocess::builtin;

const FFMPEG: &[&str] = &[
    "/opt/homebrew/bin/ffmpeg",
    "/usr/local/bin/ffmpeg",
    "/usr/bin/ffmpeg",
];
const WHISPER: &str = "whisper/16k-filtered";

fn ffmpeg() -> PathBuf {
    FFMPEG
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .expect("the resampled view runs real ffmpeg: install ffmpeg")
}

fn specimen() -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/multimodal/attack_96k.wav"),
    )
    .expect("specimen")
}

/// ffmpeg run directly with the reference command, not through SIGIL.
fn reference_pcm(wav: &[u8]) -> Vec<u8> {
    let mut child = Command::new(ffmpeg())
        .args([
            "-loglevel",
            "error",
            "-i",
            "pipe:0",
            "-f",
            "s16le",
            "-ac",
            "1",
            "-ar",
            "16000",
            "pipe:1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn ffmpeg");
    let mut stdin = child.stdin.take().expect("stdin");
    let input = wav.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output().expect("ffmpeg output");
    writer.join().expect("writer").expect("write");
    assert!(out.status.success());
    out.stdout
}

fn adapter(resampler: Option<ExternalPipe>) -> AudioAdapter {
    AudioAdapter {
        transcript: None,
        profile: builtin(WHISPER),
        resampler,
    }
}

fn pinned() -> ExternalPipe {
    let args = resampler_args(&builtin(WHISPER).expect("profile")).expect("ffmpeg profile");
    ExternalPipe::pin(ffmpeg(), args, "ffmpeg".to_string()).expect("pin")
}

fn perceive(
    adapter: &AudioAdapter,
    wav: &[u8],
) -> Result<sigil_multimodal::PerceptionReport, PerceptionError> {
    adapter.perceive(&ArtifactRef {
        source_id: "attack_96k.wav".to_string(),
        bytes: wav,
        media_type: Some("audio/wav".to_string()),
    })
}

#[test]
fn the_view_is_what_ffmpeg_produces_with_the_reference_command() {
    let wav = specimen();
    let report = perceive(&adapter(Some(pinned())), &wav).expect("perceive");
    let consumed = report.consumed.expect("consumed");
    let expected: String = Sha384::digest(reference_pcm(&wav))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(consumed.digest, expected);
    // The specimen's recorded reference hash came from an unrecorded ffmpeg
    // version and is not reproduced, so parity is not claimed.
    assert_eq!(consumed.parity, ConsumedParity::Approximate);
}

#[test]
fn an_approximate_resampled_view_keeps_the_cap() {
    let report = perceive(&adapter(Some(pinned())), &specimen()).expect("perceive");
    let inputs = channels_to_modal_inputs(&report, Modality::Audio);
    let assessment = MultimodalEngine::new(Policy::default(), Vocab::tiktoken("cl100k_base"))
        .expect("engine")
        .analyze(&inputs)
        .expect("analysis");
    assert_eq!(assessment.authority_ceiling, AuthorityCeiling::Observe);
}

#[test]
fn without_a_pinned_resampler_the_profile_fails_closed() {
    let result = perceive(&adapter(None), &specimen());
    assert!(
        matches!(&result, Err(PerceptionError::ExtractorFailed(why)) if why.contains("needs a pinned resampler")),
        "{result:?}"
    );
}

#[test]
fn a_resampler_pinned_with_other_arguments_is_refused() {
    let other = ExternalPipe::pin(
        ffmpeg(),
        [
            "-loglevel",
            "error",
            "-i",
            "pipe:0",
            "-f",
            "s16le",
            "-ac",
            "1",
            "-ar",
            "8000",
            "pipe:1",
        ]
        .map(str::to_string)
        .to_vec(),
        "ffmpeg".to_string(),
    )
    .expect("pin");
    let result = perceive(&adapter(Some(other)), &specimen());
    assert!(
        matches!(&result, Err(PerceptionError::ExtractorFailed(why)) if why.contains("profile's arguments")),
        "{result:?}"
    );
}
