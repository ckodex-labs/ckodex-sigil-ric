//! Stream-extraction tests for `VideoAdapter`: fake pinned binaries
//! exercise the real spawn path — no real ffmpeg/tesseract needed. The
//! fake "ffmpeg" branches on the canonical arg sets; the fake "ocr"
//! emits fixed text for every frame it receives.

use sigil_multimodal::{ArtifactRef, ChannelKind};
use sigil_perception::video::{PerceptionAdapter, StreamExtract, VideoAdapter};

/// 16 kHz mono WAV, 100 silent samples (base64).
const WAV_B64: &str = "UklGRuwAAABXQVZFZm10IBAAAAABAAEAgD4AAAB9AAACABAAZGF0YcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
/// Two fake PNG frames, each `FAKEPNG` + IEND (base64).
const PNG_B64: &str = "RkFLRVBOR0lFTkSuQmCCRkFLRVBOR0lFTkSuQmCC";

fn temp_binary(name: &str, body: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("sigil-video-{name}-{}", std::process::id()));
    std::fs::write(&path, body).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
    }
    path
}

fn fixture() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tiny_av.mp4"
    ))
    .expect("fixture")
}

fn artifact(bytes: &[u8]) -> ArtifactRef<'_> {
    ArtifactRef {
        source_id: "vid".to_string(),
        bytes,
        media_type: Some("video/mp4".to_string()),
    }
}

#[test]
fn stream_extract_pipes_audio_and_frames() {
    let ffmpeg = temp_binary(
        "ffmpeg-ok",
        &format!(
            "#!/bin/sh\ncat >/dev/null\ncase \"$*\" in\n  *wav*) echo '{WAV_B64}' | base64 -d ;;\n  *image2pipe*) echo '{PNG_B64}' | base64 -d ;;\n  *srt*) echo '1\n00:00:00,000 --> 00:00:00,800\nsubtitle text\n' ;;\nesac\n"
        ),
    );
    let ocr = temp_binary("ocr-ok", "#!/bin/sh\ncat >/dev/null\necho 'frame text'\n");
    let extract =
        StreamExtract::pin(ffmpeg.clone(), Some((ocr.clone(), Vec::new())), None).expect("pin");
    let adapter = VideoAdapter {
        stream_extract: Some(extract),
    };
    let bytes = fixture();
    let report = adapter.perceive(&artifact(&bytes)).expect("perceive");

    let frames: Vec<_> = report
        .channels
        .iter()
        .filter(|c| c.extractor.name.contains("frame-ocr"))
        .collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].channel_kind, ChannelKind::OcrText);
    assert_eq!(frames[0].content.trim(), "frame text");
    assert!(report
        .channels
        .iter()
        .any(|c| c.extractor.name.contains("sigil-perception/audio")));
    let captions: Vec<_> = report
        .channels
        .iter()
        .filter(|c| c.channel_kind == ChannelKind::Caption)
        .collect();
    assert_eq!(captions.len(), 1);
    assert!(captions[0].content.contains("subtitle text"));
    assert!(captions[0].extractor.name.ends_with("/subtitles"));
    assert!(report
        .properties
        .iter()
        .any(|(k, v)| k.ends_with("stream.frames") && v == "2"));
    assert!(report
        .properties
        .iter()
        .any(|(k, _)| k.ends_with("stream.audio.channels")));
    let _ = std::fs::remove_file(ffmpeg);
    let _ = std::fs::remove_file(ocr);
}

#[test]
fn stream_extract_failures_degrade_to_properties() {
    let ffmpeg = temp_binary("ffmpeg-fail", "#!/bin/sh\nexit 1\n");
    let ocr = temp_binary("ocr-fail", "#!/bin/sh\nexit 1\n");
    let extract =
        StreamExtract::pin(ffmpeg.clone(), Some((ocr.clone(), Vec::new())), None).expect("pin");
    let adapter = VideoAdapter {
        stream_extract: Some(extract),
    };
    let bytes = fixture();
    let report = adapter.perceive(&artifact(&bytes)).expect("perceive");

    assert!(report
        .properties
        .iter()
        .any(|(k, v)| k.ends_with("stream.audio") && v.starts_with("failed:")));
    assert!(report
        .properties
        .iter()
        .any(|(k, v)| k.ends_with("stream.frames") && v.starts_with("failed:")));
    assert!(report
        .properties
        .iter()
        .any(|(k, v)| k.ends_with("stream.subtitles") && v.starts_with("failed:")));
    // Extraction failure never loses the container report itself.
    assert!(report
        .channels
        .iter()
        .any(|c| c.channel_kind == ChannelKind::Metadata));
    let _ = std::fs::remove_file(ffmpeg);
    let _ = std::fs::remove_file(ocr);
}
