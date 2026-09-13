use super::*;
use sigil_multimodal::perception::channels_to_modal_inputs;
use sigil_multimodal::ArtifactRef;

/// Encode a minimal valid WAV file with the given sample rate, channels,
/// and sample count. Each sample is a zero-amplitude 16-bit value.
fn encode_wav(sample_rate: u32, channels: u16, samples: u16) -> Vec<u8> {
    let spec = hound::WavSpec {
        channels,
        sample_rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut out = Cursor::new(Vec::new());
    let mut writer = hound::WavWriter::new(&mut out, spec).expect("wav writer");
    for _ in 0..samples {
        for _ in 0..channels {
            writer.write_sample(0i16).expect("write sample");
        }
    }
    writer.finalize().expect("finalize");
    out.into_inner()
}

/// Encode a float WAV with a sine wave at the given frequency.
fn encode_float_wav(sample_rate: u32, freq_hz: f32, duration_secs: f32) -> Vec<u8> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate,
        bits_per_sample: 32,
        sample_format: hound::SampleFormat::Float,
    };
    let n = (sample_rate as f32 * duration_secs) as usize;
    let mut out = Cursor::new(Vec::new());
    let mut writer = hound::WavWriter::new(&mut out, spec).expect("wav writer");
    for i in 0..n {
        let t = i as f32 / sample_rate as f32;
        writer
            .write_sample((2.0 * std::f32::consts::PI * freq_hz * t).sin())
            .expect("write sample");
    }
    writer.finalize().expect("finalize");
    out.into_inner()
}

#[test]
fn float_wav_produces_spectral_channel() {
    let bytes = encode_float_wav(16000, 440.0, 0.1);
    let adapter = AudioAdapter { transcript: None };
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "float-audio".to_string(),
            bytes: &bytes,
            media_type: Some("audio/wav".to_string()),
        })
        .expect("perceive");
    let spectral = report
        .channels
        .iter()
        .find(|c| c.extractor.name.ends_with("/spectral"))
        .expect("spectral channel must exist for float WAV");
    assert!(!spectral.truncated, "float WAV should not be truncated");
    let json: serde_json::Value = serde_json::from_str(&spectral.content).expect("spectral JSON");
    assert!(
        json["windows_analyzed"].as_u64().unwrap_or(0) > 0,
        "float WAV should produce spectral windows"
    );
}

#[test]
fn audio_adapter_decodes_wav_and_reports_structure() {
    let bytes = encode_wav(16000, 1, 16000); // 1 second of silence
    let adapter = AudioAdapter { transcript: None };
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "audio-1".to_string(),
            bytes: &bytes,
            media_type: Some("audio/wav".to_string()),
        })
        .expect("perceive");

    assert_eq!(report.source_id, "audio-1");
    assert_eq!(report.artifact_digest.len(), 96, "SHA-384 hex");
    assert!(report
        .properties
        .iter()
        .any(|(k, v)| k.ends_with(".sample_rate") && v == "16000"));
    assert!(report
        .properties
        .iter()
        .any(|(k, v)| k.ends_with(".channels") && v == "1"));
    assert!(report
        .properties
        .iter()
        .any(|(k, v)| k.ends_with(".bits_per_sample") && v == "16"));
    // Metadata channel present, no transcript configured.
    assert!(report
        .channels
        .iter()
        .all(|channel| channel.channel_kind == ChannelKind::Metadata));
}

#[test]
fn audio_adapter_duration_estimate_is_correct() {
    // 16000 Hz, mono, 16000 samples = 1.0 second.
    let bytes = encode_wav(16000, 1, 16000);
    let adapter = AudioAdapter { transcript: None };
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "dur-1".to_string(),
            bytes: &bytes,
            media_type: Some("audio/wav".to_string()),
        })
        .expect("perceive");
    let duration_prop = report
        .properties
        .iter()
        .find(|(k, _)| k.ends_with(".duration_secs"))
        .expect("duration property");
    let duration: f64 = duration_prop.1.parse().expect("parse duration");
    assert!(
        (duration - 1.0).abs() < 0.01,
        "duration should be ~1.0s, got {duration}"
    );
}

#[test]
fn audio_adapter_stereo_duration_halved_per_channel() {
    // 16000 Hz, stereo, 16000 frames (32000 total samples = 16000 * 2 channels).
    // Duration = 16000 frames / 16000 Hz = 1.0 second.
    let bytes = encode_wav(16000, 2, 16000);
    let adapter = AudioAdapter { transcript: None };
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "stereo-1".to_string(),
            bytes: &bytes,
            media_type: Some("audio/wav".to_string()),
        })
        .expect("perceive");
    let duration_prop = report
        .properties
        .iter()
        .find(|(k, _)| k.ends_with(".duration_secs"))
        .expect("duration property");
    let duration: f64 = duration_prop.1.parse().expect("parse duration");
    assert!(
        (duration - 1.0).abs() < 0.01,
        "stereo duration should be ~1.0s, got {duration}"
    );
}

/// WAV where the data-chunk header declares a valid (even) size but the
/// file is truncated after the header — hound accepts the header, then
/// hits EOF during sample reads, yielding Err for the missing samples.
fn encode_wav_truncated_data(sample_rate: u32, channels: u16, actual_data_bytes: usize) -> Vec<u8> {
    let block_align = channels * 2;
    let byte_rate = sample_rate * u32::from(block_align);
    let fmt_size: u32 = 16;
    let declared_data = (actual_data_bytes + 2) as u32; // claim 2 more bytes than present
    let riff_size = 4 + (8 + fmt_size) + (8 + declared_data);
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&riff_size.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&fmt_size.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes()); // PCM
    buf.extend_from_slice(&channels.to_le_bytes());
    buf.extend_from_slice(&sample_rate.to_le_bytes());
    buf.extend_from_slice(&byte_rate.to_le_bytes());
    buf.extend_from_slice(&block_align.to_le_bytes());
    buf.extend_from_slice(&16u16.to_le_bytes()); // bits
    buf.extend_from_slice(b"data");
    buf.extend_from_slice(&declared_data.to_le_bytes());
    buf.resize(buf.len() + actual_data_bytes, 0);
    buf
}

#[test]
fn truncated_wav_marks_spectral_channel_truncated() {
    // Header declares 32002 bytes but file only has 32000 → 1 missing i16.
    let bytes = encode_wav_truncated_data(16000, 1, 32000);
    let adapter = AudioAdapter { transcript: None };
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "trunc-audio".to_string(),
            bytes: &bytes,
            media_type: Some("audio/wav".to_string()),
        })
        .expect("perceive");

    assert!(
        report
            .properties
            .iter()
            .any(|(k, _)| k.ends_with(".dropped_samples")),
        "dropped_samples property should be present"
    );
    let spectral = report
        .channels
        .iter()
        .find(|c| c.extractor.name.ends_with("/spectral"));
    if let Some(ch) = spectral {
        assert!(ch.truncated, "spectral channel must be truncated");
    }
}

#[test]
fn undecodable_audio_fails_closed() {
    let adapter = AudioAdapter { transcript: None };
    let err = adapter
        .perceive(&ArtifactRef {
            source_id: "bad-audio".to_string(),
            bytes: b"not a wav file",
            media_type: Some("audio/wav".to_string()),
        })
        .expect_err("decode must fail");
    assert_eq!(err, PerceptionError::DecodeFailed);
}

#[test]
fn transcript_channel_flows_through_kernel_mapping_as_derived() {
    // Fake ASR binary: a shell script that echoes deterministic text.
    #[cfg(unix)]
    {
        let dir = std::env::temp_dir().join("sigil-perception-asr-test");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let fake_asr = dir.join("fake-asr.sh");
        // Consumes stdin (no EPIPE) and emits deterministic text.
        std::fs::write(&fake_asr, "#!/bin/sh\ncat > /dev/null\necho hello-world\n").expect("write");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_asr, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }

        let transcript =
            ExternalTranscript::pin(fake_asr, vec![], "fake-1.0".to_string()).expect("pin");
        let adapter = AudioAdapter {
            transcript: Some(transcript),
        };

        let wav = encode_wav(8000, 1, 100);
        let report = adapter
            .perceive(&ArtifactRef {
                source_id: "audio-9".to_string(),
                bytes: &wav,
                media_type: Some("audio/wav".to_string()),
            })
            .expect("perceive");

        let transcript_channel = report
            .channels
            .iter()
            .find(|channel| channel.channel_kind == ChannelKind::Transcript)
            .expect("transcript channel present");
        assert_eq!(transcript_channel.extractor.name, "external-transcript");
        assert_eq!(transcript_channel.extractor.version, "fake-1.0");
        assert!(!transcript_channel.extractor.config_digest.is_empty());

        // Kernel mapping: derived provenance, lineage to the artifact.
        let inputs = channels_to_modal_inputs(&report, adapter.modality());
        let mapped = inputs
            .iter()
            .find(|input| input.source_id.as_deref() == Some("audio-9:transcript"))
            .expect("mapped transcript channel");
        assert_ne!(
            mapped.provenance,
            sigil_core::types::Provenance::User,
            "transcript channel must be derived-untrusted"
        );
        assert_ne!(
            mapped.provenance,
            sigil_core::types::Provenance::System,
            "transcript channel must never claim system authority"
        );
        assert_eq!(mapped.derived_from.as_deref(), Some("audio-9"));
    }
}

mod transcript_tests {
    use super::super::transcript::ExternalTranscript;
    use sigil_multimodal::PerceptionError;
    use std::io::Write;

    fn temp_binary(name: &str, body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("sigil-test-{name}-{}", std::process::id()));
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(body.as_bytes()).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).expect("meta").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod");
        }
        path
    }

    #[test]
    fn pin_computes_sha384_digest() {
        let path = temp_binary("pin", "fake-binary");
        let pinned =
            ExternalTranscript::pin(path.clone(), vec!["-x".into()], "v1".into()).expect("pin");
        assert_eq!(pinned.binary_digest.len(), 96); // sha384 hex
        assert_eq!(pinned.version, "v1");
        let id = pinned.identity();
        assert_eq!(id.name, "external-transcript");
        assert_eq!(id.config_digest, pinned.binary_digest);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn pin_missing_binary_errors() {
        let err = ExternalTranscript::pin(
            std::path::PathBuf::from("/nonexistent/sigil-no-such-binary"),
            vec![],
            "v".into(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn extract_streams_bytes_to_stdin() {
        // `cat` echoes stdin to stdout — exercises the real spawn path.
        let path = temp_binary("cat", "#!/bin/sh\nexec cat\n");
        let t = ExternalTranscript::pin(path.clone(), vec![], "cat".into()).expect("pin");
        let out = t.extract(b"transcribe me").expect("extract");
        assert_eq!(out, "transcribe me");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn extract_fails_on_nonzero_exit() {
        let path = temp_binary("fail", "#!/bin/sh\nexit 1\n");
        let t = ExternalTranscript::pin(path.clone(), vec![], "fail".into()).expect("pin");
        let err = t.extract(b"x").expect_err("must fail");
        assert!(matches!(err, PerceptionError::ExtractorFailed(_)));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn extract_fails_on_non_utf8_output() {
        let path = temp_binary("bin", "#!/bin/sh\nprintf '\\377\\376'\n");
        let t = ExternalTranscript::pin(path.clone(), vec![], "bin".into()).expect("pin");
        let err = t.extract(b"x").expect_err("non-utf8 must fail");
        assert!(matches!(err, PerceptionError::ExtractorFailed(_)));
        let _ = std::fs::remove_file(path);
    }
}
