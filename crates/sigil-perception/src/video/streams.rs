//! Stream extraction for `VideoAdapter` — pinned external demux pipes.
//! See `mod.rs` for the adapter contract and `StreamExtract` pinning.

use super::*;

impl VideoAdapter {
    /// Demux the container through the pinned pipes; each stream becomes
    /// channels via the owning modality adapter. Pipe failures degrade to
    /// a named property — never a panic, never a silent skip.
    pub(super) fn extract_streams(
        &self,
        artifact: &sigil_multimodal::ArtifactRef<'_>,
        extract: &StreamExtract,
        subtitle_tracks: usize,
        properties: &mut Vec<(String, String)>,
        channels: &mut Vec<ExtractedChannel>,
    ) {
        let id = self.adapter_id();
        if let Some(pipe) = &extract.audio {
            self.extract_audio(artifact, pipe, extract, id, properties, channels);
        }
        if let Some(frame_ocr) = &extract.frames {
            self.extract_frames(artifact, frame_ocr, id, properties, channels);
        }
        if let Some(pipe) = &extract.subtitles {
            match pipe.run(artifact.bytes) {
                Ok(bytes) if !bytes.is_empty() => {
                    match String::from_utf8(bytes) {
                        Ok(text) => {
                            channels.push(ExtractedChannel {
                                channel_kind: ChannelKind::Caption,
                                content: text,
                                extractor: ExtractorIdentity {
                                    name: format!("{id}/subtitles"),
                                    version: pipe.version.clone(),
                                    config_digest: pipe.binary_digest.clone(),
                                },
                                confidence: None,
                                truncated: false,
                            });
                            // mp4parse has no TrackType::Subtitle — mov_text
                            // lands in Unknown, so a caption the demuxer found
                            // but the inventory missed is a parser-vs-demux
                            // divergence worth surfacing.
                            if subtitle_tracks == 0 {
                                properties.push((
                                    format!("{id}.stream.subtitle_beyond_inventory"),
                                    "yes".to_string(),
                                ));
                            }
                        }
                        Err(_) => properties
                            .push((format!("{id}.stream.subtitles"), "non-utf8".to_string())),
                    }
                }
                Ok(_) => {
                    properties.push((format!("{id}.stream.subtitles"), "absent".to_string()));
                }
                Err(err) => {
                    properties.push((format!("{id}.stream.subtitles"), format!("failed: {err}")));
                }
            }
        }
    }

    fn extract_audio(
        &self,
        artifact: &sigil_multimodal::ArtifactRef<'_>,
        pipe: &crate::ExternalPipe,
        extract: &StreamExtract,
        id: &str,
        properties: &mut Vec<(String, String)>,
        channels: &mut Vec<ExtractedChannel>,
    ) {
        let wav = match pipe.run(artifact.bytes) {
            Ok(bytes) if !bytes.is_empty() => wav_patch_streamed_sizes(bytes),
            Ok(_) => {
                properties.push((format!("{id}.stream.audio"), "absent".to_string()));
                return;
            }
            Err(err) => {
                properties.push((format!("{id}.stream.audio"), format!("failed: {err}")));
                return;
            }
        };
        let adapter = crate::audio::AudioAdapter {
            transcript: extract.transcript.clone(),
        };
        let sub = sigil_multimodal::ArtifactRef {
            source_id: format!("{}:audio", artifact.source_id),
            bytes: &wav,
            media_type: Some("audio/wav".to_string()),
        };
        match adapter.perceive(&sub) {
            Ok(report) => {
                properties.push((
                    format!("{id}.stream.audio.channels"),
                    report.channels.len().to_string(),
                ));
                channels.extend(report.channels);
            }
            Err(err) => {
                properties.push((format!("{id}.stream.audio"), format!("decode: {err}")));
            }
        }
    }

    fn extract_frames(
        &self,
        artifact: &sigil_multimodal::ArtifactRef<'_>,
        frame_ocr: &FrameOcr,
        id: &str,
        properties: &mut Vec<(String, String)>,
        channels: &mut Vec<ExtractedChannel>,
    ) {
        let bytes = match frame_ocr.frames.run(artifact.bytes) {
            Ok(bytes) => bytes,
            Err(err) => {
                properties.push((format!("{id}.stream.frames"), format!("failed: {err}")));
                return;
            }
        };
        let frames = split_png_stream(&bytes);
        properties.push((format!("{id}.stream.frames"), frames.len().to_string()));
        if frames.len() > MAX_FRAMES {
            properties.push((format!("{id}.stream.frames_capped"), MAX_FRAMES.to_string()));
        }
        for (i, png) in frames.iter().take(MAX_FRAMES).enumerate() {
            if let Ok(text) = frame_ocr.ocr.extract(png) {
                if !text.trim().is_empty() {
                    channels.push(ExtractedChannel {
                        channel_kind: ChannelKind::OcrText,
                        content: text,
                        extractor: ExtractorIdentity {
                            name: format!("{id}/frame-ocr[{i}]"),
                            version: frame_ocr.ocr.version.clone(),
                            config_digest: frame_ocr.ocr.binary_digest.clone(),
                        },
                        confidence: None,
                        truncated: false,
                    });
                }
            }
        }
    }
}

/// ffmpeg's streamed WAV leaves the RIFF and `data` chunk sizes at
/// `0xFFFFFFFF` (unknown until close), which hound rejects. Walk the
/// chunk table and patch both to the real byte counts.
fn wav_patch_streamed_sizes(mut wav: Vec<u8>) -> Vec<u8> {
    if wav.len() < 12 || &wav[0..4] != b"RIFF" {
        return wav;
    }
    if wav[4..8] == [0xff; 4] {
        let size = (wav.len() - 8) as u32;
        wav[4..8].copy_from_slice(&size.to_le_bytes());
    }
    let mut pos = 12;
    while pos + 8 <= wav.len() {
        let tag = &wav[pos..pos + 4];
        let size = u32::from_le_bytes(wav[pos + 4..pos + 8].try_into().unwrap_or_default());
        if tag == b"data" && size == u32::MAX {
            let real = (wav.len() - pos - 8) as u32;
            wav[pos + 4..pos + 8].copy_from_slice(&real.to_le_bytes());
            break;
        }
        // Chunks are word-aligned; a streamed size means "to EOF".
        let advance = if size == u32::MAX {
            break;
        } else {
            8 + size as usize + (size as usize & 1)
        };
        pos += advance;
    }
    wav
}

/// Split a concatenated PNG stream (ffmpeg `image2pipe`) into frames.
/// Each PNG ends with a zero-length IEND chunk: `IEND` + fixed CRC.
pub(super) fn split_png_stream(bytes: &[u8]) -> Vec<&[u8]> {
    const IEND: [u8; 8] = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
    let mut frames = Vec::new();
    let mut start = 0;
    while let Some(pos) = bytes[start..].windows(8).position(|w| w == IEND) {
        let end = start + pos + 8;
        frames.push(&bytes[start..end]);
        start = end;
    }
    frames
}
