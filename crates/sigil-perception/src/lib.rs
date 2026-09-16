//! SIGIL perception adapters (Phase 1 — image, Phase 2 — audio).
//!
//! Adapters decompose artifacts into governed text channels; the kernel
//! judges. This crate implements the `PerceptionAdapter` port defined in
//! `sigil-multimodal::perception` (docs/PERCEPTION-ADAPTERS.md, Option B).

pub mod audio;
pub mod code;
pub mod document;
pub mod spectral;
pub mod video;

use image::ImageReader;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use sigil_multimodal::{ChannelKind, ExtractedChannel, ExtractorIdentity};

pub use sigil_multimodal::{PerceptionAdapter, PerceptionError, PerceptionReport};
use std::io::{Cursor, Write};
use std::process::Command;

/// Image adapter: decodes the artifact, inventories metadata, and optionally
/// extracts an OCR text channel through a pinned external OCR binary.
///
/// The OCR binary is pinned at construction (its SHA-384 digest is recorded
/// in every channel's extractor identity), receives artifact bytes on stdin,
/// and returns text on stdout. Artifact bytes never appear in an argument —
/// the argument-injection surface is closed by construction.
pub struct ImageAdapter {
    pub ocr: Option<ExternalOcr>,
}

/// Configuration for the external-command OCR extractor.
#[derive(Clone, Debug)]
pub struct ExternalOcr {
    /// Path to the OCR binary. Pinned by digest at construction.
    pub binary: std::path::PathBuf,
    /// Arguments passed to the binary. Artifact bytes are streamed on
    /// stdin, never placed in an argument.
    pub args: Vec<String>,
    /// Human-readable version label recorded in extractor identity.
    pub version: String,
    /// SHA-384 over the binary, computed at pin time.
    pub binary_digest: String,
}

impl ExternalOcr {
    /// Pin an OCR binary: computes its SHA-384 digest for the evidence chain.
    pub fn pin(
        binary: std::path::PathBuf,
        args: Vec<String>,
        version: String,
    ) -> std::io::Result<Self> {
        let bytes = std::fs::read(&binary)?;
        let mut hasher = Sha384::new();
        hasher.update(&bytes);
        let binary_digest = hex_digest(&hasher.finalize());
        Ok(Self {
            binary,
            args,
            version,
            binary_digest,
        })
    }

    fn identity(&self) -> ExtractorIdentity {
        ExtractorIdentity {
            name: "external-ocr".to_string(),
            version: self.version.clone(),
            config_digest: self.binary_digest.clone(),
        }
    }

    pub(crate) fn extract(&self, bytes: &[u8]) -> Result<String, PerceptionError> {
        let mut child = Command::new(&self.binary)
            .args(&self.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|err| PerceptionError::ExtractorFailed(format!("spawn: {err}")))?;
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(bytes)
            .map_err(|err| PerceptionError::ExtractorFailed(format!("stdin: {err}")))?;
        let output = child
            .wait_with_output()
            .map_err(|err| PerceptionError::ExtractorFailed(format!("wait: {err}")))?;
        if !output.status.success() {
            return Err(PerceptionError::ExtractorFailed(format!(
                "ocr binary exited with {}",
                output.status
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| PerceptionError::ExtractorFailed("non-UTF-8 OCR output".to_string()))
    }
}

/// A pinned external binary with the same contract as [`ExternalOcr`] but
/// returning raw bytes — for renderers (e.g. `pdftoppm`) whose stdout is an
/// image, not text. Artifact bytes stream on stdin, never in an argument.
#[derive(Clone, Debug)]
pub struct ExternalPipe {
    pub binary: std::path::PathBuf,
    pub args: Vec<String>,
    pub version: String,
    pub binary_digest: String,
}

impl ExternalPipe {
    /// Pin a pipe binary: computes its SHA-384 digest for the evidence chain.
    pub fn pin(
        binary: std::path::PathBuf,
        args: Vec<String>,
        version: String,
    ) -> std::io::Result<Self> {
        let bytes = std::fs::read(&binary)?;
        let mut hasher = Sha384::new();
        hasher.update(&bytes);
        let binary_digest = hex_digest(&hasher.finalize());
        Ok(Self {
            binary,
            args,
            version,
            binary_digest,
        })
    }

    pub fn run(&self, bytes: &[u8]) -> Result<Vec<u8>, PerceptionError> {
        self.run_with(bytes, &[])
    }

    /// Like `run`, but appends per-invocation args after the pinned set
    /// (e.g. `-f N -l N` to select one page per render). The pinned digest
    /// covers the base args; callers record appended args as evidence.
    pub fn run_with(
        &self,
        bytes: &[u8],
        extra_args: &[String],
    ) -> Result<Vec<u8>, PerceptionError> {
        let mut child = Command::new(&self.binary)
            .args(&self.args)
            .args(extra_args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|err| PerceptionError::ExtractorFailed(format!("spawn: {err}")))?;
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(bytes)
            .map_err(|err| PerceptionError::ExtractorFailed(format!("stdin: {err}")))?;
        let output = child
            .wait_with_output()
            .map_err(|err| PerceptionError::ExtractorFailed(format!("wait: {err}")))?;
        if !output.status.success() {
            return Err(PerceptionError::ExtractorFailed(format!(
                "pipe binary exited with {}",
                output.status
            )));
        }
        Ok(output.stdout)
    }
}

impl PerceptionAdapter for ImageAdapter {
    fn modality(&self) -> sigil_multimodal::Modality {
        sigil_multimodal::Modality::Vision
    }

    fn adapter_id(&self) -> &str {
        "sigil-perception/image/0.1"
    }

    fn perceive(
        &self,
        artifact: &sigil_multimodal::ArtifactRef<'_>,
    ) -> Result<PerceptionReport, PerceptionError> {
        let mut hasher = Sha384::new();
        hasher.update(artifact.bytes);
        let artifact_digest = hex_digest(&hasher.finalize());

        let decoded = ImageReader::new(Cursor::new(artifact.bytes))
            .with_guessed_format()
            .map_err(|_| PerceptionError::DecodeFailed)?
            .decode()
            .map_err(|_| PerceptionError::DecodeFailed)?;
        let (width, height) = (decoded.width(), decoded.height());

        let mut properties = vec![
            (
                format!("{}.color", self.adapter_id()),
                format!("{:?}", decoded.color()),
            ),
            (format!("{}.width", self.adapter_id()), width.to_string()),
            (format!("{}.height", self.adapter_id()), height.to_string()),
        ];

        let mut channels = Vec::new();

        // Metadata channel: EXIF inventory rendered as `tag = value` lines.
        // Values are scanned by the kernel like any other text channel.
        if let Some((content, field_count, truncated)) = inventory_exif(artifact.bytes) {
            properties.push((
                format!("{}.exif.fields", self.adapter_id()),
                field_count.to_string(),
            ));
            channels.push(ExtractedChannel {
                channel_kind: ChannelKind::Metadata,
                content,
                extractor: ExtractorIdentity {
                    name: format!("{}/exif", self.adapter_id()),
                    version: "kamadak-exif/0.19".to_string(),
                    config_digest: artifact_digest.clone(),
                },
                confidence: None,
                truncated,
            });
        }

        // OCR channel via the pinned external binary, when configured.
        if let Some(ocr) = &self.ocr {
            let text = ocr.extract(artifact.bytes)?;
            channels.push(ExtractedChannel {
                channel_kind: ChannelKind::OcrText,
                content: text,
                extractor: ocr.identity(),
                confidence: None,
                // The external-OCR contract requires the binary to emit its
                // complete output; a non-zero exit is an error, not a
                // truncation. The adapter cannot detect silent truncation
                // inside the binary — documented limitation.
                truncated: false,
            });
        }

        Ok(PerceptionReport {
            source_id: artifact.source_id.clone(),
            artifact_digest,
            media_type: artifact
                .media_type
                .clone()
                .unwrap_or_else(|| "image/*".to_string()),
            properties,
            channels,
        })
    }
}

/// EXIF inventory: `tag = value` lines, capped at 256 fields. The cap is
/// declared via the `truncated` flag — silent truncation is forbidden.
fn inventory_exif(bytes: &[u8]) -> Option<(String, usize, bool)> {
    let reader = exif::Reader::new();
    let mut cursor = Cursor::new(bytes);
    let exif = reader.read_from_container(&mut cursor).ok()?;

    const MAX_FIELDS: usize = 256;
    let mut content = String::new();
    let mut count = 0usize;
    let mut truncated = false;
    for field in exif.fields() {
        if count >= MAX_FIELDS {
            truncated = true;
            break;
        }
        content.push_str(&format!(
            "{} = {}\n",
            field.tag,
            field.display_value().with_unit(&exif)
        ));
        count += 1;
    }
    Some((content, count, truncated))
}

/// Adapter-level result envelope for CLI consumption.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PerceptionOutcome {
    pub adapter_id: String,
    pub report: PerceptionReport,
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_multimodal::perception::channels_to_modal_inputs;
    use sigil_multimodal::ArtifactRef;

    fn encode_png(width: u32, height: u32, rgba: [u8; 4]) -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(width, height, image::Rgba(rgba));
        let mut out = Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png)
            .expect("png");
        out.into_inner()
    }

    #[test]
    fn image_adapter_decodes_and_reports_structure() {
        let bytes = encode_png(4, 3, [10, 20, 30, 255]);
        let adapter = ImageAdapter { ocr: None };
        let report = adapter
            .perceive(&ArtifactRef {
                source_id: "img-1".to_string(),
                bytes: &bytes,
                media_type: Some("image/png".to_string()),
            })
            .expect("perceive");

        assert_eq!(report.source_id, "img-1");
        assert_eq!(report.artifact_digest.len(), 96, "SHA-384 hex");
        assert!(report
            .properties
            .iter()
            .any(|(k, v)| k.ends_with(".width") && v == "4"));
        assert!(report
            .properties
            .iter()
            .any(|(k, v)| k.ends_with(".height") && v == "3"));
        // No OCR configured: only the metadata channel, no fabricated content.
        assert!(report
            .channels
            .iter()
            .all(|channel| channel.channel_kind == ChannelKind::Metadata));
    }

    #[test]
    fn undecodable_artifact_fails_closed() {
        let adapter = ImageAdapter { ocr: None };
        let err = adapter
            .perceive(&ArtifactRef {
                source_id: "bad-1".to_string(),
                bytes: b"not an image",
                media_type: Some("image/png".to_string()),
            })
            .expect_err("decode must fail");
        assert_eq!(err, PerceptionError::DecodeFailed);
    }

    #[test]
    fn ocr_channel_flows_through_kernel_mapping_as_derived() {
        // Fake OCR binary: a shell script that echoes its stdin. Proves the
        // external-command path end-to-end without a real OCR engine.
        #[cfg(unix)]
        {
            let dir = std::env::temp_dir().join("sigil-perception-ocr-test");
            std::fs::create_dir_all(&dir).expect("mkdir");
            let fake_ocr = dir.join("fake-ocr.sh");
            // Consumes stdin (no EPIPE) and emits deterministic text — a stand-in
            // for a real OCR engine's output contract.
            std::fs::write(
                &fake_ocr,
                "#!/bin/sh\ncat > /dev/null\necho extracted-text\n",
            )
            .expect("write");
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&fake_ocr, std::fs::Permissions::from_mode(0o755))
                    .expect("chmod");
            }

            let ocr = ExternalOcr::pin(fake_ocr, vec![], "fake-1.0".to_string()).expect("pin");
            let adapter = ImageAdapter { ocr: Some(ocr) };

            let png = encode_png(1, 1, [255, 0, 0, 255]);
            let report = adapter
                .perceive(&ArtifactRef {
                    source_id: "img-9".to_string(),
                    bytes: &png,
                    media_type: Some("image/png".to_string()),
                })
                .expect("perceive");

            let ocr_channel = report
                .channels
                .iter()
                .find(|channel| channel.channel_kind == ChannelKind::OcrText)
                .expect("ocr channel present");
            assert_eq!(ocr_channel.extractor.name, "external-ocr");
            assert_eq!(ocr_channel.extractor.version, "fake-1.0");
            assert!(!ocr_channel.extractor.config_digest.is_empty());

            // Kernel mapping: derived provenance, lineage to the artifact.
            let inputs = channels_to_modal_inputs(&report, adapter.modality());
            let mapped = inputs
                .iter()
                .find(|input| input.source_id.as_deref() == Some("img-9:ocr_text"))
                .expect("mapped ocr channel");
            assert_ne!(
                mapped.provenance,
                sigil_core::types::Provenance::User,
                "OCR channel must be derived-untrusted"
            );
            assert_ne!(
                mapped.provenance,
                sigil_core::types::Provenance::System,
                "OCR channel must never claim system authority"
            );
            assert_eq!(mapped.derived_from.as_deref(), Some("img-9"));
        }
    }
}
