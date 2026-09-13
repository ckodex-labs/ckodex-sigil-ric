use sha2::{Digest, Sha384};
use sigil_multimodal::ExtractorIdentity;
use std::io::Write;
use std::process::Command;

use super::hex_digest;
use super::PerceptionError;

/// Configuration for the external-command ASR transcript extractor.
#[derive(Clone, Debug)]
pub struct ExternalTranscript {
    /// Path to the ASR binary. Pinned by digest at construction.
    pub binary: std::path::PathBuf,
    /// Arguments passed to the binary. Artifact bytes are streamed on
    /// stdin, never placed in an argument.
    pub args: Vec<String>,
    /// Human-readable version label recorded in extractor identity.
    pub version: String,
    /// SHA-384 over the binary, computed at pin time.
    pub binary_digest: String,
}

impl ExternalTranscript {
    /// Pin an ASR binary: computes its SHA-384 digest for the evidence chain.
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

    pub(crate) fn identity(&self) -> ExtractorIdentity {
        ExtractorIdentity {
            name: "external-transcript".to_string(),
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
                "asr binary exited with {}",
                output.status
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| PerceptionError::ExtractorFailed("non-UTF-8 ASR output".to_string()))
    }
}
