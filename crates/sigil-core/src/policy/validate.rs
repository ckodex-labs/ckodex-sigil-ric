//! Fail-closed policy validation: a control that is configured but cannot run
//! is a configuration error, never a silently disabled detector.

use super::DlpPolicy;
use crate::error::{Result, SigilError};
use serde::Deserialize;
use std::fs;

impl DlpPolicy {
    pub(super) fn validate_custom_patterns(&self) -> Result<()> {
        for (index, entry) in self.custom_patterns.iter().enumerate() {
            let invalid = |why: String| {
                SigilError::Schema(format!(
                    "scan.dlp.custom_patterns[{index}] ({entry}): {why}"
                ))
            };
            let patterns = if entry.ends_with(".toml") {
                read_custom_pattern_file(entry).map_err(|err| invalid(err.to_string()))?
            } else {
                vec![entry.clone()]
            };
            for pattern in &patterns {
                regex::Regex::new(pattern).map_err(|err| {
                    invalid(format!("pattern {pattern:?} does not compile: {err}"))
                })?;
            }
        }
        Ok(())
    }
}

/// Reads a custom DLP pattern file (`patterns = ["…"]`), surfacing I/O and
/// parse errors to the caller.
pub(crate) fn read_custom_pattern_file(path: &str) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct CustomPatternFile {
        patterns: Vec<String>,
    }
    let contents = fs::read_to_string(path)?;
    let file: CustomPatternFile = toml::from_str(&contents)?;
    Ok(file.patterns)
}

#[cfg(test)]
mod tests {
    use crate::error::SigilError;
    use crate::policy::Policy;
    use std::path::PathBuf;

    /// A per-test file under the system temp dir, removed on drop.
    struct TempFile(PathBuf);

    impl TempFile {
        fn new(tag: &str, contents: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("sigil-policy-{tag}-{}.toml", std::process::id()));
            std::fs::write(&path, contents).expect("write temp pattern file");
            Self(path)
        }

        fn path(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn policy_with(entry: &str) -> crate::error::Result<Policy> {
        Policy::from_toml_str(&format!("[scan.dlp]\ncustom_patterns = [{entry:?}]\n"))
    }

    fn assert_rejected(result: crate::error::Result<Policy>, needle: &str) {
        match result {
            Err(SigilError::Schema(message)) => {
                assert!(message.contains("custom_patterns[0]"), "{message}");
                assert!(message.contains(needle), "{message} lacks {needle:?}");
            }
            other => panic!("configured-but-unusable DLP must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn missing_pattern_file_is_a_config_error_not_a_disabled_detector() {
        let path = std::env::temp_dir().join("sigil-policy-definitely-absent.toml");
        let path = path.to_string_lossy().into_owned();
        assert_rejected(policy_with(&path), "sigil-policy-definitely-absent");
    }

    #[test]
    fn malformed_pattern_file_is_rejected() {
        let file = TempFile::new("malformed", "patterns = \"not an array\"");
        assert_rejected(policy_with(&file.path()), "malformed");
    }

    #[test]
    fn empty_pattern_file_is_rejected() {
        let file = TempFile::new("empty", "");
        assert_rejected(policy_with(&file.path()), "empty");
    }

    #[test]
    fn uncompilable_inline_pattern_is_rejected() {
        assert_rejected(policy_with("[unclosed"), "does not compile");
    }

    #[test]
    fn uncompilable_pattern_inside_file_is_rejected() {
        let file = TempFile::new("badregex", "patterns = [\"OK-[0-9]+\", \"(open\"]");
        assert_rejected(policy_with(&file.path()), "(open");
    }

    #[test]
    fn valid_file_and_inline_patterns_load() {
        let file = TempFile::new("valid", "patterns = [\"TOKEN-[A-Z]+\"]");
        let toml = format!(
            "[scan.dlp]\ncustom_patterns = [{:?}, \"SECRET-[0-9]+\"]\n",
            file.path()
        );
        let policy = Policy::from_toml_str(&toml).expect("valid custom patterns load");
        assert_eq!(policy.scan.dlp.custom_patterns.len(), 2);
    }

    #[test]
    fn policy_without_custom_patterns_is_unaffected() {
        assert!(Policy::from_toml_str("").is_ok());
    }
}
