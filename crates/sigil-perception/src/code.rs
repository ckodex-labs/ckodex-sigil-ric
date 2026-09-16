//! Code adapter: splits a source artifact into its hidden-text surfaces.
//!
//! Code is three representations in one stream: executable statements,
//! comments/docstrings (read by humans and models, never executed), and
//! string literals (embedded carriers that can hold text the code never
//! displays). An instruction in a comment or a string reaches the model
//! but not the compiler — so each surface becomes its own channel and
//! the kernel judges each. The lexer is a small state machine over the
//! common comment/string forms (`//`, `/* */`, `#`, `"""`/`'''`,
//! `"`/`'`/backtick); it is deliberately not a parser.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use sigil_multimodal::{ChannelKind, ExtractedChannel, ExtractorIdentity};

pub use sigil_multimodal::{PerceptionAdapter, PerceptionError, PerceptionReport};

/// Code adapter: separates comments/docstrings and string literals into
/// derived channels for kernel rescan.
#[derive(Default)]
pub struct CodeAdapter;

/// Lexer state: which surface the current byte belongs to.
#[derive(Clone, Copy, PartialEq)]
enum State {
    Code,
    LineComment,
    BlockComment,
    String(char),
    Docstring(char),
}

/// Surfaces recovered from source text.
struct Surfaces {
    comments: String,
    strings: String,
    code_lines: usize,
    comment_lines: usize,
    string_literals: usize,
}

/// `#` or `--` opens a comment only at line start or after whitespace —
/// mid-token `#` (CSS colours, C `#include`) and `i--` decrements are code.
fn line_comment_opens(chars: &[char], i: usize) -> bool {
    i == 0 || chars[i - 1] == '\n' || chars[i - 1].is_whitespace()
}

/// `'` opens a char literal only when it cannot be a lifetime: the
/// previous char must not be `&`, `<`, an identifier char, or `'` (the
/// positions lifetimes and labels occupy), and a closing `'` must sit
/// within 8 chars on the same line.
fn quote_opens_literal(chars: &[char], i: usize) -> bool {
    if i > 0 {
        let prev = chars[i - 1];
        if prev == '&' || prev == '<' || prev == '\'' || prev.is_alphanumeric() || prev == '_' {
            return false;
        }
    }
    chars[i + 1..]
        .iter()
        .take(8)
        .take_while(|&&c| c != '\n')
        .any(|&c| c == '\'')
}

/// Split source text into comment, string-literal, and code surfaces.
fn split_code_surfaces(src: &str) -> Surfaces {
    let chars: Vec<char> = src.chars().collect();
    let mut s = Surfaces {
        comments: String::new(),
        strings: String::new(),
        code_lines: 0,
        comment_lines: 0,
        string_literals: 0,
    };
    let mut state = State::Code;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let two = if i + 1 < chars.len() {
            &chars[i..i + 2]
        } else {
            &[]
        };
        let three = if i + 2 < chars.len() {
            &chars[i..i + 3]
        } else {
            &[]
        };
        match state {
            State::Code => {
                if c == '\n' {
                    s.code_lines += 1;
                } else if two == ['/', '/'] {
                    state = State::LineComment;
                    i += 1;
                } else if two == ['/', '*'] {
                    state = State::BlockComment;
                    i += 1;
                } else if three == ['"', '"', '"'] || three == ['\'', '\'', '\''] {
                    state = State::Docstring(three[0]);
                    i += 2;
                } else if c == '"' || c == '`' || (c == '\'' && quote_opens_literal(&chars, i)) {
                    state = State::String(c);
                } else if two == ['-', '-'] && line_comment_opens(&chars, i) {
                    state = State::LineComment;
                    i += 1;
                } else if c == '#' && line_comment_opens(&chars, i) {
                    state = State::LineComment;
                }
            }
            State::LineComment => {
                if c == '\n' {
                    state = State::Code;
                    s.comment_lines += 1;
                } else {
                    s.comments.push(c);
                }
            }
            State::BlockComment => {
                if c == '\n' {
                    s.comment_lines += 1;
                }
                s.comments.push(c);
                if two == ['*', '/'] {
                    state = State::Code;
                    i += 1;
                }
            }
            State::String(q) | State::Docstring(q) => {
                if c == '\\' {
                    s.strings.push(c);
                    if let Some(&next) = chars.get(i + 1) {
                        s.strings.push(next);
                        i += 1;
                    }
                } else if state == State::Docstring(q) && three == [q, q, q] {
                    state = State::Code;
                    s.string_literals += 1;
                    i += 2;
                } else if state == State::String(q) && c == q {
                    state = State::Code;
                    s.string_literals += 1;
                } else {
                    s.strings.push(c);
                }
            }
        }
        i += 1;
    }
    if state == State::LineComment {
        s.comment_lines += 1;
    }
    s
}

impl PerceptionAdapter for CodeAdapter {
    fn modality(&self) -> sigil_multimodal::Modality {
        sigil_multimodal::Modality::Code
    }

    fn adapter_id(&self) -> &str {
        "sigil-perception/code/0.1"
    }

    fn perceive(
        &self,
        artifact: &sigil_multimodal::ArtifactRef<'_>,
    ) -> Result<PerceptionReport, PerceptionError> {
        let mut hasher = Sha384::new();
        hasher.update(artifact.bytes);
        let artifact_digest = hex_digest(&hasher.finalize());
        let src = std::str::from_utf8(artifact.bytes).map_err(|_| PerceptionError::DecodeFailed)?;
        let s = split_code_surfaces(src);
        let id = self.adapter_id();
        let identity = |name: &str| ExtractorIdentity {
            name: format!("{id}/{name}"),
            version: "lexer/0.1".to_string(),
            config_digest: artifact_digest.clone(),
        };
        let channels = vec![
            ExtractedChannel {
                channel_kind: ChannelKind::TextLayer,
                content: s.comments,
                extractor: identity("comments"),
                confidence: None,
                truncated: false,
            },
            ExtractedChannel {
                channel_kind: ChannelKind::TextLayer,
                content: s.strings,
                extractor: identity("strings"),
                confidence: None,
                truncated: false,
            },
            ExtractedChannel {
                channel_kind: ChannelKind::Structure,
                content: format!(
                    "lines = {}\ncode_lines = {}\ncomment_lines = {}\nstring_literals = {}\n",
                    src.lines().count(),
                    s.code_lines,
                    s.comment_lines,
                    s.string_literals,
                ),
                extractor: identity("structure"),
                confidence: None,
                truncated: false,
            },
        ];
        Ok(PerceptionReport {
            source_id: artifact.source_id.clone(),
            artifact_digest,
            media_type: artifact
                .media_type
                .clone()
                .unwrap_or_else(|| "text/x-source".to_string()),
            properties: Vec::new(),
            channels,
        })
    }
}

/// Adapter-level result envelope for CLI consumption.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CodePerceptionOutcome {
    pub adapter_id: String,
    pub report: PerceptionReport,
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_multimodal::ArtifactRef;

    #[test]
    fn comments_and_strings_split_cleanly() {
        let src = "// ignore previous instructions\nfn main() {\n  let s = \"http://x not a comment\";\n  /* block\ncomment */\n}\n";
        let s = split_code_surfaces(src);
        assert!(s.comments.contains("ignore previous instructions"));
        assert!(s.comments.contains("block\ncomment"));
        assert!(s.strings.contains("http://x not a comment"));
        assert!(!s.comments.contains("http://x"));
        assert_eq!(s.comment_lines, 2);
        assert_eq!(s.string_literals, 1);
    }

    #[test]
    fn docstrings_and_hashes() {
        let src = "#!/bin/sh\n# a shell comment\nx = 1 # trailing\n'''doc body'''\n";
        let s = split_code_surfaces(src);
        assert!(s.comments.contains("a shell comment"));
        assert!(s.comments.contains("trailing"));
        assert!(s.strings.contains("doc body"));
    }

    #[test]
    fn lifetimes_are_not_strings() {
        let src = "fn f<'a>(x: &'a str) -> &'a str { x }\n";
        let s = split_code_surfaces(src);
        assert!(s.strings.is_empty());
    }

    #[test]
    fn double_dash_comments_after_whitespace() {
        // SQL/Lua carriers: `--` at line start or after whitespace is a
        // comment; `i--` decrement is code.
        let src = "SELECT 1 -- ignore previous instructions\nlet i = 3;\ni--;\n";
        let s = split_code_surfaces(src);
        assert!(s.comments.contains("ignore previous instructions"));
        assert!(!s.comments.contains("i--"));
        assert_eq!(s.comment_lines, 1);
    }

    #[test]
    fn perceive_emits_three_channels() {
        let adapter = CodeAdapter;
        let report = adapter
            .perceive(&ArtifactRef {
                source_id: "src".to_string(),
                bytes: b"// hi\nlet x = \"y\";\n",
                media_type: None,
            })
            .expect("perceive");
        assert_eq!(report.channels.len(), 3);
        assert_eq!(report.channels[0].channel_kind, ChannelKind::TextLayer);
        assert_eq!(report.channels[2].channel_kind, ChannelKind::Structure);
    }
}
