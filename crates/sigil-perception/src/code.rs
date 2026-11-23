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
use sigil_multimodal::{ChannelKind, ExtractedChannel};

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
    let mut lexer = Lexer {
        chars: &chars,
        i: 0,
        state: State::Code,
        surfaces: Surfaces {
            comments: String::new(),
            strings: String::new(),
            code_lines: 0,
            comment_lines: 0,
            string_literals: 0,
        },
    };
    while lexer.i < chars.len() {
        lexer.step();
        lexer.i += 1;
    }
    if lexer.state == State::LineComment {
        lexer.surfaces.comment_lines += 1;
    }
    lexer.surfaces
}

/// The lexer's position in the source, its state and what it has recovered.
struct Lexer<'a> {
    chars: &'a [char],
    i: usize,
    state: State,
    surfaces: Surfaces,
}

impl Lexer<'_> {
    /// The next `n` chars, or none when fewer remain.
    fn ahead(&self, n: usize) -> &[char] {
        if self.i + n <= self.chars.len() {
            &self.chars[self.i..self.i + n]
        } else {
            &[]
        }
    }

    /// Consume the char at `i`; a transition may advance `i` past a
    /// multi-char delimiter, and the caller then steps over the last char.
    fn step(&mut self) {
        let c = self.chars[self.i];
        match self.state {
            State::Code => self.step_code(c),
            State::LineComment => self.step_line_comment(c),
            State::BlockComment => self.step_block_comment(c),
            State::String(quote) | State::Docstring(quote) => self.step_quoted(quote, c),
        }
    }

    fn step_code(&mut self, c: char) {
        let (two, three) = (self.ahead(2), self.ahead(3));
        if c == '\n' {
            self.surfaces.code_lines += 1;
        } else if two == ['/', '/'] {
            self.state = State::LineComment;
            self.i += 1;
        } else if two == ['/', '*'] {
            self.state = State::BlockComment;
            self.i += 1;
        } else if three == ['"', '"', '"'] || three == ['\'', '\'', '\''] {
            self.state = State::Docstring(three[0]);
            self.i += 2;
        } else if c == '"' || c == '`' || (c == '\'' && quote_opens_literal(self.chars, self.i)) {
            self.state = State::String(c);
        } else if two == ['-', '-'] && line_comment_opens(self.chars, self.i) {
            self.state = State::LineComment;
            self.i += 1;
        } else if c == '#' && line_comment_opens(self.chars, self.i) {
            self.state = State::LineComment;
        }
    }

    fn step_line_comment(&mut self, c: char) {
        if c == '\n' {
            self.state = State::Code;
            self.surfaces.comment_lines += 1;
        } else {
            self.surfaces.comments.push(c);
        }
    }

    fn step_block_comment(&mut self, c: char) {
        if c == '\n' {
            self.surfaces.comment_lines += 1;
        }
        self.surfaces.comments.push(c);
        if self.ahead(2) == ['*', '/'] {
            self.state = State::Code;
            self.i += 1;
        }
    }

    fn step_quoted(&mut self, quote: char, c: char) {
        if c == '\\' {
            self.surfaces.strings.push(c);
            if let Some(&next) = self.chars.get(self.i + 1) {
                self.surfaces.strings.push(next);
                self.i += 1;
            }
        } else if self.state == State::Docstring(quote) && self.ahead(3) == [quote; 3] {
            self.state = State::Code;
            self.surfaces.string_literals += 1;
            self.i += 2;
        } else if self.state == State::String(quote) && c == quote {
            self.state = State::Code;
            self.surfaces.string_literals += 1;
        } else {
            self.surfaces.strings.push(c);
        }
    }
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
        let identity =
            |name: &str| crate::in_process_identity(format!("{id}/{name}"), "lexer/0.1", &[]);
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
            consumed: None,
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
