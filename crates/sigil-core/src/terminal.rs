//! Terminal-escape detection port (F2).
//!
//! Text destined for a terminal is also a representation boundary:
//! embedded VT/ANSI control sequences can hijack clipboards (OSC 52),
//! smuggle hyperlinks whose display text disagrees with the target URI
//! (OSC 8), spoof titles/notifications, or forge output via cursor and
//! device-control sequences. SIGIL already flags invisible *codepoints*;
//! this detector flags control *sequences*.
//!
//! Boundary discipline mirrors `perplexity.rs`: an injected
//! [`TerminalSequenceScanner`] extracts and classifies sequences (the
//! engine — e.g. `sigil-vt`'s Ghostty-backed scanner); the kernel owns
//! severity mapping, evidence text, and the verdict path. Scanner
//! failures are recorded as `Failed` evidence — visible, never silent.

use crate::types::{ByteRange, DetectorId, ScanFinding, Severity};
use serde::{Deserialize, Serialize};

/// Port for sequence-extraction engines. Implementations live outside
/// the kernel (`sigil-vt`) and may wrap a full terminal emulator.
pub trait TerminalSequenceScanner {
    fn name(&self) -> &str;
    /// Extract terminal control sequences from raw bytes. `Err` is a
    /// scanner failure — recorded as `Failed` evidence, not a verdict.
    fn scan(&self, bytes: &[u8]) -> Result<Vec<TerminalSequence>, String>;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TerminalSequence {
    pub byte_range: ByteRange,
    pub kind: TerminalSequenceKind,
    /// Scanner-provided detail (e.g. the OSC command name). Used for
    /// evidence text only — classification is `kind`'s job.
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalSequenceKind {
    /// OSC sequence; `command` is the classified command name
    /// (e.g. `clipboard_contents`, `hyperlink_start`).
    Osc { command: String },
    /// CSI sequence (cursor/mode/erase manipulation).
    Csi,
    /// DCS passthrough (device control string — highest-risk channel:
    /// sixel/regis/kbd payloads reach the terminal driver verbatim).
    Dcs,
    /// Bare ESC/C1 introducer or unclassified escape.
    Escape,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalStatus {
    Evaluated,
    /// Detector was enabled but could not run (no scanner injected).
    Skipped {
        reason: String,
    },
    /// The scanner errored; recorded for evidence, not treated as signal.
    Failed {
        reason: String,
    },
}

/// Evidence record for the terminal-escape pass.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TerminalReport {
    pub status: TerminalStatus,
    pub scanner: String,
    /// Sequences returned by the scanner (pre-dedup, pre-cap).
    pub sequence_count: usize,
}

impl TerminalReport {
    pub fn skipped(scanner: &str, reason: impl Into<String>) -> Self {
        Self {
            status: TerminalStatus::Skipped {
                reason: reason.into(),
            },
            scanner: scanner.to_string(),
            sequence_count: 0,
        }
    }

    pub fn failed(scanner: &str, reason: impl Into<String>) -> Self {
        Self {
            status: TerminalStatus::Failed {
                reason: reason.into(),
            },
            scanner: scanner.to_string(),
            sequence_count: 0,
        }
    }
}

/// Map extracted sequences to findings. Severity assignment is kernel
/// policy — the scanner reports what the sequence *is*; the kernel
/// decides what it *means*.
pub fn detect_terminal_escapes(
    sequences: &[crate::terminal::TerminalSequence],
    scanner_name: &str,
    max_sequences: usize,
) -> (Vec<ScanFinding>, TerminalReport) {
    let mut findings = Vec::new();
    for seq in sequences.iter().take(max_sequences) {
        if let Some((severity, what)) = classify(seq) {
            findings.push(ScanFinding {
                byte_range: seq.byte_range,
                severity,
                detectors: vec![DetectorId::TerminalEscape],
                confidence: 1.0,
                evidence: format!(
                    "terminal {what} at bytes {}..{}{}",
                    seq.byte_range.start,
                    seq.byte_range.end,
                    if seq.detail.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", seq.detail)
                    }
                ),
            });
        }
    }
    let report = TerminalReport {
        status: TerminalStatus::Evaluated,
        scanner: scanner_name.to_string(),
        sequence_count: sequences.len(),
    };
    (findings, report)
}

/// Kernel-side risk classification. Returns `None` for sequence kinds
/// that are not findings (currently none — every control sequence in
/// admitted text is reportable at some severity).
fn classify(seq: &TerminalSequence) -> Option<(Severity, &'static str)> {
    let risk = match &seq.kind {
        TerminalSequenceKind::Osc { command } => match command.as_str() {
            "clipboard_contents" => (Severity::High, "clipboard-write OSC"),
            "conemu_run_process" | "conemu_gui_macro" => (Severity::High, "ConEmu automation OSC"),
            "rxvt_extension" | "iterm2_extension" | "kitty_clipboard_protocol" => (
                Severity::High,
                "extension-channel OSC (clipboard/eval/file-drop)",
            ),
            "hyperlink_start" | "hyperlink_end" => {
                (Severity::Medium, "hyperlink OSC (display/target smuggling)")
            }
            "change_window_title" | "conemu_change_tab_title" => {
                (Severity::Medium, "window-title OSC (spoofing)")
            }
            "show_desktop_notification" | "conemu_show_message_box" => {
                (Severity::Medium, "notification OSC (spoofing)")
            }
            "report_pwd" => (Severity::Medium, "cwd-report OSC (information leak)"),
            "kitty_dnd_protocol" | "conemu_xterm_emulation" => {
                (Severity::Medium, "terminal-mode/file-drop OSC")
            }
            _ => (Severity::Low, "OSC sequence"),
        },
        TerminalSequenceKind::Dcs => (Severity::High, "device-control string"),
        TerminalSequenceKind::Csi => (Severity::Low, "CSI sequence (output manipulation)"),
        TerminalSequenceKind::Escape => (Severity::Low, "escape sequence"),
    };
    Some(risk)
}

#[cfg(test)]
mod tests;
