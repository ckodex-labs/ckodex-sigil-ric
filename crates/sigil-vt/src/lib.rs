//! Ghostty-backed [`TerminalSequenceScanner`] (F2).
//!
//! `libghostty-vt` is the VT engine extracted from the Ghostty terminal —
//! its `osc::Parser` is the fuzzed, upstream-maintained classifier for
//! OSC commands (clipboard writes, hyperlink smuggling, title/notification
//! spoofing, ConEmu automation). This crate owns *extraction and
//! classification*; `sigil-core` owns severity mapping and verdicts.
//!
//! The outer CSI/DCS/ESC span lexer here is intentionally minimal —
//! sequence *framing*, not emulation. A full `Terminal`/`Screen`
//! side-effect diff (emulate the consumer) is a planned follow-up.

use sigil_core::terminal::{TerminalSequence, TerminalSequenceKind, TerminalSequenceScanner};

const ESC: u8 = 0x1B;
const BEL: u8 = 0x07;
const C1_DCS: u8 = 0x90;
const C1_SOS: u8 = 0x98;
const C1_CSI: u8 = 0x9B;
const C1_ST: u8 = 0x9C;
const C1_OSC: u8 = 0x9D;
const C1_PM: u8 = 0x9E;
const C1_APC: u8 = 0x9F;

/// Ghostty-backed sequence scanner.
#[derive(Default)]
pub struct GhosttyScanner;

impl GhosttyScanner {
    pub fn new() -> Self {
        Self
    }
}

impl TerminalSequenceScanner for GhosttyScanner {
    fn name(&self) -> &str {
        // engine identity — evidence names the parser that classified
        // the sequence, not the crate
        "libghostty-vt 0.2.1 (osc)"
    }

    fn scan(&self, bytes: &[u8]) -> Result<Vec<TerminalSequence>, String> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let start = i;
            match bytes[i] {
                ESC if i + 1 < bytes.len() => match bytes[i + 1] {
                    b'[' => {
                        i = csi_end(bytes, i + 2, |e| {
                            out.push(TerminalSequence {
                                byte_range: sigil_core::types::ByteRange::new(start, e),
                                kind: TerminalSequenceKind::Csi,
                                detail: csi_detail(&bytes[start..e]),
                            });
                        })
                    }
                    b']' => i = osc_end(bytes, i + 2, start, &mut out),
                    b'P' => i = st_end(bytes, i + 2, start, &mut out, TerminalSequenceKind::Dcs),
                    b'X' | b'^' | b'_' => {
                        i = st_end(bytes, i + 2, start, &mut out, TerminalSequenceKind::Escape)
                    }
                    _ => {
                        out.push(TerminalSequence {
                            byte_range: sigil_core::types::ByteRange::new(start, start + 2),
                            kind: TerminalSequenceKind::Escape,
                            detail: format!("ESC {}", printable(bytes[i + 1])),
                        });
                        i += 2;
                    }
                },
                ESC => {
                    out.push(TerminalSequence {
                        byte_range: sigil_core::types::ByteRange::new(start, start + 1),
                        kind: TerminalSequenceKind::Escape,
                        detail: "lone ESC".to_string(),
                    });
                    i += 1;
                }
                C1_CSI => {
                    i = csi_end(bytes, i + 1, |e| {
                        out.push(TerminalSequence {
                            byte_range: sigil_core::types::ByteRange::new(start, e),
                            kind: TerminalSequenceKind::Csi,
                            detail: csi_detail(&bytes[start..e]),
                        });
                    })
                }
                C1_OSC => i = osc_end(bytes, i + 1, start, &mut out),
                C1_DCS | C1_SOS | C1_PM | C1_APC => {
                    i = st_end(bytes, i + 1, start, &mut out, TerminalSequenceKind::Dcs)
                }
                _ => i += 1,
            }
        }
        Ok(out)
    }
}

/// Consume a CSI sequence: params (0x30–0x3F), intermediates (0x20–0x2F),
/// final byte (0x40–0x7E). `emit` receives the exclusive end.
fn csi_end(bytes: &[u8], mut i: usize, mut emit: impl FnMut(usize)) -> usize {
    while i < bytes.len() && (0x30..=0x3F).contains(&bytes[i]) {
        i += 1;
    }
    while i < bytes.len() && (0x20..=0x2F).contains(&bytes[i]) {
        i += 1;
    }
    if i < bytes.len() && (0x40..=0x7E).contains(&bytes[i]) {
        i += 1;
    }
    emit(i);
    i
}

/// Consume an OSC sequence: payload to BEL or ST (`ESC \` or 0x9C),
/// classified by `libghostty-vt`'s OSC parser.
fn osc_end(bytes: &[u8], mut i: usize, start: usize, out: &mut Vec<TerminalSequence>) -> usize {
    let payload_start = i;
    while i < bytes.len() && bytes[i] != BEL && bytes[i] != C1_ST {
        if bytes[i] == ESC && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
            break;
        }
        i += 1;
    }
    let terminator = if i < bytes.len() { bytes[i] } else { BEL };
    let end = if i < bytes.len() {
        if bytes[i] == ESC {
            i + 2
        } else {
            i + 1
        }
    } else {
        i
    };
    let command = classify_osc(&bytes[payload_start..i], terminator);
    out.push(TerminalSequence {
        byte_range: sigil_core::types::ByteRange::new(start, end.min(bytes.len())),
        kind: TerminalSequenceKind::Osc { command },
        detail: "OSC".to_string(),
    });
    end.min(bytes.len())
}

/// Consume an ST-terminated sequence (DCS/SOS/PM/APC).
fn st_end(
    bytes: &[u8],
    mut i: usize,
    start: usize,
    out: &mut Vec<TerminalSequence>,
    kind: TerminalSequenceKind,
) -> usize {
    while i < bytes.len() && bytes[i] != C1_ST {
        if bytes[i] == ESC && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
            break;
        }
        i += 1;
    }
    let end = if i < bytes.len() {
        if bytes[i] == ESC {
            i + 2
        } else {
            i + 1
        }
    } else {
        i
    };
    out.push(TerminalSequence {
        byte_range: sigil_core::types::ByteRange::new(start, end.min(bytes.len())),
        kind,
        detail: "ST-terminated".to_string(),
    });
    end.min(bytes.len())
}

/// Classify an OSC payload with `libghostty-vt`'s parser → snake_case
/// command name for the kernel's severity map.
fn classify_osc(payload: &[u8], terminator: u8) -> String {
    let mut parser = match libghostty_vt::osc::Parser::new() {
        Ok(p) => p,
        Err(_) => return "unclassified".to_string(),
    };
    for &b in payload {
        parser.next_byte(b);
    }
    snake(&format!("{:?}", parser.end(terminator).command_type()))
}

fn snake(dbg: &str) -> String {
    let head = dbg.split(['(', '{']).next().unwrap_or(dbg).trim();
    let mut out = String::with_capacity(head.len() + 4);
    for (i, c) in head.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

fn csi_detail(seq: &[u8]) -> String {
    seq.last()
        .map(|&f| format!("final {}", printable(f)))
        .unwrap_or_default()
}

fn printable(b: u8) -> String {
    if (0x20..0x7F).contains(&b) {
        format!("'{}'", b as char)
    } else {
        format!("0x{b:02x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(bytes: &[u8]) -> Vec<TerminalSequence> {
        GhosttyScanner::new().scan(bytes).expect("scan")
    }

    #[test]
    fn plain_text_yields_nothing() {
        assert!(scan(b"hello world").is_empty());
    }

    #[test]
    fn osc52_clipboard_classified() {
        let seqs = scan(b"pre\x1b]52;c;Y2xpcA==\x07post");
        assert_eq!(seqs.len(), 1);
        assert_eq!(
            seqs[0].kind,
            TerminalSequenceKind::Osc {
                command: "clipboard_contents".to_string()
            }
        );
        assert_eq!(seqs[0].byte_range.start, 3);
    }

    #[test]
    fn osc8_hyperlink_classified() {
        let seqs = scan(b"\x1b]8;;https://evil.example\x1b\\click me\x1b]8;;\x1b\\");
        assert_eq!(seqs.len(), 2);
        assert!(matches!(
            &seqs[0].kind,
            TerminalSequenceKind::Osc { command } if command == "hyperlink_start"
        ));
        assert!(matches!(
            &seqs[1].kind,
            TerminalSequenceKind::Osc { command } if command == "hyperlink_end"
        ));
    }

    #[test]
    fn csi_and_esc_and_dcs_spans() {
        let seqs = scan(b"a\x1b[31mRED\x1b[0m \x1bPq\x1b\\");
        assert_eq!(seqs.len(), 3);
        assert_eq!(seqs[0].kind, TerminalSequenceKind::Csi);
        assert_eq!(seqs[1].kind, TerminalSequenceKind::Csi);
        assert_eq!(seqs[2].kind, TerminalSequenceKind::Dcs);
        assert_eq!(seqs[0].byte_range.start, 1);
    }

    #[test]
    fn c1_osc_form_detected() {
        let seqs = scan(b"x\x9d52;c;YQ==\x9cy");
        assert_eq!(seqs.len(), 1);
        assert!(
            matches!(&seqs[0].kind, TerminalSequenceKind::Osc { command } if command == "clipboard_contents")
        );
    }

    #[test]
    fn lone_esc_reported() {
        let seqs = scan(b"end\x1b");
        assert_eq!(seqs.len(), 1);
        assert_eq!(seqs[0].kind, TerminalSequenceKind::Escape);
    }
}
