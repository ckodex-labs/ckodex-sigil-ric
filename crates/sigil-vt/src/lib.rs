//! `sigil-vt` — built-in [`TerminalSequenceScanner`] for the terminal-
//! escape detector (F2).
//!
//! Sequence *framing* (CSI/DCS/OSC/ESC spans, byte ranges) is a minimal
//! purpose-built lexer. OSC payload *classification* maps the command
//! selector (`Ps`) to a command name using a table derived from ghostty's
//! `osc.zig` state trie (pinned commit `a887df4`, reviewed against source).
//! Command names intentionally match ghostty's `Command` snake_case
//! spellings so `sigil-core`'s severity map stays aligned with the
//! upstream taxonomy. Alongside framing, a bounded virtual window
//! (`window.rs`) replays writes/moves/erases over a 200×48 cell grid so
//! repaint detection is *semantic*: it fires when the displayed byte
//! stream diverges from what a terminal would actually show, not when an
//! erase op is merely present.
//!
//! Boundary discipline: this crate extracts and classifies — `sigil-core`
//! owns severity mapping, evidence text, and verdicts. A `conformance`
//! cargo feature cross-checks this table against `libghostty-vt`'s
//! fuzzed parser (build-time cost: rust ≥1.90 + zig 0.15.2 + ghostty
//! source fetch — kept out of the default build).

use sigil_core::terminal::{TerminalSequence, TerminalSequenceKind, TerminalSequenceScanner};
use sigil_core::types::ByteRange;

mod osc;
mod window;
use osc::osc_end;
use window::VirtualWindow;

const ESC: u8 = 0x1B;
const BEL: u8 = 0x07;
const C1_DCS: u8 = 0x90;
const C1_SOS: u8 = 0x98;
const C1_CSI: u8 = 0x9B;
const C1_ST: u8 = 0x9C;
const C1_OSC: u8 = 0x9D;
const C1_PM: u8 = 0x9E;
const C1_APC: u8 = 0x9F;

/// Built-in VT sequence scanner (no emulator, no FFI).
#[derive(Default)]
pub struct VtScanner;

impl VtScanner {
    pub fn new() -> Self {
        Self
    }
}

impl TerminalSequenceScanner for VtScanner {
    fn name(&self) -> &str {
        "sigil-vt osc-table+window"
    }

    fn scan(&self, bytes: &[u8]) -> Result<Vec<TerminalSequence>, String> {
        Ok(run(bytes).0)
    }
}

/// The shared byte walk: frame sequences, feed the virtual window,
/// emit classified sequences + window findings. The window is
/// returned so the conformance lane can inspect final grid state.
fn run(bytes: &[u8]) -> (Vec<TerminalSequence>, VirtualWindow) {
    let mut out = Vec::new();
    // Side-structure: the virtual window replays writes/moves/erases
    // so divergence is *semantic* — a repaint finding fires when a
    // cell's displayed byte is overwritten, not when an erase op is
    // merely present.
    let mut win = VirtualWindow::new();
    let mut i = 0;
    while i < bytes.len() {
        i = match bytes[i] {
            ESC if i + 1 < bytes.len() => esc_dispatch(bytes, i, &mut win, &mut out),
            ESC => {
                out.push(seq(
                    i,
                    i + 1,
                    TerminalSequenceKind::Escape,
                    "lone ESC".into(),
                ));
                i + 1
            }
            C1_CSI => csi_span(bytes, i + 1, i, &mut win, &mut out),
            C1_OSC => osc_end(bytes, i + 1, i, &mut out),
            C1_DCS | C1_SOS | C1_PM | C1_APC => {
                st_end(bytes, i + 1, i, &mut out, TerminalSequenceKind::Dcs)
            }
            b => {
                feed_plain(b, i, &mut win);
                i + 1
            }
        };
    }
    for (range, name, detail) in win.finish() {
        out.push(seq(
            range.start,
            range.end,
            TerminalSequenceKind::Pattern { name: name.into() },
            detail,
        ));
    }
    (out, win)
}

/// Conformance-lane access to the window's post-scan grid state.
#[cfg(all(test, feature = "conformance"))]
pub(crate) fn scan_window(bytes: &[u8]) -> VirtualWindow {
    run(bytes).1
}

/// Dispatch on the byte after `ESC` (position `i`); returns the index
/// after the handled span.
fn esc_dispatch(
    bytes: &[u8],
    i: usize,
    win: &mut VirtualWindow,
    out: &mut Vec<TerminalSequence>,
) -> usize {
    match bytes[i + 1] {
        b'[' => csi_span(bytes, i + 2, i, win, out),
        b']' => osc_end(bytes, i + 2, i, out),
        b'P' => st_end(bytes, i + 2, i, out, TerminalSequenceKind::Dcs),
        b'X' | b'^' | b'_' => st_end(bytes, i + 2, i, out, TerminalSequenceKind::Escape),
        0x20..=0x2F => esc_intermediates(bytes, i, out),
        b => esc_single(b, i, win, out),
    }
}

/// ESC + intermediates + final: charset selects, DECALN, DECSASD —
/// they change what bytes render as, so they are quarantined as
/// unmodeled rather than leaking the final byte into the window.
fn esc_intermediates(bytes: &[u8], i: usize, out: &mut Vec<TerminalSequence>) -> usize {
    let mut j = i + 1;
    while j < bytes.len() && (0x20..=0x2F).contains(&bytes[j]) {
        j += 1;
    }
    if j < bytes.len() && (0x30..=0x7E).contains(&bytes[j]) {
        j += 1;
    }
    out.push(seq(
        i,
        j,
        TerminalSequenceKind::Escape,
        "ESC intermediates".into(),
    ));
    unmodeled(i, j, "ESC intermediates (charset/decsasd)", out);
    j
}

/// Single-ESC forms: display ops still drive the window; anything
/// else is quarantined.
fn esc_single(b: u8, i: usize, win: &mut VirtualWindow, out: &mut Vec<TerminalSequence>) -> usize {
    let modeled = match b {
        b'D' => {
            win.line_feed(); // IND
            true
        }
        b'E' => {
            win.next_line(); // NEL
            true
        }
        b'M' => {
            win.reverse_index(); // RI
            true
        }
        b'7' => {
            win.save_restore(true); // DECSC
            true
        }
        b'8' => {
            win.save_restore(false); // DECRC
            true
        }
        b'c' => {
            win.ris(); // RIS full reset
            true
        }
        b'=' | b'>' => true, // keypad modes — no display state
        _ => false,
    };
    out.push(seq(
        i,
        i + 2,
        TerminalSequenceKind::Escape,
        format!("ESC {}", printable(b)),
    ));
    if !modeled {
        unmodeled(i, i + 2, "ESC op", out);
    }
    i + 2
}

/// Feed a non-sequence byte to the window: C0 controls drive cursor
/// state, printable bytes write cells, everything else is ignored.
fn feed_plain(b: u8, pos: usize, win: &mut VirtualWindow) {
    match b {
        // Raw C1 bytes are NOT display ops: ghostty's stream parser
        // passes them to text handling (verified in the conformance
        // lane) — the ESC D/E/M forms are the interpreted ones.
        0x0A..=0x0C => win.line_feed(), // LF VT FF
        0x0D => win.carriage_return(),
        0x09 => win.tab(),
        0x08 => win.backspace(),
        _ if is_printable(b) => win.write(b, pos),
        _ => {}
    }
}

/// Frame a CSI sequence, decode its op, apply it to the window, and
/// emit the classified sequence. `params_at` is where the body starts
/// (after `ESC [` or the single C1 byte); `start` is the span start.
fn csi_span(
    bytes: &[u8],
    params_at: usize,
    start: usize,
    win: &mut VirtualWindow,
    out: &mut Vec<TerminalSequence>,
) -> usize {
    csi_end(bytes, params_at, |e| {
        let span = &bytes[start..e];
        // The same bytes are a different op under private modes —
        // `CSI s` is DECSLRM under `?69h`, CUP is region-relative
        // under `?6h` — so dispatch through the mode-aware gate.
        let command = win.effective_op(csi_command(span));
        win.apply_csi(command, csi_params(span), span.last() == Some(&b'l'));
        out.push(seq(
            start,
            e,
            TerminalSequenceKind::Csi {
                command: command.to_string(),
            },
            csi_detail(span, command),
        ));
        if !is_modeled(command) {
            unmodeled(start, e, &format!("unmodeled CSI op {command}"), out);
        }
    })
}

/// CSI ops the window replays (or that are verified no-ops for display
/// state — SGR, cursor visibility, generic mode sets). Anything else —
/// `csi_unknown`, origin mode, DECLRMM left/right margins, LNM, 132-col —
/// can silently desync the model, so it is quarantined as a finding.
fn is_modeled(command: &str) -> bool {
    matches!(
        command,
        "cursor_up"
            | "cursor_down"
            | "cursor_forward"
            | "cursor_back"
            | "cursor_next_line"
            | "cursor_prev_line"
            | "cursor_column"
            | "cursor_row"
            | "cursor_position"
            | "erase_line"
            | "erase_display"
            | "erase_chars"
            | "delete_chars"
            | "insert_chars"
            | "delete_lines"
            | "insert_lines"
            | "scroll_up"
            | "scroll_down"
            | "scroll_region"
            | "save_cursor"
            | "restore_cursor"
            | "alt_screen"
            | "insert_mode"
            | "decawm"
            | "sgr"
            | "sgr_conceal"
            | "cursor_visibility"
            | "erase_scrollback"
            | "set_reset_mode"
    )
}

/// Quarantine finding: the byte stream exercised a display op the
/// window cannot faithfully replay — tracking beyond this point is
/// unreliable, so the op itself is reportable.
fn unmodeled(start: usize, end: usize, what: &str, out: &mut Vec<TerminalSequence>) {
    out.push(seq(
        start,
        end,
        TerminalSequenceKind::Pattern {
            name: "window_unmodeled".into(),
        },
        format!("{what}: display state beyond this point is untracked"),
    ));
}

/// Bytes that render as glyphs. Excludes C0/C1 controls (0x00–0x1F,
/// 0x7F, 0x80–0x9F); UTF-8 continuation/lead bytes (0xA0+) count.
fn is_printable(b: u8) -> bool {
    (0x20..0x7F).contains(&b) || b >= 0xA0
}

fn seq(start: usize, end: usize, kind: TerminalSequenceKind, detail: String) -> TerminalSequence {
    TerminalSequence {
        byte_range: ByteRange::new(start, end),
        kind,
        detail,
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

/// Consume an ST-terminated sequence (OSC/DCS/SOS/PM/APC). Returns the
/// exclusive end; emits via `out`.
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
    let end = end.min(bytes.len());
    out.push(seq(start, end, kind, "ST-terminated".into()));
    end
}

/// Parse a field of pure ASCII digits into a u16 (None on empty/overflow).
pub(crate) fn digits(field: &[u8]) -> Option<u16> {
    if field.is_empty() || !field.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    field.iter().try_fold(0u16, |acc, b| {
        acc.checked_mul(10)?.checked_add((b - b'0') as u16)
    })
}

/// Decode a CSI sequence's operation from params + final byte. Table
/// authored from ECMA-48/xterm — the upstream C API exposes no CSI
/// taxonomy (`osc::Parser` covers OSC only). `seq_bytes` is the full
/// span including introducer and final byte.
fn csi_command(seq_bytes: &[u8]) -> &'static str {
    // Strip the introducer (ESC [ = 2 bytes, C1 CSI = 1) and split
    // params+intermediates from the final byte.
    let skip = if seq_bytes.first() == Some(&ESC) {
        2
    } else {
        1
    };
    let body = seq_bytes.get(skip..).unwrap_or(&[]);
    let Some((&final_b, params)) = body.split_last() else {
        return "csi_unknown";
    };
    match final_b {
        b'K' => "erase_line",
        b'J' if params == b"3" => "erase_scrollback",
        b'J' => "erase_display",
        b'X' => "erase_chars",
        b'm' if sgr_conceals(params) => "sgr_conceal",
        b'm' => "sgr",
        b'H' | b'f' => "cursor_position",
        b'A' => "cursor_up",
        b'B' => "cursor_down",
        b'C' => "cursor_forward",
        b'D' => "cursor_back",
        b'E' => "cursor_next_line",
        b'F' => "cursor_prev_line",
        b'G' | b'`' => "cursor_column",
        b'd' => "cursor_row",
        b'S' => "scroll_up",
        b'T' => "scroll_down",
        b'L' => "insert_lines",
        b'M' => "delete_lines",
        b'P' => "delete_chars",
        b'@' => "insert_chars",
        b'r' => "scroll_region", // DECSTBM
        b'h' | b'l' => mode_command(params),
        b's' => "save_cursor",
        b'u' => "restore_cursor",
        _ => "csi_unknown",
    }
}

/// SGR param 8 = conceal (renders following text invisible).
fn sgr_conceals(params: &[u8]) -> bool {
    params.split(|&b| b == b';').any(|p| p == b"8")
}

/// `h`/`l` mode ops worth naming. Modeled: `4` insert mode, `?7`
/// DECAWM, `?25` visibility (no-op), alt screens. Display-state modes
/// we do NOT replay get their own names so they are quarantined as
/// unmodeled: `?6` origin, `?69` DECLRMM, `?3` 132-col, `20` LNM.
/// Everything else (visual-only modes) stays `set_reset_mode`.
fn mode_command(params: &[u8]) -> &'static str {
    match params {
        b"4" => "insert_mode",
        b"?7" => "decawm",
        b"?6" => "origin_mode",
        b"?69" => "declrmm",
        b"?3" => "column_mode",
        b"20" => "linefeed_mode",
        b"?25" => "cursor_visibility",
        b"?47" | b"?1047" | b"?1049" => "alt_screen",
        _ => "set_reset_mode",
    }
}

/// Raw CSI parameter bytes (between introducer and final byte) —
/// `?`-private markers and intermediates included.
fn csi_params(seq: &[u8]) -> &[u8] {
    let skip = if seq.first() == Some(&ESC) { 2 } else { 1 };
    let body = seq.get(skip..).unwrap_or(&[]);
    &body[..body.len().saturating_sub(1)]
}

fn csi_detail(seq: &[u8], command: &str) -> String {
    let params = csi_params(seq);
    if params.is_empty() {
        command.to_string()
    } else {
        format!("{command} params \"{}\"", String::from_utf8_lossy(params))
    }
}

fn printable(b: u8) -> String {
    if (0x20..0x7F).contains(&b) {
        format!("'{}'", b as char)
    } else {
        format!("0x{b:02x}")
    }
}

#[cfg(test)]
mod tests;
