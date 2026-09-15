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

mod window;
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
    for (range, detail) in win.finish() {
        out.push(seq(
            range.start,
            range.end,
            TerminalSequenceKind::Pattern {
                name: "repaint_overwrite".into(),
            },
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
        b => {
            // Single-ESC display ops still drive the window.
            match b {
                b'D' => win.line_feed(),         // IND
                b'E' => win.next_line(),         // NEL
                b'M' => win.reverse_index(),     // RI
                b'7' => win.save_restore(true),  // DECSC
                b'8' => win.save_restore(false), // DECRC
                _ => {}
            }
            out.push(seq(
                i,
                i + 2,
                TerminalSequenceKind::Escape,
                format!("ESC {}", printable(b)),
            ));
            i + 2
        }
    }
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
        let command = csi_command(span);
        win.apply_csi(command, csi_params(span), span.last() == Some(&b'l'));
        out.push(seq(
            start,
            e,
            TerminalSequenceKind::Csi {
                command: command.to_string(),
            },
            csi_detail(span, command),
        ));
    })
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

/// Consume an OSC sequence: payload to BEL or ST, then classify the
/// payload's command selector.
fn osc_end(bytes: &[u8], mut i: usize, start: usize, out: &mut Vec<TerminalSequence>) -> usize {
    let payload_start = i;
    while i < bytes.len() && bytes[i] != BEL && bytes[i] != C1_ST {
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
    let command = classify_osc(&bytes[payload_start..i.min(bytes.len())]);
    out.push(seq(
        start,
        end,
        TerminalSequenceKind::Osc { command },
        "OSC".into(),
    ));
    end
}

/// Classify an OSC payload (`Ps ; Pt`) by its numeric selector.
///
/// Table derived from ghostty `src/terminal/osc.zig` (commit `a887df4`):
/// which selectors the upstream parser recognizes and which command each
/// produces. Names match the `libghostty-vt` Rust `CommandType`
/// spellings — note the wrapper differs from the Zig field name on
/// `conemu_gui_macro` (Zig: `conemu_guimacro`); we follow the Rust API
/// since that is what the conformance feature verifies against. Anything
/// unrecognized or malformed is `"unclassified"` — the kernel still
/// records a finding (a control sequence in admitted text is reportable
/// regardless of whether we can name it).
fn classify_osc(payload: &[u8]) -> String {
    let mut fields = payload.split(|&b| b == b';');
    let selector = fields.next().unwrap_or(b"");
    let command = match digits(selector) {
        Some(52) => "clipboard_contents",
        Some(8) => hyperlink_kind(&mut fields),
        Some(9) => osc9_kind(&mut fields),
        Some(0) | Some(2) => "change_window_title",
        Some(1) => "change_window_icon",
        Some(7) => "report_pwd",
        Some(777) => rxvt_kind(&mut fields),
        Some(1337) => iterm2_kind(&mut fields),
        Some(5522) => "kitty_clipboard_protocol",
        Some(21) => "kitty_color_protocol",
        Some(66) => "kitty_text_sizing",
        Some(72) => "kitty_dnd_protocol",
        Some(133) => "semantic_prompt",
        Some(3008) => "context_signal",
        Some(4..=5) | Some(10..=19) | Some(104) | Some(110..=119) => "color_operation",
        _ => "unclassified",
    };
    command.to_string()
}

/// OSC 8: `8;params;uri` — non-empty URI (or an `id=` param) opens a
/// hyperlink; empty URI closes one (ghostty `hyperlink.zig`).
fn hyperlink_kind<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> &'static str {
    let params = fields.next().unwrap_or(b"");
    let uri = fields.next().unwrap_or(b"");
    if !uri.is_empty()
        || params
            .split(|&b| b == b':')
            .any(|seg| seg.starts_with(b"id="))
    {
        "hyperlink_start"
    } else {
        "hyperlink_end"
    }
}

/// OSC 777 (rxvt extension): only `notify` is a notification; every
/// other extension — `perl-eval`, `xterm-256color`, arbitrary future
/// exts — is an opaque extension channel (ghostty calls it invalid;
/// we flag it `rxvt_extension`, which the kernel maps High since the
/// family includes perl-eval).
fn rxvt_kind<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> &'static str {
    match fields.next() {
        Some(b"notify") => "show_desktop_notification",
        _ => "rxvt_extension",
    }
}

/// OSC 1337 (iTerm2): the dangerous subcommands re-map to canonical
/// commands — `Copy=` writes the clipboard, `CurrentDir=` reports cwd
/// (ghostty `iterm2.zig`). All other keys stay `iterm2_extension`
/// (High — the family carries clipboard-write and remote-host vars).
fn iterm2_kind<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> &'static str {
    let kv = fields.next().unwrap_or(b"");
    let key = kv.split(|&b| b == b'=').next().unwrap_or(b"");
    match key {
        b"Copy" => "clipboard_contents",
        b"CurrentDir" => "report_pwd",
        _ => "iterm2_extension",
    }
}

/// OSC 9: ConEmu subcommands carry a numeric second field
/// (`9;N;...`, ghostty `osc9.zig`); anything else is an iTerm2-style
/// desktop notification.
fn osc9_kind<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> &'static str {
    let sub = fields.next().unwrap_or(b"");
    match digits(sub) {
        Some(1) => "conemu_sleep",
        Some(2) => "conemu_show_message_box",
        Some(3) => "conemu_change_tab_title",
        Some(4) => "conemu_progress_report",
        Some(5) => "conemu_wait_input",
        Some(6) => "conemu_gui_macro",
        Some(7) => "conemu_run_process",
        Some(8) => "conemu_output_environment_variable",
        Some(10) => "conemu_xterm_emulation",
        Some(11) => "conemu_comment",
        Some(12) => "semantic_prompt",
        _ => "show_desktop_notification",
    }
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

/// `h`/`l` private-mode ops worth naming: `?25` cursor visibility,
/// `?47`/`?1047`/`?1049` alternate screen. Everything else stays
/// `set_mode`/`reset_mode`.
fn mode_command(params: &[u8]) -> &'static str {
    match params {
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
