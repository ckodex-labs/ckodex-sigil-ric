//! OSC sequence handling: consume the ST/BEL-terminated span and
//! classify the payload's command selector.

use crate::{digits, seq, BEL, C1_ST, ESC};
use sigil_core::terminal::{TerminalSequence, TerminalSequenceKind};

/// Consume an OSC sequence: payload to BEL or ST, then classify the
/// payload's command selector.
pub(crate) fn osc_end(
    bytes: &[u8],
    mut i: usize,
    start: usize,
    out: &mut Vec<TerminalSequence>,
) -> usize {
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
pub(crate) fn classify_osc(payload: &[u8]) -> String {
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
