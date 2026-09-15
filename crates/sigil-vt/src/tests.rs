use super::*;

fn scan(bytes: &[u8]) -> Vec<TerminalSequence> {
    VtScanner::new().scan(bytes).expect("scan")
}

fn osc_command(seqs: &[TerminalSequence], idx: usize) -> &str {
    match &seqs[idx].kind {
        TerminalSequenceKind::Osc { command } => command,
        other => panic!("expected Osc, got {other:?}"),
    }
}

#[test]
fn plain_text_yields_nothing() {
    assert!(scan(b"hello world").is_empty());
}

#[test]
fn osc52_clipboard_classified() {
    let seqs = scan(b"pre\x1b]52;c;Y2xpcA==\x07post");
    assert_eq!(seqs.len(), 1);
    assert_eq!(osc_command(&seqs, 0), "clipboard_contents");
    assert_eq!(seqs[0].byte_range, ByteRange::new(3, 19));
}

#[test]
fn osc8_hyperlink_start_and_end() {
    let seqs = scan(b"\x1b]8;;https://evil.example\x1b\\click me\x1b]8;;\x1b\\");
    assert_eq!(seqs.len(), 2);
    assert_eq!(osc_command(&seqs, 0), "hyperlink_start");
    assert_eq!(osc_command(&seqs, 1), "hyperlink_end");
}

#[test]
fn osc8_id_only_param_is_start() {
    let seqs = scan(b"\x1b]8;id=foo;\x1b\\");
    assert_eq!(osc_command(&seqs, 0), "hyperlink_start");
}

#[test]
fn osc_title_notification_and_pwd() {
    assert_eq!(
        osc_command(&scan(b"\x1b]2;title\x07"), 0),
        "change_window_title"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]0;title\x07"), 0),
        "change_window_title"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]1;icon\x07"), 0),
        "change_window_icon"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]9;hi there\x07"), 0),
        "show_desktop_notification"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]777;notify;title;body\x07"), 0),
        "show_desktop_notification"
    );
    // Non-notify rxvt exts (perl-eval etc.) are opaque extension channels
    assert_eq!(
        osc_command(&scan(b"\x1b]777;perl-eval;code\x07"), 0),
        "rxvt_extension"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]7;file:///etc\x07"), 0),
        "report_pwd"
    );
}

#[test]
fn conemu_subcommands() {
    let cases: [(&[u8], &str); 6] = [
        (b"\x1b]9;3;tab\x07", "conemu_change_tab_title"),
        (b"\x1b]9;4;1;50\x07", "conemu_progress_report"),
        (b"\x1b]9;5\x07", "conemu_wait_input"),
        (b"\x1b]9;6;macro()\x07", "conemu_gui_macro"),
        (b"\x1b]9;7;cmd\x07", "conemu_run_process"),
        (b"\x1b]9;12\x07", "semantic_prompt"),
    ];
    for (input, want) in cases {
        assert_eq!(osc_command(&scan(input), 0), want, "input {input:?}");
    }
    // Non-ConEmu numeric subcode falls back to notification
    assert_eq!(
        osc_command(&scan(b"\x1b]9;99;x\x07"), 0),
        "show_desktop_notification"
    );
}

#[test]
fn extension_channels() {
    // iTerm2 dangerous subcommands re-map to canonical commands
    assert_eq!(
        osc_command(&scan(b"\x1b]1337;Copy=:YQ==\x07"), 0),
        "clipboard_contents"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]1337;CurrentDir=/etc\x07"), 0),
        "report_pwd"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]1337;SetUserVar=x=y\x07"), 0),
        "iterm2_extension"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]5522;write;s\x07"), 0),
        "kitty_clipboard_protocol"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]21;red=ff0000\x07"), 0),
        "kitty_color_protocol"
    );
    assert_eq!(osc_command(&scan(b"\x1b]133;A\x07"), 0), "semantic_prompt");
    assert_eq!(
        osc_command(&scan(b"\x1b]3008;sig=1\x07"), 0),
        "context_signal"
    );
    assert_eq!(
        osc_command(&scan(b"\x1b]4;0;rgb:ff/00/00\x07"), 0),
        "color_operation"
    );
}

#[test]
fn unknown_and_malformed_osc_are_unclassified() {
    assert_eq!(osc_command(&scan(b"\x1b]9999;x\x07"), 0), "unclassified");
    assert_eq!(osc_command(&scan(b"\x1b]abc;x\x07"), 0), "unclassified");
    // Unterminated OSC still produces a sequence finding
    let seqs = scan(b"tail \x1b]52;c;YQ==");
    assert_eq!(seqs.len(), 1);
    assert_eq!(osc_command(&seqs, 0), "clipboard_contents");
}

#[test]
fn csi_and_esc_and_dcs_spans() {
    let seqs = scan(b"a\x1b[31mRED\x1b[0m \x1bPq\x1b\\");
    assert_eq!(seqs.len(), 3);
    assert_eq!(
        seqs[0].kind,
        TerminalSequenceKind::Csi {
            command: "sgr".into()
        }
    );
    assert_eq!(
        seqs[1].kind,
        TerminalSequenceKind::Csi {
            command: "sgr".into()
        }
    );
    assert_eq!(seqs[2].kind, TerminalSequenceKind::Dcs);
    assert_eq!(seqs[0].byte_range.start, 1);
}

#[test]
fn csi_command_decoding() {
    let cases: &[(&[u8], &str)] = &[
        (b"\x1b[2K", "erase_line"),
        (b"\x1b[K", "erase_line"),
        (b"\x1b[J", "erase_display"),
        (b"\x1b[3J", "erase_scrollback"),
        (b"\x1b[2X", "erase_chars"),
        (b"\x1b[8m", "sgr_conceal"),
        (b"\x1b[1;8;31m", "sgr_conceal"),
        (b"\x1b[31m", "sgr"),
        (b"\x1b[?1049h", "alt_screen"),
        (b"\x1b[?25l", "cursor_visibility"),
        (b"\x1b[5h", "set_reset_mode"),
        (b"\x1b[1A", "cursor_up"),
        (b"\x1b[3;4H", "cursor_position"),
        (b"\x1b[5S", "scroll_up"),
        (b"\x1b[2P", "delete_chars"),
        (b"\x1b[s", "save_cursor"),
        (b"\x1b[ZZ", "csi_unknown"),
        // C1-introduced CSI decodes identically
        (b"\x9b2K", "erase_line"),
    ];
    for (input, want) in cases {
        let seqs = scan(input);
        assert_eq!(seqs.len(), 1, "{input:?}");
        match &seqs[0].kind {
            TerminalSequenceKind::Csi { command } => {
                assert_eq!(command, want, "{input:?}");
            }
            other => panic!("expected Csi, got {other:?}"),
        }
    }
}

#[test]
fn repaint_overwrite_pattern_detected() {
    // erase-line + carriage-return + rewrite — canonical repaint idiom
    let seqs = scan(b"ran: apt install\x1b[2K\x1b[Gran: apt update");
    let pattern = seqs
        .iter()
        .find(|s| matches!(&s.kind, TerminalSequenceKind::Pattern { .. }))
        .expect("repaint pattern");
    assert_eq!(
        pattern.kind,
        TerminalSequenceKind::Pattern {
            name: "repaint_overwrite".into()
        }
    );
    // span covers erase seq through the rewritten run
    assert_eq!(pattern.byte_range.start, 16);
    assert_eq!(pattern.detail, "repaint after erase_line");
    // cursor-up + erase + rewrite (previous-line overwrite)
    let seqs = scan(b"line1\nline2\x1b[1A\x1b[2KFORGED");
    assert!(seqs.iter().any(
        |s| matches!(&s.kind, TerminalSequenceKind::Pattern { name } if name == "repaint_overwrite")
    ));
}

#[test]
fn repaint_pattern_negatives() {
    // erase with no following text — capability only, no pattern
    let seqs = scan(b"text\x1b[2K");
    assert!(!seqs
        .iter()
        .any(|s| matches!(&s.kind, TerminalSequenceKind::Pattern { .. })));
    // erase then newline then text — LF closes the window
    let seqs = scan(b"x\x1b[2K\ny");
    assert!(!seqs
        .iter()
        .any(|s| matches!(&s.kind, TerminalSequenceKind::Pattern { .. })));
    // SGR color then text — not a repaint trigger
    let seqs = scan(b"a\x1b[31mred");
    assert!(!seqs
        .iter()
        .any(|s| matches!(&s.kind, TerminalSequenceKind::Pattern { .. })));
}

#[test]
fn c1_osc_form_detected() {
    let seqs = scan(b"x\x9d52;c;YQ==\x9cy");
    assert_eq!(seqs.len(), 1);
    assert_eq!(osc_command(&seqs, 0), "clipboard_contents");
}

#[test]
fn lone_esc_reported() {
    let seqs = scan(b"end\x1b");
    assert_eq!(seqs.len(), 1);
    assert_eq!(seqs[0].kind, TerminalSequenceKind::Escape);
}

/// Cross-check the owned table against `libghostty-vt`'s fuzzed parser.
/// Gated behind `conformance` — that dep needs rust ≥1.90 + zig 0.15.2 +
/// a ghostty source fetch, so it stays out of the default test build.
#[cfg(feature = "conformance")]
mod ghostty_conformance {
    use super::*;

    fn ghostty_classify(payload: &[u8]) -> String {
        let mut parser = libghostty_vt::osc::Parser::new().expect("parser");
        for &b in payload {
            parser.next_byte(b);
        }
        let dbg = format!("{:?}", parser.end(0x07).command_type());
        let head = dbg
            .split(['(', '{'])
            .next()
            .unwrap_or(&dbg)
            .trim()
            .to_string();
        let mut out = String::new();
        for (i, c) in head.chars().enumerate() {
            if c.is_uppercase() && i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        }
        out
    }

    /// Payloads where our naming must match ghostty's classification.
    #[test]
    fn dangerous_osc_agrees_with_ghostty() {
        let cases: &[(&[u8], &str)] = &[
            (b"52;c;YQ==", "clipboard_contents"),
            (b"8;;https://evil.example", "hyperlink_start"),
            (b"8;;", "hyperlink_end"),
            (b"2;title", "change_window_title"),
            (b"1;icon", "change_window_icon"),
            (b"7;file:///etc", "report_pwd"),
            (b"9;3;tab", "conemu_change_tab_title"),
            (b"9;4;1;50", "conemu_progress_report"),
            (b"9;5", "conemu_wait_input"),
            (b"9;6;macro()", "conemu_gui_macro"),
            (b"9;7;cmd", "conemu_run_process"),
            (b"9;hi there", "show_desktop_notification"),
            (b"777;notify;t;b", "show_desktop_notification"),
            (b"133;A", "semantic_prompt"),
            (b"21;red=ff0000", "kitty_color_protocol"),
            (b"4;0;rgb:ff/00/00", "color_operation"),
        ];
        for (payload, want) in cases {
            let upstream = ghostty_classify(payload);
            assert_eq!(&upstream, want, "ghostty baseline for {payload:?}");
            assert_eq!(classify_osc(payload), *want, "ours for {payload:?}");
        }
    }

    /// Malformed/unrecognized selectors: ghostty's `end()` yields a null
    /// command here — the Rust wrapper *panics* on it, so upstream cannot
    /// even represent these inputs. Our contract is strictly stronger:
    /// they still produce a finding via `unclassified` (a control
    /// sequence in admitted text is reportable regardless of whether we
    /// can name it).
    #[test]
    fn unparseable_osc_maps_to_unclassified() {
        for payload in [&b"9999;x"[..], &b"abc;x"[..], &b""[..]] {
            assert_eq!(classify_osc(payload), "unclassified");
        }
        // bare "9" is still a valid OSC-9 notification, not malformed
        assert_eq!(classify_osc(b"9"), "show_desktop_notification");
    }
}
