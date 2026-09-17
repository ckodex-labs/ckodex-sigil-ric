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
    // Unknown CSI decodes `csi_unknown` AND quarantines as unmodeled.
    let seqs = scan(b"\x1b[ZZ");
    match &seqs[0].kind {
        TerminalSequenceKind::Csi { command } => assert_eq!(command, "csi_unknown"),
        other => panic!("expected Csi, got {other:?}"),
    }
    assert!(matches!(
        &seqs[1].kind,
        TerminalSequenceKind::Pattern { name } if name == "window_unmodeled"
    ));
}

fn pattern(seqs: &[TerminalSequence]) -> &TerminalSequence {
    seqs.iter()
        .find(|s| matches!(&s.kind, TerminalSequenceKind::Pattern { .. }))
        .expect("repaint pattern")
}

fn no_pattern(seqs: &[TerminalSequence]) -> bool {
    !seqs
        .iter()
        .any(|s| matches!(&s.kind, TerminalSequenceKind::Pattern { .. }))
}

#[test]
fn repaint_overwrite_pattern_detected() {
    // erase-line + rewind + rewrite — canonical repaint idiom. The
    // window compares the row's pre-erase content against what it
    // ends showing, so evidence carries both representations.
    let seqs = scan(b"ran: apt install\x1b[2K\x1b[Gran: apt update");
    let p = pattern(&seqs);
    assert_eq!(
        p.kind,
        TerminalSequenceKind::Pattern {
            name: "repaint_overwrite".into()
        }
    );
    // span: first shown byte (0) through the forged run's last byte
    assert_eq!(p.byte_range, ByteRange::new(0, 38));
    assert_eq!(
        p.detail,
        "repaint: \"ran: apt install\" → \"ran: apt update\""
    );
}

#[test]
fn repaint_displaced_rewrite_detected() {
    // cursor-up + erase + rewrite at a different column — FORGED lands
    // on untouched cells while the erased "line1" diverges; the
    // per-row snapshot path catches what per-cell compares cannot.
    let seqs = scan(b"line1\nline2\x1b[1A\x1b[2KFORGED");
    let p = pattern(&seqs);
    assert_eq!(p.detail, "repaint: \"line1\" → \"FORGED\"");
}

#[test]
fn repaint_cursor_back_overwrite() {
    // no erase needed — writing different bytes over shown cells
    // diverges (cursor-back alone opens the window)
    let seqs = scan(b"abc\x1b[3DXY");
    let p = pattern(&seqs);
    assert_eq!(p.detail, "repaint: \"ab\" → \"XY\"");
    assert_eq!(p.byte_range, ByteRange::new(0, 9));
}

#[test]
fn repaint_backspace_overstrike() {
    let seqs = scan(b"ab\x08X");
    let p = pattern(&seqs);
    assert_eq!(p.detail, "repaint: \"b\" → \"X\"");
    assert_eq!(p.byte_range, ByteRange::new(1, 4));
}

#[test]
fn repaint_survives_scroll_eviction() {
    // the divergent row scrolls out of the 48-row window — evaluated
    // at eviction, the finding is still reported
    let mut input = b"shown\x1b[2K\rforged".to_vec();
    input.extend(std::iter::repeat_n(b'\n', 60));
    let seqs = scan(&input);
    let p = pattern(&seqs);
    assert_eq!(p.detail, "repaint: \"shown\" → \"forged\"");
}

#[test]
fn window_bounded_under_long_stream() {
    // ~1.2MB of lines with a repaint at the start — the window is
    // bounded, the scan completes, the evicted finding survives
    let mut input = b"shown\x1b[2K\rforged".to_vec();
    for _ in 0..120_000 {
        input.extend_from_slice(b"more text\n");
    }
    let seqs = scan(&input);
    assert!(seqs.iter().any(
        |s| matches!(&s.kind, TerminalSequenceKind::Pattern { name } if name == "repaint_overwrite")
    ));
}

#[test]
fn repaint_pattern_negatives() {
    // erase with no following text — capability only, no pattern
    assert!(no_pattern(&scan(b"text\x1b[2K")));
    // erase then newline then text — the erased row ends blank
    assert!(no_pattern(&scan(b"x\x1b[2K\ny")));
    // SGR color then text — not a repaint trigger
    assert!(no_pattern(&scan(b"a\x1b[31mred")));
    // erase of an already-blank row, then text — nothing diverged
    assert!(no_pattern(&scan(b"\x1b[2Khello")));
    // cursor-back + byte-identical rewrite — net-zero divergence
    assert!(no_pattern(&scan(b"abc\x1b[3Dabc")));
    // erase + byte-identical rewrite — display restored exactly
    assert!(no_pattern(&scan(b"ab\x1b[2K\rab")));
}

fn named_pattern<'a>(seqs: &'a [TerminalSequence], want: &str) -> &'a TerminalSequence {
    seqs.iter()
        .find(|s| matches!(&s.kind, TerminalSequenceKind::Pattern { name } if name == want))
        .unwrap_or_else(|| panic!("pattern {want} in {seqs:?}"))
}

fn pattern_names(seqs: &[TerminalSequence]) -> Vec<&str> {
    seqs.iter()
        .filter_map(|s| match &s.kind {
            TerminalSequenceKind::Pattern { name } => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn repaint_epoch_evasion_caught() {
    // A → erase → B → erase → A: the transient B was displayed, but
    // the final row equals the first snapshot — a first-snapshot-only
    // model stays silent. Per-epoch eval catches both divergent
    // transitions (A→B at the second erase, B→A at end-of-stream).
    let seqs = scan(b"A\x1b[2K\rB\x1b[2K\rA");
    assert_eq!(
        pattern_names(&seqs),
        ["repaint_overwrite", "repaint_overwrite"]
    );
}

#[test]
fn nonascii_row_rewrite_is_degraded() {
    // 0xC3 0xBC = 'ü': two byte-cells where a terminal sees one glyph
    // — positions desync, so the overwrite is quarantined, not
    // reported as a precise repaint.
    let seqs = scan(b"\xc3\xbcab\x1b[4DXY");
    let names = pattern_names(&seqs);
    assert_eq!(names, ["window_degraded"]);
    assert_eq!(
        named_pattern(&seqs, "window_degraded").detail,
        "non-ASCII content overwritten — byte-cell tracking unreliable"
    );
}

#[test]
fn nonascii_flag_clears_when_row_blanked() {
    // after the flagged row is erased blank, later ASCII-only
    // divergence reports precisely again
    let seqs = scan(b"\xc3\xbc\x1b[2K\rab\x1b[2DXY");
    let names = pattern_names(&seqs);
    assert!(names.contains(&"window_degraded"), "{names:?}");
    assert!(names.contains(&"repaint_overwrite"), "{names:?}");
}

#[test]
fn ris_resets_display_but_keeps_prior_findings() {
    // repaint before RIS still reports; content after RIS starts
    // from a clean screen so nothing diverges
    let seqs = scan(b"ab\x1b[2K\rXY\x1bczz");
    assert_eq!(pattern_names(&seqs), ["repaint_overwrite"]);
}

#[test]
fn insert_mode_shifts_instead_of_overwriting() {
    // IRM on: X/Y push the row tail right — no cell is overwritten,
    // so no repaint; the same bytes with IRM off diverge
    assert_eq!(
        pattern_names(&scan(b"abcd\x1b[4D\x1b[4hXY\x1b[4l")),
        Vec::<&str>::new()
    );
    assert_eq!(
        pattern_names(&scan(b"abcd\x1b[4DXY")),
        ["repaint_overwrite"]
    );
}

#[test]
fn decawm_off_overstrikes_last_cell() {
    // DECAWM off: no pending wrap — writes at the last column stack
    // onto the same cell (each an overwrite)
    let mut input = vec![b'x'; 200];
    input.extend_from_slice(b"\x1b[?7lyz");
    let seqs = scan(&input);
    let p = pattern(&seqs);
    assert_eq!(p.detail, "repaint: \"xy\" → \"yz\"");
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

/// Quarantine + mode-gate tests — `tests/quarantine.rs`.
mod quarantine;

/// Cross-checks against `libghostty-vt`'s fuzzed parser and real
/// `Terminal` — see `tests/ghostty_conformance.rs`. Gated behind
/// `conformance` (needs rust ≥1.90 + zig 0.15.2 + a ghostty source
/// fetch), so it stays out of the default test build.
#[cfg(feature = "conformance")]
mod ghostty_conformance;
