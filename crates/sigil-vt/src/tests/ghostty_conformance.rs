//! Cross-check the owned table and window model against
//! `libghostty-vt`'s fuzzed parser and real `Terminal`. Gated behind
//! `conformance` — that dep needs rust ≥1.90 + zig 0.15.2 + a ghostty
//! source fetch, so it stays out of the default test build.

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

/// Display-state parity: run identical byte streams through our
/// `VirtualWindow` and ghostty's real `Terminal`, assert the final
/// active-area grids match cell-for-cell. ASCII-only — our model is
/// byte-granular (documented limit), ghostty is glyph-exact.
mod window_parity {
    use crate::window::{COLS, ROWS};
    use libghostty_vt::terminal::{Point, PointCoordinate};
    use libghostty_vt::{Terminal, TerminalOptions};

    fn ghostty_cells(input: &[u8]) -> Vec<u32> {
        let mut t = Terminal::new(TerminalOptions {
            cols: COLS as u16,
            rows: ROWS as u16,
            max_scrollback: 0,
        })
        .expect("terminal");
        t.vt_write(input);
        let mut out = vec![0u32; COLS * ROWS];
        for y in 0..ROWS as u32 {
            for x in 0..COLS as u16 {
                out[y as usize * COLS + x as usize] = t
                    .grid_ref(Point::Active(PointCoordinate { x, y }))
                    .and_then(|g| g.cell())
                    .map(|c| {
                        if c.has_text().unwrap_or(false) {
                            c.codepoint().unwrap_or(0)
                        } else {
                            0
                        }
                    })
                    .unwrap_or(0);
            }
        }
        out
    }

    fn our_cells(input: &[u8]) -> Vec<u32> {
        let w = crate::scan_window(input);
        (0..ROWS * COLS)
            .map(|i| w.cell_byte(i / COLS, i % COLS) as u32)
            .collect()
    }

    /// Both grids, rendered as strings of differing cells.
    fn divergence(input: &[u8]) -> String {
        let (ours, theirs) = (our_cells(input), ghostty_cells(input));
        let mut d = String::new();
        for (i, (a, b)) in ours.iter().zip(&theirs).enumerate() {
            if a != b {
                let at = (i / COLS, i % COLS);
                let (a, b) = (*a as u8 as char, *b as u8 as char);
                d.push_str(&format!(" r{at:?} ours={a:?} ghostty={b:?}"));
            }
        }
        d
    }

    /// Every op the window claims to model, compared cell-for-cell
    /// against the real emulator.
    #[test]
    fn modeled_ops_match_ghostty() {
        let cases: &[&[u8]] = &[
            b"hello",
            b"line1\nline2\nline3",
            b"abc\r\nXY",
            b"a\tb\tc",
            b"x\x1b[197Gt\tz",                    // tab clamps at right margin
            b"abc\x08X",                          // BS overstrike
            b"abc\x1b[2DXY",                      // CUB overwrite
            b"one\ntwo\x1b[Aover",                // CUA + write
            b"one\ntwo\x1b[1;5H@",                // CUP absolute
            b"abc\x1b[3G\x1b[2Gq",                // CHA
            b"abc\x1b[2dq",                       // VPA
            b"a\x1b[10Eq",                        // CNL mid-screen
            b"abc\x1b[2Fq",                       // CPL
            b"ab\x1b[Kcd",                        // EL right
            b"ab\x1b[2Kcd",                       // EL all
            b"ab\x1b[1Kz",                        // EL left
            b"abcdef\x1b[3D\x1b[2P",              // DCH
            b"abc\x1b[D\x1b[@z",                  // ICH
            b"abc\x1b[2Xz",                       // ECH
            b"r1\nr2\nr3\nr4\x1b[3A\x1b[M",       // DL
            b"r1\nr2\nr3\x1b[2A\x1b[Lx",          // IL
            b"a\nb\nc\x1b[2S",                    // SU
            b"a\nb\nc\x1b[2T",                    // SD
            b"fill\nup\n\x1b[2Jx",                // ED all
            b"abc\x1b[sXYZ\x1b[u!",               // CSI s/u save+restore
            b"abc\x1b7XY\x1b8!",                  // ESC 7/8 DECSC/DECRC
            b"main\x1b[?1049halt stuff",          // 1049 entry: cursor copies
            b"main\x1b[?1049halt\x1b[?1049lback", // round trip restores
            b"main\x1b[?47halt",                  // 47: swap only
            b"pre\x1b[?1047hXY",                  // 1047 entry
            b"ab\x1b[?1047hcd\x1b[?1047lef",      // 1047 erases alt on exit
            // Raw C1 bytes (0x84/0x85/0x8D) are NOT display ops:
            // ghostty renders them as glyphs — we ignore them.
            b"a\x1bDb",                    // ESC D = IND
            b"a\x1bEb",                    // ESC E = NEL
            b"a\x1bMb",                    // ESC M = RI mid-screen
            b"\x1bMtop",                   // RI at top = scroll down
            b"r1\nr2\x1b[1A\x1b[2KFORGED", // displaced repaint
            b"run: apt install\x1b[2K\x1b[Gran: rm -rf /",
        ];
        for input in cases {
            let d = divergence(input);
            assert!(d.is_empty(), "grid divergence on {input:?}:{d}");
        }
    }

    /// CNL at the bottom margin clamps; only LF scrolls.
    #[test]
    fn cnl_does_not_scroll() {
        let mut input = b"x".to_vec();
        input.extend_from_slice(&[b'\n'; 47]); // cursor at last row
        input.extend_from_slice(b"\x1b[5Ez");
        let d = divergence(&input);
        assert!(d.is_empty(), "CNL scroll divergence:{d}");
    }

    /// Rows scrolled past the top are evicted identically.
    #[test]
    fn scroll_eviction_matches() {
        let mut input = Vec::new();
        for i in 0..60u8 {
            input.extend_from_slice(format!("row{i}\n").as_bytes());
        }
        input.extend_from_slice(b"last");
        let d = divergence(&input);
        assert!(d.is_empty(), "scroll divergence:{d}");
    }

    /// Autowrap past the last column lands identically.
    #[test]
    fn wrap_matches() {
        let mut input = vec![b'x'; COLS + 10];
        input.extend_from_slice(b"\nend");
        let d = divergence(&input);
        assert!(d.is_empty(), "wrap divergence:{d}");
    }

    /// Pending-wrap state: every erase/shift op clears it via
    /// `cursorResetWrap` (next write stays on the row); scroll
    /// preserves it (next write wraps). CR/LF/cursor moves clear.
    #[test]
    fn pending_wrap_edges() {
        let full = vec![b'x'; COLS];
        for tail in [
            &b"\x1b[Kz"[..],  // EL clears -> z at (0,199)
            &b"\x1b[2Jz"[..], // ED clears
            &b"\x1b[5Xz"[..], // ECH clears
            &b"\x1b[Pz"[..],  // DCH clears
            &b"\x1b[@z"[..],  // ICH clears
            &b"\rz"[..],      // CR clears
            &b"\nz"[..],      // LF clears
            &b"\x1b[2Sz"[..], // SU preserves -> z wraps to (1,0)
        ] {
            let mut input = full.clone();
            input.extend_from_slice(tail);
            let d = divergence(&input);
            assert!(d.is_empty(), "pending-wrap divergence on {tail:?}:{d}");
        }
    }
}
