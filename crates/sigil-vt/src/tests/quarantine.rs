//! Quarantine contract: ops the window cannot replay faithfully are
//! findings, not silence — including ops whose meaning shifts under
//! private modes (`?69` DECLRMM, `?6` DECOM).

use super::*;

#[test]
fn unmodeled_csi_ops_quarantined() {
    // Display-state modes the window does not replay — each must
    // surface as a finding rather than silently desync the model.
    for input in [
        &b"\x1b[?6h"[..],  // origin mode — shifts CUP coordinates
        &b"\x1b[?69h"[..], // DECLRMM — left/right margins
        &b"\x1b[20h"[..],  // LNM — LF starts implying CR
        &b"\x1b[?3h"[..],  // 132-col mode
        &b"\x1b[ZZ"[..],   // unrecognized final
    ] {
        assert_eq!(
            pattern_names(&scan(input)),
            ["window_unmodeled"],
            "{input:?}"
        );
    }
    // Modeled ops and visual-only modes stay quiet.
    for input in [
        &b"\x1b[4h"[..],   // insert mode — modeled
        &b"\x1b[?7l"[..],  // DECAWM off — modeled
        &b"\x1b[2;5r"[..], // DECSTBM — modeled
        &b"\x1b[?25h"[..], // cursor visibility — no-op
        &b"\x1b[?5h"[..],  // reverse video — visual only
        &b"\x1b[31m"[..],  // SGR — no-op for positions
    ] {
        assert_eq!(pattern_names(&scan(input)), Vec::<&str>::new(), "{input:?}");
    }
}

#[test]
fn unmodeled_esc_ops_quarantined() {
    // charset select: ESC ( 0 — the '0' is the selector, not text;
    // it must not leak into the window as a printable byte
    let seqs = scan(b"\x1b(0abc");
    assert_eq!(pattern_names(&seqs), ["window_unmodeled"], "{seqs:?}");
    // unmodeled single-ESC final (ESC F = cursor to lower-left)
    assert_eq!(pattern_names(&scan(b"\x1bF")), ["window_unmodeled"]);
    // modeled singles stay quiet
    assert_eq!(pattern_names(&scan(b"\x1bc")), Vec::<&str>::new()); // RIS
    assert_eq!(pattern_names(&scan(b"\x1bD")), Vec::<&str>::new()); // IND
}

#[test]
fn declrmm_redefines_csi_s() {
    // xterm ctlseqs: `CSI s` is SCOSC only while DECLRMM is off —
    // under `?69h` the same bytes are DECSLRM (left/right margins).
    // Quarantined, not misapplied as a save: `CSI u` then restores
    // the default (0,0) slot, so 'B' overwrites 'A' → repaint fires.
    // Had `s` been misread as a save, `u` would land at (0,3) and the
    // divergence would go unreported.
    let seqs = scan(b"A\x1b[?69h\x1b[3C\x1b[s\x1b[uB");
    let names = pattern_names(&seqs);
    assert_eq!(
        names.iter().filter(|&&n| n == "window_unmodeled").count(),
        2,
        "{names:?}"
    );
    assert_eq!(names.last(), Some(&"repaint_overwrite"), "{names:?}");
    // `?69l` restores the save-cursor meaning — modeled again.
    let seqs = scan(b"A\x1b[?69h\x1b[?69l\x1b[3C\x1b[s\x1b[uB");
    let names = pattern_names(&seqs);
    assert_eq!(
        names.iter().filter(|&&n| n == "repaint_overwrite").count(),
        0,
        "{names:?}"
    );
}

#[test]
fn decom_quarantines_cursor_addressing() {
    // Under `?6h`, CUP/HVP and VPA address the scroll region, not the
    // screen — gated out of the modeled set, not applied absolutely.
    for input in [
        &b"\x1b[?6h\x1b[5;5H"[..], // CUP → origin-relative
        &b"\x1b[?6h\x1b[5;5f"[..], // HVP — same gate
        &b"\x1b[?6h\x1b[5d"[..],   // VPA → origin-relative
    ] {
        let seqs = scan(input);
        let names = pattern_names(&seqs);
        assert_eq!(
            names.iter().filter(|&&n| n == "window_unmodeled").count(),
            2,
            "{input:?}"
        );
    }
    // `?6l` restores absolute addressing — CUP is modeled again.
    let seqs = scan(b"\x1b[?6h\x1b[?6l\x1b[5;5H");
    assert_eq!(
        pattern_names(&seqs)
            .iter()
            .filter(|&&n| n == "window_unmodeled")
            .count(),
        2
    );
}

#[test]
fn decrc_restores_decom_state() {
    // DECSC/DECRC carry origin mode (ghostty SavedCursor.origin):
    // `?6h` → save → `?6l` → restore → CUP is region-relative again.
    let seqs = scan(b"\x1b[?6h\x1b7\x1b[?6l\x1b8\x1b[5;5H");
    let names = pattern_names(&seqs);
    assert_eq!(
        names.iter().filter(|&&n| n == "window_unmodeled").count(),
        3, // ?6h, ?6l, origin-gated CUP
        "{names:?}"
    );
}
