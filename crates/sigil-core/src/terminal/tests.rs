use super::*;

fn seq(kind: TerminalSequenceKind, start: usize, end: usize, detail: &str) -> TerminalSequence {
    TerminalSequence {
        byte_range: ByteRange::new(start, end),
        kind,
        detail: detail.to_string(),
    }
}

fn detect(seqs: Vec<TerminalSequence>) -> (Vec<ScanFinding>, TerminalReport) {
    detect_terminal_escapes(&seqs, "fake-scanner", 512)
}

#[test]
fn clipboard_write_is_high() {
    let (findings, report) = detect(vec![seq(
        TerminalSequenceKind::Osc {
            command: "clipboard_contents".to_string(),
        },
        3,
        18,
        "OSC 52",
    )]);
    assert_eq!(report.status, TerminalStatus::Evaluated);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].detectors, vec![DetectorId::TerminalEscape]);
    assert!(findings[0].evidence.contains("clipboard-write"));
}

#[test]
fn hyperlink_osc_is_medium() {
    let (findings, _) = detect(vec![seq(
        TerminalSequenceKind::Osc {
            command: "hyperlink_start".to_string(),
        },
        0,
        30,
        "",
    )]);
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].evidence.contains("hyperlink"));
}

#[test]
fn title_and_notification_spoofing() {
    for command in [
        "change_window_title",
        "show_desktop_notification",
        "report_pwd",
    ] {
        let (findings, _) = detect(vec![seq(
            TerminalSequenceKind::Osc {
                command: command.to_string(),
            },
            0,
            10,
            "",
        )]);
        assert_eq!(
            findings[0].severity,
            Severity::Medium,
            "command {command} should be Medium"
        );
    }
}

#[test]
fn dcs_is_high_csi_is_low() {
    let (findings, _) = detect(vec![
        seq(TerminalSequenceKind::Dcs, 0, 5, ""),
        seq(TerminalSequenceKind::Csi, 5, 10, ""),
        seq(TerminalSequenceKind::Escape, 10, 12, ""),
    ]);
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[1].severity, Severity::Low);
    assert_eq!(findings[2].severity, Severity::Low);
}

#[test]
fn extension_channels_are_high() {
    for command in [
        "rxvt_extension",
        "iterm2_extension",
        "kitty_clipboard_protocol",
        "conemu_run_process",
        "conemu_gui_macro",
    ] {
        let (findings, _) = detect(vec![seq(
            TerminalSequenceKind::Osc {
                command: command.to_string(),
            },
            0,
            10,
            "",
        )]);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "command {command} should be High"
        );
    }
}

#[test]
fn mode_and_drop_oscs_are_medium() {
    for command in [
        "kitty_dnd_protocol",
        "conemu_xterm_emulation",
        "conemu_show_message_box",
    ] {
        let (findings, _) = detect(vec![seq(
            TerminalSequenceKind::Osc {
                command: command.to_string(),
            },
            0,
            10,
            "",
        )]);
        assert_eq!(
            findings[0].severity,
            Severity::Medium,
            "command {command} should be Medium"
        );
    }
}

#[test]
fn unclassified_osc_is_low() {
    let (findings, _) = detect(vec![seq(
        TerminalSequenceKind::Osc {
            command: "color_operation".to_string(),
        },
        0,
        10,
        "",
    )]);
    assert_eq!(findings[0].severity, Severity::Low);
}

#[test]
fn max_sequences_caps_findings() {
    let seqs = vec![seq(TerminalSequenceKind::Csi, 0, 4, ""); 10];
    let (findings, report) = detect_terminal_escapes(&seqs, "fake", 3);
    assert_eq!(findings.len(), 3);
    assert_eq!(report.sequence_count, 10);
}

#[test]
fn empty_scan_evaluates_clean() {
    let (findings, report) = detect(Vec::new());
    assert!(findings.is_empty());
    assert_eq!(report.status, TerminalStatus::Evaluated);
    assert_eq!(report.sequence_count, 0);
}

#[test]
fn skipped_and_failed_reports_are_visible() {
    let skipped = TerminalReport::skipped("ghostty", "no scanner injected");
    assert!(matches!(skipped.status, TerminalStatus::Skipped { .. }));
    let failed = TerminalReport::failed("ghostty", "parser blew up");
    assert!(matches!(failed.status, TerminalStatus::Failed { .. }));
}
