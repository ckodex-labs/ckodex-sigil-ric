//! Detection half of the virtual window: per-cell overwrite events,
//! per-row pre-erase snapshots, and the finding synthesis at scroll
//! eviction / end-of-stream. `window.rs` owns grid + cursor state;
//! this module owns "did the display diverge".

use super::{VirtualWindow, COLS, NO_SRC, ROWS};
use sigil_core::types::ByteRange;

/// A cell-overwrite event: window position + stream offsets of what
/// was displayed and what replaced it.
pub(super) struct Overwrite {
    row: usize,
    col: usize,
    alt: bool,
    old: u8,
    old_src: usize,
    new: u8,
    new_pos: usize,
}

/// A row's content at first erase — compared against its final state.
pub(super) struct RowSnap {
    pub(super) text: Vec<u8>,
    pub(super) srcs: Vec<usize>,
}

impl VirtualWindow {
    /// Record a cell overwrite (old byte differs from the write).
    pub(super) fn record_overwrite(
        &mut self,
        row: usize,
        col: usize,
        old: u8,
        old_src: usize,
        new: u8,
        new_pos: usize,
    ) {
        self.overwrites.push(Overwrite {
            row,
            col,
            alt: self.on_alt,
            old,
            old_src,
            new,
            new_pos,
        });
    }

    /// Record a finding if a row's snapshot diverges from its content.
    pub(super) fn eval_row(&mut self, alt: bool, row: usize) {
        if let Some(f) = self.row_finding(alt, row) {
            self.findings.push(f);
        }
    }

    fn row_finding(&self, alt: bool, row: usize) -> Option<(ByteRange, String)> {
        let snap = self.snaps_ref(alt)[row].as_ref()?;
        let cells = &self.grid_ref(alt)[row * COLS..row * COLS + COLS];
        let new: Vec<u8> = cells.iter().map(|c| c.ch).collect();
        if new.iter().all(|&b| b == 0) {
            return None; // erased and left blank — plain erase
        }
        let (os, oe) = trim(&snap.text);
        let (ns, ne) = trim(&new);
        if os == oe || snap.text[os..oe] == new[ns..ne] {
            return None; // identical rewrite — no divergence
        }
        // Evidence span: earliest shown byte through the latest
        // rewritten byte, whichever representation came first.
        let srcs = snap.srcs[os..oe]
            .iter()
            .copied()
            .filter(|&s| s != NO_SRC)
            .chain(cells.iter().filter(|c| c.ch != 0).map(|c| c.src));
        let start = srcs.clone().min().unwrap_or(0);
        let end = srcs.max().map(|s| s + 1).unwrap_or(0);
        Some((
            ByteRange::new(start.min(end), end),
            format!(
                "repaint: \"{}\" → \"{}\"",
                clip(&snap.text[os..oe]),
                clip(&new[ns..ne])
            ),
        ))
    }

    /// Group pending overwrite events into contiguous same-row runs,
    /// one finding per run; called before any grid shift and at end.
    pub(super) fn flush_events(&mut self, alt: bool) {
        let (mut mine, rest): (Vec<Overwrite>, Vec<Overwrite>) =
            self.overwrites.drain(..).partition(|e| e.alt == alt);
        self.overwrites = rest;
        mine.sort_by_key(|e| (e.row, e.col));
        let mut run: Vec<Overwrite> = Vec::new();
        for e in mine {
            let contiguous = run
                .last()
                .is_some_and(|p| p.row == e.row && e.col <= p.col + 1);
            if !contiguous && !run.is_empty() {
                self.findings.push(run_detail(&run));
                run.clear();
            }
            run.push(e);
        }
        if !run.is_empty() {
            self.findings.push(run_detail(&run));
        }
    }

    /// Evaluate both grids, flush events, return all findings.
    pub(crate) fn finish(&mut self) -> Vec<(ByteRange, String)> {
        for alt in [false, true] {
            for r in 0..ROWS {
                self.eval_row(alt, r);
            }
            self.flush_events(alt);
        }
        std::mem::take(&mut self.findings)
    }
}

/// First/last non-blank extent of a row buffer.
fn trim(v: &[u8]) -> (usize, usize) {
    let s = v.iter().position(|&b| b != 0).unwrap_or(0);
    let e = v.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(s);
    (s, e)
}

fn run_detail(run: &[Overwrite]) -> (ByteRange, String) {
    let old: Vec<u8> = run.iter().map(|e| e.old).collect();
    let new: Vec<u8> = run.iter().map(|e| e.new).collect();
    let start = run
        .iter()
        .map(|e| e.old_src.min(e.new_pos))
        .min()
        .unwrap_or(0);
    let end = run
        .iter()
        .map(|e| e.old_src.max(e.new_pos) + 1)
        .max()
        .unwrap_or(0);
    (
        ByteRange::new(start, end),
        format!("repaint: \"{}\" → \"{}\"", clip(&old), clip(&new)),
    )
}

/// Escape non-printable bytes for evidence text; cap at 48 bytes.
fn clip(bs: &[u8]) -> String {
    let mut s = String::new();
    for &b in bs.iter().take(48) {
        match b {
            0x20..=0x7E => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    if bs.len() > 48 {
        s.push('…');
    }
    s
}
