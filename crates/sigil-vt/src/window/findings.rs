//! Detection half of the virtual window: per-cell overwrite events,
//! per-row pre-erase snapshots, the non-ASCII degrade quarantine, and
//! finding synthesis at epoch boundaries (erase), scroll eviction and
//! end-of-stream. `window.rs` owns grid + cursor state; this module
//! owns "did the display diverge".

use super::{VirtualWindow, COLS, NO_SRC, ROWS};
use sigil_core::types::ByteRange;

/// Findings are bounded: beyond the cap the first dropped range is
/// kept and reported once as a `window_degraded` marker — suppression
/// is itself evidence, never silent.
const MAX_FINDINGS: usize = 128;

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

/// Per-row detection state; travels with its row on line shifts and
/// scrolls so snapshots stay aligned with the content they describe.
#[derive(Default)]
pub(super) struct RowState {
    pub(super) snap: Option<RowSnap>,
    /// A byte ≥0x80 was written here — glyph cells desync from byte
    /// cells, so precise repaint evidence on this row is unreliable.
    pub(super) nonascii: bool,
    /// The degraded finding for the current flag epoch already fired.
    pub(super) deg_fired: bool,
}

impl VirtualWindow {
    /// Bounded find push — overflow is remembered, not dropped silent.
    pub(super) fn push_finding(&mut self, f: (ByteRange, &'static str, String)) {
        if self.findings.len() < MAX_FINDINGS {
            self.findings.push(f);
        } else if self.overflow.is_none() {
            self.overflow = Some(f.0);
        }
    }

    /// Record a cell overwrite (old byte differs from the write). On a
    /// non-ASCII-flagged row the cell position may be wrong, so the
    /// precise event is quarantined into a `window_degraded` finding.
    pub(super) fn record_overwrite(
        &mut self,
        row: usize,
        col: usize,
        old: u8,
        old_src: usize,
        new: u8,
        new_pos: usize,
    ) {
        let alt = self.on_alt;
        if self.rows_ref(alt)[row].nonascii {
            if !self.rows_ref(alt)[row].deg_fired {
                self.rows_at(alt)[row].deg_fired = true;
                self.push_finding((
                    ByteRange::new(old_src.min(new_pos), new_pos + 1),
                    "window_degraded",
                    "non-ASCII content overwritten — byte-cell tracking unreliable".into(),
                ));
            }
            return;
        }
        self.overwrites.push(Overwrite {
            row,
            col,
            alt,
            old,
            old_src,
            new,
            new_pos,
        });
    }

    /// Evaluate a row at an epoch boundary: flagged rows degrade,
    /// otherwise compare the pre-erase snapshot against the content
    /// shown since (epoch semantics — every erase re-arms the check).
    pub(super) fn eval_row(&mut self, alt: bool, row: usize) {
        if self.rows_ref(alt)[row].nonascii {
            self.eval_degraded(alt, row);
            return;
        }
        if let Some(f) = self.row_finding(alt, row) {
            self.push_finding(f);
        }
    }

    /// `window_degraded` for a flagged row at an erase/scroll eval —
    /// once per flag epoch (the flag clears when the row goes blank).
    fn eval_degraded(&mut self, alt: bool, row: usize) {
        if self.rows_ref(alt)[row].deg_fired {
            return;
        }
        self.rows_at(alt)[row].deg_fired = true;
        self.push_finding((
            self.row_src_span(alt, row),
            "window_degraded",
            "non-ASCII content erased/scrolled — byte-cell tracking unreliable".into(),
        ));
    }

    /// Evidence span over a row's byte sources: snapshot srcs plus the
    /// live cells' srcs, earliest through latest written byte.
    fn row_src_span(&self, alt: bool, row: usize) -> ByteRange {
        let cells = &self.grid_ref(alt)[row * COLS..row * COLS + COLS];
        let snap_srcs = self.rows_ref(alt)[row]
            .snap
            .as_ref()
            .map(|s| s.srcs.as_slice())
            .unwrap_or(&[]);
        let mut lo = usize::MAX;
        let mut hi = 0;
        for s in snap_srcs
            .iter()
            .copied()
            .chain(cells.iter().filter(|c| c.ch != 0).map(|c| c.src))
            .filter(|&s| s != NO_SRC)
        {
            lo = lo.min(s);
            hi = hi.max(s + 1);
        }
        ByteRange::new(lo.min(hi), hi)
    }

    fn row_finding(&self, alt: bool, row: usize) -> Option<(ByteRange, &'static str, String)> {
        let snap = self.rows_ref(alt)[row].snap.as_ref()?;
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
            "repaint_overwrite",
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
                let f = run_detail(&run);
                self.push_finding(f);
                run.clear();
            }
            run.push(e);
        }
        if !run.is_empty() {
            let f = run_detail(&run);
            self.push_finding(f);
        }
    }

    /// Evaluate both grids, flush events, return all findings.
    pub(crate) fn finish(&mut self) -> Vec<(ByteRange, &'static str, String)> {
        for alt in [false, true] {
            for r in 0..ROWS {
                self.eval_row(alt, r);
            }
            self.flush_events(alt);
        }
        if let Some(r) = self.overflow.take() {
            self.push_finding((
                r,
                "window_degraded",
                "finding cap reached — further divergence suppressed".into(),
            ));
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

fn run_detail(run: &[Overwrite]) -> (ByteRange, &'static str, String) {
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
        "repaint_overwrite",
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
