//! Bounded virtual window — a sliding-screen model of how a terminal
//! would interpret the byte stream.
//!
//! Not an emulator: just enough state (a bounded cell grid, cursor,
//! alternate screen, per-row pre-erase snapshots) to detect *semantic*
//! divergence — cells overwritten by different bytes, or rows erased
//! and repainted with different text. That is the display-vs-stream
//! divergence `repaint_overwrite` flags.
//!
//! Two bounded detection paths:
//! - per-cell overwrites: a byte lands on a cell showing a different
//!   byte (cursor-back rewrites, BS overstrike);
//! - per-row snapshots: an erase records the row's prior text; if the
//!   row ends non-blank and different, the repaint displaced content.
//!   A row left blank after erase is a plain erase: silent.
//!
//! Limits (documented, not hidden): byte-granular cells (not glyph-
//! exact); no scrollback — rows are evaluated at scroll eviction;
//! DECAWM autowrap; raw-stream semantics (LF ≠ CR+LF); snapshots keep
//! the first pre-erase state per row.

use sigil_core::types::ByteRange;

/// Window geometry: a sliding 200×48 grid. Anything older has already
/// scrolled off — replaying beyond that is emulator territory, which
/// the runtime path deliberately does not enter.
const COLS: usize = 200;
const ROWS: usize = 48;

const NO_SRC: usize = usize::MAX;

/// A cell-overwrite event: window position + stream offsets of what
/// was displayed and what replaced it.
#[derive(Clone, Copy, Debug)]
struct Overwrite {
    row: usize,
    col: usize,
    alt: bool,
    old: u8,
    old_src: usize,
    new: u8,
    new_pos: usize,
}

/// A row's content at first erase — compared against its final state.
struct RowSnap {
    text: Vec<u8>,
    srcs: Vec<usize>,
}

#[derive(Clone, Copy, Default)]
struct Cell {
    ch: u8,     // current byte (0 = blank)
    src: usize, // stream offset that wrote it
}

pub(crate) struct VirtualWindow {
    cells: Vec<Cell>,
    alt: Vec<Cell>,
    on_alt: bool,
    row: usize,
    col: usize,
    saved: (usize, usize),
    saved_alt: (usize, usize),
    snaps: Vec<Option<RowSnap>>,
    alt_snaps: Vec<Option<RowSnap>>,
    overwrites: Vec<Overwrite>,
    findings: Vec<(ByteRange, String)>,
}

impl VirtualWindow {
    pub(crate) fn new() -> Self {
        Self {
            cells: vec![Cell::default(); ROWS * COLS],
            alt: vec![Cell::default(); ROWS * COLS],
            on_alt: false,
            row: 0,
            col: 0,
            saved: (0, 0),
            saved_alt: (0, 0),
            snaps: std::iter::repeat_with(|| None).take(ROWS).collect(),
            alt_snaps: std::iter::repeat_with(|| None).take(ROWS).collect(),
            overwrites: Vec::new(),
            findings: Vec::new(),
        }
    }

    fn grid(&mut self) -> &mut Vec<Cell> {
        if self.on_alt {
            &mut self.alt
        } else {
            &mut self.cells
        }
    }

    fn grid_ref(&self, alt: bool) -> &[Cell] {
        if alt {
            &self.alt
        } else {
            &self.cells
        }
    }

    fn snaps_mut(&mut self) -> &mut Vec<Option<RowSnap>> {
        if self.on_alt {
            &mut self.alt_snaps
        } else {
            &mut self.snaps
        }
    }

    fn snaps_ref(&self, alt: bool) -> &[Option<RowSnap>] {
        if alt {
            &self.alt_snaps
        } else {
            &self.snaps
        }
    }

    /// Write a printable byte at the cursor (DECAWM wrap); fires an
    /// overwrite event when the cell showed a different byte.
    pub(crate) fn write(&mut self, b: u8, pos: usize) {
        if self.col >= COLS {
            self.col = 0;
            self.advance_row(1);
        }
        let idx = self.row * COLS + self.col;
        let (old, old_src) = {
            let cell = &mut self.grid()[idx];
            let o = (cell.ch, cell.src);
            cell.ch = b;
            cell.src = pos;
            o
        };
        if old != 0 && old != b && old_src != NO_SRC {
            self.overwrites.push(Overwrite {
                row: self.row,
                col: self.col,
                alt: self.on_alt,
                old,
                old_src,
                new: b,
                new_pos: pos,
            });
        }
        self.col += 1;
    }

    /// LF/VT/FF move down only — CR is the column reset.
    pub(crate) fn line_feed(&mut self) {
        self.advance_row(1);
    }

    /// NEL (C1 0x85): down one row and column zero.
    pub(crate) fn next_line(&mut self) {
        self.col = 0;
        self.advance_row(1);
    }

    pub(crate) fn carriage_return(&mut self) {
        self.col = 0;
    }

    pub(crate) fn tab(&mut self) {
        self.col = (self.col + 8) & !7;
    }

    /// BS (0x08) moves back one — the classic overstrike enabler.
    pub(crate) fn backspace(&mut self) {
        self.col = self.col.saturating_sub(1);
    }

    fn advance_row(&mut self, n: usize) {
        self.row = self.row.saturating_add(n);
        if self.row >= ROWS {
            self.slide(self.row - ROWS + 1, false);
            self.row = ROWS - 1;
        }
    }

    /// Evaluate rows leaving the window, flush stale events, shift.
    /// `down` inserts blanks at top (SU drops top rows; SD bottom).
    fn slide(&mut self, n: usize, down: bool) {
        let n = n.min(ROWS);
        let alt = self.on_alt;
        let evicted = if down { ROWS - n..ROWS } else { 0..n };
        for r in evicted {
            self.eval_row(alt, r);
        }
        self.flush_events(alt);
        if down {
            self.grid()
                .splice(0..0, std::iter::repeat(Cell::default()).take(n * COLS));
            self.grid().truncate(ROWS * COLS);
            self.snaps_mut()
                .splice(0..0, std::iter::repeat_with(|| None).take(n));
            self.snaps_mut().truncate(ROWS);
        } else {
            self.grid().drain(0..n * COLS);
            self.grid()
                .extend(std::iter::repeat(Cell::default()).take(n * COLS));
            self.snaps_mut().drain(0..n);
            self.snaps_mut()
                .extend(std::iter::repeat_with(|| None).take(n));
        }
    }

    /// Clear cells in [start, end) into their row snapshots.
    fn erase_range(&mut self, start: usize, end: usize) {
        let len = self.grid().len();
        let end = end.min(len);
        for idx in start.min(end)..end {
            let ch = self.grid()[idx].ch;
            if ch == 0 {
                continue;
            }
            let (row, col) = (idx / COLS, idx % COLS);
            let src = self.grid()[idx].src;
            let snap = self.snaps_mut()[row].get_or_insert_with(|| RowSnap {
                text: vec![0; COLS],
                srcs: vec![NO_SRC; COLS],
            });
            snap.text[col] = ch;
            snap.srcs[col] = src;
            self.grid()[idx].ch = 0;
        }
    }

    /// Apply a decoded CSI op with raw params; `reset` = `…l` final
    /// byte (alt-screen enter vs exit share the `alt_screen` name).
    pub(crate) fn apply_csi(&mut self, command: &str, params: &[u8], reset: bool) {
        let p = |i: usize, dflt: usize| -> usize {
            params
                .split(|&b| b == b';')
                .nth(i)
                .and_then(crate::digits)
                .map_or(dflt, |v| v as usize)
        };
        match command {
            "cursor_up" | "cursor_down" | "cursor_forward" | "cursor_back" | "cursor_next_line"
            | "cursor_prev_line" | "cursor_column" | "cursor_row" | "cursor_position" => {
                self.move_cursor(command, p(0, 1), p(1, 1))
            }
            "erase_line" => {
                let r = self.row * COLS;
                match p(0, 0) {
                    0 => self.erase_range(r + self.col, r + COLS),
                    1 => self.erase_range(r, r + self.col + 1),
                    _ => self.erase_range(r, r + COLS),
                }
            }
            "erase_display" => self.erase_display(p(0, 0)),
            "erase_chars" => {
                let s = self.row * COLS + self.col;
                self.erase_range(s, s + p(0, 1))
            }
            "delete_chars" => self.shift_cells(p(0, 1), false),
            "insert_chars" => self.shift_cells(p(0, 1), true),
            "delete_lines" => self.shift_lines(p(0, 1), false),
            "insert_lines" => self.shift_lines(p(0, 1), true),
            "scroll_up" => self.slide(p(0, 1), false),
            "scroll_down" => self.slide(p(0, 1), true),
            "save_cursor" | "restore_cursor" => self.save_restore(command == "save_cursor"),
            "alt_screen" => self.toggle_alt(reset),
            _ => {}
        }
    }

    fn move_cursor(&mut self, command: &str, a: usize, b: usize) {
        match command {
            "cursor_up" => self.row = self.row.saturating_sub(a),
            "cursor_down" => self.row = (self.row + a).min(ROWS - 1),
            "cursor_forward" => self.col = (self.col + a).min(COLS - 1),
            "cursor_back" => self.col = self.col.saturating_sub(a),
            "cursor_next_line" => {
                self.col = 0;
                self.advance_row(a);
            }
            "cursor_prev_line" => {
                self.col = 0;
                self.row = self.row.saturating_sub(a);
            }
            "cursor_column" => self.col = a.saturating_sub(1).min(COLS - 1),
            "cursor_row" => self.row = a.saturating_sub(1).min(ROWS - 1),
            "cursor_position" => {
                self.row = a.saturating_sub(1).min(ROWS - 1);
                self.col = b.saturating_sub(1).min(COLS - 1);
            }
            _ => {}
        }
    }

    fn erase_display(&mut self, mode: usize) {
        let at = self.row * COLS + self.col;
        match mode {
            0 => self.erase_range(at, ROWS * COLS),
            1 => self.erase_range(0, at + 1),
            _ => self.erase_range(0, ROWS * COLS),
        }
    }

    /// DCH pulls the row's tail left; ICH (`right`) pushes blanks in.
    fn shift_cells(&mut self, count: usize, right: bool) {
        let (row, col) = (self.row, self.col);
        let g = self.grid();
        let (at, re) = (row * COLS + col, row * COLS + COLS);
        let n = count.min(COLS - col);
        if right {
            g.copy_within(at..re - n, at + n);
            for c in &mut g[at..at + n] {
                *c = Cell::default();
            }
        } else {
            g.copy_within(at + n..re, at);
            for c in &mut g[re - n..re] {
                *c = Cell::default();
            }
        }
    }

    /// DL/IL shift rows; evicted rows are evaluated first. Snapshots
    /// stay row-indexed — shifted-in content compares against prior.
    fn shift_lines(&mut self, count: usize, insert: bool) {
        let (row, alt) = (self.row, self.on_alt);
        let n = count.min(ROWS - row);
        if insert {
            for r in (ROWS - n)..ROWS {
                self.eval_row(alt, r);
            }
        } else {
            for r in row..row + n {
                self.eval_row(alt, r);
            }
        }
        self.flush_events(alt);
        let g = self.grid();
        if insert {
            g.copy_within(row * COLS..(ROWS - n) * COLS, (row + n) * COLS);
            for c in &mut g[row * COLS..(row + n) * COLS] {
                *c = Cell::default();
            }
        } else {
            g.copy_within((row + n) * COLS..ROWS * COLS, row * COLS);
            for c in &mut g[(ROWS - n) * COLS..] {
                *c = Cell::default();
            }
        }
    }

    /// `CSI s`/`CSI u` — cursor save/restore, tracked per grid.
    fn save_restore(&mut self, save: bool) {
        let slot = if self.on_alt {
            &mut self.saved_alt
        } else {
            &mut self.saved
        };
        if save {
            *slot = (self.row, self.col);
        } else {
            (self.row, self.col) = *slot;
        }
    }

    /// `?1049h`/`…l` — swap the modeled grid and snapshot set.
    fn toggle_alt(&mut self, exit: bool) {
        if exit != self.on_alt {
            return;
        }
        if exit {
            self.on_alt = false;
            let (r, c) = self.saved;
            self.row = r;
            self.col = c;
        } else {
            self.saved = (self.row, self.col);
            self.on_alt = true;
            self.row = 0;
            self.col = 0;
        }
    }

    /// Record a finding if a row's snapshot diverges from its content.
    fn eval_row(&mut self, alt: bool, row: usize) {
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
    fn flush_events(&mut self, alt: bool) {
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
