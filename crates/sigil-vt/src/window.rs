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

mod findings;

use findings::{Overwrite, RowSnap};
use sigil_core::types::ByteRange;

/// Window geometry: a sliding 200×48 grid. Anything older has already
/// scrolled off — replaying beyond that is emulator territory, which
/// the runtime path deliberately does not enter.
pub(crate) const COLS: usize = 200;
pub(crate) const ROWS: usize = 48;

const NO_SRC: usize = usize::MAX;

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
    /// DECAWM deferred wrap: after a write at the last column the
    /// cursor stays put and the next printable wraps — matching
    /// ghostty's `pending_wrap` (cursor moves and LF clear it without
    /// wrapping; erases leave it untouched).
    pending_wrap: bool,
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
            pending_wrap: false,
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
        if self.pending_wrap {
            self.pending_wrap = false;
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
            self.record_overwrite(self.row, self.col, old, old_src, b, pos);
        }
        self.col += 1;
        if self.col == COLS {
            self.col = COLS - 1;
            self.pending_wrap = true;
        }
    }

    /// LF/VT/FF move down only — CR is the column reset.
    pub(crate) fn line_feed(&mut self) {
        self.pending_wrap = false;
        self.advance_row(1);
    }

    /// NEL (C1 0x85): down one row and column zero.
    pub(crate) fn next_line(&mut self) {
        self.pending_wrap = false;
        self.col = 0;
        self.advance_row(1);
    }

    pub(crate) fn carriage_return(&mut self) {
        self.pending_wrap = false;
        self.col = 0;
    }

    /// HT advances to the next tabstop, capped at the right margin.
    pub(crate) fn tab(&mut self) {
        self.pending_wrap = false;
        self.col = ((self.col + 8) & !7).min(COLS - 1);
    }

    /// BS (0x08) moves back one — the classic overstrike enabler.
    pub(crate) fn backspace(&mut self) {
        self.pending_wrap = false;
        self.col = self.col.saturating_sub(1);
    }

    /// RI (C1 0x8D / `ESC M`): up one, scroll down at the top margin
    /// (scroll preserves pending-wrap; the cursor-up path clears it).
    pub(crate) fn reverse_index(&mut self) {
        if self.row == 0 {
            self.slide(1, true);
        } else {
            self.pending_wrap = false;
            self.row -= 1;
        }
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

    /// Clear cells in [start, end) into their row snapshots. All
    /// erase ops clear pending-wrap (ghostty `cursorResetWrap`).
    fn erase_range(&mut self, start: usize, end: usize) {
        self.pending_wrap = false;
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
            "alt_screen" => self.toggle_alt(reset, alt_mode(params)),
            _ => {}
        }
    }

    fn move_cursor(&mut self, command: &str, a: usize, b: usize) {
        self.pending_wrap = false;
        match command {
            "cursor_up" => self.row = self.row.saturating_sub(a),
            "cursor_down" => self.row = (self.row + a).min(ROWS - 1),
            "cursor_forward" => self.col = (self.col + a).min(COLS - 1),
            "cursor_back" => self.col = self.col.saturating_sub(a),
            "cursor_next_line" => {
                self.col = 0;
                self.row = (self.row + a).min(ROWS - 1); // CNL clamps — only LF scrolls
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
    /// Both clear pending-wrap via `cursorResetWrap`.
    fn shift_cells(&mut self, count: usize, right: bool) {
        self.pending_wrap = false;
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
    /// The cursor lands on the left margin of its row (xterm/DEC).
    fn shift_lines(&mut self, count: usize, insert: bool) {
        self.col = 0;
        self.pending_wrap = false;
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
        // Snapshots stay row-aligned with the content they describe.
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
        let s = self.snaps_mut();
        if insert {
            s.splice(row..row, std::iter::repeat_with(|| None).take(n));
            s.truncate(ROWS);
        } else {
            s.drain(row..row + n);
            s.extend(std::iter::repeat_with(|| None).take(n));
        }
    }

    /// `CSI s`/`CSI u` and `ESC 7`/`ESC 8` — cursor save/restore,
    /// tracked per grid.
    pub(crate) fn save_restore(&mut self, save: bool) {
        let slot = if self.on_alt {
            &mut self.saved_alt
        } else {
            &mut self.saved
        };
        if save {
            *slot = (self.row, self.col);
        } else {
            (self.row, self.col) = *slot;
            self.pending_wrap = false; // slot is (row,col) only
        }
    }

    /// `?47`/`?1047`/`?1049` alt-screen ops — xterm `charproc.c`
    /// semantics (ghostty `switchScreenMode`): entering copies the
    /// cursor onto the alt screen (all modes); 1049 also saves the
    /// cursor and erases the alt grid; exiting 1047 erases the alt
    /// grid; exiting 1049 restores the saved cursor.
    fn toggle_alt(&mut self, exit: bool, mode: u16) {
        if exit != self.on_alt {
            return;
        }
        if !exit {
            if mode == 1049 {
                self.saved = (self.row, self.col);
            }
            self.on_alt = true;
            if mode == 1049 {
                self.clear_alt();
            }
        } else {
            if mode == 1047 {
                self.clear_alt(); // erase the screen being left
            }
            self.on_alt = false;
            if mode == 1049 {
                (self.row, self.col) = self.saved;
            }
        }
        self.pending_wrap = false;
    }

    /// Wipe the alt grid; rows are evaluated first so repaints on a
    /// previous alt session still report.
    fn clear_alt(&mut self) {
        for r in 0..ROWS {
            self.eval_row(true, r);
        }
        self.flush_events(true);
        for c in &mut self.alt {
            *c = Cell::default();
        }
        for s in &mut self.alt_snaps {
            *s = None;
        }
    }

    /// Active-grid cell byte — conformance lane only (grid parity vs
    /// ghostty `Terminal`/`Screen`).
    #[cfg(all(test, feature = "conformance"))]
    pub(crate) fn cell_byte(&self, row: usize, col: usize) -> u8 {
        self.grid_ref(self.on_alt)[row * COLS + col].ch
    }
}

/// Alt-screen mode number from CSI private params (`?1049` etc.).
fn alt_mode(params: &[u8]) -> u16 {
    match params {
        b"?47" => 47,
        b"?1047" => 1047,
        _ => 1049,
    }
}
