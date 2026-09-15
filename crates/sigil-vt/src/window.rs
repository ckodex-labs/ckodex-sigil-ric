//! Bounded virtual window — a sliding-screen model of how a terminal
//! would interpret the byte stream.
//!
//! Not an emulator: just enough state (a bounded cell grid, cursor,
//! scroll region, alternate screen, per-row pre-erase snapshots) to
//! detect *semantic* divergence — cells overwritten by different bytes,
//! or rows erased and repainted with different text. That is the
//! display-vs-stream divergence `repaint_overwrite` flags.
//!
//! Quarantine discipline: anything the model cannot faithfully replay
//! is itself a finding, not silent state —
//! - `window_degraded`: a row holding non-ASCII bytes (≥0x80, where
//!   byte cells desync from glyph cells) is erased or overwritten;
//! - `window_unmodeled` (emitted by the dispatcher): an op outside the
//!   modeled set — origin mode, DECLRMM, LNM, 132-col, charsets.
//!
//! Remaining limits (documented, not hidden): byte-granular cells; no
//! scrollback — rows are evaluated at scroll eviction; raw-stream
//! semantics (LF ≠ CR+LF); left/right margins (DECLRMM) untracked.

mod findings;
mod ops;

use findings::{Overwrite, RowSnap, RowState};
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
    /// DECSTBM scroll region (inclusive row bounds, default full).
    scroll_top: usize,
    scroll_bottom: usize,
    insert_mode: bool, // IRM (`CSI 4 h`)
    autowrap: bool,    // DECAWM (`CSI ? 7 h/l`, default on)
    rows: Vec<RowState>,
    alt_rows: Vec<RowState>,
    overwrites: Vec<Overwrite>,
    findings: Vec<(ByteRange, &'static str, String)>,
    /// First dropped finding's range once the cap is hit — finish()
    /// reports it as a `window_degraded` marker so suppression is
    /// itself visible.
    overflow: Option<ByteRange>,
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
            scroll_top: 0,
            scroll_bottom: ROWS - 1,
            insert_mode: false,
            autowrap: true,
            rows: std::iter::repeat_with(RowState::default)
                .take(ROWS)
                .collect(),
            alt_rows: std::iter::repeat_with(RowState::default)
                .take(ROWS)
                .collect(),
            overwrites: Vec::new(),
            findings: Vec::new(),
            overflow: None,
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

    /// Row-state vec for the *active* grid.
    fn rows_mut(&mut self) -> &mut Vec<RowState> {
        self.rows_at(self.on_alt)
    }

    /// Row-state vec for an explicit grid (eval paths use `alt`).
    fn rows_at(&mut self, alt: bool) -> &mut Vec<RowState> {
        if alt {
            &mut self.alt_rows
        } else {
            &mut self.rows
        }
    }

    fn rows_ref(&self, alt: bool) -> &[RowState] {
        if alt {
            &self.alt_rows
        } else {
            &self.rows
        }
    }

    /// Write a printable byte at the cursor (DECAWM wrap); fires an
    /// overwrite event when the cell showed a different byte. Insert
    /// mode shifts the row tail right first; bytes ≥0x80 flag the row
    /// as non-ASCII (byte-cell tracking degrades to `window_degraded`).
    pub(crate) fn write(&mut self, b: u8, pos: usize) {
        // pending_wrap is only honored while DECAWM is on — ghostty
        // keeps the flag set across `?7l` but never acts on it.
        if self.pending_wrap && self.autowrap {
            self.pending_wrap = false;
            self.col = 0;
            self.advance_row();
        }
        // IRM: blanks are inserted before the glyph (not at last col).
        if self.insert_mode && self.col + 1 < COLS {
            self.shift_cells(1, true);
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
        if b >= 0x80 {
            let r = self.row;
            self.rows_mut()[r].nonascii = true;
        }
        self.col += 1;
        if self.col == COLS {
            self.col = COLS - 1;
            if self.autowrap {
                self.pending_wrap = true;
            }
        }
    }

    /// LF/VT/FF move down only — CR is the column reset.
    pub(crate) fn line_feed(&mut self) {
        self.pending_wrap = false;
        self.advance_row();
    }

    /// NEL (`ESC E`): down one row and column zero.
    pub(crate) fn next_line(&mut self) {
        self.pending_wrap = false;
        self.col = 0;
        self.advance_row();
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

    /// RI (`ESC M`): up one, scroll down at the top margin (scroll
    /// preserves pending-wrap; the cursor-up path clears it).
    pub(crate) fn reverse_index(&mut self) {
        if self.row == self.scroll_top {
            self.slide(1, true);
        } else {
            self.pending_wrap = false;
            self.row = self.row.saturating_sub(1);
        }
    }

    /// Down one row (ghostty `index`): at the bottom margin the scroll
    /// region slides; outside/below the region the cursor just moves.
    fn advance_row(&mut self) {
        if self.row == self.scroll_bottom {
            self.slide(1, false);
        } else {
            self.row = (self.row + 1).min(ROWS - 1);
        }
    }

    /// Shift rows inside the scroll region only. `down` inserts blanks
    /// at the region top (SU drops top rows; SD bottom). Rows leaving
    /// the region are evaluated; row state moves with its content.
    fn slide(&mut self, n: usize, down: bool) {
        let (top, bottom) = (self.scroll_top, self.scroll_bottom);
        let n = n.min(bottom + 1 - top);
        let alt = self.on_alt;
        if down {
            for r in (bottom + 1 - n)..=bottom {
                self.eval_row(alt, r);
            }
        } else {
            for r in top..top + n {
                self.eval_row(alt, r);
            }
        }
        self.flush_events(alt);
        let (a, b) = (top * COLS, (bottom + 1) * COLS);
        let g = self.grid();
        if down {
            g.copy_within(a..b - n * COLS, a + n * COLS);
            for c in &mut g[a..a + n * COLS] {
                *c = Cell::default();
            }
        } else {
            g.copy_within(a + n * COLS..b, a);
            for c in &mut g[b - n * COLS..b] {
                *c = Cell::default();
            }
        }
        let s = self.rows_mut();
        if down {
            for r in (top..=bottom - n).rev() {
                s[r + n] = std::mem::take(&mut s[r]);
            }
        } else {
            for r in top..=bottom - n {
                s[r] = std::mem::take(&mut s[r + n]);
            }
        }
    }

    /// Clear cells in [start, end) into their row snapshots. All
    /// erase ops clear pending-wrap (ghostty `cursorResetWrap`).
    /// Each affected row is evaluated first — every erase is an epoch
    /// boundary, so `A → erase → B → erase → A` cannot launder the
    /// transient `B` (the first-snapshot-only blind spot).
    fn erase_range(&mut self, start: usize, end: usize) {
        self.pending_wrap = false;
        let alt = self.on_alt;
        let end = end.min(self.grid().len());
        if start >= end {
            return;
        }
        self.flush_events(alt);
        let (r0, r1) = (start / COLS, ((end - 1) / COLS).min(ROWS - 1));
        for r in r0..=r1 {
            self.eval_row(alt, r);
        }
        for idx in start..end {
            let (ch, src) = (self.grid()[idx].ch, self.grid()[idx].src);
            if ch == 0 {
                continue;
            }
            let (row, col) = (idx / COLS, idx % COLS);
            let snap = self.rows_mut()[row].snap.get_or_insert_with(|| RowSnap {
                text: vec![0; COLS],
                srcs: vec![NO_SRC; COLS],
            });
            snap.text[col] = ch;
            snap.srcs[col] = src;
            self.grid()[idx].ch = 0;
        }
        // A row gone fully blank sheds its non-ASCII flag: fresh
        // content written afterwards is byte-trackable again.
        for r in r0..=r1 {
            if self.grid_ref(alt)[r * COLS..(r + 1) * COLS]
                .iter()
                .all(|c| c.ch == 0)
            {
                let st = &mut self.rows_at(alt)[r];
                st.nonascii = false;
                st.deg_fired = false;
            }
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

    /// DL/IL shift rows inside the scroll region — a no-op when the
    /// cursor is outside it (ghostty `insertLines`/`deleteLines`).
    /// Evicted rows are evaluated first; row state moves with content.
    /// The cursor lands on the left margin of its row (xterm/DEC).
    fn shift_lines(&mut self, count: usize, insert: bool) {
        if self.row < self.scroll_top || self.row > self.scroll_bottom {
            return;
        }
        self.col = 0;
        self.pending_wrap = false;
        let (row, alt, bottom) = (self.row, self.on_alt, self.scroll_bottom);
        let n = count.min(bottom + 1 - row);
        if insert {
            for r in (bottom + 1 - n)..=bottom {
                self.eval_row(alt, r);
            }
        } else {
            for r in row..row + n {
                self.eval_row(alt, r);
            }
        }
        self.flush_events(alt);
        let (a, b) = (row * COLS, (bottom + 1) * COLS);
        let g = self.grid();
        if insert {
            g.copy_within(a..b - n * COLS, a + n * COLS);
            for c in &mut g[a..a + n * COLS] {
                *c = Cell::default();
            }
        } else {
            g.copy_within(a + n * COLS..b, a);
            for c in &mut g[b - n * COLS..b] {
                *c = Cell::default();
            }
        }
        let s = self.rows_mut();
        if insert {
            for r in (row..=bottom - n).rev() {
                s[r + n] = std::mem::take(&mut s[r]);
            }
        } else {
            for r in row..=bottom - n {
                s[r] = std::mem::take(&mut s[r + n]);
            }
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
    /// semantics (ghostty `switchScreenMode`): mode effects are
    /// unconditional — `1049h` always saves the active screen's
    /// cursor and erases the alt grid (even already on it), `1049l`
    /// always restores the primary saved cursor; `1047l` erases the
    /// alt grid only when leaving it. Cursor copies on a real screen
    /// change carry pending-wrap, so the flag survives 47/1047.
    fn toggle_alt(&mut self, exit: bool, mode: u16) {
        match (mode, exit, self.on_alt) {
            (1049, false, true) => self.saved_alt = (self.row, self.col),
            (1049, false, false) => self.saved = (self.row, self.col),
            (1047, true, true) => self.clear_alt(),
            _ => {}
        }
        if exit == self.on_alt {
            self.on_alt = !exit;
        }
        match (mode, exit) {
            (1049, false) => self.clear_alt(),
            (1049, true) => {
                (self.row, self.col) = self.saved;
                self.pending_wrap = false; // slot is (row,col) only
            }
            _ => {}
        }
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
        for s in &mut self.alt_rows {
            *s = RowState::default();
        }
    }

    /// RIS (`ESC c`) — ghostty `fullReset`: back to primary screen,
    /// alt destroyed, grid cleared, cursor home, modes and scroll
    /// region reset. Pre-reset divergence still reports.
    pub(crate) fn ris(&mut self) {
        for alt in [false, true] {
            for r in 0..ROWS {
                self.eval_row(alt, r);
            }
            self.flush_events(alt);
        }
        let findings = std::mem::take(&mut self.findings);
        let overflow = self.overflow.take();
        *self = Self::new();
        self.findings = findings;
        self.overflow = overflow;
    }

    /// Active-grid cell byte — conformance lane only (grid parity vs
    /// ghostty `Terminal`/`Screen`).
    #[cfg(all(test, feature = "conformance"))]
    pub(crate) fn cell_byte(&self, row: usize, col: usize) -> u8 {
        self.grid_ref(self.on_alt)[row * COLS + col].ch
    }

    /// Cursor row/col/pending-wrap — conformance lane only.
    #[cfg(all(test, feature = "conformance"))]
    pub(crate) fn cursor_state(&self) -> (usize, usize, bool) {
        (self.row, self.col, self.pending_wrap)
    }
}
