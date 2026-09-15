//! CSI op dispatch: maps decoded command names onto the window's
//! state primitives. Ops absent here are `unmodeled` — the dispatcher
//! in `lib.rs` quarantines them as findings rather than letting them
//! silently desync the model.

use super::{VirtualWindow, COLS, ROWS};

impl VirtualWindow {
    /// Apply a decoded CSI op with raw params; `reset` = `…l` final
    /// byte (alt-screen enter vs exit share the `alt_screen` name,
    /// as do `h`/`l` mode pairs like IRM and DECAWM).
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
            "scroll_region" => self.set_margins(p(0, 1), p(1, 0)),
            "insert_mode" => self.insert_mode = !reset,
            "decawm" => self.autowrap = !reset,
            // DECOM set/reset homes the cursor to the *new* origin
            // (xterm charproc.c, ghostty setOriginMode): the flag is
            // quarantined, but the home itself is modeled state.
            "origin_mode" => {
                self.decom = !reset;
                self.home();
            }
            "declrmm" => self.declrmm = !reset,
            "save_cursor" | "restore_cursor" => self.save_restore(command == "save_cursor"),
            "alt_screen" => self.toggle_alt(reset, alt_mode(params)),
            _ => {}
        }
    }

    /// The op this sequence *effectively is* in the current mode
    /// state. The flag modes are tracked (not modeled) precisely so
    /// ops whose meaning shifts under them stay quarantined instead of
    /// being misapplied:
    /// - under DECLRMM (`?69h`), `CSI s` is DECSLRM (left/right
    ///   margins), not SCOSC — xterm ctlseqs: "Save cursor, available
    ///   only when DECLRMM is disabled";
    /// - under DECOM (`?6h`), CUP/HVP and VPA address the scroll
    ///   region, not the screen.
    ///   Renamed ops fall out of the modeled set — quarantined, not run.
    pub(crate) fn effective_op<'a>(&self, command: &'a str) -> &'a str {
        match command {
            "save_cursor" if self.declrmm => "declrmm_margins",
            "cursor_position" if self.decom => "origin_cup",
            "cursor_row" if self.decom => "origin_vpa",
            _ => command,
        }
    }

    /// Vertical moves clamp at the scroll-region margins when the
    /// cursor is inside them (ghostty `cursorUp`/`cursorDown`): a
    /// cursor at the region top can't rise above it. Outside the
    /// region the screen edge is the bound.
    fn move_cursor(&mut self, command: &str, a: usize, b: usize) {
        self.pending_wrap = false;
        let floor = if self.row >= self.scroll_top {
            self.scroll_top
        } else {
            0
        };
        let ceil = if self.row <= self.scroll_bottom {
            self.scroll_bottom
        } else {
            ROWS - 1
        };
        match command {
            "cursor_up" => self.row = self.row.saturating_sub(a).max(floor),
            "cursor_down" => self.row = (self.row + a).min(ceil),
            "cursor_forward" => self.col = (self.col + a).min(COLS - 1),
            "cursor_back" => self.col = self.col.saturating_sub(a),
            "cursor_next_line" => {
                self.col = 0;
                self.row = (self.row + a).min(ceil); // CNL clamps — only LF scrolls
            }
            "cursor_prev_line" => {
                self.col = 0;
                self.row = self.row.saturating_sub(a).max(floor);
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

    /// DECSTBM (`CSI top ; bottom r`): 1-indexed, empty bottom = last
    /// row, invalid pairs ignored; the cursor homes — to the region's
    /// top-left under DECOM, else the screen's (ghostty
    /// `setTopAndBottomMargin` → `setCursorPos(1,1)`, origin-relative).
    fn set_margins(&mut self, top: usize, bottom: usize) {
        let t = top.max(1).saturating_sub(1);
        let b = (if bottom == 0 { ROWS } else { bottom })
            .min(ROWS)
            .saturating_sub(1);
        if t >= b {
            return;
        }
        self.scroll_top = t;
        self.scroll_bottom = b;
        self.home();
    }

    /// Cursor home: the scroll region's top-left under DECOM, the
    /// screen's otherwise (left margin unmodeled — DECLRMM is
    /// quarantined).
    fn home(&mut self) {
        self.row = if self.decom { self.scroll_top } else { 0 };
        self.col = 0;
        self.pending_wrap = false;
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
