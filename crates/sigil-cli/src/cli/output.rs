use crate::cli::results::JsonResult;
use crate::cli::types::{ColorMode, OutputFormat};
use anyhow::Result;
use serde::Serialize;
use std::io::IsTerminal;

pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Resolved output presentation for one invocation. `auto` follows the
/// terminal convention (human + color on a TTY, JSON when piped); the
/// explicit modes force either side so scripts and tests are
/// deterministic.
#[derive(Clone, Copy, Debug)]
pub struct Printer {
    pub human: bool,
    pub color: bool,
}

impl Printer {
    pub fn detect(format: OutputFormat, color: ColorMode) -> Self {
        let tty = std::io::stdout().is_terminal();
        let human = match format {
            OutputFormat::Auto => tty,
            OutputFormat::Human => true,
            OutputFormat::Json => false,
        };
        let color = match color {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => tty && std::env::var_os("NO_COLOR").is_none(),
        };
        Self { human, color }
    }

    /// Emit `result` — JSON envelope (the stable machine contract) or
    /// the supplied human renderer.
    pub fn emit<T: Serialize>(&self, result: &T, human: impl FnOnce(&T) -> String) -> Result<()> {
        if self.human {
            println!("{}", human(result));
            Ok(())
        } else {
            print_json(&JsonResult { result })
        }
    }
}

// ── minimal ANSI styling ────────────────────────────────────────────

pub mod style {
    pub const BOLD: &str = "1";
    pub const DIM: &str = "2";
    pub const RED: &str = "31";
    pub const GREEN: &str = "32";
    pub const YELLOW: &str = "33";
    pub const MAGENTA: &str = "35";
    pub const CYAN: &str = "36";
    /// Alternating token-slot backgrounds (256-color, still legible on
    /// 8-color fallbacks which clamp to the nearest system color).
    pub const BG_A: &str = "48;5;236";
    pub const BG_B: &str = "48;5;240";
}

/// Wrap `text` in an SGR sequence when `enabled`; otherwise return it
/// unchanged. Renderers receive plain text when color is off, so
/// `--color never` output is byte-clean for tests and logs.
pub fn paint(enabled: bool, code: &str, text: &str) -> String {
    if enabled && !text.is_empty() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}
