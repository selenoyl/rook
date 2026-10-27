//! The boot banner on the VGA text screen: Rufus, the Rook logo, beside
//! the ROOK wordmark, both fading from solid to faint, then the motto and
//! the boot report.

#![forbid(unsafe_code)]

use crate::arch::vga;
use core::fmt::{self, Write};

/// Rufus, the Rook logo, drawn the way the wordmark is: blocks that fade
/// from solid to faint down the rows, a box-line drop shadow, and a
/// reflection. Redrawn at 70% from assets/rook-logo.png, each character
/// standing for two of its pixels, one above the other (VGA cells are
/// about twice as tall as they are wide).
const LOGO: &str = include_str!("../assets/logo.txt");
/// The wordmark, in block and box-drawing characters.
const WORDMARK: &str = include_str!("../assets/wordmark.txt");
const BAR: &str = "·  ·░░▒▒▓▓████████████████████████████████████████▓▓▒▒░░·  ·";
const MOTTO: &str = "Nisi Dominus custodierit civitatem, frustra vigilat qui custodit eam";
const CREDIT: &str = "░▒▓  Designed by Ryan Raikes  ▓▒░";

const LOGO_ROW: usize = 1;
const LOGO_COL: usize = 13;
const WORDMARK_ROW: usize = 2;
const WORDMARK_COL: usize = 36;
const CREDIT_ROW: usize = 10;
const BAR_ROW: usize = 14;
const MOTTO_ROW: usize = 16;
const STATUS_ROW: usize = 17;
const REPORT_ROW: usize = 19;
const REPORT_COL: usize = 4;
const VALUE_COL: usize = REPORT_COL + 10;

/// Rook blue, the logo's color, with a lighter and a darker shade of the
/// same hue for the logo's fade, and a deep shade for the reflections.
const ROOK_LIGHT_RGB: u32 = 0x46_8A_D2;
const ROOK_BLUE_RGB: u32 = 0x26_61_9C;
const ROOK_DARK_RGB: u32 = 0x1A_44_70;
const ROOK_DEEP_RGB: u32 = 0x13_30_4E;

// Text colors. The ROOK_ colors take over four of the 16 slots.
const ROOK_DEEP: u8 = 0x1;
const ROOK_DARK: u8 = 0x2;
const ROOK_BLUE: u8 = 0x3;
const BROWN: u8 = 0x6;
const LIGHT_GRAY: u8 = 0x7;
const DARK_GRAY: u8 = 0x8;
const ROOK_LIGHT: u8 = 0x9;
const LIGHT_GREEN: u8 = 0xA;
const LIGHT_RED: u8 = 0xC;
const WHITE: u8 = 0xF;

/// The logo and the wordmark darken row by row, ending in shadow and a
/// deep-blue reflection: the logo in Rook blues, the wordmark in grays.
/// The logo stays solid down to its base, so Rufus's face stays clear.
const LOGO_COLORS: [u8; 12] = [
    ROOK_LIGHT, ROOK_LIGHT, ROOK_LIGHT, ROOK_LIGHT, ROOK_BLUE, ROOK_BLUE, ROOK_BLUE, ROOK_BLUE,
    ROOK_BLUE, ROOK_DARK, ROOK_DARK, ROOK_DEEP,
];
const WORDMARK_COLORS: [u8; 7] = [
    WHITE, WHITE, LIGHT_GRAY, LIGHT_GRAY, DARK_GRAY, DARK_GRAY, ROOK_DEEP,
];

pub struct Summary {
    pub usable_mib: u64,
    pub free_mib: u64,
    pub stack_guards: usize,
    pub ticks_per_second: u64,
    /// The ring-0/ring-3 walls (SMEP, SMAP, UMIP) all went up.
    pub walls: bool,
    pub nx: bool,
    pub check_ok: bool,
}

/// The VGA font is code page 437; map the characters the banner uses.
fn cp437(c: char) -> u8 {
    match c {
        ' '..='~' => c as u8,
        '█' => 0xDB,
        '▀' => 0xDF,
        '▄' => 0xDC,
        '▓' => 0xB2,
        '▒' => 0xB1,
        '░' => 0xB0,
        '·' => 0xFA,
        '═' => 0xCD,
        '║' => 0xBA,
        '╔' => 0xC9,
        '╗' => 0xBB,
        '╚' => 0xC8,
        '╝' => 0xBC,
        _ => b'?',
    }
}

/// Shades fade: solid is brightest, the lightest shade darkest.
fn shade_color(c: char) -> u8 {
    match c {
        '█' => WHITE,
        '▓' => LIGHT_GRAY,
        '▒' | '░' | '·' => DARK_GRAY,
        _ => LIGHT_GRAY,
    }
}

/// Draw block art one line per row, each row in its own color.
fn draw_shaded(art: &str, row: usize, col: usize, colors: &[u8]) {
    for (i, line) in art.lines().enumerate() {
        let color = colors.get(i).copied().unwrap_or(DARK_GRAY);
        text(row.saturating_add(i), col, line, |_| color);
    }
}

/// Draw text, coloring each character; returns the column after it.
fn text(row: usize, col: usize, s: &str, color: impl Fn(char) -> u8) -> usize {
    let mut col = col;
    for c in s.chars() {
        vga::put(row, col, cp437(c), color(c));
        col = col.saturating_add(1);
    }
    col
}

fn centered(row: usize, s: &str, color: impl Fn(char) -> u8) {
    let col = vga::WIDTH.saturating_sub(s.chars().count()) / 2;
    text(row, col, s, color);
}

/// A line of text built with `write!`, at most one screen row long.
struct Line {
    chars: [char; vga::WIDTH],
    len: usize,
}

impl Line {
    fn new() -> Line {
        Line {
            chars: [' '; vga::WIDTH],
            len: 0,
        }
    }

    fn draw(&self, row: usize, col: usize, attr: u8) -> usize {
        let mut col = col;
        for &c in self.chars.iter().take(self.len) {
            vga::put(row, col, cp437(c), attr);
            col = col.saturating_add(1);
        }
        col
    }
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            if let Some(slot) = self.chars.get_mut(self.len) {
                *slot = c;
                self.len = self.len.saturating_add(1);
            }
        }
        Ok(())
    }
}

fn report_line(row: usize, label: &str, value: &str, color: u8) {
    text(row, REPORT_COL, label, |_| DARK_GRAY);
    text(row, VALUE_COL, value, |_| color);
}

/// Blank a report row's value.
fn clear_value(row: usize) {
    for col in VALUE_COL..vga::WIDTH {
        vga::put(row, col, b' ', LIGHT_GRAY);
    }
}

/// The last two report rows: the self-checks, and Rufus's verdict.
/// `ring3` is the ring-3 test program's result, None until it has run.
pub fn draw_checks(breakpoint_ok: bool, ring3: Option<bool>) {
    let (check, watch) = (REPORT_ROW + 4, REPORT_ROW + 5);
    clear_value(check);
    clear_value(watch);
    text(check, REPORT_COL, "check", |_| DARK_GRAY);
    let col = match breakpoint_ok {
        true => text(check, VALUE_COL, "breakpoint trap handled", |_| LIGHT_GRAY),
        false => text(check, VALUE_COL, "breakpoint trap FAILED", |_| WHITE),
    };
    let col = text(check, col, " · ", |_| LIGHT_GRAY);
    match ring3 {
        None => text(check, col, "ring 3 starting", |_| DARK_GRAY),
        Some(true) => text(check, col, "ring 3 + IPC", |_| LIGHT_GRAY),
        Some(false) => text(check, col, "ring 3 FAILED", |_| WHITE),
    };
    let (verdict, color) = match (breakpoint_ok, ring3) {
        (false, _) | (_, Some(false)) => ("Rufus raised the alarm", LIGHT_RED),
        (true, None) => ("Rufus is keeping watch", DARK_GRAY),
        (true, Some(true)) => ("Rufus reports all quiet", ROOK_LIGHT),
    };
    report_line(watch, "watch", verdict, color);
}

pub fn draw(summary: &Summary) {
    vga::clear(LIGHT_GRAY);
    vga::hide_cursor();
    vga::set_color(ROOK_LIGHT, ROOK_LIGHT_RGB);
    vga::set_color(ROOK_BLUE, ROOK_BLUE_RGB);
    vga::set_color(ROOK_DARK, ROOK_DARK_RGB);
    vga::set_color(ROOK_DEEP, ROOK_DEEP_RGB);

    draw_shaded(LOGO, LOGO_ROW, LOGO_COL, &LOGO_COLORS);
    draw_shaded(WORDMARK, WORDMARK_ROW, WORDMARK_COL, &WORDMARK_COLORS);
    text(CREDIT_ROW, WORDMARK_COL, CREDIT, |c| match c {
        '░' | '▒' | '▓' => DARK_GRAY,
        _ => LIGHT_GRAY,
    });
    centered(BAR_ROW, BAR, shade_color);
    centered(MOTTO_ROW, MOTTO, |_| BROWN);

    // "Keep v0.1.0 · x86-64 · 127 MiB · Drawbridge raised"
    let mut status = Line::new();
    let _ = write!(
        status,
        "Keep v{} · x86-64 · {} MiB · ",
        crate::VERSION,
        summary.usable_mib
    );
    let col = status.draw(STATUS_ROW, REPORT_COL, DARK_GRAY);
    text(STATUS_ROW, col, "Drawbridge raised", |_| LIGHT_GREEN);

    let mut cpu = Line::new();
    let _ = write!(
        cpu,
        "x86-64 · no-execute {} · ring 0/3 walls {}",
        if summary.nx { "on" } else { "OFF" },
        if summary.walls { "up" } else { "OFF" }
    );
    text(REPORT_ROW, REPORT_COL, "cpu", |_| DARK_GRAY);
    cpu.draw(REPORT_ROW, VALUE_COL, LIGHT_GRAY);

    let mut memory = Line::new();
    let _ = write!(
        memory,
        "{} MiB usable · {} MiB free after boot",
        summary.usable_mib, summary.free_mib
    );
    text(REPORT_ROW + 1, REPORT_COL, "memory", |_| DARK_GRAY);
    memory.draw(REPORT_ROW + 1, VALUE_COL, LIGHT_GRAY);

    let mut paging = Line::new();
    let _ = write!(
        paging,
        "W^X kernel · null unmapped · {} stack guards",
        summary.stack_guards
    );
    text(REPORT_ROW + 2, REPORT_COL, "paging", |_| DARK_GRAY);
    paging.draw(REPORT_ROW + 2, VALUE_COL, LIGHT_GRAY);

    let mut traps = Line::new();
    let _ = write!(
        traps,
        "32 exception gates · {} Hz APIC timer",
        summary.ticks_per_second
    );
    text(REPORT_ROW + 3, REPORT_COL, "traps", |_| DARK_GRAY);
    traps.draw(REPORT_ROW + 3, VALUE_COL, LIGHT_GRAY);

    draw_checks(summary.check_ok, None);
}
