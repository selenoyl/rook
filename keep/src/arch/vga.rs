//! The VGA text screen: 80x25 cells of a code page 437 character and a
//! color attribute, at physical address 0xB8000.

use super::paging::phys_to_virt;
use super::port::outb;
use super::sync::Exclusive;

pub const WIDTH: usize = 80;
pub const HEIGHT: usize = 25;
/// Physical address of the text buffer.
pub const BUFFER_PHYS: u64 = 0xB8000;

/// The text console's color: bright white on black.
const TEXT_ATTR: u8 = 0x0f;

/// Where the next console character goes.
struct Cursor {
    row: usize,
    col: usize,
}

static CURSOR: Exclusive<Cursor> = Exclusive::new(Cursor { row: 0, col: 0 });

/// Read one text cell (character and attribute together).
fn get(row: usize, col: usize) -> u16 {
    let cell = (phys_to_virt(BUFFER_PHYS) as *const u16).wrapping_add(row * WIDTH + col);
    // SAFETY: callers pass row < HEIGHT and col < WIDTH, so `cell` is inside
    // the text buffer, mapped through the physical-memory window. Volatile,
    // because it is device memory.
    unsafe { cell.read_volatile() }
}

/// Write bytes to the text console at the cursor, advancing it: `\n` ends a
/// line, `\r` returns to column 0, backspace (0x08) erases one cell, and
/// form-feed (0x0c) clears the screen. The screen scrolls when the cursor
/// runs off the bottom. This is what the `print` system call drives.
pub fn console_write(bytes: &[u8]) {
    CURSOR.with(|c| {
        for &b in bytes {
            write_byte(c, b);
        }
    });
}

fn write_byte(c: &mut Cursor, b: u8) {
    match b {
        b'\n' => newline(c),
        b'\r' => c.col = 0,
        0x0c => {
            clear(TEXT_ATTR);
            c.row = 0;
            c.col = 0;
        }
        0x08 => {
            if c.col > 0 {
                c.col -= 1;
                put(c.row, c.col, b' ', TEXT_ATTR);
            }
        }
        0x20..=0x7e => {
            put(c.row, c.col, b, TEXT_ATTR);
            c.col += 1;
            if c.col >= WIDTH {
                newline(c);
            }
        }
        _ => {}
    }
}

fn newline(c: &mut Cursor) {
    c.col = 0;
    if c.row + 1 >= HEIGHT {
        scroll();
    } else {
        c.row += 1;
    }
}

/// Move every row up one, clearing the bottom row: the console has reached
/// the foot of the screen.
fn scroll() {
    for row in 1..HEIGHT {
        for col in 0..WIDTH {
            let cell = get(row, col);
            put(row - 1, col, cell as u8, (cell >> 8) as u8);
        }
    }
    for col in 0..WIDTH {
        put(HEIGHT - 1, col, b' ', TEXT_ATTR);
    }
}

/// Put one character on screen. Positions off screen are ignored.
pub fn put(row: usize, col: usize, ch: u8, attr: u8) {
    if row >= HEIGHT || col >= WIDTH {
        return;
    }
    let cell = (phys_to_virt(BUFFER_PHYS) as *mut u16).wrapping_add(row * WIDTH + col);
    // SAFETY: row and col are checked above, so `cell` is inside the text
    // buffer, which is mapped at phys_to_virt(BUFFER_PHYS): by the boot
    // identity map, then by the physical-memory window. Volatile, because
    // the buffer is device memory.
    unsafe { cell.write_volatile(u16::from(attr) << 8 | u16::from(ch)) };
}

/// Fill the screen with blanks in one color.
pub fn clear(attr: u8) {
    for row in 0..HEIGHT {
        for col in 0..WIDTH {
            put(row, col, b' ', attr);
        }
    }
}

/// Set one of the 16 text colors to an exact 24-bit RGB value.
pub fn set_color(color: u8, rgb: u32) {
    // In text mode the attribute controller maps the 16 text colors to
    // these entries of the DAC, the VGA's color table.
    const DAC_ENTRY: [u8; 16] = [0, 1, 2, 3, 4, 5, 20, 7, 56, 57, 58, 59, 60, 61, 62, 63];
    let Some(&entry) = DAC_ENTRY.get(usize::from(color)) else {
        return;
    };
    let channel = |shift: u32| (rgb >> shift) as u8 >> 2; // the DAC takes 6 bits
    // SAFETY: 0x3C8 selects a DAC entry and 0x3C9 then takes its red,
    // green and blue in turn. This changes how a color looks on screen
    // and nothing else.
    unsafe {
        outb(0x3C8, entry);
        outb(0x3C9, channel(16));
        outb(0x3C9, channel(8));
        outb(0x3C9, channel(0));
    }
}

/// Hide the blinking hardware cursor.
pub fn hide_cursor() {
    // SAFETY: 0x3D4/0x3D5 are the VGA CRT controller's index and data
    // ports; register 0x0A bit 5 only turns the text cursor off.
    unsafe {
        outb(0x3D4, 0x0A);
        outb(0x3D5, 0x20);
    }
}
