//! The VGA text screen: 80x25 cells of a code page 437 character and a
//! color attribute, at physical address 0xB8000.

use super::paging::phys_to_virt;
use super::port::outb;

pub const WIDTH: usize = 80;
pub const HEIGHT: usize = 25;
/// Physical address of the text buffer.
pub const BUFFER_PHYS: u64 = 0xB8000;

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
