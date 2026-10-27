//! COM1 serial port (16550 UART) for the boot log.

use super::port::{inb, outb};

const COM1: u16 = 0x3F8;
const LINE_STATUS: u16 = COM1 + 5;
const TRANSMIT_EMPTY: u8 = 0x20;
/// How long to wait for the UART before dropping a byte, so a machine
/// without a serial port doesn't hang.
const SPIN_LIMIT: u32 = 100_000;

/// Set COM1 to 115200 baud, 8 data bits, no parity, one stop bit.
pub fn init() {
    // SAFETY: these are the standard 16550 registers at COM1's fixed
    // base; programming the baud rate and line format has no effect on
    // memory.
    unsafe {
        outb(COM1 + 1, 0x00); // no UART interrupts
        outb(COM1 + 3, 0x80); // divisor latch on
        outb(COM1, 0x01); // divisor 1: 115200 baud
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03); // 8N1, divisor latch off
        outb(COM1 + 2, 0xC7); // FIFOs on and cleared
        outb(COM1 + 4, 0x03); // DTR and RTS
    }
}

fn write_byte(byte: u8) {
    for _ in 0..SPIN_LIMIT {
        // SAFETY: reading COM1's line status register has no side effects.
        if unsafe { inb(LINE_STATUS) } & TRANSMIT_EMPTY != 0 {
            // SAFETY: COM1's transmit register only sends the byte.
            unsafe { outb(COM1, byte) };
            return;
        }
    }
}

/// Write text to COM1, turning `\n` into `\r\n` for terminals.
pub fn write_str(s: &str) {
    for byte in s.bytes() {
        if byte == b'\n' {
            write_byte(b'\r');
        }
        write_byte(byte);
    }
}
