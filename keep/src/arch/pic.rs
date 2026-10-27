//! The legacy 8259 interrupt controllers. The Keep takes interrupts from
//! the local APIC instead, so it moves the 8259s out of the way and
//! masks them.

use super::port::outb;

const PRIMARY: u16 = 0x20;
const SECONDARY: u16 = 0xA0;
/// Where their sixteen lines would arrive, if unmasked: clear of the CPU
/// exception vectors, which the boot firmware leaves them on top of.
const PRIMARY_BASE: u8 = 0x20;
const SECONDARY_BASE: u8 = 0x28;

/// Move both PICs' vectors to 0x20..0x2F and mask every line. Left at the
/// firmware's vectors, a stray timer interrupt would look like a double
/// fault.
pub fn disable() {
    // SAFETY: 0x20/0x21 and 0xA0/0xA1 are the command and data ports of
    // the primary and secondary PIC. This is the standard initialization
    // sequence (ICW1 to ICW4) followed by a full mask; writes to port
    // 0x80, the POST code port, give slow PICs time between commands.
    // None of it touches memory.
    unsafe {
        for (command, data, base, wiring) in [
            (PRIMARY, PRIMARY + 1, PRIMARY_BASE, 0x04), // secondary on line 2
            (SECONDARY, SECONDARY + 1, SECONDARY_BASE, 0x02), // its cascade identity
        ] {
            outb(command, 0x11); // ICW1: initialize, ICW4 follows
            outb(0x80, 0);
            outb(data, base); // ICW2: vector base
            outb(0x80, 0);
            outb(data, wiring); // ICW3
            outb(0x80, 0);
            outb(data, 0x01); // ICW4: 8086 mode
            outb(0x80, 0);
            outb(data, 0xFF); // mask all eight lines
        }
    }
}
