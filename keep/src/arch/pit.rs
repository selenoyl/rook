//! The 8254 programmable interval timer. The Keep only uses it to time
//! a known interval while calibrating the local APIC timer.

use super::port::{inb, outb};

/// The PIT's input clock, in Hz.
const FREQUENCY: u32 = 1_193_182;
const CHANNEL_2: u16 = 0x42;
const COMMAND: u16 = 0x43;
/// Channel 2, low byte then high byte, mode 0 (count down once), binary.
const ONE_SHOT: u8 = 0b1011_0000;
/// System control port B: bit 0 gates channel 2, bit 1 drives the
/// speaker from it, bit 5 reads its output.
const PORT_B: u16 = 0x61;
const GATE: u8 = 1 << 0;
const SPEAKER: u8 = 1 << 1;
const OUTPUT: u8 = 1 << 5;
/// Polls before giving up: some machines stop the PIT's clock.
const SPIN_LIMIT: u32 = 100_000_000;
/// The longest wait the 16-bit counter can time.
pub const MAX_WAIT_MS: u32 = 50;

/// Busy-wait `ms` milliseconds (up to MAX_WAIT_MS) on channel 2. Returns
/// false if the count never ran out.
pub fn wait(ms: u32) -> bool {
    let count = FREQUENCY * ms.min(MAX_WAIT_MS) / 1000;
    // SAFETY: these are the PIT's command and channel 2 ports and port B.
    // This turns channel 2's gate on with the speaker off and starts a
    // one-shot count; none of it touches memory.
    unsafe {
        outb(PORT_B, inb(PORT_B) & !SPEAKER | GATE);
        outb(COMMAND, ONE_SHOT);
        outb(CHANNEL_2, count as u8);
        outb(CHANNEL_2, (count >> 8) as u8);
    }
    for _ in 0..SPIN_LIMIT {
        // SAFETY: reading port B has no side effects.
        if unsafe { inb(PORT_B) } & OUTPUT != 0 {
            return true;
        }
    }
    false
}
