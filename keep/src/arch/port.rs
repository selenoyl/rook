//! x86 port I/O.

use core::arch::asm;

/// Write a byte to an I/O port.
///
/// # Safety
/// Ports reach devices directly; some (DMA controllers, for example) can
/// overwrite memory. Callers must know what device sits at `port` and
/// that `value` is a safe thing to send it.
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller vouches for the port and value; `out` itself
    // touches no Rust-visible memory.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    };
}

/// Write a 32-bit value to an I/O port. Same contract as [`outb`].
pub unsafe fn outl(port: u16, value: u32) {
    // SAFETY: as for `outb`.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags))
    };
}

/// Read a byte from an I/O port.
///
/// # Safety
/// Reading some device registers has side effects; callers must know what
/// device sits at `port`.
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller vouches for the port; `in` touches no
    // Rust-visible memory.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}
