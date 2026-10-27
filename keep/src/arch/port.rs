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

/// Write a 16-bit value to an I/O port. Same contract as [`outb`].
pub unsafe fn outw(port: u16, value: u16) {
    // SAFETY: as for `outb`.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags))
    };
}

/// Read a 16-bit value from an I/O port. Same contract as [`inb`].
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    // SAFETY: as for `inb`.
    unsafe {
        asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}

// The capability-gated device I/O the syscall layer performs once it has
// checked a task's I/O Writ. Port access can reach a device, but the Writ
// fixes exactly which ports a task may touch, so from the Keep's side
// these are ordinary reads and writes of a named register. They are safe
// to call; the danger is in *which* port, which the caller has checked.

/// Read one byte from a device register.
pub fn reg_in8(port: u16) -> u8 {
    // SAFETY: the syscall layer confirmed the caller holds an I/O Writ
    // covering `port`; a byte read of a register has no memory effect.
    unsafe { inb(port) }
}

/// Write one byte to a device register.
pub fn reg_out8(port: u16, value: u8) {
    // SAFETY: as for `reg_in8`; the caller's Writ covers `port`.
    unsafe { outb(port, value) }
}

/// Read `buf.len()/2` 16-bit words from `port` into `buf`, little-endian:
/// the PIO data-transfer path for a block device. `buf` is a Keep buffer,
/// so this touches no user memory.
pub fn drain_port(port: u16, buf: &mut [u8]) {
    for pair in buf.chunks_exact_mut(2) {
        // SAFETY: the caller's Writ covers `port`; `pair` is two bytes of
        // a Keep-owned buffer.
        let word = unsafe { inw(port) };
        pair.copy_from_slice(&word.to_le_bytes());
    }
}

/// Write `buf.len()/2` 16-bit words from `buf` to `port`, little-endian.
pub fn fill_port(port: u16, buf: &[u8]) {
    for pair in buf.chunks_exact(2) {
        let word = u16::from_le_bytes([pair[0], pair[1]]);
        // SAFETY: as for `drain_port`; the caller's Writ covers `port`.
        unsafe { outw(port, word) };
    }
}
