//! QEMU's isa-debug-exit device, used to end self-test runs with a result.
//! QEMU exits with status (code << 1) | 1, so success is 33 and failure 35.

use super::port::outl;

pub const EXIT_SUCCESS: u32 = 0x10;
pub const EXIT_FAILURE: u32 = 0x11;
const DEBUG_EXIT_PORT: u16 = 0xF4;

/// Ask QEMU to exit. Halts if no such device is listening.
pub fn exit(code: u32) -> ! {
    // SAFETY: only reached in self-test mode, which runs under QEMU with
    // `-device isa-debug-exit,iobase=0xf4`; elsewhere nothing decodes this
    // port and the write is dropped.
    unsafe { outl(DEBUG_EXIT_PORT, code) };
    super::cpu::halt_forever()
}
