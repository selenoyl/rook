//! The local APIC: this CPU's interrupt controller and its timer, which
//! drives preemption.
//!
//! The Keep uses xAPIC mode, where the registers are a page of memory;
//! `memory::build` maps that page, uncached, at `layout::APIC_VIRT`. They
//! can't be reached before the Keep's own page tables are loaded.

use super::layout::APIC_VIRT;
use super::{cpu, pit};

const BASE_ENABLED: u64 = 1 << 11;
const BASE_X2APIC: u64 = 1 << 10;
const BASE_ADDRESS: u64 = 0x000F_FFFF_FFFF_F000;

// Register offsets within the page.
const END_OF_INTERRUPT: u64 = 0xB0;
const SPURIOUS: u64 = 0xF0;
const LVT_TIMER: u64 = 0x320;
const LVT_LINT0: u64 = 0x350;
const TIMER_INITIAL: u64 = 0x380;
const TIMER_CURRENT: u64 = 0x390;
const TIMER_DIVIDE: u64 = 0x3E0;

const SOFTWARE_ENABLE: u32 = 1 << 8;
const MASKED: u32 = 1 << 16;
const PERIODIC: u32 = 1 << 17;
const DIVIDE_BY_16: u32 = 0b0011;
/// The timer counts down at the bus clock divided by this.
pub const DIVIDER: u64 = 16;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    Missing,
    Disabled,
    X2apicOnly,
    PitSilent,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(match self {
            Error::Missing => "this CPU has no local APIC",
            Error::Disabled => "the firmware turned the local APIC off",
            Error::X2apicOnly => {
                "the local APIC is in x2APIC mode, which the Keep doesn't drive yet"
            }
            Error::PitSilent => "the PIT never counted down, so the APIC timer can't be calibrated",
        })
    }
}

/// The physical address of the local APIC's registers.
pub fn phys_base() -> Result<u64, Error> {
    let base = cpu::apic_base().ok_or(Error::Missing)?;
    if base & BASE_ENABLED == 0 {
        return Err(Error::Disabled);
    }
    if base & BASE_X2APIC != 0 {
        return Err(Error::X2apicOnly);
    }
    Ok(base & BASE_ADDRESS)
}

fn read(register: u64) -> u32 {
    // SAFETY: APIC_VIRT maps the local APIC's register page, uncached,
    // and `register` is one of the offsets above, aligned and inside the
    // page. No Rust object lives there. Volatile, because these are device
    // registers.
    unsafe { ((APIC_VIRT + register) as *const u32).read_volatile() }
}

fn write(register: u64, value: u32) {
    // SAFETY: as for `read`.
    unsafe { ((APIC_VIRT + register) as *mut u32).write_volatile(value) }
}

/// Turn the local APIC on, with stray interrupts going to `spurious` and
/// the legacy PICs' line (LINT0) masked.
pub fn init(spurious: u8) {
    write(LVT_LINT0, MASKED);
    write(LVT_TIMER, MASKED);
    write(SPURIOUS, SOFTWARE_ENABLE | u32::from(spurious));
}

/// How many timer counts pass in `ms` milliseconds, timed by the PIT.
pub fn calibrate(ms: u32) -> Result<u32, Error> {
    write(TIMER_DIVIDE, DIVIDE_BY_16);
    write(LVT_TIMER, MASKED); // one-shot, and silent: only counting
    write(TIMER_INITIAL, u32::MAX);
    let finished = pit::wait(ms);
    let remaining = read(TIMER_CURRENT);
    write(TIMER_INITIAL, 0); // stop the timer
    match u32::MAX - remaining {
        counts if finished && counts > 0 => Ok(counts),
        _ => Err(Error::PitSilent),
    }
}

/// Interrupt on `vector` every `counts` timer counts.
pub fn start_timer(vector: u8, counts: u32) {
    write(TIMER_DIVIDE, DIVIDE_BY_16);
    write(LVT_TIMER, PERIODIC | u32::from(vector));
    write(TIMER_INITIAL, counts);
}

/// Tell the local APIC the interrupt being handled is done, so it can
/// deliver the next.
pub fn end_of_interrupt() {
    write(END_OF_INTERRUPT, 0);
}
