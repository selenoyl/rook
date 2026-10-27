//! The Keep's virtual address space: where the linker put the Keep, the
//! task stacks, and the device registers, and where the guard pages are.
//!
//! | From | What |
//! | --- | --- |
//! | `0x0000_0000_0000_1000` | User programs load from here up |
//! | `0x0000_7FFF_FFFF_B000` | A user task's stack (top of the lower half) |
//! | `0xFFFF_8000_0000_0000` | All RAM (`paging::PHYS_WINDOW`) |
//! | `0xFFFF_FE00_0000_0000` | Device registers, uncached |
//! | `0xFFFF_FF00_0000_0000` | Task stacks, each above an unmapped guard |
//! | `0xFFFF_FFFF_8000_0000` | The Keep's image |
//!
//! The null page stays unmapped, so a null pointer faults in ring 3 as
//! well as ring 0.

pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// User programs live in the lower half. A program's ELF segments must
/// lie in `USER_MIN..USER_MAX`, above the null page and inside the
/// canonical lower half. Each task's stack sits at the top, above an
/// unmapped guard page.
pub const USER_MIN: u64 = 0x1000;
pub const USER_MAX: u64 = 0x0000_8000_0000_0000;
// Generous enough for the post-quantum crypto, with a guard page below.
// ML-DSA signing and verification keep several vectors of 256-coefficient
// polynomials live at once (and a Drawbridge handshake layers its own
// buffers on top), so give user tasks room to spare.
pub const USER_STACK_SIZE: u64 = 512 * 1024;
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;

/// The lowest mapped byte of a user task's stack.
pub const fn user_stack_base() -> u64 {
    USER_STACK_TOP - USER_STACK_SIZE
}

/// Whether `addr` is in the unmapped guard just below a user task's
/// stack: a user stack overflow.
pub fn user_stack_overflow(addr: u64) -> bool {
    let base = user_stack_base();
    (base.saturating_sub(STACK_SLOT)..base).contains(&addr)
}

/// Device registers. The local APIC's page is first.
pub const DEVICES: u64 = 0xFFFF_FE00_0000_0000;
pub const APIC_VIRT: u64 = DEVICES;

/// Task stacks. Task slot `i` owns the `STACK_SLOT` bytes from
/// `TASK_STACKS + i * STACK_SLOT`: the top `STACK_SIZE` bytes are its
/// stack, and the rest, below, is never mapped, so an overflow faults.
/// Slot 0 is the idle task, which runs on the boot stack, so it has no
/// stack here.
pub const TASK_STACKS: u64 = 0xFFFF_FF00_0000_0000;
pub const TASK_SLOTS: usize = 16;
pub const STACK_SLOT: u64 = 64 * 1024;
pub const STACK_SIZE: u64 = 16 * 1024;

/// The top of task slot `slot`'s stack (stacks grow down).
pub const fn stack_top(slot: usize) -> u64 {
    TASK_STACKS + (slot as u64 + 1) * STACK_SLOT
}

/// A guard: unmapped memory just below a stack.
#[derive(Clone, Copy)]
pub enum Guard {
    Boot,
    DoubleFault,
    Task(usize),
}

impl core::fmt::Display for Guard {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Guard::Boot => write!(f, "the guard page below the boot stack"),
            Guard::DoubleFault => write!(f, "the guard page below the double-fault stack"),
            Guard::Task(slot) => write!(f, "the guard below task {slot}'s stack"),
        }
    }
}

/// Which stack's guard `addr` falls in, if any.
pub fn guard_at(addr: u64) -> Option<Guard> {
    let page = addr & !0xFFF;
    let layout = kernel();
    if page == layout.guards[0] {
        return Some(Guard::Boot);
    }
    if page == layout.guards[1] {
        return Some(Guard::DoubleFault);
    }
    let offset = addr.checked_sub(TASK_STACKS)?;
    let slot = usize::try_from(offset / STACK_SLOT).ok()?;
    let below_stack = offset % STACK_SLOT < STACK_SLOT - STACK_SIZE;
    ((1..TASK_SLOTS).contains(&slot) && below_stack).then_some(Guard::Task(slot))
}

unsafe extern "C" {
    // Defined by linker.ld (sections) and boot.rs (stack guard). Only
    // their addresses are used.
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __bss_end: u8;
    static __keep_phys_start: u8;
    static __keep_phys_end: u8;
    static boot_stack_guard: u8;
}

/// A range of virtual addresses, `start..end`, page-aligned.
#[derive(Clone, Copy)]
pub struct Section {
    pub start: u64,
    pub end: u64,
}

pub struct Layout {
    /// Code: read and execute.
    pub text: Section,
    /// Constants: read only.
    pub rodata: Section,
    /// Data and .bss: read and write, never execute.
    pub data: Section,
    /// Physical memory the image occupies, `phys_start..phys_end`.
    pub phys_start: u64,
    pub phys_end: u64,
    /// Pages left unmapped so that overflowing a stack faults.
    pub guards: [u64; 2],
}

pub fn kernel() -> Layout {
    let section = |start: *const u8, end: *const u8| Section {
        start: start as u64,
        end: end as u64,
    };
    Layout {
        text: section(&raw const __text_start, &raw const __text_end),
        rodata: section(&raw const __rodata_start, &raw const __rodata_end),
        data: section(&raw const __data_start, &raw const __bss_end),
        phys_start: &raw const __keep_phys_start as u64,
        phys_end: &raw const __keep_phys_end as u64,
        guards: [
            &raw const boot_stack_guard as u64,
            super::gdt::double_fault_guard(),
        ],
    }
}
