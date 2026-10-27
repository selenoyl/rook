//! What the Keep does when the CPU raises an exception.
//!
//! Fail closed, but no further than the fault reaches. A breakpoint (the
//! self-check) resumes. A fault in a user task ends that task and lets
//! the Keep carry on, since a user program is isolated and only hurts
//! itself. A fault in the Keep's own code stops the machine rather than
//! running on in an unknown state.

#![forbid(unsafe_code)]

use crate::arch::layout;
use core::sync::atomic::{AtomicU32, Ordering};

const BREAKPOINT: u8 = 3;
const DOUBLE_FAULT: u8 = 8;
const INVALID_TSS: u8 = 10;
const GENERAL_PROTECTION: u8 = 13;
const PAGE_FAULT: u8 = 14;
/// In a selector error code: the index is an IDT vector.
const SELECTOR_IDT: u64 = 1 << 1;

pub struct Trap {
    pub vector: u8,
    pub error_code: u64,
    pub rip: u64,
    /// For page faults and double faults, the address the last page
    /// fault touched.
    pub fault_addr: u64,
    /// Whether the fault came from a ring-3 (user) task.
    pub from_user: bool,
}

pub enum Action {
    Resume,
    Stop,
}

static BREAKPOINTS: AtomicU32 = AtomicU32::new(0);

/// How many breakpoint traps have been handled.
pub fn breakpoints() -> u32 {
    BREAKPOINTS.load(Ordering::Relaxed)
}

pub fn handle(trap: &Trap) -> Action {
    if trap.vector == BREAKPOINT && !trap.from_user {
        BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        kprintln!("[keep] trap: breakpoint at {:#x}, resuming", trap.rip);
        return Action::Resume;
    }
    // A user fault ends only that task; a Keep fault stops the machine.
    let ending = if trap.from_user {
        "ending the task"
    } else {
        "stopping"
    };
    match trap.vector {
        PAGE_FAULT => kprintln!(
            "[keep] trap: page fault at {:#x} touching {:#x} (error {:#x}); {ending}",
            trap.rip,
            trap.fault_addr,
            trap.error_code
        ),
        vector => kprintln!(
            "[keep] trap: {} (vector {}) at {:#x}, error {:#x}; {ending}",
            name(vector),
            vector,
            trap.rip,
            trap.error_code
        ),
    }
    // These faults' error codes can name an IDT entry: a vector with no
    // gate was raised.
    if (INVALID_TSS..=GENERAL_PROTECTION).contains(&trap.vector)
        && trap.error_code & SELECTOR_IDT != 0
    {
        kprintln!(
            "[keep] trap: interrupt {:#x} arrived, and it has no gate",
            trap.error_code >> 3
        );
    }
    // A stack overflow shows up as a page fault in a guard, or, when the
    // CPU can't push the page fault's frame either, as a double fault.
    if matches!(trap.vector, PAGE_FAULT | DOUBLE_FAULT) {
        if let Some(guard) = layout::guard_at(trap.fault_addr) {
            kprintln!(
                "[keep] trap: {:#x} is in {guard}: a stack overflow",
                trap.fault_addr
            );
        } else if trap.from_user && layout::user_stack_overflow(trap.fault_addr) {
            kprintln!(
                "[keep] trap: {:#x} is below the task's stack: a stack overflow",
                trap.fault_addr
            );
        }
    }
    if let Some((slot, name)) = crate::sched::running_task() {
        kprintln!("[keep] trap: task {slot} ({name}) was running");
    }
    Action::Stop
}

fn name(vector: u8) -> &'static str {
    match vector {
        0 => "divide error",
        1 => "debug",
        2 => "non-maskable interrupt",
        3 => "breakpoint",
        4 => "overflow",
        5 => "bound range exceeded",
        6 => "invalid opcode",
        7 => "device not available",
        8 => "double fault",
        10 => "invalid TSS",
        11 => "segment not present",
        12 => "stack-segment fault",
        13 => "general protection fault",
        14 => "page fault",
        16 => "x87 floating-point error",
        17 => "alignment check",
        18 => "machine check",
        19 => "SIMD floating-point error",
        20 => "virtualization exception",
        21 => "control protection",
        28 => "hypervisor injection",
        29 => "VMM communication",
        30 => "security exception",
        _ => "reserved exception",
    }
}
