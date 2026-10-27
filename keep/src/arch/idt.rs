//! The IDT and trap entry.
//!
//! Every vector the Keep handles has a small assembly stub that makes the
//! stack look the same for every vector (pushing a zero where the CPU
//! pushes no error code), saves the general registers and calls
//! `keep_trap`. That returns the frame to restore: the same one, or,
//! when the scheduler switches tasks, the frame another task saved on
//! its own stack. The decisions live in `crate::trap` and `crate::sched`.

use super::cpu;
use super::gdt::{DOUBLE_FAULT_IST, KERNEL_CODE};
use super::task::Context;
use core::arch::{asm, global_asm};
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};

/// The local APIC timer.
pub const TIMER_VECTOR: u8 = 0x30;
/// A task giving up the CPU (`cpu::yield_now`).
pub const YIELD_VECTOR: u8 = 0x31;
/// Where the local APIC sends interrupts that vanished before delivery.
pub const SPURIOUS_VECTOR: u8 = 0xFF;
/// A user program asking the Keep for something (`abi::VECTOR`).
pub const SYSCALL_VECTOR: u8 = 0x80;
// The assembly below names these vectors by number.
const _: () = assert!(TIMER_VECTOR == 48 && YIELD_VECTOR == 49 && SPURIOUS_VECTOR == 255);
const _: () = assert!(SYSCALL_VECTOR == 128 && SYSCALL_VECTOR == abi::VECTOR);
/// The 32 exception vectors, then the timer, yield, syscall and spurious.
const GATES: usize = 36;
const DOUBLE_FAULT: u8 = 8;
const PAGE_FAULT: u8 = 14;
/// Present, ring 0, 64-bit interrupt gate (interrupts stay off inside).
const INTERRUPT_GATE: u64 = 0x8E;
/// Like INTERRUPT_GATE, but ring 3 may invoke it: the syscall gate, so a
/// user program's `int 0x80` is allowed instead of faulting.
const SYSCALL_GATE: u64 = 0xEE;

#[repr(C, align(16))]
struct Idt([u64; 512]);

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

static mut IDT: Idt = Idt([0; 512]);

/// How many traps are being handled right now. Tasks switch only from
/// the outermost trap: a switch requested inside a trap handler would
/// leave two saved states on one stack.
static DEPTH: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    /// A (vector, entry stub address) pair for each gate, defined in the
    /// assembly below.
    static isr_stub_table: [[u64; 2]; GATES];
}

/// What the entry stubs save, lowest address first. Every field must be
/// here for the layout to match the stubs, even ones not read yet.
#[repr(C)]
pub struct TrapFrame {
    pub(super) r15: u64,
    pub(super) r14: u64,
    pub(super) r13: u64,
    pub(super) r12: u64,
    pub(super) r11: u64,
    pub(super) r10: u64,
    pub(super) r9: u64,
    pub(super) r8: u64,
    pub(super) rbp: u64,
    pub(super) rdi: u64,
    pub(super) rsi: u64,
    pub(super) rdx: u64,
    pub(super) rcx: u64,
    pub(super) rbx: u64,
    pub(super) rax: u64,
    pub(super) vector: u64,
    pub(super) error_code: u64,
    pub(super) rip: u64,
    pub(super) cs: u64,
    pub(super) rflags: u64,
    pub(super) rsp: u64,
    pub(super) ss: u64,
}

impl TrapFrame {
    pub(super) const ZERO: TrapFrame = TrapFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        vector: 0,
        error_code: 0,
        rip: 0,
        cs: 0,
        rflags: 0,
        rsp: 0,
        ss: 0,
    };
}

/// Install the gates: the 32 exception vectors, the timer, yield and the
/// spurious vector. Call once, at boot, after the GDT. Every other entry
/// stays zero, which is no valid gate, so a stray interrupt raises a
/// general protection fault and fails closed.
pub fn init() {
    // SAFETY: the table is a read-only array defined in the assembly
    // below, and it is never written.
    let stubs: &[[u64; 2]; GATES] = unsafe { &isr_stub_table };
    for &[vector, handler] in stubs {
        let ist = if vector == u64::from(DOUBLE_FAULT) {
            DOUBLE_FAULT_IST
        } else {
            0
        };
        let gate = if vector == u64::from(SYSCALL_VECTOR) {
            SYSCALL_GATE
        } else {
            INTERRUPT_GATE
        };
        let low = (handler & 0xFFFF)
            | u64::from(KERNEL_CODE) << 16
            | u64::from(ist) << 32
            | gate << 40
            | (handler >> 16 & 0xFFFF) << 48;
        let high = handler >> 32;
        let slot = 2 * vector as usize;
        // SAFETY: this runs once, on the only CPU, with interrupts off and
        // before the IDT is loaded, so nothing else reads it yet. Indexing
        // is bounds-checked.
        unsafe {
            let idt = &raw mut IDT;
            (*idt).0[slot] = low;
            (*idt).0[slot + 1] = high;
        }
    }
    let pointer = Pointer {
        limit: (size_of::<Idt>() - 1) as u16,
        base: &raw const IDT as u64,
    };
    // SAFETY: the IDT is a static that lives forever and now holds valid
    // gates for every vector the Keep handles.
    unsafe { asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags)) };
}

/// Called by the entry stubs with the state of the interrupted code.
/// Returns the frame to restore.
#[unsafe(no_mangle)]
extern "C" fn keep_trap(frame: *mut TrapFrame) -> *mut TrapFrame {
    // SAFETY: the entry stub passes the frame it just pushed on this
    // stack, which stays in place until the stub restores a frame.
    let (vector, error_code, rip) = unsafe { ((*frame).vector, (*frame).error_code, (*frame).rip) };
    let outermost = DEPTH.fetch_add(1, Ordering::Relaxed) == 0;
    let resume = dispatch(frame, vector as u8, error_code, rip, outermost);
    DEPTH.fetch_sub(1, Ordering::Relaxed);
    resume
}

fn dispatch(
    frame: *mut TrapFrame,
    vector: u8,
    error_code: u64,
    rip: u64,
    outermost: bool,
) -> *mut TrapFrame {
    match vector {
        TIMER_VECTOR | YIELD_VECTOR | SYSCALL_VECTOR if !outermost => {
            kprintln!("[keep] trap: task switch asked for inside a trap handler; stopping");
            crate::fail_closed()
        }
        TIMER_VECTOR => {
            super::apic::end_of_interrupt();
            crate::sched::tick(Context::saved(frame)).resume()
        }
        YIELD_VECTOR => crate::sched::switch(Context::saved(frame)).resume(),
        SYSCALL_VECTOR => crate::syscall::handle(super::task::SyscallFrame::new(frame)).resume(),
        SPURIOUS_VECTOR => frame, // nothing to acknowledge
        vector => {
            // SAFETY: the frame is the one the entry stub just pushed; its
            // cs names the ring the fault came from (3 for a user task).
            let from_user = unsafe { (*frame).cs } & 3 == 3;
            let trap = crate::trap::Trap {
                vector,
                error_code,
                rip,
                fault_addr: match vector {
                    PAGE_FAULT | DOUBLE_FAULT => cpu::cr2(),
                    _ => 0,
                },
                from_user,
            };
            match crate::trap::handle(&trap) {
                crate::trap::Action::Resume => frame,
                // A user task that faults is ended; the Keep carries on.
                crate::trap::Action::Stop if from_user && outermost => {
                    crate::sched::kill_current(Context::saved(frame)).resume()
                }
                crate::trap::Action::Stop => crate::fail_closed(),
            }
        }
    }
}

global_asm!(
    ".section .text.isr, \"ax\"",
    ".macro ISR_NOERR n",
    "isr_\\n:",
    "    push 0",
    "    push \\n",
    "    jmp isr_common",
    ".endm",
    ".macro ISR_ERR n",
    "isr_\\n:",
    "    push \\n",
    "    jmp isr_common",
    ".endm",
    // Vectors where the CPU pushes no error code (the exceptions without
    // one, the timer, yield and spurious), then those where it does.
    ".irp n, 0,1,2,3,4,5,6,7,9,15,16,18,19,20,22,23,24,25,26,27,28,31,48,49,128,255",
    "ISR_NOERR \\n",
    ".endr",
    ".irp n, 8,10,11,12,13,14,17,21,29,30",
    "ISR_ERR \\n",
    ".endr",
    "isr_common:",
    "    push rax",
    "    push rbx",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push rbp",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov rdi, rsp",
    "    cld",
    "    call keep_trap",
    // The frame to restore: this one, or another task's.
    "    mov rsp, rax",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rbp",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rbx",
    "    pop rax",
    "    add rsp, 16", // vector and error code
    "    iretq",
    "",
    ".section .rodata.isr_table, \"a\"",
    ".balign 8",
    ".global isr_stub_table",
    "isr_stub_table:",
    ".irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,48,49,128,255",
    "    .quad \\n, isr_\\n",
    ".endr",
);

/// Addresses that must stay mapped for traps to work: the IDT and the
/// entry stubs.
pub fn tables() -> [u64; 2] {
    // SAFETY: reads the stub table's first entry; the table is never
    // written.
    let [_, stub] = unsafe { isr_stub_table[0] };
    [&raw const IDT as u64, stub]
}
