//! The GDT and TSS: ring-0 and ring-3 code and data segments, the kernel
//! stack the CPU switches to when a ring-3 task traps (RSP0), and a
//! separate stack for double faults, so a fault caused by a broken stack
//! can still be reported.

use core::arch::asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};

pub const KERNEL_CODE: u16 = 0x08;
pub const KERNEL_DATA: u16 = 0x10;
/// Ring-3 selectors: the low two bits are the requested privilege, 3.
pub const USER_CODE: u16 = 0x18 | 3;
pub const USER_DATA: u16 = 0x20 | 3;
const TSS_SELECTOR: u16 = 0x28;
/// Interrupt-stack-table slot (numbered from 1, as the IDT counts them).
pub const DOUBLE_FAULT_IST: u8 = 1;
const STACK_SIZE: usize = 16 * 1024;

const PAGE: usize = 4096;

/// A stack with a guard page below it, which the Keep's page tables leave
/// unmapped.
#[repr(C, align(4096))]
struct GuardedStack {
    guard: [u8; PAGE],
    stack: [u8; STACK_SIZE],
}

/// The 104-byte 64-bit TSS, as 32-bit words because its 64-bit fields
/// are not naturally aligned. RSP0 is words 1 and 2; IST1 is words 9
/// and 10.
#[repr(C, align(16))]
struct Tss([u32; 26]);

#[repr(C, align(8))]
struct Gdt([u64; 7]);

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

static mut DOUBLE_FAULT_STACK: GuardedStack = GuardedStack {
    guard: [0; PAGE],
    stack: [0; STACK_SIZE],
};
static mut TSS: Tss = Tss([0; 26]);
static mut GDT: Gdt = Gdt([
    0,
    0x00AF_9A00_0000_FFFF, // 0x08 kernel code (ring 0)
    0x00CF_9200_0000_FFFF, // 0x10 kernel data (ring 0)
    0x00AF_FA00_0000_FFFF, // 0x18 user code (ring 3)
    0x00CF_F200_0000_FFFF, // 0x20 user data (ring 3)
    0,                     // 0x28 TSS descriptor, low half
    0,                     // 0x30 TSS descriptor, high half
]);

/// The address of the TSS's RSP0 field, so the scheduler can point it at
/// each ring-3 task's kernel stack. Set by `init`; 0 before then.
static RSP0: AtomicU64 = AtomicU64::new(0);

/// Install the Keep's GDT and TSS. Call once, at boot.
pub fn init() {
    let stack_top = double_fault_stack_top();
    let tss_base = &raw const TSS as u64;
    let tss_limit = (size_of::<Tss>() - 1) as u64;
    let tss_low = (tss_limit & 0xFFFF)
        | (tss_base & 0xFF_FFFF) << 16
        | 0x89 << 40 // present, available 64-bit TSS
        | (tss_limit >> 16 & 0xF) << 48
        | (tss_base >> 24 & 0xFF) << 56;
    let tss_high = tss_base >> 32;

    // SAFETY: this runs once, on the only CPU, with interrupts off and
    // before the GDT or TSS is loaded, so nothing else reads them yet.
    // Raw pointers avoid references to the mutable statics.
    unsafe {
        let tss = &raw mut TSS;
        (*tss).0[9] = stack_top as u32; // IST1, low half
        (*tss).0[10] = (stack_top >> 32) as u32; // IST1, high half
        (*tss).0[25] = (size_of::<Tss>() as u32) << 16; // no I/O bitmap
        let gdt = &raw mut GDT;
        (*gdt).0[5] = tss_low;
        (*gdt).0[6] = tss_high;
    }
    RSP0.store(&raw const TSS as u64 + 4, Ordering::Relaxed);

    let pointer = Pointer {
        limit: (size_of::<Gdt>() - 1) as u16,
        base: &raw const GDT as u64,
    };
    // SAFETY: the GDT is a static that lives forever and keeps the boot
    // GDT's code and data selectors, so reloading CS, DS, ES and SS keeps
    // the same flat segments. `ltr` loads the TSS filled in above.
    unsafe {
        asm!("lgdt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
        asm!(
            "push {sel}",
            "lea {tmp}, [rip + 55f]",
            "push {tmp}",
            "retfq",
            "55:",
            sel = in(reg) u64::from(KERNEL_CODE),
            tmp = lateout(reg) _,
            options(preserves_flags),
        );
        asm!(
            "mov ds, {0:x}",
            "mov es, {0:x}",
            "mov ss, {0:x}",
            in(reg) KERNEL_DATA,
            options(nostack, preserves_flags),
        );
        asm!("ltr {0:x}", in(reg) TSS_SELECTOR, options(nostack, preserves_flags));
    }
}

/// Point RSP0 at `stack_top`: the kernel stack the CPU switches to when a
/// ring-3 task traps. The scheduler sets this to the task about to run,
/// with interrupts off, before returning to it.
pub fn set_kernel_stack(stack_top: u64) {
    let field = RSP0.load(Ordering::Relaxed);
    if field == 0 {
        return;
    }
    // SAFETY: `field` is the address of the TSS's 8-byte RSP0, set by
    // `init` once the TSS exists. The CPU reads RSP0 only when it takes a
    // ring-3-to-ring-0 interrupt; this writes it with interrupts off (in
    // the scheduler), so no such interrupt reads it half-written.
    unsafe { (field as *mut u64).write_unaligned(stack_top) };
}

/// The page below the double-fault stack, left unmapped.
pub fn double_fault_guard() -> u64 {
    &raw const DOUBLE_FAULT_STACK as u64
}

/// The top of the double-fault stack (it grows down).
pub fn double_fault_stack_top() -> u64 {
    &raw const DOUBLE_FAULT_STACK as u64 + (PAGE + STACK_SIZE) as u64
}

/// Addresses of the GDT and TSS, which must stay mapped.
pub fn tables() -> [u64; 2] {
    [&raw const GDT as u64, &raw const TSS as u64]
}
