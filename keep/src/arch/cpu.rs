//! Small CPU operations: halting, interrupts on and off, a test trap,
//! turning on the walls that keep ring 0 and ring 3 apart, and reading
//! control registers and feature bits.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

const EFER: u32 = 0xC000_0080;
const EFER_NXE: u64 = 1 << 11;
const EFER_LMA: u64 = 1 << 10;
const APIC_BASE: u32 = 0x1B;
const CR0_EM: u64 = 1 << 2;
const CR0_WP: u64 = 1 << 16;
const CR0_PG: u64 = 1 << 31;
const CR4_UMIP: u64 = 1 << 11;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;
const RFLAGS_IF: u64 = 1 << 9;
/// CPUID leaf 1, EDX: the CPU has a local APIC.
const CPUID_APIC: u32 = 1 << 9;
/// CPUID leaf 7: SMEP (EBX bit 7), SMAP (EBX bit 20), UMIP (ECX bit 2).
const CPUID_SMEP: u32 = 1 << 7;
const CPUID_SMAP: u32 = 1 << 20;
const CPUID_UMIP: u32 = 1 << 2;

/// Whether SMAP is on, so `with_user_access` knows to lift it briefly.
static SMAP_ON: AtomicBool = AtomicBool::new(false);

/// Stop this CPU for good.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: cli and hlt only stop this CPU; they touch no memory.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Turn interrupts off. Returns whether they were on, for
/// `restore_interrupts`.
pub fn disable_interrupts() -> bool {
    let rflags: u64;
    // SAFETY: reads RFLAGS through the stack and clears the interrupt
    // flag, which only holds interrupts back. Not `nomem`, so it is a
    // compiler barrier: memory accesses after it stay after it.
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) rflags, options(preserves_flags)) };
    rflags & RFLAGS_IF != 0
}

/// Turn interrupts back on if they were on before `disable_interrupts`.
pub fn restore_interrupts(were_on: bool) {
    if were_on {
        // SAFETY: interrupts were on before the matching
        // `disable_interrupts`, so this restores that state. A compiler
        // barrier, like `disable_interrupts`.
        unsafe { asm!("sti", options(nostack, preserves_flags)) };
    }
}

/// Run `f` with interrupts off.
pub fn without_interrupts<R>(f: impl FnOnce() -> R) -> R {
    let were_on = disable_interrupts();
    let result = f();
    restore_interrupts(were_on);
    result
}

/// Turn interrupts on and sleep until one arrives.
pub fn wait_for_interrupt() {
    // SAFETY: `sti` takes effect only after the next instruction, so no
    // interrupt can arrive between the two and leave `hlt` waiting for
    // one that already came. The IDT is loaded before anything calls
    // this. Not `nomem`: interrupt handlers run before it returns.
    unsafe { asm!("sti", "hlt", options(nostack, preserves_flags)) };
}

/// Raise a breakpoint trap (`int3`). The IDT's handler returns from it.
pub fn breakpoint() {
    // SAFETY: int3 traps into the breakpoint gate and resumes after it.
    // Not `nomem`: the handler counts the trap in memory.
    unsafe { asm!("int3", options(preserves_flags)) };
}

// Deliberate faults for the boot tests. Each should be stopped by the
// trap handler, which halts the machine; if a protection is missing, the
// access succeeds harmlessly and the function returns, so the caller can
// report it.

/// Read a byte at `addr`.
pub fn read_test(addr: u64) {
    // SAFETY: a read has no effect beyond producing a value, which is
    // discarded. Expected to fault.
    unsafe { asm!("mov al, [{}]", in(reg) addr, out("al") _, options(nostack, readonly)) };
}

/// Write the byte at `addr` back to itself.
pub fn write_test(addr: u64) {
    // SAFETY: the byte written is the one just read, so even if the write
    // is allowed, memory is unchanged. Expected to fault on the write.
    unsafe {
        asm!(
            "mov al, [{0}]",
            "mov [{0}], al",
            in(reg) addr,
            out("al") _,
            options(nostack),
        )
    };
}

/// Call `addr`, which must hold a `ret` instruction.
pub fn exec_test(addr: u64) {
    // SAFETY: the target is a `ret`, so if executing it is allowed it
    // simply returns; the call follows the C ABI for clobbers. Expected to
    // fault on the instruction fetch.
    unsafe { asm!("call {}", in(reg) addr, clobber_abi("C")) };
}

/// Raise interrupt 0x40, which has no gate.
pub fn stray_interrupt_test() {
    // SAFETY: vector 0x40's IDT entry is zero, which is no valid gate,
    // so `int` raises a general protection fault instead, which stops the
    // machine. If a gate were there, its handler would return. Not
    // `nomem`, as for any trap.
    unsafe { asm!("int 0x40", options(preserves_flags)) };
}

/// The address that caused the last page fault.
pub fn cr2() -> u64 {
    let value: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe { asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

fn cr0() -> u64 {
    let value: u64;
    // SAFETY: reading CR0 has no side effects.
    unsafe { asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

/// Read a model-specific register. Only for MSRs this module knows exist:
/// reading one that doesn't raises a general protection fault.
fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: callers pass EFER, which every 64-bit CPU has, or
    // IA32_APIC_BASE after checking for a local APIC. Reading either has
    // no side effects.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high,
             options(nomem, nostack, preserves_flags));
    }
    u64::from(high) << 32 | u64::from(low)
}

/// Whether the CPU is in long mode with paging on.
pub fn long_mode_active() -> bool {
    rdmsr(EFER) & EFER_LMA != 0 && cr0() & CR0_PG != 0
}

/// Whether no-execute page protection is on.
pub fn nx_enabled() -> bool {
    rdmsr(EFER) & EFER_NXE != 0
}

fn has_apic() -> bool {
    let edx: u32;
    // SAFETY: CPUID leaf 1 exists on every 64-bit CPU and only reports
    // features. CPUID overwrites rbx, which the compiler reserves, so the
    // asm saves and restores it.
    unsafe {
        asm!(
            "mov {saved}, rbx",
            "cpuid",
            "mov rbx, {saved}",
            saved = out(reg) _,
            inout("eax") 1u32 => _,
            inout("ecx") 0u32 => _,
            out("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    edx & CPUID_APIC != 0
}

/// The IA32_APIC_BASE register, or None if the CPU has no local APIC.
pub fn apic_base() -> Option<u64> {
    has_apic().then(|| rdmsr(APIC_BASE))
}

/// Which walls between ring 0 and ring 3 the Keep turned on.
pub struct Walls {
    /// Ring 0 can't run ring-3 code (SMEP).
    pub no_user_execute: bool,
    /// Ring 0 can't touch ring-3 memory except through `with_user_access`
    /// (SMAP).
    pub no_user_access: bool,
    /// Ring 3 can't read the descriptor-table registers (UMIP).
    pub hide_tables: bool,
}

/// CPUID leaf 7, subleaf 0: (EBX, ECX), or (0, 0) if the leaf is missing.
fn cpuid_leaf7() -> (u32, u32) {
    let max_leaf: u32;
    // SAFETY: CPUID leaf 0 exists on every 64-bit CPU and returns the
    // highest leaf in EAX. CPUID clobbers rbx, saved and restored here.
    unsafe {
        asm!(
            "mov {tmp}, rbx", "cpuid", "mov rbx, {tmp}",
            tmp = out(reg) _,
            inout("eax") 0u32 => max_leaf,
            out("ecx") _, out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
    }
    if max_leaf < 7 {
        return (0, 0);
    }
    let (ebx, ecx): (u32, u32);
    // SAFETY: leaf 7 exists (checked above) and only reports features.
    // CPUID clobbers rbx; the result is moved out before rbx is restored.
    unsafe {
        asm!(
            "mov {tmp}, rbx", "cpuid", "mov {out:e}, ebx", "mov rbx, {tmp}",
            tmp = out(reg) _,
            out = out(reg) ebx,
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => ecx,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
    }
    (ebx, ecx)
}

/// Turn on the walls between the Keep and user programs, as far as the CPU
/// supports them, and trap any use of the floating-point unit (the Keep
/// and its user programs use none, so there is no FP state to leak between
/// tasks). Call once, at boot. Returns which walls went up.
pub fn harden() -> Walls {
    let (ebx, ecx) = cpuid_leaf7();
    let walls = Walls {
        no_user_execute: ebx & CPUID_SMEP != 0,
        no_user_access: ebx & CPUID_SMAP != 0,
        hide_tables: ecx & CPUID_UMIP != 0,
    };
    let mut cr4 = read_cr4();
    if walls.no_user_execute {
        cr4 |= CR4_SMEP;
    }
    if walls.no_user_access {
        cr4 |= CR4_SMAP;
    }
    if walls.hide_tables {
        cr4 |= CR4_UMIP;
    }
    // SAFETY: SMEP, SMAP and UMIP only forbid ring 0 from running or
    // reaching ring-3 memory and ring 3 from reading descriptor-table
    // registers. The Keep reaches user memory only through
    // `with_user_access`, which lifts SMAP around that one access. CR0.WP
    // (already on) and CR0.EM: WP makes ring 0 honor read-only pages, EM
    // traps FP instructions, which this soft-float build never emits.
    unsafe {
        write_cr4(cr4);
        write_cr0(cr0() | CR0_WP | CR0_EM);
    }
    SMAP_ON.store(walls.no_user_access, Ordering::Relaxed);
    walls
}

/// Run `f` with the Keep briefly allowed to touch user memory, if SMAP is
/// on. `f` does one bounded, already-checked access to a user buffer and
/// nothing else; interrupts are off, so nothing runs with access lifted.
pub fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    if !SMAP_ON.load(Ordering::Relaxed) {
        return f();
    }
    // SAFETY: SMAP is on (checked above), so `stac` and `clac` are valid;
    // they only set and clear RFLAGS.AC, which lets ring 0 reach ring-3
    // pages in between. The caller does one checked user access and no
    // more. Compiler barriers keep that access between the two.
    unsafe { asm!("stac", options(nostack)) };
    let result = f();
    // SAFETY: as above; clac restores the ban on reaching user memory.
    unsafe { asm!("clac", options(nostack)) };
    result
}

/// Copy `dst.len()` bytes from user address `src` into `dst`. The caller
/// must have checked that `[src, src + dst.len())` is present, user-owned
/// memory in the address space now loaded (the calling task's), so this
/// reads only that task's memory.
pub fn copy_from_user(dst: &mut [u8], src: u64) {
    with_user_access(|| {
        for (i, slot) in dst.iter_mut().enumerate() {
            let at = src.wrapping_add(i as u64);
            // SAFETY: the caller validated the whole range as present
            // user memory in the current space; `i < dst.len()`, so `at`
            // is inside it. Volatile, as it is another ring's memory.
            *slot = unsafe { (at as *const u8).read_volatile() };
        }
    });
}

/// Copy `src.len()` bytes into user address `dst`. The caller must have
/// checked that `[dst, dst + src.len())` is present, user-owned, writable
/// memory in the address space now loaded (the calling task's), so this
/// writes only that task's memory.
pub fn copy_to_user(dst: u64, src: &[u8]) {
    with_user_access(|| {
        for (i, &byte) in src.iter().enumerate() {
            let at = dst.wrapping_add(i as u64);
            // SAFETY: the caller validated the whole range as present,
            // writable user memory in the current space; `i < src.len()`,
            // so `at` is inside it. Volatile, as it is another ring's
            // memory.
            unsafe { (at as *mut u8).write_volatile(byte) };
        }
    });
}

fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: reading CR4 has no side effects.
    unsafe { asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

/// # Safety
/// The caller must keep paging and long mode on (bits the Keep never
/// clears) and set only bits the CPU supports.
unsafe fn write_cr4(value: u64) {
    // SAFETY: the caller upholds the contract above.
    unsafe { asm!("mov cr4, {}", in(reg) value, options(nomem, nostack, preserves_flags)) };
}

/// # Safety
/// The caller must keep paging, protection and write-protect on.
unsafe fn write_cr0(value: u64) {
    // SAFETY: the caller upholds the contract above.
    unsafe { asm!("mov cr0, {}", in(reg) value, options(nomem, nostack, preserves_flags)) };
}
