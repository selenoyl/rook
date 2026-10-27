//! Low-level x86-64 code: the only part of the Keep allowed to use
//! `unsafe`. Every unsafe block and unsafe attribute here is listed, with
//! why it is sound, in UNSAFE.md.

pub mod apic;
pub mod boot;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod layout;
pub mod multiboot;
pub mod paging;
pub mod pic;
mod pit;
mod port;
pub mod qemu;
pub mod serial;
pub mod sync;
pub mod task;
pub mod vga;

/// Addresses the CPU uses behind the Keep's back, which must map to the
/// same physical memory before and after the Keep switches page tables:
/// descriptor tables, trap entry, the double-fault stack and the screen.
pub fn must_stay_mapped() -> [(u64, u64); 6] {
    let kernel = |virt: u64| (virt, virt.wrapping_sub(layout::KERNEL_BASE));
    let [gdt, tss] = gdt::tables();
    let [idt, stub] = idt::tables();
    let window = paging::PHYS_WINDOW + vga::BUFFER_PHYS;
    [
        kernel(gdt),
        kernel(tss),
        kernel(idt),
        kernel(stub),
        kernel(gdt::double_fault_stack_top() - 8),
        (window, vga::BUFFER_PHYS),
    ]
}
