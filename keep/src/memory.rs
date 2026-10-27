//! The Keep's own address space.
//!
//! Replaces the boot map (the first GiB mapped writable and executable
//! twice) with tables that give every part of the Keep only the access
//! it needs:
//!
//! - code: read and execute, never written
//! - constants: read only, never executed
//! - data and stacks: read and write, never executed; a guard page under
//!   each stack is left unmapped, so an overflow faults instead of
//!   silently overwriting memory
//! - task stacks: read and write, never executed, each above an unmapped
//!   gap of 48 KiB
//! - device registers: read and write, uncached, never executed
//! - all RAM: read and write through the physical-memory window, never
//!   executed
//!
//! Nothing is mapped in the lower half, so a null pointer faults, and the
//! lower half stays free for user tasks.

#![forbid(unsafe_code)]

use crate::arch::layout::{
    self, APIC_VIRT, KERNEL_BASE, STACK_SIZE, Section, TASK_SLOTS, stack_top,
};
use crate::arch::paging::{
    AddressSpace, FrameSource, GLOBAL, HUGE_PAGE_SIZE, MapError, NO_EXECUTE, PAGE_SIZE,
    PHYS_WINDOW, UNCACHED, WRITABLE,
};

const CODE: u64 = GLOBAL;
const READ_ONLY: u64 = GLOBAL | NO_EXECUTE;
const READ_WRITE: u64 = GLOBAL | WRITABLE | NO_EXECUTE;
const DEVICE: u64 = GLOBAL | WRITABLE | NO_EXECUTE | UNCACHED;
/// The window covers physical memory up to here at most.
const WINDOW_LIMIT: u64 = 64 << 30;

pub struct KernelSpace {
    pub space: AddressSpace,
    pub window_bytes: u64,
    /// Guard pages in the Keep's image, under the boot and double-fault
    /// stacks.
    pub guard_pages: usize,
    pub task_stacks: usize,
}

/// Build the Keep's address space, mapping RAM up to `top_of_ram` and the
/// local APIC's registers from `apic`.
pub fn build(
    frames: &mut impl FrameSource,
    top_of_ram: u64,
    apic: u64,
) -> Result<KernelSpace, MapError> {
    let layout = layout::kernel();
    let mut space = AddressSpace::new(frames)?;
    let mut guards = 0;
    for (section, flags) in [
        (layout.text, CODE),
        (layout.rodata, READ_ONLY),
        (layout.data, READ_WRITE),
    ] {
        guards += map_section(&mut space, frames, section, flags, &layout.guards)?;
    }

    // Slot 0 is the idle task, which keeps the boot stack.
    for slot in 1..TASK_SLOTS {
        let top = stack_top(slot);
        let mut virt = top - STACK_SIZE;
        while virt < top {
            space.map_zeroed(virt, READ_WRITE, frames)?;
            virt += PAGE_SIZE;
        }
    }

    space.map_page(APIC_VIRT, apic, DEVICE, frames)?;

    let window = top_of_ram
        .min(WINDOW_LIMIT)
        .next_multiple_of(HUGE_PAGE_SIZE);
    let mut phys = 0;
    while phys < window {
        space.map_huge(PHYS_WINDOW + phys, phys, READ_WRITE, frames)?;
        phys += HUGE_PAGE_SIZE;
    }

    Ok(KernelSpace {
        space,
        window_bytes: window,
        guard_pages: guards,
        task_stacks: TASK_SLOTS - 1,
    })
}

/// Map a section of the Keep's image with 4 KiB pages, skipping guard
/// pages. Returns how many guard pages it skipped.
fn map_section(
    space: &mut AddressSpace,
    frames: &mut impl FrameSource,
    section: Section,
    flags: u64,
    guards: &[u64],
) -> Result<usize, MapError> {
    let mut skipped = 0;
    let mut virt = section.start;
    while virt < section.end {
        if guards.contains(&virt) {
            skipped += 1;
        } else {
            space.map_page(virt, virt - KERNEL_BASE, flags, frames)?;
        }
        virt += PAGE_SIZE;
    }
    Ok(skipped)
}
