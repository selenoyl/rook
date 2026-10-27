//! Page tables: building an address space, and switching to it.
//!
//! Page-table frames are reached through `phys_to_virt`: through the boot
//! identity map until the Keep loads its own tables, then through the
//! physical-memory window, which maps all RAM at PHYS_WINDOW.

use super::layout::KERNEL_BASE;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

pub const PAGE_SIZE: u64 = 4096;
pub const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
/// Where all physical memory is mapped once the Keep's tables are loaded.
pub const PHYS_WINDOW: u64 = 0xFFFF_8000_0000_0000;

pub const PRESENT: u64 = 1 << 0;
pub const WRITABLE: u64 = 1 << 1;
/// Ring 3 may reach this page. A page is reachable from ring 3 only if
/// every table leading to it, and the page itself, has this bit.
pub const USER: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
/// Page-level write-through and cache-disable: with the default PAT,
/// uncached, as device registers need.
pub const UNCACHED: u64 = 1 << 3 | 1 << 4;
pub const GLOBAL: u64 = 1 << 8;
pub const NO_EXECUTE: u64 = 1 << 63;
const ADDRESS: u64 = 0x000F_FFFF_FFFF_F000;
const ENTRIES: u64 = 512;
const CR4_GLOBAL_PAGES: u64 = 1 << 7;

/// Added to a physical address to reach it from the Keep.
static ACCESS_OFFSET: AtomicU64 = AtomicU64::new(0);

/// The virtual address the Keep uses for a physical address.
pub fn phys_to_virt(phys: u64) -> u64 {
    phys.wrapping_add(ACCESS_OFFSET.load(Ordering::Relaxed))
}

/// Something that hands out unused 4 KiB frames (physical addresses).
pub trait FrameSource {
    fn frame(&mut self) -> Option<u64>;
}

#[derive(Debug, Clone, Copy)]
pub enum MapError {
    OutOfFrames,
    /// Something is already mapped there.
    Overlap(u64),
    Unaligned(u64),
    /// A check before switching found this address unmapped or mapped
    /// somewhere else.
    Missing(u64),
}

impl core::fmt::Display for MapError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            MapError::OutOfFrames => write!(f, "out of memory for page tables"),
            MapError::Overlap(a) => write!(f, "{a:#x} is already mapped"),
            MapError::Unaligned(a) => write!(f, "{a:#x} is not page-aligned"),
            MapError::Missing(a) => write!(f, "{a:#x} would not stay mapped"),
        }
    }
}

/// A four-level page table, identified by its top-level frame.
pub struct AddressSpace {
    root: u64,
}

fn index(virt: u64, level: u32) -> u64 {
    (virt >> (12 + 9 * (level - 1))) & (ENTRIES - 1)
}

fn entry_ptr(table: u64, i: u64) -> *mut u64 {
    (phys_to_virt(table) as *mut u64).wrapping_add((i % ENTRIES) as usize)
}

/// Read entry `i` (the `i`th 64-bit word) of the page table in frame
/// `table`.
fn read(table: u64, i: u64) -> u64 {
    // SAFETY: `table` is always a frame this module took from a
    // FrameSource (so nothing else owns it): a page table, or a page it
    // zeroes before mapping. It is reachable through phys_to_virt, and
    // `entry_ptr` keeps the index inside the frame.
    unsafe { entry_ptr(table, i).read_volatile() }
}

/// Write entry `i` of the page table in frame `table`.
fn write(table: u64, i: u64, value: u64) {
    // SAFETY: as for `read`. These frames are never Rust objects, so no
    // reference aliases the write.
    unsafe { entry_ptr(table, i).write_volatile(value) }
}

/// A frame from `frames`, filled with zeros.
fn zeroed_frame(frames: &mut impl FrameSource) -> Result<u64, MapError> {
    let frame = frames.frame().ok_or(MapError::OutOfFrames)?;
    for i in 0..ENTRIES {
        write(frame, i, 0);
    }
    Ok(frame)
}

impl AddressSpace {
    pub fn new(frames: &mut impl FrameSource) -> Result<AddressSpace, MapError> {
        Ok(AddressSpace {
            root: zeroed_frame(frames)?,
        })
    }

    /// The table at `level` (1 = page table .. 3 = PDPT) that covers
    /// `virt`, creating the ones above it as needed.
    fn table_for(
        &mut self,
        virt: u64,
        level: u32,
        frames: &mut impl FrameSource,
    ) -> Result<u64, MapError> {
        let mut table = self.root;
        for current in (level + 1..=4).rev() {
            let i = index(virt, current);
            let entry = read(table, i);
            table = if entry & PRESENT == 0 {
                let next = zeroed_frame(frames)?;
                write(table, i, next | PRESENT | WRITABLE | USER);
                next
            } else if entry & HUGE != 0 {
                return Err(MapError::Overlap(virt));
            } else {
                entry & ADDRESS
            };
        }
        Ok(table)
    }

    /// Map one 4 KiB page. `flags` sets the permissions; PRESENT is added.
    pub fn map_page(
        &mut self,
        virt: u64,
        phys: u64,
        flags: u64,
        frames: &mut impl FrameSource,
    ) -> Result<(), MapError> {
        if !virt.is_multiple_of(PAGE_SIZE) || !phys.is_multiple_of(PAGE_SIZE) {
            return Err(MapError::Unaligned(virt));
        }
        let table = self.table_for(virt, 1, frames)?;
        let i = index(virt, 1);
        if read(table, i) & PRESENT != 0 {
            return Err(MapError::Overlap(virt));
        }
        write(table, i, phys | flags | PRESENT);
        Ok(())
    }

    /// Map a fresh, zeroed frame at `virt`.
    pub fn map_zeroed(
        &mut self,
        virt: u64,
        flags: u64,
        frames: &mut impl FrameSource,
    ) -> Result<(), MapError> {
        let frame = zeroed_frame(frames)?;
        self.map_page(virt, frame, flags, frames)
    }

    /// Map a fresh page at `virt`, its first bytes set to `data` and the
    /// rest left zero: one page of a loaded program. `data` is at most a
    /// page.
    pub fn map_filled(
        &mut self,
        virt: u64,
        flags: u64,
        data: &[u8],
        frames: &mut impl FrameSource,
    ) -> Result<(), MapError> {
        if data.len() as u64 > PAGE_SIZE {
            return Err(MapError::Unaligned(virt));
        }
        let frame = zeroed_frame(frames)?;
        let dst = phys_to_virt(frame) as *mut u8;
        for (i, &byte) in data.iter().enumerate() {
            // SAFETY: `frame` is a fresh frame from the allocator, owned
            // by this mapping and reachable through the window; `i` is
            // less than `data.len()`, which is at most a page, so the
            // write stays inside the frame.
            unsafe { dst.add(i).write_volatile(byte) };
        }
        self.map_page(virt, frame, flags, frames)
    }

    /// Map one 2 MiB page.
    pub fn map_huge(
        &mut self,
        virt: u64,
        phys: u64,
        flags: u64,
        frames: &mut impl FrameSource,
    ) -> Result<(), MapError> {
        if !virt.is_multiple_of(HUGE_PAGE_SIZE) || !phys.is_multiple_of(HUGE_PAGE_SIZE) {
            return Err(MapError::Unaligned(virt));
        }
        let table = self.table_for(virt, 2, frames)?;
        let i = index(virt, 2);
        if read(table, i) & PRESENT != 0 {
            return Err(MapError::Overlap(virt));
        }
        write(table, i, phys | flags | PRESENT | HUGE);
        Ok(())
    }

    /// The physical address of this space's top-level table, for CR3.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// A read-only view of the address space now loaded (from CR3), for
    /// checking a running task's own mappings. It owns nothing: the tables
    /// belong to whatever built them.
    pub fn current() -> AddressSpace {
        let root: u64;
        // SAFETY: reading CR3 has no side effects; the value is the
        // physical address of the live top-level table.
        unsafe { asm!("mov {}, cr3", out(reg) root, options(nomem, nostack, preserves_flags)) };
        AddressSpace {
            root: root & ADDRESS,
        }
    }

    /// Whether `[start, start + len)` is entirely present, user-owned
    /// memory in this space: the check the Keep makes before reading a
    /// buffer a user task names, so the task can't aim it at the Keep's
    /// own memory.
    pub fn user_range_ok(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        let mut page = start & !(PAGE_SIZE - 1);
        while page < end {
            match self.translate(page) {
                Some((_, flags)) if flags & (PRESENT | USER) == PRESENT | USER => {}
                _ => return false,
            }
            match page.checked_add(PAGE_SIZE) {
                Some(next) => page = next,
                None => return false,
            }
        }
        true
    }

    /// A new user address space: its own empty lower half, and the Keep's
    /// entire higher half shared, so the Keep stays mapped at the same
    /// addresses while a user task runs. The higher-half tables are
    /// shared, not copied, so every space sees one set of kernel pages.
    pub fn new_user(
        kernel: &AddressSpace,
        frames: &mut impl FrameSource,
    ) -> Result<AddressSpace, MapError> {
        let root = zeroed_frame(frames)?;
        for i in ENTRIES / 2..ENTRIES {
            write(root, i, read(kernel.root, i));
        }
        Ok(AddressSpace { root })
    }

    /// The physical address and flags `virt` maps to, if it is mapped.
    pub fn translate(&self, virt: u64) -> Option<(u64, u64)> {
        let mut table = self.root;
        for level in (1..=4).rev() {
            let entry = read(table, index(virt, level));
            if entry & PRESENT == 0 {
                return None;
            }
            let page = match (level, entry & HUGE != 0) {
                (1, _) => PAGE_SIZE,
                (2, true) => HUGE_PAGE_SIZE,
                (_, true) => return None, // 1 GiB pages aren't used
                _ => {
                    table = entry & ADDRESS;
                    continue;
                }
            };
            let base = entry & ADDRESS & !(page - 1);
            return Some((base | (virt & (page - 1)), entry & !ADDRESS));
        }
        None
    }
}

/// Switch CR3 to the tables rooted at `root`. The caller must keep the
/// running code, the stack and everything the CPU touches mapped at the
/// same addresses: a user space from `new_user` shares the Keep's whole
/// higher half, so switching to one from kernel code does.
pub fn activate(root: u64) {
    // SAFETY: a user space built by `new_user` holds every higher-half
    // entry the Keep's space has, so the kernel code running now, its
    // stack and all kernel data stay mapped where they were; only the
    // lower half changes. Loading CR3 flushes the old non-global (user)
    // TLB entries. The asm is a compiler barrier.
    unsafe { asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) };
}

/// Switch to `space`, after checking it maps the code running now, the
/// stack, and each `(virtual, physical)` pair in `must_map` (descriptor
/// tables, interrupt stacks, the screen) exactly as the current tables do.
pub fn load_kernel_space(space: &AddressSpace, must_map: &[(u64, u64)]) -> Result<(), MapError> {
    let rsp: u64;
    // SAFETY: reading RSP has no side effects.
    unsafe { asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    let rip = load_kernel_space as fn(&AddressSpace, &[(u64, u64)]) -> Result<(), MapError> as usize
        as u64;
    let running = [
        (rip, rip.wrapping_sub(KERNEL_BASE)),
        (rsp, rsp.wrapping_sub(KERNEL_BASE)),
    ];
    for &(virt, phys) in running.iter().chain(must_map) {
        match space.translate(virt) {
            Some((mapped, _)) if mapped == phys => {}
            _ => return Err(MapError::Missing(virt)),
        }
    }
    // SAFETY: the checks above show the new tables map the code, the stack
    // and everything in `must_map` to the same physical memory as now, so
    // execution carries on unchanged. Nothing touches physical memory
    // between the CR3 load and the offset switch, so `phys_to_virt` stays
    // correct; the asm is a compiler barrier.
    unsafe {
        asm!("mov cr3, {}", in(reg) space.root, options(nostack, preserves_flags));
    }
    ACCESS_OFFSET.store(PHYS_WINDOW, Ordering::Relaxed);
    let cr4: u64;
    // SAFETY: turning on global pages only changes TLB behavior: the
    // Keep's own mappings, which are marked GLOBAL, survive CR3 switches.
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("mov cr4, {}", in(reg) cr4 | CR4_GLOBAL_PAGES, options(nostack, preserves_flags));
    }
    Ok(())
}
