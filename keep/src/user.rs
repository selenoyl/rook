//! Loading a user program into an address space of its own.
//!
//! This is a Gatehouse: it reads an ELF file the Keep ships and refuses
//! anything malformed rather than trusting it. Even though these programs
//! are built alongside the Keep, the loader treats their headers as
//! untrusted input, so the same code can one day load a program that
//! arrived from outside. It parses no more of ELF than Rook uses: 64-bit
//! executables with loadable segments.
//!
//! Each program gets a fresh address space that shares the Keep's higher
//! half (so the Keep stays mapped while the program runs) and has the
//! program's own segments and a stack in the lower half. No segment may
//! be both writable and executable.

#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used
)]

use crate::arch::layout::{USER_MAX, USER_MIN, USER_STACK_TOP, user_stack_base};
use crate::arch::paging::{
    AddressSpace, FrameSource, MapError, NO_EXECUTE, PAGE_SIZE, USER, WRITABLE,
};

/// The most loadable segments the loader will read from one program.
const MAX_SEGMENTS: u16 = 16;
/// The most memory one segment may span, a guard against a wild `p_memsz`.
const MAX_SEGMENT: u64 = 16 * 1024 * 1024;

const ELF_HEADER: usize = 64;
const PH_ENTRY: usize = 56;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

/// A loaded program, ready to run.
pub struct Program {
    pub space: AddressSpace,
    pub entry: u64,
    pub stack_top: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum LoadError {
    NotElf,
    Unsupported,
    Truncated,
    TooManySegments,
    /// A segment the Keep won't map, and why.
    BadSegment(u64, &'static str),
    Map(MapError),
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            LoadError::NotElf => write!(f, "not an ELF file"),
            LoadError::Unsupported => write!(f, "not a 64-bit x86-64 executable"),
            LoadError::Truncated => write!(f, "the file ends inside a header or segment"),
            LoadError::TooManySegments => write!(f, "too many loadable segments"),
            LoadError::BadSegment(vaddr, why) => write!(f, "segment at {vaddr:#x}: {why}"),
            LoadError::Map(e) => write!(f, "{e}"),
        }
    }
}

impl From<MapError> for LoadError {
    fn from(e: MapError) -> LoadError {
        LoadError::Map(e)
    }
}

fn u16_at(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(off..end)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(off..end)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    Some(u64::from_le_bytes(bytes.get(off..end)?.try_into().ok()?))
}

/// Load `elf` into a new address space built on the Keep's higher half,
/// and give it a stack. `kernel` is the Keep's own space, whose higher
/// half the new space shares.
pub fn load(
    elf: &[u8],
    kernel: &AddressSpace,
    frames: &mut impl FrameSource,
) -> Result<Program, LoadError> {
    let header = elf.get(..ELF_HEADER).ok_or(LoadError::Truncated)?;
    if header.get(..4) != Some(b"\x7fELF") {
        return Err(LoadError::NotElf);
    }
    // 64-bit (class 2), little-endian (data 1), x86-64 (machine 0x3E),
    // executable (type 2).
    let ok = header.get(4) == Some(&2)
        && header.get(5) == Some(&1)
        && u16_at(header, 16) == Some(2)
        && u16_at(header, 18) == Some(0x3E);
    if !ok {
        return Err(LoadError::Unsupported);
    }

    let entry = u64_at(header, 24).ok_or(LoadError::Truncated)?;
    let phoff = u64_at(header, 32).ok_or(LoadError::Truncated)?;
    let phentsize = u16_at(header, 54).ok_or(LoadError::Truncated)?;
    let phnum = u16_at(header, 56).ok_or(LoadError::Truncated)?;
    if usize::from(phentsize) != PH_ENTRY {
        return Err(LoadError::Unsupported);
    }
    if phnum > MAX_SEGMENTS {
        return Err(LoadError::TooManySegments);
    }

    let mut space = AddressSpace::new_user(kernel, frames)?;
    for i in 0..phnum {
        let base = usize::try_from(phoff)
            .ok()
            .and_then(|o| {
                usize::from(i)
                    .checked_mul(PH_ENTRY)
                    .and_then(|x| o.checked_add(x))
            })
            .ok_or(LoadError::Truncated)?;
        let ph = elf
            .get(base..base.checked_add(PH_ENTRY).ok_or(LoadError::Truncated)?)
            .ok_or(LoadError::Truncated)?;
        if u32_at(ph, 0) != Some(PT_LOAD) {
            continue;
        }
        load_segment(&mut space, elf, ph, frames)?;
    }

    map_stack(&mut space, frames)?;
    if !(USER_MIN..USER_MAX).contains(&entry) {
        return Err(LoadError::BadSegment(
            entry,
            "entry point outside user space",
        ));
    }
    Ok(Program {
        space,
        entry,
        stack_top: USER_STACK_TOP,
    })
}

fn load_segment(
    space: &mut AddressSpace,
    elf: &[u8],
    ph: &[u8],
    frames: &mut impl FrameSource,
) -> Result<(), LoadError> {
    let flags = u32_at(ph, 4).ok_or(LoadError::Truncated)?;
    let offset = u64_at(ph, 8).ok_or(LoadError::Truncated)?;
    let vaddr = u64_at(ph, 16).ok_or(LoadError::Truncated)?;
    let filesz = u64_at(ph, 32).ok_or(LoadError::Truncated)?;
    let memsz = u64_at(ph, 40).ok_or(LoadError::Truncated)?;
    let bad = |why| LoadError::BadSegment(vaddr, why);

    if flags & PF_W != 0 && flags & PF_X != 0 {
        return Err(bad("writable and executable"));
    }
    if !vaddr.is_multiple_of(PAGE_SIZE) {
        return Err(bad("not page-aligned"));
    }
    if filesz > memsz {
        return Err(bad("file size exceeds memory size"));
    }
    if memsz == 0 || memsz > MAX_SEGMENT {
        return Err(bad("empty or too large"));
    }
    let end = vaddr.checked_add(memsz).ok_or(bad("wraps around"))?;
    if vaddr < USER_MIN || end > USER_MAX {
        return Err(bad("outside user space"));
    }
    let file_end = usize::try_from(offset)
        .ok()
        .and_then(|o| usize::try_from(filesz).ok().and_then(|n| o.checked_add(n)))
        .ok_or(LoadError::Truncated)?;
    let contents = elf
        .get(usize::try_from(offset).map_err(|_| LoadError::Truncated)?..file_end)
        .ok_or(LoadError::Truncated)?;

    let mut page_flags = USER;
    if flags & PF_W != 0 {
        page_flags |= WRITABLE;
    }
    if flags & PF_X == 0 {
        page_flags |= NO_EXECUTE;
    }

    // Map each page of the segment, copying the file bytes that fall in
    // it and leaving the rest (including all of .bss) zero.
    let mut done: u64 = 0;
    while done < memsz {
        let virt = vaddr.checked_add(done).ok_or(bad("wraps around"))?;
        let start = usize::try_from(done).map_err(|_| LoadError::Truncated)?;
        let take = contents.len().saturating_sub(start).min(PAGE_SIZE as usize);
        let data = contents.get(start..start.checked_add(take).unwrap_or(start));
        space.map_filled(virt, page_flags, data.unwrap_or(&[]), frames)?;
        done = done.checked_add(PAGE_SIZE).ok_or(bad("wraps around"))?;
    }
    Ok(())
}

/// Map the task's stack: `USER_STACK_SIZE` of writable, no-execute pages
/// ending at `USER_STACK_TOP`, with the page below left unmapped as a
/// guard so an overflow faults.
fn map_stack(space: &mut AddressSpace, frames: &mut impl FrameSource) -> Result<(), LoadError> {
    let mut virt = user_stack_base();
    while virt < USER_STACK_TOP {
        space.map_zeroed(virt, USER | WRITABLE | NO_EXECUTE, frames)?;
        virt = virt.checked_add(PAGE_SIZE).ok_or(LoadError::Truncated)?;
    }
    Ok(())
}
