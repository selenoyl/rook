//! Raw access to the information the Multiboot loader leaves in memory.
//!
//! This module only finds and bounds the loader's bytes. Parsing them is
//! the job of `bootinfo`, which treats them as untrusted input.

const BOOT_MAGIC: u32 = 0x2BAD_B002;
const INFO_LEN: usize = 52;
const FLAG_CMDLINE: u32 = 1 << 2;
const FLAG_MMAP: u32 = 1 << 6;
/// The boot page tables identity-map memory below this address.
const MAPPED_LIMIT: u64 = 1 << 30;
const MAX_MMAP_BYTES: u32 = 4096;
const MAX_CMDLINE: usize = 255;

/// The loader's memory map and command line, as raw bytes.
pub struct RawBootInfo {
    pub magic_ok: bool,
    pub mmap: &'static [u8],
    pub cmdline: &'static [u8],
}

fn mapped(addr: u32, len: u32) -> bool {
    addr != 0 && u64::from(addr) + u64::from(len) <= MAPPED_LIMIT
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    bytes
        .get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

pub fn read(magic: u32, info: u32) -> RawBootInfo {
    let mut out = RawBootInfo {
        magic_ok: false,
        mmap: &[],
        cmdline: &[],
    };
    if magic != BOOT_MAGIC || !mapped(info, INFO_LEN as u32) {
        return out;
    }
    out.magic_ok = true;

    // SAFETY: the magic in EAX means EBX holds the address of the
    // loader's information block, which is at least INFO_LEN bytes;
    // `mapped` checked that it lies in identity-mapped memory. The loader's
    // memory is never reused, so a 'static read-only view is sound.
    let header: &'static [u8] =
        unsafe { core::slice::from_raw_parts(info as usize as *const u8, INFO_LEN) };
    let flags = word(header, 0);

    if flags & FLAG_MMAP != 0 {
        let len = word(header, 44).min(MAX_MMAP_BYTES);
        let addr = word(header, 48);
        if mapped(addr, len) {
            // SAFETY: the loader describes a memory map of `len` bytes at
            // `addr`; `len` is capped and the range is checked as mapped.
            out.mmap =
                unsafe { core::slice::from_raw_parts(addr as usize as *const u8, len as usize) };
        }
    }

    if flags & FLAG_CMDLINE != 0 {
        let addr = word(header, 16);
        if mapped(addr, MAX_CMDLINE as u32 + 1) {
            // SAFETY: the command line is a NUL-terminated string in the
            // loader's memory. We look at no more than MAX_CMDLINE + 1
            // bytes, all of which are in mapped RAM, and stop at the NUL.
            let bytes: &'static [u8] =
                unsafe { core::slice::from_raw_parts(addr as usize as *const u8, MAX_CMDLINE + 1) };
            let len = bytes.iter().position(|&b| b == 0).unwrap_or(0);
            out.cmdline = bytes.get(..len).unwrap_or(&[]);
        }
    }
    out
}
