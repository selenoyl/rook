//! Parses the boot loader's memory map and command line.
//!
//! This is input from outside the Keep, so it follows the Gatehouse
//! rules: every field is read with bounds checks into a typed structure
//! before anything uses it, malformed data is dropped rather than
//! trusted, and nothing here can panic.

#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used
)]

pub const MAX_REGIONS: usize = 32;
const MAX_CMDLINE: usize = 128;
/// Multiboot memory map entry: size (u32), base (u64), length (u64),
/// type (u32). `size` counts the bytes after itself.
const ENTRY_MIN: u32 = 20;
const TYPE_AVAILABLE: u32 = 1;

#[derive(Clone, Copy)]
pub struct Region {
    pub start: u64,
    pub len: u64,
    pub usable: bool,
}

pub struct BootInfo {
    regions: [Region; MAX_REGIONS],
    count: usize,
    dropped: usize,
    cmdline: [u8; MAX_CMDLINE],
    cmdline_len: usize,
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    bytes.get(at..end)?.try_into().ok().map(u32::from_le_bytes)
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    bytes.get(at..end)?.try_into().ok().map(u64::from_le_bytes)
}

impl BootInfo {
    pub fn parse(mmap: &[u8], cmdline: &[u8]) -> BootInfo {
        let mut info = BootInfo {
            regions: [Region {
                start: 0,
                len: 0,
                usable: false,
            }; MAX_REGIONS],
            count: 0,
            dropped: 0,
            cmdline: [0; MAX_CMDLINE],
            cmdline_len: 0,
        };
        info.parse_mmap(mmap);
        for (slot, &byte) in info.cmdline.iter_mut().zip(cmdline) {
            // Keep printable ASCII only; anything else becomes '?'.
            *slot = if (0x20..0x7F).contains(&byte) {
                byte
            } else {
                b'?'
            };
        }
        info.cmdline_len = cmdline.len().min(MAX_CMDLINE);
        info
    }

    fn parse_mmap(&mut self, mmap: &[u8]) {
        let mut at = 0usize;
        while let Some(size) = read_u32(mmap, at) {
            let entry = at.checked_add(4);
            let (Some(entry), true) = (entry, size >= ENTRY_MIN) else {
                return; // malformed: stop reading
            };
            let (Some(start), Some(len), Some(kind)) = (
                read_u64(mmap, entry),
                entry.checked_add(8).and_then(|a| read_u64(mmap, a)),
                entry.checked_add(16).and_then(|a| read_u32(mmap, a)),
            ) else {
                return; // truncated entry
            };
            if start.checked_add(len).is_some() && len > 0 {
                match self.regions.get_mut(self.count) {
                    Some(slot) => {
                        *slot = Region {
                            start,
                            len,
                            usable: kind == TYPE_AVAILABLE,
                        };
                        self.count = self.count.saturating_add(1);
                    }
                    None => self.dropped = self.dropped.saturating_add(1),
                }
            }
            let Some(next) = entry.checked_add(size as usize) else {
                return;
            };
            at = next;
        }
    }

    pub fn regions(&self) -> &[Region] {
        self.regions.get(..self.count).unwrap_or(&[])
    }

    /// Regions past MAX_REGIONS that were left out.
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    pub fn usable_bytes(&self) -> u64 {
        self.regions()
            .iter()
            .filter(|r| r.usable)
            .fold(0u64, |sum, r| sum.saturating_add(r.len))
    }

    pub fn cmdline(&self) -> &str {
        let bytes = self.cmdline.get(..self.cmdline_len).unwrap_or(&[]);
        core::str::from_utf8(bytes).unwrap_or("")
    }

    /// Whether the command line contains `word` as a whole word.
    pub fn has_word(&self, word: &str) -> bool {
        self.cmdline().split(' ').any(|w| w == word)
    }

    /// The value of `key=value` on the command line, if present.
    pub fn value(&self, key: &str) -> Option<&str> {
        self.cmdline().split(' ').find_map(|w| {
            let (k, v) = w.split_once('=')?;
            (k == key).then_some(v)
        })
    }

    /// The end of the highest usable region.
    pub fn top_of_ram(&self) -> u64 {
        self.regions()
            .iter()
            .filter(|r| r.usable)
            .map(|r| r.start.saturating_add(r.len))
            .max()
            .unwrap_or(0)
    }
}
