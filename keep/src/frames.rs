//! Physical memory at boot.
//!
//! Hands out 4 KiB frames from the usable RAM in the boot memory map,
//! skipping reserved ranges (low memory and the Keep's own image). It
//! never frees: the Keep sets its memory aside during boot and then seals
//! the allocator, so it allocates nothing after boot. What is left will be
//! handed to user space as a whole.

#![forbid(unsafe_code)]

use crate::arch::paging::FrameSource;
use crate::bootinfo::{BootInfo, MAX_REGIONS};

pub const FRAME: u64 = 4096;
const MAX_RESERVED: usize = 4;

/// A range of physical addresses, `start..end`.
#[derive(Clone, Copy)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}

impl Range {
    const EMPTY: Range = Range { start: 0, end: 0 };

    fn contains(&self, addr: u64) -> bool {
        self.start <= addr && addr < self.end
    }
}

pub struct Frames {
    usable: [Range; MAX_REGIONS],
    usable_count: usize,
    reserved: [Range; MAX_RESERVED],
    reserved_count: usize,
    /// Boot allocations stay below this address.
    limit: u64,
    region: usize,
    next: u64,
    handed_out: u64,
    sealed: bool,
}

impl Frames {
    /// `limit` bounds where boot allocations may come from, so the frames
    /// are reachable through the boot identity map.
    pub fn new(boot: &BootInfo, reserved: &[Range], limit: u64) -> Frames {
        let mut frames = Frames {
            usable: [Range::EMPTY; MAX_REGIONS],
            usable_count: 0,
            reserved: [Range::EMPTY; MAX_RESERVED],
            reserved_count: 0,
            limit,
            region: 0,
            next: 0,
            handed_out: 0,
            sealed: false,
        };
        for r in boot.regions().iter().filter(|r| r.usable) {
            // Whole frames only.
            let start = r.start.next_multiple_of(FRAME);
            let end = r.start.saturating_add(r.len) / FRAME * FRAME;
            if start < end
                && let Some(slot) = frames.usable.get_mut(frames.usable_count)
            {
                *slot = Range { start, end };
                frames.usable_count += 1;
            }
        }
        frames.usable[..frames.usable_count].sort_unstable_by_key(|r| r.start);
        for (slot, r) in frames.reserved.iter_mut().zip(reserved) {
            *slot = *r;
            frames.reserved_count += 1;
        }
        frames
    }

    fn reserved(&self, frame: u64) -> bool {
        self.reserved[..self.reserved_count]
            .iter()
            .any(|r| r.contains(frame) || r.contains(frame + FRAME - 1))
    }

    /// The next free frame, or None once memory runs out or the
    /// allocator is sealed.
    pub fn alloc(&mut self) -> Option<u64> {
        if self.sealed {
            return None;
        }
        while let Some(r) = self.usable[..self.usable_count].get(self.region).copied() {
            self.next = self.next.max(r.start);
            let end = r.end.min(self.limit);
            if self.next + FRAME > end {
                self.region += 1;
                continue;
            }
            let frame = self.next;
            self.next += FRAME;
            if !self.reserved(frame) {
                self.handed_out += 1;
                return Some(frame);
            }
        }
        None
    }

    /// Stop handing out frames, for good.
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    pub fn used_bytes(&self) -> u64 {
        self.handed_out * FRAME
    }

    /// Usable memory not handed out and not reserved.
    pub fn free_bytes(&self) -> u64 {
        let mut free = 0;
        for (i, r) in self.usable[..self.usable_count].iter().enumerate() {
            let mut frame = if i == self.region {
                self.next.max(r.start)
            } else {
                r.start
            };
            if i < self.region {
                continue;
            }
            while frame + FRAME <= r.end {
                if !self.reserved(frame) {
                    free += FRAME;
                }
                frame += FRAME;
            }
        }
        free
    }
}

impl FrameSource for Frames {
    fn frame(&mut self) -> Option<u64> {
        self.alloc()
    }
}
