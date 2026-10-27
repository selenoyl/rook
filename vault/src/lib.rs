//! The Vault: Rook's simple on-disk filesystem.
//!
//! The Vault is deliberately small and easy to see is correct, the same
//! spirit as the rest of the Keep. It sits on any [`BlockDevice`] — the
//! ATA driver on real hardware, an in-memory array in tests — and stores a
//! handful of whole files in contiguous extents.
//!
//! Layout. Block 0 is the superblock: a 32-byte header followed by a fixed
//! directory of entries. Each file's bytes live in a run of consecutive
//! blocks; allocation is a bump pointer (`next_free`), so there is no free
//! list and no fragmentation to reason about. This cannot reclaim a
//! deleted file's blocks — fine for an image that is written once and
//! mostly read — and it is not a general-purpose filesystem. It is enough
//! for Rook to keep programs and data on disk instead of baked into the
//! boot image, served by a user-space task behind a Writ.
//!
//! Everything here treats the disk as untrusted: every offset read from it
//! is checked against the device size before it is used, so a corrupt or
//! hostile image cannot make the reader run off the end.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// Bytes in a block. The whole filesystem works a block at a time.
pub const BLOCK: usize = 512;

/// Longest file name, in bytes.
pub const NAME_LEN: usize = 16;

/// Bytes of superblock header before the directory.
const HEADER: usize = 32;
/// Bytes per directory entry: name, start block, length, flags, reserved.
const ENTRY: usize = 32;
/// Directory entries that fit in the superblock block.
pub const MAX_FILES: usize = (BLOCK - HEADER) / ENTRY;

/// The magic at the start of a Vault superblock.
const MAGIC: [u8; 8] = *b"ROOKVLT1";

// Header field offsets within block 0.
const OFF_MAGIC: usize = 0;
const OFF_BLOCKS: usize = 8;
const OFF_NEXT_FREE: usize = 12;
const OFF_FILE_COUNT: usize = 16;

// Entry field offsets within a directory entry.
const E_NAME: usize = 0;
const E_START: usize = 16;
const E_LEN: usize = 20;
const E_FLAGS: usize = 24;
const FLAG_USED: u32 = 1;

/// What went wrong with a filesystem operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The block device returned an error.
    Device,
    /// The superblock's magic is wrong: not a Vault, or corrupt.
    BadMagic,
    /// The superblock describes something impossible (a file past the end
    /// of the device, say). The image is corrupt.
    Corrupt,
    /// A name is empty or longer than `NAME_LEN`.
    BadName,
    /// A file by that name already exists.
    Exists,
    /// No file by that name.
    NotFound,
    /// The directory is full (`MAX_FILES` already).
    DirectoryFull,
    /// Not enough free blocks for the file.
    NoSpace,
}

/// A device of fixed-size [`BLOCK`]-byte blocks.
pub trait BlockDevice {
    /// Read block `lba` into `buf`.
    fn read_block(&mut self, lba: u64, buf: &mut [u8; BLOCK]) -> Result<(), Error>;
    /// Write `buf` to block `lba`.
    fn write_block(&mut self, lba: u64, buf: &[u8; BLOCK]) -> Result<(), Error>;
    /// How many blocks the device holds.
    fn blocks(&self) -> u64;
}

fn rd_u32(b: &[u8; BLOCK], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn wr_u32(b: &mut [u8; BLOCK], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// One directory entry: a file's name and where its bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The name, without its NUL padding.
    pub name: [u8; NAME_LEN],
    pub name_len: usize,
    pub start: u32,
    pub len: u32,
}

impl Entry {
    /// The name as a byte slice (no trailing NULs).
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Blocks this file's bytes occupy.
    fn block_span(&self) -> u64 {
        len_blocks(self.len)
    }
}

/// Blocks needed to hold `len` bytes.
fn len_blocks(len: u32) -> u64 {
    (len as u64).div_ceil(BLOCK as u64)
}

/// A mounted Vault: a block device plus a cached copy of the superblock.
pub struct Vault<D: BlockDevice> {
    dev: D,
    sb: [u8; BLOCK],
}

impl<D: BlockDevice> Vault<D> {
    /// Write a fresh, empty filesystem onto `dev` and return it mounted.
    /// The device must have at least one block.
    pub fn format(mut dev: D) -> Result<Vault<D>, Error> {
        let blocks = dev.blocks();
        if blocks == 0 || blocks > u32::MAX as u64 {
            return Err(Error::Corrupt);
        }
        let mut sb = [0u8; BLOCK];
        sb[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(&MAGIC);
        wr_u32(&mut sb, OFF_BLOCKS, blocks as u32);
        wr_u32(&mut sb, OFF_NEXT_FREE, 1); // block 0 is the superblock
        wr_u32(&mut sb, OFF_FILE_COUNT, 0);
        dev.write_block(0, &sb)?;
        Ok(Vault { dev, sb })
    }

    /// Mount an existing Vault, checking the superblock is sound.
    pub fn open(mut dev: D) -> Result<Vault<D>, Error> {
        let mut sb = [0u8; BLOCK];
        dev.read_block(0, &mut sb)?;
        if sb[OFF_MAGIC..OFF_MAGIC + 8] != MAGIC {
            return Err(Error::BadMagic);
        }
        let blocks = rd_u32(&sb, OFF_BLOCKS) as u64;
        let next_free = rd_u32(&sb, OFF_NEXT_FREE) as u64;
        // The superblock must agree with the device and be internally
        // consistent, or we refuse to trust it.
        if blocks > dev.blocks() || next_free < 1 || next_free > blocks {
            return Err(Error::Corrupt);
        }
        let vault = Vault { dev, sb };
        // Every live entry must name blocks that lie within the device.
        for i in 0..MAX_FILES {
            if let Some(entry) = vault.entry(i) {
                let end = (entry.start as u64)
                    .checked_add(entry.block_span())
                    .ok_or(Error::Corrupt)?;
                if entry.start < 1 || end > blocks {
                    return Err(Error::Corrupt);
                }
            }
        }
        Ok(vault)
    }

    /// Total blocks on the device.
    pub fn blocks(&self) -> u64 {
        rd_u32(&self.sb, OFF_BLOCKS) as u64
    }

    /// Blocks not yet allocated to any file.
    pub fn free_blocks(&self) -> u64 {
        self.blocks().saturating_sub(self.next_free())
    }

    fn next_free(&self) -> u64 {
        rd_u32(&self.sb, OFF_NEXT_FREE) as u64
    }

    /// The number of live files.
    pub fn file_count(&self) -> u32 {
        rd_u32(&self.sb, OFF_FILE_COUNT)
    }

    /// The directory entry in slot `i`, if that slot holds a live file.
    pub fn entry(&self, i: usize) -> Option<Entry> {
        if i >= MAX_FILES {
            return None;
        }
        let base = HEADER + i * ENTRY;
        if rd_u32(&self.sb, base + E_FLAGS) & FLAG_USED == 0 {
            return None;
        }
        let mut name = [0u8; NAME_LEN];
        name.copy_from_slice(&self.sb[base + E_NAME..base + E_NAME + NAME_LEN]);
        let name_len = name.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
        Some(Entry {
            name,
            name_len,
            start: rd_u32(&self.sb, base + E_START),
            len: rd_u32(&self.sb, base + E_LEN),
        })
    }

    /// Call `f` for each live file, in directory order.
    pub fn for_each<F: FnMut(&Entry)>(&self, mut f: F) {
        for i in 0..MAX_FILES {
            if let Some(entry) = self.entry(i) {
                f(&entry);
            }
        }
    }

    /// Find the entry for `name`.
    pub fn lookup(&self, name: &[u8]) -> Option<Entry> {
        for i in 0..MAX_FILES {
            if let Some(entry) = self.entry(i)
                && entry.name() == name
            {
                return Some(entry);
            }
        }
        None
    }

    /// Read the file `name` into `out`, returning how many bytes it holds.
    /// If `out` is shorter than the file, only the first `out.len()` bytes
    /// are filled, but the file's true length is still returned.
    pub fn read(&mut self, name: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let entry = self.lookup(name).ok_or(Error::NotFound)?;
        let len = entry.len as usize;
        let mut block = [0u8; BLOCK];
        let mut done = 0;
        let want = core::cmp::min(len, out.len());
        let mut lba = entry.start as u64;
        while done < want {
            self.dev.read_block(lba, &mut block)?;
            let take = core::cmp::min(BLOCK, want - done);
            out[done..done + take].copy_from_slice(&block[..take]);
            done += take;
            lba += 1;
        }
        Ok(len)
    }

    /// Create a file `name` holding `data`. Fails if the name is taken, the
    /// directory is full, or there isn't room.
    pub fn create(&mut self, name: &[u8], data: &[u8]) -> Result<(), Error> {
        if name.is_empty() || name.len() > NAME_LEN {
            return Err(Error::BadName);
        }
        if self.lookup(name).is_some() {
            return Err(Error::Exists);
        }
        let slot = self.free_slot().ok_or(Error::DirectoryFull)?;
        let span = len_blocks(data.len() as u32);
        let start = self.next_free();
        if data.len() > u32::MAX as usize {
            return Err(Error::NoSpace);
        }
        if start + span > self.blocks() {
            return Err(Error::NoSpace);
        }

        // Write the data blocks, zero-padding the last one.
        for b in 0..span {
            let mut block = [0u8; BLOCK];
            let from = (b as usize) * BLOCK;
            let take = core::cmp::min(BLOCK, data.len() - from);
            block[..take].copy_from_slice(&data[from..from + take]);
            self.dev.write_block(start + b, &block)?;
        }

        // Add the directory entry and update the header, then flush the
        // superblock last, so a half-written file is never linked in.
        let base = HEADER + slot * ENTRY;
        let mut padded = [0u8; NAME_LEN];
        padded[..name.len()].copy_from_slice(name);
        self.sb[base + E_NAME..base + E_NAME + NAME_LEN].copy_from_slice(&padded);
        wr_u32(&mut self.sb, base + E_START, start as u32);
        wr_u32(&mut self.sb, base + E_LEN, data.len() as u32);
        wr_u32(&mut self.sb, base + E_FLAGS, FLAG_USED);
        wr_u32(&mut self.sb, OFF_NEXT_FREE, (start + span) as u32);
        let count = self.file_count() + 1;
        wr_u32(&mut self.sb, OFF_FILE_COUNT, count);
        let sb = self.sb;
        self.dev.write_block(0, &sb)?;
        Ok(())
    }

    /// The first free directory slot, if any.
    fn free_slot(&self) -> Option<usize> {
        (0..MAX_FILES).find(|&i| self.entry(i).is_none())
    }

    /// Give the block device back.
    pub fn into_device(self) -> D {
        self.dev
    }
}

#[cfg(test)]
mod tests;
