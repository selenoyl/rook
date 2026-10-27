//! A small ATA (IDE) disk driver, in ring 3.
//!
//! This is a user-space driver: it reaches the controller only through the
//! capability-gated I/O system calls, holding an I/O Writ for the primary
//! bus's ports and nothing else. It is PIO (the CPU moves every word, no
//! DMA), polled (no interrupts), LBA28, master drive — the simplest thing
//! that reads and writes the Vault's blocks. It implements
//! [`vault::BlockDevice`], so the filesystem rides on top unchanged.

use vault::{BLOCK, BlockDevice};

// Primary ATA bus: the I/O ports, which the driver's Writ must cover.
const DATA: u16 = 0x1F0;
const SECTOR_COUNT: u16 = 0x1F2;
const LBA_LOW: u16 = 0x1F3;
const LBA_MID: u16 = 0x1F4;
const LBA_HIGH: u16 = 0x1F5;
const DRIVE: u16 = 0x1F6;
const STATUS: u16 = 0x1F7; // reading: status; writing: command
const COMMAND: u16 = 0x1F7;

const CMD_READ: u8 = 0x20;
const CMD_WRITE: u8 = 0x30;
const CMD_FLUSH: u8 = 0xE7;
const CMD_IDENTIFY: u8 = 0xEC;

const ST_BSY: u8 = 0x80;
const ST_DRQ: u8 = 0x08;
const ST_ERR: u8 = 0x01;

/// LBA28 addresses a drive up to this many sectors.
const MAX_LBA28: u64 = 0x0FFF_FFFF;

/// Status reads to poll before giving up, so a missing or stuck drive
/// fails instead of hanging. A real transfer finishes in far fewer.
const POLL_LIMIT: u32 = 50_000_000;

/// The ATA driver for the primary master, holding its I/O Writ handle.
pub struct Ata {
    io: u64,
    sectors: u64,
}

impl Ata {
    /// Probe the primary master with IDENTIFY and return a driver for it,
    /// or `None` if no drive answers. `io` is the handle of the task's I/O
    /// Writ covering the primary bus's ports.
    pub fn open(io: u64) -> Option<Ata> {
        let drive = Ata { io, sectors: 0 };
        // A floating bus with no drive reads status 0xFF.
        if drive.status()? == 0xFF {
            return None;
        }
        drive.out(DRIVE, 0xA0)?; // select master
        drive.out(SECTOR_COUNT, 0)?;
        drive.out(LBA_LOW, 0)?;
        drive.out(LBA_MID, 0)?;
        drive.out(LBA_HIGH, 0)?;
        drive.out(COMMAND, CMD_IDENTIFY)?;
        if drive.status()? == 0 {
            return None; // no drive
        }
        drive.wait_data().ok()?;
        let mut identify = [0u8; BLOCK];
        crate::io_read(io, DATA, &mut identify).ok()?;
        // LBA28 total sectors: the u32 at word 60 (bytes 120..124).
        let sectors =
            u32::from_le_bytes([identify[120], identify[121], identify[122], identify[123]]) as u64;
        Some(Ata { io, sectors })
    }

    fn status(&self) -> Option<u8> {
        crate::io_in(self.io, STATUS).ok()
    }

    fn out(&self, port: u16, value: u8) -> Option<()> {
        crate::io_out(self.io, port, value).ok()
    }

    /// Poll until the drive is not busy, returning the status byte.
    fn wait_not_busy(&self) -> Result<u8, vault::Error> {
        for _ in 0..POLL_LIMIT {
            let s = self.status().ok_or(vault::Error::Device)?;
            if s & ST_BSY == 0 {
                return Ok(s);
            }
        }
        Err(vault::Error::Device)
    }

    /// Poll until the drive has data ready (not busy, DRQ set), or a error.
    fn wait_data(&self) -> Result<(), vault::Error> {
        for _ in 0..POLL_LIMIT {
            let s = self.status().ok_or(vault::Error::Device)?;
            if s & ST_BSY != 0 {
                continue;
            }
            if s & ST_ERR != 0 {
                return Err(vault::Error::Device);
            }
            if s & ST_DRQ != 0 {
                return Ok(());
            }
        }
        Err(vault::Error::Device)
    }

    /// Select the drive and point it at one sector at `lba`.
    fn seek(&self, lba: u64) -> Result<(), vault::Error> {
        if lba > MAX_LBA28 {
            return Err(vault::Error::Device);
        }
        self.wait_not_busy()?;
        let dev = || vault::Error::Device;
        self.out(DRIVE, 0xE0 | ((lba >> 24) as u8 & 0x0F))
            .ok_or_else(dev)?;
        self.out(SECTOR_COUNT, 1).ok_or_else(dev)?;
        self.out(LBA_LOW, lba as u8).ok_or_else(dev)?;
        self.out(LBA_MID, (lba >> 8) as u8).ok_or_else(dev)?;
        self.out(LBA_HIGH, (lba >> 16) as u8).ok_or_else(dev)?;
        Ok(())
    }
}

impl BlockDevice for Ata {
    fn read_block(&mut self, lba: u64, buf: &mut [u8; BLOCK]) -> Result<(), vault::Error> {
        self.seek(lba)?;
        self.out(COMMAND, CMD_READ).ok_or(vault::Error::Device)?;
        self.wait_data()?;
        crate::io_read(self.io, DATA, buf).map_err(|_| vault::Error::Device)
    }

    fn write_block(&mut self, lba: u64, buf: &[u8; BLOCK]) -> Result<(), vault::Error> {
        self.seek(lba)?;
        self.out(COMMAND, CMD_WRITE).ok_or(vault::Error::Device)?;
        self.wait_data()?;
        crate::io_write(self.io, DATA, buf).map_err(|_| vault::Error::Device)?;
        // Flush the drive's write cache so the bytes reach the medium.
        self.out(COMMAND, CMD_FLUSH).ok_or(vault::Error::Device)?;
        self.wait_not_busy()?;
        Ok(())
    }

    fn blocks(&self) -> u64 {
        self.sectors
    }
}
