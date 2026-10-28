//! A small NE2000 (DP8390) network-card driver, in ring 3.
//!
//! Like the ATA driver, this is a user-space driver that reaches the card
//! only through the capability-gated I/O system calls, holding an I/O Writ
//! for the card's 32 ports and nothing else. It is PIO (the CPU moves every
//! word through the card's data port — the NE2000's "remote DMA" is really
//! programmed I/O), polled (no interrupts), and word-wide. QEMU's `ne2k_isa`
//! sits at port 0x300, so the Writ covers 0x300..0x320.
//!
//! The card has 16 KB of its own buffer RAM in 256-byte pages. The transmit
//! buffer is one frame at page 0x40; received frames fill a ring from page
//! 0x46 to 0x80, each behind a 4-byte status header the card writes.

// Base and the register offsets within the card's I/O window.
const BASE: u16 = 0x300;
const CR: u16 = BASE; // command
const ISR: u16 = BASE + 0x07; // interrupt status
const DATA: u16 = BASE + 0x10; // remote-DMA data port
const RESET: u16 = BASE + 0x1F;

// Page-0 registers (written with the command register on page 0).
const PSTART: u16 = BASE + 0x01;
const PSTOP: u16 = BASE + 0x02;
const BNRY: u16 = BASE + 0x03;
const TPSR: u16 = BASE + 0x04;
const TBCR0: u16 = BASE + 0x05;
const TBCR1: u16 = BASE + 0x06;
const RSAR0: u16 = BASE + 0x08;
const RSAR1: u16 = BASE + 0x09;
const RBCR0: u16 = BASE + 0x0A;
const RBCR1: u16 = BASE + 0x0B;
const RCR: u16 = BASE + 0x0C;
const TCR: u16 = BASE + 0x0D;
const DCR: u16 = BASE + 0x0E;
const IMR: u16 = BASE + 0x0F;

// Page-1 registers.
const PAR0: u16 = BASE + 0x01; // our MAC filter
const CURR: u16 = BASE + 0x07; // ring write pointer
const MAR0: u16 = BASE + 0x08; // multicast filter

// Command-register bits.
const CR_STP: u8 = 0x01;
const CR_STA: u8 = 0x02;
const CR_TXP: u8 = 0x04;
const CR_RD_READ: u8 = 0x08; // remote read
const CR_RD_WRITE: u8 = 0x10; // remote write
const CR_RD_ABORT: u8 = 0x20;
const CR_PAGE1: u8 = 0x40;

// Interrupt-status bits.
const ISR_PRX: u8 = 0x01; // packet received
const ISR_PTX: u8 = 0x02; // packet transmitted
const ISR_RDC: u8 = 0x40; // remote DMA complete
const ISR_RST: u8 = 0x80; // reset / overflow

// Ring layout, in 256-byte pages.
const TX_PAGE: u8 = 0x40;
const RX_START: u8 = 0x46;
const RX_STOP: u8 = 0x80;

/// A short Ethernet frame is padded to this many bytes on the wire.
const MIN_FRAME: usize = 60;

/// Polls before giving up, so a missing or stuck card fails instead of
/// hanging the task.
const POLL_LIMIT: u32 = 2_000_000;

/// The most bytes a single `io_read`/`io_write` moves: the Keep caps a
/// transfer at `MAX_IO_WORDS` 16-bit words. A frame larger than this is
/// streamed through the data port in several calls against one remote-DMA
/// setup, since the card advances its own address as the port is read.
const IO_CHUNK: usize = abi::MAX_IO_WORDS as usize * 2;

/// The NE2000 driver, holding its I/O Writ handle and the card's MAC.
pub struct Ne2000 {
    io: u64,
    mac: [u8; 6],
    /// The next ring page the driver will read from.
    next: u8,
}

impl Ne2000 {
    /// Bring the card up and return a driver for it, or `None` if it does
    /// not answer. `io` is the handle of the task's I/O Writ over the
    /// card's ports.
    pub fn open(io: u64) -> Option<Ne2000> {
        let dev = Ne2000 {
            io,
            mac: [0; 6],
            next: RX_START + 1,
        };

        // Reset: the card latches the value read back from its reset port,
        // then raises ISR.RST. Proceed even if that bit never shows, since
        // the register init below is what actually configures it.
        let r = dev.get(RESET)?;
        dev.put(RESET, r)?;
        for _ in 0..POLL_LIMIT {
            if dev.get(ISR)? & ISR_RST != 0 {
                break;
            }
        }

        dev.put(CR, CR_STP | CR_RD_ABORT)?; // stop, page 0, abort DMA
        dev.put(DCR, 0x49)?; // word-wide, normal, loopback off
        dev.put(RBCR0, 0)?;
        dev.put(RBCR1, 0)?;
        dev.put(RCR, 0x20)?; // monitor: accept nothing while starting
        dev.put(TCR, 0x02)?; // internal loopback while starting
        dev.put(TPSR, TX_PAGE)?;
        dev.put(PSTART, RX_START)?;
        dev.put(BNRY, RX_START)?;
        dev.put(PSTOP, RX_STOP)?;
        dev.put(ISR, 0xFF)?; // clear any latched status
        dev.put(IMR, 0x00)?; // no interrupts; the driver polls

        // The MAC lives in the card's PROM, read over remote DMA from
        // address 0. In word mode each byte is doubled, so the six address
        // bytes are at 0, 2, 4, 6, 8, 10.
        let mut prom = [0u8; 32];
        dev.remote_read(0, &mut prom)?;
        let mut mac = [0u8; 6];
        for (i, b) in mac.iter_mut().enumerate() {
            *b = prom[i * 2];
        }

        // Program the card with its MAC (the receive filter) on page 1.
        dev.put(CR, CR_STP | CR_RD_ABORT | CR_PAGE1)?;
        for (i, b) in mac.iter().enumerate() {
            dev.put(PAR0 + i as u16, *b)?;
        }
        for i in 0..8 {
            dev.put(MAR0 + i, 0)?; // no multicast
        }
        dev.put(CURR, RX_START + 1)?;

        // Back to page 0: accept broadcast (unicast to our MAC is accepted
        // anyway), leave loopback, and start.
        dev.put(CR, CR_STP | CR_RD_ABORT)?;
        dev.put(RCR, 0x04)?;
        dev.put(TCR, 0x00)?;
        dev.put(CR, CR_STA | CR_RD_ABORT)?;
        dev.put(ISR, 0xFF)?;

        Some(Ne2000 {
            io,
            mac,
            next: RX_START + 1,
        })
    }

    /// The card's six-byte MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn get(&self, port: u16) -> Option<u8> {
        crate::io_in(self.io, port).ok()
    }

    fn put(&self, port: u16, value: u8) -> Option<()> {
        crate::io_out(self.io, port, value).ok()
    }

    /// Read `out.len()` bytes (an even count) from the card's buffer at
    /// `addr` over remote DMA.
    fn remote_read(&self, addr: u16, out: &mut [u8]) -> Option<()> {
        self.put(RBCR0, out.len() as u8)?;
        self.put(RBCR1, (out.len() >> 8) as u8)?;
        self.put(RSAR0, addr as u8)?;
        self.put(RSAR1, (addr >> 8) as u8)?;
        self.put(CR, CR_STA | CR_RD_READ)?;
        for chunk in out.chunks_mut(IO_CHUNK) {
            crate::io_read(self.io, DATA, chunk).ok()?;
        }
        self.wait(ISR_RDC)?;
        self.put(ISR, ISR_RDC)?;
        Some(())
    }

    /// Poll until `bit` shows in the interrupt-status register.
    fn wait(&self, bit: u8) -> Option<()> {
        for _ in 0..POLL_LIMIT {
            if self.get(ISR)? & bit != 0 {
                return Some(());
            }
        }
        None
    }

    /// Transmit one Ethernet frame. Short frames are padded to the 60-byte
    /// minimum; frames longer than one buffer page run are refused.
    pub fn send(&self, frame: &[u8]) -> Option<()> {
        let len = frame.len().max(MIN_FRAME);
        let padded = (len + 1) & !1; // the data port moves 16-bit words
        let mut buf = [0u8; 1536];
        if padded > buf.len() || frame.len() > buf.len() {
            return None;
        }
        buf[..frame.len()].copy_from_slice(frame);

        // Copy the frame into the card's transmit page over remote DMA.
        self.put(ISR, ISR_RDC)?;
        self.put(RBCR0, padded as u8)?;
        self.put(RBCR1, (padded >> 8) as u8)?;
        self.put(RSAR0, 0)?; // low byte of TX_PAGE << 8
        self.put(RSAR1, TX_PAGE)?;
        self.put(CR, CR_STA | CR_RD_WRITE)?;
        for chunk in buf[..padded].chunks(IO_CHUNK) {
            crate::io_write(self.io, DATA, chunk).ok()?;
        }
        self.wait(ISR_RDC)?;
        self.put(ISR, ISR_RDC)?;

        // Fire the transmitter and wait for it to finish, so the next
        // frame does not overwrite the transmit page mid-send.
        self.put(TPSR, TX_PAGE)?;
        self.put(TBCR0, len as u8)?;
        self.put(TBCR1, (len >> 8) as u8)?;
        self.put(CR, CR_STA | CR_TXP | CR_RD_ABORT)?;
        self.wait(ISR_PTX)?;
        self.put(ISR, ISR_PTX)?;
        Some(())
    }

    /// Take the next received frame into `out`, returning its length, or
    /// `None` if the ring is empty. Reads straight from the card's receive
    /// ring, following the wrap at its end.
    pub fn poll(&mut self, out: &mut [u8]) -> Option<usize> {
        // The card writes incoming frames at CURR (page 1); when it has
        // moved past our read pointer there is a frame waiting.
        self.put(CR, CR_STA | CR_RD_ABORT | CR_PAGE1)?;
        let curr = self.get(CURR)?;
        self.put(CR, CR_STA | CR_RD_ABORT)?;
        if curr == self.next {
            return None;
        }

        // Each frame sits behind a 4-byte header: status, next page, and
        // the total length (header included) little-endian.
        let addr = u16::from(self.next) << 8;
        let mut header = [0u8; 4];
        self.remote_read(addr, &mut header)?;
        let next_page = header[1];
        let total = usize::from(u16::from_le_bytes([header[2], header[3]]));

        // Refuse a nonsensical header rather than trust it; just advance.
        if !(RX_START..RX_STOP).contains(&next_page) || !(18..=1518).contains(&total) {
            self.advance(next_page.max(RX_START))?;
            return None;
        }
        let frame_len = total - 4;
        let padded = (frame_len + 1) & !1;
        let mut buf = [0u8; 1536];

        // Read the frame bytes, following the ring wrap if it crosses the
        // end. Page boundaries are even, so each half stays word-aligned.
        let data = addr.wrapping_add(4);
        let ring_end = u16::from(RX_STOP) << 8;
        if u32::from(data) + padded as u32 <= u32::from(ring_end) {
            self.remote_read(data, &mut buf[..padded])?;
        } else {
            let first = usize::from(ring_end - data);
            self.remote_read(data, &mut buf[..first])?;
            self.remote_read(u16::from(RX_START) << 8, &mut buf[first..padded])?;
        }

        self.advance(next_page)?;
        let n = frame_len.min(out.len());
        out[..n].copy_from_slice(&buf[..n]);
        Some(frame_len)
    }

    /// Mark the ring read up to `next_page`: the boundary register lags one
    /// page behind, wrapping at the ring's start.
    fn advance(&mut self, next_page: u8) -> Option<()> {
        self.next = next_page;
        let bnry = if next_page == RX_START {
            RX_STOP - 1
        } else {
            next_page - 1
        };
        self.put(BNRY, bnry)?;
        self.put(ISR, ISR_PRX)?;
        Some(())
    }
}
