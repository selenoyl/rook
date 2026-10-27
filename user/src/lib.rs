//! What every Rook user program shares: its entry point, the system
//! calls, and what to do on a panic.
//!
//! The Keep starts a program in ring 3 at `_start(arg)`, with a stack of
//! its own and `arg` from whoever started it. A program names its main
//! function with `program!(main)`.

#![no_std]

// The only module allowed to use `unsafe`; see UNSAFE.md.
#[allow(unsafe_code)]
pub mod sys;

pub mod ata;

pub use abi;
pub use abi::Error;
use abi::call;
use core::fmt::{self, Write};

/// A call the Keep refused, with the error it gave, if it gave a known
/// one.
pub type Refused = Option<Error>;

/// Write `message` to the boot log, under this task's name.
pub fn log(message: &str) -> Result<(), Refused> {
    log_raw(message.as_ptr() as u64, message.len() as u64)
}

/// A fixed buffer to format one log line into, no longer than the Keep
/// takes.
struct Line {
    bytes: [u8; abi::MAX_LOG as usize],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &byte in s.as_bytes() {
            if self.len < self.bytes.len() {
                self.bytes[self.len] = byte;
                self.len += 1;
            }
        }
        Ok(())
    }
}

/// Log a formatted line. Used through the `logln!` macro.
pub fn logf(args: fmt::Arguments) -> Result<(), Refused> {
    let mut line = Line {
        bytes: [0; abi::MAX_LOG as usize],
        len: 0,
    };
    let _ = line.write_fmt(args);
    log_raw(line.bytes.as_ptr() as u64, line.len as u64)
}

/// Log a formatted line, like `kprintln!` but from a user program.
#[macro_export]
macro_rules! logln {
    ($($arg:tt)*) => { let _ = $crate::logf(format_args!($($arg)*)); };
}

/// LOG with any address and length, valid or not.
pub fn log_raw(address: u64, length: u64) -> Result<(), Refused> {
    abi::result(sys::call(call::LOG, [address, length, 0, 0])).map(|_| ())
}

/// Let other tasks run.
pub fn yield_now() -> Result<(), Refused> {
    abi::result(sys::call(call::YIELD, [0; 4])).map(|_| ())
}

/// Sleep for `ticks` timer ticks.
pub fn sleep(ticks: u64) -> Result<(), Refused> {
    abi::result(sys::call(call::SLEEP, [ticks, 0, 0, 0])).map(|_| ())
}

/// Timer ticks since the scheduler started.
pub fn now() -> u64 {
    abi::result(sys::call(call::NOW, [0; 4])).unwrap_or(0)
}

/// End this task.
pub fn exit(code: u64) -> ! {
    sys::call(call::EXIT, [code, 0, 0, 0]);
    // The Keep never returns from EXIT; if it somehow did, keep asking.
    loop {
        sys::call(call::EXIT, [code, 0, 0, 0]);
    }
}

/// Send the four `words` through the endpoint `handle` names, blocking
/// until a task receives them. Needs a Writ with the send right.
pub fn send(handle: u64, words: [u64; abi::MSG_WORDS]) -> Result<(), Refused> {
    abi::result(sys::send(handle, words)).map(|_| ())
}

/// Receive a message from the endpoint `handle` names, blocking until a
/// task sends one. Returns the sender's badge and the four words. Needs a
/// Writ with the receive right.
pub fn recv(handle: u64) -> Result<(u64, [u64; abi::MSG_WORDS]), Refused> {
    let (badge, words) = sys::recv(handle);
    abi::result(badge).map(|badge| (badge, words))
}

/// Ask the Keep how the task a Task Writ names is doing. Decode the
/// result with `abi::status`.
pub fn watch(handle: u64) -> Result<u64, Refused> {
    abi::result(sys::call(call::WATCH, [handle, 0, 0, 0]))
}

/// Read one byte from a device register through an I/O Writ.
pub fn io_in(handle: u64, port: u16) -> Result<u8, Refused> {
    abi::result(sys::call(call::IO_IN, [handle, u64::from(port), 0, 0])).map(|v| v as u8)
}

/// Write one byte to a device register through an I/O Writ.
pub fn io_out(handle: u64, port: u16, value: u8) -> Result<(), Refused> {
    abi::result(sys::call(
        call::IO_OUT,
        [handle, u64::from(port), u64::from(value), 0],
    ))
    .map(|_| ())
}

/// Read `buf.len()/2` 16-bit words from a device data port into `buf`
/// through an I/O Writ. `buf` must have an even length, at most
/// `2 * abi::MAX_IO_WORDS` bytes.
pub fn io_read(handle: u64, port: u16, buf: &mut [u8]) -> Result<(), Refused> {
    let words = (buf.len() / 2) as u64;
    abi::result(sys::call(
        call::IO_READ,
        [handle, u64::from(port), buf.as_ptr() as u64, words],
    ))
    .map(|_| ())
}

/// Write `buf.len()/2` 16-bit words from `buf` out to a device data port
/// through an I/O Writ.
pub fn io_write(handle: u64, port: u16, buf: &[u8]) -> Result<(), Refused> {
    let words = (buf.len() / 2) as u64;
    abi::result(sys::call(
        call::IO_WRITE,
        [handle, u64::from(port), buf.as_ptr() as u64, words],
    ))
    .map(|_| ())
}

/// Fill `buf` with cryptographically-random bytes from the Keep. No Writ
/// is needed.
pub fn random(buf: &mut [u8]) -> Result<(), Refused> {
    for chunk in buf.chunks_mut(abi::MAX_RANDOM as usize) {
        abi::result(sys::call(
            call::RANDOM,
            [chunk.as_ptr() as u64, chunk.len() as u64, 0, 0],
        ))?;
    }
    Ok(())
}

/// Bytes carried in one endpoint message (four 64-bit words).
const BLOB_CHUNK: usize = abi::MSG_WORDS * 8;

/// Send a byte buffer over an endpoint as a run of fixed-size messages.
/// The receiver calls `recv_blob` with a buffer of the same length, so the
/// two agree how many messages to expect — Drawbridge's message sizes are
/// fixed constants, so they always do. The last message is zero-padded;
/// the receiver ignores the padding. This is the small fragmentation layer
/// that carries a handshake, larger than one message, over the Keep's
/// register-sized IPC.
pub fn send_blob(handle: u64, bytes: &[u8]) -> Result<(), Refused> {
    for chunk in bytes.chunks(BLOB_CHUNK) {
        let mut words = [0u64; abi::MSG_WORDS];
        for (i, word) in words.iter_mut().enumerate() {
            let start = i * 8;
            if start < chunk.len() {
                let end = core::cmp::min(start + 8, chunk.len());
                let mut buf = [0u8; 8];
                buf[..end - start].copy_from_slice(&chunk[start..end]);
                *word = u64::from_le_bytes(buf);
            }
        }
        send(handle, words)?;
    }
    Ok(())
}

/// Receive a byte buffer sent with `send_blob` into `out`, reassembling the
/// messages. Returns the sender's badge (from the first message).
pub fn recv_blob(handle: u64, out: &mut [u8]) -> Result<u64, Refused> {
    let mut badge = 0;
    for (n, chunk) in out.chunks_mut(BLOB_CHUNK).enumerate() {
        let (b, words) = recv(handle)?;
        if n == 0 {
            badge = b;
        }
        for (i, word) in words.iter().enumerate() {
            let start = i * 8;
            if start < chunk.len() {
                let end = core::cmp::min(start + 8, chunk.len());
                let bytes = word.to_le_bytes();
                chunk[start..end].copy_from_slice(&bytes[..end - start]);
            }
        }
    }
    Ok(badge)
}

/// Fixed identity keys for the Drawbridge-over-IPC demonstration between
/// `michael` and `check`.
///
/// These are NOT secret and NOT random — they are two constant bytes
/// repeated. Real identities come from per-device entropy and are
/// exchanged in person by Castling; these exist only so the two built-in
/// tasks can authenticate each other at boot, to show the handshake runs
/// over real endpoints. A deployed Rook must never ship a fixed key.
pub mod demo_identity {
    /// Michael's demo identity secret.
    pub const MICHAEL_SECRET: [u8; 32] = [0x4d; 32];
    /// The check task's demo identity secret.
    pub const CHECK_SECRET: [u8; 32] = [0x43; 32];
    /// The Vault's demo identity secret.
    pub const VAULT_SECRET: [u8; 32] = [0x56; 32];

    /// A fresh ephemeral secret for one handshake, drawn from the Keep's
    /// CSPRNG. `role` is mixed in only as a fallback, so the two ends still
    /// differ if the randomness call were ever refused.
    pub fn ephemeral(role: u8) -> [u8; 32] {
        let mut secret = [role; 32];
        let _ = super::random(&mut secret);
        secret
    }
}

/// Make a raw call: for testing how the Keep answers calls it doesn't
/// know.
pub fn call_raw(number: u64, args: [u64; 4]) -> Result<u64, Refused> {
    abi::result(sys::call(number, args))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    let _ = log("panicked");
    exit(101)
}
