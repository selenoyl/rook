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
