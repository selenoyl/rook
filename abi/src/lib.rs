//! The system call interface between the Keep and user programs.
//!
//! A task calls the Keep with `int 0x80`: the call number in rax, its
//! arguments in rdi, rsi, rdx and r10 (and r8 for the fourth message
//! word). The result comes back in rax, as a value or, for a call the
//! Keep refuses, as an error: a small negative number. Message words
//! travel in rsi, rdx, r10 and r8. Every other register comes back
//! unchanged.
//!
//! A task reaches another task only through an **endpoint**, and only if
//! it holds a **Writ** for it: an unforgeable capability the Keep placed
//! in the task's capability table. A task names a Writ by a small handle
//! (its index in that table); it can't make one up.

#![no_std]
#![forbid(unsafe_code)]

/// The interrupt vector for system calls.
pub const VECTOR: u8 = 0x80;

/// Call numbers.
pub mod call {
    /// Write a message to the boot log: `(address, length)`. The Keep
    /// prints it under the task's name, with anything but printable ASCII
    /// replaced.
    pub const LOG: u64 = 0;
    /// Let other tasks run.
    pub const YIELD: u64 = 1;
    /// Sleep for `(ticks)` timer ticks, at most `MAX_SLEEP`.
    pub const SLEEP: u64 = 2;
    /// End the task with `(code)`.
    pub const EXIT: u64 = 3;
    /// Timer ticks since the scheduler started.
    pub const NOW: u64 = 4;
    /// Send a message through an endpoint: `(handle, w0, w1, w2, w3)`.
    /// Blocks until a task receives it. Needs a Writ with the send right.
    pub const SEND: u64 = 5;
    /// Receive a message from an endpoint: `(handle)`. Blocks until a
    /// task sends one; returns the sender's badge in rax and the four
    /// words in rsi, rdx, r10, r8. Needs a Writ with the receive right.
    pub const RECV: u64 = 6;
    /// Ask after a task a Task Writ names: `(handle)`. Returns its status
    /// (see `status`). Needs a Task Writ.
    pub const WATCH: u64 = 7;
}

/// The longest message LOG takes, in bytes.
pub const MAX_LOG: u64 = 200;
/// The longest sleep, in ticks: an hour at 100 ticks a second.
pub const MAX_SLEEP: u64 = 100 * 60 * 60;
/// Words in a message passed through an endpoint.
pub const MSG_WORDS: usize = 4;

/// Why the Keep refused a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoSuchCall = 1,
    /// Memory the call names isn't the task's own, mapped for it to read.
    BadAddress = 2,
    TooLong = 3,
    BadArgument = 4,
    /// The handle names no Writ, or one of the wrong kind or rights.
    BadCapability = 5,
}

impl Error {
    /// This error as a result in rax: its number, negated.
    pub const fn to_raw(self) -> u64 {
        (self as u64).wrapping_neg()
    }
}

/// Decode a result from rax. Values with the top bit set are errors.
pub fn result(raw: u64) -> Result<u64, Option<Error>> {
    if raw >> 63 == 0 {
        return Ok(raw);
    }
    Err(match raw.wrapping_neg() {
        1 => Some(Error::NoSuchCall),
        2 => Some(Error::BadAddress),
        3 => Some(Error::TooLong),
        4 => Some(Error::BadArgument),
        5 => Some(Error::BadCapability),
        _ => None,
    })
}

/// How a watched task is doing, as WATCH returns it: a kind in the high
/// 32 bits and, for an exited task, its code in the low 32.
pub mod status {
    pub const ALIVE: u64 = 0;
    pub const EXITED: u64 = 1;
    pub const FAULTED: u64 = 2;

    /// Pack a kind and code into a status word.
    pub const fn encode(kind: u64, code: u64) -> u64 {
        kind << 32 | (code & 0xffff_ffff)
    }
    /// The kind of a status word (`ALIVE`, `EXITED`, `FAULTED`).
    pub const fn kind(status: u64) -> u64 {
        status >> 32
    }
    /// The exit code in a status word.
    pub const fn code(status: u64) -> u64 {
        status & 0xffff_ffff
    }
}

/// Modes for `check`, the Keep's user-mode test program.
pub mod check {
    /// Check the system calls, capabilities and message passing, then
    /// exit with 0.
    pub const CALLS: u64 = 0;
    /// Crash on purpose, to show the Keep ends a crashed task cleanly and
    /// keeps running.
    pub const CRASH: u64 = 1;
}
