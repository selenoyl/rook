//! System calls: the narrow set of things a user task may ask the Keep
//! to do. The task enters through `int 0x80`; the trap entry hands the
//! saved registers here as a `SyscallFrame`.
//!
//! Everything a task passes is checked before it is trusted. A buffer the
//! task names is confirmed to lie in the task's own memory before the
//! Keep reads it, so a task can't aim a call at the Keep's memory or
//! another task's. Anything the Keep refuses comes back as a small
//! negative error, never a fault.

#![forbid(unsafe_code)]

use crate::arch;
use crate::arch::cpu;
use crate::arch::paging::AddressSpace;
use crate::arch::task::{Context, SyscallFrame};
use crate::sched;
use abi::{Error, MAX_IO_WORDS, MAX_LOG, MAX_RANDOM, MAX_SLEEP, call};

/// Handle one system call and return the task to run next: the caller
/// again for a call that just returns a value, or another task for one
/// that sleeps, yields or exits.
pub fn handle(frame: SyscallFrame) -> Context {
    let args = frame.args();
    match frame.number() {
        call::LOG => {
            frame.set_result(log(args[0], args[1]));
            frame.context()
        }
        call::NOW => {
            frame.set_result(sched::now());
            frame.context()
        }
        call::YIELD => {
            frame.set_result(0);
            sched::switch(frame.context())
        }
        call::SLEEP => match checked_sleep(args[0]) {
            Ok(ticks) => {
                frame.set_result(0);
                sched::sleep_current(ticks, frame.context())
            }
            Err(e) => {
                frame.set_result(e.to_raw());
                frame.context()
            }
        },
        call::EXIT => sched::exit_current(args[0], frame.context()),
        call::SEND => sched::send(args[0], frame.context()),
        call::RECV => sched::recv(args[0], frame.context()),
        call::WATCH => sched::watch(args[0], frame.context()),
        call::IO_IN => {
            frame.set_result(io_in(args[0], args[1]));
            frame.context()
        }
        call::IO_OUT => {
            frame.set_result(io_out(args[0], args[1], args[2]));
            frame.context()
        }
        call::IO_READ => {
            frame.set_result(io_read(args[0], args[1], args[2], args[3]));
            frame.context()
        }
        call::IO_WRITE => {
            frame.set_result(io_write(args[0], args[1], args[2], args[3]));
            frame.context()
        }
        call::RANDOM => {
            frame.set_result(random(args[0], args[1]));
            frame.context()
        }
        _ => {
            frame.set_result(Error::NoSuchCall.to_raw());
            frame.context()
        }
    }
}

/// LOG: write the task's message to the boot log, under its name, with
/// anything but printable ASCII replaced by a dot.
fn log(address: u64, length: u64) -> u64 {
    if length == 0 {
        return 0;
    }
    if length > MAX_LOG {
        return Error::TooLong.to_raw();
    }
    // The buffer is in the task's own space, which is the one now loaded.
    if !AddressSpace::current().user_range_ok(address, length) {
        return Error::BadAddress.to_raw();
    }
    let mut buffer = [0u8; MAX_LOG as usize];
    let message = &mut buffer[..length as usize];
    cpu::copy_from_user(message, address);
    for byte in message.iter_mut() {
        if !(0x20..=0x7e).contains(byte) {
            *byte = b'.';
        }
    }
    let text = core::str::from_utf8(message).unwrap_or("");
    let name = sched::running_task().map_or("task", |(_, name)| name);
    kprintln!("[{name}] {text}");
    0
}

fn checked_sleep(ticks: u64) -> Result<u64, Error> {
    if ticks > MAX_SLEEP {
        Err(Error::BadArgument)
    } else {
        Ok(ticks)
    }
}

/// A port argument as a `u16`, or `BadArgument` if it doesn't fit.
fn port_of(arg: u64) -> Result<u16, Error> {
    u16::try_from(arg).map_err(|_| Error::BadArgument)
}

/// IO_IN: read one byte from a device register, if the task's I/O Writ
/// covers the port.
fn io_in(handle: u64, port: u64) -> u64 {
    let port = match port_of(port) {
        Ok(p) => p,
        Err(e) => return e.to_raw(),
    };
    if !sched::io_allows(handle, port) {
        return Error::BadCapability.to_raw();
    }
    u64::from(arch::reg_in8(port))
}

/// IO_OUT: write one byte to a device register, if the task's I/O Writ
/// covers the port.
fn io_out(handle: u64, port: u64, value: u64) -> u64 {
    let port = match port_of(port) {
        Ok(p) => p,
        Err(e) => return e.to_raw(),
    };
    let Ok(byte) = u8::try_from(value) else {
        return Error::BadArgument.to_raw();
    };
    if !sched::io_allows(handle, port) {
        return Error::BadCapability.to_raw();
    }
    arch::reg_out8(port, byte);
    0
}

/// IO_READ: move `words` 16-bit words from a device data port into the
/// task's buffer. The Keep reads into its own buffer, then copies out, so
/// the device never writes user memory directly.
fn io_read(handle: u64, port: u64, address: u64, words: u64) -> u64 {
    let port = match port_of(port) {
        Ok(p) => p,
        Err(e) => return e.to_raw(),
    };
    if words == 0 || words > MAX_IO_WORDS {
        return Error::BadArgument.to_raw();
    }
    if !sched::io_allows(handle, port) {
        return Error::BadCapability.to_raw();
    }
    let len = words as usize * 2;
    if !AddressSpace::current().user_range_writable(address, len as u64) {
        return Error::BadAddress.to_raw();
    }
    let mut buffer = [0u8; MAX_IO_WORDS as usize * 2];
    let slice = &mut buffer[..len];
    arch::drain_port(port, slice);
    cpu::copy_to_user(address, slice);
    0
}

/// IO_WRITE: move `words` 16-bit words from the task's buffer out to a
/// device data port. The Keep copies into its own buffer first.
fn io_write(handle: u64, port: u64, address: u64, words: u64) -> u64 {
    let port = match port_of(port) {
        Ok(p) => p,
        Err(e) => return e.to_raw(),
    };
    if words == 0 || words > MAX_IO_WORDS {
        return Error::BadArgument.to_raw();
    }
    if !sched::io_allows(handle, port) {
        return Error::BadCapability.to_raw();
    }
    let len = words as usize * 2;
    if !AddressSpace::current().user_range_ok(address, len as u64) {
        return Error::BadAddress.to_raw();
    }
    let mut buffer = [0u8; MAX_IO_WORDS as usize * 2];
    let slice = &mut buffer[..len];
    cpu::copy_from_user(slice, address);
    arch::fill_port(port, slice);
    0
}

/// RANDOM: fill a user buffer with cryptographically-random bytes. No Writ
/// is needed; randomness is safe for any task to ask for.
fn random(address: u64, length: u64) -> u64 {
    if length == 0 {
        return 0;
    }
    if length > MAX_RANDOM {
        return Error::TooLong.to_raw();
    }
    if !AddressSpace::current().user_range_writable(address, length) {
        return Error::BadAddress.to_raw();
    }
    let mut buffer = [0u8; MAX_RANDOM as usize];
    let slice = &mut buffer[..length as usize];
    crate::random::fill(slice);
    cpu::copy_to_user(address, slice);
    0
}
