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

use crate::arch::cpu;
use crate::arch::paging::AddressSpace;
use crate::arch::task::{Context, SyscallFrame};
use crate::sched;
use abi::{Error, MAX_LOG, MAX_SLEEP, call};

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
