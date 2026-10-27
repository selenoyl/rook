//! check: the Keep's user-mode test program, run at every boot.
//!
//! Started with `abi::check::CALLS`, it checks that the system calls work,
//! that the Keep refuses bad arguments and Writs it wasn't given, and that
//! it can trade a message with the supervisor; then it exits with 0, or
//! with 1 naming the check that failed. Started with `abi::check::CRASH`,
//! it crashes on purpose: the Keep must end it and carry on.
//!
//! The Keep seeds its capability table at boot:
//!   handle 0  send requests to the supervisor
//!   handle 1  receive replies from it

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use user::Error;
use user::abi::{MAX_LOG, check};

const TO_SUPERVISOR: u64 = 0;
const FROM_SUPERVISOR: u64 = 1;
const ABSENT_HANDLE: u64 = 3;

/// Where the Keep's image starts: memory no user task may read.
const KEEP_IMAGE: u64 = 0xFFFF_FFFF_8000_0000;
const MESSAGE: &str = "running in ring 3";

user::program!(main);

fn main(mode: u64) -> ! {
    if mode == check::CRASH {
        let _ = user::log("crashing on purpose");
        user::sys::crash();
    }
    match run_checks() {
        Ok(()) => {
            let _ = user::log("all checks passed");
            user::exit(0)
        }
        Err(failed) => {
            let _ = user::log("a check FAILED:");
            let _ = user::log(failed);
            user::exit(1)
        }
    }
}

fn expect(ok: bool, name: &'static str) -> Result<(), &'static str> {
    if ok { Ok(()) } else { Err(name) }
}

fn refused<T>(result: Result<T, user::Refused>, error: Error) -> bool {
    matches!(result, Err(Some(e)) if e == error)
}

/// The most times the preemption loop spins before giving up. A timer
/// tick is 10 ms and each turn makes a quick call, so a tick arrives in
/// far fewer than this; reaching it means the timer never preempted.
const SPIN_LIMIT: u64 = 100_000_000;

fn run_checks() -> Result<(), &'static str> {
    expect(user::sys::privilege_level() == 3, "privilege level 3")?;
    expect(user::log(MESSAGE).is_ok(), "log")?;

    let before = user::now();
    expect(user::sleep(3).is_ok(), "sleep")?;
    expect(
        user::now() >= before.saturating_add(3),
        "sleep lasts as long as asked",
    )?;
    expect(user::yield_now().is_ok(), "yield")?;

    // Preemption: spin in ring 3 until the clock advances, which only
    // happens if the timer interrupts this loop.
    let start = user::now();
    let mut spins: u64 = 0;
    while user::now() == start {
        spins = spins.saturating_add(1);
        if spins >= SPIN_LIMIT {
            return Err("the timer never preempted the task");
        }
    }

    // Bad arguments must come back as errors.
    let message = MESSAGE.as_ptr() as u64;
    expect(
        refused(user::log_raw(0, 16), Error::BadAddress),
        "log from address 0 is refused",
    )?;
    expect(
        refused(user::log_raw(KEEP_IMAGE, 16), Error::BadAddress),
        "log from the Keep's memory is refused",
    )?;
    expect(
        refused(user::log_raw(u64::MAX - 4, 16), Error::BadAddress),
        "log from a range that wraps around is refused",
    )?;
    expect(
        refused(user::log_raw(message, MAX_LOG + 1), Error::TooLong),
        "an overlong log is refused",
    )?;
    expect(
        refused(user::sleep(u64::MAX), Error::BadArgument),
        "an overlong sleep is refused",
    )?;
    expect(
        refused(user::call_raw(99, [0; 4]), Error::NoSuchCall),
        "an unknown call is refused",
    )?;

    // Cryptography: every primitive against its official test vector,
    // computed here in ring 3.
    expect(crypto::self_test(), "cryptography known-answer vectors")?;
    let _ = user::log("crypto: SHA-2, HMAC, ChaCha20-Poly1305, X25519, Ed25519 verified");

    // Writs: a task may use only the ones the Keep gave it.
    expect(
        refused(user::recv(TO_SUPERVISOR), Error::BadCapability),
        "receiving on a send-only Writ is refused",
    )?;
    expect(
        refused(user::send(ABSENT_HANDLE, [0; 4]), Error::BadCapability),
        "using a handle with no Writ is refused",
    )?;

    // Message passing: report to the supervisor and wait for the reply.
    expect(
        user::send(TO_SUPERVISOR, [0x00C0FFEE, 0, 0, 0]).is_ok(),
        "reporting to the supervisor",
    )?;
    expect(
        user::recv(FROM_SUPERVISOR).is_ok(),
        "hearing back from the supervisor",
    )?;
    Ok(())
}
