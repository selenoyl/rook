//! The low-level part of the user programs: the program entry point, the
//! instruction that calls the Keep, and two small helpers for the test
//! program. Every unsafe block is listed in UNSAFE.md.

use core::arch::asm;

/// Define `_start`, where the Keep starts the program, to run `$main`, a
/// `fn(u64) -> !`.
#[macro_export]
macro_rules! program {
    ($main:path) => {
        #[unsafe(no_mangle)]
        extern "C" fn _start(arg: u64) -> ! {
            $main(arg)
        }
    };
}

/// Call the Keep.
pub fn call(number: u64, args: [u64; 4]) -> u64 {
    let result;
    // SAFETY: `int 0x80` enters the Keep, which reads the call from these
    // registers, puts the result in rax and comes back here with every
    // other register as it was. It runs on the Keep's own stack, so this
    // stack is untouched. Not `nomem`: the Keep reads memory the call
    // names.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            options(nostack),
        );
    }
    result
}

/// Send a message: the endpoint handle in rdi, the four words in rsi,
/// rdx, r10 and r8. Returns the Keep's result in rax.
pub fn send(handle: u64, words: [u64; 4]) -> u64 {
    let result;
    // SAFETY: `int 0x80` enters the Keep, which reads the handle and the
    // four message words from these registers, returns its result in rax
    // and leaves the rest. It runs on the Keep's own stack. Not `nomem`:
    // the Keep may block this task and run others before returning.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") abi::call::SEND => result,
            in("rdi") handle,
            in("rsi") words[0],
            in("rdx") words[1],
            in("r10") words[2],
            in("r8") words[3],
            options(nostack),
        );
    }
    result
}

/// Receive a message: the endpoint handle in rdi. Returns the sender's
/// badge (in rax) and the four words (in rsi, rdx, r10, r8).
pub fn recv(handle: u64) -> (u64, [u64; 4]) {
    let (badge, w0, w1, w2, w3);
    // SAFETY: `int 0x80` enters the Keep, which returns the sender's
    // badge in rax and the four words in rsi, rdx, r10 and r8, leaving
    // the rest. It runs on the Keep's own stack. Not `nomem`: the Keep
    // may block this task and run others before returning.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") abi::call::RECV => badge,
            in("rdi") handle,
            out("rsi") w0,
            out("rdx") w1,
            out("r10") w2,
            out("r8") w3,
            options(nostack),
        );
    }
    (badge, [w0, w1, w2, w3])
}

/// The privilege level this code runs at: 3 for user mode.
pub fn privilege_level() -> u16 {
    let cs: u16;
    // SAFETY: reading CS has no side effects.
    unsafe { asm!("mov {:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags)) };
    cs & 3
}

/// Crash: run an undefined instruction.
pub fn crash() -> ! {
    // SAFETY: `ud2` always raises an invalid-opcode fault, and the Keep
    // ends a task that faults. It never returns.
    unsafe { asm!("ud2", options(nomem, nostack, noreturn)) }
}
