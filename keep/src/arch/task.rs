//! Saved task state.
//!
//! A task that isn't running is a `Context`: its registers, saved as a
//! trap frame, or built by `new_kernel`/`new_user` for a task that hasn't
//! started. The frame always lives on the task's kernel stack (the slot
//! it was given); a user task resumes through the trap entry's `iretq`,
//! which drops to ring 3 on the user stack the frame names. A Context
//! can't be copied or made from an address, and resuming one consumes it,
//! so each saved state is resumed at most once and only real frames are.

use super::gdt::{KERNEL_CODE, KERNEL_DATA, USER_CODE, USER_DATA};
use super::idt::TrapFrame;
use super::layout::{TASK_SLOTS, stack_top};
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};

/// Interrupts on (bit 9), plus bit 1, which is always set.
const START_FLAGS: u64 = 1 << 9 | 1 << 1;

/// Task stack slots already given to a task. Slot 0 is the idle task's,
/// which runs on the boot stack, so it starts taken.
static TAKEN: AtomicU32 = AtomicU32::new(1);

pub struct Context {
    frame: u64,
}

/// Where a task's first frame goes and what it holds.
struct Start {
    rip: u64,
    cs: u16,
    ss: u16,
    /// The stack the task runs on after the first return.
    rsp: u64,
    arg: u64,
}

/// Claim stack slot `slot` for a new task. Returns false if `slot` is out
/// of range or already taken.
fn claim(slot: usize) -> bool {
    let Some(bit) = u32::try_from(slot).ok().and_then(|s| 1u32.checked_shl(s)) else {
        return false;
    };
    slot < TASK_SLOTS && TAKEN.fetch_or(bit, Ordering::Relaxed) & bit == 0
}

impl Context {
    /// A new kernel task in stack slot `slot`, which will start running
    /// `entry(arg)` in ring 0 on its own stack. Returns None if `slot` is
    /// out of range or already used.
    pub fn new_kernel(slot: usize, entry: extern "C" fn(u64) -> !, arg: u64) -> Option<Context> {
        if !claim(slot) {
            return None;
        }
        // The task starts as if `entry` had just been called: a zero
        // return address below the top of its stack (returning would jump
        // to the unmapped null page and fault), then the frame below that.
        let rsp = stack_top(slot) - 8;
        let frame = rsp - size_of::<TrapFrame>() as u64;
        // SAFETY: `claim` just took this slot, so nothing runs on its
        // stack, which `memory::build` mapped read-write. The zero slot
        // and the frame are in the stack's top ~184 bytes, 8-aligned.
        unsafe { (rsp as *mut u64).write(0) };
        write_frame(
            frame,
            Start {
                rip: entry as usize as u64,
                cs: KERNEL_CODE,
                ss: KERNEL_DATA,
                rsp,
                arg,
            },
        );
        Some(Context { frame })
    }

    /// A new ring-3 task in stack slot `slot`, which the slot's stack
    /// serves as kernel stack (where it traps) while it runs on
    /// `user_stack_top` in its own address space, starting at `entry`.
    /// Returns None if `slot` is out of range or already used.
    pub fn new_user(slot: usize, entry: u64, user_stack_top: u64, arg: u64) -> Option<Context> {
        if !claim(slot) {
            return None;
        }
        // The frame sits at the very top of the kernel stack, so once the
        // trap entry returns to ring 3 the kernel stack is empty for the
        // next trap. The user stack's own return slot is already zero.
        let frame = stack_top(slot) - size_of::<TrapFrame>() as u64;
        // SAFETY: `claim` just took this slot; its stack is mapped
        // read-write and nothing runs on it. The frame is in the stack's
        // top 176 bytes, 8-aligned.
        write_frame(
            frame,
            Start {
                rip: entry,
                cs: USER_CODE,
                ss: USER_DATA,
                rsp: user_stack_top - 8,
                arg,
            },
        );
        Some(Context { frame })
    }

    /// The registers the trap entry just saved at `frame`.
    pub(super) fn saved(frame: *mut TrapFrame) -> Context {
        Context {
            frame: frame as u64,
        }
    }

    /// Give the frame back to the trap entry, to restore.
    pub(super) fn resume(self) -> *mut TrapFrame {
        self.frame as *mut TrapFrame
    }

    /// The four message words a sending task left in its registers
    /// (rsi, rdx, r10, r8).
    pub(crate) fn message(&self) -> [u64; 4] {
        let f = self.frame as *const TrapFrame;
        // SAFETY: `frame` points at a saved frame on a task's kernel
        // stack, which lives as long as the task; these reads take the
        // message words the task passed to a send.
        unsafe { [(*f).rsi, (*f).rdx, (*f).r10, (*f).r8] }
    }

    /// Set the value a task gets back from its call (rax).
    pub(crate) fn set_result(&self, value: u64) {
        // SAFETY: as for `message`; sets rax of the saved frame.
        unsafe { (*(self.frame as *mut TrapFrame)).rax = value };
    }

    /// Deliver a received message to a task: the sender's `badge` in rax
    /// and the four words in rsi, rdx, r10, r8.
    pub(crate) fn deliver(&self, badge: u64, words: [u64; 4]) {
        let f = self.frame as *mut TrapFrame;
        // SAFETY: as for `message`; writes the registers the task's recv
        // call returns in.
        unsafe {
            (*f).rax = badge;
            (*f).rsi = words[0];
            (*f).rdx = words[1];
            (*f).r10 = words[2];
            (*f).r8 = words[3];
        }
    }
}

/// A system call as the trap entry saw it: its number and arguments, read
/// from the registers the user task left in its saved frame, and a way to
/// set the value it gets back.
pub struct SyscallFrame {
    frame: *mut TrapFrame,
}

impl SyscallFrame {
    pub(super) fn new(frame: *mut TrapFrame) -> SyscallFrame {
        SyscallFrame { frame }
    }

    /// The call number (rax).
    pub fn number(&self) -> u64 {
        // SAFETY: the trap entry passed a frame on the current kernel
        // stack, which stays in place until this syscall returns a frame.
        unsafe { (*self.frame).rax }
    }

    /// The four arguments (rdi, rsi, rdx, r10).
    pub fn args(&self) -> [u64; 4] {
        // SAFETY: as for `number`.
        unsafe {
            [
                (*self.frame).rdi,
                (*self.frame).rsi,
                (*self.frame).rdx,
                (*self.frame).r10,
            ]
        }
    }

    /// Set the value the task gets back (rax).
    pub fn set_result(&self, value: u64) {
        // SAFETY: as for `number`; sets rax in the saved frame.
        unsafe { (*self.frame).rax = value };
    }

    /// The saved registers, to resume this task if it keeps running.
    pub fn context(self) -> Context {
        Context::saved(self.frame)
    }
}

/// Write a task's first frame at `frame` on its kernel stack.
fn write_frame(frame: u64, start: Start) {
    let regs = TrapFrame {
        rdi: start.arg,
        rip: start.rip,
        cs: u64::from(start.cs),
        rflags: START_FLAGS,
        rsp: start.rsp,
        ss: u64::from(start.ss),
        ..TrapFrame::ZERO
    };
    // SAFETY: the callers pass a `frame` inside a stack slot they just
    // claimed, mapped read-write with nothing else on it, and 8-aligned.
    unsafe { (frame as *mut TrapFrame).write(regs) };
}
